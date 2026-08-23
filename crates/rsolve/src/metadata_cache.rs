//! CLI-owned resolution of the on-disk metadata cache root.

use rsolve_core::RegistryId;
use rsolve_provider::{SnapshotStore, SnapshotStoreError};
use sha2::{Digest, Sha256};
use std::env;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const CACHE_VERSION: &str = "v1";
const REGISTRIES_DIRECTORY: &str = "registries";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CachePlatform {
    Windows,
    MacOs,
    Unix,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CacheEnvironment {
    pub(crate) home: Option<PathBuf>,
    pub(crate) local_app_data: Option<PathBuf>,
    pub(crate) xdg_cache_home: Option<PathBuf>,
}

impl CacheEnvironment {
    fn from_process() -> Self {
        Self {
            home: env::var_os("HOME").map(PathBuf::from),
            local_app_data: env::var_os("LOCALAPPDATA").map(PathBuf::from),
            xdg_cache_home: env::var_os("XDG_CACHE_HOME").map(PathBuf::from),
        }
    }
}

#[derive(Debug)]
pub(crate) enum MetadataCacheError {
    MissingEnvironment(&'static str),
    RelativeXdgCacheHome(PathBuf),
    EmptyExplicitRoot,
    RootNotDirectory(PathBuf),
    RootCreation {
        path: PathBuf,
        message: String,
    },
    Store {
        path: PathBuf,
        source: SnapshotStoreError,
    },
}

impl fmt::Display for MetadataCacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEnvironment(variable) => {
                write!(
                    formatter,
                    "required environment variable {variable} is missing"
                )
            }
            Self::RelativeXdgCacheHome(path) => write!(
                formatter,
                "XDG_CACHE_HOME must be absolute, got {}",
                path.display()
            ),
            Self::EmptyExplicitRoot => formatter.write_str("--metadata-cache must not be empty"),
            Self::RootNotDirectory(path) => {
                write!(
                    formatter,
                    "metadata cache root is not a directory: {}",
                    path.display()
                )
            }
            Self::RootCreation { path, message } => write!(
                formatter,
                "cannot create metadata cache root {}: {message}",
                path.display()
            ),
            Self::Store { path, source } => write!(
                formatter,
                "cannot open metadata cache store {}: {source}",
                path.display()
            ),
        }
    }
}

impl Error for MetadataCacheError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MetadataCache {
    root: PathBuf,
}

impl MetadataCache {
    pub(crate) fn resolve(explicit_root: Option<&Path>) -> Result<Self, MetadataCacheError> {
        let root = match explicit_root {
            Some(path) => {
                if path.as_os_str().is_empty() {
                    return Err(MetadataCacheError::EmptyExplicitRoot);
                }
                path.to_owned()
            }
            None => default_root(host_platform(), &CacheEnvironment::from_process())?,
        };
        prepare_root(root)
    }

    #[cfg(test)]
    pub(crate) fn resolve_for_test(
        explicit_root: Option<&Path>,
        platform: CachePlatform,
        environment: &CacheEnvironment,
    ) -> Result<Self, MetadataCacheError> {
        let root = match explicit_root {
            Some(path) => {
                if path.as_os_str().is_empty() {
                    return Err(MetadataCacheError::EmptyExplicitRoot);
                }
                path.to_owned()
            }
            None => default_root(platform, environment)?,
        };
        prepare_root(root)
    }

    #[allow(dead_code)] // Test support inspects the resolved root directly.
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn store_path(&self, registry_id: &RegistryId) -> PathBuf {
        self.root
            .join(CACHE_VERSION)
            .join(REGISTRIES_DIRECTORY)
            .join(registry_digest(registry_id))
    }

    pub(crate) fn open_store(
        &self,
        registry_id: RegistryId,
    ) -> Result<SnapshotStore, MetadataCacheError> {
        let path = self.store_path(&registry_id);
        SnapshotStore::open(&path, registry_id)
            .map_err(|source| MetadataCacheError::Store { path, source })
    }
}

fn host_platform() -> CachePlatform {
    if cfg!(windows) {
        CachePlatform::Windows
    } else if cfg!(target_os = "macos") {
        CachePlatform::MacOs
    } else {
        CachePlatform::Unix
    }
}

fn default_root(
    platform: CachePlatform,
    environment: &CacheEnvironment,
) -> Result<PathBuf, MetadataCacheError> {
    let base = match platform {
        CachePlatform::Windows => {
            non_empty_path(environment.local_app_data.as_deref(), "LOCALAPPDATA")?.to_owned()
        }
        CachePlatform::MacOs => non_empty_path(environment.home.as_deref(), "HOME")?
            .join("Library")
            .join("Caches"),
        CachePlatform::Unix => match non_empty_path_optional(environment.xdg_cache_home.as_deref())
        {
            Some(path) if !path.is_absolute() => {
                return Err(MetadataCacheError::RelativeXdgCacheHome(path.to_owned()));
            }
            Some(path) => path.to_owned(),
            None => non_empty_path(environment.home.as_deref(), "HOME")?.join(".cache"),
        },
    };
    Ok(base.join("rsolve").join("metadata"))
}

fn non_empty_path<'a>(
    path: Option<&'a Path>,
    variable: &'static str,
) -> Result<&'a Path, MetadataCacheError> {
    non_empty_path_optional(path).ok_or(MetadataCacheError::MissingEnvironment(variable))
}

fn non_empty_path_optional(path: Option<&Path>) -> Option<&Path> {
    path.filter(|path| !path.as_os_str().is_empty())
}

fn prepare_root(root: PathBuf) -> Result<MetadataCache, MetadataCacheError> {
    match fs::symlink_metadata(&root) {
        Ok(metadata) if !metadata.is_dir() => {
            return Err(MetadataCacheError::RootNotDirectory(root));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(&root).map_err(|error| MetadataCacheError::RootCreation {
                path: root.clone(),
                message: error.to_string(),
            })?;
        }
        Err(error) => {
            return Err(MetadataCacheError::RootCreation {
                path: root,
                message: error.to_string(),
            });
        }
    }
    Ok(MetadataCache { root })
}

fn registry_digest(registry_id: &RegistryId) -> String {
    Sha256::digest(registry_id.as_str().as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn environment() -> CacheEnvironment {
        CacheEnvironment {
            home: Some(PathBuf::from("/home/tester")),
            local_app_data: Some(PathBuf::from("C:/Users/tester/AppData/Local")),
            xdg_cache_home: None,
        }
    }

    #[test]
    fn default_root_selection_is_platform_and_environment_driven() {
        let mut env = environment();
        assert_eq!(
            default_root(CachePlatform::Windows, &env).unwrap(),
            PathBuf::from("C:/Users/tester/AppData/Local/rsolve/metadata")
        );
        assert_eq!(
            default_root(CachePlatform::MacOs, &env).unwrap(),
            PathBuf::from("/home/tester/Library/Caches/rsolve/metadata")
        );
        assert_eq!(
            default_root(CachePlatform::Unix, &env).unwrap(),
            PathBuf::from("/home/tester/.cache/rsolve/metadata")
        );
        env.xdg_cache_home = Some(PathBuf::from("/var/cache/user"));
        assert_eq!(
            default_root(CachePlatform::Unix, &env).unwrap(),
            PathBuf::from("/var/cache/user/rsolve/metadata")
        );
    }

    #[test]
    fn default_root_rejects_missing_environment_and_relative_xdg() {
        let mut env = environment();
        env.home = None;
        assert!(matches!(
            default_root(CachePlatform::MacOs, &env),
            Err(MetadataCacheError::MissingEnvironment("HOME"))
        ));
        env.xdg_cache_home = Some(PathBuf::from("relative-cache"));
        assert!(matches!(
            default_root(CachePlatform::Unix, &env),
            Err(MetadataCacheError::RelativeXdgCacheHome(_))
        ));
        env.xdg_cache_home = Some(PathBuf::new());
        env.home = Some(PathBuf::from("/home/tester"));
        assert_eq!(
            default_root(CachePlatform::Unix, &env).unwrap(),
            PathBuf::from("/home/tester/.cache/rsolve/metadata")
        );
    }

    #[test]
    fn explicit_root_allows_relative_paths_and_rejects_files() {
        let dir = tempdir().unwrap();
        let relative_path = format!(".rsolve-metadata-cache-test-{}", std::process::id());
        let relative = Path::new(&relative_path);
        let cache =
            MetadataCache::resolve_for_test(Some(relative), CachePlatform::Unix, &environment())
                .unwrap();
        assert_eq!(cache.root(), relative);
        let file = dir.path().join("not-a-directory");
        fs::write(&file, b"file").unwrap();
        assert!(matches!(
            MetadataCache::resolve_for_test(Some(&file), CachePlatform::Unix, &environment()),
            Err(MetadataCacheError::RootNotDirectory(path)) if path == file
        ));
        let _ = fs::remove_dir_all(relative);

        let parent_file = dir.path().join("parent-file");
        fs::write(&parent_file, b"file").unwrap();
        let nested = parent_file.join("nested");
        assert!(matches!(
            MetadataCache::resolve_for_test(Some(&nested), CachePlatform::Unix, &environment()),
            Err(MetadataCacheError::RootCreation { path, .. }) if path == nested
        ));
    }

    #[test]
    fn explicit_root_wins_over_every_platform_default_environment() {
        let dir = tempdir().unwrap();
        let environment = CacheEnvironment {
            home: None,
            local_app_data: None,
            xdg_cache_home: Some(PathBuf::from("relative-cache")),
        };
        for platform in [
            CachePlatform::Windows,
            CachePlatform::MacOs,
            CachePlatform::Unix,
        ] {
            let explicit = dir.path().join(format!("{platform:?}"));
            let cache =
                MetadataCache::resolve_for_test(Some(&explicit), platform, &environment).unwrap();
            assert_eq!(cache.root(), explicit);
            assert!(explicit.is_dir());
        }
    }

    #[test]
    // RegistryId.as_str() bytes are hashed as supplied; only the digest
    // rendering is lowercase hexadecimal.
    fn stores_use_versioned_registry_digest_paths() {
        let dir = tempdir().unwrap();
        let cache =
            MetadataCache::resolve_for_test(Some(dir.path()), CachePlatform::Unix, &environment())
                .unwrap();
        let cran = RegistryId::new("cran").unwrap();
        let private = RegistryId::new("private").unwrap();
        cache.open_store(cran.clone()).unwrap();
        cache.open_store(private.clone()).unwrap();
        assert!(cache.store_path(&cran).is_dir());
        assert!(cache.store_path(&private).is_dir());
        assert_ne!(cache.store_path(&cran), cache.store_path(&private));
        assert_eq!(
            cache.store_path(&cran).parent().unwrap().file_name(),
            Some("registries".as_ref())
        );
        assert_eq!(
            cache
                .store_path(&cran)
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .file_name(),
            Some("v1".as_ref())
        );
        assert_eq!(cache.store_path(&cran).file_name().unwrap().len(), 64);
        assert_eq!(
            cache.store_path(&cran).file_name().unwrap(),
            "7f3892f518fc4de287519eca546033397b616b0a53a46b2ef6f417bc972eb85b"
        );
        assert!(
            cache
                .store_path(&cran)
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }
}
