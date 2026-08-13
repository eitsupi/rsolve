#[cfg(target_os = "linux")]
#[path = "pak_portable.rs"]
mod pak_harness;

#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
const ISOLATION_MODE_ENV: &str = "NRR_PAK_ISOLATION_MODE";
#[cfg(target_os = "linux")]
const PARENT_NETNS_ENV: &str = "NRR_PAK_PARENT_NETNS";
#[cfg(target_os = "linux")]
const DECLARED_ISOLATION_MODE: &str = "linux-netns-v1";

#[cfg(target_os = "linux")]
fn namespace_identity(path: &Path) -> Result<String, String> {
    let identity = fs::read_link(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?
        .to_string_lossy()
        .into_owned();
    let valid = identity
        .strip_prefix("net:[")
        .and_then(|value| value.strip_suffix(']'))
        .is_some_and(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()));
    if !valid {
        return Err(format!("invalid network namespace identity: {identity:?}"));
    }
    Ok(identity)
}

#[cfg(target_os = "linux")]
fn has_ipv4_default_route(contents: &str) -> Result<bool, String> {
    let mut lines = contents.lines();
    let header: Vec<_> = lines
        .next()
        .ok_or_else(|| "missing IPv4 route header".to_owned())?
        .split_whitespace()
        .collect();
    if header
        != [
            "Iface",
            "Destination",
            "Gateway",
            "Flags",
            "RefCnt",
            "Use",
            "Metric",
            "Mask",
            "MTU",
            "Window",
            "IRTT",
        ]
    {
        return Err("malformed IPv4 route header".into());
    }
    lines.try_fold(false, |found, line| {
        let mut fields = line.split_whitespace();
        let fields: Vec<_> = fields.by_ref().collect();
        if fields.len() != 11 || fields[1].len() != 8 || fields[7].len() != 8 {
            return Err("malformed IPv4 route record".into());
        }
        if !fields[1].bytes().all(|byte| byte.is_ascii_hexdigit())
            || !fields[7].bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("malformed IPv4 route record".into());
        }
        Ok(found || (fields[1] == "00000000" && fields[7] == "00000000"))
    })
}

#[cfg(target_os = "linux")]
fn has_ipv6_default_route(contents: &str) -> Result<bool, String> {
    contents.lines().try_fold(false, |found, line| {
        let mut fields = line.split_whitespace();
        let fields: Vec<_> = fields.by_ref().collect();
        if fields.len() != 10
            || fields[0].len() != 32
            || fields[1].len() != 2
            || fields[2].len() != 32
            || fields[3].len() != 2
        {
            return Err("malformed IPv6 route record".into());
        }
        for field in fields.iter().take(4) {
            if !field.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err("malformed IPv6 route record".into());
            }
        }
        Ok(found || (fields[0] == "00000000000000000000000000000000" && fields[1] == "00"))
    })
}

#[cfg(target_os = "linux")]
fn preflight() -> Result<(), String> {
    if env::var("NRR_TEST_MODE").as_deref() != Ok("pak-isolated") {
        return Err("NRR_TEST_MODE must be pak-isolated".into());
    }
    if env::var(ISOLATION_MODE_ENV).as_deref() != Ok(DECLARED_ISOLATION_MODE) {
        return Err(format!(
            "{ISOLATION_MODE_ENV} must be {DECLARED_ISOLATION_MODE}"
        ));
    }
    let parent = env::var(PARENT_NETNS_ENV)
        .map_err(|_| format!("{PARENT_NETNS_ENV} must be supplied by the isolation wrapper"))?;
    let parent_valid = parent
        .strip_prefix("net:[")
        .and_then(|value| value.strip_suffix(']'))
        .is_some_and(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()));
    if !parent_valid {
        return Err(format!(
            "{PARENT_NETNS_ENV} is not a valid net namespace identity"
        ));
    }
    let current = namespace_identity(Path::new("/proc/self/ns/net"))?;
    if parent == current {
        return Err("isolated test is running in the wrapper parent network namespace".into());
    }
    if has_ipv4_default_route(
        &fs::read_to_string("/proc/net/route").map_err(|error| error.to_string())?,
    )? || has_ipv6_default_route(
        &fs::read_to_string("/proc/net/ipv6_route").map_err(|error| error.to_string())?,
    )? {
        return Err("isolated network namespace has a default route".into());
    }
    let interfaces = fs::read_dir("/sys/class/net")
        .map_err(|error| error.to_string())?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if interfaces.iter().any(|name| name != "lo") || interfaces.is_empty() {
        return Err("isolated network namespace interfaces must contain only lo".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn isolated_pak_contract_requires_wrapper_preflight_and_runs_shared_contract() {
    if let Err(error) = preflight() {
        panic!(
            "pak_isolated requires wrapper-provided {ISOLATION_MODE_ENV}={DECLARED_ISOLATION_MODE}, distinct {PARENT_NETNS_ENV}, no default route, and only lo: {error}"
        );
    }
    pak_harness::run_contract("pak-isolated");
}

#[cfg(not(target_os = "linux"))]
#[test]
fn isolated_pak_contract_requires_linux() {
    panic!("pak_isolated requires Linux network namespace prerequisites");
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::{has_ipv4_default_route, has_ipv6_default_route, namespace_identity};
    use std::fs;

    #[test]
    fn route_parsers_only_match_default_routes() {
        let header =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT  ";
        assert!(
            has_ipv4_default_route(&format!(
                "{header}\neth0 00000000 00000000 0003 0 0 0 00000000 0 0 0"
            ))
            .unwrap()
        );
        assert!(
            !has_ipv4_default_route(&format!(
                "{header}\neth0 01000000 00000000 0003 0 0 0 00000000 0 0 0"
            ))
            .unwrap()
        );
        assert!(
            has_ipv4_default_route(&format!(
                "{header}\neth0 00000000 01000000 0003 0 0 0 00000000 0 0 0"
            ))
            .unwrap()
        );
        let ipv6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo";
        assert!(has_ipv6_default_route(ipv6).unwrap());
        assert!(!has_ipv6_default_route(&ipv6.replacen(" 00 ", " 80 ", 1)).unwrap());
        assert!(
            !has_ipv6_default_route(&ipv6.replacen(
                "00000000000000000000000000000000 00",
                "00000000000000000000000000000001 00",
                1
            ))
            .unwrap()
        );
    }

    #[test]
    fn namespace_identity_requires_kernel_net_inode_format() {
        let path = std::env::temp_dir().join(format!("nrr-netns-test-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        #[cfg(unix)]
        std::os::unix::fs::symlink("not-a-netns", &path).expect("create test link");
        assert!(namespace_identity(&path).is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn current_proc_route_files_are_parseable() {
        let ipv4 = fs::read_to_string("/proc/net/route").expect("read IPv4 routes");
        let ipv6 = fs::read_to_string("/proc/net/ipv6_route").expect("read IPv6 routes");
        assert!(has_ipv4_default_route(&ipv4).is_ok());
        assert!(has_ipv6_default_route(&ipv6).is_ok());
    }
}
