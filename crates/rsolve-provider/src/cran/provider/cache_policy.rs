use std::time::Duration;

/// The cache action selected from a validated Cache-Control header.
#[cfg_attr(not(test), expect(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheControlPolicy {
    /// The representation must not be retained for later reuse.
    NoStore,
    /// The representation may be retained, but must be revalidated.
    Revalidate,
    /// The server supplied a valid freshness lifetime.
    MaxAge(Duration),
    /// No server lifetime was supplied; use the provider fallback.
    Fallback(Duration),
}

#[cfg_attr(not(test), expect(dead_code))]
impl CacheControlPolicy {
    pub fn can_store(self) -> bool {
        !matches!(self, Self::NoStore)
    }

    pub fn ttl(self) -> Option<Duration> {
        match self {
            Self::MaxAge(ttl) | Self::Fallback(ttl) => Some(ttl),
            Self::NoStore | Self::Revalidate => None,
        }
    }
}

/// Resolve Cache-Control precedence without depending on transport or cache
/// storage. Unknown extension directives are intentionally ignored.
#[cfg_attr(not(test), expect(dead_code))]
pub fn cache_control_policy(header: Option<&str>, fallback_ttl: Duration) -> CacheControlPolicy {
    let Some(header) = header else {
        return CacheControlPolicy::Fallback(fallback_ttl);
    };
    if header.trim().is_empty() {
        return CacheControlPolicy::Revalidate;
    }

    let mut saw_directive = false;
    let mut no_store = false;
    let mut no_cache = false;
    let mut max_age = None;
    let mut malformed_known = false;

    for raw_directive in header.split(',') {
        let directive = raw_directive.trim();
        if directive.is_empty() {
            malformed_known = true;
            continue;
        }
        let (name, value) = directive
            .split_once('=')
            .map_or((directive, None), |(name, value)| {
                (name.trim(), Some(value.trim()))
            });
        let name = name.to_ascii_lowercase();
        match name.as_str() {
            "no-store" => {
                saw_directive = true;
                malformed_known |= value.is_some();
                no_store = true;
            }
            "no-cache" => {
                saw_directive = true;
                malformed_known |= value.is_some();
                no_cache = true;
            }
            "max-age" => {
                saw_directive = true;
                let Some(value) = value else {
                    malformed_known = true;
                    continue;
                };
                let Ok(seconds) = value.parse::<u64>() else {
                    malformed_known = true;
                    continue;
                };
                let candidate = Duration::from_secs(seconds);
                if let Some(previous) = max_age {
                    if previous != candidate {
                        malformed_known = true;
                    }
                } else {
                    max_age = Some(candidate);
                }
            }
            _ => {}
        }
    }

    if malformed_known {
        return if no_store {
            CacheControlPolicy::NoStore
        } else {
            CacheControlPolicy::Revalidate
        };
    }
    if !saw_directive {
        return CacheControlPolicy::Fallback(fallback_ttl);
    }
    if no_store {
        CacheControlPolicy::NoStore
    } else if no_cache {
        CacheControlPolicy::Revalidate
    } else if let Some(max_age) = max_age {
        CacheControlPolicy::MaxAge(max_age)
    } else {
        CacheControlPolicy::Fallback(fallback_ttl)
    }
}

/// Future observations never qualify as fresh, even when a server supplied a
/// positive lifetime.
#[cfg_attr(not(test), expect(dead_code))]
pub fn permits_reuse(
    now: jiff::Timestamp,
    observed_at: jiff::Timestamp,
    policy: CacheControlPolicy,
) -> bool {
    if observed_at > now {
        return false;
    }
    let Some(ttl) = policy.ttl() else {
        return false;
    };
    now.duration_since(observed_at)
        .try_into()
        .is_ok_and(|age: Duration| age <= ttl)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FALLBACK: Duration = Duration::from_secs(3600);

    #[test]
    fn cache_control_precedence_is_conservative() {
        assert_eq!(
            cache_control_policy(None, FALLBACK),
            CacheControlPolicy::Fallback(FALLBACK)
        );
        assert_eq!(
            cache_control_policy(Some("max-age=120"), FALLBACK),
            CacheControlPolicy::MaxAge(Duration::from_secs(120))
        );
        assert_eq!(
            cache_control_policy(Some("no-cache, max-age=120"), FALLBACK),
            CacheControlPolicy::Revalidate
        );
        assert!(cache_control_policy(Some("no-cache"), FALLBACK).can_store());
        assert_eq!(cache_control_policy(Some("no-cache"), FALLBACK).ttl(), None);
        assert_eq!(
            cache_control_policy(Some("no-store, max-age=120"), FALLBACK),
            CacheControlPolicy::NoStore
        );
        assert!(!cache_control_policy(Some("no-store"), FALLBACK).can_store());
        assert_eq!(cache_control_policy(Some("no-store"), FALLBACK).ttl(), None);
    }

    #[test]
    fn malformed_known_directives_revalidate_and_unknown_extensions_are_ignored() {
        assert_eq!(
            cache_control_policy(Some("max-age=not-a-number"), FALLBACK),
            CacheControlPolicy::Revalidate
        );
        assert_eq!(
            cache_control_policy(Some("max-age=1, max-age=2"), FALLBACK),
            CacheControlPolicy::Revalidate
        );
        assert_eq!(
            cache_control_policy(Some("max-age=18446744073709551616"), FALLBACK),
            CacheControlPolicy::Revalidate
        );
        assert_eq!(
            cache_control_policy(Some("x-provider-extension=value"), FALLBACK),
            CacheControlPolicy::Fallback(FALLBACK)
        );
        assert_eq!(
            cache_control_policy(Some("x-provider-extension=value, max-age=120"), FALLBACK),
            CacheControlPolicy::MaxAge(Duration::from_secs(120))
        );
    }

    #[test]
    fn future_observation_is_never_reusable() {
        let observed = "2026-08-23T00:00:01Z".parse().unwrap();
        let now = "2026-08-23T00:00:00Z".parse().unwrap();
        assert!(!permits_reuse(
            now,
            observed,
            CacheControlPolicy::MaxAge(Duration::from_secs(3600))
        ));
    }

    #[test]
    fn freshness_lifetime_has_an_inclusive_boundary() {
        let observed = "2026-08-23T00:00:00Z".parse().unwrap();
        let at_boundary = "2026-08-23T00:02:00Z".parse().unwrap();
        let beyond_boundary = "2026-08-23T00:02:01Z".parse().unwrap();
        let policy = CacheControlPolicy::MaxAge(Duration::from_secs(120));
        assert!(permits_reuse(at_boundary, observed, policy));
        assert!(!permits_reuse(beyond_boundary, observed, policy));
    }
}
