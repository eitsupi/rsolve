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
const ISOLATION_MODE_ENV: &str = "RSOLVE_PAK_ISOLATION_MODE";
#[cfg(target_os = "linux")]
const PARENT_NETNS_ENV: &str = "RSOLVE_PAK_PARENT_NETNS";
#[cfg(target_os = "linux")]
const PARENT_USERNS_ENV: &str = "RSOLVE_PAK_PARENT_USERNS";
#[cfg(target_os = "linux")]
const PARENT_PIDNS_ENV: &str = "RSOLVE_PAK_PARENT_PIDNS";
#[cfg(target_os = "linux")]
const DECLARED_ISOLATION_MODE: &str = "linux-user-pid-netns-v1";

#[cfg(target_os = "linux")]
fn namespace_identity(path: &Path, kind: &str) -> Result<String, String> {
    let identity = fs::read_link(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?
        .to_string_lossy()
        .into_owned();
    let valid = identity
        .strip_prefix(&format!("{kind}:["))
        .and_then(|value| value.strip_suffix(']'))
        .is_some_and(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()));
    if !valid {
        return Err(format!("invalid {kind} namespace identity: {identity:?}"));
    }
    Ok(identity)
}

#[cfg(target_os = "linux")]
fn has_ipv4_default_route(contents: &str) -> Result<bool, String> {
    if contents.trim().is_empty() {
        return Ok(false);
    }
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
        Ok(found || (fields[0] != "lo" && fields[1] == "00000000" && fields[7] == "00000000"))
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
        Ok(found
            || (fields[9] != "lo"
                && fields[0] == "00000000000000000000000000000000"
                && fields[1] == "00"))
    })
}

#[cfg(target_os = "linux")]
fn parse_interfaces(contents: &str) -> Result<std::collections::BTreeSet<String>, String> {
    let mut lines = contents.lines();
    let first: Vec<_> = lines
        .next()
        .ok_or_else(|| "missing /proc/net/dev header".to_owned())?
        .split_whitespace()
        .collect();
    let second: Vec<_> = lines
        .next()
        .ok_or_else(|| "missing /proc/net/dev header".to_owned())?
        .split_whitespace()
        .collect();
    if first != ["Inter-|", "Receive", "|", "Transmit"]
        || second
            != [
                "face",
                "|bytes",
                "packets",
                "errs",
                "drop",
                "fifo",
                "frame",
                "compressed",
                "multicast|bytes",
                "packets",
                "errs",
                "drop",
                "fifo",
                "colls",
                "carrier",
                "compressed",
            ]
    {
        return Err("malformed /proc/net/dev header".into());
    }
    let mut interfaces = std::collections::BTreeSet::new();
    for line in lines {
        let (name, counters) = line
            .split_once(':')
            .ok_or_else(|| "malformed /proc/net/dev interface record".to_owned())?;
        let name = name.trim();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
            || !interfaces.insert(name.to_owned())
        {
            return Err("malformed or duplicate /proc/net/dev interface".into());
        }
        let counters: Vec<_> = counters.split_whitespace().collect();
        if counters.len() != 16 || counters.iter().any(|value| value.parse::<u64>().is_err()) {
            return Err("malformed /proc/net/dev counters".into());
        }
    }
    if interfaces.is_empty() {
        return Err("/proc/net/dev has no interfaces".into());
    }
    Ok(interfaces)
}

#[cfg(target_os = "linux")]
fn preflight() -> Result<(), String> {
    if env::var("RSOLVE_TEST_MODE").as_deref() != Ok("pak-isolated") {
        return Err("RSOLVE_TEST_MODE must be pak-isolated".into());
    }
    if env::var(ISOLATION_MODE_ENV).as_deref() != Ok(DECLARED_ISOLATION_MODE) {
        return Err(format!(
            "{ISOLATION_MODE_ENV} must be {DECLARED_ISOLATION_MODE}"
        ));
    }
    for (env_name, kind, proc_path) in [
        (PARENT_USERNS_ENV, "user", "/proc/self/ns/user"),
        (PARENT_PIDNS_ENV, "pid", "/proc/self/ns/pid"),
        (PARENT_NETNS_ENV, "net", "/proc/self/ns/net"),
    ] {
        let parent = env::var(env_name)
            .map_err(|_| format!("{env_name} must be supplied by the isolation wrapper"))?;
        let parent = parse_namespace_identity(&parent, kind)
            .map_err(|error| format!("{env_name}: {error}"))?;
        let current = namespace_identity(Path::new(proc_path), kind)?;
        if parent == current {
            return Err(format!(
                "isolated test is running in the wrapper parent {kind} namespace"
            ));
        }
    }
    if has_ipv4_default_route(
        &fs::read_to_string("/proc/net/route").map_err(|error| error.to_string())?,
    )? || has_ipv6_default_route(
        &fs::read_to_string("/proc/net/ipv6_route").map_err(|error| error.to_string())?,
    )? {
        return Err("isolated network namespace has a default route".into());
    }
    let interfaces = parse_interfaces(
        &fs::read_to_string("/proc/net/dev")
            .map_err(|error| format!("cannot read /proc/net/dev: {error}"))?,
    )?;
    if interfaces != std::iter::once("lo".to_owned()).collect() {
        return Err("isolated network namespace interfaces must contain only lo".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn parse_namespace_identity(identity: &str, kind: &str) -> Result<String, String> {
    let prefix = format!("{kind}:[");
    if identity
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix(']'))
        .is_some_and(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
    {
        Ok(identity.to_owned())
    } else {
        Err(format!("expected {kind}:[digits], got {identity:?}"))
    }
}

#[cfg(target_os = "linux")]
#[test]
fn isolated_pak_contract_requires_wrapper_preflight_and_runs_shared_contract() {
    if let Err(error) = preflight() {
        panic!(
            "pak_isolated requires wrapper-provided {ISOLATION_MODE_ENV}={DECLARED_ISOLATION_MODE}, distinct user/pid/net parent identities, no default route, and only lo: {error}"
        );
    }
    let fixture = std::env::var_os("RSOLVE_PAK_FIXTURE_ROOT")
        .map(std::path::PathBuf::from)
        .expect("RSOLVE_PAK_FIXTURE_ROOT must be supplied by the isolation wrapper");
    pak_harness::run_contract("pak-isolated", &fixture);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn isolated_pak_contract_requires_linux() {
    panic!("pak_isolated requires Linux network namespace prerequisites");
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::{
        has_ipv4_default_route, has_ipv6_default_route, namespace_identity, parse_interfaces,
        parse_namespace_identity,
    };
    use std::fs;

    #[test]
    fn route_parsers_only_match_default_routes() {
        assert!(!has_ipv4_default_route("").unwrap());
        assert!(!has_ipv4_default_route(" \n\t").unwrap());
        assert!(!has_ipv6_default_route("").unwrap());
        assert!(has_ipv4_default_route("not a route header").is_err());
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
        assert!(
            !has_ipv4_default_route(&format!(
                "{header}\nlo 00000000 00000000 0003 0 0 0 00000000 0 0 0"
            ))
            .unwrap()
        );
        let ipv6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo";
        assert!(!has_ipv6_default_route(ipv6).unwrap());
        assert!(has_ipv6_default_route(&ipv6.replacen(" lo", " eth0", 1)).unwrap());
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
    fn proc_net_dev_parser_requires_only_lo_and_strict_records() {
        let header = "Inter-|  Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed";
        let counters = "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
        let only_lo = format!("{header}\nlo: {counters}");
        assert_eq!(
            parse_interfaces(&only_lo)
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>(),
            vec!["lo"]
        );
        let with_eth0 = format!("{only_lo}\neth0: {counters}");
        assert!(parse_interfaces(&with_eth0).unwrap().contains("eth0"));
        assert!(parse_interfaces(&format!("{header}\nlo: {counters}\nlo: {counters}")).is_err());
        assert!(parse_interfaces("malformed").is_err());
        assert!(parse_interfaces(&format!("{header}\nlo: 1 2")).is_err());
    }

    #[test]
    fn current_proc_net_dev_is_parseable() {
        let contents = fs::read_to_string("/proc/net/dev").expect("read /proc/net/dev");
        assert!(!super::parse_interfaces(&contents).unwrap().is_empty());
    }

    #[test]
    fn namespace_identity_requires_kernel_net_inode_format() {
        let path = std::env::temp_dir().join(format!("rsolve-netns-test-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        #[cfg(unix)]
        std::os::unix::fs::symlink("not-a-netns", &path).expect("create test link");
        assert!(namespace_identity(&path, "net").is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn namespace_identity_accepts_only_the_requested_kind() {
        assert_eq!(
            parse_namespace_identity("user:[123]", "user").unwrap(),
            "user:[123]"
        );
        assert!(parse_namespace_identity("net:[123]", "user").is_err());
        assert!(parse_namespace_identity("pid:[x]", "pid").is_err());
        assert!(parse_namespace_identity("pid:[123]", "net").is_err());
    }

    #[test]
    fn current_proc_route_files_are_parseable() {
        let ipv4 = fs::read_to_string("/proc/net/route").expect("read IPv4 routes");
        let ipv6 = fs::read_to_string("/proc/net/ipv6_route").expect("read IPv6 routes");
        assert!(has_ipv4_default_route(&ipv4).is_ok());
        assert!(has_ipv6_default_route(&ipv6).is_ok());
    }
}
