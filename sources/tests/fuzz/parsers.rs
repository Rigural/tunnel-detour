#![no_main]

//! Synthetic inputs only. No router, DNS provider or host network access.

use std::{
    error::Error,
    fs,
    num::NonZeroUsize,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Mutex, OnceLock},
    time::Duration,
};

use libfuzzer_sys::fuzz_target;
use tunnel_detour_core::{
    DomainName, DomainPattern, ExceptionPolicy, FakeIpRange, LeaseStore, RuleSet, Timestamp,
    answer_dns,
};
use tunnel_detour_service::{InboundConfig, ServiceConfig};

struct Fixture {
    _directory: tempfile::TempDir,
    policy: ExceptionPolicy,
    path: PathBuf,
    durable: Vec<u8>,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("leases.json");
        let capacity = NonZeroUsize::new(1).ok_or("invalid fuzz capacity")?;
        let mut store = LeaseStore::open(&path, "198.18.0.0/28".parse()?, capacity)?;
        store.issue(
            &"selected.example.test".parse()?,
            Timestamp::from_unix_seconds(100),
            Duration::from_secs(3600),
        )?;
        let durable = fs::read(&path)?;
        let mut policy = ExceptionPolicy::new(
            RuleSet::from_lines("selected.example.test", capacity)?,
            store,
            Duration::from_secs(3600),
        )?;
        policy.set_mapping_limit_per_rule(capacity);
        Ok(Self {
            _directory: directory,
            policy,
            path,
            durable,
        })
    }
}

fn exercise(data: &[u8]) -> Result<(), Box<dyn Error>> {
    if data.len() > 65_536 {
        return Ok(());
    }
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(domain) = text.parse::<DomainName>() {
            assert_eq!(
                domain.as_str().parse::<DomainName>()?,
                domain,
                "normalization must be idempotent"
            );
            assert!(
                domain.as_str().len() <= 253,
                "normalized hostname exceeded DNS bounds"
            );
        }
        if let Ok(pattern) = text.parse::<DomainPattern>() {
            assert_eq!(
                pattern.to_string().parse::<DomainPattern>()?,
                pattern,
                "pattern mode changed on round trip"
            );
        }
        let capacity = NonZeroUsize::new(16).ok_or("invalid fuzz rule capacity")?;
        if let Ok(rules) = RuleSet::from_lines(text, capacity) {
            assert!(rules.rules().len() <= 16, "rule capacity was bypassed");
        }
    }
    // These constructors validate data only; neither applies OS or network changes.
    let _configuration = ServiceConfig::from_json(data);
    let _inbound = InboundConfig::from_json(data);
    tunnel_detour_service::fuzz_private_state_parsers(data)?;

    static FIXTURE: OnceLock<Result<Mutex<Fixture>, String>> = OnceLock::new();
    let fixture = FIXTURE.get_or_init(|| {
        Fixture::new()
            .map(Mutex::new)
            .map_err(|error| error.to_string())
    });
    let fixture = fixture
        .as_ref()
        .map_err(|error| format!("fuzz fixture initialization: {error}"))?;
    let mut fixture = fixture.lock().map_err(|_| "fuzz fixture was poisoned")?;
    let _answer = answer_dns(&mut fixture.policy, data, Timestamp::from_unix_seconds(101));
    assert_eq!(
        fixture.policy.mapping_usage()?.allocated,
        1,
        "arbitrary packets allocated an unauthorized hostname"
    );
    assert_eq!(
        fs::read(&fixture.path)?,
        fixture.durable,
        "invalid/ordinary/warm DNS changed durable identities"
    );

    // The allocator's recovery snapshot decoder is also an untrusted boundary.
    // Give every input a new private directory so lock/recovery history is deterministic.
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("candidate.json");
    fs::write(&path, data)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let range: FakeIpRange = "198.18.0.0/28".parse()?;
    let capacity = NonZeroUsize::new(8).ok_or("invalid snapshot capacity")?;
    if let Ok(store) = LeaseStore::open(&path, range, capacity) {
        assert!(
            store.table()?.len() <= capacity.get(),
            "snapshot bypassed allocator capacity"
        );
    }
    assert_eq!(
        fs::read(path)?,
        data,
        "decoding arbitrary snapshots modified the source"
    );
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    if let Err(error) = exercise(data) {
        panic!("fuzz setup or oracle failed: {error}");
    }
});
