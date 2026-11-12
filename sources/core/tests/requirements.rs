//! Each test owns one requirement. Fixtures contain only synthetic domains and local state.
//! These are library and real-filesystem tests; they do not claim router/network validation.

use std::{
    error::Error,
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroUsize,
    path::PathBuf,
    time::Duration,
};

use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        DNSClass, Name, RData, Record, RecordType,
        rdata::{
            A, AAAA, HTTPS, SVCB,
            svcb::{
                Alpn, EchConfigList, IpHint, Mandatory, SvcParamKey as Key, SvcParamValue as Value,
                Unknown,
            },
        },
    },
};
use tempfile::TempDir;
use tunnel_detour_core::{
    ConnectionError, DnsAddressFamilies, DnsDecision, DnsQuestionType, DomainName, DomainPattern,
    ExceptionPolicy, FakeIpError, FakeIpRange, LeaseStore, LeaseTable, MatchScope, Rule, RuleSet,
    RuleSetError, StoreError, Timestamp,
};
use tunnel_detour_core::{DnsWireDecision, DnsWireError, answer_dns, validate_upstream_reply};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn r131_rule_budgets_preserve_other_rules_and_permanent_identities_across_restart() -> TestResult {
    let fixture = StateFixture::new()?;
    let rules = RuleSet::from_lines(
        "***.scoped.example.test\nother.example.test\nreserved.scoped.example.test",
        NonZeroUsize::new(3).ok_or("rule capacity")?,
    )?;
    let first: DomainName = "one.scoped.example.test".parse()?;
    let second: DomainName = "two.scoped.example.test".parse()?;
    let excess: DomainName = "three.scoped.example.test".parse()?;
    let mut policy = ExceptionPolicy::new(rules.clone(), fixture.open()?, Duration::from_secs(60))?;
    policy.set_mapping_limit_per_rule(NonZeroUsize::new(2).ok_or("mapping limit")?);
    let DnsDecision::Synthetic(original) =
        policy.decide_dns(&first, DnsQuestionType::A, instant(100))?
    else {
        return Err("first hostname was not issued".into());
    };
    policy.decide_dns(&second, DnsQuestionType::A, instant(100))?;
    let before = fs::read(&fixture.path)?;
    assert!(matches!(
        policy.decide_dns(&excess, DnsQuestionType::A, instant(100)),
        Err(StoreError::Lease(FakeIpError::RuleCapacity))
    ));
    assert_eq!(fs::read(&fixture.path)?, before);
    for name in ["other.example.test", "reserved.scoped.example.test"] {
        assert!(matches!(
            policy.decide_dns(&name.parse()?, DnsQuestionType::A, instant(100))?,
            DnsDecision::Synthetic(_)
        ));
    }
    assert_eq!(policy.mapping_usage()?.allocated, 4);
    drop(policy);
    let mut restored = ExceptionPolicy::new(rules, fixture.open()?, Duration::from_secs(60))?;
    restored.set_mapping_limit_per_rule(NonZeroUsize::new(2).ok_or("mapping limit")?);
    assert!(matches!(
        restored.decide_dns(&excess, DnsQuestionType::A, instant(200)),
        Err(StoreError::Lease(FakeIpError::RuleCapacity))
    ));
    let DnsDecision::Synthetic(renewed) =
        restored.decide_dns(&first, DnsQuestionType::A, instant(200))?
    else {
        return Err("known hostname did not renew".into());
    };
    assert_eq!(renewed.address(), original.address());
    assert_eq!(renewed.ipv6_address(), original.ipv6_address());
    assert_eq!(restored.mapping_usage()?.allocated, 4);
    let saved = fs::read(&fixture.path)?;
    restored.decide_dns(&first, DnsQuestionType::A, instant(201))?;
    assert_eq!(
        fs::read(&fixture.path)?,
        saved,
        "warm known identities must not be rewritten"
    );
    Ok(())
}

#[test]
fn r101_ipv6_identities_derive_from_legacy_leases_without_reassignment_or_new_persistent_fields()
-> TestResult {
    let fixture = StateFixture::new()?;
    // A literal version-1 snapshot represents an already installed IPv4 allocator.
    // Expected addresses below are independently specified, not encoded by the API.
    let legacy = br#"{"version":1,"range":"198.18.0.0/28","last_issued_at":100,"entries":[{"domain":"one.example.test","address":"198.18.0.1","issued_at":100,"expires_at":160}]}"#;
    fs::write(&fixture.path, legacy)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o600))?;
    }
    let mut store = fixture.open()?;
    let first: Ipv6Addr = "2001:2::c612:1".parse()?;
    assert_eq!(
        store.table()?.range().ipv6_range().to_string(),
        "2001:2::c612:0/124"
    );
    let old = store.table()?.lookup_ipv6(first, instant(120))?;
    assert_eq!(old.domain().as_str(), "one.example.test");
    assert_eq!(old.address(), Ipv4Addr::new(198, 18, 0, 1));
    assert_eq!(old.ipv6_address(), first);
    assert_eq!(
        fs::read(&fixture.path)?,
        legacy,
        "opening must not rewrite legacy state"
    );
    for rejected in [
        "2001:2::c612:0",     // IPv4 network identity is never allocated.
        "2001:2::c612:f",     // IPv4 broadcast identity is never allocated.
        "2001:2::c612:2",     // In range, but not issued yet.
        "2001:2::c612:10",    // Outside the configured /28.
        "2001:2::c613:1",     // Another IPv4 benchmark subnet.
        "2001:2:0:1::c612:1", // Low 32 bits alone are insufficient.
        "::ffff:198.18.0.1",
        "::1",
    ] {
        assert_eq!(
            store.table()?.lookup_ipv6(rejected.parse()?, instant(120)),
            Err(FakeIpError::UnknownAddress),
            "accepted an unowned IPv6 identity: {rejected}"
        );
    }
    assert_eq!(
        store.table()?.lookup_ipv6(first, instant(160)),
        Err(FakeIpError::Expired)
    );
    let second = store.issue(
        &"two.example.test".parse()?,
        instant(200),
        Duration::from_secs(60),
    )?;
    assert_eq!(second.ipv6_address(), "2001:2::c612:2".parse::<Ipv6Addr>()?);
    assert_eq!(
        store.table()?.lookup_ipv6(first, instant(200)),
        Err(FakeIpError::Expired)
    );
    let renewed = store.issue(
        &"one.example.test".parse()?,
        instant(200),
        Duration::from_secs(60),
    )?;
    assert_eq!(renewed.ipv6_address(), first);
    assert_eq!(
        store.table()?.len(),
        2,
        "paired identities must not consume separate slots"
    );
    assert_eq!(
        store.table()?.lookup_ipv6(first, instant(199)),
        Err(FakeIpError::ClockReversed)
    );
    drop(store);
    let reopened = fixture.open()?;
    assert_eq!(
        reopened.table()?.lookup_ipv6(first, instant(220))?,
        &renewed
    );
    assert_eq!(
        reopened.table()?.lookup(renewed.address(), instant(220))?,
        &renewed
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(&fixture.path)?)?,
        serde_json::json!({
            "version": 1, "range": "198.18.0.0/28", "last_issued_at": 200,
            "entries": [
                {"domain": "one.example.test", "address": "198.18.0.1", "issued_at": 200, "expires_at": 260},
                {"domain": "two.example.test", "address": "198.18.0.2", "issued_at": 200, "expires_at": 260}
            ]
        }),
        "IPv6 derivation must preserve the legacy persistent format"
    );
    for (ipv4, expected, last) in [
        ("198.18.0.0/15", "2001:2::c612:0/111", "2001:2::c613:fffe"),
        (
            "198.19.255.252/30",
            "2001:2::c613:fffc/126",
            "2001:2::c613:fffe",
        ),
    ] {
        let range: FakeIpRange = ipv4.parse()?;
        assert_eq!(range.ipv6_range().to_string(), expected);
        assert_eq!(
            range.ipv4_identity(last.parse()?),
            Some(Ipv4Addr::new(198, 19, 255, 254))
        );
    }
    Ok(())
}

#[test]
fn r036_repeated_dns_queries_reuse_a_durable_deadline_to_bound_flash_writes_without_extending_unpersisted_ttls()
-> TestResult {
    let fixture = StateFixture::new()?;
    let mut policy = ExceptionPolicy::with_families(
        rules(true)?,
        fixture.open()?,
        Duration::from_secs(60),
        DnsAddressFamilies::DualStack,
    )?;
    let query = dns_query("selected.example.test", RecordType::A)?;
    let first = dns_reply(answer_dns(&mut policy, &query, instant(100))?)?;
    assert_eq!(first.answers[0].ttl, 60);
    let snapshot = fs::read(&fixture.path)?;
    fs::File::open(&fixture.path)?
        .set_times(fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH))?;
    let query6 = dns_query("selected.example.test", RecordType::AAAA)?;
    let first6 = dns_reply(answer_dns(&mut policy, &query6, instant(100))?)?;
    for second in 101..=130 {
        for (query, original) in [(&query, &first), (&query6, &first6)] {
            let response = dns_reply(answer_dns(&mut policy, query, instant(second))?)?;
            assert_eq!(response.answers[0].ttl, 160 - u32::try_from(second)?);
            assert_eq!(response.answers[0].data, original.answers[0].data);
            assert_eq!(
                fs::metadata(&fixture.path)?.modified()?,
                std::time::UNIX_EPOCH,
                "a cached durable lease was unnecessarily rewritten"
            );
        }
    }
    assert_eq!(fs::read(&fixture.path)?, snapshot);
    let renewed = dns_reply(answer_dns(&mut policy, &query, instant(131))?)?;
    assert_eq!(renewed.answers[0].ttl, 60);
    assert_eq!(renewed.answers[0].data, first.answers[0].data);
    assert_ne!(
        fs::metadata(&fixture.path)?.modified()?,
        std::time::UNIX_EPOCH
    );
    assert_ne!(
        fs::read(&fixture.path)?,
        snapshot,
        "renewal must be persisted before its full TTL is returned"
    );
    Ok(())
}

fn count(value: usize) -> Result<NonZeroUsize, Box<dyn Error>> {
    NonZeroUsize::new(value).ok_or_else(|| "test capacity must be positive".into())
}

fn instant(seconds: u64) -> Timestamp {
    Timestamp::from_unix_seconds(seconds)
}

fn rules(enabled: bool) -> Result<RuleSet, Box<dyn Error>> {
    Ok(RuleSet::new(
        vec![Rule {
            pattern: DomainPattern {
                domain: "example.test".parse()?,
                scope: MatchScope::DomainAndSubdomains,
            },
            enabled,
        }],
        count(16)?,
    )?)
}

struct StateFixture {
    _directory: TempDir,
    path: PathBuf,
}

impl StateFixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        }
        let path = directory.path().join("leases.json");
        Ok(Self {
            _directory: directory,
            path,
        })
    }

    fn open(&self) -> Result<LeaseStore, StoreError> {
        let capacity = NonZeroUsize::new(8).ok_or(FakeIpError::Exhausted)?;
        LeaseStore::open(&self.path, "198.18.0.0/28".parse()?, capacity)
    }
}

#[test]
fn r001_hostnames_are_normalized_and_invalid_external_values_are_rejected() -> TestResult {
    assert!(
        format!("{}example.test", "\u{00ad}".repeat(1024))
            .parse::<DomainName>()
            .is_err(),
        "ignored IDNA characters must not bypass the input resource bound"
    );
    assert_eq!(
        "WWW.Example.Test.".parse::<DomainName>()?.as_str(),
        "www.example.test"
    );
    assert_eq!(
        "bücher.test".parse::<DomainName>()?.as_str(),
        "xn--bcher-kva.test"
    );
    assert_eq!(
        "cdn---edge.example.test".parse::<DomainName>()?.as_str(),
        "cdn---edge.example.test"
    );
    for invalid in [
        "",
        ".",
        "example.test..",
        "bad..test",
        "https://example.test",
        "example.test:443",
        "*.example.test",
        "bad_label.test",
        "-bad.test",
        "bad-.test",
        " example.test",
        "example.test ",
        "127.0.0.1",
        "::1",
        "example.test/path",
        "example.test\n",
    ] {
        assert!(
            invalid.parse::<DomainName>().is_err(),
            "accepted invalid hostname {invalid:?}"
        );
    }
    assert!(
        format!("{}.test", "a".repeat(64))
            .parse::<DomainName>()
            .is_err()
    );
    assert!(
        vec!["a".repeat(63); 5]
            .join(".")
            .parse::<DomainName>()
            .is_err()
    );
    Ok(())
}

#[test]
fn r002_explicit_wildcard_modes_respect_label_boundaries_and_root_selection() -> TestResult {
    let cases = [
        ("example.test", [true, false, false, true]),
        ("one.example.test", [false, true, true, true]),
        ("two.one.example.test", [false, false, true, true]),
        ("otherexample.test", [false; 4]),
        ("example.test.other.test", [false; 4]),
    ];
    for (candidate, expected) in cases {
        for (input, selected) in [
            "example.test",
            "*.example.test",
            "**.example.test",
            "***.example.test",
        ]
        .into_iter()
        .zip(expected)
        {
            let pattern: DomainPattern = input.parse()?;
            assert_eq!(
                pattern.matches(&candidate.parse()?),
                selected,
                "{input}: {candidate}"
            );
        }
    }
    assert_eq!(
        "**.EXAMPLE.TEST".parse::<DomainPattern>()?.scope,
        MatchScope::AllSubdomains
    );
    for invalid in [
        "*",
        "*example.test",
        "one.*.test",
        "*.*.example.test",
        "****.example.test",
    ] {
        assert!(invalid.parse::<DomainPattern>().is_err());
    }
    assert_eq!(
        "***.EXAMPLE.TEST.".parse::<DomainPattern>()?.to_string(),
        "***.example.test"
    );
    Ok(())
}

#[test]
fn r003_rule_updates_support_disabling_removal_and_reject_ambiguous_duplicates() -> TestResult {
    let lines = RuleSet::from_lines(
        "example.test\n *.other.test\n\n **.deep.test\r\n***.all.test",
        count(4)?,
    )?;
    for name in [
        "example.test",
        "one.other.test",
        "one.two.deep.test",
        "all.test",
        "one.two.all.test",
    ] {
        assert!(lines.selects(&name.parse()?));
    }
    for name in ["other.test", "one.two.other.test", "deep.test"] {
        assert!(!lines.selects(&name.parse()?));
    }
    assert!(matches!(
        RuleSet::from_lines("example.test\n\n****.other.test", count(4)?),
        Err(RuleSetError::InvalidLine { line: 3, .. })
    ));
    assert!(matches!(
        RuleSet::from_lines("*.EXAMPLE.TEST\n*.example.test.", count(4)?),
        Err(RuleSetError::Duplicate)
    ));
    let name = "one.example.test".parse()?;
    assert!(rules(true)?.selects(&name));
    assert!(!rules(false)?.selects(&name));
    assert!(!RuleSet::new(vec![], count(1)?)?.selects(&name));
    let rule = rules(true)?.rules()[0].clone();
    assert_eq!(
        RuleSet::new(vec![rule.clone(), rule.clone()], count(2)?).err(),
        Some(RuleSetError::Duplicate)
    );
    assert_eq!(
        RuleSet::new(vec![rule.clone(), rule], count(1)?).err(),
        Some(RuleSetError::Capacity)
    );
    Ok(())
}

#[test]
fn r004_each_hostname_keeps_a_distinct_synthetic_identity_without_real_ip_inputs() -> TestResult {
    let mut table = LeaseTable::new("198.18.0.0/29".parse()?, count(6)?)?;
    let first = table.issue(
        &"one.example.test".parse()?,
        instant(100),
        Duration::from_secs(60),
    )?;
    let second = table.issue(
        &"two.example.test".parse()?,
        instant(100),
        Duration::from_secs(60),
    )?;
    assert_eq!(first.address(), Ipv4Addr::new(198, 18, 0, 1));
    assert_eq!(second.address(), Ipv4Addr::new(198, 18, 0, 2));
    assert_eq!(
        table
            .lookup(first.address(), instant(120))?
            .domain()
            .as_str(),
        "one.example.test"
    );
    assert_eq!(
        table
            .lookup(second.address(), instant(120))?
            .domain()
            .as_str(),
        "two.example.test"
    );
    Ok(())
}

#[test]
fn r005_expired_addresses_are_never_reassigned_and_renewals_keep_their_identity() -> TestResult {
    let mut table = LeaseTable::new("198.18.0.0/29".parse()?, count(6)?)?;
    let name = "one.example.test".parse()?;
    let original = table.issue(&name, instant(100), Duration::from_secs(60))?;
    let other = table.issue(
        &"two.example.test".parse()?,
        instant(200),
        Duration::from_secs(60),
    )?;
    assert_ne!(original.address(), other.address());
    let renewed = table.issue(&name, instant(200), Duration::from_secs(60))?;
    assert_eq!(renewed.address(), original.address());
    assert_eq!(renewed.expires_at(), instant(260));
    let shorter = table.issue(&name, instant(210), Duration::from_secs(1))?;
    assert_eq!(shorter.expires_at(), instant(260));
    assert_eq!(table.len(), 2);
    Ok(())
}

#[test]
fn r006_exhaustion_clock_reversal_and_overflow_do_not_modify_allocations() -> TestResult {
    let mut table = LeaseTable::new("198.18.0.0/30".parse()?, count(1)?)?;
    let name = "one.example.test".parse()?;
    let lease = table.issue(&name, instant(100), Duration::from_secs(60))?;
    assert_eq!(
        table.issue(
            &"two.example.test".parse()?,
            instant(200),
            Duration::from_secs(60)
        ),
        Err(FakeIpError::Exhausted)
    );
    assert_eq!(
        table.issue(&name, instant(99), Duration::from_secs(60)),
        Err(FakeIpError::ClockReversed)
    );
    assert_eq!(
        table.issue(&name, instant(u64::MAX), Duration::from_secs(1)),
        Err(FakeIpError::TimeOverflow)
    );
    for ttl in [
        Duration::ZERO,
        Duration::from_millis(1),
        Duration::from_secs(u64::from(u32::MAX) + 1),
    ] {
        assert_eq!(
            table.issue(&name, instant(100), ttl),
            Err(FakeIpError::InvalidTtl)
        );
    }
    assert_eq!(table.lookup(lease.address(), instant(120))?, &lease);
    assert_eq!(table.len(), 1);
    for invalid in [
        "10.0.0.0/24",
        "198.18.0.1/24",
        "198.18.0.0/31",
        "198.18.0.0/14",
    ] {
        assert!(invalid.parse::<FakeIpRange>().is_err());
    }
    Ok(())
}

#[test]
fn r007_a_real_filesystem_restart_preserves_addresses_and_advances_without_reuse() -> TestResult {
    let fixture = StateFixture::new()?;
    let mut store = fixture.open()?;
    let name = "one.example.test".parse()?;
    let first = store.issue(&name, instant(100), Duration::from_secs(60))?;
    drop(store);
    let mut reopened = fixture.open()?;
    assert_eq!(
        reopened.table()?.lookup(first.address(), instant(120))?,
        &first
    );
    let second = reopened.issue(
        &"two.example.test".parse()?,
        instant(200),
        Duration::from_secs(60),
    )?;
    assert_ne!(second.address(), first.address());
    assert_eq!(
        reopened
            .issue(&name, instant(200), Duration::from_secs(60))?
            .address(),
        first.address()
    );
    Ok(())
}

#[test]
fn r008_corrupt_or_incompatible_persisted_state_is_rejected_instead_of_reset() -> TestResult {
    let fixture = StateFixture::new()?;
    let mut store = fixture.open()?;
    store.issue(
        &"one.example.test".parse()?,
        instant(100),
        Duration::from_secs(60),
    )?;
    drop(store);
    let valid = fs::read(&fixture.path)?;
    let original: serde_json::Value = serde_json::from_slice(&valid)?;
    let mut future_version = original.clone();
    future_version["version"] = 99.into();
    let mut wrong_address = original.clone();
    wrong_address["entries"][0]["address"] = "198.18.0.8".into();
    let mut invalid_domain = original.clone();
    invalid_domain["entries"][0]["domain"] = "*.example.test".into();
    let mut invalid_deadline = original.clone();
    invalid_deadline["entries"][0]["expires_at"] = 1.into();
    for corrupt in [
        b"not json".to_vec(),
        serde_json::to_vec(&future_version)?,
        serde_json::to_vec(&wrong_address)?,
        serde_json::to_vec(&invalid_domain)?,
        serde_json::to_vec(&invalid_deadline)?,
    ] {
        fs::write(&fixture.path, &corrupt)?;
        assert!(fixture.open().is_err());
        assert_eq!(
            fs::read(&fixture.path)?,
            corrupt,
            "rejected state must not be overwritten"
        );
    }
    fs::write(&fixture.path, valid)?;
    assert!(LeaseStore::open(&fixture.path, "198.18.1.0/28".parse()?, count(8)?).is_err());
    Ok(())
}

#[test]
fn r009_concurrent_allocators_cannot_open_the_same_state() -> TestResult {
    let fixture = StateFixture::new()?;
    let first = fixture.open()?;
    assert!(matches!(fixture.open(), Err(StoreError::Lock(_))));
    drop(first);
    assert!(fixture.open().is_ok());
    Ok(())
}

#[test]
fn r010_uncertain_write_failure_poisoning_blocks_both_dns_issuance_and_lookup() -> TestResult {
    let fixture = StateFixture::new()?;
    let mut store = fixture.open()?;
    let first = store.issue(
        &"one.example.test".parse()?,
        instant(100),
        Duration::from_secs(60),
    )?;
    let backup = fixture.path.with_extension("saved");
    fs::rename(&fixture.path, &backup)?;
    fs::create_dir(&fixture.path)?;
    assert!(matches!(
        store.issue(
            &"two.example.test".parse()?,
            instant(120),
            Duration::from_secs(60)
        ),
        Err(StoreError::Io(_))
    ));
    assert!(matches!(store.table(), Err(StoreError::Unavailable)));
    assert!(matches!(
        store.issue(
            &"one.example.test".parse()?,
            instant(120),
            Duration::from_secs(60)
        ),
        Err(StoreError::Unavailable)
    ));
    drop(store);
    fs::remove_dir(&fixture.path)?;
    fs::rename(backup, &fixture.path)?;
    assert_eq!(
        fixture
            .open()?
            .table()?
            .lookup(first.address(), instant(130))?
            .domain()
            .as_str(),
        "one.example.test"
    );
    Ok(())
}

#[test]
fn r011_missing_previously_created_state_never_initializes_a_fresh_allocator() -> TestResult {
    let fixture = StateFixture::new()?;
    let mut store = fixture.open()?;
    store.issue(
        &"one.example.test".parse()?,
        instant(100),
        Duration::from_secs(60),
    )?;
    drop(store);
    fs::remove_file(&fixture.path)?;
    assert!(matches!(fixture.open(), Err(StoreError::MissingSnapshot)));
    assert!(!fixture.path.exists());
    Ok(())
}

#[test]
fn r012_dns_policy_synthesizes_only_enabled_address_families_and_suppresses_bypass_records()
-> TestResult {
    for families in [DnsAddressFamilies::Ipv4Only, DnsAddressFamilies::DualStack] {
        let fixture = StateFixture::new()?;
        let mut policy = ExceptionPolicy::with_families(
            rules(true)?,
            fixture.open()?,
            Duration::from_secs(60),
            families,
        )?;
        for record_type in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::HTTPS,
            RecordType::SVCB,
            RecordType::TXT,
        ] {
            let request = dns_query("one.example.test", record_type)?;
            if record_type == RecordType::HTTPS {
                let DnsWireDecision::ServiceBinding(binding) =
                    answer_dns(&mut policy, &request, instant(100))?
                else {
                    return Err("selected HTTPS needs the dedicated binding policy".into());
                };
                assert_eq!(binding.packet(), request);
                continue;
            }
            let response = dns_reply(answer_dns(&mut policy, &request, instant(100))?)?;
            assert_eq!(response.metadata.id, 321);
            assert_eq!(response.metadata.message_type, MessageType::Response);
            assert_eq!(response.metadata.response_code, ResponseCode::NoError);
            assert!(response.metadata.recursion_desired);
            assert!(
                !response.metadata.authentic_data,
                "synthetic answers are not DNSSEC validated"
            );
            assert!(!response.metadata.checking_disabled);
            assert_eq!(response.queries, Message::from_vec(&request)?.queries);
            assert!(response.edns.is_some());
            if record_type == RecordType::A {
                assert_eq!(response.answers.len(), 1);
                assert_eq!(
                    &response.answers[0].data,
                    &RData::A(A(Ipv4Addr::new(198, 18, 0, 1)))
                );
                assert_eq!(response.answers[0].ttl, 60);
            } else if record_type == RecordType::AAAA && families == DnsAddressFamilies::DualStack {
                assert_eq!(response.answers.len(), 1);
                assert_eq!(
                    response.answers[0].data,
                    RData::AAAA(AAAA("2001:2::c612:1".parse()?))
                );
                assert_eq!(response.answers[0].ttl, 60);
            } else {
                assert!(
                    response.answers.is_empty(),
                    "alternate addresses and bindings must be suppressed"
                );
            }
            assert!(response.additionals.is_empty());
            assert!(response.authorities.is_empty());
        }
        for record_type in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::HTTPS,
            RecordType::SVCB,
        ] {
            let request = dns_query("unrelated.test", record_type)?;
            assert_eq!(
                answer_dns(&mut policy, &request, instant(100))?,
                DnsWireDecision::Forward(request)
            );
        }
    }
    Ok(())
}

fn dns_query(name: &str, record_type: RecordType) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut message = Message::new(321, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.metadata.authentic_data = true;
    message.metadata.checking_disabled = true;
    message.add_query(Query::query(Name::from_ascii(name)?, record_type));
    message.set_edns(Edns::new());
    Ok(message.to_vec()?)
}

fn dns_reply(decision: DnsWireDecision) -> Result<Message, Box<dyn Error>> {
    match decision {
        DnsWireDecision::Reply(bytes) => Ok(Message::from_vec(&bytes)?),
        DnsWireDecision::Forward(_) => Err("expected a local DNS response".into()),
        DnsWireDecision::ServiceBinding(_) => {
            Err("HTTPS needs a real upstream reply and the binding policy".into())
        }
    }
}

#[test]
fn r014_invalid_dns_envelopes_are_rejected_before_allocating_addresses() -> TestResult {
    let fixture = StateFixture::new()?;
    let mut policy = ExceptionPolicy::new(rules(true)?, fixture.open()?, Duration::from_secs(60))?;
    for bytes in [vec![], vec![0; 11], vec![0; 65536]] {
        assert!(answer_dns(&mut policy, &bytes, instant(100)).is_err());
    }
    // A TSIG RR declares only one byte of RDATA, while its algorithm, time,
    // fudge and MAC length extend beyond that boundary. Reporting this error
    // used to underflow inside the wire decoder (RUSTSEC-2026-0488).
    let mut malformed_tsig = vec![0_u8; 12];
    malformed_tsig[11] = 1; // One additional record.
    malformed_tsig.extend_from_slice(&[
        0, // Root owner.
        0, 250, // TSIG type.
        0, 255, // ANY class.
        0, 0, 0, 0, // Zero TTL.
        0, 1, // Deliberately short RDLENGTH.
    ]);
    malformed_tsig.extend_from_slice(b"\x0bhmac-sha256\x00");
    malformed_tsig.extend_from_slice(&[0; 10]); // Time, fudge, zero MAC length.
    assert!(answer_dns(&mut policy, &malformed_tsig, instant(100)).is_err());
    let request = Message::from_vec(&dns_query("one.example.test", RecordType::A)?)?;
    let mut bad_class = request.clone();
    bad_class.queries[0].set_query_class(DNSClass::CH);
    let mut two_questions = request.clone();
    two_questions.add_query(request.queries[0].clone());
    let mut not_query = request.clone();
    not_query.metadata.message_type = MessageType::Response;
    let mut bad_opcode = request.clone();
    bad_opcode.metadata.op_code = OpCode::Update;
    let mut bad_edns = request.clone();
    let mut edns = Edns::new();
    edns.set_version(1);
    bad_edns.set_edns(edns);
    for (message, code) in [
        (bad_class, ResponseCode::Refused),
        (two_questions, ResponseCode::FormErr),
        (not_query, ResponseCode::FormErr),
        (bad_opcode, ResponseCode::NotImp),
        (bad_edns, ResponseCode::BADVERS),
    ] {
        let response = dns_reply(answer_dns(&mut policy, &message.to_vec()?, instant(100))?)?;
        // BADVERS and BADSIG share wire code 16; decoding the name of that code is contextual.
        assert_eq!(u16::from(response.metadata.response_code), u16::from(code));
        assert!(response.answers.is_empty());
    }
    drop(policy);
    assert!(fixture.open()?.table()?.is_empty());
    Ok(())
}

#[test]
fn r015_real_dns_responses_must_match_the_question_and_not_reenter_the_synthetic_range()
-> TestResult {
    let query = dns_query("one.example.test", RecordType::A)?;
    let request = Message::from_vec(&query)?;
    let mut response = Message::response(request.metadata.id, OpCode::Query);
    response.add_queries(request.queries.clone());
    let name = Name::from_ascii("one.example.test")?;
    response.add_answer(Record::from_rdata(
        name.clone(),
        60,
        RData::A(A(Ipv4Addr::new(203, 0, 113, 10))),
    ));
    response.add_additional(Record::from_rdata(
        name.clone(),
        60,
        RData::AAAA(AAAA("2001:db8::10".parse()?)),
    ));
    let range = "198.18.0.0/15".parse()?;
    validate_upstream_reply(&query, &response.to_vec()?, range)?;
    let mut wrong_id = response.clone();
    wrong_id.metadata.id = 322;
    let mut wrong_question = response.clone();
    wrong_question.queries[0].set_name(Name::from_ascii("other.test")?);
    let mut truncated = response.clone();
    truncated.metadata.truncation = true;
    for invalid in [wrong_id, wrong_question, truncated] {
        assert!(matches!(
            validate_upstream_reply(&query, &invalid.to_vec()?, range),
            Err(DnsWireError::UnexpectedUpstream)
        ));
    }
    for address in [
        RData::A(A(Ipv4Addr::new(198, 18, 0, 1))),
        RData::AAAA(AAAA("2001:2::c612:1".parse()?)),
        RData::AAAA(AAAA("2001:2::c612:0".parse()?)),
        RData::AAAA(AAAA("2001:2::c613:ffff".parse()?)),
        RData::HTTPS(HTTPS(SVCB::new(
            1,
            Name::root(),
            vec![(
                Key::Ipv4Hint,
                Value::Ipv4Hint(IpHint(vec![A("198.18.0.1".parse()?)])),
            )],
        ))),
        RData::SVCB(SVCB::new(
            1,
            Name::root(),
            vec![(
                Key::Ipv6Hint,
                Value::Ipv6Hint(IpHint(vec![AAAA("2001:2::c612:1".parse()?)])),
            )],
        )),
    ] {
        for section in 0..3 {
            let mut invalid = response.clone();
            let records = match section {
                0 => &mut invalid.answers,
                1 => &mut invalid.authorities,
                _ => &mut invalid.additionals,
            };
            records.push(Record::from_rdata(name.clone(), 60, address.clone()));
            assert!(
                matches!(
                    validate_upstream_reply(&query, &invalid.to_vec()?, range),
                    Err(DnsWireError::SyntheticUpstream)
                ),
                "synthetic address escaped validation in section {section}: {address:?}"
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn r016_state_files_reject_symlinks_and_access_by_other_users() -> TestResult {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let fixture = StateFixture::new()?;
    drop(fixture.open()?);
    let alias = fixture.path.with_extension("alias");
    fs::hard_link(&fixture.path, &alias)?;
    assert!(
        matches!(fixture.open(), Err(StoreError::UnsafeFile)),
        "aliased persistent state must be refused"
    );
    fs::remove_file(alias)?;
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o644))?;
    assert!(matches!(fixture.open(), Err(StoreError::UnsafeFile)));
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o600))?;
    let target = fixture.path.with_extension("saved");
    fs::rename(&fixture.path, &target)?;
    symlink(&target, &fixture.path)?;
    assert!(matches!(fixture.open(), Err(StoreError::UnsafeFile)));
    fs::remove_file(&fixture.path)?;
    fs::rename(target, &fixture.path)?;
    let parent = fixture.path.parent().ok_or("missing fixture directory")?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?;
    assert!(matches!(fixture.open(), Err(StoreError::UnsafeFile)));
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[test]
fn r118_direct_https_bindings_preserve_tcp_parameters_and_shared_lease_ttl_while_replacing_all_address_hints()
-> TestResult {
    for families in [DnsAddressFamilies::Ipv4Only, DnsAddressFamilies::DualStack] {
        let fixture = StateFixture::new()?;
        let mut policy = ExceptionPolicy::with_families(
            rules(true)?,
            fixture.open()?,
            Duration::from_secs(60),
            families,
        )?;
        policy.decide_dns(
            &"one.example.test".parse()?,
            DnsQuestionType::A,
            instant(100),
        )?;
        let saved = fs::read(&fixture.path)?;
        let request = dns_query("one.example.test", RecordType::HTTPS)?;
        let DnsWireDecision::ServiceBinding(query) =
            answer_dns(&mut policy, &request, instant(120))?
        else {
            return Err("missing HTTPS policy dispatch".into());
        };
        let owner = Name::from_ascii("one.example.test.")?;
        let mut real = Message::response(321, OpCode::Query);
        real.add_queries(Message::from_vec(&request)?.queries);
        real.metadata.authentic_data = true;
        for (priority, target, ttl) in [(1, Name::root(), 3600), (2, owner.clone(), 10)] {
            let params = vec![
                (
                    Key::Mandatory,
                    Value::Mandatory(Mandatory(vec![Key::Alpn, Key::Port, Key::Ipv4Hint])),
                ),
                (
                    Key::Alpn,
                    Value::Alpn(Alpn(vec!["h3".into(), "h2".into(), "http/1.1".into()])),
                ),
                (Key::NoDefaultAlpn, Value::NoDefaultAlpn),
                (Key::Port, Value::Port(443)),
                (
                    Key::Ipv4Hint,
                    Value::Ipv4Hint(IpHint(vec![A("203.0.113.10".parse()?)])),
                ),
                (
                    Key::Ipv6Hint,
                    Value::Ipv6Hint(IpHint(vec![AAAA("2001:db8::10".parse()?)])),
                ),
            ];
            real.add_answer(Record::from_rdata(
                owner.clone(),
                ttl,
                RData::HTTPS(HTTPS(SVCB::new(priority, target, params))),
            ));
        }
        real.add_additional(Record::from_rdata(
            owner.clone(),
            3600,
            RData::A(A("203.0.113.10".parse()?)),
        ));
        real.add_authority(Record::from_rdata(
            owner.clone(),
            3600,
            RData::AAAA(AAAA("2001:db8::10".parse()?)),
        ));
        let response =
            Message::from_vec(&query.answer(&mut policy, &real.to_vec()?, instant(120))?)?;
        assert_eq!(response.answers.len(), 2);
        assert!(!response.metadata.authentic_data && !response.metadata.checking_disabled);
        assert!(response.authorities.is_empty() && response.additionals.is_empty());
        assert_eq!(response.queries, Message::from_vec(&request)?.queries);
        for (index, record) in response.answers.iter().enumerate() {
            assert_eq!(record.name, owner);
            assert_eq!(record.ttl, if index == 0 { 40 } else { 10 });
            let RData::HTTPS(binding) = &record.data else {
                return Err("missing HTTPS answer".into());
            };
            assert_eq!(usize::from(binding.0.svc_priority), index + 1);
            assert!(binding.0.target_name.is_root());
            let mut expected = vec![
                (
                    Key::Mandatory,
                    Value::Mandatory(Mandatory(vec![Key::Alpn, Key::Port, Key::Ipv4Hint])),
                ),
                (
                    Key::Alpn,
                    Value::Alpn(Alpn(vec!["h2".into(), "http/1.1".into()])),
                ),
                (Key::NoDefaultAlpn, Value::NoDefaultAlpn),
                (Key::Port, Value::Port(443)),
                (
                    Key::Ipv4Hint,
                    Value::Ipv4Hint(IpHint(vec![A("198.18.0.1".parse()?)])),
                ),
            ];
            if families == DnsAddressFamilies::DualStack {
                expected.push((
                    Key::Ipv6Hint,
                    Value::Ipv6Hint(IpHint(vec![AAAA("2001:2::c612:1".parse()?)])),
                ));
            }
            assert_eq!(binding.0.svc_params, expected);
        }
        assert_eq!(
            fs::read(&fixture.path)?,
            saved,
            "binding queries renewed a still-durable shared lease"
        );
    }
    Ok(())
}

#[test]
fn r119_unsupported_https_endpoints_protocols_ech_and_mandatory_parameters_cannot_publish_hints_or_allocate_leases()
-> TestResult {
    let fixture = StateFixture::new()?;
    let mut policy = ExceptionPolicy::new(rules(true)?, fixture.open()?, Duration::from_secs(60))?;
    let packet = dns_query("one.example.test", RecordType::HTTPS)?;
    let DnsWireDecision::ServiceBinding(query) = answer_dns(&mut policy, &packet, instant(100))?
    else {
        return Err("missing binding dispatch".into());
    };
    let cases = [
        (
            "alias",
            SVCB::new(0, Name::from_ascii("alternate.test.")?, vec![]),
        ),
        ("unavailable alias", SVCB::new(0, Name::root(), vec![])),
        (
            "alternate endpoint",
            SVCB::new(1, Name::from_ascii("alternate.test.")?, vec![]),
        ),
        (
            "different port",
            SVCB::new(1, Name::root(), vec![(Key::Port, Value::Port(8443))]),
        ),
        (
            "no TCP suite",
            SVCB::new(
                1,
                Name::root(),
                vec![
                    (Key::Alpn, Value::Alpn(Alpn(vec!["h3".into()]))),
                    (Key::NoDefaultAlpn, Value::NoDefaultAlpn),
                ],
            ),
        ),
        (
            "no-default without ALPN",
            SVCB::new(
                1,
                Name::root(),
                vec![(Key::NoDefaultAlpn, Value::NoDefaultAlpn)],
            ),
        ),
        (
            "ECH",
            SVCB::new(
                1,
                Name::root(),
                vec![(
                    Key::EchConfigList,
                    Value::EchConfigList(EchConfigList(vec![0, 0])),
                )],
            ),
        ),
        (
            "unknown optional",
            SVCB::new(
                1,
                Name::root(),
                vec![(Key::Unknown(65400), Value::Unknown(Unknown(vec![1])))],
            ),
        ),
        (
            "unknown mandatory",
            SVCB::new(
                1,
                Name::root(),
                vec![
                    (
                        Key::Mandatory,
                        Value::Mandatory(Mandatory(vec![Key::Unknown(65400)])),
                    ),
                    (Key::Unknown(65400), Value::Unknown(Unknown(vec![1]))),
                ],
            ),
        ),
        (
            "mandatory missing",
            SVCB::new(
                1,
                Name::root(),
                vec![(Key::Mandatory, Value::Mandatory(Mandatory(vec![Key::Port])))],
            ),
        ),
        (
            "mandatory disabled family",
            SVCB::new(
                1,
                Name::root(),
                vec![
                    (
                        Key::Mandatory,
                        Value::Mandatory(Mandatory(vec![Key::Ipv6Hint])),
                    ),
                    (
                        Key::Ipv6Hint,
                        Value::Ipv6Hint(IpHint(vec![AAAA("2001:db8::10".parse()?)])),
                    ),
                ],
            ),
        ),
    ];
    for (label, binding) in cases {
        let mut real = Message::response(321, OpCode::Query);
        real.add_queries(Message::from_vec(&packet)?.queries);
        real.add_answer(Record::from_rdata(
            Name::from_ascii("one.example.test.")?,
            60,
            RData::HTTPS(HTTPS(binding)),
        ));
        let response =
            Message::from_vec(&query.answer(&mut policy, &real.to_vec()?, instant(100))?)?;
        assert!(
            response.answers.is_empty()
                && response.additionals.is_empty()
                && response.authorities.is_empty(),
            "unsupported {label} published endpoint data"
        );
        assert!(
            policy
                .authorize_tcp("198.18.0.1".parse::<Ipv4Addr>()?, 443, instant(100))
                .is_err(),
            "unsupported {label} allocated a lease"
        );
    }
    // Generic SVCB is not the HTTP mapping (RFC 9460 section 9).
    assert!(
        dns_reply(answer_dns(
            &mut policy,
            &dns_query("one.example.test", RecordType::SVCB)?,
            instant(100)
        )?)?
        .answers
        .is_empty()
    );
    for (owner, kind) in [
        ("_443._https.one.example.test", RecordType::HTTPS),
        ("_80._https.one.example.test", RecordType::HTTPS),
        ("_8443._https.one.example.test", RecordType::HTTPS),
        ("_443._tcp.one.example.test", RecordType::SVCB),
    ] {
        assert!(
            dns_reply(answer_dns(
                &mut policy,
                &dns_query(owner, kind)?,
                instant(100)
            )?)?
            .answers
            .is_empty(),
            "qualified owner escaped suppression: {owner}"
        );
    }
    let unrelated = dns_query("_443._https.unrelated.test", RecordType::HTTPS)?;
    assert_eq!(
        answer_dns(&mut policy, &unrelated, instant(100))?,
        DnsWireDecision::Forward(unrelated)
    );
    policy.replace_rules(rules(false)?);
    let mut real = Message::response(321, OpCode::Query);
    real.add_queries(Message::from_vec(&packet)?.queries);
    real.add_answer(Record::from_rdata(
        Name::from_ascii("one.example.test.")?,
        60,
        RData::HTTPS(HTTPS(SVCB::new(1, Name::root(), vec![]))),
    ));
    let response = Message::from_vec(&query.answer(&mut policy, &real.to_vec()?, instant(100))?)?;
    assert_eq!(response.metadata.response_code, ResponseCode::Refused);
    assert!(response.answers.is_empty());
    Ok(())
}

#[test]
fn r013_tcp_admission_revalidates_expiry_ports_current_rules_and_unknown_addresses() -> TestResult {
    let fixture = StateFixture::new()?;
    let mut policy = ExceptionPolicy::with_families(
        rules(true)?,
        fixture.open()?,
        Duration::from_secs(60),
        DnsAddressFamilies::DualStack,
    )?;
    let name = "one.example.test".parse()?;
    let DnsDecision::Synthetic(lease) =
        policy.decide_dns(&name, DnsQuestionType::A, instant(100))?
    else {
        return Err("missing lease".into());
    };
    for address in [
        IpAddr::V4(lease.address()),
        IpAddr::V6(lease.ipv6_address()),
    ] {
        policy.replace_rules(rules(true)?);
        for port in [80, 443] {
            assert_eq!(policy.authorize_tcp(address, port, instant(120))?, &name);
        }
        assert!(matches!(
            policy.authorize_tcp(address, 22, instant(120)),
            Err(ConnectionError::UnsupportedPort)
        ));
        assert!(matches!(
            policy.authorize_tcp(address, 443, instant(99)),
            Err(ConnectionError::Lease(FakeIpError::ClockReversed))
        ));
        assert!(matches!(
            policy.authorize_tcp(address, 443, instant(160)),
            Err(ConnectionError::Lease(FakeIpError::Expired))
        ));
        policy.replace_rules(rules(false)?);
        assert!(matches!(
            policy.authorize_tcp(address, 443, instant(120)),
            Err(ConnectionError::NotExcepted)
        ));
        policy.replace_rules(RuleSet::new(vec![], count(16)?)?);
        assert!(matches!(
            policy.authorize_tcp(address, 443, instant(120)),
            Err(ConnectionError::NotExcepted)
        ));
    }
    policy.replace_rules(rules(true)?);
    for unknown in [
        IpAddr::V4(Ipv4Addr::new(198, 18, 0, 14)),
        "2001:2::c612:e".parse()?,
        "2001:2:0:1::c612:1".parse()?,
    ] {
        assert!(matches!(
            policy.authorize_tcp(unknown, 443, instant(120)),
            Err(ConnectionError::Lease(FakeIpError::UnknownAddress))
        ));
    }
    drop(policy);
    let ipv4_only = ExceptionPolicy::new(rules(true)?, fixture.open()?, Duration::from_secs(60))?;
    assert!(
        matches!(
            ipv4_only.authorize_tcp(lease.ipv6_address(), 443, instant(120)),
            Err(ConnectionError::UnsupportedFamily)
        ),
        "a cached IPv6 identity was admitted after IPv6 mode was disabled"
    );
    assert_eq!(
        ipv4_only.authorize_tcp(lease.address(), 443, instant(120))?,
        &name
    );
    Ok(())
}
