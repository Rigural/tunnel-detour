//! PF-01a/b: validate publication policy before any OS adapter may activate it.

use ipnet::IpNet;
use std::{
    error::Error,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
};
use tunnel_detour_core::{
    InboundAccess, InboundError, InboundProtocol, InboundRuleSpec, InboundRules, InboundTarget,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct Fixture {
    networks: Vec<IpNet>,
    router: Vec<IpAddr>,
    capacity: NonZeroUsize,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        Ok(Self {
            networks: ["192.0.2.0/24", "2001:db8:1::/64", "fd00:1234::/64"]
                .into_iter()
                .map(str::parse)
                .collect::<Result<_, _>>()?,
            router: ["192.0.2.1", "2001:db8:1::1", "fd00:1234::1"]
                .into_iter()
                .map(str::parse)
                .collect::<Result<_, _>>()?,
            capacity: NonZeroUsize::new(16).ok_or("invalid test capacity")?,
        })
    }

    fn spec(id: &str, protocol: InboundProtocol) -> TestResult<InboundRuleSpec> {
        Ok(InboundRuleSpec {
            id: id.parse()?,
            name: "  Test server  ".into(),
            enabled: true,
            protocol,
            access: InboundAccess::WanOnly,
            public_port: 18080,
            destination: "[2001:db8:1::2]:8080".parse()?,
        })
    }

    fn build(&self, specs: Vec<InboundRuleSpec>) -> Result<InboundRules, InboundError> {
        InboundRules::new(specs, self.capacity, &self.networks, &self.router)
    }
}

#[test]
fn r048_inbound_inputs_require_explicit_lan_unicast_hosts_valid_ports_and_safe_identifiers()
-> TestResult {
    let fixture = Fixture::new()?;
    let spec = Fixture::spec("server_1", InboundProtocol::TcpUdp)?;
    let rules = fixture.build(vec![spec.clone()])?;
    let rule = &rules.rules()[0];
    assert_eq!(rule.id().as_str(), "server_1");
    assert_eq!(rule.name(), "Test server");
    assert!(rule.enabled());
    assert_eq!(rule.protocol(), InboundProtocol::TcpUdp);
    assert_eq!(rule.access(), InboundAccess::WanOnly);
    let mut legacy = serde_json::to_value(&spec)?;
    legacy
        .as_object_mut()
        .ok_or("expected object")?
        .remove("access");
    let legacy: InboundRuleSpec = serde_json::from_value(legacy)?;
    assert_eq!(
        legacy.access,
        InboundAccess::WanOnly,
        "legacy rules must not enable LAN access implicitly"
    );
    let mut local = spec.clone();
    local.access = InboundAccess::WanAndLan;
    assert_eq!(
        fixture.build(vec![local])?.rules()[0].access(),
        InboundAccess::WanAndLan
    );
    assert_eq!(rule.public_port().get(), 18080);
    assert_eq!(rule.destination().endpoint(), spec.destination);
    assert!(!rule.destination().requires_relay());

    for destination in ["[fd00:1234::2]:8080", "192.0.2.2:8080"] {
        let address: SocketAddr = destination.parse()?;
        let target = InboundTarget::new(address, &fixture.networks, &fixture.router)?;
        assert_eq!(target.endpoint(), address);
        assert_eq!(target.requires_relay(), address.is_ipv4());
    }
    for destination in [
        "[::]:8080",
        "[::1]:8080",
        "[fe80::2]:8080",
        "[ff02::2]:8080",
        "[::ffff:192.0.2.2]:8080",
        "[::192.0.2.2]:8080",
        "[2001:db8:2::2]:8080",
        "[2001:db8:1::1]:8080",
        "[fd00:1234::1]:8080",
        "0.0.0.0:8080",
        "127.0.0.2:8080",
        "169.254.1.2:8080",
        "224.0.0.2:8080",
        "255.255.255.255:8080",
        "198.18.0.2:8080",
        "198.19.0.2:8080",
        "192.0.2.0:8080",
        "192.0.2.255:8080",
        "192.0.2.1:8080",
        "203.0.113.2:8080",
    ] {
        let target = InboundTarget::new(destination.parse()?, &fixture.networks, &fixture.router);
        assert_eq!(
            target,
            Err(InboundError::Target),
            "accepted unsafe target {destination}"
        );
    }
    let address: SocketAddr = "[2001:db8:1::2]:8080".parse()?;
    assert_eq!(
        InboundTarget::new(address, &[], &[]),
        Err(InboundError::Lan)
    );
    assert_eq!(
        InboundTarget::new(address, &["::/0".parse()?], &[]),
        Err(InboundError::Lan)
    );
    let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(
        "2001:db8:1::2".parse()?,
        8080,
        0,
        2,
    ));
    assert_eq!(
        InboundTarget::new(scoped, &fixture.networks, &fixture.router),
        Err(InboundError::Target)
    );
    for id in [
        "",
        "contains space",
        "injected;rule",
        "../escape",
        "line\nbreak",
    ] {
        assert_eq!(
            id.parse::<tunnel_detour_core::InboundId>(),
            Err(InboundError::Identifier)
        );
    }
    let mut invalid = spec.clone();
    invalid.public_port = 0;
    assert_eq!(
        fixture.build(vec![invalid]).map(|_| ()),
        Err(InboundError::Port)
    );
    let mut invalid = spec.clone();
    invalid.destination.set_port(0);
    assert_eq!(
        fixture.build(vec![invalid]).map(|_| ()),
        Err(InboundError::Port)
    );
    for name in [
        "".to_owned(),
        "\n".to_owned(),
        "control\u{7f}".to_owned(),
        "a".repeat(81),
    ] {
        let mut invalid = spec.clone();
        invalid.name = name;
        assert_eq!(
            fixture.build(vec![invalid]).map(|_| ()),
            Err(InboundError::Name)
        );
    }
    for protocol in [InboundProtocol::Udp, InboundProtocol::TcpUdp] {
        let mut invalid = spec.clone();
        invalid.protocol = protocol;
        invalid.destination = "192.0.2.2:8080".parse()?;
        assert_eq!(
            fixture.build(vec![invalid]).map(|_| ()),
            Err(InboundError::RelayProtocol)
        );
    }
    let mut invalid = spec;
    invalid.protocol = InboundProtocol::Tcp;
    invalid.destination = "192.0.2.2:8080".parse()?;
    assert!(
        fixture.build(vec![invalid])?.rules()[0]
            .destination()
            .requires_relay()
    );
    Ok(())
}

#[test]
fn r049_inbound_lists_reject_duplicate_identity_and_overlapping_enabled_transports_atomically()
-> TestResult {
    let fixture = Fixture::new()?;
    let tcp = Fixture::spec("first", InboundProtocol::Tcp)?;
    let udp = Fixture::spec("second", InboundProtocol::Udp)?;
    let rules = fixture.build(vec![tcp.clone(), udp.clone()])?;
    assert_eq!(
        rules.rules().len(),
        2,
        "separate transports may share one public port"
    );
    assert_eq!(
        fixture.build(vec![tcp.clone(), tcp.clone()]).map(|_| ()),
        Err(InboundError::DuplicateIdentifier)
    );
    let both = Fixture::spec("combined", InboundProtocol::TcpUdp)?;
    for other in [tcp.clone(), udp] {
        assert_eq!(
            fixture.build(vec![both.clone(), other]).map(|_| ()),
            Err(InboundError::PortConflict)
        );
    }
    let mut relay = Fixture::spec("relay", InboundProtocol::Tcp)?;
    relay.destination = "192.0.2.2:9000".parse()?;
    assert_eq!(
        fixture.build(vec![tcp.clone(), relay]).map(|_| ()),
        Err(InboundError::PortConflict),
        "native forwarding and relay listeners share public TCP admission"
    );
    let mut disabled = both;
    disabled.enabled = false;
    assert_eq!(fixture.build(vec![tcp.clone(), disabled])?.rules().len(), 2);
    assert_eq!(
        InboundRules::new(
            vec![tcp.clone(), Fixture::spec("other", InboundProtocol::Udp)?],
            NonZeroUsize::new(1).ok_or("invalid capacity")?,
            &fixture.networks,
            &fixture.router
        )
        .map(|_| ()),
        Err(InboundError::Capacity)
    );
    assert_eq!(
        fixture.build(vec![tcp])?.rules().len(),
        1,
        "failed candidate lists cannot alter the accepted input policy"
    );
    Ok(())
}
