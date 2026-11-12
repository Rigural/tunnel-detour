//! Inbound configuration has its own dependencies, separate from domain exceptions.

use serde_json::{Value, json};
use std::error::Error;
use tunnel_detour_service::{InboundConfig, InboundConfigError};

fn fixture() -> Value {
    json!({
        "lan_device":"lan0", "lan_networks":["2001:db8:1::/64"],
        "router_addresses":["2001:db8:1::1"],
        "wan":{"device":"wan0", "addresses":["2001:db8:2::1"], "gateway":"fe80::2", "route_table":41900,"mark_prefix":1413742592_u32,"rule_priority":100},
        "state_file":"/tmp/inbound-test/state.json", "status_file":"/tmp/inbound-test/status.json",
        "rules":[{"id":"sample","name":"Test service","enabled":true,"protocol":"tcp_udp","public_port":18080,"destination":"[2001:db8:1::2]:8080"}]
    })
}

fn decode(value: &Value) -> Result<InboundConfig, Box<dyn Error>> {
    Ok(InboundConfig::from_json(&serde_json::to_vec(value)?)?)
}

#[test]
fn r050_inbound_configuration_requires_no_dns_settings_and_rejects_unsafe_wan_routing_and_paths()
-> Result<(), Box<dyn Error>> {
    let original = fixture();
    let mut boundary = original.clone();
    boundary["router_addresses"] = json!(
        (1..=255)
            .map(|index| format!("2001:db8:ffff::{index:x}"))
            .collect::<Vec<_>>()
    );
    let maximum = decode(&boundary)?;
    decode(&serde_json::to_value(maximum)?)?;
    boundary["router_addresses"]
        .as_array_mut()
        .ok_or("missing router addresses")?
        .push(json!("2001:db8:ffff::100"));
    assert!(
        matches!(
            InboundConfig::from_json(&serde_json::to_vec(&boundary)?),
            Err(InboundConfigError::Limits)
        ),
        "WAN addresses must count toward the recoverable router-address limit"
    );
    let config = decode(&original)?;
    let encoded = serde_json::to_value(&config)?;
    assert_eq!(encoded["relay"]["max_connections"], 32);
    assert_eq!(encoded["relay"]["connect_timeout_seconds"], 5);
    assert_eq!(encoded["relay"]["idle_timeout_seconds"], 3600);
    for field in [
        "listen_port",
        "max_connections",
        "connect_timeout_seconds",
        "idle_timeout_seconds",
    ] {
        let mut invalid = original.clone();
        invalid["relay"] = json!({(field):0});
        assert!(
            matches!(
                InboundConfig::from_json(&serde_json::to_vec(&invalid)?),
                Err(InboundConfigError::Limits)
            ),
            "the config boundary bypassed relay validation for {field}"
        );
    }
    let mut local = original.clone();
    local["rules"][0]["access"] = json!("wan_and_lan");
    assert!(matches!(
        InboundConfig::from_json(&serde_json::to_vec(&local)?),
        Err(InboundConfigError::LanSource)
    ));
    local["lan_router_addresses"] = json!(["2001:db8:1::1"]);
    assert_eq!(
        decode(&local)?.rules().rules()[0].access(),
        tunnel_detour_core::InboundAccess::WanAndLan
    );
    for source in [
        "::",
        "::1",
        "fe80::1",
        "ff02::1",
        "2001:db8:2::1",
        "2001:db8:3::1",
    ] {
        let mut invalid = local.clone();
        invalid["lan_router_addresses"] = json!([source]);
        assert!(
            decode(&invalid).is_err(),
            "accepted unsafe LAN rewrite source {source}"
        );
    }
    let mut invalid = local.clone();
    invalid["rules"][0]["access"] = json!("unknown_policy");
    assert!(
        decode(&invalid).is_err(),
        "unknown access policy silently selected a mode"
    );
    assert_eq!(config.rules().rules().len(), 1);
    assert_eq!(
        decode(&serde_json::to_value(&config)?)?.rules().rules()[0].destination(),
        config.rules().rules()[0].destination(),
        "validated configuration must retain its policy through recovery serialization"
    );
    for field in [
        "adguard",
        "dns_integration",
        "real_upstream",
        "dns_listen",
        "fake_range",
    ] {
        assert!(
            original.get(field).is_none(),
            "the independent fixture must omit {field}"
        );
    }
    for address in ["::", "::1", "fe80::2", "fd00:1234::2", "ff02::1"] {
        let mut value = original.clone();
        value["wan"]["addresses"] = json!([address]);
        assert!(
            matches!(
                InboundConfig::from_json(&serde_json::to_vec(&value)?),
                Err(InboundConfigError::Wan)
            ),
            "accepted non-global WAN address {address}"
        );
    }
    for gateway in ["::", "::1", "ff02::1", "::ffff:192.0.2.1"] {
        let mut value = original.clone();
        value["wan"]["gateway"] = json!(gateway);
        assert!(matches!(
            InboundConfig::from_json(&serde_json::to_vec(&value)?),
            Err(InboundConfigError::Wan)
        ));
    }
    for (field, invalid) in [
        ("mark_prefix", 0),
        ("mark_prefix", 1),
        ("mark_prefix", 1413742593),
        ("route_table", 254),
        ("rule_priority", 0),
        ("rule_priority", 32766),
    ] {
        let mut value = original.clone();
        value["wan"][field] = json!(invalid);
        assert!(
            matches!(
                InboundConfig::from_json(&serde_json::to_vec(&value)?),
                Err(InboundConfigError::Routing)
            ),
            "accepted invalid routing {field}"
        );
    }
    for status in [
        "relative.json",
        "/tmp/inbound-test/../status.json",
        "/tmp/inbound-test/state.json",
        "/tmp/inbound-test/state.json.lock",
    ] {
        let mut value = original.clone();
        value["status_file"] = json!(status);
        assert!(
            matches!(
                InboundConfig::from_json(&serde_json::to_vec(&value)?),
                Err(InboundConfigError::Paths)
            ),
            "accepted unsafe status path {status}"
        );
    }
    let mut value = original.clone();
    value["wan"]["device"] = json!("lan0");
    assert!(matches!(
        InboundConfig::from_json(&serde_json::to_vec(&value)?),
        Err(InboundConfigError::Device)
    ));
    let mut value = original.clone();
    value["max_rules"] = json!(257);
    assert!(matches!(
        InboundConfig::from_json(&serde_json::to_vec(&value)?),
        Err(InboundConfigError::Limits)
    ));
    for scope in ["::/0", "2001:db8:1::2/64", "ff00::/8", "::1/128"] {
        let mut value = original.clone();
        value["lan_networks"] = json!([scope]);
        value["rules"] = json!([]);
        assert!(
            matches!(
                InboundConfig::from_json(&serde_json::to_vec(&value)?),
                Err(InboundConfigError::Policy(_))
            ),
            "unsafe LAN scope {scope} must fail even with no publications"
        );
    }
    let mut value = original;
    value["rules"][0]["destination"] = json!("[2001:db8:2::1]:8080");
    assert!(
        matches!(
            InboundConfig::from_json(&serde_json::to_vec(&value)?),
            Err(InboundConfigError::Policy(_))
        ),
        "the WAN's own address must never be a LAN destination"
    );
    Ok(())
}
