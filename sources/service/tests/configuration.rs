//! Admission checks run before listeners or kernel mutations. Network behavior has its own lab.

use std::{error::Error, fs, os::unix::fs::PermissionsExt};

use serde_json::{Value, json};
use tunnel_detour_service::{BoundService, DnsIntegration, ServiceConfig, validate_patterns};

type TestResult = Result<(), Box<dyn Error>>;

fn configuration() -> Value {
    json!({
        "dns_listen": "127.0.0.1:0", "proxy_listen": "0.0.0.0:0",
        "real_upstream": "127.0.0.1:5353", "state_file": "/var/lib/example/leases.json",
        "status_file": "/var/run/example/status.json", "fake_range": "198.18.0.0/15",
        "lan_device": "lan0", "lan_networks": ["192.0.2.0/24"],
        "wan": {"device": "wan0", "gateway": null, "route_table": 41872, "mark": 21572, "rule_priority": 11000},
        "rules": [{"pattern": "selected.example.test", "enabled": true}]
    })
}

#[test]
fn r134_trusted_client_configuration_cannot_expand_the_selected_lan_or_accept_ambiguous_scopes()
-> TestResult {
    for clients in [json!([]), json!(["192.0.2.2/32"]), json!(["192.0.2.0/25"])] {
        let mut config = configuration();
        config["trusted_clients"] = clients;
        ServiceConfig::from_json(&serde_json::to_vec(&config)?)?;
    }
    for clients in [
        json!(["0.0.0.0/0"]),
        json!(["192.0.2.1/24"]),
        json!(["192.0.3.2/32"]),
        json!(["2001:db8:1::2/128"]),
        json!(["example.test"]),
        json!(vec!["192.0.2.2/32"; 65]),
    ] {
        let mut config = configuration();
        config["trusted_clients"] = clients;
        assert!(ServiceConfig::from_json(&serde_json::to_vec(&config)?).is_err());
    }
    Ok(())
}

#[test]
fn r017_invalid_listener_routing_path_and_resource_settings_are_rejected_before_startup()
-> TestResult {
    let base = configuration();
    ServiceConfig::from_json(&serde_json::to_vec(&base)?)?;
    for endpoint in ["[::1]:5353", "[2001:db8::53]:5353"] {
        let mut valid = base.clone();
        valid["real_upstream"] = json!(endpoint);
        ServiceConfig::from_json(&serde_json::to_vec(&valid)?)?;
    }
    for (pointer, value) in [
        ("/dns_listen", json!("0.0.0.0:10535")),
        ("/proxy_listen", json!("203.0.113.1:10536")),
        ("/real_upstream", json!("198.19.255.254:53")),
        ("/real_upstream", json!("[2001:2::c612:1]:53")),
        ("/real_upstream", json!("[::]:53")),
        ("/real_upstream", json!("[ff02::1]:53")),
        ("/real_upstream", json!("[fe80::53]:53")),
        ("/real_upstream", json!("[2001:db8::53%2]:53")),
        ("/real_upstream", json!("[::ffff:192.0.2.53]:53")),
        ("/real_upstream", json!("[::192.0.2.53]:53")),
        ("/real_upstream", json!("[2001:db8::53]:0")),
        ("/lan_device", json!("lan0\"; flush ruleset")),
        ("/wan/device", json!("lan0")),
        ("/wan/route_table", json!(254)),
        ("/wan/mark", json!(0)),
        ("/wan/rule_priority", json!(0)),
        ("/state_file", json!("relative/leases.json")),
        ("/state_file", json!("/var/lib/example/../leases.json")),
        (
            "/status_file",
            json!("/var/lib/example/leases.json.adguard.json"),
        ),
    ] {
        let mut invalid = base.clone();
        *invalid
            .pointer_mut(pointer)
            .ok_or("fixture pointer is absent")? = value;
        assert!(
            ServiceConfig::from_json(&serde_json::to_vec(&invalid)?).is_err(),
            "accepted {pointer}"
        );
    }
    for (option, value) in [
        ("connections", json!(0)),
        ("dns_jobs", json!(257)),
        ("max_mappings", json!(131071)),
        ("max_mappings_per_rule", json!(0)),
        ("ttl_seconds", json!(3601)),
    ] {
        let mut invalid = base.clone();
        invalid["limits"] = json!({option: value});
        assert!(
            ServiceConfig::from_json(&serde_json::to_vec(&invalid)?).is_err(),
            "accepted {option}"
        );
    }
    for url in [
        "https://127.0.0.1:3000",
        "http://203.0.113.1",
        "http://user:secret@127.0.0.1",
        "http://127.0.0.1?password=secret",
    ] {
        let mut invalid = base.clone();
        invalid["adguard"] = json!({"api_url": url, "username": null, "password": null});
        assert!(
            ServiceConfig::from_json(&serde_json::to_vec(&invalid)?).is_err(),
            "accepted control endpoint"
        );
    }
    Ok(())
}

#[test]
fn r107_ipv6_settings_require_explicit_native_wan_and_bounded_nonoverlapping_lan_prefixes()
-> TestResult {
    let mut valid = configuration();
    valid["ipv6"] = json!({
        "lan_networks":["2001:db8:1::/64", "fd00:1234::/64"],
        "wan":{"device":"wan6", "source":"2001:db8:2::1", "gateway":"fe80::1"}
    });
    ServiceConfig::from_json(&serde_json::to_vec(&valid)?)?;
    for gateway in [json!(null), json!("2001:db8:2::2")] {
        let mut point_to_point = valid.clone();
        point_to_point["ipv6"]["wan"]["gateway"] = gateway;
        ServiceConfig::from_json(&serde_json::to_vec(&point_to_point)?)?;
    }
    for (pointer, value) in [
        ("/ipv6/lan_networks", json!([])),
        ("/ipv6/lan_networks", json!(["::/0"])),
        ("/ipv6/lan_networks", json!(["fe80::/64"])),
        ("/ipv6/lan_networks", json!(["ff00::/8"])),
        ("/ipv6/lan_networks", json!(["2001:2::/48"])),
        ("/ipv6/lan_networks", json!(["2001:db8:1::1/64"])),
        (
            "/ipv6/lan_networks",
            json!(["2001:db8:1::/64", "2001:db8:1::1/128"]),
        ),
        ("/ipv6/lan_networks", json!(["2001:db8:2::/64"])),
        ("/ipv6/lan_networks", json!(vec!["fd00:1234::/64"; 17])),
        ("/ipv6/wan/device", json!("lan0")),
        ("/ipv6/wan/device", json!("lo")),
        ("/ipv6/wan/device", json!("wan6; flush ruleset")),
        ("/ipv6/wan/source", json!("::")),
        ("/ipv6/wan/source", json!("::1")),
        ("/ipv6/wan/source", json!("fd00:1234::1")),
        ("/ipv6/wan/source", json!("fe80::1")),
        ("/ipv6/wan/source", json!("::ffff:203.0.113.1")),
        ("/ipv6/wan/source", json!("2002:cb00:7101::1")),
        ("/ipv6/wan/source", json!("2001:0:cb00:7101::1")),
        ("/ipv6/wan/source", json!("2001:2::c612:1")),
        ("/ipv6/wan/source", json!("2001:20::1")),
        ("/ipv6/wan/gateway", json!("::1")),
        ("/ipv6/wan/gateway", json!("ff02::1")),
        ("/ipv6/wan/gateway", json!("fe80::1%wan6")),
        ("/ipv6/wan/gateway", json!("2001:db8:2::1")),
    ] {
        let mut invalid = valid.clone();
        *invalid
            .pointer_mut(pointer)
            .ok_or("missing IPv6 fixture input")? = value;
        assert!(
            ServiceConfig::from_json(&serde_json::to_vec(&invalid)?).is_err(),
            "accepted {pointer}"
        );
    }
    Ok(())
}

#[test]
fn r018_management_validation_uses_the_production_rule_capacity_and_returns_actionable_errors() {
    let lines = (0..256)
        .map(|index| format!("entry{index}.example.test"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(validate_patterns(&lines)["valid"], true);
    let result = validate_patterns(&format!("{lines}\nexcess.example.test"));
    assert_eq!(result["valid"], false);
    assert!(
        result["error"]
            .as_str()
            .is_some_and(|message| !message.is_empty())
    );
    let rows =
        validate_patterns("EXAMPLE.test.\nexample.test\n*.example.test\nhttps://example.test/path");
    assert_eq!(rows["valid"], false);
    assert_eq!(
        rows["rows"][0],
        json!({"pattern":"example.test","error":"duplicate"})
    );
    assert_eq!(rows["rows"][1], rows["rows"][0]);
    assert_eq!(rows["rows"][2], json!({"pattern":"*.example.test"}));
    assert_eq!(rows["rows"][3], json!({"error":"invalid_domain"}));
    assert_eq!(result["rows"].as_array().map(Vec::len), Some(256));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r019_status_paths_cannot_overwrite_persistent_state_through_parent_directory_aliases()
-> TestResult {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let persistent = directory.path().join("persistent");
    fs::create_dir(&persistent)?;
    fs::set_permissions(&persistent, fs::Permissions::from_mode(0o700))?;
    let alias = directory.path().join("alias");
    std::os::unix::fs::symlink(&persistent, &alias)?;
    let persistent = persistent.join("inner");
    fs::create_dir(&persistent)?;
    fs::set_permissions(&persistent, fs::Permissions::from_mode(0o700))?;
    for suffix in [
        "",
        ".lock",
        ".adguard.json",
        ".adguard.json.lock",
        ".adguard-preview.json",
        ".dnsmasq.json",
        ".dnsmasq.json.lock",
    ] {
        let mut config = configuration();
        config["state_file"] = json!(alias.join("inner/leases.json"));
        config["status_file"] = json!(persistent.join(format!("leases.json{suffix}")));
        let config = ServiceConfig::from_json(&serde_json::to_vec(&config)?)?;
        assert!(
            matches!(
                BoundService::bind(config).await,
                Err(tunnel_detour_service::ServiceError::Config(
                    tunnel_detour_service::ConfigError::Paths
                ))
            ),
            "aliased {suffix} was accepted"
        );
        assert!(
            !persistent.join("leases.json").exists(),
            "rejection must precede allocator initialization"
        );
    }
    Ok(())
}

#[test]
fn r041_optional_integration_preserves_legacy_json_and_validates_only_the_selected_frontend()
-> TestResult {
    let mut config = configuration();
    assert_eq!(
        ServiceConfig::from_json(&serde_json::to_vec(&config)?)?.dns_integration(),
        DnsIntegration::External
    );
    config["adguard"] = json!({"api_url":"http://127.0.0.1:13000","username":null,"password":null});
    assert_eq!(
        ServiceConfig::from_json(&serde_json::to_vec(&config)?)?.dns_integration(),
        DnsIntegration::Adguard
    );
    config["dns_integration"] = json!("dnsmasq");
    config["adguard"] = json!({"api_url":"not an endpoint","username":"unused","password":null});
    assert_eq!(
        ServiceConfig::from_json(&serde_json::to_vec(&config)?)?.dns_integration(),
        DnsIntegration::Dnsmasq
    );
    config["dns_integration"] = json!("adguard");
    assert!(ServiceConfig::from_json(&serde_json::to_vec(&config)?).is_err());
    config["adguard"] = Value::Null;
    assert!(ServiceConfig::from_json(&serde_json::to_vec(&config)?).is_err());
    config["dns_integration"] = json!("unknown");
    assert!(ServiceConfig::from_json(&serde_json::to_vec(&config)?).is_err());
    Ok(())
}
