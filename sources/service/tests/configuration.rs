//! Admission checks run before listeners or kernel mutations. Network behavior has its own lab.

use std::{error::Error, fs, os::unix::fs::PermissionsExt};

use serde_json::{Value, json};
use tunnel_detour_service::{BoundService, ServiceConfig, validate_patterns};

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
fn r017_invalid_listener_routing_path_and_resource_settings_are_rejected_before_startup()
-> TestResult {
    let base = configuration();
    ServiceConfig::from_json(&serde_json::to_vec(&base)?)?;
    for (pointer, value) in [
        ("/dns_listen", json!("0.0.0.0:10535")),
        ("/proxy_listen", json!("203.0.113.1:10536")),
        ("/real_upstream", json!("198.19.255.254:53")),
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
    for suffix in ["", ".lock", ".adguard.json", ".adguard.json.lock"] {
        let mut config = configuration();
        config["state_file"] = json!(alias.join("inner/leases.json"));
        config["status_file"] = json!(persistent.join(format!("leases.json{suffix}")));
        let config = ServiceConfig::from_json(&serde_json::to_vec(&config)?)?;
        assert!(
            BoundService::bind(config).await.is_err(),
            "aliased {suffix} was accepted"
        );
        assert!(
            !persistent.join("leases.json").exists(),
            "rejection must precede allocator initialization"
        );
    }
    Ok(())
}
