//! R125 owns observation fidelity, containment and cleanup.
use serde_json::{Value, json};
use std::{
    error::Error,
    fs,
    io::{Read, Write},
    net::TcpStream,
    os::unix::fs::PermissionsExt,
    time::Duration,
};
use xtask::observe::Observer;
const TEST: &str = "r125_observation_preserves_samples_rejects_foreign_hosts_and_joins_workers";

fn get(url: &str, path: &str, host: Option<&str>) -> Result<String, Box<dyn Error>> {
    let endpoint = url
        .strip_prefix("http://")
        .ok_or("missing HTTP URL")?
        .trim_end_matches('/');
    let mut stream = TcpStream::connect(endpoint)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        host.unwrap_or(endpoint)
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

#[test]
fn r125_observation_preserves_samples_rejects_foreign_hosts_and_joins_workers()
-> Result<(), Box<dyn Error>> {
    if let Ok(mode) = std::env::var("TUNNEL_DETOUR_OBSERVATION_FIXTURE") {
        if mode == "oversized" {
            println!("TD_SNAPSHOT={}", "x".repeat(512 * 1024 + 1));
        } else {
            println!("TD_SNAPSHOT={{\"boundary\":{{\"packets\":7}},\"source\":\"synthetic\"}}");
        }
        return Ok(());
    }
    let base = tempfile::tempdir()?;
    let directory = base.path().join("run");
    let command = |mode: &str| -> Result<Vec<String>, Box<dyn Error>> {
        Ok(vec![
            "env".into(),
            format!("TUNNEL_DETOUR_OBSERVATION_FIXTURE={mode}"),
            std::env::current_exe()?
                .to_str()
                .ok_or("fixture path is not UTF-8")?
                .into(),
            "--exact".into(),
            TEST.into(),
            "--nocapture".into(),
        ])
    };
    let observer = Observer::start(&directory, command("normal")?, json!({"fixture":"r125"}))?;
    observer.phase("known-boundary")?;
    let state: Value = serde_json::from_reader(fs::File::open(directory.join("state.json"))?)?;
    assert_eq!(
        state["observation"]["data"],
        json!({"boundary":{"packets":7},"source":"synthetic"})
    );
    assert_eq!(state["phase"], "known-boundary");
    assert_eq!(state["atomic_snapshot"], false);
    assert_eq!(
        fs::metadata(&directory)?.permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(directory.join("state.json"))?
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let session: Value = serde_json::from_reader(fs::File::open(directory.join("session.json"))?)?;
    let url = session["url"].as_str().ok_or("missing viewer URL")?;
    assert!(url.starts_with("http://127.0.0.1:"));
    let response = get(url, "/state.json", None)?;
    assert!(response.starts_with("HTTP/1.1 200"));
    let (_, body) = response.split_once("\r\n\r\n").ok_or("missing HTTP body")?;
    assert_eq!(serde_json::from_str::<Value>(body)?, state);
    let checkpoint = get(url, "/event-01.json", None)?;
    let (_, checkpoint) = checkpoint
        .split_once("\r\n\r\n")
        .ok_or("checkpoint body missing")?;
    assert_eq!(
        serde_json::from_str::<Value>(checkpoint)?["phase"],
        "known-boundary"
    );
    assert!(get(url, "/state.json", Some("foreign.example.test"))?.starts_with("HTTP/1.1 403"));
    fs::write(directory.join("secret.txt"), b"private sentinel")?;
    for path in [
        "/../secret.txt",
        "/secret.txt",
        "/events.jsonl",
        "/event-65.json",
        "/event-01.json/../secret.txt",
    ] {
        assert!(get(url, path, None)?.starts_with("HTTP/1.1 404"));
    }
    assert!(Observer::start(&directory, command("normal")?, json!({})).is_err());
    assert_eq!(fs::read(directory.join("secret.txt"))?, b"private sentinel");
    observer.finish(true)?;
    let final_state: Value =
        serde_json::from_reader(fs::File::open(directory.join("state.json"))?)?;
    assert_eq!(final_state["terminal"], true);
    assert_eq!(final_state["phase"], "passed");
    let endpoint = url
        .strip_prefix("http://")
        .ok_or("missing HTTP URL")?
        .trim_end_matches('/');
    assert!(
        TcpStream::connect(endpoint).is_err(),
        "finished viewer still accepts clients"
    );
    let oversize = base.path().join("oversize");
    let observer = Observer::start(&oversize, command("oversized")?, json!({}))?;
    observer.phase("bounded-output")?;
    let state: Value = serde_json::from_reader(fs::File::open(oversize.join("state.json"))?)?;
    assert_eq!(state["observation"]["ok"], false);
    assert!(
        state["observation"]["error"]
            .as_str()
            .is_some_and(|error| !error.is_empty())
    );
    observer.finish(false)?;
    Ok(())
}
