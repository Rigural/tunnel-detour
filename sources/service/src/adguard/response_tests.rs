//! Strict API documents (R144) and real HTTP resource/cancellation bounds (R145).

use super::*;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

type TestError = Box<dyn std::error::Error>;
const MAX_API_REPLY_BYTES: usize = 4 * 1024 * 1024;
const STATUS: &[u8] =
    br#"{"running":true,"dns_addresses":["127.0.0.1"],"dns_port":53,"protection_enabled":true}"#;

#[test]
fn r150_api_collections_reject_cardinality_amplification_before_allocating_outside_the_parser_budget()
-> Result<(), TestError> {
    const ROLE: &str = "TUNNEL_DETOUR_API_ALLOCATION_PROBE";
    const OWNER: &str = "adguard::response_tests::r150_api_collections_reject_cardinality_amplification_before_allocating_outside_the_parser_budget";
    let array = |count: usize| format!("[{}\"\"]", "\"\",".repeat(count - 1));
    if std::env::var(ROLE).as_deref() == Ok("1") {
        // Construct equal-size classes before applying the process-local budget.
        // Only decoding is constrained; the parent and other tests are untouched.
        let compact = format!("{{\"upstream_dns\":{}}}", array(1_300_000));
        let padding = format!(
            "{{\"upstream_dns\":[],\"future\":\"{}\"}}",
            "x".repeat(3_900_000)
        );
        assert!(compact.len() < 4 * 1024 * 1024 && padding.len() < 4 * 1024 * 1024);
        let status = std::fs::read_to_string("/proc/self/status")?;
        let virtual_kib: u64 = status
            .lines()
            .find_map(|line| line.strip_prefix("VmSize:"))
            .and_then(|line| line.split_whitespace().next())
            .ok_or("missing parser address-space accounting")?
            .parse()?;
        let budget = virtual_kib
            .checked_mul(1024)
            .and_then(|bytes| bytes.checked_add(8 * 1024 * 1024))
            .ok_or("API parser budget overflow")?;
        for (resource, limit) in [
            (rustix::process::Resource::Core, 0),
            (rustix::process::Resource::Cpu, 3),
            (rustix::process::Resource::As, budget),
        ] {
            rustix::process::setrlimit(
                resource,
                rustix::process::Rlimit {
                    current: Some(limit),
                    maximum: Some(limit),
                },
            )?;
        }
        assert!(
            AdguardControl::decode::<DnsInfo>("dns_info", padding.as_bytes()).is_ok(),
            "large ignored metadata must remain supported"
        );
        assert!(
            AdguardControl::decode::<DnsInfo>("dns_info", compact.as_bytes()).is_err(),
            "compact oversized collections must be refused before materialization"
        );
        println!(
            "API collection amplification rejected within an 8-MiB incremental address-space budget"
        );
        return Ok(());
    }
    let child = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", OWNER, "--nocapture"])
        .env(ROLE, "1")
        .output()?;
    if !child.status.success() {
        return Err(format!(
            "bounded API parser child failed {}: {}",
            child.status,
            String::from_utf8_lossy(&child.stderr)
        )
        .into());
    }
    assert!(String::from_utf8(child.stdout)?.contains(
        "API collection amplification rejected within an 8-MiB incremental address-space budget"
    ));
    let at_limit = format!("{{\"upstream_dns\":{}}}", array(8192));
    assert_eq!(
        AdguardControl::decode::<DnsInfo>("dns_info", at_limit.as_bytes())?
            .upstream_dns
            .len(),
        8192
    );
    let beyond = format!("{{\"upstream_dns\":{}}}", array(8193));
    assert!(AdguardControl::decode::<DnsInfo>("dns_info", beyond.as_bytes()).is_err());
    for field in ["bootstrap_dns", "fallback_dns"] {
        let valid = format!("{{\"upstream_dns\":[],\"{field}\":{}}}", array(64));
        assert!(AdguardControl::decode::<DnsInfo>("dns_info", valid.as_bytes()).is_ok());
        let invalid = format!("{{\"upstream_dns\":[],\"{field}\":{}}}", array(65));
        assert!(AdguardControl::decode::<DnsInfo>("dns_info", invalid.as_bytes()).is_err());
    }
    for count in [256, 257] {
        let input = format!(
            "{{\"running\":true,\"dns_addresses\":{},\"dns_port\":53,\"protection_enabled\":true}}",
            array(count)
        );
        assert_eq!(
            AdguardControl::decode::<ServerStatus>("status", input.as_bytes()).is_ok(),
            count == 256
        );
    }
    let client = |ids: usize| {
        format!(
            "{{\"name\":\"synthetic\",\"ids\":{},\"use_global_settings\":false,\"filtering_enabled\":false,\"disallowed\":true}}",
            array(ids)
        )
    };
    for count in [64, 65] {
        let persistent = format!("{{\"clients\":[{}]}}", client(count));
        let search = format!("[{{\"192.0.2.2\":{}}}]", client(count));
        assert_eq!(
            AdguardControl::decode::<Clients>("clients", persistent.as_bytes()).is_ok(),
            count == 64
        );
        let parsed = AdguardControl::decode::<ClientSearch>("clients/search", search.as_bytes());
        assert_eq!(parsed.is_ok(), count == 64);
        if count == 64 {
            let parsed = parsed?;
            assert!(
                parsed.0[0].0["192.0.2.2"].disallowed,
                "bounded decoding lost the filtering decision"
            );
        }
    }
    for count in [1024, 1025] {
        let entries = vec![client(1); count].join(",");
        let persistent = format!("{{\"clients\":[{entries}]}}");
        assert_eq!(
            AdguardControl::decode::<Clients>("clients", persistent.as_bytes()).is_ok(),
            count == 1024
        );
    }
    for input in ["{}", "{\"clients\":null}", "{\"clients\":[]}"] {
        assert!(AdguardControl::decode::<Clients>("clients", input.as_bytes()).is_ok());
    }
    for input in ["[]", "[{}]"] {
        assert!(AdguardControl::decode::<ClientSearch>("clients/search", input.as_bytes()).is_ok());
    }
    for input in [
        "[{},{}]".to_owned(),
        format!(
            "[{{\"192.0.2.2\":{},\"192.0.2.3\":{}}}]",
            client(1),
            client(1)
        ),
        // Duplicate keys also count; replacing an existing map entry must not
        // allow arbitrarily many materialized values.
        format!(
            "[{{\"192.0.2.2\":{},\"192.0.2.2\":{}}}]",
            client(1),
            client(1)
        ),
    ] {
        assert!(
            AdguardControl::decode::<ClientSearch>("clients/search", input.as_bytes()).is_err()
        );
    }
    let unknown = serde_json::to_vec(
        &serde_json::json!({"upstream_dns":[],"future":{"values":vec!["unused";20_000],"escaped":"\\\"[,]{}:".repeat(20_000),"number":null}}),
    )?;
    assert!(
        AdguardControl::decode::<DnsInfo>("dns_info", &unknown).is_ok(),
        "ignored future metadata must not consume typed collection quotas"
    );
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(super::recovery_tests::oversized_merge_preserves_remote_settings_and_journal())?;
    Ok(())
}

#[test]
fn r144_adguard_responses_require_one_utf8_json_document_with_valid_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let status = STATUS;
    let mut valid = status.to_vec();
    valid.extend_from_slice(b" \t\r\n");
    let parsed: ServerStatus = AdguardControl::decode("status", &valid)?;
    assert!(parsed.running && parsed.protection_enabled);
    assert_eq!(parsed.dns_port, 53);
    assert_eq!(parsed.dns_addresses, ["127.0.0.1"]);

    for trailer in [
        b"{}".as_slice(),
        b"false",
        b" null",
        b"\n[]",
        b"garbage",
        b"\0",
        b"\xff",
    ] {
        let mut invalid = status.to_vec();
        invalid.extend_from_slice(trailer);
        assert!(
            AdguardControl::decode::<ServerStatus>("status", &invalid).is_err(),
            "an API reply with a second document or invalid trailer was accepted"
        );
    }
    let mut invalid_unknown = status[..status.len() - 1].to_vec();
    invalid_unknown.extend_from_slice(b",\"future_field\":\"\xff\"}");
    assert!(
        AdguardControl::decode::<ServerStatus>("status", &invalid_unknown).is_err(),
        "an ignored field bypassed the document's UTF-8 boundary"
    );
    assert!(matches!(
        AdguardControl::decode::<DnsInfo>("dns_info", b"{\"upstream_dns\":[],\"\":[\"\xff\"]}"),
        Err(AdguardError::Encoding(_))
    ));
    let mut extended = status[..status.len() - 1].to_vec();
    extended.extend_from_slice(br#", "future_field":{"label":"\u00E9","large_number":1e400}}"#);
    assert!(
        AdguardControl::decode::<ServerStatus>("status", &extended)?.running,
        "valid unknown fields must retain forward compatibility"
    );
    for invalid in [
        &status[..status.len() - 1],
        b"{}",
        br#"{"running":"true","dns_addresses":[],"dns_port":53,"protection_enabled":true}"#,
        br#"{"running":true,"running":false,"dns_addresses":[],"dns_port":53,"protection_enabled":true}"#,
    ] {
        assert!(AdguardControl::decode::<ServerStatus>("status", invalid).is_err());
    }
    let invalid = br#"{"running":true,"dns_addresses":[],"dns_port":"private-synthetic-value","protection_enabled":true}"#;
    match AdguardControl::decode::<ServerStatus>("status", invalid) {
        Err(AdguardError::Response {
            operation, field, ..
        }) => {
            assert_eq!(operation, "status");
            assert_eq!(field, "dns_port", "field diagnostics lost their location");
        }
        _ => return Err("invalid API field did not retain structured diagnostics".into()),
    }
    Ok(())
}

async fn accept_probe(listener: &TcpListener) -> Result<TcpStream, TestError> {
    let (mut stream, peer) = listener.accept().await?;
    assert!(
        peer.ip().is_loopback(),
        "fixture accepted a nonlocal client"
    );
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") && header.len() < 4096 {
        header.push(stream.read_u8().await?);
    }
    assert!(header.starts_with(b"GET /control/status HTTP/1.1\r\n"));
    assert!(header.ends_with(b"\r\n\r\n"), "unbounded fixture request");
    Ok(stream)
}

async fn reply(
    control: &AdguardControl,
    listener: &TcpListener,
    bytes: &[u8],
) -> Result<Result<AdguardHealth, AdguardError>, TestError> {
    let server = async {
        let mut stream = accept_probe(listener).await?;
        if let Err(error) = stream.write_all(bytes).await
            && !matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            )
        {
            return Err(error.into());
        }
        Ok::<_, TestError>(())
    };
    let request = async { Ok::<_, TestError>(control.probe().await) };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::try_join!(request, server)
    })
    .await??;
    Ok(result)
}

async fn require_full_capacity(
    control: &AdguardControl,
    listener: &TcpListener,
    response: &[u8],
) -> Result<(), TestError> {
    let server = async {
        let mut streams = Vec::new();
        // No response is released until all eight requests reach the socket.
        // Even one leaked permit must fail this barrier, rather than merely
        // demonstrating that some capacity survived the previous failure.
        for _ in 0..8 {
            streams.push(accept_probe(listener).await?);
        }
        for mut stream in streams {
            stream.write_all(response).await?;
        }
        Ok::<_, TestError>(())
    };
    let requests = async {
        let (a, b, c, d, e, f, g, h) = tokio::try_join!(
            control.probe(),
            control.probe(),
            control.probe(),
            control.probe(),
            control.probe(),
            control.probe(),
            control.probe(),
            control.probe(),
        )?;
        for health in [a, b, c, d, e, f, g, h] {
            assert!(health.dns_running && health.protection_enabled);
        }
        Ok::<_, TestError>(())
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::try_join!(requests, server)
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn r145_adguard_api_bounds_declared_and_chunked_bodies_and_recovers_after_timeout_and_cancellation()
-> Result<(), TestError> {
    // This fixture owns only an ephemeral loopback socket. Both futures are
    // joined or dropped together; it never contacts an existing DNS/frontend.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let control = AdguardControl::new(AdguardSettings {
        api_url: format!("http://{}", listener.local_addr()?),
        username: None,
        password: None,
    })?;
    let mut valid = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        STATUS.len()
    )
    .into_bytes();
    valid.extend_from_slice(STATUS);
    let health = reply(&control, &listener, &valid).await??;
    assert!(health.dns_running && health.protection_enabled);

    let mut at_limit = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {MAX_API_REPLY_BYTES}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let header_length = at_limit.len();
    at_limit.extend_from_slice(STATUS);
    at_limit.resize(header_length + MAX_API_REPLY_BYTES, b' ');
    assert!(reply(&control, &listener, &at_limit).await??.dns_running);

    // Refuse an oversized declared body before trying to receive its bytes.
    let declared = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        MAX_API_REPLY_BYTES + 1
    );
    assert!(matches!(
        reply(&control, &listener, declared.as_bytes()).await?,
        Err(AdguardError::TooLarge)
    ));
    // Chunked transfer has no Content-Length; the same cumulative bound applies.
    let mut chunked = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
        MAX_API_REPLY_BYTES + 1
    )
    .into_bytes();
    chunked.resize(chunked.len() + MAX_API_REPLY_BYTES + 1, b' ');
    chunked.extend_from_slice(b"\r\n0\r\n\r\n");
    assert!(matches!(
        reply(&control, &listener, &chunked).await?,
        Err(AdguardError::TooLarge)
    ));

    // Cancel every available request slot only after the real HTTP request
    // reaches the fixture. A leaked permit would prevent later requests.
    for _ in 0..8 {
        let arrived = tokio::sync::Notify::new();
        let server = async {
            let mut stream = accept_probe(&listener).await?;
            arrived.notify_one();
            assert_eq!(stream.read(&mut [0; 1]).await?, 0);
            Ok::<_, TestError>(())
        };
        let request = async {
            let probe = control.probe();
            tokio::pin!(probe);
            tokio::select! {
                _ = arrived.notified() => Ok::<_, TestError>(()),
                _ = &mut probe => Err("stalled request completed before cancellation".into()),
            }
        };
        tokio::time::timeout(Duration::from_secs(3), async {
            tokio::try_join!(request, server)
        })
        .await??;
    }
    require_full_capacity(&control, &listener, &valid).await?;

    // Exercise the production client's actual ten-second whole-request timeout,
    // without changing its builder or relying on a shorter test-only deadline.
    let server = async {
        let mut stream = accept_probe(&listener).await?;
        assert_eq!(stream.read(&mut [0; 1]).await?, 0);
        Ok::<_, TestError>(())
    };
    let request = async { Ok::<_, TestError>(control.probe().await) };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(14), async {
        tokio::try_join!(request, server)
    })
    .await??;
    assert!(matches!(result, Err(AdguardError::Request(error)) if error.is_timeout()));
    require_full_capacity(&control, &listener, &valid).await?;
    Ok(())
}
