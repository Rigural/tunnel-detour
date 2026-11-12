//! R148: a lost HTTP reply is not evidence that the remote write was rolled back.

use super::*;
use std::{num::NonZeroUsize, path::PathBuf, sync::Mutex};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

type TestError = Box<dyn std::error::Error>;
const FORWARD: &str = "[/selected.example.test/]127.0.0.1:10535";

/// R150 also proves that a supported snapshot cannot generate an unrecoverable
/// oversized remote write when one owned conditional forward is appended.
pub(super) async fn oversized_merge_preserves_remote_settings_and_journal() -> Result<(), TestError>
{
    let directory = tempfile::tempdir()?;
    let state = directory.path().join("leases.json");
    let journal = appended_path(&state, ".adguard.json");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let settings = AdguardSettings {
        api_url: format!("http://{}", listener.local_addr()?),
        username: None,
        password: None,
    };
    let original = DnsInfo {
        upstream_dns: vec!["# synthetic foreign configuration".into(); 8192],
        upstream_dns_file: String::new(),
        fallback_dns: Some(vec![]),
        bootstrap_dns: Some(vec![]),
    };
    let model = Arc::new(Mutex::new(Model {
        dns: original.clone(),
        journal: journal.clone(),
        delayed: false,
        writes: 0,
    }));
    let (seen_tx, _seen_rx) = oneshot::channel();
    let (_release_tx, release_rx) = oneshot::channel();
    let (settled_tx, _settled_rx) = oneshot::channel();
    let (done_tx, done_rx) = oneshot::channel();
    let fixture = server(
        listener,
        model.clone(),
        LostReply::PostCancelled,
        seen_tx,
        release_rx,
        settled_tx,
        done_rx,
    );
    let exercise = async {
        let mut manager = AdguardManager::open(settings, &state, Some("127.0.0.1:15353".parse()?))?;
        let before = if journal.try_exists()? {
            Some(std::fs::read(&journal)?)
        } else {
            None
        };
        let rules = RuleSet::from_lines(
            "selected.example.test",
            NonZeroUsize::new(8).ok_or("invalid capacity")?,
        )?;
        assert!(
            matches!(
                manager
                    .reconcile(Some((
                        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10535),
                        &rules
                    )))
                    .await,
                Err(AdguardError::TooLarge)
            ),
            "an oversized merge must be refused before a remote write"
        );
        let after = if journal.try_exists()? {
            Some(std::fs::read(&journal)?)
        } else {
            None
        };
        assert_eq!(
            before, after,
            "refused cardinality changed the recovery journal"
        );
        {
            let observed = model.lock().map_err(|_| "poisoned fixture")?;
            assert_eq!(observed.writes, 0, "an unreadable list reached the API");
            assert!(
                observed.dns == original,
                "a refused merge changed foreign upstream settings"
            );
        }
        done_tx
            .send(())
            .map_err(|_| "fixture stopped before verification")?;
        Ok::<_, TestError>(())
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::try_join!(exercise, fixture)
    })
    .await??;
    Ok(())
}

#[derive(Clone, Copy)]
enum LostReply {
    PostCancelled,
    PostTimeout,
    CacheClearCancelled,
}

struct Model {
    dns: DnsInfo,
    journal: PathBuf,
    delayed: bool,
    writes: usize,
}

async fn request(stream: &mut TcpStream) -> Result<(String, Vec<u8>), TestError> {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= 8192 {
            return Err("unbounded recovery fixture HTTP header".into());
        }
        header.push(stream.read_u8().await?);
    }
    let header = std::str::from_utf8(&header)?;
    let first = header
        .lines()
        .next()
        .ok_or("missing recovery request line")?
        .to_owned();
    let mut length = 0_usize;
    for line in header.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse()?;
            }
            if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err("unexpected chunked fixture request".into());
            }
        }
    }
    if length > 65536 {
        return Err("unbounded recovery fixture request body".into());
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    Ok((first, body))
}

async fn respond(stream: &mut TcpStream, body: &[u8]) -> Result<(), TestError> {
    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn server(
    listener: TcpListener,
    model: Arc<Mutex<Model>>,
    loss: LostReply,
    seen: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
    settled: oneshot::Sender<()>,
    mut done: oneshot::Receiver<()>,
) -> Result<(), TestError> {
    let mut seen = Some(seen);
    let mut release = Some(release);
    let mut settled = Some(settled);
    loop {
        let (mut stream, peer) = tokio::select! {
            _=&mut done => return Ok(()),
            result=listener.accept()=>result?,
        };
        assert!(peer.ip().is_loopback());
        let (request, body) = request(&mut stream).await?;
        let (response, delay) = {
            let mut state = model.lock().map_err(|_| "poisoned recovery fixture")?;
            match request.as_str() {
                "GET /control/dns_info HTTP/1.1" => (serde_json::to_vec(&state.dns)?,false),
                "GET /control/status HTTP/1.1" => (br#"{"running":true,"dns_addresses":["127.0.0.1"],"dns_port":53,"protection_enabled":true}"#.to_vec(),false),
                "POST /control/dns_config HTTP/1.1" => {
                    let next:serde_json::Value=serde_json::from_slice(&body)?;
                    let lines:Vec<String>=serde_json::from_value(next["upstream_dns"].clone())?;
                    if lines.iter().any(|line|line==FORWARD) {
                        let ownership:Ownership=integration_state::existing(&state.journal)?.ok_or("write reached the API without a recovery journal")?;
                        assert!(ownership.managed.contains(FORWARD),"recovery ownership was not durable before the remote mutation");
                    }
                    state.dns.upstream_dns=lines;
                    state.writes+=1;
                    let delay=!state.delayed && matches!(loss,LostReply::PostCancelled|LostReply::PostTimeout);
                    state.delayed|=delay;
                    (b"{}".to_vec(),delay)
                }
                "POST /control/cache_clear HTTP/1.1" => {
                    let delay=!state.delayed && matches!(loss,LostReply::CacheClearCancelled);
                    state.delayed|=delay;
                    (b"{}".to_vec(),delay)
                }
                _=>return Err(format!("unexpected recovery fixture request {request}").into()),
            }
        };
        if delay {
            seen.take()
                .ok_or("duplicate recovery write barrier")?
                .send(())
                .map_err(|_| "recovery observer disappeared")?;
            release
                .take()
                .ok_or("missing recovery release barrier")?
                .await?;
            match tokio::time::timeout(Duration::from_secs(2), stream.read_u8()).await? {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                    ) => {}
                other => {
                    return Err(format!(
                        "cancelled request did not close its actual HTTP connection: {other:?}"
                    )
                    .into());
                }
            }
            // The connection is gone, while the already-applied model mutation
            // remains. No successful reply is invented for the cancelled writer.
            settled
                .take()
                .ok_or("duplicate recovery settlement")?
                .send(())
                .map_err(|_| "recovery settlement receiver disappeared")?;
        } else {
            respond(&mut stream, &response).await?;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r148_lost_adguard_write_and_cache_clear_responses_retain_ownership_until_verified_recovery()
-> Result<(), TestError> {
    for loss in [
        LostReply::PostCancelled,
        LostReply::PostTimeout,
        LostReply::CacheClearCancelled,
    ] {
        let directory = tempfile::tempdir()?;
        let state = directory.path().join("leases.json");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let settings = AdguardSettings {
            api_url: format!("http://{}", listener.local_addr()?),
            username: None,
            password: None,
        };
        let original = DnsInfo {
            upstream_dns: vec![
                "tcp://192.0.2.53:5353".into(),
                "# preserve this foreign comment".into(),
                "[/unrelated.example.test/]tcp://192.0.2.54:5353".into(),
            ],
            upstream_dns_file: String::new(),
            fallback_dns: Some(vec![]),
            bootstrap_dns: Some(vec!["192.0.2.53".into()]),
        };
        let model = Arc::new(Mutex::new(Model {
            dns: original.clone(),
            journal: appended_path(&state, ".adguard.json"),
            delayed: false,
            writes: 0,
        }));
        let (seen_tx, seen_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let (settled_tx, settled_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let fixture = server(
            listener,
            model.clone(),
            loss,
            seen_tx,
            release_rx,
            settled_tx,
            done_rx,
        );
        let exercise = async {
            let mut manager =
                AdguardManager::open(settings.clone(), &state, Some("127.0.0.1:15353".parse()?))?;
            let rules = RuleSet::from_lines(
                "selected.example.test",
                NonZeroUsize::new(8).ok_or("invalid test capacity")?,
            )?;
            {
                let operation = manager.reconcile(Some((
                    SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10535),
                    &rules,
                )));
                tokio::pin!(operation);
                let seen = async {
                    seen_rx
                        .await
                        .map_err(|_| "recovery request never reached its write barrier")
                };
                tokio::pin!(seen);
                tokio::select! {
                    result=&mut operation=>return Err(format!("reconciliation finished before the lost-response barrier: {result:?}").into()),
                    result=&mut seen=>result?,
                }
                if matches!(loss, LostReply::PostTimeout) {
                    match operation.await {
                        Err(AdguardError::Request(error)) if error.is_timeout() => {}
                        other => {
                            return Err(format!(
                                "missing actual production HTTP write timeout: {other:?}"
                            )
                            .into());
                        }
                    }
                }
                // The other modes drop the actual in-flight reconciliation here.
            }
            release_tx
                .send(())
                .map_err(|_| "lost-response fixture stopped")?;
            settled_rx.await?;
            let ownership: Ownership =
                integration_state::existing(&appended_path(&state, ".adguard.json"))?
                    .ok_or("recovery journal disappeared")?;
            assert!(ownership.managed.contains(FORWARD));
            assert!(
                model
                    .lock()
                    .map_err(|_| "poisoned fixture")?
                    .dns
                    .upstream_dns
                    .iter()
                    .any(|line| line == FORWARD),
                "the lost response incorrectly rolled back the remote model"
            );
            drop(manager);
            assert!(
                AdguardManager::recovery(&state)?.is_some(),
                "restart lost its recoverable endpoint"
            );
            let added = "# foreign edit while the manager was stopped".to_owned();
            model
                .lock()
                .map_err(|_| "poisoned fixture")?
                .dns
                .upstream_dns
                .push(added.clone());
            let mut recovered =
                AdguardManager::open(settings, &state, Some("127.0.0.1:15353".parse()?))?;
            recovered.reconcile(None).await?;
            let mut expected = original.clone();
            expected.upstream_dns.push(added);
            let observed = model.lock().map_err(|_| "poisoned fixture")?;
            assert!(
                observed.dns == expected,
                "recovery removed a foreign setting or retained its conditional forward"
            );
            assert_eq!(
                observed.writes, 2,
                "a failed POST was retried as though it had never happened"
            );
            drop(observed);
            assert!(
                AdguardManager::recovery(&state)?.is_none(),
                "verified release retained live ownership"
            );
            done_tx
                .send(())
                .map_err(|_| "fixture stopped before recovery verification")?;
            Ok::<_, TestError>(())
        };
        tokio::time::timeout(Duration::from_secs(18), async {
            tokio::try_join!(exercise, fixture)
        })
        .await??;
    }
    Ok(())
}
