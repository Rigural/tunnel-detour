//! Synthetic HTTP and fixed-arrival DNS actors for full-application observations.
//! These actors never choose production DNS or run in the measured node cgroup.

use super::{Result, actor_resources};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use serde_json::{Value, json};
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
    task::JoinSet,
    time::{Instant, sleep_until, timeout},
};
use xtask::latency;

/// Enter only a named disposable endpoint before the runtime creates threads.
pub(super) fn enter_namespace() -> Result {
    use std::os::fd::AsFd;
    let Ok(namespace) = std::env::var("TUNNEL_DETOUR_BENCH_NETNS") else {
        return Ok(());
    };
    if std::env::var("TUNNEL_DETOUR_BENCH_LAB").as_deref() != Ok("1")
        || !["lan", "wan"].contains(&namespace.as_str())
        || !rustix::process::geteuid().is_root()
    {
        return Err("namespace entry requires a declared disposable endpoint".into());
    }
    let namespace = std::fs::File::open(format!("/proc/1/root/var/run/netns/td-app-{namespace}"))?;
    rustix::thread::move_into_link_name_space(
        namespace.as_fd(),
        Some(rustix::thread::LinkNameSpaceType::Network),
    )?;
    Ok(())
}

pub(super) async fn configured() -> Result {
    timeout(Duration::from_secs(60), async {
        while !Path::new("/tmp/application-start").exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    Ok(())
}

async fn serve(mut stream: TcpStream, body: &'static [u8]) -> Result {
    loop {
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            if header.len() >= 8192 {
                return Err("application origin request header exceeded its bound".into());
            }
            match timeout(Duration::from_secs(10), stream.read_u8()).await {
                Ok(Ok(byte)) => header.push(byte),
                Ok(Err(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                    ) && header.is_empty() =>
                {
                    return Ok(());
                }
                Err(_) if header.is_empty() => return Ok(()),
                Ok(Err(error)) => return Err(error.into()),
                Err(error) => return Err(error.into()),
            }
        }
        if !header.starts_with(b"GET /route.txt HTTP/1.1\r\n") {
            return Err("unexpected synthetic application request".into());
        }
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            body.len()
        );
        // One short frame avoids an artificial header/body Nagle + delayed-ACK
        // stall in the synthetic endpoint. The client still verifies all bytes.
        response.push_str(std::str::from_utf8(body)?);
        timeout(
            Duration::from_secs(3),
            stream.write_all(response.as_bytes()),
        )
        .await??;
    }
}

pub(super) async fn origin(device: &str, route: &str) -> Result {
    let body: &'static [u8] = match (device, route) {
        ("bench0", "wan") => b"application-wan",
        ("wgpeer0", "vpn") => b"application-vpn",
        _ => return Err("application origin requires a synthetic WAN or VPN device".into()),
    };
    configured().await?;
    let socket = TcpSocket::new_v4()?;
    socket2::SockRef::from(&socket)
        .bind_device(Some(device.as_bytes()))
        .map_err(|error| format!("synthetic origin device binding failed: {error}"))?;
    socket.set_reuseaddr(true)?;
    socket
        .bind("203.0.113.2:80".parse()?)
        .map_err(|error| format!("synthetic origin address binding failed: {error}"))?;
    let listener: TcpListener = socket.listen(128)?;
    let mut jobs = JoinSet::new();
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut resolver = if route == "vpn" {
        Some(
            tokio::process::Command::new("unbound")
                .args(["-d", "-c", "/tmp/application-unbound.conf"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::inherit())
                .kill_on_drop(true)
                .spawn()?,
        )
    } else {
        None
    };
    println!(
        "{}",
        json!({"ready":true,"role":"application-origin","route":route})
    );
    let result = async {
        loop {
            tokio::select! {
                _ = term.recv() => return Ok::<_,Box<dyn std::error::Error + Send + Sync>>(()),
                status = async { Ok::<_,Box<dyn std::error::Error+Send+Sync>>(resolver.as_mut().ok_or("missing owned resolver")?.wait().await?) }, if resolver.is_some() => {
                    return Err(format!("the synthetic VPN resolver exited unexpectedly: {}", status?).into());
                }
                completed = jobs.join_next(), if !jobs.is_empty() => { completed.ok_or("missing origin task")???; }
                accepted = listener.accept(), if jobs.len() < 128 => {
                    let (stream, _) = accepted?;
                    jobs.spawn(serve(stream, body));
                }
            }
        }
    }.await;
    jobs.abort_all();
    let mut completion: Result = Ok(());
    while let Some(completed) = jobs.join_next().await {
        let observed: Result = match completed {
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error.into()),
            Ok(result) => result,
        };
        if completion.is_ok() {
            completion = observed;
        }
    }
    let resolver_shutdown: Result = async {
        if let Some(mut resolver) = resolver {
            if resolver.try_wait()?.is_none() {
                resolver.start_kill()?;
            }
            resolver.wait().await?;
        }
        Ok(())
    }
    .await;
    result?;
    completion?;
    resolver_shutdown
}

async fn question(remote: SocketAddr, kind: RecordType, id: u16) -> Result {
    let mut request = Message::new(id, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(
        Name::from_ascii("selected.example.net.")?,
        kind,
    ));
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    socket.connect(remote).await?;
    socket.send(&request.to_vec()?).await?;
    let mut bytes = [0; 4096];
    let count = socket.recv(&mut bytes).await?;
    let response = Message::from_vec(&bytes[..count])?;
    if response.metadata.id != id
        || response.queries != request.queries
        || response.metadata.message_type != MessageType::Response
        || response.metadata.response_code != ResponseCode::NoError
        || response.metadata.truncation
        || response.metadata.authentic_data
    {
        return Err("application DNS response failed its independent acceptance checks".into());
    }
    match kind {
        RecordType::A
            if response.answers.len() == 1
                && matches!(&response.answers[0].data, RData::A(value) if value.0 == Ipv4Addr::new(198,18,0,1)) =>
            {}
        RecordType::AAAA | RecordType::HTTPS if response.answers.is_empty() => {}
        _ => {
            return Err(
                "application DNS lost its identity or exposed an alternate endpoint".into(),
            );
        }
    }
    Ok(())
}

struct Samples {
    replies: u64,
    errors: u64,
    capacity: u64,
    rtt: Vec<u64>,
    scheduled: Vec<u64>,
    first_error: Option<String>,
}
impl Samples {
    fn new() -> Self {
        Self {
            replies: 0,
            errors: 0,
            capacity: 0,
            rtt: vec![0; latency::BUCKETS],
            scheduled: vec![0; latency::BUCKETS],
            first_error: None,
        }
    }
    fn record(&mut self, value: Result<(Duration, Duration)>) -> Result {
        match value {
            Ok((rtt, scheduled)) => {
                self.replies = self
                    .replies
                    .checked_add(1)
                    .ok_or("application sample count overflow")?;
                for (histogram, elapsed) in [(&mut self.rtt, rtt), (&mut self.scheduled, scheduled)]
                {
                    let bucket = latency::bucket(elapsed.as_micros())?;
                    histogram[bucket] = histogram[bucket]
                        .checked_add(1)
                        .ok_or("application histogram overflow")?;
                }
            }
            Err(error) => {
                self.errors = self
                    .errors
                    .checked_add(1)
                    .ok_or("application error count overflow")?;
                if self.first_error.is_none() {
                    self.first_error = Some(error.to_string());
                }
            }
        }
        Ok(())
    }
    fn value(self) -> Value {
        json!({"successful":self.replies,"errors":self.errors,"capacity_refused":self.capacity,"first_error":self.first_error,"rtt_histogram_microseconds":self.rtt,"scheduled_histogram_microseconds":self.scheduled})
    }
}

async fn http(client: &reqwest::Client, name: &str, expected: &[u8]) -> Result {
    let reply = client
        .get(format!("http://{name}/route.txt"))
        .send()
        .await
        .map_err(|error| format!("synthetic HTTP request failed: {error:?}"))?
        .error_for_status()?;
    // This fixture requires an exact short body, never an unbounded body read.
    if reply.content_length() != Some(u64::try_from(expected.len())?) {
        return Err("application origin sent an unexpected body length".into());
    }
    if reply.bytes().await?.as_ref() != expected {
        return Err("application HTTP traversed the wrong WAN/VPN path or corrupted data".into());
    }
    Ok(())
}

pub(super) async fn held_client() -> Result {
    configured().await?;
    timeout(
        Duration::from_secs(3),
        question("192.0.2.1:53".parse()?, RecordType::A, 65534),
    )
    .await??;
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect("198.18.0.1:80")).await??;
    timeout(Duration::from_secs(3), async {
        stream
            .write_all(b"GET /route.txt HTTP/1.1\r\nHost: selected.example.net\r\n\r\n")
            .await?;
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            if header.len() >= 8192 {
                return Err("held-client response header exceeded its bound".into());
            }
            header.push(stream.read_u8().await?);
        }
        if !header.starts_with(b"HTTP/1.1 200 OK\r\n") {
            return Err("held-client origin rejected its request".into());
        }
        let mut body = [0_u8; 15];
        stream.read_exact(&mut body).await?;
        if &body != b"application-wan" {
            return Err("held client used the wrong path or corrupted its payload".into());
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    println!(
        "{}",
        json!({"role":"application-held","ready":true,"local_endpoint":stream.local_addr()?.to_string(),"payload_verified":true})
    );
    timeout(Duration::from_secs(20), async {
        while !Path::new("/tmp/application-check-closed").exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    match timeout(Duration::from_secs(3), stream.read_u8()).await? {
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
            ) => {}
        other => {
            return Err(format!(
                "terminated worker did not close its actual held connection: {other:?}"
            )
            .into());
        }
    }
    println!(
        "{}",
        json!({"role":"application-held","closed":true,"payload_verified":true})
    );
    Ok(())
}

pub(super) fn kill_worker(pid: u32, parent: u32) -> Result {
    if !rustix::process::geteuid().is_root()
        || !Path::new("/proc/1/root/etc/tunnel-detour-container").is_dir()
    {
        return Err("worker fault injection requires the disposable native fixture".into());
    }
    let id = rustix::process::Pid::from_raw(i32::try_from(pid)?).ok_or("invalid worker PID")?;
    let handle = rustix::process::pidfd_open(id, rustix::process::PidfdFlags::NONBLOCK)?;
    let command = std::fs::read(format!("/proc/{pid}/cmdline"))?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    let ppid = status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .ok_or("worker has no parent status")?
        .trim()
        .parse::<u32>()?;
    if ppid != parent
        || !command
            .split(|byte| *byte == 0)
            .any(|argument| argument == b"--transport-worker")
        || std::fs::read_link(format!("/proc/{pid}/exe"))? != Path::new("/usr/bin/tunnel-detour")
    {
        return Err(
            "fault injection target is not the selected controller's transport child".into(),
        );
    }
    rustix::process::pidfd_send_signal(&handle, rustix::process::Signal::KILL)?;
    Ok(())
}

pub(super) async fn client(seconds: u64, churn: bool, http_qps: u64) -> Result {
    if !(5..=30).contains(&seconds) {
        return Err("application pilot requires 5–30 seconds".into());
    }
    if !(1..=20).contains(&http_qps) || !200_u64.is_multiple_of(http_qps) {
        return Err("HTTP arrival rate must divide 200 and lie in 1..=20".into());
    }
    configured().await?;
    let remote: SocketAddr = "192.0.2.1:53".parse()?;
    timeout(
        Duration::from_secs(3),
        question(remote, RecordType::A, 65535),
    )
    .await??;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .http1_only()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(3))
        .pool_max_idle_per_host(if churn { 0 } else { 1 })
        .resolve("selected.example.net", "198.18.0.1:80".parse()?)
        .resolve("ordinary.example.net", "203.0.113.2:80".parse()?)
        .build()?;
    http(&client, "selected.example.net", b"application-wan").await?;
    http(&client, "ordinary.example.net", b"application-vpn").await?;
    println!("{}", json!({"ready":true,"role":"application-client"}));
    let started = Instant::now();
    let mut jobs: JoinSet<(usize, Result<(Duration, Duration)>)> = JoinSet::new();
    let mut samples: Vec<_> = (0..5).map(|_| Samples::new()).collect();
    let mut offered = [0_u64; 5];
    let epoch = Instant::now();
    let result = async {
        for index in 0..seconds * 200 {
            let scheduled = epoch + Duration::from_millis(index * 5);
            sleep_until(scheduled).await;
            while let Some(completed) = jobs.try_join_next() {
                let (kind, result) = completed?;
                samples[kind].record(result)?;
            }
            let dns_kind = usize::try_from(index % 3)?;
            let mut operations = vec![dns_kind];
            if index % (200 / http_qps) == 0 {
                operations.extend([3, 4]);
            }
            for kind in operations {
                offered[kind] = offered[kind]
                    .checked_add(1)
                    .ok_or("offered application count overflow")?;
                if jobs.len() >= 64 {
                    samples[kind].capacity = samples[kind]
                        .capacity
                        .checked_add(1)
                        .ok_or("application capacity count overflow")?;
                    continue;
                }
                let client = client.clone();
                jobs.spawn(async move {
                    let sent = Instant::now();
                    let result: Result<(Duration, Duration)> = async {
                        timeout(Duration::from_secs(3), async {
                            match kind {
                                0..=2 => {
                                    question(
                                        remote,
                                        [RecordType::A, RecordType::AAAA, RecordType::HTTPS][kind],
                                        u16::try_from(index)?,
                                    )
                                    .await
                                }
                                3 => {
                                    http(&client, "selected.example.net", b"application-wan").await
                                }
                                4 => {
                                    http(&client, "ordinary.example.net", b"application-vpn").await
                                }
                                _ => Err("invalid application operation".into()),
                            }
                        })
                        .await??;
                        let received = Instant::now();
                        Ok((
                            received.duration_since(sent),
                            received.duration_since(scheduled),
                        ))
                    }
                    .await;
                    (kind, result)
                });
            }
        }
        while let Some(completed) = jobs.join_next().await {
            let (kind, result) = completed?;
            samples[kind].record(result)?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    jobs.abort_all();
    while let Some(completed) = jobs.join_next().await {
        match completed {
            Err(error) if error.is_cancelled() => {}
            other => {
                let (kind, value) = other?;
                samples[kind].record(value)?;
            }
        }
    }
    result?;
    for (index, sample) in samples.iter().enumerate() {
        if sample.replies + sample.errors + sample.capacity != offered[index] {
            return Err("application operation accounting mismatch".into());
        }
    }
    let success = samples
        .iter()
        .all(|sample| sample.errors == 0 && sample.capacity == 0);
    println!(
        "{}",
        json!({"role":"application-client","seconds":seconds,"http_qps_per_route":http_qps,"http_connection_reuse":!churn,"offered":offered,"operations":["dns_A","dns_AAAA","dns_HTTPS","http_WAN","http_WireGuard"],"results":samples.into_iter().map(Samples::value).collect::<Vec<_>>(),"histogram_schema":latency::schema(),"max_in_flight":64,"scope":"HTTP/1.1 plaintext with declared connection reuse policy and hot DNS; HTTP resolve overrides use previously verified synthetic identity/ordinary IP; DNS generator remains separate; no TLS timing or cold-DNS claim","actor_resources":actor_resources(started)?})
    );
    if !success {
        return Err("application workload reported errors or generator capacity refusals".into());
    }
    Ok(())
}
