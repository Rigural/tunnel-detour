//! Development-only actors for the isolated relay benchmark; never shipped in an APK.

use std::{error::Error, net::SocketAddr, process::ExitCode, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    task::JoinSet,
    time::{Instant, timeout},
};
use tunnel_detour_service::{RelayAdmission, RelayLimits, RelaySessions};
use xtask::latency;

type Result<T = ()> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

#[path = "relay_bench/application.rs"]
mod application;
#[path = "relay_bench/bulk.rs"]
mod bulk;
#[path = "relay_bench/churn.rs"]
mod churn;
#[path = "relay_bench/dns.rs"]
mod dns;
#[path = "relay_bench/namespace_lifetime.rs"]
mod namespace_lifetime;
#[path = "relay_bench/operational.rs"]
mod operational;

fn actor_resources(started: Instant) -> Result<serde_json::Value> {
    use std::{collections::BTreeMap, fs};
    if fs::read_to_string("/proc/self/cgroup")?.trim() != "0::/" {
        return Err("actor accounting requires a private cgroup-v2 namespace".into());
    }
    let mut cpu = BTreeMap::new();
    for line in fs::read_to_string("/sys/fs/cgroup/cpu.stat")?.lines() {
        let mut fields = line.split_whitespace();
        let key = fields.next().ok_or("invalid cgroup CPU field")?;
        let value = fields
            .next()
            .ok_or("missing cgroup CPU value")?
            .parse::<u64>()?;
        if fields.next().is_some() || cpu.insert(key.to_owned(), value).is_some() {
            return Err("invalid or duplicate cgroup CPU field".into());
        }
    }
    if !cpu.contains_key("usage_usec") {
        return Err("cgroup CPU usage is unavailable".into());
    }
    let memory = fs::read_to_string("/sys/fs/cgroup/memory.current")?
        .trim()
        .parse::<u64>()?;
    Ok(
        serde_json::json!({"elapsed_microseconds":started.elapsed().as_micros(),"cpu_stat":cpu,"memory_current_bytes":memory}),
    )
}

fn retired_process(path: &std::path::Path) -> std::io::Result<bool> {
    // /proc may revoke fd-directory access during exit before State becomes Z.
    // Confirm retirement within a bound; never ignore permission errors of a live task.
    // This runs inside the already-owned blocking sampler, outside the measured cgroup.
    for attempt in 0..=25 {
        match std::fs::read_to_string(path.join("stat")) {
            Ok(stat) => match stat
                .rsplit_once(") ")
                .and_then(|(_, tail)| tail.split_whitespace().next())
            {
                Some("Z" | "X") => return Ok(true),
                Some(_) => {}
                None => return Err(std::io::Error::from(std::io::ErrorKind::InvalidData)),
            },
            Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => return Ok(true),
            Err(error) => return Err(error),
        }
        if attempt < 25 {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    Ok(false)
}

fn process_memory() -> Result<serde_json::Value> {
    use std::{fs, io::Read};
    let own = std::process::id();
    // Other application actors share this PID namespace to enter its owned
    // network namespaces, but retain independent cgroups. Never charge their
    // PSS, threads or descriptors to the native router.
    let target_group = fs::read_to_string("/proc/1/cgroup")?;
    let target_group = target_group
        .trim()
        .strip_prefix("0::")
        .ok_or("observer requires a unified target cgroup")?;
    if target_group == "/" || fs::read_to_string("/proc/self/cgroup")?.trim() != "0::/" {
        return Err("observer requires its own private cgroup outside the target".into());
    }
    let mut pss = 0_u64;
    let mut processes = 0_u32;
    let mut threads = 0_u64;
    let mut descriptors = 0_u64;
    'process: for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == own || pid == 0 {
            continue;
        }
        let group = match fs::read_to_string(entry.path().join("cgroup")) {
            Ok(group) => group,
            Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => continue,
            Err(error) => return Err(error.into()),
        };
        let group = group
            .trim()
            .strip_prefix("0::")
            .ok_or("invalid observed cgroup")?;
        if group != target_group
            && !group
                .strip_prefix(target_group)
                .is_some_and(|suffix| suffix.starts_with('/'))
        {
            continue;
        }
        let file = match fs::File::open(entry.path().join("smaps_rollup")) {
            Ok(file) => file,
            // A process can disappear between directory enumeration and open.
            // procfs reports either ENOENT or ESRCH for that race.
            Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => continue,
            Err(error)
                if error.kind() == std::io::ErrorKind::PermissionDenied
                    && retired_process(&entry.path())? =>
            {
                continue;
            }
            Err(error) => return Err(format!("open process PSS: {error}").into()),
        };
        let mut bytes = String::new();
        match file.take(65_537).read_to_string(&mut bytes) {
            Ok(_) if bytes.len() <= 65_536 => {}
            Ok(_) => return Err("process memory report exceeded its bound".into()),
            Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => continue,
            Err(error)
                if error.kind() == std::io::ErrorKind::PermissionDenied
                    && retired_process(&entry.path())? =>
            {
                continue;
            }
            Err(error) => return Err(format!("read process PSS: {error}").into()),
        }
        let amount = bytes
            .lines()
            .find_map(|line| line.strip_prefix("Pss:"))
            .ok_or("PSS is unavailable")?;
        let mut words = amount.split_whitespace();
        let value = words
            .next()
            .ok_or("PSS amount is missing")?
            .parse::<u64>()?;
        if words.next() != Some("kB") || words.next().is_some() {
            return Err("PSS units are invalid".into());
        }
        let status = match fs::read_to_string(entry.path().join("status")) {
            Ok(status) => status,
            Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => continue,
            Err(error)
                if error.kind() == std::io::ErrorKind::PermissionDenied
                    && retired_process(&entry.path())? =>
            {
                continue;
            }
            Err(error) => return Err(format!("read process status: {error}").into()),
        };
        let count = status
            .lines()
            .find_map(|line| line.strip_prefix("Threads:"))
            .ok_or("thread count is unavailable")?
            .trim()
            .parse::<u64>()?;
        let entries = match fs::read_dir(entry.path().join("fd")) {
            Ok(entries) => entries,
            Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => continue,
            Err(error)
                if error.kind() == std::io::ErrorKind::PermissionDenied
                    && retired_process(&entry.path())? =>
            {
                continue;
            }
            Err(error) => {
                return Err(format!(
                    "list process descriptors of {pid}: {error}; state: {:?}",
                    std::fs::read_to_string(entry.path().join("stat"))
                )
                .into());
            }
        };
        let mut descriptor_count = 0_u64;
        for descriptor in entries {
            match descriptor {
                Ok(_) => {}
                Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => continue 'process,
                Err(error) => return Err(error.into()),
            }
            descriptor_count = descriptor_count
                .checked_add(1)
                .ok_or("descriptor count overflow")?;
            if descriptor_count > 2048 {
                return Err("descriptor sampling capacity exceeded".into());
            }
        }
        pss = pss.checked_add(value).ok_or("PSS counter overflow")?;
        threads = threads.checked_add(count).ok_or("thread count overflow")?;
        descriptors = descriptors
            .checked_add(descriptor_count)
            .ok_or("descriptor count overflow")?;
        if descriptors > 2048 {
            return Err("descriptor sampling capacity exceeded".into());
        }
        processes = processes.checked_add(1).ok_or("process counter overflow")?;
        if processes > 128 {
            return Err("the relay process count exceeded the pilot bound".into());
        }
    }
    if processes == 0 {
        return Err("no relay processes were observed".into());
    }
    Ok(
        serde_json::json!({"pss_kib":pss,"processes":processes,"threads":threads,"descriptors":descriptors}),
    )
}

async fn observe() -> Result {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let started = Instant::now();
    let mut samples = Vec::new();
    println!("{}", serde_json::json!({"ready":true,"role":"observe"}));
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = term.recv() => break,
            _ = interval.tick() => {
                if samples.len() >= 600 { return Err("observer sampling capacity exceeded".into()); }
                // This owned job is always observed before cancellation is handled.
                let memory = tokio::task::spawn_blocking(process_memory).await??;
                samples.push(serde_json::json!({"elapsed_microseconds":started.elapsed().as_micros(),"memory":memory}));
            }
        }
    }
    println!(
        "{}",
        serde_json::json!({"role":"observe","samples":samples})
    );
    Ok(())
}

async fn relay(listen: SocketAddr, target: SocketAddr, lan: String, reply: String) -> Result {
    let (SocketAddr::V6(_), SocketAddr::V4(target)) = (listen, target) else {
        return Err("relay requires IPv6 ingress and an IPv4 destination".into());
    };
    let socket = TcpSocket::new_v6()?;
    let limits = RelayLimits::new(32, Duration::from_secs(5), Duration::from_secs(3600))?;
    limits.configure_socket(&socket)?;
    socket2::SockRef::from(&socket).set_only_v6(true)?;
    socket.set_reuseaddr(true)?;
    socket.bind(listen)?;
    let listener = socket.listen(u32::try_from(tunnel_detour_service::RELAY_LISTEN_BACKLOG)?)?;
    std::fs::create_dir_all("/var/run")?;
    let mut sessions = RelaySessions::new(limits).with_isolated_transport()?;
    let mut capacity_denials = 0_u64;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    println!("{}", serde_json::json!({"ready":true,"role":"relay"}));
    let result = async {
        loop {
            tokio::select! {
                biased;
                _ = term.recv() => break,
                result = sessions.next_completion() => {
                    let completion = result?;
                    if let Some(error)=completion.error { return Err(format!("relay session failed during measurement: {error:?}").into()); }
                }
                result = listener.accept() => {
                    let (stream, _) = result?;
                    // The benchmark fixture authorizes this fixed path. The integrated
                    // service's kernel proof is measured separately, never disabled there.
                    match sessions.enqueue(stream, RelayAdmission {
                        publication: "benchmark".parse()?, generation:1, target,
                        lan_device:lan.clone(), reply_device:reply.clone(),
                    }) {
                        Ok(_)=>{},
                        Err(tunnel_detour_service::RelayError::Capacity)=>{
                            if capacity_denials==0 {eprintln!("benchmark relay admission limit reached");}
                            capacity_denials=capacity_denials.checked_add(1).ok_or("capacity denial counter overflow")?;
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
            }
        }
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    }.await;
    drop(listener);
    let remaining = sessions.connections();
    let shutdown = sessions.shutdown().await;
    result?;
    shutdown?;
    println!(
        "{}",
        serde_json::json!({"capacity_denials":capacity_denials,"sessions_at_stop":remaining.len(),"queued_at_stop":remaining.iter().filter(|connection|connection.queued).count()})
    );
    Ok(())
}

async fn echo(listen: SocketAddr) -> Result {
    let listener = TcpListener::bind(listen).await?;
    let mut jobs = JoinSet::new();
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    println!("{}", serde_json::json!({"ready":true,"role":"echo"}));
    let result = async {
        loop {
            tokio::select! {
                _ = term.recv() => break,
                result = jobs.join_next(), if !jobs.is_empty() => {
                    result.ok_or("missing echo task")???;
                }
                result = listener.accept(), if jobs.len() < 128 => {
                    let (mut stream, _) = result?;
                    jobs.spawn(async move {
                        let mut bytes = [0; 16_384];
                        loop {
                            let count = timeout(Duration::from_secs(60), stream.read(&mut bytes)).await??;
                            if count == 0 { break; }
                            timeout(Duration::from_secs(5), stream.write_all(&bytes[..count])).await??;
                        }
                        stream.shutdown().await?;
                        Ok::<_, Box<dyn Error + Send + Sync>>(())
                    });
                }
            }
        }
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    }.await;
    jobs.abort_all();
    while let Some(result) = jobs.join_next().await {
        match result {
            Err(error) if error.is_cancelled() => {}
            other => other??,
        }
    }
    result
}

struct Samples {
    histogram: Vec<u64>,
    count: u64,
    bytes: u64,
    total_bytes: u64,
}
impl Samples {
    fn new() -> Self {
        Self {
            histogram: vec![0; latency::BUCKETS],
            count: 0,
            bytes: 0,
            total_bytes: 0,
        }
    }
    fn record(&mut self, size: usize, elapsed: Option<Duration>) -> Result {
        let bytes = u64::try_from(size)?
            .checked_mul(2)
            .ok_or("sample byte count overflow")?;
        self.total_bytes = self
            .total_bytes
            .checked_add(bytes)
            .ok_or("total byte count overflow")?;
        if let Some(elapsed) = elapsed {
            let bucket = latency::bucket(elapsed.as_micros())?;
            self.histogram[bucket] = self.histogram[bucket]
                .checked_add(1)
                .ok_or("histogram count overflow")?;
            self.count = self.count.checked_add(1).ok_or("exchange count overflow")?;
            self.bytes = self
                .bytes
                .checked_add(bytes)
                .ok_or("sample byte count overflow")?;
        }
        Ok(())
    }
    fn merge(&mut self, other: Self) -> Result {
        if other.histogram.len() != latency::BUCKETS {
            return Err("incompatible worker histogram".into());
        }
        self.count = self
            .count
            .checked_add(other.count)
            .ok_or("exchange count overflow")?;
        self.bytes = self
            .bytes
            .checked_add(other.bytes)
            .ok_or("measured byte count overflow")?;
        self.total_bytes = self
            .total_bytes
            .checked_add(other.total_bytes)
            .ok_or("total byte count overflow")?;
        for (total, value) in self.histogram.iter_mut().zip(other.histogram) {
            *total = total.checked_add(value).ok_or("histogram count overflow")?;
        }
        Ok(())
    }
}

async fn verify_echo(stream: &mut TcpStream, sent: &[u8], received: &mut [u8]) -> Result {
    timeout(Duration::from_secs(2), async {
        stream.write_all(sent).await?;
        stream.read_exact(received).await?;
        Ok::<_, std::io::Error>(())
    })
    .await??;
    if sent != received {
        return Err("benchmark stream integrity failed".into());
    }
    Ok(())
}

async fn ping(
    remote: SocketAddr,
    connections: usize,
    size: usize,
    warmup: u64,
    seconds: u64,
) -> Result {
    let started = Instant::now();
    if ![1, 4, 16, 32].contains(&connections)
        || ![64, 256, 1024].contains(&size)
        || warmup > 10
        || !(1..=30).contains(&seconds)
    {
        return Err("unsupported bounded latency workload".into());
    }
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(connections));
    let epoch = std::sync::Arc::new(std::sync::OnceLock::new());
    let mut jobs = JoinSet::new();
    for client in 0..connections {
        let barrier = barrier.clone();
        let epoch = epoch.clone();
        jobs.spawn(async move {
            let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(remote)).await??;
            stream.set_nodelay(false)?;
            barrier.wait().await;
            let measured = *epoch.get_or_init(Instant::now) + Duration::from_secs(warmup);
            let end = measured + Duration::from_secs(seconds);
            let mut samples = Samples::new();
            let mut packet = vec![u8::try_from(client)?; size];
            let mut received = vec![0; size];
            let mut sequence = 0_u64;
            while Instant::now() < end {
                packet[..8].copy_from_slice(&sequence.to_be_bytes());
                let start = Instant::now();
                verify_echo(&mut stream, &packet, &mut received).await?;
                samples.record(size, (start >= measured).then(|| start.elapsed()))?;
                sequence = sequence
                    .checked_add(1)
                    .ok_or("benchmark sequence exhausted")?;
            }
            stream.shutdown().await?;
            if timeout(Duration::from_secs(5), stream.read(&mut [0; 1])).await?? != 0 {
                return Err("unexpected trailing benchmark bytes".into());
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(samples)
        });
    }
    let result=timeout(Duration::from_secs(60),async {
        let mut total=Samples::new();
        while let Some(result)=jobs.join_next().await {total.merge(result??)?;}
        if total.count==0 {return Err("no measured latency exchanges".into());}
        println!("{}",serde_json::json!({"role":"ping","measurement_kind":"timed","connections":connections,"message_bytes":size,
            "warmup_seconds":warmup,"measured_seconds":seconds,"measured_elapsed_microseconds":u128::from(seconds)*1_000_000,
            "exchanges":total.count,"verified_bytes":total.bytes,"verified_total_bytes":total.total_bytes,
            "histogram_microseconds":total.histogram,"histogram_schema":latency::schema(),"actor_resources":actor_resources(started)?}));
        Ok::<_,Box<dyn Error+Send+Sync>>(())
    }).await;
    let result = match result {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };
    jobs.abort_all();
    while let Some(result) = jobs.join_next().await {
        match result {
            Err(error) if error.is_cancelled() => {}
            other => {
                other??;
            }
        }
    }
    result
}

async fn run() -> Result {
    if std::env::var("TUNNEL_DETOUR_BENCH_LAB").as_deref() != Ok("1") {
        return Err("benchmark actors require the isolated xtask laboratory".into());
    }
    let mut args: Vec<_> = std::env::args().skip(1).collect();
    if matches!(args.as_slice(),[role] if role == "benchmark-info") {
        println!(
            "{}",
            serde_json::json!({"protocol":2,"prepared_generator":true,"preparation_seconds":60,"bulk_first_client_seconds":60})
        );
        return Ok(());
    }
    if args.first().is_some_and(|role| role == "await-start") {
        args.remove(0);
        if !args.first().is_some_and(|role| {
            ["ping", "churn", "bulk-client", "idle", "saturation"].contains(&role.as_str())
        }) {
            return Err("only traffic generators may wait at the preparation barrier".into());
        }
        println!(
            "{}",
            serde_json::json!({"ready":true,"role":"prepared-generator"})
        );
        application::configured().await?;
    }
    match args.as_slice() {
        [role, remote] if role == "namespace-client" => {
            namespace_lifetime::client(remote.parse()?).await
        }
        [role, listen] if role == "namespace-origin" => {
            namespace_lifetime::origin(listen.parse()?).await
        }
        [role] if role == "application-held" => application::held_client().await,
        [role, pid, parent] if role == "application-kill-worker" => {
            application::kill_worker(pid.parse()?, parent.parse()?)
        }
        [role, device, route] if role == "application-origin" => {
            application::origin(device, route).await
        }
        [role, seconds] if role == "application-client" => {
            application::client(seconds.parse()?, false, 20).await
        }
        [role, seconds, mode] if role == "application-client" && mode == "churn" => {
            application::client(seconds.parse()?, true, 20).await
        }
        [role, seconds, mode, rate]
            if role == "application-client" && ["churn", "reuse"].contains(&mode.as_str()) =>
        {
            application::client(seconds.parse()?, mode == "churn", rate.parse()?).await
        }
        [role, remote, seconds] if role == "dns-load" => {
            dns::client(remote.parse()?, seconds.parse()?).await
        }
        [role, remote, connections, seconds] if role == "idle" || role == "saturation" => {
            operational::client(
                remote.parse()?,
                connections.parse()?,
                seconds.parse()?,
                role == "saturation",
            )
            .await
        }
        [role, listen, target, lan, reply] if role == "relay" => {
            relay(listen.parse()?, target.parse()?, lan.clone(), reply.clone()).await
        }
        [role, listen] if role == "echo" => echo(listen.parse()?).await,
        [role, listen, connections] if role == "bulk-origin" => {
            bulk::origin(listen.parse()?, connections.parse()?).await
        }
        [role, remote, mode, connections, warmup, seconds] if role == "bulk-client" => {
            bulk::client(
                remote.parse()?,
                connections.parse()?,
                bulk::Mode::parse(mode)?,
                warmup.parse()?,
                seconds.parse()?,
            )
            .await
        }
        [role] if role == "observe" => observe().await,
        [role, remote, connections, size, warmup, measured] if role == "churn" => {
            churn::client(
                remote.parse()?,
                connections.parse()?,
                size.parse()?,
                warmup.parse()?,
                measured.parse()?,
            )
            .await
        }
        [role, remote, connections, size, warmup, seconds] if role == "ping" => {
            ping(
                remote.parse()?,
                connections.parse()?,
                size.parse()?,
                warmup.parse()?,
                seconds.parse()?,
            )
            .await
        }
        _ => Err("expected relay, echo or ping worker arguments".into()),
    }
}

fn main() -> ExitCode {
    if let Some(result) = tunnel_detour_service::transport_worker_entrypoint() {
        return result;
    }
    if let Err(error) = application::enter_namespace() {
        eprintln!("endpoint namespace entry failed: {error}");
        return ExitCode::FAILURE;
    }
    if std::env::args().nth(1).as_deref() == Some("namespace-exec") {
        use std::os::unix::process::CommandExt;
        let arguments: Vec<_> = std::env::args_os().skip(2).collect();
        let Some(command) = arguments.first() else {
            return ExitCode::FAILURE;
        };
        let error = std::process::Command::new(command)
            .args(&arguments[1..])
            .exec();
        eprintln!("endpoint command failed: {error}");
        return ExitCode::FAILURE;
    }
    let workers = match std::env::args().nth(1).as_deref() {
        Some("relay") => 2,
        Some("observe") => 1,
        _ => 4,
    };
    let result = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .map_err(|error| -> Box<dyn Error + Send + Sync> { error.into() });
    match result.and_then(|runtime| runtime.block_on(run())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
