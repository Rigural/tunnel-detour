//! Fixed verified cycle volumes avoid silently exhausting TCP TIME_WAIT ports.

use super::{Result, Samples, actor_resources, verify_echo};
use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    task::JoinSet,
    time::{Instant, timeout},
};

pub(super) fn port_budget(total: u64) -> Result<serde_json::Value> {
    let range = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")?;
    let ports = range
        .split_whitespace()
        .map(str::parse::<u16>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let [first, last] = ports.as_slice() else {
        return Err("incompatible ephemeral port range".into());
    };
    let available = u64::from(*last)
        .checked_sub(u64::from(*first))
        .and_then(|value| value.checked_add(1))
        .ok_or("invalid ephemeral range")?;
    if available < total.checked_mul(2).ok_or("cycle volume overflow")? {
        return Err("the fixed churn volume requires more ephemeral port headroom; kernel settings remain unchanged".into());
    }
    Ok(
        serde_json::json!({"first":first,"last":last,"available":available,"tcp_tw_reuse":std::fs::read_to_string("/proc/sys/net/ipv4/tcp_tw_reuse")?.trim()}),
    )
}

pub(super) async fn client(
    remote: SocketAddr,
    connections: usize,
    size: usize,
    warmup: u64,
    measured: u64,
) -> Result {
    let started = Instant::now();
    let workers = u64::try_from(connections)?;
    if ![1, 4, 16, 32].contains(&connections)
        || size != 256
        || warmup > 1024
        || !(1..=8192).contains(&measured)
        || !warmup.is_multiple_of(workers)
        || !measured.is_multiple_of(workers)
    {
        return Err("unsupported bounded churn volume".into());
    }
    let total = warmup
        .checked_add(measured)
        .ok_or("cycle volume overflow")?;
    let ports = port_budget(total)?;
    let barrier = Arc::new(tokio::sync::Barrier::new(connections));
    let epoch = Arc::new(OnceLock::new());
    let mut jobs = JoinSet::new();
    for client in 0..connections {
        let barrier = barrier.clone();
        let epoch = epoch.clone();
        jobs.spawn(async move {
            let mut packet = vec![u8::try_from(client)?; size];
            let mut received = vec![0; size];
            let mut samples = Samples::new();
            for sequence in 0..total / workers {
                if sequence == warmup / workers {
                    barrier.wait().await;
                    epoch.get_or_init(Instant::now);
                }
                packet[..8].copy_from_slice(&sequence.to_be_bytes());
                let cycle = Instant::now();
                let mut stream =
                    timeout(Duration::from_secs(5), TcpStream::connect(remote)).await??;
                stream.set_nodelay(false)?;
                verify_echo(&mut stream, &packet, &mut received).await?;
                stream.shutdown().await?;
                if timeout(Duration::from_secs(5), stream.read(&mut [0; 1])).await?? != 0 {
                    return Err("unexpected trailing churn bytes".into());
                }
                samples.record(
                    size,
                    (sequence >= warmup / workers).then(|| cycle.elapsed()),
                )?;
            }
            let measured_started = epoch.get().ok_or("churn measurement did not start")?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                samples,
                measured_started.elapsed().as_micros(),
            ))
        });
    }
    let result=timeout(Duration::from_secs(60),async {
        let mut result=Samples::new();
        let mut elapsed=0_u128;
        while let Some(completed)=jobs.join_next().await {
            let (samples,duration)=completed??;
            result.merge(samples)?;
            elapsed=elapsed.max(duration);
        }
        if result.count!=measured || result.total_bytes!=total.checked_mul(u64::try_from(size)?).and_then(|value|value.checked_mul(2)).ok_or("cycle byte count overflow")? || elapsed==0 {
            return Err("churn did not complete its declared verified volume".into());
        }
        println!("{}",serde_json::json!({"role":"churn","measurement_kind":"fixed_volume","connections":connections,"message_bytes":size,
            "warmup_cycles":warmup,"measured_cycles":measured,"measured_elapsed_microseconds":elapsed,
            "exchanges":result.count,"verified_bytes":result.bytes,"verified_total_bytes":result.total_bytes,
            "histogram_microseconds":result.histogram,"histogram_schema":xtask::latency::schema(),
            "ephemeral_ports":ports,"actor_resources":actor_resources(started)?}));
        Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
    }).await;
    let result = match result {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };
    jobs.abort_all();
    while let Some(completed) = jobs.join_next().await {
        match completed {
            Err(error) if error.is_cancelled() => {}
            other => {
                other??;
            }
        }
    }
    result
}
