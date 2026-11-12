//! Verified upload/download/duplex loads. The relay does not interpret this fixture protocol.

use super::Result;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::{Instant, timeout},
};

const BLOCK: usize = 16_384;

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Mode {
    Upload,
    Download,
    Duplex,
    SlowUpload,
    SlowDownload,
}
impl Mode {
    pub(super) fn parse(value: &str) -> Result<Self> {
        match value {
            "upload" => Ok(Self::Upload),
            "download" => Ok(Self::Download),
            "duplex" => Ok(Self::Duplex),
            "slow-upload" => Ok(Self::SlowUpload),
            "slow-download" => Ok(Self::SlowDownload),
            _ => Err("unknown bulk direction".into()),
        }
    }
    fn byte(self) -> u8 {
        match self {
            Self::Upload => 1,
            Self::Download => 2,
            Self::Duplex => 3,
            Self::SlowUpload => 4,
            Self::SlowDownload => 5,
        }
    }
}

#[derive(Default)]
struct Count {
    total: u64,
    measured: u64,
}
impl Count {
    fn add(&mut self, bytes: usize, measured: bool) -> Result {
        let bytes = u64::try_from(bytes)?;
        self.total = self
            .total
            .checked_add(bytes)
            .ok_or("bulk byte counter overflow")?;
        if measured {
            self.measured = self
                .measured
                .checked_add(bytes)
                .ok_or("bulk byte counter overflow")?;
        }
        Ok(())
    }
}

fn pattern(seed: u8) -> Vec<u8> {
    (0_u8..=250)
        .cycle()
        .take(BLOCK)
        .map(|byte| byte ^ seed)
        .collect()
}

async fn write(
    mut stream: impl AsyncWrite + Unpin,
    seed: u8,
    warm: Instant,
    end: Instant,
) -> Result<Count> {
    let mut bytes = pattern(seed);
    let mut sequence = 0_u64;
    let mut count = Count::default();
    while Instant::now() < end {
        bytes[..8].copy_from_slice(&sequence.to_be_bytes());
        timeout(Duration::from_secs(3), stream.write_all(&bytes)).await??;
        count.add(bytes.len(), Instant::now() >= warm)?;
        sequence = sequence.checked_add(1).ok_or("bulk sequence exhausted")?;
    }
    stream.shutdown().await?;
    Ok(count)
}

async fn read(
    mut stream: impl AsyncRead + Unpin,
    seed: u8,
    warm: Instant,
    end: Instant,
    slow: bool,
) -> Result<Count> {
    let mut expected = pattern(seed);
    let mut sequence = 0_u64;
    let mut bytes = [0; BLOCK];
    let mut offset = 0;
    let mut count = Count::default();
    loop {
        let length = timeout(Duration::from_secs(5), stream.read(&mut bytes)).await??;
        if length == 0 {
            break;
        }
        let mut position = 0;
        while position < length {
            if offset == 0 {
                expected[..8].copy_from_slice(&sequence.to_be_bytes());
            }
            let part = (length - position).min(BLOCK - offset);
            if bytes[position..position + part] != expected[offset..offset + part] {
                return Err("bulk stream integrity failed".into());
            }
            offset = (offset + part) % BLOCK;
            position += part;
            if offset == 0 {
                sequence = sequence.checked_add(1).ok_or("bulk sequence exhausted")?;
            }
        }
        let now = Instant::now();
        count.add(length, now >= warm && now <= end)?;
        if slow {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    if offset != 0 {
        return Err("bulk stream ended within a block".into());
    }
    Ok(count)
}

fn report(id: u8, sent: Count, received: Count) -> serde_json::Value {
    serde_json::json!({"id":id,"sent_total":sent.total,"received_total":received.total,"sent_measured":sent.measured,"received_measured":received.measured})
}

async fn serve(mut stream: TcpStream) -> Result<serde_json::Value> {
    stream.set_nodelay(false)?;
    let mut header = [0; 16];
    timeout(Duration::from_secs(5), stream.read_exact(&mut header)).await??;
    if &header[..8] != b"TDRELAY1"
        || header[9] >= 32
        || header[10] > 10
        || !(1..=30).contains(&header[11])
        || header[12..] != [0; 4]
    {
        return Err("invalid bounded bulk fixture header".into());
    }
    let mode = match header[8] {
        1 => Mode::Upload,
        2 => Mode::Download,
        3 => Mode::Duplex,
        4 => Mode::SlowUpload,
        5 => Mode::SlowDownload,
        _ => return Err("invalid bulk mode".into()),
    };
    let id = header[9];
    stream.write_all(b"READY_OK").await?;
    let mut start = [0; 1];
    timeout(Duration::from_secs(5), stream.read_exact(&mut start)).await??;
    if start != [1] {
        return Err("invalid bulk start signal".into());
    }
    let warm = Instant::now() + Duration::from_secs(u64::from(header[10]));
    let end = warm + Duration::from_secs(u64::from(header[11]));
    let (sent, received) = match mode {
        Mode::Upload | Mode::SlowUpload => {
            let received = read(&mut stream, id, warm, end, mode == Mode::SlowUpload).await?;
            stream.write_all(&received.total.to_be_bytes()).await?;
            stream.shutdown().await?;
            (Count::default(), received)
        }
        Mode::Download | Mode::SlowDownload => {
            (write(stream, id ^ 128, warm, end).await?, Count::default())
        }
        Mode::Duplex => {
            let (reader, writer) = stream.into_split();
            tokio::try_join!(
                write(writer, id ^ 128, warm, end),
                read(reader, id, warm, end, false)
            )?
        }
    };
    Ok(report(id, sent, received))
}

pub(super) async fn origin(listen: SocketAddr, connections: usize) -> Result {
    let started = Instant::now();
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    if ![1, 4, 16, 32].contains(&connections) {
        return Err("invalid bulk connection count".into());
    }
    let listener = TcpListener::bind(listen).await?;
    let mut jobs = JoinSet::new();
    println!("{}", serde_json::json!({"ready":true,"role":"bulk-origin"}));
    // Docker preparation happens before the client exists. Keep its deadline
    // separate from connected protocol/data deadlines and measured windows.
    let (first, _) = timeout(Duration::from_secs(60), listener.accept()).await??;
    jobs.spawn(serve(first));
    let result = timeout(Duration::from_secs(60), async {
        for _ in 1..connections {
            let (stream, _) = timeout(Duration::from_secs(5), listener.accept()).await??;
            jobs.spawn(serve(stream));
        }
        let mut results = Vec::new();
        while let Some(result) = jobs.join_next().await {
            results.push(result??);
        }
        println!(
            "{}",
            serde_json::json!({"role":"bulk-origin","connections":results,"actor_resources":super::actor_resources(started)?})
        );
        // A process exit destroys this container's network namespace and can discard
        // data/FIN still queued by normal socket close. The driver stops this actor
        // only after the remote reader has verified the entire stream.
        timeout(Duration::from_secs(30),term.recv()).await?.ok_or("origin termination stream ended")?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await;
    jobs.abort_all();
    while let Some(result) = jobs.join_next().await {
        match result {
            Err(error) if error.is_cancelled() => {}
            other => {
                other??;
            }
        }
    }
    result?
}

async fn connection(
    remote: SocketAddr,
    id: u8,
    mode: Mode,
    warmup: u8,
    seconds: u8,
    barrier: Arc<tokio::sync::Barrier>,
) -> Result<serde_json::Value> {
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(remote)).await??;
    stream.set_nodelay(false)?;
    let mut header = [0; 16];
    header[..8].copy_from_slice(b"TDRELAY1");
    header[8] = mode.byte();
    header[9] = id;
    header[10] = warmup;
    header[11] = seconds;
    stream.write_all(&header).await?;
    let mut ready = [0; 8];
    timeout(Duration::from_secs(5), stream.read_exact(&mut ready)).await??;
    if &ready != b"READY_OK" {
        return Err("bulk origin handshake failed".into());
    }
    barrier.wait().await;
    stream.write_all(&[1]).await?;
    let warm = Instant::now() + Duration::from_secs(u64::from(warmup));
    let end = warm + Duration::from_secs(u64::from(seconds));
    let (sent, received) = match mode {
        Mode::Upload | Mode::SlowUpload => {
            let sent = write(&mut stream, id, warm, end).await?;
            let mut ack = [0; 8];
            timeout(Duration::from_secs(5), stream.read_exact(&mut ack)).await??;
            if u64::from_be_bytes(ack) != sent.total {
                return Err("bulk upload was truncated or duplicated".into());
            }
            if timeout(Duration::from_secs(5), stream.read(&mut [0; 1])).await?? != 0 {
                return Err("unexpected trailing upload acknowledgement".into());
            }
            (sent, Count::default())
        }
        Mode::Download | Mode::SlowDownload => {
            stream.shutdown().await?;
            (
                Count::default(),
                read(stream, id ^ 128, warm, end, mode == Mode::SlowDownload).await?,
            )
        }
        Mode::Duplex => {
            let (reader, writer) = stream.into_split();
            tokio::try_join!(
                write(writer, id, warm, end),
                read(reader, id ^ 128, warm, end, false)
            )?
        }
    };
    Ok(report(id, sent, received))
}

pub(super) async fn client(
    remote: SocketAddr,
    connections: usize,
    mode: Mode,
    warmup: u8,
    seconds: u8,
) -> Result {
    let started = Instant::now();
    if ![1, 4, 16, 32].contains(&connections) || warmup > 10 || !(1..=30).contains(&seconds) {
        return Err("invalid bounded bulk workload".into());
    }
    let barrier = Arc::new(tokio::sync::Barrier::new(connections));
    let mut jobs = JoinSet::new();
    for id in 0..connections {
        jobs.spawn(connection(
            remote,
            u8::try_from(id)?,
            mode,
            warmup,
            seconds,
            barrier.clone(),
        ));
    }
    let result = timeout(Duration::from_secs(60), async {
        let mut results = Vec::new();
        while let Some(result) = jobs.join_next().await { results.push(result??); }
        println!("{}", serde_json::json!({"role":"bulk-client","mode":mode.byte(),"warmup_seconds":warmup,"measured_seconds":seconds,"connections":results,"actor_resources":super::actor_resources(started)?}));
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }).await;
    jobs.abort_all();
    while let Some(result) = jobs.join_next().await {
        match result {
            Err(error) if error.is_cancelled() => {}
            other => {
                other??;
            }
        }
    }
    result?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn r085_bulk_verification_accepts_fragmented_data_and_rejects_duplicate_reordered_or_partial_blocks()
    -> Result {
        let block = |sequence: u64| {
            let mut bytes: Vec<u8> = (0_u8..=250).cycle().take(16_384).collect();
            bytes[..8].copy_from_slice(&sequence.to_be_bytes());
            bytes
        };
        let good = [block(0), block(1)].concat();
        for (bytes, accepted) in [
            (good.clone(), true),
            ([block(1), block(0)].concat(), false),
            ([block(0), block(0)].concat(), false),
            (good[..good.len() - 1].to_vec(), false),
        ] {
            let (mut sender, reader) = tokio::io::duplex(4096);
            let write = async {
                for fragment in bytes.chunks(997) {
                    sender.write_all(fragment).await?;
                }
                sender.shutdown().await
            };
            let now = Instant::now();
            let check = async {
                let result = read(reader, 0, now, now + Duration::from_secs(5), false).await;
                assert_eq!(
                    result.is_ok(),
                    accepted,
                    "unexpected sequence verification outcome"
                );
                match result {
                    Ok(count) => assert_eq!(count.total, 32_768),
                    Err(error) => assert!(
                        error
                            .to_string()
                            .starts_with("bulk stream integrity failed")
                            || error
                                .to_string()
                                .starts_with("bulk stream ended within a block"),
                        "unexpected integrity failure: {error}"
                    ),
                }
            };
            let (written, ()) = tokio::join!(write, check);
            match written {
                Ok(()) => {}
                Err(error) if !accepted => assert_eq!(
                    error.kind(),
                    std::io::ErrorKind::BrokenPipe,
                    "only the rejected reader may close the fixture stream"
                ),
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}
