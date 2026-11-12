//! Bounded idle/resume and over-capacity probes; intentional rejection is reported.

use super::{Result, actor_resources};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, timeout},
};

async fn exchange(stream: &mut TcpStream, id: u8) -> Result {
    let sent = [id; 256];
    let mut received = [0; 256];
    timeout(Duration::from_secs(3), async {
        stream.write_all(&sent).await?;
        stream.read_exact(&mut received).await?;
        Ok::<_, std::io::Error>(())
    })
    .await??;
    if sent != received {
        return Err("operational probe integrity failed".into());
    }
    Ok(())
}

pub(super) async fn client(
    remote: SocketAddr,
    connections: usize,
    seconds: u64,
    saturation: bool,
) -> Result {
    if ![1, 16, 32].contains(&connections)
        || !(1..=20).contains(&seconds)
        || (saturation && connections != 32)
    {
        return Err("unsupported bounded operational probe".into());
    }
    let started = Instant::now();
    let mut streams = Vec::with_capacity(connections);
    for id in 0..connections {
        let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(remote)).await??;
        exchange(&mut stream, u8::try_from(id)?).await?;
        streams.push(stream);
    }
    let idle_start = started.elapsed().as_micros();
    tokio::time::sleep(Duration::from_secs(seconds)).await;
    let idle_end = started.elapsed().as_micros();
    let mut excess = serde_json::Value::Null;
    let mut pending = None;
    if saturation {
        let probe = Instant::now();
        // TCP handshake completion alone does not mean a backend was admitted.
        let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(remote)).await??;
        excess = match timeout(Duration::from_secs(2), async {
            stream.write_all(&[255; 256]).await?;
            stream.read(&mut [0; 1]).await
        })
        .await
        {
            Ok(Ok(0)) => {
                serde_json::json!({"result":"rejected_eof","elapsed_microseconds":probe.elapsed().as_micros()})
            }
            Ok(Ok(_)) => return Err("more than 32 active relayed sessions were admitted".into()),
            Ok(Err(error)) => {
                serde_json::json!({"result":"rejected","cause":error.to_string(),"elapsed_microseconds":probe.elapsed().as_micros()})
            }
            Err(_) => {
                pending = Some(stream);
                serde_json::json!({"result":"queued_without_backend_response","timeout_seconds":2,"elapsed_microseconds":probe.elapsed().as_micros()})
            }
        };
    }
    let resume = Instant::now();
    for (id, stream) in streams.iter_mut().enumerate() {
        exchange(stream, u8::try_from(id)?).await?;
    }
    let resume_time = resume.elapsed().as_micros();
    for mut stream in streams {
        stream.shutdown().await?;
        if timeout(Duration::from_secs(5), stream.read(&mut [0; 1])).await?? != 0 {
            return Err("unexpected operational trailing bytes".into());
        }
    }
    let queued_bytes = if let Some(mut stream) = pending {
        let mut response = [0; 256];
        timeout(Duration::from_secs(5), stream.read_exact(&mut response)).await??;
        if response != [255; 256] {
            return Err("queued excess stream lost data during recovery".into());
        }
        stream.shutdown().await?;
        if timeout(Duration::from_secs(5), stream.read(&mut [0; 1])).await?? != 0 {
            return Err("unexpected queued recovery bytes".into());
        }
        512
    } else {
        0
    };
    // Capacity must recover, even if the excess attempt was waiting in the backlog.
    let recovery = Instant::now();
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(remote)).await??;
    exchange(&mut stream, 254).await?;
    stream.shutdown().await?;
    if timeout(Duration::from_secs(5), stream.read(&mut [0; 1])).await?? != 0 {
        return Err("unexpected recovery bytes".into());
    }
    println!(
        "{}",
        serde_json::json!({"role":"operational-client","connections":connections,"idle_seconds":seconds,
        "idle_start_microseconds":idle_start,"idle_end_microseconds":idle_end,"resume_all_microseconds":resume_time,
        "excess":excess,"capacity_recovered":true,"recovery_microseconds":recovery.elapsed().as_micros(),
        "verified_total_bytes":(u64::try_from(connections)?*2+1)*512+queued_bytes,"actor_resources":actor_resources(started)?})
    );
    Ok(())
}
