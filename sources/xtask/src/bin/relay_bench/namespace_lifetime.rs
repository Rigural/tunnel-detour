//! Controlled queued-close actors; no relay or production service is involved.

use super::Result;
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpSocket,
    time::timeout,
};

const BYTES: usize = 256 * 1024;

pub(super) async fn client(remote: SocketAddr) -> Result {
    let socket = TcpSocket::new_v4()?;
    socket.set_send_buffer_size(512 * 1024)?;
    let mut stream = timeout(Duration::from_secs(5), socket.connect(remote)).await??;
    let send_buffer = socket2::SockRef::from(&stream).send_buffer_size()?;
    if send_buffer < BYTES {
        return Err("queued-close fixture needs a send buffer larger than its payload".into());
    }
    let mut accepted = [0_u8; 1];
    timeout(Duration::from_secs(5), stream.read_exact(&mut accepted)).await??;
    if accepted != *b"R" {
        return Err("queued-close fixture peer did not confirm acceptance".into());
    }
    let bytes = (0..BYTES)
        .map(|index| u8::try_from(index % 251))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    timeout(Duration::from_secs(5), stream.write_all(&bytes)).await??;
    stream.shutdown().await?;
    println!(
        "{}",
        serde_json::json!({"role":"namespace-client","queued_bytes":BYTES,"send_buffer_bytes":send_buffer})
    );
    // Deliberately exit without peer confirmation. The owning counterfactual
    // tests whether a separate actor must retain the network endpoint.
    Ok(())
}

pub(super) async fn origin(listen: SocketAddr) -> Result {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let socket = TcpSocket::new_v4()?;
    socket.set_recv_buffer_size(4096)?;
    socket.bind(listen)?;
    let listener = socket.listen(1)?;
    println!(
        "{}",
        serde_json::json!({"role":"namespace-origin","ready":true})
    );
    let (mut stream, _) = timeout(Duration::from_secs(30), listener.accept()).await??;
    let receive_buffer = socket2::SockRef::from(&stream).recv_buffer_size()?;
    if receive_buffer >= BYTES {
        return Err(
            "queued-close fixture must prevent the peer from acknowledging all data".into(),
        );
    }
    stream.write_all(b"R").await?;
    // The driver releases reads only after the client process has exited and
    // its owned endpoint has either disappeared or remains held independently.
    super::application::configured().await?;
    let mut received = 0_usize;
    let mut eof = false;
    let result = timeout(Duration::from_secs(5), async {
        let mut buffer = [0_u8; 4096];
        loop {
            let length = stream.read(&mut buffer).await?;
            if length == 0 {
                eof = true;
                break;
            }
            for (offset, byte) in buffer[..length].iter().enumerate() {
                let position = received
                    .checked_add(offset)
                    .ok_or("fixture offset overflow")?;
                if position >= BYTES || *byte != u8::try_from(position % 251)? {
                    return Err("queued-close fixture payload changed".into());
                }
            }
            received = received
                .checked_add(length)
                .ok_or("fixture byte count overflow")?;
        }
        if received != BYTES {
            return Err("queued-close fixture payload is incomplete".into());
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await;
    let complete = matches!(&result, Ok(Ok(())));
    println!(
        "{}",
        serde_json::json!({"role":"namespace-origin","expected_bytes":BYTES,"received_bytes":received,"eof":eof,"complete":complete,"receive_buffer_bytes":receive_buffer})
    );
    result??;
    timeout(Duration::from_secs(15), term.recv())
        .await?
        .ok_or("fixture termination stream ended")?;
    Ok(())
}
