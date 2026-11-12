//! Shared R080 scenario: the same bytes and lifecycle checks at both transport boundaries.

use std::{
    error::Error,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tunnel_detour_service::{RelayAdmission, RelayLimits, RelayOutcome, RelaySessions};

pub async fn run(isolated: bool) -> Result<(), Box<dyn Error>> {
    timeout(Duration::from_secs(15), async {
        for cancel in [false, true] {
            let ingress = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await?;
            let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let socket = tokio::net::TcpSocket::new_v6()?;
            // Negotiate a small receive window before the handshake. The response
            // fits the relay's send queue but cannot be acknowledged by this reader.
            socket.set_recv_buffer_size(1024)?;
            let mut client = socket.connect(ingress.local_addr()?).await?;
            let (incoming, _) = ingress.accept().await?;
            let SocketAddr::V4(target) = origin.local_addr()? else {
                return Err("IPv4 fixture required".into());
            };
            let admission = RelayAdmission {
                publication: "closing".parse()?,
                generation: 1,
                target,
                lan_device: "lo".into(),
                reply_device: "lo".into(),
            };
            let relay = RelaySessions::new(RelayLimits::new(
                1,
                Duration::from_secs(2),
                Duration::from_secs(5),
            )?);
            let mut relay = if isolated {
                relay.with_isolated_transport()?
            } else {
                relay
            };
            relay.admit(incoming, admission.clone())?;
            let (mut server, _) = origin.accept().await?;
            client.shutdown().await?;
            assert_eq!(
                server.read(&mut [0; 1]).await.map_err(|error| {
                    format!("client half-close did not reach backend (isolated={isolated}): {error}")
                })?,
                0
            );
            let payload: Vec<_> = (0_u8..=250).cycle().take(256 * 1024).collect();
            server.write_all(&payload).await.map_err(|error| {
                format!("backend could not queue response (isolated={isolated}): {error}")
            })?;
            server.shutdown().await.map_err(|error| {
                format!("backend half-close failed (isolated={isolated}): {error}")
            })?;
            assert!(
                timeout(Duration::from_millis(150), relay.next_completion())
                    .await
                    .is_err(),
                "queued but unacknowledged output released the session capacity"
            );
            assert_eq!(relay.connections().len(), 1);
            let _extra_client = TcpStream::connect(ingress.local_addr()?).await?;
            let (extra, _) = ingress.accept().await?;
            assert!(matches!(
                relay.admit(extra, admission),
                Err(tunnel_detour_service::RelayError::Capacity)
            ));
            if cancel {
                relay.retain(&std::collections::BTreeMap::new()).await?;
                assert!(relay.connections().is_empty());
                let mut received = Vec::new();
                let read = client.read_to_end(&mut received).await;
                assert!(read.is_err(), "forced retirement must abort queued output");
                assert!(
                    received.len() < payload.len(),
                    "retirement delivered the retired queue"
                );
            } else {
                let mut received = Vec::new();
                client.read_to_end(&mut received).await.map_err(|error| {
                    format!(
                        "normal close lost queued output (isolated={isolated}, received={}): {error}",
                        received.len()
                    )
                })?;
                assert_eq!(received, payload, "normal close lost queued output");
                let completion = relay.next_completion().await?;
                assert_eq!(completion.outcome, RelayOutcome::Complete);
                assert_eq!(completion.bytes, Some((0, 256 * 1024)));
                assert!(relay.connections().is_empty());
            }
            relay.shutdown().await?;
        }
        Ok::<(), Box<dyn Error>>(())
    })
    .await??;
    Ok(())
}
