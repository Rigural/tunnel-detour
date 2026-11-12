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

#[tokio::test]
async fn r083_tcp_queue_caps_are_shared_across_capacity_and_inherited_by_unaccepted_ingress()
-> Result<(), Box<dyn Error>> {
    for (capacity, accounted_per_buffer) in [(1, 1_048_576_usize), (32, 524_288), (256, 65_536)] {
        let limits = RelayLimits::new(capacity, Duration::from_secs(2), Duration::from_secs(5))?;
        let ingress = tokio::net::TcpSocket::new_v6()?;
        limits.configure_socket(&ingress)?;
        ingress.bind((Ipv6Addr::LOCALHOST, 0).into())?;
        let listener = ingress.listen(32)?;
        let client = TcpStream::connect(listener.local_addr()?).await?;
        let (incoming, _) = listener.accept().await?;
        let reduced = RelayLimits::new(256, Duration::from_secs(2), Duration::from_secs(5))?;
        reduced.configure_socket(&listener)?;
        let later_client = TcpStream::connect(listener.local_addr()?).await?;
        let (later, _) = listener.accept().await?;
        assert!(
            socket2::SockRef::from(&later).recv_buffer_size()? <= 65_536,
            "new handshakes must inherit a reduced listener queue cap"
        );
        assert!(socket2::SockRef::from(&later).send_buffer_size()? <= 65_536);
        drop((later_client, later));
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let outgoing = tokio::net::TcpSocket::new_v4()?;
        limits.configure_socket(&outgoing)?;
        let outgoing = outgoing.connect(origin.local_addr()?).await?;
        let (_server, _) = origin.accept().await?;
        for socket in [
            socket2::SockRef::from(&listener),
            socket2::SockRef::from(&incoming),
            socket2::SockRef::from(&outgoing),
        ] {
            assert!(
                socket.recv_buffer_size()? <= accounted_per_buffer,
                "the receive queue exceeded its independently specified kernel share"
            );
            assert!(
                socket.send_buffer_size()? <= accounted_per_buffer,
                "the send queue exceeded its independently specified kernel share"
            );
        }
        assert!(
            accounted_per_buffer
                .checked_mul(4)
                .and_then(|bytes| bytes.checked_mul(capacity))
                .is_some_and(|bytes| bytes <= 64 * 1024 * 1024),
            "two sockets per admitted session must share at most 64 MiB of configured queue limits"
        );
        drop((incoming, outgoing, client));
    }
    Ok(())
}

#[path = "../../tests/transport/acknowledgements.rs"]
mod acknowledgements;

#[tokio::test]
async fn r080_half_closed_slow_receivers_keep_capacity_until_acknowledged_and_retirement_discards_pending_output()
-> Result<(), Box<dyn Error>> {
    acknowledgements::run(false).await
}

#[tokio::test]
async fn r074_stopped_readers_apply_backpressure_in_each_direction_and_resuming_preserves_all_bytes()
-> Result<(), Box<dyn Error>> {
    timeout(Duration::from_secs(30), async {
        for slow_origin in [true, false] {
            let ingress = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await?;
            let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let mut client = TcpStream::connect(ingress.local_addr()?).await?;
            let (incoming, _) = ingress.accept().await?;
            let SocketAddr::V4(target) = origin.local_addr()? else {
                return Err("IPv4 fixture required".into());
            };
            let mut relay = RelaySessions::new(RelayLimits::new(
                1,
                Duration::from_secs(2),
                Duration::from_secs(10),
            )?);
            relay.admit(
                incoming,
                RelayAdmission {
                    publication: "slow".parse()?,
                    generation: 1,
                    target,
                    lan_device: "lo".into(),
                    reply_device: "lo".into(),
                },
            )?;
            let (mut server, _) = origin.accept().await?;
            let (writer, reader) = if slow_origin {
                (&mut client, &mut server)
            } else {
                (&mut server, &mut client)
            };
            socket2::SockRef::from(&*writer).set_send_buffer_size(65_536)?;
            socket2::SockRef::from(&*reader).set_recv_buffer_size(65_536)?;
            let payload: Vec<_> = (0_u8..=250).cycle().take(16 * 1024 * 1024).collect();
            let write = async {
                writer.write_all(&payload).await?;
                writer.shutdown().await?;
                Ok::<(), std::io::Error>(())
            };
            tokio::pin!(write);
            // The receiving application deliberately does no reads during this interval.
            // Finite socket and transfer buffers must make the sender await capacity.
            assert!(
                timeout(Duration::from_millis(150), &mut write)
                    .await
                    .is_err(),
                "the stopped reader did not exert backpressure"
            );
            let read = async {
                let mut offset = 0;
                let mut buffer = [0; 16_384];
                loop {
                    let length = reader.read(&mut buffer).await?;
                    if length == 0 {
                        break;
                    }
                    assert_eq!(
                        &buffer[..length],
                        &payload[offset..offset + length],
                        "resuming a slow reader changed the byte stream"
                    );
                    offset += length;
                }
                assert_eq!(offset, payload.len(), "a slow reader lost pending data");
                reader.shutdown().await?;
                Ok::<(), std::io::Error>(())
            };
            tokio::try_join!(write, read)?;
            let completion = relay.next_completion().await?;
            assert_eq!(completion.outcome, RelayOutcome::Complete);
            assert_eq!(
                completion.bytes,
                Some(if slow_origin {
                    (16 * 1024 * 1024, 0)
                } else {
                    (0, 16 * 1024 * 1024)
                })
            );
            assert!(relay.connections().is_empty());
            relay.shutdown().await?;
        }
        Ok::<(), Box<dyn Error>>(())
    })
    .await??;
    Ok(())
}
