use std::{
    collections::BTreeMap,
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

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

async fn ingress() -> TestResult<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await?;
    let client = TcpStream::connect(listener.local_addr()?).await?;
    let (incoming, _) = listener.accept().await?;
    Ok((client, incoming))
}

fn admission(target: SocketAddr, publication: &str, generation: u16) -> TestResult<RelayAdmission> {
    let SocketAddr::V4(target) = target else {
        return Err("test origin must be IPv4".into());
    };
    // This is a transport-only loopback fixture. The production policy adapter must
    // reject loopback/router destinations before constructing an admission.
    Ok(RelayAdmission {
        publication: publication.parse()?,
        generation,
        target,
        lan_device: "lo".into(),
        reply_device: "lo".into(),
    })
}

fn sessions(capacity: usize, idle: Duration) -> TestResult<RelaySessions> {
    Ok(RelaySessions::new(RelayLimits::new(
        capacity,
        Duration::from_secs(2),
        idle,
    )?))
}

async fn echo(client: &mut TcpStream, server: &mut TcpStream, bytes: &[u8]) -> TestResult {
    client.write_all(bytes).await?;
    let mut received = vec![0; bytes.len()];
    server.read_exact(&mut received).await?;
    assert_eq!(
        received, bytes,
        "the IPv4 endpoint received altered or cross-delivered bytes"
    );
    server.write_all(&received).await?;
    client.read_exact(&mut received).await?;
    assert_eq!(
        received, bytes,
        "the IPv6 client received altered or cross-delivered bytes"
    );
    Ok(())
}

async fn closed(stream: &mut TcpStream) -> TestResult {
    match stream.read(&mut [0; 1]).await {
        Ok(0) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            ) =>
        {
            Ok(())
        }
        other => Err(format!("the retired endpoint did not close: {other:?}").into()),
    }
}

#[tokio::test]
async fn r069_relay_sessions_keep_ipv6_clients_separate_and_forward_exact_bytes_to_fixed_ipv4_targets()
-> TestResult {
    timeout(Duration::from_secs(10), async {
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let target = origin.local_addr()?;
        let mut relay = sessions(2, Duration::from_secs(5))?;
        let (mut client_a, incoming_a) = ingress().await?;
        let (mut client_b, incoming_b) = ingress().await?;
        let first = relay.admit(incoming_a, admission(target, "first", 1)?)?;
        let second = relay.admit(incoming_b, admission(target, "second", 2)?)?;
        let (mut server_a, source_a) = origin.accept().await?;
        let (mut server_b, source_b) = origin.accept().await?;
        assert!(source_a.is_ipv4() && source_b.is_ipv4());
        assert_eq!(
            source_a.ip(),
            source_b.ip(),
            "the target sees the relay's address"
        );
        assert_ne!(
            source_a.port(),
            source_b.port(),
            "sessions need distinct TCP tuples"
        );
        let snapshot = relay.connections();
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[0].id, first);
        assert_eq!(snapshot[1].id, second);
        assert_eq!(SocketAddr::V6(snapshot[0].client), client_a.local_addr()?);
        assert_eq!(SocketAddr::V6(snapshot[1].client), client_b.local_addr()?);
        // The listener can accept the two connects in either order. A deterministic
        // message identifies each stream without relying on scheduling order.
        client_a.write_all(b"A").await?;
        client_b.write_all(b"B").await?;
        let mut identity_a = [0; 1];
        let mut identity_b = [0; 1];
        server_a.read_exact(&mut identity_a).await?;
        server_b.read_exact(&mut identity_b).await?;
        assert_ne!(identity_a, identity_b);
        if identity_a == *b"B" {
            std::mem::swap(&mut server_a, &mut server_b);
        }
        let request_a: Vec<_> = (0_u8..=250).cycle().take(131_072).collect();
        let request_b: Vec<_> = (0_u8..=250).rev().cycle().take(131_072).collect();
        tokio::try_join!(
            echo(&mut client_a, &mut server_a, &request_a),
            echo(&mut client_b, &mut server_b, &request_b)
        )?;
        client_a.shutdown().await?;
        client_b.shutdown().await?;
        server_a.shutdown().await?;
        server_b.shutdown().await?;
        for _ in 0..2 {
            let completion = relay.next_completion().await?;
            assert_eq!(completion.outcome, RelayOutcome::Complete);
            assert_eq!(completion.bytes, Some((131_073, 131_072)));
        }
        assert!(relay.connections().is_empty());
        relay.shutdown().await?;
        Ok::<(), Box<dyn Error>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn r070_relay_retirement_closes_changed_generations_and_shutdown_joins_work_without_cutting_retained_sessions()
-> TestResult {
    timeout(Duration::from_secs(10), async {
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut relay = sessions(2, Duration::from_secs(5))?;
        let (mut changed, incoming) = ingress().await?;
        relay.admit(incoming, admission(origin.local_addr()?, "changed", 1)?)?;
        let (mut server_changed, _) = origin.accept().await?;
        let (mut retained, incoming) = ingress().await?;
        relay.admit(incoming, admission(origin.local_addr()?, "retained", 2)?)?;
        let (mut server_retained, _) = origin.accept().await?;
        echo(&mut changed, &mut server_changed, b"before change").await?;
        echo(&mut retained, &mut server_retained, b"before retention").await?;
        // Same publication, new generation must not retain the old connection.
        relay
            .retain(&BTreeMap::from([
                ("changed".parse()?, 3),
                ("retained".parse()?, 2),
            ]))
            .await?;
        assert_eq!(relay.connections().len(), 1);
        closed(&mut changed).await?;
        closed(&mut server_changed).await?;
        echo(
            &mut retained,
            &mut server_retained,
            b"the original retained session still works",
        )
        .await?;
        relay.stop_admission();
        let (mut late, incoming) = ingress().await?;
        assert!(matches!(
            relay.admit(incoming, admission(origin.local_addr()?, "late", 4)?),
            Err(tunnel_detour_service::RelayError::Stopped)
        ));
        closed(&mut late).await?;
        relay.shutdown().await?;
        assert!(relay.connections().is_empty());
        closed(&mut retained).await?;
        closed(&mut server_retained).await?;
        Ok::<(), Box<dyn Error>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn r071_relay_capacity_rejects_excess_sessions_and_recovers_after_observed_completion()
-> TestResult {
    timeout(Duration::from_secs(10), async {
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut relay = sessions(1, Duration::from_secs(5))?;
        let (mut client, incoming) = ingress().await?;
        let first = relay.admit(incoming, admission(origin.local_addr()?, "limited", 1)?)?;
        let (mut server, _) = origin.accept().await?;
        let (mut rejected, incoming) = ingress().await?;
        assert!(matches!(
            relay.admit(incoming, admission(origin.local_addr()?, "limited", 1)?),
            Err(tunnel_detour_service::RelayError::Capacity)
        ));
        closed(&mut rejected).await?;
        assert_eq!(relay.connections().len(), 1);
        echo(
            &mut client,
            &mut server,
            b"capacity leaves the admitted connection intact",
        )
        .await?;
        client.shutdown().await?;
        server.shutdown().await?;
        assert_eq!(
            relay.next_completion().await?.outcome,
            RelayOutcome::Complete
        );
        let (mut fresh, incoming) = ingress().await?;
        let next = relay.admit(incoming, admission(origin.local_addr()?, "limited", 1)?)?;
        assert!(next > first);
        let (mut new_server, _) = origin.accept().await?;
        echo(&mut fresh, &mut new_server, b"capacity is reusable").await?;
        relay.shutdown().await?;
        assert!(relay.connections().is_empty());
        Ok::<(), Box<dyn Error>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn r072_relay_refused_destinations_and_idle_sessions_close_without_reconnect_while_active_sessions_have_no_lifetime_cutoff()
-> TestResult {
    timeout(Duration::from_secs(10), async {
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let unused = origin.local_addr()?;
        drop(origin);
        let mut relay = sessions(1, Duration::from_millis(500))?;
        let (mut client, incoming) = ingress().await?;
        relay.admit(incoming, admission(unused, "missing", 1)?)?;
        let failure = relay.next_completion().await?;
        assert_eq!(failure.outcome, RelayOutcome::ConnectFailed);
        assert_eq!(
            failure.error.as_ref().and_then(|cause| match cause {
                tunnel_detour_service::RelayError::Io(error) => Some(error.kind()),
                _ => None,
            }),
            Some(std::io::ErrorKind::ConnectionRefused)
        );
        closed(&mut client).await?;
        assert!(relay.connections().is_empty());
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let (mut client, incoming) = ingress().await?;
        relay.admit(incoming, admission(origin.local_addr()?, "idle", 2)?)?;
        let (mut server, _) = origin.accept().await?;
        let started = tokio::time::Instant::now();
        let mut heartbeat = tokio::time::interval(Duration::from_millis(100));
        for _ in 0..8 {
            heartbeat.tick().await;
            echo(&mut client, &mut server, b"actual I/O resets inactivity").await?;
        }
        assert!(
            started.elapsed() > Duration::from_millis(500),
            "active traffic must outlive the inactivity limit"
        );
        assert_eq!(
            relay.next_completion().await?.outcome,
            RelayOutcome::IdleTimeout
        );
        closed(&mut client).await?;
        closed(&mut server).await?;
        assert!(relay.connections().is_empty());
        relay.shutdown().await?;
        Ok::<(), Box<dyn Error>>(())
    })
    .await??;
    Ok(())
}

#[test]
fn r073_relay_resource_configuration_rejects_unbounded_connections_and_deadlines() -> TestResult {
    for (count, connect, idle) in [
        (0, Duration::from_secs(1), Duration::from_secs(1)),
        (257, Duration::from_secs(1), Duration::from_secs(1)),
        (1, Duration::ZERO, Duration::from_secs(1)),
        (1, Duration::from_secs(31), Duration::from_secs(1)),
        (1, Duration::from_secs(1), Duration::ZERO),
        (1, Duration::from_secs(1), Duration::from_secs(86_401)),
    ] {
        assert!(RelayLimits::new(count, connect, idle).is_err());
    }
    RelayLimits::new(32, Duration::from_secs(5), Duration::from_secs(3600))?;
    Ok(())
}
