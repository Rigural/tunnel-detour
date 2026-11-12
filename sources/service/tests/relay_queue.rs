use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    io,
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Instant, timeout},
};
use tunnel_detour_service::{
    RELAY_ADMISSION_WAIT, RELAY_PENDING_LIMIT, RelayAdmission, RelayError, RelayLimits,
    RelayOutcome, RelaySessions,
};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

async fn ingress(listener: &TcpListener) -> Result<(TcpStream, TcpStream)> {
    let client = TcpStream::connect(listener.local_addr()?).await?;
    let (incoming, _) = listener.accept().await?;
    Ok((client, incoming))
}

fn admission(target: &TcpListener, name: &str) -> Result<RelayAdmission> {
    let std::net::SocketAddr::V4(target) = target.local_addr()? else {
        return Err("fixture target is not IPv4".into());
    };
    Ok(RelayAdmission {
        publication: name.parse()?,
        generation: 1,
        target,
        lan_device: "lo".into(),
        reply_device: "lo".into(),
    })
}

async fn closed(stream: &mut TcpStream) -> Result {
    match timeout(Duration::from_secs(2), stream.read(&mut [0; 1])).await? {
        Ok(0) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ) =>
        {
            Ok(())
        }
        other => Err(format!("queued socket did not close: {other:?}").into()),
    }
}

fn assert_no_backend(listener: &TcpListener) {
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(
        listener.poll_accept(&mut context).is_pending(),
        "waiting ingress must not open another backend connection"
    );
}

#[tokio::test]
async fn r088_queued_ingress_keeps_identity_and_bytes_and_dials_only_after_the_previous_slot_drains()
-> Result {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await?;
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut sessions = RelaySessions::new(RelayLimits::new(
            1,
            Duration::from_secs(1),
            Duration::from_secs(3),
        )?);
        let (mut first, incoming) = ingress(&listener).await?;
        let id = sessions.enqueue(incoming, admission(&target, "first")?)?;
        let (mut first_target, _) = target.accept().await?;
        let (mut second, incoming) = ingress(&listener).await?;
        let queued = sessions.enqueue(incoming, admission(&target, "second")?)?;
        second.write_all(b"queued").await?;
        second.shutdown().await?;
        let state = sessions.connections();
        assert_eq!(state.len(), 2);
        assert_eq!(
            state.iter().filter(|connection| connection.queued).count(),
            1
        );
        assert_no_backend(&target);
        let engine = async {
            let completed = sessions.next_completion().await?;
            assert_eq!(completed.connection.id, id);
            assert_eq!(completed.outcome, RelayOutcome::Complete);
            let completed = sessions.next_completion().await?;
            assert_eq!(completed.connection.id, queued);
            assert_eq!(
                completed.outcome,
                RelayOutcome::Complete,
                "queued admission failed: {:?}",
                completed.error
            );
            assert_eq!(completed.bytes, Some((6, 8)));
            assert!(sessions.connections().is_empty());
            Ok::<_, Box<dyn Error>>(())
        };
        let server = async {
            let mut bytes = Vec::new();
            first_target.read_to_end(&mut bytes).await?;
            assert_eq!(bytes, b"active");
            first_target.write_all(b"finished").await?;
            first_target.shutdown().await?;
            drop(first_target);
            let (mut next, _) = target.accept().await?;
            bytes.clear();
            next.read_to_end(&mut bytes).await?;
            assert_eq!(bytes, b"queued");
            next.write_all(b"promoted").await?;
            next.shutdown().await?;
            Ok::<_, Box<dyn Error>>(())
        };
        let clients = async {
            first.write_all(b"active").await?;
            first.shutdown().await?;
            let mut bytes = Vec::new();
            first.read_to_end(&mut bytes).await?;
            assert_eq!(bytes, b"finished");
            bytes.clear();
            second.read_to_end(&mut bytes).await?;
            assert_eq!(bytes, b"promoted");
            Ok::<_, Box<dyn Error>>(())
        };
        tokio::try_join!(engine, server, clients)?;
        sessions.shutdown().await?;
        Ok::<_, Box<dyn Error>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn r089_a_full_pending_fifo_refuses_excess_and_expired_ingress_never_reaches_the_backend()
-> Result {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await?;
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut sessions = RelaySessions::new(RelayLimits::new(
            1,
            Duration::from_secs(1),
            Duration::from_secs(3),
        )?);
        let (_active, incoming) = ingress(&listener).await?;
        sessions.enqueue(incoming, admission(&target, "active")?)?;
        let (_backend, _) = target.accept().await?;
        let mut waiting = Vec::new();
        let started = Instant::now();
        let mut pending_ids = BTreeSet::new();
        for _ in 0..RELAY_PENDING_LIMIT {
            let (client, incoming) = ingress(&listener).await?;
            let id = sessions.enqueue(incoming, admission(&target, "waiting")?)?;
            assert!(
                pending_ids.insert(id),
                "queued identities must remain distinct"
            );
            waiting.push(client);
        }
        let (mut excess, incoming) = ingress(&listener).await?;
        assert!(matches!(
            sessions.enqueue(incoming, admission(&target, "excess")?),
            Err(RelayError::Capacity)
        ));
        closed(&mut excess).await?;
        assert_eq!(sessions.connections().len(), 1 + RELAY_PENDING_LIMIT);
        // A controller may be awaiting a network audit. The queue deadline must
        // close ingress independently of the next call that observes completion.
        closed(waiting.first_mut().ok_or("missing first pending client")?).await?;
        for _ in 0..RELAY_PENDING_LIMIT {
            let result = sessions.next_completion().await?;
            assert!(
                pending_ids.remove(&result.connection.id),
                "an expiry must complete its own queued identity exactly once"
            );
            assert_eq!(result.outcome, RelayOutcome::AdmissionTimeout);
        }
        assert!(pending_ids.is_empty());
        assert!(
            started.elapsed() >= RELAY_ADMISSION_WAIT,
            "queued ingress must not expire before its admission deadline"
        );
        assert_no_backend(&target);
        sessions.shutdown().await?;
        for client in waiting.iter_mut().skip(1) {
            closed(client).await?;
        }
        assert!(sessions.connections().is_empty());
        Ok::<_, Box<dyn Error>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn r090_retirement_closes_waiting_generations_while_retained_streams_continue_and_shutdown_empties_the_queue()
-> Result {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await?;
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut sessions = RelaySessions::new(RelayLimits::new(
            1,
            Duration::from_secs(1),
            Duration::from_secs(3),
        )?);
        let (mut active, incoming) = ingress(&listener).await?;
        sessions.enqueue(incoming, admission(&target, "retained")?)?;
        let (mut backend, _) = target.accept().await?;
        let (mut retired, incoming) = ingress(&listener).await?;
        sessions.enqueue(incoming, admission(&target, "retired")?)?;
        sessions
            .retain(&BTreeMap::from([("retained".parse()?, 1)]))
            .await?;
        closed(&mut retired).await?;
        assert_eq!(sessions.connections().len(), 1);
        let client = async {
            active.write_all(b"keep").await?;
            let mut bytes = [0; 4];
            active.read_exact(&mut bytes).await?;
            assert_eq!(&bytes, b"live");
            Ok::<_, Box<dyn Error>>(())
        };
        let server = async {
            let mut bytes = [0; 4];
            backend.read_exact(&mut bytes).await?;
            assert_eq!(&bytes, b"keep");
            backend.write_all(b"live").await?;
            Ok::<_, Box<dyn Error>>(())
        };
        tokio::try_join!(client, server)?;
        let (mut stopped, incoming) = ingress(&listener).await?;
        sessions.enqueue(incoming, admission(&target, "stopped")?)?;
        sessions.shutdown().await?;
        closed(&mut stopped).await?;
        closed(&mut active).await?;
        closed(&mut backend).await?;
        assert!(sessions.connections().is_empty());
        assert_no_backend(&target);
        Ok::<_, Box<dyn Error>>(())
    })
    .await??;
    Ok(())
}
