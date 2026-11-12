use std::{
    error::Error,
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tunnel_detour_service::transfer_tcp;

type TestResult = Result<(), Box<dyn Error>>;

#[tokio::test]
async fn r084_an_eager_upload_cannot_starve_a_ready_reverse_response() -> TestResult {
    use std::{
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::{Context, Poll, ready},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    const UPLOAD: usize = 4 * 1024 * 1024;
    struct Endpoint {
        remaining: usize,
        upload: bool,
        forward: Arc<AtomicUsize>,
        reverse_before_upload_ends: Arc<AtomicBool>,
    }
    impl AsyncRead for Endpoint {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let progress = ready!(tokio::task::coop::poll_proceed(cx));
            let count = buffer.remaining().min(self.remaining).min(8192);
            buffer.put_slice(&[42; 8192][..count]);
            self.remaining -= count;
            if self.upload {
                self.forward.store(self.remaining, Ordering::SeqCst);
            }
            progress.made_progress();
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncWrite for Endpoint {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let progress = ready!(tokio::task::coop::poll_proceed(cx));
            if self.upload && !bytes.is_empty() && self.forward.load(Ordering::SeqCst) > 0 {
                self.reverse_before_upload_ends
                    .store(true, Ordering::SeqCst);
            }
            progress.made_progress();
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    // Cooperative, permanently ready adapters make scheduling observable without relying
    // on TCP timing or a throughput threshold. Real duplex loads are measured separately.
    let remaining = Arc::new(AtomicUsize::new(UPLOAD));
    let responded = Arc::new(AtomicBool::new(false));
    let mut incoming = Endpoint {
        remaining: UPLOAD,
        upload: true,
        forward: remaining.clone(),
        reverse_before_upload_ends: responded.clone(),
    };
    let mut outgoing = Endpoint {
        remaining: 1,
        upload: false,
        forward: remaining,
        reverse_before_upload_ends: responded.clone(),
    };
    assert_eq!(
        transfer_tcp(&mut incoming, &mut outgoing).await?,
        (u64::try_from(UPLOAD)?, 1)
    );
    assert!(
        responded.load(Ordering::SeqCst),
        "a ready reverse response must be delivered before an eager upload finishes"
    );
    Ok(())
}

#[tokio::test]
async fn r066_tcp_half_close_from_either_endpoint_preserves_the_complete_pending_response()
-> TestResult {
    // RLY-03: both orderings use real IPv6 ingress and IPv4 destination sockets. No task
    // outlives the bounded joined exchange, including when an endpoint fails or times out.
    for server_closes_first in [false, true] {
        let ingress = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await?;
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut client = TcpStream::connect(ingress.local_addr()?).await?;
        let (mut incoming, _) = ingress.accept().await?;
        let mut outgoing = TcpStream::connect(origin.local_addr()?).await?;
        let (mut server, _) = origin.accept().await?;
        let request: Vec<_> = (0_u8..=250).cycle().take(1_048_576).collect();
        let response: Vec<_> = (0_u8..=250).rev().cycle().take(1_048_576).collect();
        let client_side = async {
            let mut received = Vec::new();
            if server_closes_first {
                client.read_to_end(&mut received).await?;
                client.write_all(&request).await?;
                client.shutdown().await?;
            } else {
                client.write_all(&request).await?;
                client.shutdown().await?;
                client.read_to_end(&mut received).await?;
            }
            assert!(
                received == response,
                "the client received a truncated or altered response ({} bytes, expected {})",
                received.len(),
                response.len()
            );
            Ok::<(), std::io::Error>(())
        };
        let server_side = async {
            let mut received = Vec::new();
            if server_closes_first {
                server.write_all(&response).await?;
                server.shutdown().await?;
                server.read_to_end(&mut received).await?;
            } else {
                server.read_to_end(&mut received).await?;
                server.write_all(&response).await?;
                server.shutdown().await?;
            }
            assert!(
                received == request,
                "the server received a truncated or altered request ({} bytes, expected {})",
                received.len(),
                request.len()
            );
            Ok::<(), std::io::Error>(())
        };
        let (_, _, counts) = timeout(Duration::from_secs(10), async {
            tokio::try_join!(
                client_side,
                server_side,
                transfer_tcp(&mut incoming, &mut outgoing)
            )
        })
        .await??;
        assert_eq!(counts, (1_048_576, 1_048_576));
    }
    Ok(())
}
