//! Byte transfer shared by TCP adapters. Authorization, routing and lifecycle belong to callers.

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

/// Per-direction userspace buffer size. Each transfer has two such buffers, excluding
/// socket buffers and caller-owned state. Concurrency must be bounded by the admitting adapter.
pub const TCP_TRANSFER_BUFFER_BYTES: usize = 8 * 1024;

/// Transfer opaque bytes in both directions, preserving independent TCP half-closes.
///
/// An EOF closes the opposing write side while the remaining direction continues draining.
/// The result counts bytes from `incoming` to `outgoing`, then the reverse direction.
/// Callers own timeouts and cancellation: dropping this future can discard buffered bytes.
///
/// # Errors
/// Returns the underlying read, write, flush or shutdown error. After an error, the caller
/// must close both endpoints; this function does not reconnect or select another destination.
pub async fn transfer_tcp<A, B>(incoming: &mut A, outgoing: &mut B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let (incoming_read, mut incoming_write) = tokio::io::split(incoming);
    let (outgoing_read, mut outgoing_write) = tokio::io::split(outgoing);
    let forward = async {
        let mut reader = BufReader::with_capacity(TCP_TRANSFER_BUFFER_BYTES, incoming_read);
        let count = tokio::io::copy_buf(&mut reader, &mut outgoing_write).await?;
        outgoing_write.shutdown().await?;
        Ok::<_, std::io::Error>(count)
    };
    let reverse = async {
        let mut reader = BufReader::with_capacity(TCP_TRANSFER_BUFFER_BYTES, outgoing_read);
        let count = tokio::io::copy_buf(&mut reader, &mut incoming_write).await?;
        incoming_write.shutdown().await?;
        Ok::<_, std::io::Error>(count)
    };
    // The default try_join! rotates its first polled branch. A fixed first copy can
    // spend the entire cooperative budget on a permanently ready upload, starving
    // the reverse direction even while it has data ready. Neither future is detached.
    tokio::try_join!(forward, reverse)
}
