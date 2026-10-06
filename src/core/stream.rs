use bytes::Bytes;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::{CancellationToken, PollSender};

/// Handle for sending a FIN frame through the writer task channel.
/// Extracted from a `Stream` before it is consumed (e.g. by `tokio::io::split`).
pub struct FinSender {
    stream_id: u32,
    tx: mpsc::Sender<WriteCommand>,
    fin_sent: Arc<AtomicBool>,
}

impl FinSender {
    pub async fn send_fin(&self) -> io::Result<()> {
        if self.fin_sent.load(Ordering::Acquire) {
            return Ok(());
        }
        // Reserve before marking FIN sent so cancellation under backpressure
        // cannot suppress a later close attempt.
        let permit = self
            .tx
            .reserve()
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "session closed"))?;
        if !self.fin_sent.swap(true, Ordering::AcqRel) {
            permit.send(WriteCommand::fin(self.stream_id));
        }
        Ok(())
    }
}

pub struct WriteCommand {
    pub stream_id: u32,
    pub data: Bytes,
    /// When true, the writer task emits a FIN frame after any data.
    /// Routing FIN through the same channel as PSH guarantees ordering.
    pub fin: bool,
}

impl WriteCommand {
    pub fn fin(stream_id: u32) -> Self {
        Self {
            stream_id,
            data: Bytes::new(),
            fin: true,
        }
    }
}

pub struct Stream {
    id: u32,
    data_rx: mpsc::Receiver<Bytes>,
    session_tx: PollSender<WriteCommand>,
    /// Raw sender kept for `send_fin()` — works even after `tokio::io::split`.
    fin_tx: mpsc::Sender<WriteCommand>,
    read_buf: Bytes,
    fin_sent: Arc<AtomicBool>,
    shutdown: CancellationToken,
}

impl Stream {
    pub fn new(
        id: u32,
        session_tx: mpsc::Sender<WriteCommand>,
        channel_capacity: usize,
    ) -> (mpsc::Sender<Bytes>, Self) {
        let (data_tx, data_rx) = mpsc::channel(channel_capacity);
        let stream = Self {
            id,
            data_rx,
            fin_tx: session_tx.clone(),
            session_tx: PollSender::new(session_tx),
            read_buf: Bytes::new(),
            fin_sent: Arc::new(AtomicBool::new(false)),
            shutdown: CancellationToken::new(),
        };
        (data_tx, stream)
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub(crate) fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Returns a sender that can enqueue a FIN for this stream through the
    /// writer task channel. Useful when the Stream will be consumed (e.g. by
    /// `tokio::io::split`) and `send_fin()` cannot be called directly.
    pub fn fin_sender(&self) -> FinSender {
        FinSender {
            stream_id: self.id,
            tx: self.fin_tx.clone(),
            fin_sent: self.fin_sent.clone(),
        }
    }

    /// Send a FIN frame through the writer task channel, guaranteeing it is
    /// ordered after all previously queued PSH data for this stream.
    pub async fn send_fin(&self) -> io::Result<()> {
        self.fin_sender().send_fin().await
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drain read_buf first
        if !self.read_buf.is_empty() {
            let amt = self.read_buf.len().min(buf.remaining());
            buf.put_slice(&self.read_buf[..amt]);
            self.read_buf = self.read_buf.slice(amt..);
            return Poll::Ready(Ok(()));
        }

        // Poll for new data
        match self.data_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let amt = data.len().min(buf.remaining());
                buf.put_slice(&data[..amt]);
                if amt < data.len() {
                    self.read_buf = data.slice(amt..);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // Channel closed — EOF
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.fin_sent.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream closed",
            )));
        }
        match self.session_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let stream_id = self.id;
                let data = Bytes::copy_from_slice(buf);
                let len = data.len();
                self.session_tx
                    .send_item(WriteCommand {
                        stream_id,
                        data,
                        fin: false,
                    })
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "session closed"))?;
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session channel closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.fin_sent.load(Ordering::Acquire) {
            self.session_tx.abort_send();
            self.data_rx.close();
            self.shutdown.cancel();
            return Poll::Ready(Ok(()));
        }
        match self.session_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                if self.fin_sent.swap(true, Ordering::AcqRel) {
                    self.session_tx.abort_send();
                } else {
                    let id = self.id;
                    if self.session_tx.send_item(WriteCommand::fin(id)).is_err() {
                        self.fin_sent.store(false, Ordering::Release);
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "session closed",
                        )));
                    }
                }
                // AnyTLS FIN closes the whole stream. Stop accepting uploads
                // and let the relay release its socket without peer FIN.
                self.data_rx.close();
                self.shutdown.cancel();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_stream_read_receives_data() {
        let (writer, mut stream) = Stream::new(1, dummy_writer(), 128);
        writer
            .send(bytes::Bytes::from_static(b"hello"))
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[tokio::test]
    async fn test_stream_read_eof_on_drop() {
        let (writer, mut stream) = Stream::new(1, dummy_writer(), 128);
        drop(writer);
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn test_stream_read_partial_buffer() {
        let (writer, mut stream) = Stream::new(1, dummy_writer(), 128);
        writer
            .send(bytes::Bytes::from_static(b"hello world"))
            .await
            .unwrap();
        let mut buf = [0u8; 5];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"hello");
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b" worl");
    }

    #[tokio::test]
    async fn test_stream_write_sends_frame() {
        let (session_writer, mut rx) = tokio::sync::mpsc::channel::<WriteCommand>(8);
        let (_data_tx, mut stream) = Stream::new(1, session_writer, 128);
        stream.write_all(b"hello").await.unwrap();
        let cmd = rx.recv().await.unwrap();
        assert_eq!(cmd.stream_id, 1);
        assert_eq!(&cmd.data[..], b"hello");
    }

    #[tokio::test]
    async fn test_stream_id() {
        let (_writer, stream) = Stream::new(42, dummy_writer(), 128);
        assert_eq!(stream.id(), 42);
    }

    /// Stream::new should accept a configurable channel capacity parameter.
    #[tokio::test]
    async fn test_stream_new_with_custom_capacity() {
        let (writer, mut stream) = Stream::new(1, dummy_writer(), 16);
        writer
            .send(bytes::Bytes::from_static(b"hello"))
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    fn dummy_writer() -> tokio::sync::mpsc::Sender<WriteCommand> {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        tx
    }
}
