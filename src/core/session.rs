use rustc_hash::FxHashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::core::frame::{Command, FrameHeader, HEADER_SIZE};
use crate::core::padding::PaddingFactory;
use crate::core::stream::{Stream, WriteCommand};
use crate::error::Result;

/// Write a single WriteCommand as one or more PSH frames (chunking at u16::MAX).
/// Does NOT flush — caller is responsible for flushing after batching.
/// Header and payload are coalesced into a single write to avoid generating
/// separate TLS records (each record adds ~29 bytes overhead + encryption).
async fn write_psh_frames<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    cmd: &WriteCommand,
    combined_buf: &mut Vec<u8>,
) -> std::io::Result<()> {
    let data = &cmd.data;
    let total = data.len();
    let mut offset = 0;
    loop {
        let chunk_end = (offset + u16::MAX as usize).min(total);
        let chunk = &data[offset..chunk_end];
        let header = FrameHeader {
            command: Command::Psh,
            stream_id: cmd.stream_id,
            length: chunk.len() as u16,
        };
        // Coalesce header + payload into a single write_all call.
        combined_buf.clear();
        let mut hdr_buf = [0u8; HEADER_SIZE];
        header.encode(&mut hdr_buf);
        combined_buf.extend_from_slice(&hdr_buf);
        combined_buf.extend_from_slice(chunk);
        w.write_all(combined_buf).await?;
        offset = chunk_end;
        if offset >= total {
            break;
        }
    }
    Ok(())
}

/// Write a single WriteCommand: PSH data frames, then optionally a FIN frame.
/// Routing FIN through the same writer task as PSH guarantees FIN is never
/// sent before all preceding PSH data for that stream.
async fn write_cmd_frame<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    cmd: &WriteCommand,
    combined_buf: &mut Vec<u8>,
) -> std::io::Result<()> {
    if !cmd.data.is_empty() {
        write_psh_frames(w, cmd, combined_buf).await?;
    }
    if cmd.fin {
        let header = FrameHeader {
            command: Command::Fin,
            stream_id: cmd.stream_id,
            length: 0,
        };
        let mut hdr_buf = [0u8; HEADER_SIZE];
        header.encode(&mut hdr_buf);
        w.write_all(&hdr_buf).await?;
    }
    Ok(())
}

pub const DEFAULT_WRITE_BUF_SIZE: usize = 32 * 1024;
pub const DEFAULT_STREAM_CHANNEL_CAPACITY: usize = 128;

/// Maximum number of WriteCommands processed in a single writer batch
/// before flushing. Prevents the try_recv loop from spinning indefinitely
/// under sustained high throughput, which would defer flush() and consume
/// 100% CPU on the writer task.
const MAX_BATCH_SIZE: usize = 64;

/// Maximum time to wait for a single control frame write+flush before
/// treating the connection as dead. Only applied to control frames
/// (HeartResponse, SynAck, Settings, etc.) which are small and should
/// complete quickly. Data frame writes have no timeout — network congestion
/// can cause legitimate delays. This aligns with sing-anytls where only
/// writeControlFrame has a deadline.
const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Wraps an async write operation with [`WRITE_TIMEOUT`], converting an
/// elapsed timeout to [`crate::error::Error::WriteTimeout`].
/// Used only for control frame writes, not data frame writes.
async fn timed_write<F>(fut: F) -> Result<()>
where
    F: std::future::Future<Output = std::io::Result<()>>,
{
    match tokio::time::timeout(WRITE_TIMEOUT, fut).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Err(crate::error::Error::WriteTimeout),
    }
}

pub struct SessionConfig {
    pub max_streams: usize,
    pub write_cmd_capacity: usize,
    /// BufWriter buffer size for the TLS write half (bytes).
    pub write_buf_size: usize,
    /// Per-stream data channel capacity (number of Bytes messages).
    pub stream_channel_capacity: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_streams: 256,
            write_cmd_capacity: 512,
            write_buf_size: DEFAULT_WRITE_BUF_SIZE,
            stream_channel_capacity: DEFAULT_STREAM_CHANNEL_CAPACITY,
        }
    }
}

pub struct Session<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    read_half: Mutex<tokio::io::ReadHalf<T>>,
    write_half: Arc<Mutex<tokio::io::BufWriter<tokio::io::WriteHalf<T>>>>,
    padding: PaddingFactory,
    config: SessionConfig,
    peer_version: AtomicU8,
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Session<T> {
    pub fn new_server(conn: T, padding: PaddingFactory, config: SessionConfig) -> Self {
        let (read_half, write_half) = tokio::io::split(conn);
        let buf_size = config.write_buf_size;
        Self {
            read_half: Mutex::new(read_half),
            write_half: Arc::new(Mutex::new(tokio::io::BufWriter::with_capacity(
                buf_size, write_half,
            ))),
            padding,
            config,
            peer_version: AtomicU8::new(0),
        }
    }

    pub fn padding_md5(&self) -> &str {
        self.padding.md5_hex()
    }

    pub async fn recv_loop(
        self: Arc<Self>,
        new_stream_tx: mpsc::Sender<Stream>,
        cancel_token: CancellationToken,
    ) -> Result<()> {
        let mut streams: FxHashMap<u32, mpsc::Sender<Bytes>> = FxHashMap::default();
        let mut settings_received = false;

        // Create the write command channel and spawn writer task.
        // The writer_cancel token lets the writer signal recv_loop to exit
        // when a write error occurs (e.g. network disruption).
        let (write_cmd_tx, mut write_cmd_rx) =
            mpsc::channel::<WriteCommand>(self.config.write_cmd_capacity);
        let writer = self.write_half.clone();
        let writer_failed = CancellationToken::new();
        let writer_failed_signal = writer_failed.clone();
        // Clone for the writer task so it can observe cancellation. Without
        // this, a write_all blocked on a slow/dead peer keeps the writer task
        // alive indefinitely, holding the only remaining write_half Arc clone
        // → underlying TcpStream stuck in CLOSE-WAIT for tcp_retries2 (~15min).
        let writer_cancel = cancel_token.clone();
        tokio::spawn(async move {
            // Reusable buffer for coalescing header+payload into single writes.
            let mut combined_buf = Vec::with_capacity(HEADER_SIZE + u16::MAX as usize);

            let err = 'outer: loop {
                let cmd = tokio::select! {
                    biased;
                    _ = writer_cancel.cancelled() => break None,
                    r = write_cmd_rx.recv() => match r {
                        Some(c) => c,
                        None => break None,
                    },
                };

                // Write the first command under a lock hold.
                // No timeout on data frame writes — network congestion can
                // cause legitimate delays exceeding 5s. Aligns with
                // sing-anytls where writeDataFrame has no deadline.
                let mut w = writer.lock().await;
                let res = tokio::select! {
                    biased;
                    _ = writer_cancel.cancelled() => break 'outer None,
                    r = write_cmd_frame(&mut *w, &cmd, &mut combined_buf) => r,
                };
                if let Err(e) = res {
                    break Some(e);
                }

                // Batch more pending commands, but **release and re-acquire
                // the lock between each command** so that control frame
                // writers (write_frame: SynAck, HeartResponse, etc.) can
                // interleave.  The Go server acquires/releases the lock per
                // frame; without this yield the writer task can hold the
                // lock for the entire batch duration — longer than the
                // client's 3-second SYN deadline when the connection is
                // slow or congested.
                let mut batch_remaining = MAX_BATCH_SIZE - 1;
                while batch_remaining > 0 {
                    let Ok(cmd) = write_cmd_rx.try_recv() else {
                        break;
                    };
                    // Yield lock so control frame writers get a turn.
                    drop(w);
                    w = writer.lock().await;
                    let res = tokio::select! {
                        biased;
                        _ = writer_cancel.cancelled() => break 'outer None,
                        r = write_cmd_frame(&mut *w, &cmd, &mut combined_buf) => r,
                    };
                    if let Err(e) = res {
                        break 'outer Some(e);
                    }
                    batch_remaining -= 1;
                }

                // Flush remaining data in the BufWriter to TLS.
                // (A control frame writer may have already flushed part of
                // the batch between lock yields — that's fine.)
                let res = tokio::select! {
                    biased;
                    _ = writer_cancel.cancelled() => break 'outer None,
                    r = w.flush() => r,
                };
                if let Err(e) = res {
                    break Some(e);
                }
            };
            if let Some(e) = err {
                warn!("writer task: write error: {}", e);
                writer_failed_signal.cancel();
            }
        });

        let mut reader = self.read_half.lock().await;
        // Reusable buffer to avoid per-frame heap allocation
        let mut payload_buf = BytesMut::with_capacity(u16::MAX as usize);

        loop {
            let mut hdr_buf = [0u8; HEADER_SIZE];
            let read_result = tokio::select! {
                r = reader.read_exact(&mut hdr_buf) => r,
                _ = cancel_token.cancelled() => {
                    debug!("session cancelled by connection manager");
                    break;
                }
                _ = writer_failed.cancelled() => {
                    debug!("writer task failed, closing session");
                    break;
                }
            };
            match read_result {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    debug!("connection closed");
                    break;
                }
                Err(e) => return Err(e.into()),
            }

            let header = FrameHeader::decode(&hdr_buf);
            let len = header.length as usize;

            match header.command {
                Command::Psh => {
                    payload_buf.resize(len, 0);
                    if len > 0 {
                        reader.read_exact(&mut payload_buf[..len]).await?;
                    }
                    if let Some(tx) = streams.get(&header.stream_id) {
                        // split() → freeze() gives a zero-copy Bytes;
                        // the underlying allocation is reused on next resize.
                        let data = payload_buf.split().freeze();
                        // Use try_send to avoid head-of-line blocking: if one
                        // stream's channel is full, we must not block recv_loop
                        // (which would stall ALL streams on this connection).
                        match tx.try_send(data) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                streams.remove(&header.stream_id);
                            }
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                // Channel full — consumer is severely behind.
                                // Drop this stream to avoid blocking recv_loop
                                // (which would stall ALL streams).
                                let stream_id = header.stream_id;
                                warn!(stream_id, "stream channel full, closing stream");
                                streams.remove(&stream_id);
                                // Notify the peer so it stops sending data for
                                // this stream. Routed through the writer task
                                // channel to preserve frame ordering.
                                let _ = write_cmd_tx.try_send(WriteCommand::fin(stream_id));
                            }
                        }
                    }
                }
                Command::Settings => {
                    payload_buf.resize(len, 0);
                    if len > 0 {
                        reader.read_exact(&mut payload_buf[..len]).await?;
                    }
                    let text = String::from_utf8_lossy(&payload_buf[..len]);
                    let mut peer_version: u8 = 0;
                    let mut peer_padding_md5 = String::new();
                    for line in text.lines() {
                        if let Some(v) = line.strip_prefix("v=") {
                            peer_version = v.parse().unwrap_or(0);
                        } else if let Some(md5) = line.strip_prefix("padding-md5=") {
                            peer_padding_md5 = md5.to_string();
                        }
                    }
                    self.peer_version.store(peer_version, Ordering::Relaxed);
                    settings_received = true;

                    // Batch settings response frames under a single lock + flush.
                    let need_padding = peer_padding_md5 != self.padding.md5_hex();
                    let need_server_settings = peer_version >= 2;
                    if need_padding || need_server_settings {
                        self.write_settings_response(need_padding, need_server_settings)
                            .await?;
                    }
                }
                Command::Syn => {
                    if !settings_received {
                        self.write_frame(
                            Command::Alert,
                            header.stream_id,
                            b"settings not received",
                        )
                        .await?;
                        if len > 0 {
                            payload_buf.resize(len, 0);
                            reader.read_exact(&mut payload_buf[..len]).await?;
                        }
                        continue;
                    }
                    if streams.len() >= self.config.max_streams {
                        self.write_frame(Command::Alert, header.stream_id, b"max streams exceeded")
                            .await?;
                        if len > 0 {
                            payload_buf.resize(len, 0);
                            reader.read_exact(&mut payload_buf[..len]).await?;
                        }
                        continue;
                    }
                    if len > 0 {
                        payload_buf.resize(len, 0);
                        reader.read_exact(&mut payload_buf[..len]).await?;
                    }
                    let (data_tx, stream) = Stream::new(
                        header.stream_id,
                        write_cmd_tx.clone(),
                        self.config.stream_channel_capacity,
                    );
                    streams.insert(header.stream_id, data_tx);
                    if new_stream_tx.send(stream).await.is_err() {
                        warn!("new_stream_tx receiver dropped");
                        break;
                    }
                }
                Command::Fin => {
                    if len > 0 {
                        payload_buf.resize(len, 0);
                        reader.read_exact(&mut payload_buf[..len]).await?;
                    }
                    streams.remove(&header.stream_id);
                }
                Command::Alert => {
                    payload_buf.resize(len, 0);
                    if len > 0 {
                        reader.read_exact(&mut payload_buf[..len]).await?;
                    }
                    let msg = String::from_utf8_lossy(&payload_buf[..len]);
                    warn!("received alert: {}", msg);
                    break;
                }
                Command::HeartRequest => {
                    if len > 0 {
                        payload_buf.resize(len, 0);
                        reader.read_exact(&mut payload_buf[..len]).await?;
                    }
                    self.write_frame(Command::HeartResponse, 0, &[]).await?;
                }
                // HeartResponse, Waste, and unknown commands: skip payload.
                _ => {
                    if len > 0 {
                        payload_buf.resize(len, 0);
                        reader.read_exact(&mut payload_buf[..len]).await?;
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn write_frame(&self, command: Command, stream_id: u32, data: &[u8]) -> Result<()> {
        if data.len() > u16::MAX as usize {
            return Err(crate::error::Error::FrameTooLarge(data.len()));
        }
        let header = FrameHeader {
            command,
            stream_id,
            length: data.len() as u16,
        };
        let mut hdr_buf = [0u8; HEADER_SIZE];
        header.encode(&mut hdr_buf);

        let total = HEADER_SIZE + data.len();
        let mut w = tokio::time::timeout(WRITE_TIMEOUT, self.write_half.lock())
            .await
            .map_err(|_| crate::error::Error::WriteTimeout)?;

        timed_write(async {
            // Use stack buffer for small control frames (FIN, SynAck, HeartResponse, etc.)
            // to avoid heap allocation. Most control frames are ≤ 128 bytes.
            if total <= 128 {
                let mut stack_buf = [0u8; 128];
                stack_buf[..HEADER_SIZE].copy_from_slice(&hdr_buf);
                stack_buf[HEADER_SIZE..total].copy_from_slice(data);
                w.write_all(&stack_buf[..total]).await?;
            } else {
                let mut buf = Vec::with_capacity(total);
                buf.extend_from_slice(&hdr_buf);
                buf.extend_from_slice(data);
                w.write_all(&buf).await?;
            }
            // Flush immediately so control frames are not delayed in the buffer.
            w.flush().await?;
            Ok(())
        })
        .await
    }

    /// Batch-write settings response frames (UpdatePaddingScheme and/or
    /// ServerSettings) in a single lock acquisition, single write_all, and flush.
    /// All frames are coalesced into one buffer to avoid generating separate TLS
    /// records (each record adds ~29 bytes overhead + encryption cost).
    async fn write_settings_response(
        &self,
        send_padding: bool,
        send_server_settings: bool,
    ) -> Result<()> {
        if !send_padding && !send_server_settings {
            return Ok(());
        }

        // Pre-compute total size and build a single coalesced buffer.
        let padding_data = if send_padding {
            let data = self.padding.raw_scheme().as_bytes();
            if data.len() > u16::MAX as usize {
                return Err(crate::error::Error::FrameTooLarge(data.len()));
            }
            Some(data)
        } else {
            None
        };
        let padding_frame_len = padding_data.map_or(0, |d| HEADER_SIZE + d.len());
        let settings_frame_len = if send_server_settings {
            HEADER_SIZE + 3
        } else {
            0
        };
        let total = padding_frame_len + settings_frame_len;

        let mut buf = Vec::with_capacity(total);

        if let Some(data) = padding_data {
            let header = FrameHeader {
                command: Command::UpdatePaddingScheme,
                stream_id: 0,
                length: data.len() as u16,
            };
            let mut hdr_buf = [0u8; HEADER_SIZE];
            header.encode(&mut hdr_buf);
            buf.extend_from_slice(&hdr_buf);
            buf.extend_from_slice(data);
        }

        if send_server_settings {
            let header = FrameHeader {
                command: Command::ServerSettings,
                stream_id: 0,
                length: 3,
            };
            let mut hdr_buf = [0u8; HEADER_SIZE];
            header.encode(&mut hdr_buf);
            buf.extend_from_slice(&hdr_buf);
            buf.extend_from_slice(b"v=2");
        }

        let mut w = tokio::time::timeout(WRITE_TIMEOUT, self.write_half.lock())
            .await
            .map_err(|_| crate::error::Error::WriteTimeout)?;
        timed_write(async {
            w.write_all(&buf).await?;
            w.flush().await?;
            Ok(())
        })
        .await
    }

    pub async fn handshake_success(&self, stream_id: u32) -> Result<()> {
        if self.peer_version.load(Ordering::Relaxed) >= 2 {
            self.write_frame(Command::SynAck, stream_id, &[]).await?;
        }
        Ok(())
    }

    pub async fn handshake_failure(&self, stream_id: u32, err: &str) -> Result<()> {
        if self.peer_version.load(Ordering::Relaxed) >= 2 {
            self.write_frame(Command::SynAck, stream_id, err.as_bytes())
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::frame::{Command, FrameHeader, HEADER_SIZE};
    use crate::core::padding::{DEFAULT_SCHEME, PaddingFactory};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio_util::sync::CancellationToken;

    fn test_padding() -> PaddingFactory {
        PaddingFactory::new(DEFAULT_SCHEME).unwrap()
    }

    // Helper: write a frame to an AsyncWrite
    async fn write_frame<W: AsyncWriteExt + Unpin>(
        w: &mut W,
        cmd: Command,
        stream_id: u32,
        data: &[u8],
    ) {
        let header = FrameHeader {
            command: cmd,
            stream_id,
            length: data.len() as u16,
        };
        let mut hdr_buf = [0u8; HEADER_SIZE];
        header.encode(&mut hdr_buf);
        w.write_all(&hdr_buf).await.unwrap();
        if !data.is_empty() {
            w.write_all(data).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_session_settings_exchange() {
        let (mut client_io, server_io) = duplex(8192);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;
        let (new_stream_tx, _) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, CancellationToken::new())
                .await
        });
        drop(client_io);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_session_syn_creates_stream() {
        let (mut client_io, server_io) = duplex(65536);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));
        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, CancellationToken::new())
                .await
        });
        write_frame(&mut client_io, Command::Syn, 1, &[]).await;
        let stream = tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stream.id(), 1);
        drop(client_io);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_session_psh_delivers_data() {
        let (mut client_io, server_io) = duplex(65536);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));
        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, CancellationToken::new())
                .await
        });
        write_frame(&mut client_io, Command::Syn, 1, &[]).await;
        let mut stream =
            tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
                .await
                .unwrap()
                .unwrap();
        write_frame(&mut client_io, Command::Psh, 1, b"hello from client").await;
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"hello from client");
        drop(client_io);
        let _ = handle.await;
    }

    /// Verify that write_frame flushes immediately so control frames are not
    /// delayed when the transport is buffered (e.g. BufWriter / TLS).
    #[tokio::test]
    async fn test_control_frame_flushed_immediately() {
        let (mut client_io, server_io) = duplex(65536);
        let buf_server_io = tokio::io::BufWriter::with_capacity(8192, server_io);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            buf_server_io,
            padding,
            SessionConfig::default(),
        ));
        let (new_stream_tx, _) = tokio::sync::mpsc::channel(8);
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, CancellationToken::new())
                .await
        });

        // Send a HeartRequest — server should respond with HeartResponse
        write_frame(&mut client_io, Command::HeartRequest, 0, &[]).await;

        // Try to read the response within a short timeout.
        // If write_frame doesn't flush, the HeartResponse will be stuck in BufWriter.
        let mut hdr_buf = [0u8; HEADER_SIZE];
        let mut found_heart = false;
        for _ in 0..5 {
            match tokio::time::timeout(
                std::time::Duration::from_millis(100),
                client_io.read_exact(&mut hdr_buf),
            )
            .await
            {
                Ok(Ok(_)) => {
                    let hdr = FrameHeader::decode(&hdr_buf);
                    if hdr.length > 0 {
                        let mut skip = vec![0u8; hdr.length as usize];
                        client_io.read_exact(&mut skip).await.unwrap();
                    }
                    if hdr.command == Command::HeartResponse {
                        found_heart = true;
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(
            found_heart,
            "HeartResponse not received within timeout — write_frame likely not flushing"
        );
        drop(client_io);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_session_heart_request_response() {
        let (mut client_io, server_io) = duplex(65536);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));
        let (new_stream_tx, _) = tokio::sync::mpsc::channel(8);
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, CancellationToken::new())
                .await
        });
        write_frame(&mut client_io, Command::HeartRequest, 0, &[]).await;
        // Read frames back — may get ServerSettings first, then HeartResponse
        let mut found_heart = false;
        for _ in 0..5 {
            let mut hdr_buf = [0u8; HEADER_SIZE];
            match tokio::time::timeout(
                std::time::Duration::from_secs(1),
                client_io.read_exact(&mut hdr_buf),
            )
            .await
            {
                Ok(Ok(_)) => {
                    let hdr = FrameHeader::decode(&hdr_buf);
                    if hdr.length > 0 {
                        let mut skip = vec![0u8; hdr.length as usize];
                        client_io.read_exact(&mut skip).await.unwrap();
                    }
                    if hdr.command == Command::HeartResponse {
                        found_heart = true;
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(found_heart, "did not receive HeartResponse");
        drop(client_io);
        let _ = handle.await;
    }

    /// recv_loop must exit promptly when a CancellationToken is cancelled,
    /// even if the connection is otherwise healthy and active.
    #[tokio::test]
    async fn test_recv_loop_exits_on_cancel_token() {
        let (mut client_io, server_io) = duplex(65536);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;

        let cancel_token = tokio_util::sync::CancellationToken::new();
        let (new_stream_tx, _) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let ct = cancel_token.clone();
        let handle = tokio::spawn(async move { sess.recv_loop(new_stream_tx, ct).await });

        // Connection is alive — send a heartbeat to confirm
        write_frame(&mut client_io, Command::HeartRequest, 0, &[]).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!handle.is_finished(), "session should still be running");

        // Cancel the token — recv_loop should exit promptly
        cancel_token.cancel();

        let result = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        assert!(
            result.is_ok(),
            "recv_loop did not exit after cancel_token was cancelled"
        );

        drop(client_io);
    }

    /// write_settings_response must coalesce UpdatePaddingScheme and
    /// ServerSettings into a single write so they share one TLS record.
    #[tokio::test]
    async fn test_settings_response_coalesced() {
        let (mut client_io, server_io) = duplex(65536);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));
        // Send settings with a wrong padding MD5 to trigger UpdatePaddingScheme + ServerSettings
        let settings_data = "v=2\npadding-md5=wrong_md5";
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;

        let (new_stream_tx, _) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, CancellationToken::new())
                .await
        });

        let mut found_padding = false;
        let mut found_server_settings = false;
        for _ in 0..5 {
            let mut hdr_buf = [0u8; HEADER_SIZE];
            match tokio::time::timeout(
                std::time::Duration::from_secs(1),
                client_io.read_exact(&mut hdr_buf),
            )
            .await
            {
                Ok(Ok(_)) => {
                    let hdr = FrameHeader::decode(&hdr_buf);
                    if hdr.length > 0 {
                        let mut payload = vec![0u8; hdr.length as usize];
                        client_io.read_exact(&mut payload).await.unwrap();
                        if hdr.command == Command::ServerSettings {
                            assert_eq!(&payload, b"v=2");
                        }
                    }
                    match hdr.command {
                        Command::UpdatePaddingScheme => found_padding = true,
                        Command::ServerSettings => found_server_settings = true,
                        _ => {}
                    }
                }
                _ => break,
            }
        }
        assert!(
            found_padding,
            "expected UpdatePaddingScheme frame in response"
        );
        assert!(
            found_server_settings,
            "expected ServerSettings frame in response"
        );

        drop(client_io);
        let _ = handle.await;
    }

    /// Issue #2: write_cmd channel (capacity 256) shared by ALL streams.
    /// Verify that the writer task's try_recv batch drains the entire channel
    /// under a single lock hold. When the batch is large (many streams writing
    /// simultaneously), the lock is held for a long time, starving control frames.
    /// This test verifies data from multiple streams flows through correctly.
    #[tokio::test]
    async fn test_write_cmd_shared_channel_multiple_streams() {
        let (mut client_io, server_io) = duplex(2 * 1024 * 1024);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;

        // Create 5 streams
        for i in 1..=5u32 {
            write_frame(&mut client_io, Command::Syn, i, &[]).await;
        }

        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, CancellationToken::new())
                .await
        });

        let mut streams = Vec::new();
        for _ in 0..5 {
            let stream =
                tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
                    .await
                    .unwrap()
                    .unwrap();
            streams.push(stream);
        }

        // Each stream writes 20 chunks of 1KB through the SHARED write_cmd channel.
        // Total: 5 streams * 20 * 1KB = 100KB. All competing for capacity 256.
        let chunk = vec![0xCD_u8; 1024];
        let mut write_handles = Vec::new();
        for mut stream in streams {
            let data = chunk.clone();
            write_handles.push(tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                for _ in 0..20 {
                    stream.write_all(&data).await.unwrap();
                }
            }));
        }

        // Drain output concurrently so writer doesn't block on duplex.
        let drain = tokio::spawn(async move {
            let mut buf = [0u8; 65536];
            loop {
                match client_io.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });

        // All 100 writes (5*20) must complete within 2 seconds.
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            for h in write_handles {
                h.await.unwrap();
            }
        })
        .await;

        assert!(
            result.is_ok(),
            "concurrent writes from 5 streams timed out — write_cmd channel bottleneck"
        );

        drain.abort();
        let _ = handle.await;
    }

    /// RED test: Prove that send_fin can arrive before pending PSH data.
    ///
    /// Scenario: a stream writes many PSH chunks through write_cmd_tx (writer task),
    /// then immediately calls session.send_fin() which bypasses the writer task
    /// and writes FIN directly to the TLS connection via write_half mutex.
    /// Under contention, FIN can win the lock race and arrive before the
    /// writer task has flushed all PSH data — causing ERR_CONNECTION_CLOSED.
    #[tokio::test]
    async fn test_fin_must_arrive_after_all_psh_data() {
        let (mut client_io, server_io) = duplex(2 * 1024 * 1024);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;
        write_frame(&mut client_io, Command::Syn, 1, &[]).await;

        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, CancellationToken::new())
                .await
        });

        let mut stream =
            tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(stream.id(), 1);

        // Write many PSH chunks through the stream (goes via write_cmd_tx → writer task).
        // Use large enough volume that the writer task can't flush instantly.
        {
            use tokio::io::AsyncWriteExt;
            let data = vec![0xBE_u8; 4096];
            for _ in 0..50 {
                stream.write_all(&data).await.unwrap();
            }
        }

        // Send FIN through the same writer task channel — guarantees ordering
        // after all PSH data. (The old code used session.send_fin() which
        // bypassed the channel and raced with the writer task.)
        stream.send_fin().await.unwrap();

        // Read all frames from client side and verify:
        // ALL PSH frames for stream 1 must appear BEFORE the FIN.
        let mut hdr_buf = [0u8; HEADER_SIZE];
        let mut skip_buf = vec![0u8; 65536];
        let mut total_psh_bytes: usize = 0;
        let mut fin_seen = false;
        let mut psh_after_fin = false;

        let read_result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if client_io.read_exact(&mut hdr_buf).await.is_err() {
                    break;
                }
                let hdr = FrameHeader::decode(&hdr_buf);
                if hdr.length > 0 {
                    if client_io
                        .read_exact(&mut skip_buf[..hdr.length as usize])
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                if hdr.stream_id == 1 {
                    match hdr.command {
                        Command::Psh => {
                            total_psh_bytes += hdr.length as usize;
                            if fin_seen {
                                psh_after_fin = true;
                            }
                        }
                        Command::Fin => {
                            fin_seen = true;
                        }
                        _ => {}
                    }
                }
                if fin_seen && !psh_after_fin {
                    // FIN seen and no more PSH expected — we can stop reading
                    // Give a small window to catch any late PSH frames
                    break;
                }
            }
        })
        .await;
        assert!(read_result.is_ok(), "timed out reading frames");

        let expected_psh_bytes = 50 * 4096;
        assert!(fin_seen, "FIN frame not received");
        assert!(
            !psh_after_fin,
            "BUG: PSH data arrived AFTER FIN — client would see ERR_CONNECTION_CLOSED. \
             Got {total_psh_bytes}/{expected_psh_bytes} PSH bytes before FIN."
        );
        assert_eq!(
            total_psh_bytes, expected_psh_bytes,
            "Not all PSH data arrived before FIN — {total_psh_bytes}/{expected_psh_bytes} bytes. \
             Missing data means the client sees a truncated response (ERR_CONNECTION_CLOSED)."
        );

        drop(client_io);
        let _ = handle.await;
    }

    /// Issue #3: write_frame (control) and writer task (data) share write_half
    /// mutex. The writer task's try_recv loop drains ALL pending data under one
    /// lock hold, blocking control frames. This test sends a HeartRequest while
    /// a stream is actively writing and verifies HeartResponse arrives promptly.
    #[tokio::test]
    async fn test_control_frame_not_starved_by_data_writes() {
        let (mut client_io, server_io) = duplex(2 * 1024 * 1024);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;
        write_frame(&mut client_io, Command::Syn, 1, &[]).await;

        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, CancellationToken::new())
                .await
        });

        let mut stream =
            tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
                .await
                .unwrap()
                .unwrap();

        // Stream writes 50 * 4KB = 200KB to keep writer task busy.
        let write_task = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let data = vec![0xAB_u8; 4096];
            for _ in 0..50 {
                if stream.write_all(&data).await.is_err() {
                    break;
                }
            }
        });

        // Let writer task start processing
        tokio::task::yield_now().await;

        // Send HeartRequest — response requires write_frame (same mutex)
        write_frame(&mut client_io, Command::HeartRequest, 0, &[]).await;

        // Read all frames, look for HeartResponse
        let mut hdr_buf = [0u8; HEADER_SIZE];
        let mut skip_buf = vec![0u8; 65536];

        let found_heart = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                client_io.read_exact(&mut hdr_buf).await.unwrap();
                let hdr = FrameHeader::decode(&hdr_buf);
                if hdr.length > 0 {
                    client_io
                        .read_exact(&mut skip_buf[..hdr.length as usize])
                        .await
                        .unwrap();
                }
                if hdr.command == Command::HeartResponse {
                    return true;
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(
            found_heart,
            "HeartResponse not received — control frame starved by data writer mutex"
        );

        write_task.abort();
        drop(client_io);
        let _ = handle.await;
    }

    /// When the writer task encounters a write error (e.g. network disruption),
    /// recv_loop must detect this and exit promptly. Otherwise the session stays
    /// "alive" on the read side while all streams can no longer send data back,
    /// causing clients to see ERR_CONNECTION_CLOSED on all concurrent requests.
    #[tokio::test]
    async fn test_recv_loop_exits_when_writer_task_dies() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::task::{Context, Poll};
        use tokio::io::ReadBuf;

        /// Wrapper that can independently fail writes while reads still work.
        struct FailableWriter {
            inner: tokio::io::DuplexStream,
            fail_writes: Arc<AtomicBool>,
        }

        impl AsyncRead for FailableWriter {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
            }
        }

        impl AsyncWrite for FailableWriter {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                let this = self.get_mut();
                if this.fail_writes.load(Ordering::Relaxed) {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "simulated write failure",
                    )));
                }
                std::pin::Pin::new(&mut this.inner).poll_write(cx, buf)
            }

            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                let this = self.get_mut();
                if this.fail_writes.load(Ordering::Relaxed) {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "simulated flush failure",
                    )));
                }
                std::pin::Pin::new(&mut this.inner).poll_flush(cx)
            }

            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
            }
        }

        let (mut client_io, server_io) = duplex(65536);
        let fail_writes = Arc::new(AtomicBool::new(false));
        let failable = FailableWriter {
            inner: server_io,
            fail_writes: fail_writes.clone(),
        };
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            failable,
            padding,
            SessionConfig::default(),
        ));
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;

        // Create a stream so writer task is active
        write_frame(&mut client_io, Command::Syn, 1, &[]).await;

        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, CancellationToken::new())
                .await
        });

        let mut stream =
            tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
                .await
                .unwrap()
                .unwrap();

        // Stream can write initially
        use tokio::io::AsyncWriteExt;
        stream.write_all(b"hello").await.unwrap();

        // Now fail all writes — simulates network disruption on write path
        fail_writes.store(true, Ordering::Relaxed);

        // Trigger writer task to encounter the error
        // (may need a few attempts since writer might not pick up immediately)
        for _ in 0..10 {
            let _ = stream.write_all(b"trigger failure").await;
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Keep client sending PSH data — this does NOT cause recv_loop to
        // write anything (it just dispatches to the stream channel).
        // This keeps recv_loop alive on the read side.
        let keepalive_task = tokio::spawn(async move {
            loop {
                write_frame(&mut client_io, Command::Psh, 1, b"keep alive").await;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        });

        // recv_loop should exit within 2 seconds after writer dies.
        // Currently it will hang because writer dies silently and
        // PSH handling doesn't require any writes.
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        keepalive_task.abort();

        assert!(
            result.is_ok(),
            "recv_loop did not exit after writer task died — \
             session stays half-alive, causing all streams to hang"
        );
    }

    /// When one stream's channel is full, recv_loop must NOT block all other
    /// streams.  This test fills stream 1's channel (capacity 128) without
    /// reading, then sends data to stream 2 and asserts it arrives promptly.
    #[tokio::test]
    async fn test_no_head_of_line_blocking() {
        let (mut client_io, server_io) = duplex(1024 * 1024);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;
        // Create two streams
        write_frame(&mut client_io, Command::Syn, 1, &[]).await;
        write_frame(&mut client_io, Command::Syn, 2, &[]).await;

        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, CancellationToken::new())
                .await
        });

        let _stream1 =
            tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
                .await
                .unwrap()
                .unwrap();
        let mut stream2 =
            tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
                .await
                .unwrap()
                .unwrap();

        // Fill stream 1's channel (capacity 128) — we intentionally never read from _stream1.
        for _ in 0..130 {
            write_frame(&mut client_io, Command::Psh, 1, b"x").await;
        }
        // Send data destined for stream 2.
        write_frame(&mut client_io, Command::Psh, 2, b"hello stream 2").await;

        // Stream 2 should receive data even though stream 1 is backed up.
        let mut buf = [0u8; 64];
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(1), stream2.read(&mut buf)).await;
        assert!(
            result.is_ok(),
            "stream 2 read timed out — head-of-line blocking detected"
        );
        let n = result.unwrap().unwrap();
        assert_eq!(&buf[..n], b"hello stream 2");

        drop(client_io);
        let _ = handle.await;
    }

    /// SessionConfig should have a write_buf_size field that defaults to 32KB.
    #[test]
    fn test_session_config_write_buf_size_default() {
        let config = SessionConfig::default();
        assert_eq!(config.write_buf_size, 32 * 1024);
    }

    /// SessionConfig should have a stream_channel_capacity field that defaults to 128.
    #[test]
    fn test_session_config_stream_channel_capacity_default() {
        let config = SessionConfig::default();
        assert_eq!(config.stream_channel_capacity, 128);
    }

    /// Session should use the configured stream_channel_capacity when creating streams.
    #[tokio::test]
    async fn test_session_uses_configured_stream_channel_capacity() {
        let (mut client_io, server_io) = duplex(65536);
        let padding = test_padding();
        let config = SessionConfig {
            stream_channel_capacity: 16,
            ..SessionConfig::default()
        };
        let session = Arc::new(Session::new_server(server_io, padding, config));
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;
        write_frame(&mut client_io, Command::Syn, 1, &[]).await;

        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, CancellationToken::new())
                .await
        });

        let _stream = tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
            .await
            .unwrap()
            .unwrap();

        // Fill the stream channel with capacity=16.
        // With capacity 16, sending 17 messages should trigger the "full" path.
        for i in 0..18 {
            let msg = format!("msg{}", i);
            write_frame(&mut client_io, Command::Psh, 1, msg.as_bytes()).await;
        }
        // Give recv_loop time to process
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        drop(client_io);
        let _ = handle.await;
    }

    /// RED test: Prove that the writer task's batched lock hold blocks control
    /// frames (handshake_success / HeartResponse) for longer than the client's
    /// 3-second SYN deadline, causing the client to kill the entire session.
    ///
    /// Scenario:
    /// 1. Multiple streams write large amounts of data → many WriteCommands queued
    /// 2. Writer task acquires write_half lock and processes the entire batch
    /// 3. Duplex buffer is small → writer blocks on write_all mid-batch
    /// 4. Meanwhile, a control frame (Nop = handshake_success) tries to acquire
    ///    the same lock → blocked for the entire batch duration
    /// 5. Client's 3-second SYN deadline expires → session killed →
    ///    ERR_CONNECTION_CLOSED
    ///
    /// The Go server doesn't have this problem because it acquires/releases the
    /// lock per-frame, not per-batch.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_write_frame_blocked_by_writer_batch() {
        // Small duplex buffer: writer task will block on write_all once
        // the buffer fills, holding the write_half lock.
        let (client_io, server_io) = duplex(32 * 1024);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());

        // Split client_io so we can write (send frames) and read (drain) independently
        let (client_read, mut client_write) = tokio::io::split(client_io);

        write_frame(
            &mut client_write,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;

        // Create 8 streams to simulate a page load
        for sid in 1..=8u32 {
            write_frame(&mut client_write, Command::Syn, sid, &[]).await;
        }

        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(16);
        let sess = session.clone();
        let _recv_handle = tokio::spawn(async move {
            let _ = sess
                .recv_loop(new_stream_tx, CancellationToken::new())
                .await;
        });

        // Collect all 8 streams
        let mut streams = Vec::new();
        for _ in 0..8 {
            let stream =
                tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
                    .await
                    .expect("timeout waiting for stream")
                    .expect("stream channel closed");
            streams.push(stream);
        }

        // Each stream writes 512KB of data through the writer channel.
        // Total: 8 * 512KB = 4MB queued, far more than the 32KB duplex buffer.
        let write_handles: Vec<_> = streams
            .into_iter()
            .map(|mut stream| {
                tokio::spawn(async move {
                    let data = vec![0xCD_u8; 64 * 1024]; // 64KB per write
                    for _ in 0..8 {
                        if stream.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                })
            })
            .collect();

        // Let the writer task start processing and fill the duplex buffer.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Slowly drain client side so the writer task makes *some* progress but
        // stays under pressure, holding the lock in its try_recv batch loop.
        let drain_handle = tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::new(client_read);
            let mut buf = vec![0u8; 4096]; // read slowly: 4KB at a time
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });

        // Now simulate handshake_success for a new (9th) stream.
        // This calls write_frame(Nop) which needs the write_half lock.
        // With the current batching, the writer task holds the lock for the
        // entire batch → this call is blocked.
        let session_for_nop = session.clone();
        let nop_task =
            tokio::spawn(async move { session_for_nop.write_frame(Command::SynAck, 9, &[]).await });

        // Client's SYN deadline is 3 seconds.
        // The Nop frame MUST arrive within this window.
        let nop_result = tokio::time::timeout(std::time::Duration::from_secs(3), nop_task).await;

        // Cleanup
        for h in write_handles {
            h.abort();
        }
        drain_handle.abort();
        drop(client_write);

        assert!(
            nop_result.is_ok(),
            "write_frame(Nop) blocked for > 3 seconds — writer task batch holds \
             write_half lock too long. Client would kill the session \
             (ERR_CONNECTION_CLOSED). The Go server doesn't have this problem \
             because it releases the lock after every frame."
        );
    }

    /// RED: write_frame should return an error (not block forever) when the
    /// underlying writer is stuck (e.g. TCP send buffer full on a dead connection).
    /// Currently write_frame has no internal write timeout, so it blocks
    /// indefinitely — causing HeartResponse/SynAck starvation and eventually
    /// "failed to create session: context deadline exceeded" on the client.
    #[tokio::test(start_paused = true)]
    async fn test_write_frame_returns_error_on_blocked_writer() {
        use std::pin::Pin;
        use std::task::{Context, Poll};
        use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

        /// AsyncWrite that never completes — simulates TCP send buffer full
        /// on a half-dead connection where the remote stopped reading.
        struct BlockingWrite;

        impl AsyncRead for BlockingWrite {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Pending
            }
        }

        impl AsyncWrite for BlockingWrite {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                Poll::Pending
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Pending
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Pending
            }
        }

        let session = Arc::new(Session::new_server(
            BlockingWrite,
            test_padding(),
            SessionConfig::default(),
        ));

        // If write_frame had an internal timeout, it would return Err(...)
        // before this 30s external timeout, making result = Ok(Err(...)).
        // Without internal timeout, write_frame blocks forever,
        // the external timeout fires → result = Err(Elapsed).
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            session.write_frame(Command::HeartResponse, 0, &[]),
        )
        .await;

        assert!(
            result.is_ok(),
            "write_frame blocked indefinitely on a stuck writer — no internal \
             write timeout. This causes HeartResponse/SynAck to never be sent, \
             and the client sees 'context deadline exceeded'."
        );
        // The returned Result should be an error (write timeout / broken pipe)
        assert!(
            result.unwrap().is_err(),
            "write_frame should return an error when the write is stuck"
        );
    }

    /// RED: When a stream's data channel is full, recv_loop removes it from the
    /// streams map — but does NOT send a FIN frame to the peer.  The peer
    /// continues sending data for this stream_id, which is silently dropped.
    /// The peer never learns the stream is dead until much later (if ever).
    ///
    /// Expected: recv_loop should send a FIN (or Alert) to the peer when it
    /// drops a stream due to channel full, so the peer can stop sending.
    #[tokio::test]
    async fn test_channel_full_sends_fin_to_peer() {
        let (mut client_io, server_io) = duplex(1024 * 1024);
        let padding = test_padding();
        // Use a very small stream channel capacity to easily trigger "full".
        let config = SessionConfig {
            stream_channel_capacity: 2,
            ..SessionConfig::default()
        };
        let session = Arc::new(Session::new_server(server_io, padding, config));
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;
        write_frame(&mut client_io, Command::Syn, 1, &[]).await;

        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, CancellationToken::new())
                .await
        });

        // Get stream but intentionally NEVER read from it.
        let _stream = tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
            .await
            .unwrap()
            .unwrap();

        // Send enough PSH frames to overflow the channel (capacity=2).
        // After 2 messages buffered, the 3rd+ should trigger try_send Full.
        for i in 0..10 {
            let msg = format!("overflow-{}", i);
            write_frame(&mut client_io, Command::Psh, 1, msg.as_bytes()).await;
        }

        // Give recv_loop time to process all frames and detect the full channel.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Now read frames from the client side and look for a FIN for stream 1.
        // The recv_loop should have sent FIN (or Alert) to notify the peer.
        // Also send a HeartRequest to force a response (proves the connection is alive).
        write_frame(&mut client_io, Command::HeartRequest, 0, &[]).await;

        let mut hdr_buf = [0u8; HEADER_SIZE];
        let mut fin_seen = false;
        let read_result = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if client_io.read_exact(&mut hdr_buf).await.is_err() {
                    break;
                }
                let hdr = FrameHeader::decode(&hdr_buf);
                if hdr.length > 0 {
                    let mut skip = vec![0u8; hdr.length as usize];
                    if client_io.read_exact(&mut skip).await.is_err() {
                        break;
                    }
                }
                if hdr.stream_id == 1 && hdr.command == Command::Fin {
                    fin_seen = true;
                    break;
                }
                // Stop after HeartResponse — we've seen all pending frames
                if hdr.command == Command::HeartResponse {
                    break;
                }
            }
        })
        .await;
        assert!(read_result.is_ok(), "timed out reading frames");
        assert!(
            fin_seen,
            "BUG: recv_loop dropped stream 1 due to channel full but did NOT send \
             FIN to peer. The peer will keep sending data that is silently dropped, \
             causing a zombie stream and data loss."
        );

        drop(client_io);
        let _ = handle.await;
    }

    /// RED: After recv_loop exits, spawned stream handlers may still hold
    /// Arc<Session>, preventing the underlying connection from being closed.
    /// This test verifies that Session refcount drops to 1 after recv_loop exits
    /// (only the caller's reference remains).
    #[tokio::test]
    async fn test_session_arc_released_after_recv_loop_exits() {
        let (mut client_io, server_io) = duplex(65536);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;
        // Create a stream so the session is actively used.
        write_frame(&mut client_io, Command::Syn, 1, &[]).await;
        write_frame(&mut client_io, Command::Psh, 1, b"some data").await;

        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
        let sess = session.clone(); // refcount +1
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, CancellationToken::new())
                .await
        });

        let _stream = tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
            .await
            .unwrap()
            .unwrap();

        // Close client → recv_loop should exit.
        drop(client_io);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;

        // After recv_loop exits, give the writer task time to notice channel closure.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Drop the stream (simulates stream handler finishing).
        drop(_stream);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Session should only be held by our local `session` variable now.
        let refcount = Arc::strong_count(&session);
        assert_eq!(
            refcount, 1,
            "Session Arc refcount is {} (expected 1). Something is still holding \
             a reference after recv_loop exited — this means the underlying \
             TLS/TCP connection stays open (zombie connection / FD leak).",
            refcount
        );
    }

    /// RED: Data sent to a stream AFTER its channel overflowed should be
    /// accounted for (not silently lost). Currently, once the stream is removed
    /// from the map, all subsequent PSH data for that stream_id is read from
    /// the wire but discarded without any tracking.
    #[tokio::test]
    async fn test_data_not_silently_lost_after_channel_full() {
        let (mut client_io, server_io) = duplex(1024 * 1024);
        let padding = test_padding();
        let config = SessionConfig {
            stream_channel_capacity: 2,
            ..SessionConfig::default()
        };
        let session = Arc::new(Session::new_server(server_io, padding, config));
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;
        write_frame(&mut client_io, Command::Syn, 1, &[]).await;
        // Also create stream 2 as a control — it should still work.
        write_frame(&mut client_io, Command::Syn, 2, &[]).await;

        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, CancellationToken::new())
                .await
        });

        let _stream1 =
            tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
                .await
                .unwrap()
                .unwrap();
        let mut stream2 =
            tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
                .await
                .unwrap()
                .unwrap();

        // Overflow stream 1's channel (never read from it).
        for _ in 0..10 {
            write_frame(&mut client_io, Command::Psh, 1, b"overflow").await;
        }

        // Give recv_loop time to process.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Now send to stream 2 — it should still work (no head-of-line blocking).
        write_frame(&mut client_io, Command::Psh, 2, b"still alive").await;

        let mut buf = [0u8; 64];
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(1), stream2.read(&mut buf)).await;
        assert!(result.is_ok(), "stream 2 blocked — head-of-line blocking!");
        let n = result.unwrap().unwrap();
        assert_eq!(
            &buf[..n],
            b"still alive",
            "stream 2 received wrong data after stream 1 overflow"
        );

        // KEY ASSERTION: After stream 1 overflowed, sending more data to it
        // should NOT crash/panic the recv_loop. The session should remain alive.
        write_frame(&mut client_io, Command::Psh, 1, b"after overflow").await;
        write_frame(&mut client_io, Command::Psh, 2, b"control").await;

        let result =
            tokio::time::timeout(std::time::Duration::from_secs(1), stream2.read(&mut buf)).await;
        assert!(
            result.is_ok(),
            "recv_loop crashed or hung after receiving data for an overflowed stream"
        );
        let n = result.unwrap().unwrap();
        assert_eq!(&buf[..n], b"control");

        drop(client_io);
        let _ = handle.await;
    }

    /// Session must stay alive indefinitely when idle — no idle timeout should
    /// kill it. This aligns with sing-anytls behavior where the server never
    /// actively closes connections; lifecycle is managed by the client and TCP
    /// keepalive.
    #[tokio::test]
    async fn test_session_stays_alive_when_idle() {
        let (mut client_io, server_io) = duplex(65536);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;

        let (new_stream_tx, _) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, CancellationToken::new())
                .await
        });

        // Wait 500ms with no activity — session must remain alive.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert!(
            !handle.is_finished(),
            "session terminated while idle — server must not actively close idle connections"
        );

        // Clean shutdown via connection close.
        drop(client_io);
        let _ = handle.await;
    }

    /// Session must NOT send HeartRequest frames. The server should be a passive
    /// pipe that never initiates keepalive — aligning with sing-anytls behavior.
    /// Only passive HeartResponse (replying to client HeartRequest) is allowed.
    #[tokio::test]
    async fn test_session_does_not_send_heartbeat() {
        let (mut client_io, server_io) = duplex(65536);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;

        let (new_stream_tx, _) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, CancellationToken::new())
                .await
        });

        // Wait 500ms — if server sends HeartRequest, we'll see it.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Try to read any frame from the server side. After Settings exchange,
        // the server may send ServerSettings/UpdatePaddingScheme but must NOT
        // send HeartRequest.
        let mut found_heart_request = false;
        loop {
            let mut hdr_buf = [0u8; HEADER_SIZE];
            match tokio::time::timeout(
                std::time::Duration::from_millis(100),
                client_io.read_exact(&mut hdr_buf),
            )
            .await
            {
                Ok(Ok(_)) => {
                    let hdr = FrameHeader::decode(&hdr_buf);
                    if hdr.length > 0 {
                        let mut skip = vec![0u8; hdr.length as usize];
                        client_io.read_exact(&mut skip).await.unwrap();
                    }
                    if hdr.command == Command::HeartRequest {
                        found_heart_request = true;
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(
            !found_heart_request,
            "server sent HeartRequest — server must not actively probe connections"
        );

        drop(client_io);
        let _ = handle.await;
    }

    /// Data frame writes must NOT have a hard timeout. When the network is
    /// congested, writes may take longer than 5s — the writer task should
    /// wait patiently instead of killing the session. This aligns with
    /// sing-anytls where writeDataFrame has no deadline.
    /// Control frame writes (write_frame) should still have a timeout.
    #[tokio::test]
    async fn test_data_write_no_timeout() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::task::{Context, Poll};
        use tokio::io::ReadBuf;

        /// Writer that delays writes by a configurable duration.
        struct SlowWriter {
            inner: tokio::io::DuplexStream,
            slow: Arc<AtomicBool>,
            wake_scheduled: Arc<AtomicBool>,
        }

        impl AsyncRead for SlowWriter {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
            }
        }

        impl AsyncWrite for SlowWriter {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                let this = self.get_mut();
                if this.slow.load(Ordering::Relaxed) {
                    // Return Pending to simulate a slow network. Schedule
                    // exactly one wake task to avoid spawning on every poll.
                    if !this.wake_scheduled.swap(true, Ordering::Relaxed) {
                        let waker = cx.waker().clone();
                        let slow = this.slow.clone();
                        tokio::spawn(async move {
                            // Wait 6 seconds — longer than WRITE_TIMEOUT (5s)
                            tokio::time::sleep(std::time::Duration::from_secs(6)).await;
                            slow.store(false, Ordering::Relaxed);
                            waker.wake();
                        });
                    }
                    return Poll::Pending;
                }
                std::pin::Pin::new(&mut this.inner).poll_write(cx, buf)
            }

            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
            }

            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
            }
        }

        let (mut client_io, server_io) = duplex(65536);
        let slow = Arc::new(AtomicBool::new(false));
        let slow_writer = SlowWriter {
            inner: server_io,
            slow: slow.clone(),
            wake_scheduled: Arc::new(AtomicBool::new(false)),
        };
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            slow_writer,
            padding,
            SessionConfig::default(),
        ));
        let settings_data = format!("v=2\npadding-md5={}", session.padding_md5());
        write_frame(
            &mut client_io,
            Command::Settings,
            0,
            settings_data.as_bytes(),
        )
        .await;
        write_frame(&mut client_io, Command::Syn, 1, &[]).await;

        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
        let sess = session.clone();
        let handle = tokio::spawn(async move {
            sess.recv_loop(new_stream_tx, CancellationToken::new())
                .await
        });

        let mut stream =
            tokio::time::timeout(std::time::Duration::from_secs(1), new_stream_rx.recv())
                .await
                .unwrap()
                .unwrap();

        // Make the writer slow BEFORE writing data
        slow.store(true, Ordering::Relaxed);

        // Write data through the stream — this goes through the writer task
        use tokio::io::AsyncWriteExt;
        stream.write_all(b"slow data").await.unwrap();

        // Drain the client side to receive the data (after the 6s delay)
        let mut buf = [0u8; 64];
        let drain = tokio::spawn(async move {
            let mut total = Vec::new();
            loop {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    client_io.read(&mut buf),
                )
                .await
                {
                    Ok(Ok(0)) | Err(_) => break,
                    Ok(Ok(n)) => total.extend_from_slice(&buf[..n]),
                    Ok(Err(_)) => break,
                }
            }
            total
        });

        // Session must still be alive after 6s (past the old 5s WRITE_TIMEOUT)
        tokio::time::sleep(std::time::Duration::from_secs(7)).await;
        assert!(
            !handle.is_finished(),
            "session died due to write timeout — data frame writes must not have a hard timeout"
        );

        drop(stream);
        let _ = handle.await;
        let _ = drain.await;
    }

    /// RED: The writer task's try_recv batch loop has no upper limit.
    /// When 200 commands are queued, all 200 are drained in a single batch
    /// before flush() is called. Under continuous load this means flush is
    /// indefinitely deferred and the loop spins at 100% CPU.
    #[tokio::test]
    async fn test_writer_batch_should_be_limited() {
        use crate::core::stream::WriteCommand;

        let (_client_io, server_io) = duplex(1024 * 1024);
        let (_, write_half) = tokio::io::split(server_io);
        let writer = Arc::new(Mutex::new(tokio::io::BufWriter::with_capacity(
            DEFAULT_WRITE_BUF_SIZE,
            write_half,
        )));
        let (tx, mut rx) = mpsc::channel::<WriteCommand>(512);

        // Fill channel with 200 commands.
        let num_commands = 200u32;
        for i in 0..num_commands {
            tx.try_send(WriteCommand {
                stream_id: i,
                data: bytes::Bytes::from_static(b"hello"),
                fin: false,
            })
            .unwrap();
        }

        // Simulate one iteration of the writer task's outer loop.
        let mut combined_buf = Vec::with_capacity(HEADER_SIZE + u16::MAX as usize);
        let cmd = rx.recv().await.unwrap();
        let mut w = writer.lock().await;
        write_cmd_frame(&mut *w, &cmd, &mut combined_buf)
            .await
            .unwrap();

        let mut batch_count = 1u32;
        let mut batch_remaining = MAX_BATCH_SIZE - 1;
        while batch_remaining > 0 {
            let Ok(cmd) = rx.try_recv() else {
                break;
            };
            drop(w);
            w = writer.lock().await;
            write_cmd_frame(&mut *w, &cmd, &mut combined_buf)
                .await
                .unwrap();
            batch_count += 1;
            batch_remaining -= 1;
        }
        w.flush().await.unwrap();
        drop(w);

        // RED: batch_count == 200 — all commands processed in one batch, no limit.
        // GREEN (after fix): batch_count <= MAX_BATCH_SIZE.
        assert!(
            batch_count <= 64,
            "writer batch should be limited to avoid CPU spinning, \
             but processed {batch_count} commands in a single batch"
        );
    }

    /// RED: write_frame's lock acquisition has no timeout. When the
    /// write_half lock is held externally (simulating a busy writer task),
    /// write_frame blocks indefinitely instead of returning WriteTimeout.
    #[tokio::test]
    async fn test_write_frame_lock_acquisition_has_timeout() {
        let (_, server_io) = duplex(8192);
        let padding = test_padding();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));

        // Hold the write_half lock to simulate a busy writer task.
        let _guard = session.write_half.lock().await;

        // write_frame should return WriteTimeout within WRITE_TIMEOUT,
        // NOT block indefinitely waiting for the lock.
        let deadline = WRITE_TIMEOUT + std::time::Duration::from_secs(2);
        let result = tokio::time::timeout(
            deadline,
            session.write_frame(Command::HeartResponse, 0, &[]),
        )
        .await;

        drop(_guard);

        // RED: result is Err(Elapsed) — the outer timeout fires because
        // write_frame blocked for > WRITE_TIMEOUT+2s on lock acquisition.
        // GREEN (after fix): result is Ok(Err(WriteTimeout)).
        assert!(
            result.is_ok(),
            "write_frame should return WriteTimeout within {WRITE_TIMEOUT:?}, \
             not block indefinitely on lock acquisition"
        );
    }

    /// RED: when the writer task is blocked inside `write_all` on a slow/dead
    /// peer (poll_write returning Pending forever), firing `cancel_token`
    /// must cause the writer task to exit and release its `write_half` Arc
    /// clone. Otherwise the underlying TcpStream is held alive — producing
    /// the CLOSE-WAIT leak observed in production (v0.1.36).
    ///
    /// This test wires a custom IO whose `poll_write` returns Pending
    /// forever and tracks Drop. We drive Settings + Syn so recv_loop creates
    /// a Stream, then write data on the Stream — the writer task picks up
    /// the WriteCommand and gets stuck inside write_all. Then we cancel and
    /// drop everything; the underlying IO must be dropped.
    #[tokio::test]
    async fn test_writer_task_releases_write_half_on_cancel_when_blocked() {
        use std::pin::Pin;
        use std::sync::atomic::{AtomicBool, Ordering as AOrdering};
        use std::task::{Context, Poll};
        use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
        use tokio::sync::Notify;

        struct StuckIo {
            read_data: Vec<u8>,
            read_pos: usize,
            dropped: Arc<AtomicBool>,
            write_observed: Arc<Notify>,
        }

        impl Drop for StuckIo {
            fn drop(&mut self) {
                self.dropped.store(true, AOrdering::SeqCst);
            }
        }

        impl AsyncRead for StuckIo {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                let remaining = self.read_data.len() - self.read_pos;
                if remaining == 0 {
                    return Poll::Pending;
                }
                let n = remaining.min(buf.remaining());
                let start = self.read_pos;
                buf.put_slice(&self.read_data[start..start + n]);
                self.read_pos += n;
                Poll::Ready(Ok(()))
            }
        }

        impl AsyncWrite for StuckIo {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                // Signal that the writer task has reached us — lets the test
                // proceed deterministically without timing-based sleeps.
                self.write_observed.notify_one();
                Poll::Pending
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Pending
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let write_observed = Arc::new(Notify::new());

        // Pre-load the read buffer with Settings (matching padding, v=1 to
        // skip write_settings_response) and a Syn so recv_loop emits a Stream.
        let padding = test_padding();
        let mut read_data = Vec::new();
        let settings_text = format!("v=1\npadding-md5={}", padding.md5_hex());
        let settings_hdr = FrameHeader {
            command: Command::Settings,
            stream_id: 0,
            length: settings_text.len() as u16,
        };
        let mut hdr = [0u8; HEADER_SIZE];
        settings_hdr.encode(&mut hdr);
        read_data.extend_from_slice(&hdr);
        read_data.extend_from_slice(settings_text.as_bytes());

        let syn_hdr = FrameHeader {
            command: Command::Syn,
            stream_id: 1,
            length: 0,
        };
        let mut hdr = [0u8; HEADER_SIZE];
        syn_hdr.encode(&mut hdr);
        read_data.extend_from_slice(&hdr);

        let io = StuckIo {
            read_data,
            read_pos: 0,
            dropped: dropped.clone(),
            write_observed: write_observed.clone(),
        };

        let session = Arc::new(Session::new_server(io, padding, SessionConfig::default()));

        let cancel = CancellationToken::new();
        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);

        let sess = session.clone();
        let cancel_clone = cancel.clone();
        let recv_handle =
            tokio::spawn(async move { sess.recv_loop(new_stream_tx, cancel_clone).await });

        // Pull the Stream produced by the Syn frame.
        let mut stream =
            tokio::time::timeout(std::time::Duration::from_secs(2), new_stream_rx.recv())
                .await
                .expect("timed out waiting for Stream from Syn")
                .expect("new_stream channel closed before Stream arrived");

        // Write data on the Stream. This pushes a WriteCommand into the
        // writer task's channel; the writer task picks it up and calls
        // write_all on StuckIo, which blocks on Pending forever.
        stream.write_all(b"data").await.unwrap();

        // Wait deterministically until the writer task has actually entered
        // the blocked write_all (StuckIo::poll_write was called).
        tokio::time::timeout(std::time::Duration::from_secs(2), write_observed.notified())
            .await
            .expect("writer task never reached poll_write — test setup is wrong");

        // Now fire the cancellation. The writer task must observe this and
        // release its write_half Arc clone, even though it is currently
        // blocked inside write_all.
        cancel.cancel();

        // Drop everything we hold so that the only remaining strong ref to
        // write_half (after the fix) is the writer task's clone.
        drop(stream);
        drop(new_stream_rx);
        drop(session);

        // recv_loop should exit promptly via its cancel branch.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), recv_handle).await;

        // Poll for the underlying IO to be dropped (writer task exits, drops
        // its write_half Arc clone, refcount → 0, BufWriter→WriteHalf→T drop).
        let drop_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !dropped.load(AOrdering::SeqCst) && std::time::Instant::now() < drop_deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        assert!(
            dropped.load(AOrdering::SeqCst),
            "underlying IO was not dropped after cancel — writer task is \
             stuck inside write_all and still holds a write_half Arc clone. \
             In production this keeps the inbound TcpStream alive in \
             CLOSE-WAIT until tcp_retries2 (~15min) or forever."
        );
    }
}
