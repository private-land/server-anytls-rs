use std::sync::Arc;

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;

use crate::core::hooks::{Authenticator, UserId};
use crate::core::padding::PaddingFactory;
use crate::core::server::Server;
use crate::core::session::Session;
use crate::core::stream::Stream;
use crate::error::{Error, Result};

/// Maximum allowed padding length in auth (cap at 1KB to prevent DoS).
const MAX_PADDING_LEN: u16 = 1024;

pub(crate) async fn read_auth<R: AsyncRead + Unpin>(
    reader: &mut R,
    authenticator: &dyn Authenticator,
) -> Result<Option<UserId>> {
    let mut hash = [0u8; 32];
    reader.read_exact(&mut hash).await?;

    let user_id = authenticator.authenticate(&hash);

    // If auth failed, return immediately — no need to read padding.
    if user_id.is_none() {
        return Ok(None);
    }

    let mut padding_len_buf = [0u8; 2];
    reader.read_exact(&mut padding_len_buf).await?;
    let padding_len = u16::from_be_bytes(padding_len_buf);

    if padding_len > MAX_PADDING_LEN {
        return Err(Error::InvalidFrame(format!(
            "auth padding too large: {} > {}",
            padding_len, MAX_PADDING_LEN
        )));
    }

    if padding_len > 0 {
        // Stack buffer — MAX_PADDING_LEN is 1024, fits comfortably on stack.
        // Avoids a heap allocation for data that is immediately discarded.
        let mut padding = [0u8; MAX_PADDING_LEN as usize];
        reader
            .read_exact(&mut padding[..padding_len as usize])
            .await?;
    }

    Ok(user_id)
}

pub(crate) async fn handle_connection(
    server: Arc<Server>,
    tcp_stream: TcpStream,
    peer_addr: SocketAddr,
) -> Result<()> {
    let tls_config = server
        .tls_config
        .clone()
        .ok_or_else(|| Error::Tls(rustls::Error::General("no TLS config".into())))?;

    let acceptor = TlsAcceptor::from(tls_config);

    // Wrap TLS handshake + auth read in a single timeout to prevent
    // slowloris-style attacks from holding semaphore permits indefinitely.
    let (buf_stream, user_id) = tokio::time::timeout(server.config.handshake_timeout, async {
        let tls_stream = acceptor.accept(tcp_stream).await?;
        let mut buf_stream = tokio::io::BufReader::new(tls_stream);
        let user_id = read_auth(&mut buf_stream, server.authenticator.as_ref()).await?;
        let user_id = match user_id {
            Some(uid) => uid,
            None => return Err(Error::AuthFailed),
        };
        Ok::<_, Error>((buf_stream, user_id))
    })
    .await
    .map_err(|_| Error::HandshakeTimeout)??;

    // Register connection after successful authentication
    let (conn_id, cancel_token) = server.connection_manager.register(user_id, peer_addr);
    tracing::info!(user_id, conn_id, peer = %peer_addr, "client connected");
    // Ensure unregister on exit (even on panic)
    let conn_mgr = server.connection_manager.clone();
    let _guard = scopeguard::guard(conn_id, move |id| {
        conn_mgr.unregister(id);
    });

    // Pass the BufReader directly — do NOT call into_inner() which would
    // discard any data already buffered (e.g. Settings frame arriving in the
    // same TLS record as auth).
    let padding: PaddingFactory = server.padding.clone();
    let session_config = server.session_config();
    let session = Arc::new(Session::new_server(buf_stream, padding, session_config));

    let (new_stream_tx, mut new_stream_rx) = mpsc::channel::<Stream>(256);

    // Bound concurrent stream handlers to the same limit as max_streams_per_session.
    let stream_sem = Arc::new(Semaphore::new(server.config.max_streams_per_session));

    let session_clone = session.clone();
    let server_clone = server.clone();
    let cancel_clone = cancel_token.clone();
    tokio::spawn(async move {
        while let Some(stream) = new_stream_rx.recv().await {
            let permit = stream_sem.clone().acquire_owned().await;
            let Ok(permit) = permit else { break };
            let srv = server_clone.clone();
            let sess = session_clone.clone();
            let cancel = cancel_clone.clone();
            tokio::spawn(async move {
                let _ = crate::outbound::handle_stream(srv, sess, stream, user_id, cancel).await;
                drop(permit);
            });
        }
    });

    session.recv_loop(new_stream_tx, cancel_token).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::hooks::SinglePasswordAuth;
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncWriteExt, duplex};

    fn make_auth_packet(password: &str, padding_len: u16) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        let mut packet = Vec::new();
        packet.extend_from_slice(&hash);
        packet.extend_from_slice(&padding_len.to_be_bytes());
        packet.extend(vec![0u8; padding_len as usize]);
        packet
    }

    #[tokio::test]
    async fn test_read_auth_success() {
        let packet = make_auth_packet("mypassword", 10);
        let (mut writer, reader) = duplex(4096);
        writer.write_all(&packet).await.unwrap();
        drop(writer);
        let mut reader = tokio::io::BufReader::new(reader);
        let auth = SinglePasswordAuth::new("mypassword");
        let result = read_auth(&mut reader, &auth).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_read_auth_wrong_password() {
        // Only send hash (32 bytes) — auth fails before reading padding.
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"wrongpassword");
        let hash = hasher.finalize();
        let (mut writer, reader) = duplex(4096);
        writer.write_all(&hash).await.unwrap();
        drop(writer);
        let mut reader = tokio::io::BufReader::new(reader);
        let auth = SinglePasswordAuth::new("mypassword");
        let result = read_auth(&mut reader, &auth).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_read_auth_padding_too_large() {
        // Padding length exceeds MAX_PADDING_LEN — should return error.
        let mut packet = Vec::new();
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"mypassword");
        packet.extend_from_slice(&hasher.finalize());
        // Set padding len to MAX_PADDING_LEN + 1
        packet.extend_from_slice(&(MAX_PADDING_LEN + 1).to_be_bytes());
        let (mut writer, reader) = duplex(4096);
        writer.write_all(&packet).await.unwrap();
        drop(writer);
        let mut reader = tokio::io::BufReader::new(reader);
        let auth = SinglePasswordAuth::new("mypassword");
        let result = read_auth(&mut reader, &auth).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_read_auth_timeout_on_stalled_reader() {
        use std::time::Duration;
        // A reader that never sends data should be caught by timeout
        let (_writer, reader) = tokio::io::duplex(4096);
        let mut reader = tokio::io::BufReader::new(reader);
        let auth = SinglePasswordAuth::new("mypassword");

        let result =
            tokio::time::timeout(Duration::from_millis(100), read_auth(&mut reader, &auth)).await;

        // Outer Result is Err(Elapsed) = timeout fired
        assert!(result.is_err(), "expected timeout on stalled reader");
    }

    /// When auth + Settings arrive in the same TLS record, the BufReader
    /// buffers both.  The fix: keep reading through the BufReader (don't
    /// call into_inner()).  This test verifies the data survives.
    #[tokio::test]
    async fn test_bufreader_preserves_buffered_data() {
        use crate::core::frame::{Command, FrameHeader, HEADER_SIZE};

        let password = "mypassword";
        let padding_len: u16 = 4;

        let auth_packet = make_auth_packet(password, padding_len);

        let settings_header = FrameHeader {
            command: Command::Settings,
            stream_id: 0,
            length: 0,
        };
        let mut settings_bytes = [0u8; HEADER_SIZE];
        settings_header.encode(&mut settings_bytes);

        // Combine auth + Settings into one contiguous write.
        let mut combined = Vec::with_capacity(auth_packet.len() + HEADER_SIZE);
        combined.extend_from_slice(&auth_packet);
        combined.extend_from_slice(&settings_bytes);

        let (mut writer, reader) = duplex(4096);
        writer.write_all(&combined).await.unwrap();
        drop(writer);

        // 1. Wrap in BufReader and read auth.
        let mut buf_reader = tokio::io::BufReader::new(reader);
        let auth = SinglePasswordAuth::new(password);
        let user_id = read_auth(&mut buf_reader, &auth).await.unwrap();
        assert!(user_id.is_some(), "auth should succeed");

        // 2. Keep reading through BufReader (the fix — no into_inner).
        let mut frame_buf = [0u8; HEADER_SIZE];
        let n = buf_reader.read_exact(&mut frame_buf).await;

        assert!(
            n.is_ok(),
            "Settings frame should be readable through BufReader"
        );

        let decoded = FrameHeader::decode(&frame_buf);
        assert_eq!(
            decoded.command,
            Command::Settings,
            "first frame after auth should be Settings"
        );
    }

    #[tokio::test]
    async fn test_read_auth_zero_padding() {
        let packet = make_auth_packet("mypassword", 0);
        let (mut writer, reader) = duplex(4096);
        writer.write_all(&packet).await.unwrap();
        drop(writer);
        let mut reader = tokio::io::BufReader::new(reader);
        let auth = SinglePasswordAuth::new("mypassword");
        let result = read_auth(&mut reader, &auth).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }
}
