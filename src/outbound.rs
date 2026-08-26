use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::warn;

use crate::core::hooks::{Address, OutboundType, UserId};
use crate::core::server::Server;
use crate::core::session::Session;
use crate::core::stream::Stream;
use crate::error::{Error, Result};

/// Buffer size for each direction of `copy_bidirectional` relay.
const RELAY_BUF_SIZE: usize = 32 * 1024;

/// Parse a SOCKS5-style address from the given byte slice.
/// Returns `(Address, bytes_consumed)` on success.
pub(crate) fn parse_socks_address(data: &[u8]) -> Result<(Address, usize)> {
    if data.is_empty() {
        return Err(Error::InvalidFrame("address type byte missing".into()));
    }
    match data[0] {
        0x01 => {
            // IPv4: 1 + 4 + 2 = 7 bytes
            if data.len() < 7 {
                return Err(Error::InvalidFrame("truncated IPv4 address".into()));
            }
            let ip: [u8; 4] = data[1..5].try_into().unwrap();
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((Address::IPv4(ip, port), 7))
        }
        0x03 => {
            // Domain: type(1) + len(1) + N + port(2); consumed = total
            if data.len() < 2 {
                return Err(Error::InvalidFrame("truncated domain length".into()));
            }
            let name_len = data[1] as usize;
            let total = 1 + 1 + name_len + 2;
            if data.len() < total {
                return Err(Error::InvalidFrame("truncated domain address".into()));
            }
            let domain = std::str::from_utf8(&data[2..2 + name_len])
                .map_err(|_| Error::InvalidFrame("domain is not valid UTF-8".into()))?
                .to_string();
            let port = u16::from_be_bytes([data[2 + name_len], data[2 + name_len + 1]]);
            // consumed = type(1) + len_byte(1) + name(N) + port(2)
            Ok((Address::Domain(domain, port), total))
        }
        0x04 => {
            // IPv6: 1 + 16 + 2 = 19 bytes
            if data.len() < 19 {
                return Err(Error::InvalidFrame("truncated IPv6 address".into()));
            }
            let ip: [u8; 16] = data[1..17].try_into().unwrap();
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((Address::IPv6(ip, port), 19))
        }
        t => Err(Error::InvalidFrame(format!(
            "unknown address type: 0x{:02x}",
            t
        ))),
    }
}

/// Returns true when the address is a UDP-over-TCP pseudo-domain.
pub(crate) fn is_udp_over_tcp(addr: &Address) -> bool {
    match addr {
        Address::Domain(domain, _) => domain.contains("udp-over-tcp.arpa"),
        _ => false,
    }
}

/// Wrapper that counts bytes written through an `AsyncWrite`.
struct CountedWrite<W> {
    inner: W,
    bytes_written: Arc<AtomicU64>,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CountedWrite<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            this.bytes_written.fetch_add(*n as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<W: AsyncRead + Unpin> AsyncRead for CountedWrite<W> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

/// Main entry point called by the session handler for each new stream.
pub(crate) async fn handle_stream<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    server: Arc<Server>,
    session: Arc<Session<T>>,
    mut stream: Stream,
    user_id: UserId,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    // Read the first chunk from the stream to get the SOCKS5 destination address.
    let mut buf = vec![0u8; 512];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Err(Error::StreamClosed);
    }

    let (target, consumed) = parse_socks_address(&buf[..n])?;

    // Count each stream as one request (connection is multiplexed)
    server.stats.record_request(user_id);

    if is_udp_over_tcp(&target) {
        let trailing = buf[consumed..n].to_vec();
        return crate::udp_relay::handle_udp_over_tcp(
            server, session, stream, trailing, user_id, cancel,
        )
        .await;
    }

    let trailing = buf[consumed..n].to_vec();
    let outbound = server.router.route(&target).await;
    match outbound {
        OutboundType::Direct {
            resolved,
            dialer: None,
        } => {
            proxy_tcp(
                server, session, stream, &target, trailing, user_id, resolved, cancel,
            )
            .await
        }
        OutboundType::Direct {
            resolved,
            dialer: Some(handler),
        } => {
            // Custom-dial direct: dial through the handler so its bind/mode/TCP
            // options apply. Feed it the router's already-SSRF-checked IPs so it
            // binds without re-resolving (a fresh lookup could reach an
            // unchecked, private IP).
            let mut acl_addr =
                acl_engine_rs::outbound::Addr::new(target.host_string(), target.port());
            if let Some(addrs) = resolved.as_deref() {
                acl_addr = acl_addr.with_resolve_info(resolve_info_from_addrs(addrs));
            }
            proxy_tcp_via_handler(
                server, session, stream, &target, acl_addr, trailing, user_id, handler, cancel,
            )
            .await
        }
        OutboundType::Proxy(handler) => {
            let acl_addr = acl_engine_rs::outbound::Addr::new(target.host_string(), target.port());
            proxy_tcp_via_handler(
                server, session, stream, &target, acl_addr, trailing, user_id, handler, cancel,
            )
            .await
        }
        OutboundType::Reject => {
            warn!("rejecting connection to {}", target);
            let stream_id = stream.id();
            session.handshake_failure(stream_id, "rejected").await?;
            Ok(())
        }
    }
}

/// Connect directly to `target` and relay data.
#[allow(clippy::too_many_arguments)]
async fn proxy_tcp<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    server: Arc<Server>,
    session: Arc<Session<T>>,
    stream: Stream,
    target: &Address,
    trailing: Vec<u8>,
    user_id: UserId,
    resolved: Option<Arc<[std::net::SocketAddr]>>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let stream_id = stream.id();

    let connect_result = tokio::time::timeout(
        server.config.tcp_connect_timeout,
        connect_target(target, resolved),
    )
    .await;

    let remote = match connect_result {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(e)) => {
            warn!("failed to connect to {}: {}", target, e);
            session.handshake_failure(stream_id, &e.to_string()).await?;
            return Err(Error::Io(e));
        }
        Err(_elapsed) => {
            warn!("connect timeout to {}", target);
            session
                .handshake_failure(stream_id, "connect timeout")
                .await?;
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect timeout",
            )));
        }
    };

    session.handshake_success(stream_id).await?;
    relay_and_record(server, stream, remote, trailing, user_id, cancel).await
}

/// Collapse resolved socket addresses into a `ResolveInfo` (one IPv4 + one
/// IPv6) that a custom-dial `Direct` handler consumes instead of re-resolving.
/// All addresses have already passed the router's private-IP (SSRF) check.
fn resolve_info_from_addrs(addrs: &[SocketAddr]) -> acl_engine_rs::outbound::ResolveInfo {
    let mut info = acl_engine_rs::outbound::ResolveInfo::new();
    for addr in addrs {
        match addr.ip() {
            std::net::IpAddr::V4(v4) if info.ipv4.is_none() => info.ipv4 = Some(v4),
            std::net::IpAddr::V6(v6) if info.ipv6.is_none() => info.ipv6 = Some(v6),
            _ => {}
        }
    }
    info
}

/// Connect via an ACL outbound handler (Socks5, Http, or a custom-dial Direct)
/// using the pre-built `acl_addr`, then relay data.
#[allow(clippy::too_many_arguments)]
async fn proxy_tcp_via_handler<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    server: Arc<Server>,
    session: Arc<Session<T>>,
    stream: Stream,
    target: &Address,
    mut acl_addr: acl_engine_rs::outbound::Addr,
    trailing: Vec<u8>,
    user_id: UserId,
    handler: Arc<dyn acl_engine_rs::outbound::AsyncOutbound>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let stream_id = stream.id();

    let connect_result = tokio::time::timeout(
        server.config.tcp_connect_timeout,
        handler.dial_tcp(&mut acl_addr),
    )
    .await;

    let remote = match connect_result {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => {
            warn!("proxy connect to {} failed: {}", target, e);
            session.handshake_failure(stream_id, &e.to_string()).await?;
            return Err(Error::Io(std::io::Error::other(e.to_string())));
        }
        Err(_elapsed) => {
            warn!("proxy connect timeout to {}", target);
            session
                .handshake_failure(stream_id, "connect timeout")
                .await?;
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "proxy connect timeout",
            )));
        }
    };

    session.handshake_success(stream_id).await?;
    relay_and_record(server, stream, remote, trailing, user_id, cancel).await
}

/// Bidirectional relay between client stream and remote, with byte counting and
/// traffic stats recording. Handles trailing data forwarding and FIN signaling.
async fn relay_and_record<R>(
    server: Arc<Server>,
    stream: Stream,
    mut remote: R,
    trailing: Vec<u8>,
    user_id: UserId,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    // Forward any application data that was read alongside the SOCKS address.
    let trailing_len = trailing.len() as u64;
    if !trailing.is_empty() {
        remote.write_all(&trailing).await?;
    }

    // Wrap remote with byte counters so traffic is tracked even if the relay errors.
    // upload = bytes written to remote (client → remote)
    // download = bytes written to stream (remote → client)
    let upload_bytes = Arc::new(AtomicU64::new(0));
    let download_bytes = Arc::new(AtomicU64::new(0));

    let mut counted_remote = CountedWrite {
        inner: remote,
        bytes_written: upload_bytes.clone(),
    };
    let mut counted_stream = CountedWrite {
        inner: stream,
        bytes_written: download_bytes.clone(),
    };

    let idle_timeout = server.config.relay_idle_timeout;

    let idle_watchdog = async {
        let check_interval = std::cmp::max(idle_timeout / 10, Duration::from_secs(1));
        let mut prev_up = upload_bytes.load(Ordering::Relaxed);
        let mut prev_down = download_bytes.load(Ordering::Relaxed);
        let mut idle_since = tokio::time::Instant::now();

        loop {
            tokio::time::sleep(check_interval).await;
            let cur_up = upload_bytes.load(Ordering::Relaxed);
            let cur_down = download_bytes.load(Ordering::Relaxed);
            if cur_up != prev_up || cur_down != prev_down {
                prev_up = cur_up;
                prev_down = cur_down;
                idle_since = tokio::time::Instant::now();
            } else if idle_since.elapsed() >= idle_timeout {
                tracing::debug!("relay idle for {:?}, terminating session", idle_timeout);
                cancel.cancel();
                return;
            }
        }
    };

    let relay = tokio::io::copy_bidirectional_with_sizes(
        &mut counted_stream,
        &mut counted_remote,
        RELAY_BUF_SIZE,
        RELAY_BUF_SIZE,
    );

    tokio::select! {
        _ = relay => {}
        _ = idle_watchdog => {}
        _ = cancel.cancelled() => {}
    }

    // Drop the remote TCP socket immediately to free the FD.
    // Without this, the socket lingers until after send_fin(),
    // which may block on channel backpressure.
    drop(counted_remote);

    let up = upload_bytes.load(Ordering::Relaxed) + trailing_len;
    let down = download_bytes.load(Ordering::Relaxed);
    if up > 0 || down > 0 {
        server.stats.record_upload(user_id, up);
        server.stats.record_download(user_id, down);
    }

    // Send FIN through the writer task channel (not directly via write_half)
    // to guarantee it arrives after all queued PSH data for this stream.
    counted_stream.inner.send_fin().await?;

    Ok(())
}

/// Resolve and connect to the target address.
/// When `resolved` is provided (from the router's DNS lookup), uses those addresses
/// directly instead of resolving the domain again — avoids duplicate DNS lookups.
async fn connect_target(
    target: &Address,
    resolved: Option<Arc<[SocketAddr]>>,
) -> std::io::Result<TcpStream> {
    // If the router already resolved the domain, connect using those addresses directly.
    if let Some(ref addrs) = resolved
        && !addrs.is_empty()
    {
        let port = target.port();
        let mut last_err = None;
        for addr in addrs.iter() {
            let mut addr = *addr;
            addr.set_port(port);
            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    crate::core::server::set_tcp_keepalive(&stream);
                    return Ok(stream);
                }
                Err(e) => last_err = Some(e),
            }
        }
        return Err(last_err.unwrap_or_else(|| std::io::Error::other("no resolved addresses")));
    }

    let stream = match target {
        Address::IPv4(ip, port) => {
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(*ip), *port));
            TcpStream::connect(addr).await?
        }
        Address::IPv6(ip, port) => {
            let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(*ip), *port, 0, 0));
            TcpStream::connect(addr).await?
        }
        Address::Domain(host, port) => TcpStream::connect((host.as_str(), *port)).await?,
    };
    let _ = stream.set_nodelay(true);
    crate::core::server::set_tcp_keepalive(&stream);
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::hooks::Address;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn test_parse_socks_addr_ipv4() {
        let data = &[0x01, 127, 0, 0, 1, 0x00, 0x50];
        let (addr, consumed) = parse_socks_address(data).unwrap();
        assert!(matches!(addr, Address::IPv4([127, 0, 0, 1], 80)));
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_parse_socks_addr_ipv6() {
        let mut data = vec![0x04];
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&[0x01, 0xBB]);
        let (addr, consumed) = parse_socks_address(&data).unwrap();
        assert!(matches!(addr, Address::IPv6(_, 443)));
        assert_eq!(consumed, 19);
    }

    #[test]
    fn test_parse_socks_addr_domain() {
        let mut data = vec![0x03];
        data.push(11);
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&[0x00, 0x50]);
        let (addr, consumed) = parse_socks_address(&data).unwrap();
        if let Address::Domain(domain, port) = addr {
            assert_eq!(domain, "example.com");
            assert_eq!(port, 80);
        } else {
            panic!("expected Domain address");
        }
        assert_eq!(consumed, 15);
    }

    #[test]
    fn test_parse_socks_addr_invalid_type() {
        let data = &[0xFF, 0, 0, 0, 0, 0, 0];
        let result = parse_socks_address(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_udp_over_tcp() {
        let addr = Address::Domain("sp.v2.udp-over-tcp.arpa".to_string(), 443);
        assert!(is_udp_over_tcp(&addr));
        let addr = Address::Domain("example.com".to_string(), 80);
        assert!(!is_udp_over_tcp(&addr));
        let addr = Address::IPv4([1, 2, 3, 4], 80);
        assert!(!is_udp_over_tcp(&addr));
    }

    use crate::core::hooks::{DirectRouter, SinglePasswordAuth, StatsCollector, UserId};
    use crate::core::padding::{DEFAULT_SCHEME, PaddingFactory};
    use crate::core::server::Server;
    use crate::core::session::{Session, SessionConfig};
    use crate::core::stream::{Stream, WriteCommand};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct RecordingStats {
        upload: AtomicU64,
        download: AtomicU64,
        request_count: AtomicU64,
    }

    impl RecordingStats {
        fn new() -> Self {
            Self {
                upload: AtomicU64::new(0),
                download: AtomicU64::new(0),
                request_count: AtomicU64::new(0),
            }
        }
    }

    impl StatsCollector for RecordingStats {
        fn record_upload(&self, _uid: UserId, bytes: u64) {
            self.upload.fetch_add(bytes, Ordering::Relaxed);
        }
        fn record_download(&self, _uid: UserId, bytes: u64) {
            self.download.fetch_add(bytes, Ordering::Relaxed);
        }
        fn record_request(&self, _uid: UserId) {
            self.request_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// When `copy_bidirectional` errors mid-relay (e.g. connection reset),
    /// partial traffic should still be recorded.
    #[tokio::test]
    async fn test_handle_stream_records_traffic_on_relay_error() {
        // TCP server that reads some data, sends some back, then RSTs
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let std_stream = stream.into_std().unwrap();
                // Read whatever is available
                use std::io::Read;
                let mut s = std_stream;
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                // Write some data back
                use std::io::Write;
                let _ = s.write_all(b"response-data-here");
                // RST the connection: linger(0) + drop sends TCP RST
                let sock = socket2::Socket::from(s);
                let _ = sock.set_linger(Some(std::time::Duration::from_secs(0)));
                drop(sock);
            }
        });

        let recording = Arc::new(RecordingStats::new());

        let server = Arc::new(
            Server::builder()
                .authenticator(Arc::new(SinglePasswordAuth::new("test")))
                .stats(recording.clone() as Arc<dyn StatsCollector>)
                .router(Arc::new(DirectRouter))
                .build()
                .unwrap(),
        );

        let (_client_io, server_io) = tokio::io::duplex(65536);
        let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));

        let (write_cmd_tx, mut write_cmd_rx) = tokio::sync::mpsc::channel::<WriteCommand>(256);
        tokio::spawn(async move { while write_cmd_rx.recv().await.is_some() {} });
        let (data_tx, stream) = Stream::new(1, write_cmd_tx, 128);

        // SOCKS5 IPv4 address pointing to our RST server + trailing payload
        let ip = match echo_addr {
            std::net::SocketAddr::V4(v4) => v4.ip().octets(),
            _ => panic!("expected v4"),
        };
        let port = echo_addr.port();
        let mut addr_and_payload = vec![0x01];
        addr_and_payload.extend_from_slice(&ip);
        addr_and_payload.extend_from_slice(&port.to_be_bytes());
        // Append trailing payload that counts as upload
        addr_and_payload.extend_from_slice(b"trailing-upload-data");
        data_tx
            .send(bytes::Bytes::from(addr_and_payload))
            .await
            .unwrap();

        // Send more data then close
        data_tx
            .send(bytes::Bytes::from_static(b"more-upload-data"))
            .await
            .unwrap();
        // Small delay to let data flow before closing
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(data_tx);

        let _ = handle_stream(server, session, stream, 42, CancellationToken::new()).await;

        let up = recording.upload.load(Ordering::Relaxed);
        let down = recording.download.load(Ordering::Relaxed);
        // Even though the relay errored, traffic should be recorded
        assert!(
            up > 0 || down > 0,
            "expected some traffic to be recorded on relay error, got upload={up} download={down}"
        );
        assert_eq!(recording.request_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_handle_stream_records_traffic_stats() {
        // Echo server
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = echo.accept().await {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            }
        });

        let recording = Arc::new(RecordingStats::new());

        let server = Arc::new(
            Server::builder()
                .authenticator(Arc::new(SinglePasswordAuth::new("test")))
                .stats(recording.clone() as Arc<dyn StatsCollector>)
                .router(Arc::new(DirectRouter))
                .build()
                .unwrap(),
        );

        // Session over duplex
        let (_client_io, server_io) = tokio::io::duplex(65536);
        let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));

        // Drain write commands from the session writer
        let (write_cmd_tx, mut write_cmd_rx) = tokio::sync::mpsc::channel::<WriteCommand>(256);
        tokio::spawn(async move { while write_cmd_rx.recv().await.is_some() {} });
        let (data_tx, stream) = Stream::new(1, write_cmd_tx, 128);

        // SOCKS5 IPv4 address pointing to echo server (no trailing data)
        let ip = match echo_addr {
            std::net::SocketAddr::V4(v4) => v4.ip().octets(),
            _ => panic!("expected v4"),
        };
        let port = echo_addr.port();
        let mut addr_data = vec![0x01];
        addr_data.extend_from_slice(&ip);
        addr_data.extend_from_slice(&port.to_be_bytes());
        data_tx.send(bytes::Bytes::from(addr_data)).await.unwrap();

        // Payload that goes through copy_bidirectional
        let payload = b"hello world test data";
        data_tx
            .send(bytes::Bytes::from_static(payload))
            .await
            .unwrap();
        drop(data_tx); // EOF → copy_bidirectional finishes

        let _ = handle_stream(server, session, stream, 42, CancellationToken::new()).await;

        let up = recording.upload.load(Ordering::Relaxed);
        let down = recording.download.load(Ordering::Relaxed);
        assert!(up > 0, "expected upload bytes to be recorded, got 0");
        assert!(down > 0, "expected download bytes to be recorded, got 0");
        assert_eq!(recording.request_count.load(Ordering::Relaxed), 1);
    }

    /// TCP relay must terminate promptly when cancel token fires.
    /// Without `cancel.cancelled()` in the relay select!, zombie relays
    /// accumulate for up to 60s (idle timeout), exhausting CPU/FDs under load.
    #[tokio::test]
    async fn test_tcp_relay_responds_to_cancellation() {
        // TCP server that keeps the connection alive indefinitely (never closes).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            }
        });

        let server = Arc::new(
            Server::builder()
                .authenticator(Arc::new(SinglePasswordAuth::new("test")))
                .router(Arc::new(DirectRouter))
                // Long idle timeout — relay must NOT wait for this.
                .relay_idle_timeout(std::time::Duration::from_secs(300))
                .build()
                .unwrap(),
        );

        let (_client_io, server_io) = tokio::io::duplex(65536);
        let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));

        let (write_cmd_tx, mut write_cmd_rx) = tokio::sync::mpsc::channel::<WriteCommand>(256);
        tokio::spawn(async move { while write_cmd_rx.recv().await.is_some() {} });
        let (data_tx, stream) = Stream::new(1, write_cmd_tx, 128);

        // SOCKS5 IPv4 address pointing to echo server
        let ip = match echo_addr {
            std::net::SocketAddr::V4(v4) => v4.ip().octets(),
            _ => panic!("expected v4"),
        };
        let port = echo_addr.port();
        let mut addr_data = vec![0x01];
        addr_data.extend_from_slice(&ip);
        addr_data.extend_from_slice(&port.to_be_bytes());
        data_tx.send(bytes::Bytes::from(addr_data)).await.unwrap();

        // Send some data so the relay starts, then keep channel open (no EOF).
        data_tx
            .send(bytes::Bytes::from_static(b"hello"))
            .await
            .unwrap();

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        // Cancel after 200ms
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            cancel_clone.cancel();
        });

        // Keep client sending data so the relay stays active (not idle).
        let data_tx_clone = data_tx.clone();
        tokio::spawn(async move {
            loop {
                if data_tx_clone
                    .send(bytes::Bytes::from_static(b"ping"))
                    .await
                    .is_err()
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        });

        // The relay should stop within 200ms + margin (cancel token).
        // Without the fix, it would hang for 300s (idle timeout).
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            handle_stream(server, session, stream, 42, cancel),
        )
        .await;

        assert!(
            result.is_ok(),
            "TCP relay should have stopped when cancel token fired, \
             but it hung — missing cancel.cancelled() in select!"
        );
    }

    /// RED: RELAY_BUF_SIZE is 256KB, which causes excessive memory usage
    /// under high concurrency (256 streams × 256KB × 2 = 128MB per session).
    /// Should be <= 64KB for reasonable memory footprint.
    #[test]
    fn test_relay_buf_size_reasonable() {
        assert!(
            RELAY_BUF_SIZE <= 64 * 1024,
            "RELAY_BUF_SIZE should be <= 64KB for reasonable memory usage \
             under high concurrency, but is {} KB",
            RELAY_BUF_SIZE / 1024
        );
    }

    // -----------------------------------------------------------------
    // Custom-dial direct: the TCP session path must dial through the
    // handler's dialer (applying its bind/mode/TCP options) instead of
    // the bare connect_target(), feeding it the router's already-checked
    // IPs via ResolveInfo so it binds without re-resolving.
    // -----------------------------------------------------------------

    use crate::core::hooks::OutboundRouter;
    use std::sync::Mutex;

    /// `(host, port, resolve_info.ipv4)` captured by the mock dialer.
    type DialRecord = (String, u16, Option<std::net::Ipv4Addr>);

    /// Records the `Addr` handed to `dial_tcp`, then fails the dial. The
    /// recorded value proves whether the consumer routed through the dialer.
    struct RecordingDialer {
        seen: Arc<Mutex<Option<DialRecord>>>,
    }

    #[async_trait::async_trait]
    impl acl_engine_rs::outbound::AsyncOutbound for RecordingDialer {
        async fn dial_tcp(
            &self,
            addr: &mut acl_engine_rs::outbound::Addr,
        ) -> acl_engine_rs::Result<Box<dyn acl_engine_rs::outbound::AsyncTcpConn>> {
            let v4 = addr.resolve_info().and_then(|ri| ri.ipv4);
            *self.seen.lock().unwrap() = Some((addr.host().to_string(), addr.port(), v4));
            Err(std::io::Error::other("mock dialer refuses").into())
        }

        async fn dial_udp(
            &self,
            _addr: &mut acl_engine_rs::outbound::Addr,
        ) -> acl_engine_rs::Result<Box<dyn acl_engine_rs::outbound::AsyncUdpConn>> {
            Err(std::io::Error::other("unused").into())
        }
    }

    /// Router that always returns a custom-dial Direct decision carrying the
    /// given dialer and pre-resolved IPs.
    struct DialerRouter {
        dialer: Arc<dyn acl_engine_rs::outbound::AsyncOutbound>,
        resolved: Option<Arc<[std::net::SocketAddr]>>,
    }

    #[async_trait::async_trait]
    impl OutboundRouter for DialerRouter {
        async fn route(&self, _target: &Address) -> OutboundType {
            OutboundType::Direct {
                resolved: self.resolved.clone(),
                dialer: Some(self.dialer.clone()),
            }
        }
    }

    #[tokio::test]
    async fn test_custom_dial_direct_routes_through_dialer() {
        use crate::core::hooks::SinglePasswordAuth;
        use crate::core::padding::{DEFAULT_SCHEME, PaddingFactory};
        use crate::core::session::{Session, SessionConfig};
        use crate::core::stream::{Stream, WriteCommand};

        let seen = Arc::new(Mutex::new(None));
        let dialer = Arc::new(RecordingDialer { seen: seen.clone() });
        // Router feeds a checked IPv4 (1.2.3.4, port 0 as produced by the DNS
        // cache) alongside the dialer.
        let resolved: Arc<[std::net::SocketAddr]> =
            Arc::from(vec![std::net::SocketAddr::from(([1, 2, 3, 4], 0))].into_boxed_slice());
        let router = Arc::new(DialerRouter {
            dialer: dialer as Arc<dyn acl_engine_rs::outbound::AsyncOutbound>,
            resolved: Some(resolved),
        });

        let server = Arc::new(
            Server::builder()
                .authenticator(Arc::new(SinglePasswordAuth::new("test")))
                .router(router)
                .build()
                .unwrap(),
        );

        let (_client_io, server_io) = tokio::io::duplex(65536);
        let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
        let session = Arc::new(Session::new_server(
            server_io,
            padding,
            SessionConfig::default(),
        ));

        let (write_cmd_tx, mut write_cmd_rx) = tokio::sync::mpsc::channel::<WriteCommand>(256);
        tokio::spawn(async move { while write_cmd_rx.recv().await.is_some() {} });
        let (data_tx, stream) = Stream::new(1, write_cmd_tx, 128);

        // SOCKS5 domain address example.com:443
        let mut addr_data = vec![0x03u8, 11];
        addr_data.extend_from_slice(b"example.com");
        addr_data.extend_from_slice(&443u16.to_be_bytes());
        data_tx.send(bytes::Bytes::from(addr_data)).await.unwrap();
        drop(data_tx);

        // Dial fails (mock), so handle_stream returns Err — that's expected.
        let _ = handle_stream(server, session, stream, 7, CancellationToken::new()).await;

        let rec = seen.lock().unwrap().clone();
        let (host, port, v4) = rec.expect(
            "custom-dial direct must be dialed through the handler's dialer, \
             but the dialer was never invoked (consumer used connect_target)",
        );
        assert_eq!(host, "example.com", "dialer must receive the original host");
        assert_eq!(port, 443, "dialer must receive the original port");
        assert_eq!(
            v4,
            Some(std::net::Ipv4Addr::new(1, 2, 3, 4)),
            "router's SSRF-checked IP must be fed to the dialer via ResolveInfo"
        );
    }
}
