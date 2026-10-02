use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::core::hooks::{Address, OutboundType, UserId};
use crate::core::server::Server;
use crate::core::session::Session;
use crate::core::stream::Stream;
use crate::error::{Error, Result};
use crate::outbound::parse_socks_address;

// ---------------------------------------------------------------------------
// UoT Request
// ---------------------------------------------------------------------------

struct UotRequest {
    is_connect: bool,
    destination: Address,
}

/// Parse the UoT Request from a buffer.  Returns (request, bytes_consumed).
fn parse_uot_request(data: &[u8]) -> Result<(UotRequest, usize)> {
    if data.is_empty() {
        return Err(Error::InvalidFrame(
            "UoT request: missing is_connect".into(),
        ));
    }
    let is_connect = data[0] != 0;
    let (destination, addr_consumed) = parse_socks_address(&data[1..])?;
    Ok((
        UotRequest {
            is_connect,
            destination,
        },
        1 + addr_consumed,
    ))
}

/// Minimum bytes needed to parse the UoT Request starting at `data`.
fn uot_request_min_len(data: &[u8]) -> usize {
    if data.len() < 2 {
        return 8; // need at least is_connect + addr_type + smallest addr
    }
    1 + match data[1] {
        0x01 => 7,  // IPv4
        0x04 => 19, // IPv6
        0x03 => {
            if data.len() >= 3 {
                1 + 1 + data[2] as usize + 2
            } else {
                4 // need more to determine
            }
        }
        _ => 8,
    }
}

// ---------------------------------------------------------------------------
// UoT per-packet address format (0x00=IPv4, 0x01=IPv6, 0x02=FQDN)
// ---------------------------------------------------------------------------

async fn read_uot_address<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<SocketAddr> {
    let addr_type = reader.read_u8().await.map_err(Error::Io)?;
    match addr_type {
        0x00 => {
            let mut ip = [0u8; 4];
            reader.read_exact(&mut ip).await?;
            let port = reader.read_u16().await?;
            Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
        }
        0x01 => {
            let mut ip = [0u8; 16];
            reader.read_exact(&mut ip).await?;
            let port = reader.read_u16().await?;
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(ip),
                port,
                0,
                0,
            )))
        }
        0x02 => {
            let len = reader.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            reader.read_exact(&mut name).await?;
            let domain = String::from_utf8(name)
                .map_err(|_| Error::InvalidFrame("UoT FQDN not UTF-8".into()))?;
            let port = reader.read_u16().await?;
            resolve_host(&domain, port).await
        }
        t => Err(Error::InvalidFrame(format!(
            "unknown UoT address type: 0x{t:02x}"
        ))),
    }
}

fn encode_uot_address(addr: &SocketAddr, buf: &mut Vec<u8>) {
    match addr {
        SocketAddr::V4(v4) => {
            buf.push(0x00);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            buf.push(0x01);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
}

fn resolve_failed(name: &str) -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("DNS resolution failed for {name}"),
    ))
}

async fn resolve_host(host: &str, port: u16) -> Result<SocketAddr> {
    tokio::net::lookup_host(format!("{host}:{port}"))
        .await?
        .next()
        .ok_or_else(|| resolve_failed(host))
}

async fn address_to_socket_addr(addr: &Address) -> Result<SocketAddr> {
    match addr {
        Address::IPv4(ip, port) => Ok(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from(*ip),
            *port,
        ))),
        Address::IPv6(ip, port) => Ok(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(*ip),
            *port,
            0,
            0,
        ))),
        Address::Domain(host, port) => resolve_host(host, *port).await,
    }
}

// ---------------------------------------------------------------------------
// PrefixedReader: yields `prefix` bytes first, then delegates to `inner`
// ---------------------------------------------------------------------------

struct PrefixedReader<R> {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: R,
}

impl<R> PrefixedReader<R> {
    fn new(prefix: Vec<u8>, inner: R) -> Self {
        Self {
            prefix,
            prefix_pos: 0,
            inner,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PrefixedReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.prefix_pos < this.prefix.len() {
            let remaining = &this.prefix[this.prefix_pos..];
            let amt = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..amt]);
            this.prefix_pos += amt;
            if this.prefix_pos >= this.prefix.len() {
                this.prefix = Vec::new();
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub(crate) async fn handle_udp_over_tcp<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    server: Arc<Server>,
    session: Arc<Session<T>>,
    mut stream: Stream,
    initial_data: Vec<u8>,
    user_id: UserId,
    cancel: CancellationToken,
) -> Result<()> {
    let stream_id = stream.id();

    // Read enough data to parse the UoT Request (is_connect + SOCKS5 destination).
    let mut buf = initial_data;
    loop {
        let needed = uot_request_min_len(&buf);
        if buf.len() >= needed {
            break;
        }
        let mut tmp = [0u8; 512];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(Error::StreamClosed);
        }
        buf.extend_from_slice(&tmp[..n]);
    }

    let (request, consumed) = parse_uot_request(&buf)?;
    let remaining = buf[consumed..].to_vec();

    debug!(
        stream_id,
        is_connect = request.is_connect,
        destination = %request.destination,
        "UDP-over-TCP session starting"
    );

    // Check ACL rules for UDP traffic before proceeding.
    // Proxy is treated as reject because UDP relay via SOCKS5 is not supported.
    let outbound = server.router.route_udp(&request.destination).await;
    if !matches!(outbound, OutboundType::Direct { .. }) {
        let reason = if matches!(outbound, OutboundType::Proxy(_)) {
            "UDP proxy not supported"
        } else {
            "rejected"
        };
        warn!(
            "rejecting UDP connection to {} ({reason})",
            request.destination
        );
        session.handshake_failure(stream_id, "rejected").await?;
        return Ok(());
    }

    // If connect mode, pre-resolve the destination and "connect" the socket
    // so we can use send/recv instead of send_to/recv_from.
    let connect_dest = if request.is_connect {
        Some(address_to_socket_addr(&request.destination).await?)
    } else {
        None
    };

    // Bind a UDP socket matching the destination address family.
    let bind_addr = match connect_dest {
        Some(SocketAddr::V6(_)) => "[::]:0",
        _ => "0.0.0.0:0",
    };
    let udp = Arc::new(UdpSocket::bind(bind_addr).await?);
    if let Some(dest) = connect_dest {
        udp.connect(dest).await?;
    }

    // Signal handshake success to the client.
    session.handshake_success(stream_id).await?;

    // Grab a FIN sender before splitting — split consumes the Stream.
    let fin_sender = stream.fin_sender();

    // Split the stream for concurrent read/write.
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = PrefixedReader::new(remaining, read_half);

    let upload_bytes = Arc::new(AtomicU64::new(0));
    let download_bytes = Arc::new(AtomicU64::new(0));

    // Client → UDP
    let udp_send = udp.clone();
    let up = upload_bytes.clone();
    let client_to_udp = async {
        let mut payload = vec![0u8; 65536];
        loop {
            let dest = if let Some(dest) = connect_dest {
                dest
            } else {
                read_uot_address(&mut reader).await?
            };
            let length = reader.read_u16().await.map_err(Error::Io)? as usize;
            if length == 0 {
                continue;
            }
            if payload.len() < length {
                payload.resize(length, 0);
            }
            reader.read_exact(&mut payload[..length]).await?;
            up.fetch_add(length as u64, Ordering::Relaxed);
            if connect_dest.is_some() {
                udp_send.send(&payload[..length]).await?;
            } else {
                udp_send.send_to(&payload[..length], dest).await?;
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), Error>(())
    };

    // UDP → Client
    let down = download_bytes.clone();
    let udp_to_client = async {
        let mut recv_buf = vec![0u8; 65536];
        let mut frame_buf = Vec::with_capacity(65536 + 19 + 2);
        loop {
            let (n, src_addr) = if let Some(dest) = connect_dest {
                let n = udp.recv(&mut recv_buf).await?;
                (n, dest)
            } else {
                udp.recv_from(&mut recv_buf).await?
            };
            down.fetch_add(n as u64, Ordering::Relaxed);

            // Build UoT frame
            frame_buf.clear();
            if connect_dest.is_none() {
                encode_uot_address(&src_addr, &mut frame_buf);
            }
            frame_buf.extend_from_slice(&(n as u16).to_be_bytes());
            frame_buf.extend_from_slice(&recv_buf[..n]);
            write_half.write_all(&frame_buf).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), Error>(())
    };

    // Idle watchdog: terminate if no data moves for relay_idle_timeout.
    let idle_timeout = server.config.relay_idle_timeout;
    let up_watch = upload_bytes.clone();
    let down_watch = download_bytes.clone();
    let idle_watchdog = async {
        let check_interval = std::cmp::max(idle_timeout / 10, std::time::Duration::from_secs(1));
        let mut prev_up = up_watch.load(Ordering::Relaxed);
        let mut prev_down = down_watch.load(Ordering::Relaxed);
        let mut idle_since = tokio::time::Instant::now();

        loop {
            tokio::time::sleep(check_interval).await;
            let cur_up = up_watch.load(Ordering::Relaxed);
            let cur_down = down_watch.load(Ordering::Relaxed);
            if cur_up != prev_up || cur_down != prev_down {
                prev_up = cur_up;
                prev_down = cur_down;
                idle_since = tokio::time::Instant::now();
            } else if idle_since.elapsed() >= idle_timeout {
                debug!(
                    stream_id,
                    "UDP relay idle for {:?}, terminating", idle_timeout
                );
                cancel.cancel();
                return;
            }
        }
    };

    // Run both directions; stop when either finishes (EOF, error, idle, or cancel).
    let relay_result = tokio::select! {
        r = client_to_udp => r,
        r = udp_to_client => r,
        _ = idle_watchdog => Ok(()),
        _ = cancel.cancelled() => Ok(()),
    };

    if let Err(ref e) = relay_result {
        debug!(stream_id, error = %e, "UDP-over-TCP relay ended");
    }

    let up = upload_bytes.load(Ordering::Relaxed);
    let down = download_bytes.load(Ordering::Relaxed);
    if up > 0 || down > 0 {
        server.stats.record_upload(user_id, up);
        server.stats.record_download(user_id, down);
    }

    // Send FIN through the writer task channel (not directly via write_half)
    // to guarantee it arrives after all queued PSH data for this stream.
    fin_sender.send_fin().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uot_request_connect_ipv4() {
        // is_connect=true, IPv4 127.0.0.1:53
        let data = [
            0x01, // is_connect = true
            0x01, 127, 0, 0, 1, 0x00, 0x35, // SOCKS5 IPv4 127.0.0.1:53
        ];
        let (req, consumed) = parse_uot_request(&data).unwrap();
        assert!(req.is_connect);
        assert!(matches!(req.destination, Address::IPv4([127, 0, 0, 1], 53)));
        assert_eq!(consumed, 8);
    }

    #[test]
    fn test_parse_uot_request_no_connect_domain() {
        // is_connect=false, domain "dns.google":53
        let mut data = vec![0x00]; // is_connect = false
        data.push(0x03); // SOCKS5 domain
        data.push(10); // len
        data.extend_from_slice(b"dns.google");
        data.extend_from_slice(&53u16.to_be_bytes());
        let (req, consumed) = parse_uot_request(&data).unwrap();
        assert!(!req.is_connect);
        if let Address::Domain(d, p) = &req.destination {
            assert_eq!(d, "dns.google");
            assert_eq!(*p, 53);
        } else {
            panic!("expected Domain");
        }
        assert_eq!(consumed, 1 + 1 + 1 + 10 + 2);
    }

    #[test]
    fn test_encode_uot_address_ipv4() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53));
        let mut buf = Vec::new();
        encode_uot_address(&addr, &mut buf);
        assert_eq!(buf, [0x00, 8, 8, 8, 8, 0x00, 0x35]);
    }

    #[test]
    fn test_encode_uot_address_ipv6() {
        let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0));
        let mut buf = Vec::new();
        encode_uot_address(&addr, &mut buf);
        assert_eq!(buf[0], 0x01);
        assert_eq!(buf.len(), 19);
        let port = u16::from_be_bytes([buf[17], buf[18]]);
        assert_eq!(port, 443);
    }

    #[test]
    fn test_uot_request_min_len_ipv4() {
        let data = [0x00, 0x01]; // is_connect=false, addr_type=IPv4
        assert_eq!(uot_request_min_len(&data), 8); // 1 + 7
    }

    #[test]
    fn test_uot_request_min_len_ipv6() {
        let data = [0x01, 0x04]; // is_connect=true, addr_type=IPv6
        assert_eq!(uot_request_min_len(&data), 20); // 1 + 19
    }

    #[test]
    fn test_uot_request_min_len_domain() {
        let data = [0x00, 0x03, 10]; // is_connect=false, domain, len=10
        assert_eq!(uot_request_min_len(&data), 1 + 1 + 1 + 10 + 2);
    }

    #[tokio::test]
    async fn test_read_uot_address_ipv4() {
        let data: &[u8] = &[0x00, 1, 2, 3, 4, 0x00, 80];
        let mut cursor = std::io::Cursor::new(data);
        let addr = read_uot_address(&mut cursor).await.unwrap();
        assert_eq!(
            addr,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 80))
        );
    }

    #[tokio::test]
    async fn test_read_uot_address_ipv6() {
        let mut data = vec![0x01];
        data.extend_from_slice(&[0u8; 16]); // ::0
        data.extend_from_slice(&443u16.to_be_bytes());
        let mut cursor = std::io::Cursor::new(data);
        let addr = read_uot_address(&mut cursor).await.unwrap();
        assert_eq!(
            addr,
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 443, 0, 0))
        );
    }

    #[tokio::test]
    async fn test_prefixed_reader() {
        let prefix = b"hello".to_vec();
        let inner: &[u8] = b" world";
        let mut reader = PrefixedReader::new(prefix, inner);
        let mut buf = vec![0u8; 20];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b" world");
    }

    use crate::core::hooks::{DirectRouter, SinglePasswordAuth};
    use crate::core::padding::{DEFAULT_SCHEME, PaddingFactory};
    use crate::core::server::Server;
    use crate::core::session::{Session, SessionConfig};
    use crate::core::stream::{Stream, WriteCommand};

    /// RED: UDP relay should terminate when idle (no data flows) for
    /// relay_idle_timeout. Currently handle_udp_over_tcp has no idle
    /// watchdog, so zombie UDP sessions persist indefinitely when the
    /// remote UDP endpoint goes silent.
    #[tokio::test]
    async fn test_udp_relay_terminates_when_idle() {
        // Bind a local UDP socket to act as the "remote" endpoint.
        let remote_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_addr = remote_udp.local_addr().unwrap();

        let server = Arc::new(
            Server::builder()
                .authenticator(Arc::new(SinglePasswordAuth::new("test")))
                .router(Arc::new(DirectRouter))
                .relay_idle_timeout(std::time::Duration::from_millis(500))
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

        // Build UoT connect request: is_connect=true, IPv4 pointing to our UDP socket.
        let ip = match remote_addr {
            SocketAddr::V4(v4) => v4.ip().octets(),
            _ => panic!("expected v4"),
        };
        let port = remote_addr.port();
        let mut uot_request = vec![0x01]; // is_connect = true
        uot_request.push(0x01); // SOCKS5 IPv4
        uot_request.extend_from_slice(&ip);
        uot_request.extend_from_slice(&port.to_be_bytes());

        // Send the UoT request + one small UDP payload so the relay starts.
        let payload_len: u16 = 5;
        uot_request.extend_from_slice(&payload_len.to_be_bytes());
        uot_request.extend_from_slice(b"hello");
        data_tx.send(bytes::Bytes::from(uot_request)).await.unwrap();

        // Don't send any more data — the relay should go idle.
        // Don't drop data_tx either — that would cause EOF, not idle timeout.

        // The relay should terminate within relay_idle_timeout (500ms) + margin.
        // RED: Currently handle_udp_over_tcp has no idle watchdog, so this
        // will hang until the 3-second timeout expires.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            handle_udp_over_tcp(
                server,
                session,
                stream,
                Vec::new(),
                42,
                CancellationToken::new(),
            ),
        )
        .await;

        // Must complete (not timeout). If it timed out, the idle watchdog is missing.
        assert!(
            result.is_ok(),
            "UDP relay should have terminated after 500ms idle timeout, \
             but it hung — no idle watchdog implemented"
        );
    }

    /// RED: UDP relay should stop when a cancellation token is fired
    /// (e.g. when the connection manager shuts down the session).
    /// Currently handle_udp_over_tcp does not accept or check a
    /// CancellationToken, so external cancellation has no effect.
    #[tokio::test]
    async fn test_udp_relay_responds_to_cancellation() {
        let remote_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_addr = remote_udp.local_addr().unwrap();

        let server = Arc::new(
            Server::builder()
                .authenticator(Arc::new(SinglePasswordAuth::new("test")))
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

        // UoT connect request
        let ip = match remote_addr {
            SocketAddr::V4(v4) => v4.ip().octets(),
            _ => panic!("expected v4"),
        };
        let port = remote_addr.port();
        let mut uot_request = vec![0x01, 0x01];
        uot_request.extend_from_slice(&ip);
        uot_request.extend_from_slice(&port.to_be_bytes());
        let payload_len: u16 = 5;
        uot_request.extend_from_slice(&payload_len.to_be_bytes());
        uot_request.extend_from_slice(b"hello");
        data_tx.send(bytes::Bytes::from(uot_request)).await.unwrap();

        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel_clone = cancel.clone();

        // Cancel after 200ms
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            cancel_clone.cancel();
        });

        // Keep the remote echoing so the relay stays "active" —
        // only the cancel token should stop it.
        let echo_udp = remote_udp;
        tokio::spawn(async move {
            let mut buf = [0u8; 65536];
            while let Ok((n, src)) = echo_udp.recv_from(&mut buf).await {
                let _ = echo_udp.send_to(&buf[..n], src).await;
            }
        });

        // Keep client sending data so the relay doesn't EOF.
        let data_tx_clone = data_tx.clone();
        tokio::spawn(async move {
            loop {
                let mut pkt = Vec::new();
                pkt.extend_from_slice(&4u16.to_be_bytes());
                pkt.extend_from_slice(b"ping");
                if data_tx_clone.send(bytes::Bytes::from(pkt)).await.is_err() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        });

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            handle_udp_over_tcp(server, session, stream, Vec::new(), 42, cancel),
        )
        .await;

        // With a cancel token, it should stop within 200ms + margin.
        assert!(
            result.is_ok(),
            "UDP relay should have stopped when cancel token fired"
        );
    }
}
