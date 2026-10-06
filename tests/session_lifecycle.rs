use std::sync::{Arc, Once};
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use server_anytls_rs::core::frame::{Command, FrameHeader, HEADER_SIZE};
use server_anytls_rs::core::padding::{DEFAULT_SCHEME, PaddingFactory};
use server_anytls_rs::{DirectRouter, Server, SinglePasswordAuth};

const PASSWORD: &str = "test-password-e2e";

static INIT_CRYPTO: Once = Once::new();

fn install_crypto_provider() {
    INIT_CRYPTO.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install CryptoProvider");
    });
}

/// Generate a self-signed TLS certificate and return (server_config, client_config).
fn make_tls_configs() -> (rustls::ServerConfig, Arc<rustls::ClientConfig>) {
    install_crypto_provider();
    let subject_alt_names = vec!["localhost".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names).unwrap();

    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    // Server config
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();

    // Client config — trust the self-signed cert
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    (server_config, Arc::new(client_config))
}

/// Start a simple TCP echo server. Returns the listening port.
async fn start_echo_server() -> (u16, CancellationToken) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_clone.cancelled() => break,
                result = listener.accept() => {
                    if let Ok((mut stream, _)) = result {
                        tokio::spawn(async move {
                            let mut buf = [0u8; 4096];
                            loop {
                                match stream.read(&mut buf).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        if stream.write_all(&buf[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                        });
                    }
                }
            }
        }
    });

    (port, cancel)
}

fn encode_frame(cmd: Command, stream_id: u32, data: &[u8]) -> Vec<u8> {
    let header = FrameHeader {
        command: cmd,
        stream_id,
        length: data.len() as u16,
    };
    let mut hdr_buf = [0u8; HEADER_SIZE];
    header.encode(&mut hdr_buf);
    let mut out = hdr_buf.to_vec();
    out.extend_from_slice(data);
    out
}

fn make_auth_packet(password: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();
    let mut packet = Vec::new();
    packet.extend_from_slice(&hash);
    // padding length = 0
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet
}

/// Build a SOCKS5-style IPv4 address: type(0x01) + ip(4) + port(2)
fn socks5_ipv4_addr(ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut data = vec![0x01];
    data.extend_from_slice(&ip);
    data.extend_from_slice(&port.to_be_bytes());
    data
}

async fn raw_frame(reader: &mut (impl AsyncReadExt + Unpin)) -> Option<(FrameHeader, Vec<u8>)> {
    let mut hdr_buf = [0u8; HEADER_SIZE];
    match tokio::time::timeout(Duration::from_secs(3), reader.read_exact(&mut hdr_buf)).await {
        Ok(Ok(_)) => {}
        _ => return None,
    }
    let header = FrameHeader::decode(&hdr_buf);
    let mut data = vec![0u8; header.length as usize];
    if header.length > 0 {
        reader.read_exact(&mut data).await.ok()?;
    }
    Some((header, data))
}

type Client = tokio_rustls::client::TlsStream<TcpStream>;
struct Fixture {
    client: Client,
    stop: CancellationToken,
    version: u8,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
impl Fixture {
    async fn new(version: u8, max: usize, idle: u64) -> Self {
        let (sc, cc) = make_tls_configs();
        let server = Arc::new(
            Server::builder()
                .authenticator(Arc::new(SinglePasswordAuth::new(PASSWORD)))
                .router(Arc::new(DirectRouter))
                .tls_config(sc)
                .max_streams_per_session(max)
                .relay_idle_timeout(Duration::from_secs(idle))
                .build()
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = CancellationToken::new();
        let x = stop.clone();
        tokio::spawn(async move {
            let _ = server.run(listener, x).await;
        });
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut client = TlsConnector::from(cc)
            .connect("localhost".try_into().unwrap(), tcp)
            .await
            .unwrap();
        client.write_all(&make_auth_packet(PASSWORD)).await.unwrap();
        let md5 = PaddingFactory::new(DEFAULT_SCHEME)
            .unwrap()
            .md5_hex()
            .to_string();
        let mut f = Self {
            client,
            stop,
            version,
        };
        f.send(
            Command::Settings,
            0,
            format!("v={version}\npadding-md5={md5}").as_bytes(),
        )
        .await;
        if version >= 2 {
            assert_eq!(f.next().await.unwrap().0.command, Command::ServerSettings);
        }
        f
    }
    async fn send(&mut self, cmd: Command, id: u32, data: &[u8]) {
        self.client
            .write_all(&encode_frame(cmd, id, data))
            .await
            .unwrap();
        self.client.flush().await.unwrap();
    }
    async fn next(&mut self) -> Option<(FrameHeader, Vec<u8>)> {
        loop {
            let f = tokio::time::timeout(Duration::from_secs(2), raw_frame(&mut self.client))
                .await
                .ok()??;
            if f.0.command != Command::Waste {
                return Some(f);
            }
        }
    }
    async fn open(&mut self, id: u32, port: u16) {
        self.send(Command::Syn, id, &[]).await;
        self.send(Command::Psh, id, &socks5_ipv4_addr([127, 0, 0, 1], port))
            .await;
        if self.version >= 2 {
            let f = self.next().await.expect("missing SynAck");
            assert_eq!((f.0.command, f.0.stream_id), (Command::SynAck, id));
            assert!(f.1.is_empty());
        }
    }
}

#[tokio::test]
async fn idle_stream_preserves_active_sibling_and_releases_slot() {
    for version in [1, 2] {
        let (port, echo_stop) = start_echo_server().await;
        let mut f = Fixture::new(version, 2, 1).await;
        f.open(1, port).await;
        f.open(2, port).await;
        let mut idle_fin = false;
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(300)).await;
            f.send(Command::Psh, 2, b"live").await;
            loop {
                let (h, d) = f
                    .next()
                    .await
                    .expect("idle stream closed an active session");
                if h.command == Command::Fin && h.stream_id == 1 {
                    idle_fin = true;
                    continue;
                }
                assert_eq!((h.command, h.stream_id), (Command::Psh, 2));
                assert_eq!(d, b"live");
                break;
            }
        }
        assert!(idle_fin, "idle stream was not closed");
        f.open(3, port).await;
        f.send(Command::Psh, 3, b"reused").await;
        let (h, d) = f.next().await.unwrap();
        assert_eq!((h.command, h.stream_id), (Command::Psh, 3));
        assert_eq!(d, b"reused");
        echo_stop.cancel();
    }
}

#[tokio::test]
async fn remote_eof_delivers_all_data_then_fin_without_client_fin() {
    for version in [1, 2] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let payload = vec![0x5a; 96 * 1024];
        let body = payload.clone();
        let backend = tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let b = body.clone();
                tokio::spawn(async move {
                    s.write_all(&b).await.unwrap();
                    s.shutdown().await.unwrap();
                });
            }
        });
        let mut f = Fixture::new(version, 1, 60).await;
        for id in 1..=3 {
            f.open(id, port).await;
            let mut data = Vec::new();
            loop {
                let (h, d) = f.next().await.expect("remote EOF was not forwarded as FIN");
                assert_eq!(h.stream_id, id);
                if h.command == Command::Fin {
                    break;
                }
                assert_eq!(h.command, Command::Psh);
                data.extend_from_slice(&d);
            }
            assert_eq!(data, payload, "FIN preceded outstanding response data");
        }
        backend.abort();
    }
}

#[tokio::test]
async fn fragmented_destination_preserves_trailing_payload() {
    let (port, echo_stop) = start_echo_server().await;
    for version in [1, 2] {
        let mut f = Fixture::new(version, 1, 60).await;
        let mut domain = vec![3, 9];
        domain.extend_from_slice(b"localhost");
        domain.extend_from_slice(&port.to_be_bytes());
        let ipv4 = socks5_ipv4_addr([127, 0, 0, 1], port);
        let mut id = 0;
        for addr in [ipv4, domain] {
            for cut in [1, 2, addr.len() - 1] {
                id += 1;
                f.send(Command::Syn, id, &[]).await;
                f.send(Command::Psh, id, &addr[..cut]).await;
                tokio::time::sleep(Duration::from_millis(20)).await;
                let mut tail = addr[cut..].to_vec();
                tail.extend_from_slice(b"split-address-payload");
                f.send(Command::Psh, id, &tail).await;
                if version >= 2 {
                    let (h, d) = f.next().await.expect("fragmented address rejected");
                    assert_eq!((h.command, h.stream_id), (Command::SynAck, id));
                    assert!(d.is_empty());
                }
                let (h, d) = f
                    .next()
                    .await
                    .expect("fragmented address did not proxy data");
                assert_eq!((h.command, h.stream_id), (Command::Psh, id));
                assert_eq!(d, b"split-address-payload");
                f.send(Command::Fin, id, &[]).await;
                // Existing clients may close streams after receiving all data.
                let (h, _) = f
                    .next()
                    .await
                    .expect("stream close acknowledgement missing");
                assert_eq!(h.command, Command::Fin);
            }
        }
    }
    echo_stop.cancel();
}

#[tokio::test]
async fn alert_closes_session_after_stream_limit() {
    let (port, echo_stop) = start_echo_server().await;
    for version in [1, 2] {
        let mut f = Fixture::new(version, 1, 60).await;
        f.open(1, port).await;
        f.send(Command::Syn, 2, &[]).await;
        let (h, _) = f.next().await.unwrap();
        assert_eq!(h.command, Command::Alert);
        let frame = encode_frame(Command::HeartRequest, 0, &[]);
        let _ = f.client.write_all(&frame).await;
        let _ = f.client.flush().await;
        let result = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match raw_frame(&mut f.client).await {
                    Some((h, _)) if h.command == Command::Waste => continue,
                    other => return other,
                }
            }
        })
        .await;
        assert!(matches!(result, Ok(None)), "session continued after Alert");
    }
    echo_stop.cancel();
}

#[tokio::test]
async fn server_fin_reclaims_slots_without_peer_fin() {
    use server_anytls_rs::core::session::{Session, SessionConfig};
    for version in [1, 2] {
        let (mut client, transport) = tokio::io::duplex(65536);
        let cfg = SessionConfig {
            max_streams: 2,
            downlink_padding: false,
            downlink_burst_padding: false,
            ..Default::default()
        };
        let session = Arc::new(Session::new_server(
            transport,
            PaddingFactory::new(DEFAULT_SCHEME).unwrap(),
            cfg,
        ));
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let stop = CancellationToken::new();
        let x = stop.clone();
        let task = tokio::spawn(async move { session.recv_loop(tx, x).await });
        client
            .write_all(&encode_frame(
                Command::Settings,
                0,
                format!("v={version}\npadding-md5=unused").as_bytes(),
            ))
            .await
            .unwrap();
        assert_eq!(
            raw_frame(&mut client).await.unwrap().0.command,
            Command::UpdatePaddingScheme
        );
        if version >= 2 {
            assert_eq!(
                raw_frame(&mut client).await.unwrap().0.command,
                Command::ServerSettings
            );
        }
        let mut held_streams = Vec::new();
        for id in 1..=5 {
            client
                .write_all(&encode_frame(Command::Syn, id, &[]))
                .await
                .unwrap();
            let stream = tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .expect("stream slot not reclaimed")
                .unwrap();
            assert_eq!(stream.id(), id);
            stream.send_fin().await.unwrap();
            held_streams.push(stream);
            let (h, _) = raw_frame(&mut client).await.unwrap();
            assert_eq!((h.command, h.stream_id), (Command::Fin, id));
        }
        stop.cancel();
        let _ = task.await;
    }
}

#[tokio::test]
async fn stream_shutdown_orders_one_fin_after_pending_data() {
    use server_anytls_rs::core::stream::{Stream, WriteCommand};
    let (tx, mut rx) = tokio::sync::mpsc::channel::<WriteCommand>(1);
    let (_data_tx, mut stream) = Stream::new(1, tx, 8);
    let fin = stream.fin_sender();
    stream.write_all(b"last-data").await.unwrap();
    // Backpressure must not turn a cancelled shutdown into a lost FIN.
    let result = tokio::time::timeout(Duration::from_millis(20), stream.shutdown()).await;
    assert!(
        result.is_err(),
        "shutdown did not wait for the pending write"
    );
    let data = rx.recv().await.unwrap();
    assert!(!data.fin);
    assert_eq!(&data.data[..], b"last-data");
    stream.shutdown().await.unwrap();
    let cmd = rx.recv().await.unwrap();
    assert!(cmd.fin);
    fin.send_fin().await.unwrap();
    stream.shutdown().await.unwrap();
    assert!(rx.try_recv().is_err(), "duplicate FIN queued");
}

#[tokio::test]
async fn heartbeat_preserves_request_stream_id() {
    let mut f = Fixture::new(2, 2, 60).await;
    for id in [0, 77] {
        f.send(Command::HeartRequest, id, &[]).await;
        let (h, d) = f.next().await.unwrap();
        assert_eq!((h.command, h.stream_id), (Command::HeartResponse, id));
        assert!(d.is_empty());
    }
}

#[tokio::test]
async fn local_fin_during_partial_header_preserves_framing() {
    use server_anytls_rs::core::session::{Session, SessionConfig};
    let (mut client, transport) = tokio::io::duplex(65536);
    let session = Arc::new(Session::new_server(
        transport,
        PaddingFactory::new(DEFAULT_SCHEME).unwrap(),
        SessionConfig {
            downlink_padding: false,
            ..Default::default()
        },
    ));
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let stop = CancellationToken::new();
    let x = stop.clone();
    let task = tokio::spawn(async move { session.recv_loop(tx, x).await });
    client
        .write_all(&encode_frame(
            Command::Settings,
            0,
            b"v=2\npadding-md5=unused",
        ))
        .await
        .unwrap();
    assert_eq!(
        raw_frame(&mut client).await.unwrap().0.command,
        Command::UpdatePaddingScheme
    );
    assert_eq!(
        raw_frame(&mut client).await.unwrap().0.command,
        Command::ServerSettings
    );
    client
        .write_all(&encode_frame(Command::Syn, 1, &[]))
        .await
        .unwrap();
    let stream = rx.recv().await.unwrap();
    let heart = encode_frame(Command::HeartRequest, 0, &[]);
    client.write_all(&heart[..3]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    stream.send_fin().await.unwrap();
    assert_eq!(
        raw_frame(&mut client).await.unwrap().0.command,
        Command::Fin
    );
    client.write_all(&heart[3..]).await.unwrap();
    let (h, _) = raw_frame(&mut client)
        .await
        .expect("partial header lost during local FIN");
    assert_eq!(h.command, Command::HeartResponse);
    stop.cancel();
    let _ = task.await;
}

#[tokio::test]
async fn alert_closes_without_waiting_for_rejected_syn_payload() {
    use server_anytls_rs::core::session::{Session, SessionConfig};
    let (mut client, transport) = tokio::io::duplex(65536);
    let session = Arc::new(Session::new_server(
        transport,
        PaddingFactory::new(DEFAULT_SCHEME).unwrap(),
        SessionConfig::default(),
    ));
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    let mut task =
        tokio::spawn(async move { session.recv_loop(tx, CancellationToken::new()).await });
    // Rejected SYN before Settings: the advertised payload never arrives.
    let mut header = [0; HEADER_SIZE];
    FrameHeader {
        command: Command::Syn,
        stream_id: 1,
        length: 128,
    }
    .encode(&mut header);
    client.write_all(&header).await.unwrap();
    assert_eq!(
        raw_frame(&mut client).await.unwrap().0.command,
        Command::Alert
    );
    let result = tokio::time::timeout(Duration::from_millis(300), &mut task).await;
    task.abort();
    result
        .expect("Alert left session waiting for rejected payload")
        .expect("session task panicked")
        .expect("session returned an error");
}
