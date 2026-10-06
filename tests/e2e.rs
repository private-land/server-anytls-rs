//! End-to-end integration test for the AnyTLS protocol.
//!
//! Flow:
//! 1. Start a TCP echo server on a random port.
//! 2. Start the AnyTLS server (TLS + auth + session) on another random port.
//! 3. A simulated client connects via TLS, authenticates, exchanges settings,
//!    opens a stream (SYN) with SOCKS5 address pointing to the echo server,
//!    sends data (PSH), and reads back the echoed response.

use std::sync::{Arc, Once};
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use rustls::HandshakeKind;
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

async fn read_frame(reader: &mut (impl AsyncReadExt + Unpin)) -> Option<(FrameHeader, Vec<u8>)> {
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

/// Start a "black hole" server that accepts TCP connections but never
/// reads or writes — simulates an unresponsive remote host.
/// Returns (port, cancel_token, held_connections).
async fn start_blackhole_server() -> (
    u16,
    CancellationToken,
    Arc<tokio::sync::Mutex<Vec<TcpStream>>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let connections: Arc<tokio::sync::Mutex<Vec<TcpStream>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let conns = connections.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_clone.cancelled() => break,
                result = listener.accept() => {
                    if let Ok((stream, _)) = result {
                        conns.lock().await.push(stream);
                    }
                }
            }
        }
    });
    (port, cancel, connections)
}

/// Open an AnyTLS connection that sends a stream to `blackhole_port`.
/// The relay (`copy_bidirectional`) will hang because the black hole never responds.
async fn open_stuck_connection(
    connector: &TlsConnector,
    server_port: u16,
    blackhole_port: u16,
    padding_md5: &str,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tcp = TcpStream::connect(format!("127.0.0.1:{server_port}"))
        .await
        .unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    tls.write_all(&make_auth_packet(PASSWORD)).await.unwrap();
    let settings_data = format!("v=2\npadding-md5={padding_md5}");
    tls.write_all(&encode_frame(
        Command::Settings,
        0,
        settings_data.as_bytes(),
    ))
    .await
    .unwrap();
    tls.flush().await.unwrap();

    for _ in 0..5 {
        if let Some((hdr, _)) = read_frame(&mut tls).await
            && hdr.command == Command::ServerSettings
        {
            break;
        }
    }

    tls.write_all(&encode_frame(Command::Syn, 1, &[]))
        .await
        .unwrap();

    let mut psh_payload = socks5_ipv4_addr([127, 0, 0, 1], blackhole_port);
    psh_payload.extend_from_slice(b"trigger-relay");
    tls.write_all(&encode_frame(Command::Psh, 1, &psh_payload))
        .await
        .unwrap();
    tls.flush().await.unwrap();

    for _ in 0..5 {
        if let Some((hdr, _)) = read_frame(&mut tls).await
            && hdr.command == Command::SynAck
        {
            break;
        }
    }

    tls
}

/// Try to complete a TLS handshake to the server within the given timeout.
/// Returns Ok(()) if successful, Err if timeout or connection failure.
async fn try_connect_tls(
    tls_client_config: &Arc<rustls::ClientConfig>,
    server_port: u16,
    timeout: Duration,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let connector = TlsConnector::from(tls_client_config.clone());
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    tokio::time::timeout(timeout, async {
        let tcp = TcpStream::connect(format!("127.0.0.1:{server_port}")).await?;
        let _tls = connector.connect(server_name, tcp).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await?
}

#[tokio::test]
async fn test_full_e2e_echo() {
    // 1. Start echo server
    let (echo_port, echo_cancel) = start_echo_server().await;

    // 2. Build AnyTLS server
    let (tls_server_config, tls_client_config) = make_tls_configs();
    let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
    let padding_md5 = padding.md5_hex().to_string();

    let server = Arc::new(
        Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new(PASSWORD)))
            .router(Arc::new(DirectRouter))
            .tls_config(tls_server_config)
            .build()
            .unwrap(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    let server_handle = tokio::spawn(async move {
        server.run(listener, shutdown_clone).await.unwrap();
    });

    // 3. Client connects
    let tcp = TcpStream::connect(format!("127.0.0.1:{}", server_port))
        .await
        .unwrap();

    let connector = TlsConnector::from(tls_client_config);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    // 4. Send auth
    let auth_packet = make_auth_packet(PASSWORD);
    tls.write_all(&auth_packet).await.unwrap();

    // 5. Send Settings frame
    let settings_data = format!("v=2\npadding-md5={}", padding_md5);
    let settings_frame = encode_frame(Command::Settings, 0, settings_data.as_bytes());
    tls.write_all(&settings_frame).await.unwrap();

    // 6. Read server responses (ServerSettings, possibly UpdatePaddingScheme)
    // We just drain any control frames until we're ready to send SYN
    let mut got_server_settings = false;
    for _ in 0..5 {
        if let Some((hdr, _data)) = read_frame(&mut tls).await {
            if hdr.command == Command::ServerSettings {
                got_server_settings = true;
                break;
            }
        } else {
            break;
        }
    }
    assert!(got_server_settings, "did not receive ServerSettings");

    // 7. Send SYN to open stream 1
    let syn_frame = encode_frame(Command::Syn, 1, &[]);
    tls.write_all(&syn_frame).await.unwrap();

    // 8. Send PSH with SOCKS5 address (127.0.0.1:echo_port) + trailing payload
    let mut psh_payload = socks5_ipv4_addr([127, 0, 0, 1], echo_port);
    let test_data = b"Hello, AnyTLS!";
    psh_payload.extend_from_slice(test_data);
    let psh_frame = encode_frame(Command::Psh, 1, &psh_payload);
    tls.write_all(&psh_frame).await.unwrap();
    tls.flush().await.unwrap();

    // 9. Read back: expect SynAck (v2 handshake success) then PSH with echoed data
    let mut got_synack = false;
    let mut echoed_data = Vec::new();

    for _ in 0..10 {
        if let Some((hdr, data)) = read_frame(&mut tls).await {
            match hdr.command {
                Command::SynAck => {
                    got_synack = true;
                    // Empty SynAck = success
                    assert!(data.is_empty(), "SynAck should be empty for success");
                }
                Command::Psh if hdr.stream_id == 1 => {
                    echoed_data.extend_from_slice(&data);
                    if echoed_data.len() >= test_data.len() {
                        break;
                    }
                }
                _ => {
                    // skip other frames
                }
            }
        } else {
            break;
        }
    }

    assert!(got_synack, "did not receive SynAck");
    assert_eq!(
        &echoed_data[..test_data.len()],
        test_data,
        "echoed data mismatch"
    );

    // 10. Cleanup
    shutdown.cancel();
    echo_cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

#[tokio::test]
async fn test_auth_failure() {
    let (tls_server_config, tls_client_config) = make_tls_configs();

    let server = Arc::new(
        Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new(PASSWORD)))
            .router(Arc::new(DirectRouter))
            .tls_config(tls_server_config)
            .build()
            .unwrap(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        let _ = server.run(listener, shutdown_clone).await;
    });

    let tcp = TcpStream::connect(format!("127.0.0.1:{}", server_port))
        .await
        .unwrap();

    let connector = TlsConnector::from(tls_client_config);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    // Send wrong password
    let auth_packet = make_auth_packet("wrong-password");
    tls.write_all(&auth_packet).await.unwrap();
    tls.flush().await.unwrap();

    // Server should close the connection — reading should return EOF or error
    let mut buf = [0u8; 128];
    let result = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buf)).await;
    match result {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
            // Expected: connection closed or error
        }
        Ok(Ok(n)) => {
            panic!(
                "expected connection close after auth failure, got {} bytes",
                n
            );
        }
    }

    shutdown.cancel();
}

#[tokio::test]
async fn test_heartbeat() {
    let (tls_server_config, tls_client_config) = make_tls_configs();
    let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
    let padding_md5 = padding.md5_hex().to_string();

    let server = Arc::new(
        Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new(PASSWORD)))
            .router(Arc::new(DirectRouter))
            .tls_config(tls_server_config)
            .build()
            .unwrap(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        let _ = server.run(listener, shutdown_clone).await;
    });

    let tcp = TcpStream::connect(format!("127.0.0.1:{}", server_port))
        .await
        .unwrap();

    let connector = TlsConnector::from(tls_client_config);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    // Auth
    tls.write_all(&make_auth_packet(PASSWORD)).await.unwrap();

    // Settings
    let settings_data = format!("v=2\npadding-md5={}", padding_md5);
    tls.write_all(&encode_frame(
        Command::Settings,
        0,
        settings_data.as_bytes(),
    ))
    .await
    .unwrap();

    // Drain ServerSettings
    for _ in 0..3 {
        if let Some((hdr, _)) = read_frame(&mut tls).await
            && hdr.command == Command::ServerSettings
        {
            break;
        }
    }

    // Send HeartRequest
    tls.write_all(&encode_frame(Command::HeartRequest, 0, &[]))
        .await
        .unwrap();
    tls.flush().await.unwrap();

    // Expect HeartResponse
    let mut got_heart = false;
    for _ in 0..5 {
        if let Some((hdr, _)) = read_frame(&mut tls).await {
            if hdr.command == Command::HeartResponse {
                got_heart = true;
                break;
            }
        } else {
            break;
        }
    }
    assert!(got_heart, "did not receive HeartResponse");

    shutdown.cancel();
}

#[tokio::test]
async fn test_tls_session_resumption() {
    let (tls_server_config, tls_client_config) = make_tls_configs();

    let server = Arc::new(
        Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new(PASSWORD)))
            .router(Arc::new(DirectRouter))
            .tls_config(tls_server_config)
            .build()
            .unwrap(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        let _ = server.run(listener, shutdown_clone).await;
    });

    let connector = TlsConnector::from(tls_client_config.clone());
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();

    // First connection — must be a full handshake.
    // We send auth + settings and read back ServerSettings so the client
    // receives the server's NewSessionTicket post-handshake message.
    let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
    let padding_md5 = padding.md5_hex().to_string();
    {
        let tcp = TcpStream::connect(format!("127.0.0.1:{}", server_port))
            .await
            .unwrap();
        let mut tls = connector.connect(server_name.clone(), tcp).await.unwrap();
        let (_, conn) = tls.get_ref();
        assert_eq!(
            conn.handshake_kind(),
            Some(HandshakeKind::Full),
            "first connection should be a full handshake"
        );

        // Complete the protocol handshake so session ticket is received
        tls.write_all(&make_auth_packet(PASSWORD)).await.unwrap();
        let settings_data = format!("v=2\npadding-md5={}", padding_md5);
        tls.write_all(&encode_frame(
            Command::Settings,
            0,
            settings_data.as_bytes(),
        ))
        .await
        .unwrap();
        tls.flush().await.unwrap();

        // Read ServerSettings (this also processes any queued NewSessionTicket)
        for _ in 0..5 {
            if let Some((hdr, _)) = read_frame(&mut tls).await
                && hdr.command == Command::ServerSettings
            {
                break;
            }
        }
    }

    // Brief pause so the server processes the session ticket
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Second connection — should resume via session ticket
    {
        let tcp = TcpStream::connect(format!("127.0.0.1:{}", server_port))
            .await
            .unwrap();
        let tls = connector.connect(server_name.clone(), tcp).await.unwrap();
        let (_, conn) = tls.get_ref();
        assert_eq!(
            conn.handshake_kind(),
            Some(HandshakeKind::Resumed),
            "second connection should use TLS session resumption"
        );
    }

    shutdown.cancel();
}

/// Reproduce the "zombie server" bug: when outbound targets become
/// unresponsive (accept TCP but never read/write), `copy_bidirectional`
/// in the relay hangs indefinitely. Each stuck relay holds a semaphore
/// permit (from the accept loop). Once all permits are consumed, the
/// server can no longer accept new connections — it appears dead even
/// though the process is still running.
///
/// Root cause: no idle/relay timeout on `copy_bidirectional`, no TCP
/// keepalive on outbound connections, and no session-level lifetime limit.
///
/// This test uses max_connections=2 to make the issue reproducible quickly:
/// 1. Start a "black hole" server that accepts TCP but never responds.
/// 2. Open 2 AnyTLS connections, each opening a stream to the black hole.
/// 3. copy_bidirectional hangs → permits are never released.
/// 4. A 3rd connection attempt should time out (server is zombie).
/// 5. Wait 3 seconds to prove it never recovers on its own.
#[tokio::test]
async fn test_blackhole_outbound_causes_zombie_server() {
    let (blackhole_port, blackhole_cancel, blackhole_connections) = start_blackhole_server().await;

    let (tls_server_config, tls_client_config) = make_tls_configs();
    let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
    let padding_md5 = padding.md5_hex().to_string();

    let server = Arc::new(
        Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new(PASSWORD)))
            .router(Arc::new(DirectRouter))
            .tls_config(tls_server_config)
            .max_connections(2)
            .build()
            .unwrap(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        let _ = server.run(listener, shutdown_clone).await;
    });

    let connector = TlsConnector::from(tls_client_config.clone());

    // Open 2 connections stuck on the black hole → exhaust permits
    let mut stuck_conns = Vec::new();
    for _ in 0..2 {
        let tls =
            open_stuck_connection(&connector, server_port, blackhole_port, &padding_md5).await;
        stuck_conns.push(tls);
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Server is zombie — 3rd connection cannot complete
    assert!(
        try_connect_tls(&tls_client_config, server_port, Duration::from_millis(500))
            .await
            .is_err(),
        "server should be zombie: 3rd connection must not complete \
         when all permits are consumed by stuck relays"
    );

    // Wait 3 seconds — still zombie (no recovery mechanism)
    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(
        try_connect_tls(&tls_client_config, server_port, Duration::from_millis(500))
            .await
            .is_err(),
        "server should STILL be zombie after 3 seconds — no automatic \
         recovery mechanism exists for stuck copy_bidirectional relays"
    );

    drop(stuck_conns);
    blackhole_cancel.cancel();
    drop(blackhole_connections);
    shutdown.cancel();
}

/// An idle relay releases its stream slot and leaves the outer session usable.
/// Connection permits remain owned by live sessions until their clients close.
#[tokio::test]
async fn test_blackhole_outbound_recovers_with_idle_timeout() {
    let (blackhole_port, blackhole_cancel, blackhole_connections) = start_blackhole_server().await;
    let (echo_port, echo_cancel) = start_echo_server().await;
    let (tls_server_config, tls_client_config) = make_tls_configs();
    let padding_md5 = PaddingFactory::new(DEFAULT_SCHEME)
        .unwrap()
        .md5_hex()
        .to_string();
    let server = Arc::new(
        Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new(PASSWORD)))
            .router(Arc::new(DirectRouter))
            .tls_config(tls_server_config)
            .max_connections(2)
            .max_streams_per_session(1)
            .relay_idle_timeout(Duration::from_secs(1))
            .build()
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let shutdown = CancellationToken::new();
    let stop = shutdown.clone();
    tokio::spawn(async move {
        let _ = server.run(listener, stop).await;
    });
    let connector = TlsConnector::from(tls_client_config.clone());
    let mut sessions = Vec::new();
    for _ in 0..2 {
        sessions.push(
            open_stuck_connection(&connector, server_port, blackhole_port, &padding_md5).await,
        );
    }
    assert!(
        try_connect_tls(&tls_client_config, server_port, Duration::from_millis(200))
            .await
            .is_err()
    );
    for session in &mut sessions {
        let fin = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let (h, _) = read_frame(session)
                    .await
                    .expect("outer session unexpectedly closed");
                if h.command != Command::Waste {
                    break h;
                }
            }
        })
        .await
        .expect("idle relay did not close");
        assert_eq!((fin.command, fin.stream_id), (Command::Fin, 1));
        session
            .write_all(&encode_frame(Command::Syn, 3, &[]))
            .await
            .unwrap();
        let mut data = socks5_ipv4_addr([127, 0, 0, 1], echo_port);
        data.extend_from_slice(b"recovered");
        session
            .write_all(&encode_frame(Command::Psh, 3, &data))
            .await
            .unwrap();
        session.flush().await.unwrap();
        loop {
            let (h, d) = read_frame(session)
                .await
                .expect("session not reusable after idle relay");
            if h.command == Command::Waste {
                continue;
            }
            assert_eq!(h.stream_id, 3);
            if h.command == Command::SynAck {
                assert!(d.is_empty());
                continue;
            }
            assert_eq!(h.command, Command::Psh);
            assert_eq!(d, b"recovered");
            break;
        }
    }
    // max_connections still applies to idle-but-live sessions.
    assert!(
        try_connect_tls(&tls_client_config, server_port, Duration::from_millis(200))
            .await
            .is_err()
    );
    sessions.pop();
    assert!(
        try_connect_tls(&tls_client_config, server_port, Duration::from_secs(2))
            .await
            .is_ok()
    );
    drop(sessions);
    blackhole_cancel.cancel();
    echo_cancel.cancel();
    drop(blackhole_connections);
    shutdown.cancel();
}

/// Verify that max_connections is strictly enforced at the accept loop level.
/// The semaphore is acquired before spawning, so the accept loop blocks when
/// all permits are held and new connections queue in the kernel TCP backlog.
///
/// Creates a server with max_connections=2, holds 2 connections, then verifies
/// a 3rd connection is blocked until a permit is released.
#[tokio::test]
async fn test_max_connections_enforced() {
    let (tls_server_config, tls_client_config) = make_tls_configs();

    let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
    let padding_md5 = padding.md5_hex().to_string();

    // Server with max_connections=2
    let server = Arc::new(
        Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new(PASSWORD)))
            .router(Arc::new(DirectRouter))
            .tls_config(tls_server_config)
            .max_connections(2)
            .build()
            .unwrap(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        let _ = server.run(listener, shutdown_clone).await;
    });

    let connector = TlsConnector::from(tls_client_config.clone());
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();

    // Open 2 connections that complete handshake and hold permits
    let mut held_connections = Vec::new();
    for _ in 0..2 {
        let tcp = TcpStream::connect(format!("127.0.0.1:{}", server_port))
            .await
            .unwrap();
        let mut tls = connector.connect(server_name.clone(), tcp).await.unwrap();
        tls.write_all(&make_auth_packet(PASSWORD)).await.unwrap();
        let settings_data = format!("v=2\npadding-md5={}", padding_md5);
        tls.write_all(&encode_frame(
            Command::Settings,
            0,
            settings_data.as_bytes(),
        ))
        .await
        .unwrap();
        tls.flush().await.unwrap();
        for _ in 0..5 {
            if let Some((hdr, _)) = read_frame(&mut tls).await
                && hdr.command == Command::ServerSettings
            {
                break;
            }
        }
        held_connections.push(tls);
    }

    // Both permits held. 3rd connection should NOT complete TLS handshake
    // within 200ms because accept loop is blocked waiting for a permit.
    let connector3 = TlsConnector::from(tls_client_config.clone());
    let server_name3 = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let handshake_result = tokio::time::timeout(Duration::from_millis(200), async {
        let tcp = TcpStream::connect(format!("127.0.0.1:{}", server_port)).await?;
        let _tls = connector3.connect(server_name3, tcp).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await;

    // Should timeout — the connection is queued, not accepted
    assert!(
        handshake_result.is_err(),
        "3rd connection should be blocked when max_connections is reached"
    );

    // Release one held connection — the queued 3rd should now be accepted
    held_connections.pop();
    // Give server time to release permit and accept queued connection
    tokio::time::sleep(Duration::from_millis(100)).await;

    let connector4 = TlsConnector::from(tls_client_config.clone());
    let server_name4 = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let handshake_result2 = tokio::time::timeout(Duration::from_millis(500), async {
        let tcp = TcpStream::connect(format!("127.0.0.1:{}", server_port)).await?;
        let _tls = connector4.connect(server_name4, tcp).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await;

    assert!(
        handshake_result2.is_ok(),
        "connection should succeed after a permit is released"
    );

    drop(held_connections);
    shutdown.cancel();
}
