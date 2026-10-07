use std::sync::{Arc, Once};
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use server_anytls_rs::core::frame::{Command, FrameHeader, HEADER_SIZE};
use server_anytls_rs::{Server, SinglePasswordAuth};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

static CRYPTO: Once = Once::new();

struct Fixture {
    port: u16,
    client: Arc<rustls::ClientConfig>,
    stop: CancellationToken,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl Fixture {
    async fn new() -> Self {
        Self::with_policy(None).await
    }

    async fn with_policy(enabled: Option<bool>) -> Self {
        CRYPTO.call_once(|| {
            rustls::crypto::aws_lc_rs::default_provider()
                .install_default()
                .unwrap();
        });
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key.into())
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let client = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let mut builder = Server::builder()
            .authenticator(Arc::new(SinglePasswordAuth::new("probe-test")))
            .max_connections(1)
            .tls_config(tls);
        if let Some(enabled) = enabled {
            builder = builder.auth_probe_resistance(enabled);
        }
        let server = Arc::new(builder.build().unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = CancellationToken::new();
        let server_stop = stop.clone();
        tokio::spawn(async move { server.run(listener, server_stop).await.unwrap() });
        Self { port, client, stop }
    }

    async fn tls(&self) -> tokio_rustls::client::TlsStream<TcpStream> {
        let tcp = TcpStream::connect(("127.0.0.1", self.port)).await.unwrap();
        TlsConnector::from(self.client.clone())
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap()
    }
}

async fn closed<R: AsyncRead + Unpin>(io: &mut R) {
    let mut byte = [0];
    match io.read(&mut byte).await {
        Ok(0) => {}
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
            ) => {}
        result => panic!("expected connection close, got {result:?}"),
    }
}

#[tokio::test]
async fn default_wrong_auth_waits_until_five_second_deadline() {
    let fixture = Fixture::new().await;
    let mut tls = fixture.tls().await;
    tls.write_all(&[b'x'; 32]).await.unwrap();
    tls.flush().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(4), closed(&mut tls))
            .await
            .is_err(),
        "wrong auth exposed an immediate-close boundary"
    );
    tokio::time::timeout(Duration::from_secs(2), closed(&mut tls))
        .await
        .expect("failed auth exceeded the five-second deadline");
}

#[tokio::test]
async fn default_empty_auth_closes_after_five_seconds() {
    let fixture = Fixture::new().await;
    let mut tls = fixture.tls().await;
    let start = tokio::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(6), closed(&mut tls))
        .await
        .expect("empty auth retained the legacy ten-second timeout");
    assert!(start.elapsed() >= Duration::from_millis(4700));
}

#[tokio::test]
async fn default_plain_http_closes_without_tls_alert() {
    let fixture = Fixture::new().await;
    let mut tcp = TcpStream::connect(("127.0.0.1", fixture.port))
        .await
        .unwrap();
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), tcp.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.is_empty(), "TLS alert exposed: {response:02x?}");
}

#[tokio::test]
async fn disabled_wrong_auth_closes_immediately() {
    let fixture = Fixture::with_policy(Some(false)).await;
    let mut tls = fixture.tls().await;
    tls.write_all(&[b'x'; 32]).await.unwrap();
    tls.flush().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), closed(&mut tls))
        .await
        .expect("disabled mode delayed authentication failure");
}

#[tokio::test]
async fn disabled_plain_http_retains_original_tls_alert() {
    let fixture = Fixture::with_policy(Some(false)).await;
    let mut tcp = TcpStream::connect(("127.0.0.1", fixture.port))
        .await
        .unwrap();
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), tcp.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, [0x15, 3, 3, 0, 2, 2, 0x32]);
}

#[tokio::test]
async fn default_malformed_client_hello_returns_decode_error() {
    let fixture = Fixture::new().await;
    let mut tcp = TcpStream::connect(("127.0.0.1", fixture.port))
        .await
        .unwrap();
    // A TLS handshake record containing an empty, invalid ClientHello.
    tcp.write_all(&[22, 3, 3, 0, 4, 1, 0, 0, 0]).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), tcp.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, [0x15, 3, 3, 0, 2, 2, 0x32]);
}

#[tokio::test]
async fn reference_initial_record_alerts_and_fragmentation() {
    for (input, alert) in [
        (vec![0x80, 9, 1, 0, 2, 0, 0, 0, 0, 0, 0], 0x46),
        (vec![22, 3, 3, 0xff, 0xff], 0x16),
    ] {
        let fixture = Fixture::new().await;
        let mut tcp = TcpStream::connect(("127.0.0.1", fixture.port))
            .await
            .unwrap();
        for byte in input {
            if tcp.write_all(&[byte]).await.is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
        let mut response = [0; 7];
        tokio::time::timeout(Duration::from_secs(1), tcp.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, [0x15, 3, 3, 0, 2, 2, alert]);
    }
}

#[tokio::test]
async fn reference_duplicate_sni_returns_decode_error() {
    let fixture = Fixture::new().await;
    let mut client = rustls::ClientConnection::new(
        fixture.client.clone(),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    let mut hello = wire[5..].to_vec();
    let mut offset = 39 + hello[38] as usize;
    offset += 2 + u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
    offset += 1 + hello[offset] as usize;
    let extension_length_offset = offset;
    offset += 2;
    let mut duplicate = Vec::new();
    while offset < hello.len() {
        let length = u16::from_be_bytes([hello[offset + 2], hello[offset + 3]]) as usize;
        if hello[offset..offset + 2] == [0, 0] {
            duplicate = hello[offset..offset + 4 + length].to_vec();
            break;
        }
        offset += 4 + length;
    }
    assert!(!duplicate.is_empty());
    let length = u16::from_be_bytes([
        hello[extension_length_offset],
        hello[extension_length_offset + 1],
    ]) + duplicate.len() as u16;
    hello[extension_length_offset..extension_length_offset + 2]
        .copy_from_slice(&length.to_be_bytes());
    hello.extend_from_slice(&duplicate);
    let handshake_length = (hello.len() - 4) as u32;
    hello[1..4].copy_from_slice(&handshake_length.to_be_bytes()[1..]);
    wire.truncate(5);
    wire[3..5].copy_from_slice(&(hello.len() as u16).to_be_bytes());
    wire.extend_from_slice(&hello);
    let mut tcp = TcpStream::connect(("127.0.0.1", fixture.port))
        .await
        .unwrap();
    tcp.write_all(&wire).await.unwrap();
    let mut response = [0; 7];
    tokio::time::timeout(Duration::from_secs(1), tcp.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, [21, 3, 3, 0, 2, 2, 50]);
}

#[tokio::test]
async fn early_ticket_does_not_admit_corrupt_client_finished() {
    let fixture = Fixture::new().await;
    let mut client = rustls::ClientConnection::new(
        fixture.client.clone(),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut tcp = TcpStream::connect(("127.0.0.1", fixture.port))
        .await
        .unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    tcp.write_all(&wire).await.unwrap();
    while client.is_handshaking() {
        let mut header = [0; 5];
        tcp.read_exact(&mut header).await.unwrap();
        let mut record = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
        tcp.read_exact(&mut record).await.unwrap();
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(&record);
        client.read_tls(&mut &bytes[..]).unwrap();
        client.process_new_packets().unwrap();
    }
    wire.clear();
    client.write_tls(&mut wire).unwrap();
    let mut offset = 0;
    let mut corrupted = false;
    while offset < wire.len() {
        let end = offset + 5 + u16::from_be_bytes([wire[offset + 3], wire[offset + 4]]) as usize;
        if wire[offset] == 23 {
            wire[end - 1] ^= 1;
            corrupted = true;
            break;
        }
        offset = end;
    }
    assert!(corrupted);
    tcp.write_all(&wire).await.unwrap();
    let mut rejected = false;
    for _ in 0..2 {
        let mut header = [0; 5];
        tokio::time::timeout(Duration::from_secs(1), tcp.read_exact(&mut header))
            .await
            .unwrap()
            .unwrap();
        let mut record = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
        tcp.read_exact(&mut record).await.unwrap();
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(&record);
        client.read_tls(&mut &bytes[..]).unwrap();
        if let Err(error) = client.process_new_packets() {
            assert!(matches!(
                error,
                rustls::Error::AlertReceived(rustls::AlertDescription::BadRecordMac)
            ));
            rejected = true;
            break;
        }
    }
    assert!(rejected);
    // The failed TLS handshake releases the only permit; it cannot create an
    // authenticated session merely because the server already issued a ticket.
    let _valid = fixture.tls().await;
}

#[tokio::test]
async fn reference_handshake_deadline_is_five_seconds() {
    let fixture = Fixture::new().await;
    let mut tcp = TcpStream::connect(("127.0.0.1", fixture.port))
        .await
        .unwrap();
    tcp.write_all(&[22, 3, 3]).await.unwrap();
    let start = tokio::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(6), closed(&mut tcp))
        .await
        .expect("partial TLS exceeded five seconds");
    assert!(start.elapsed() >= Duration::from_millis(4700));
}

#[tokio::test]
async fn reference_and_legacy_tls13_first_flights() {
    for enabled in [true, false] {
        let fixture = Fixture::with_policy(Some(enabled)).await;
        let mut client = rustls::ClientConnection::new(
            fixture.client.clone(),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        let mut tcp = TcpStream::connect(("127.0.0.1", fixture.port))
            .await
            .unwrap();
        tcp.write_all(&hello).await.unwrap();
        let mut encrypted = 0;
        let mut extensions = Vec::new();
        // Four handshake records plus one application-key ticket, without
        // sending the client's Finished. Legacy waits to issue tickets.
        let expected = if enabled { 5 } else { 1 };
        while encrypted < expected {
            let mut header = [0; 5];
            tokio::time::timeout(Duration::from_secs(1), tcp.read_exact(&mut header))
                .await
                .unwrap()
                .unwrap();
            let mut payload = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
            tcp.read_exact(&mut payload).await.unwrap();
            if header[0] == 23 {
                encrypted += 1;
            }
            if header[0] == 22 {
                let sid_len = payload[38] as usize;
                let mut offset = 44 + sid_len;
                while offset < payload.len() {
                    extensions.push(u16::from_be_bytes([payload[offset], payload[offset + 1]]));
                    offset +=
                        4 + u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
                }
            }
        }
        assert_eq!(
            extensions,
            if enabled { vec![43, 51] } else { vec![51, 43] }
        );
    }
}

#[tokio::test]
async fn default_tls_http_waits_until_auth_deadline() {
    let fixture = Fixture::new().await;
    let mut tls = fixture.tls().await;
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    tls.flush().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(4), closed(&mut tls))
            .await
            .is_err()
    );
    tokio::time::timeout(Duration::from_secs(2), closed(&mut tls))
        .await
        .unwrap();
}

#[tokio::test]
async fn default_fragmented_bad_auth_does_not_extend_deadline() {
    let fixture = Fixture::new().await;
    let mut tls = fixture.tls().await;
    tls.write_all(b"x").await.unwrap();
    tls.flush().await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    tls.write_all(&[b'x'; 31]).await.unwrap();
    tls.flush().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), closed(&mut tls))
            .await
            .is_err()
    );
    tokio::time::timeout(Duration::from_secs(2), closed(&mut tls))
        .await
        .unwrap();
}

fn frame(command: Command, data: &[u8]) -> Vec<u8> {
    let mut header = [0; HEADER_SIZE];
    FrameHeader {
        command,
        stream_id: 0,
        length: data.len() as u16,
    }
    .encode(&mut header);
    let mut frame = header.to_vec();
    frame.extend_from_slice(data);
    frame
}

async fn until<R: AsyncRead + Unpin>(io: &mut R, expected: Command) {
    loop {
        let mut bytes = [0; HEADER_SIZE];
        io.read_exact(&mut bytes).await.unwrap();
        let header = FrameHeader::decode(&bytes);
        let mut data = vec![0; header.length as usize];
        io.read_exact(&mut data).await.unwrap();
        if header.command == expected {
            return;
        }
        assert!(matches!(
            header.command,
            Command::Waste | Command::UpdatePaddingScheme
        ));
    }
}

#[tokio::test]
async fn valid_auth_is_immediate_and_session_survives_auth_deadline() {
    for policy in [None, Some(false)] {
        let fixture = Fixture::with_policy(policy).await;
        let mut tls = fixture.tls().await;
        let mut packet = Sha256::digest(b"probe-test").to_vec();
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(&frame(Command::Settings, b"v=2\npadding-md5=0"));
        // Coalesced authentication and Settings must retain all buffered bytes.
        tls.write_all(&packet).await.unwrap();
        tls.flush().await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            until(&mut tls, Command::ServerSettings),
        )
        .await
        .unwrap();
        if policy.is_none() {
            tokio::time::sleep(Duration::from_millis(5200)).await;
        }
        tls.write_all(&frame(Command::HeartRequest, &[]))
            .await
            .unwrap();
        tls.flush().await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            until(&mut tls, Command::HeartResponse),
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn rejected_peer_eof_releases_connection_permit_early() {
    let fixture = Fixture::new().await;
    let mut rejected = fixture.tls().await;
    rejected.write_all(&[b'x'; 32]).await.unwrap();
    rejected.flush().await.unwrap();
    rejected.shutdown().await.unwrap();
    drop(rejected);

    // The fixture has one connection permit. A second successful handshake
    // proves rejection does not keep that permit until the five-second deadline
    // after a peer has already disconnected.
    let _tls = tokio::time::timeout(Duration::from_secs(1), fixture.tls())
        .await
        .expect("disconnected rejected peer retained the sole connection permit");
}

#[tokio::test]
async fn fragmented_valid_client_hello_keeps_following_authentication_bytes() {
    let fixture = Fixture::new().await;
    let tap = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tap_port = tap.local_addr().unwrap().port();
    let server_port = fixture.port;
    let relay = tokio::spawn(async move {
        let (client, _) = tap.accept().await.unwrap();
        let server = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        server.set_nodelay(true).unwrap();
        let (mut client_read, mut client_write) = client.into_split();
        let (mut server_read, mut server_write) = server.into_split();
        let upload = async {
            let mut header = [0; 5];
            client_read.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 22);
            server_write.write_all(&header[..2]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            server_write.write_all(&header[2..]).await.unwrap();
            let mut hello = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
            client_read.read_exact(&mut hello).await.unwrap();
            for part in hello.chunks(128) {
                server_write.write_all(part).await.unwrap();
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            let _ = tokio::io::copy(&mut client_read, &mut server_write).await;
        };
        let download = async {
            let _ = tokio::io::copy(&mut server_read, &mut client_write).await;
        };
        tokio::join!(upload, download);
    });
    let tcp = TcpStream::connect(("127.0.0.1", tap_port)).await.unwrap();
    let mut tls = tokio::time::timeout(
        Duration::from_secs(2),
        TlsConnector::from(fixture.client.clone())
            .connect(ServerName::try_from("localhost").unwrap(), tcp),
    )
    .await
    .unwrap()
    .unwrap();
    let mut packet = Sha256::digest(b"probe-test").to_vec();
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&frame(Command::Settings, b"v=2\npadding-md5=0"));
    tls.write_all(&packet).await.unwrap();
    tls.flush().await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(1),
        until(&mut tls, Command::ServerSettings),
    )
    .await
    .unwrap();
    relay.abort();
}
