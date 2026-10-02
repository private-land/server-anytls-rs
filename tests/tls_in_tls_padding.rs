//! Observe encrypted outer TLS records while a real HTTPS HEAD request runs
//! through the production AnyTLS server. No TLS record boundaries are inferred
//! from TCP packet sizes or plaintext writer calls.

use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use server_anytls_rs::core::frame::{Command, FrameHeader, HEADER_SIZE};
use server_anytls_rs::core::padding::{DEFAULT_SCHEME, PaddingFactory};
use server_anytls_rs::{DirectRouter, Server, SinglePasswordAuth};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

static CRYPTO: Once = Once::new();
const PASSWORD: &str = "nested-tls-test";

fn tls_configs() -> (rustls::ServerConfig, Arc<rustls::ClientConfig>) {
    CRYPTO.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .unwrap();
    });
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    // Exclude outer/inner session tickets from the application record sample.
    server.send_tls13_tickets = 0;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (server, Arc::new(client))
}

fn frame(command: Command, stream_id: u32, data: &[u8]) -> Vec<u8> {
    let mut header = [0; HEADER_SIZE];
    FrameHeader {
        command,
        stream_id,
        length: data.len().try_into().unwrap(),
    }
    .encode(&mut header);
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(data);
    bytes
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> (FrameHeader, Vec<u8>) {
    let mut header = [0; HEADER_SIZE];
    reader.read_exact(&mut header).await.unwrap();
    let header = FrameHeader::decode(&header);
    let mut payload = vec![0; header.length as usize];
    reader.read_exact(&mut payload).await.unwrap();
    (header, payload)
}

fn record_lengths(bytes: &[u8]) -> Vec<usize> {
    let mut lengths = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        assert!(offset + 5 <= bytes.len(), "truncated TLS header");
        let length = u16::from_be_bytes([bytes[offset + 3], bytes[offset + 4]]) as usize;
        assert!(offset + 5 + length <= bytes.len(), "truncated TLS record");
        assert_eq!(bytes[offset], 23, "expected TLS 1.3 application record");
        lengths.push(length);
        offset += 5 + length;
    }
    lengths
}

async fn https_probe(
    burst_padding: Option<bool>,
    version: u8,
    matched: bool,
    enabled: bool,
) -> Vec<usize> {
    let (backend_tls, backend_client_tls) = tls_configs();
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend.local_addr().unwrap().port();
    let stop = CancellationToken::new();
    let backend_stop = stop.clone();
    let backend_task = tokio::spawn(async move {
        let (tcp, _) = backend.accept().await.unwrap();
        let mut tls = TlsAcceptor::from(Arc::new(backend_tls))
            .accept(tcp)
            .await
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(tls.read_u8().await.unwrap());
            assert!(request.len() < 1024);
        }
        assert_eq!(
            request,
            b"HEAD /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\n\r\n"
        );
        tls.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        tls.flush().await.unwrap();
        // Hold the connection open so TLS close_notify is not confused with
        // an AnyTLS application/control record in the sample.
        backend_stop.cancelled().await;
    });

    let (server_tls, client_tls) = tls_configs();
    let mut builder = Server::builder()
        .authenticator(Arc::new(SinglePasswordAuth::new(PASSWORD)))
        .router(Arc::new(DirectRouter))
        .tls_config(server_tls)
        .downlink_padding(enabled);
    if let Some(enabled) = burst_padding {
        builder = builder.downlink_burst_padding(enabled);
    }
    let server = Arc::new(builder.build().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let server_stop = stop.clone();
    let server_task = tokio::spawn(async move { server.run(listener, server_stop).await.unwrap() });

    // A transparent TCP tap captures the encrypted server-to-client byte
    // stream; the parser reconstructs TLS records independently of read sizes.
    let tap = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tap_port = tap.local_addr().unwrap().port();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let capture = captured.clone();
    let tap_task = tokio::spawn(async move {
        let (downstream, _) = tap.accept().await.unwrap();
        let upstream = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        let (mut dr, mut dw) = downstream.into_split();
        let (mut ur, mut uw) = upstream.into_split();
        let upload = async {
            tokio::io::copy(&mut dr, &mut uw).await.unwrap();
        };
        let download = async {
            let mut buf = [0; 4096];
            loop {
                let n = ur.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                capture.lock().unwrap().extend_from_slice(&buf[..n]);
                if dw.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        };
        tokio::join!(upload, download);
    });

    let tcp = TcpStream::connect(("127.0.0.1", tap_port)).await.unwrap();
    let mut outer = TlsConnector::from(client_tls)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(
        outer.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    let mut auth = Sha256::digest(PASSWORD.as_bytes()).to_vec();
    auth.extend_from_slice(&0u16.to_be_bytes());
    outer.write_all(&auth).await.unwrap();
    let settings = format!(
        "v={version}\npadding-md5={}",
        if matched {
            PaddingFactory::new(DEFAULT_SCHEME)
                .unwrap()
                .md5_hex()
                .to_owned()
        } else {
            "0".repeat(32)
        }
    );
    outer
        .write_all(&frame(Command::Settings, 0, settings.as_bytes()))
        .await
        .unwrap();
    if version >= 2 || !matched {
        let expected = if version >= 2 {
            Command::ServerSettings
        } else {
            Command::UpdatePaddingScheme
        };
        loop {
            let command = read_frame(&mut outer).await.0.command;
            assert!(
                command == expected
                    || command == Command::Waste
                    || command == Command::UpdatePaddingScheme
            );
            if command == expected {
                break;
            }
        }
    }
    outer.write_all(&frame(Command::Syn, 1, &[])).await.unwrap();
    let mut address = vec![1, 127, 0, 0, 1];
    address.extend_from_slice(&backend_port.to_be_bytes());
    outer
        .write_all(&frame(Command::Psh, 1, &address))
        .await
        .unwrap();
    if version >= 2 {
        loop {
            let (header, payload) = read_frame(&mut outer).await;
            if header.command == Command::SynAck {
                assert!(payload.is_empty());
                break;
            }
        }
    }
    captured.lock().unwrap().clear();

    // Bridge the AnyTLS stream into a byte stream usable by a second real TLS
    // client. Waste frames are discarded exactly as a protocol client does.
    let (inner_io, bridge_io) = tokio::io::duplex(64 * 1024);
    let (mut inner_read, mut inner_write) = tokio::io::split(bridge_io);
    let (mut outer_read, mut outer_write) = tokio::io::split(outer);
    let upload_task = tokio::spawn(async move {
        let mut buf = [0; 4096];
        loop {
            let n = inner_read.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            outer_write
                .write_all(&frame(Command::Psh, 1, &buf[..n]))
                .await
                .unwrap();
            outer_write.flush().await.unwrap();
        }
    });
    let download_task = tokio::spawn(async move {
        loop {
            let (header, payload) = read_frame(&mut outer_read).await;
            match header.command {
                Command::Psh if header.stream_id == 1 => {
                    inner_write.write_all(&payload).await.unwrap()
                }
                Command::Waste => {}
                command => panic!("unexpected command {command:?}"),
            }
        }
    });
    let mut inner = TlsConnector::from(backend_client_tls)
        .connect(ServerName::try_from("localhost").unwrap(), inner_io)
        .await
        .unwrap();
    inner
        .write_all(b"HEAD /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\n\r\n")
        .await
        .unwrap();
    inner.flush().await.unwrap();
    let expected = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
    let mut response = vec![0; expected.len()];
    inner.read_exact(&mut response).await.unwrap();
    assert_eq!(response, expected);
    let lengths = record_lengths(&captured.lock().unwrap());
    upload_task.abort();
    download_task.abort();
    tap_task.abort();
    stop.cancel();
    backend_task.await.unwrap();
    server_task.await.unwrap();
    lengths
}

#[tokio::test]
async fn test_https_204_early_downlink_records_are_padded() {
    let lengths = tokio::time::timeout(Duration::from_secs(10), https_probe(None, 2, true, true))
        .await
        .unwrap();
    println!("early padding enabled, encrypted TLS record lengths: {lengths:?}");
    assert!(
        lengths.len() >= 2,
        "missing TLS handshake/response: {lengths:?}"
    );
    assert!(
        lengths.iter().all(|&n| n >= 320 + 17),
        "short HTTPS response still exposed in outer TLS records: {lengths:?}"
    );
}

#[tokio::test]
async fn test_https_204_control_keeps_short_record() {
    let lengths = tokio::time::timeout(
        Duration::from_secs(10),
        https_probe(Some(false), 2, true, true),
    )
    .await
    .unwrap();
    println!("early padding disabled, encrypted TLS record lengths: {lengths:?}");
    assert!(
        lengths.iter().any(|&n| n < 160),
        "control no longer reproduces the short HTTPS response: {lengths:?}"
    );
}

#[tokio::test]
async fn test_v1_https_204_downlink_is_padded_with_matching_or_updated_scheme() {
    for matched in [true, false] {
        let lengths =
            tokio::time::timeout(Duration::from_secs(10), https_probe(None, 1, matched, true))
                .await
                .unwrap();
        println!("v1 matched={matched}, encrypted TLS record lengths: {lengths:?}");
        assert!(lengths.len() >= 2);
        assert!(
            lengths.iter().all(|&n| n >= 337),
            "v1 short response exposed: {lengths:?}"
        );
    }
}

#[tokio::test]
async fn test_v1_https_204_padding_off_preserves_short_record() {
    let lengths = tokio::time::timeout(Duration::from_secs(10), https_probe(None, 1, true, false))
        .await
        .unwrap();
    assert!(
        lengths.iter().any(|&n| n < 160),
        "off switch did not preserve short response: {lengths:?}"
    );
}
