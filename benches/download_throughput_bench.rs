//! RED/GREEN benchmark: download-direction throughput (remote → client).
//!
//! Uses real TLS connections (localhost) to capture TLS record overhead
//! from the writer task's flush pattern.
//!
//! The Go version achieves ~108 Mbps while Rust only ~6 Mbps on the same node.
//! This bench isolates the bottleneck by measuring throughput of data flowing
//! from "remote" back through the session to the "client" over actual TLS.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use server_anytls_rs::core::frame::{Command, FrameHeader, HEADER_SIZE};
use server_anytls_rs::core::padding::{DEFAULT_SCHEME, PaddingFactory};
use server_anytls_rs::core::session::{Session, SessionConfig};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

const TOTAL_BYTES: usize = 16 * 1024 * 1024; // 16MB payload

fn make_tls_configs() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let cert = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    (Arc::new(server_config), Arc::new(client_config))
}

async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, cmd: Command, sid: u32, data: &[u8]) {
    let header = FrameHeader {
        command: cmd,
        stream_id: sid,
        length: data.len() as u16,
    };
    let mut hdr_buf = [0u8; HEADER_SIZE];
    header.encode(&mut hdr_buf);
    w.write_all(&hdr_buf).await.unwrap();
    if !data.is_empty() {
        w.write_all(data).await.unwrap();
    }
}

/// Benchmark download throughput over real TLS.
fn bench_download_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (server_tls_config, client_tls_config) = make_tls_configs();

    // Pre-compute padding md5 (deterministic for the same scheme)
    let padding_md5 = {
        let p = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
        p.md5_hex().to_string()
    };

    let mut group = c.benchmark_group("download_tls");
    group.throughput(Throughput::Bytes(TOTAL_BYTES as u64));
    group.sample_size(10);

    for &buf_size in &[65536_usize, 262144] {
        group.bench_function(format!("buf_{}k", buf_size / 1024), |b| {
            let server_cfg = server_tls_config.clone();
            let client_cfg = client_tls_config.clone();
            let md5 = padding_md5.clone();

            b.iter(|| {
                rt.block_on(async {
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let addr = listener.local_addr().unwrap();
                    let acceptor = TlsAcceptor::from(server_cfg.clone());
                    let connector = TlsConnector::from(client_cfg.clone());
                    let md5_clone = md5.clone();

                    // Server side
                    let server_handle = tokio::spawn(async move {
                        let (tcp, _) = listener.accept().await.unwrap();
                        let tls_stream = acceptor.accept(tcp).await.unwrap();

                        let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
                        let session = Arc::new(Session::new_server(
                            tls_stream,
                            padding,
                            SessionConfig::default(),
                        ));

                        let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
                        let sess = session.clone();
                        let cancel = CancellationToken::new();
                        let cancel2 = cancel.clone();
                        let recv_handle = tokio::spawn(async move {
                            sess.recv_loop(new_stream_tx, cancel2).await
                        });

                        let stream = new_stream_rx.recv().await.unwrap();

                        // Remote data source
                        let (remote, mut remote_source) = tokio::io::duplex(4 * 1024 * 1024);

                        let feeder = tokio::spawn(async move {
                            let chunk = vec![0xAB_u8; buf_size];
                            let mut remaining = TOTAL_BYTES;
                            while remaining > 0 {
                                let n = remaining.min(buf_size);
                                remote_source.write_all(&chunk[..n]).await.unwrap();
                                remaining -= n;
                            }
                            remote_source.shutdown().await.unwrap();
                        });

                        // Download: remote → stream (the bottleneck path)
                        let (_stream_read, stream_write) = tokio::io::split(stream);
                        let (remote_read, _remote_write) = tokio::io::split(remote);

                        let download = tokio::spawn(async move {
                            let mut sr = remote_read;
                            let mut sw = stream_write;
                            tokio::io::copy_buf(
                                &mut tokio::io::BufReader::with_capacity(buf_size, &mut sr),
                                &mut sw,
                            )
                            .await
                        });

                        let copied = download.await.unwrap().unwrap();
                        assert_eq!(copied, TOTAL_BYTES as u64);

                        feeder.await.unwrap();
                        cancel.cancel();
                        recv_handle.abort();
                        let _ = recv_handle.await;
                    });

                    // Client side
                    let client_handle = tokio::spawn(async move {
                        let tcp = TcpStream::connect(addr).await.unwrap();
                        let server_name =
                            rustls::pki_types::ServerName::try_from("localhost").unwrap();
                        let mut tls = connector.connect(server_name, tcp).await.unwrap();

                        // Send Settings + SYN with correct padding md5
                        let settings = format!("v=2\npadding-md5={}", md5_clone);
                        write_frame(&mut tls, Command::Settings, 0, settings.as_bytes()).await;
                        write_frame(&mut tls, Command::Syn, 1, &[]).await;
                        tls.flush().await.unwrap();

                        // Drain all received data
                        let mut buf = vec![0u8; 256 * 1024];
                        loop {
                            match tls.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                    });

                    server_handle.await.unwrap();
                    client_handle.await.unwrap();
                })
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_download_throughput);
criterion_main!(benches);
