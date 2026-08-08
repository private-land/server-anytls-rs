//! Benchmark: send_fin latency during PSH data flow.
//!
//! Measures how long send_fin takes when the writer task is actively
//! processing PSH data, exposing the lock contention between control
//! frames (FIN) and data frames (PSH).

use criterion::{Criterion, criterion_group, criterion_main};
use server_anytls_rs::core::frame::{Command, FrameHeader, HEADER_SIZE};
use server_anytls_rs::core::padding::{DEFAULT_SCHEME, PaddingFactory};
use server_anytls_rs::core::session::{Session, SessionConfig};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

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

/// Measure send_fin latency when no data is flowing (baseline).
fn bench_send_fin_idle(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("send_fin_idle", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (mut client_io, server_io) = tokio::io::duplex(1024 * 1024);
                let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
                let session = Arc::new(Session::new_server(
                    server_io,
                    padding,
                    SessionConfig::default(),
                ));

                let settings = format!("v=2\npadding-md5={}", session.padding_md5());
                write_frame(&mut client_io, Command::Settings, 0, settings.as_bytes()).await;

                let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(256);
                let sess = session.clone();
                let recv_handle = tokio::spawn(async move {
                    sess.recv_loop(new_stream_tx, CancellationToken::new())
                        .await
                });

                // Create 10 streams and immediately send FIN
                for stream_id in 1..=10u32 {
                    write_frame(&mut client_io, Command::Syn, stream_id, &[]).await;
                    let stream = new_stream_rx.recv().await.unwrap();
                    stream.send_fin().await.unwrap();
                }

                recv_handle.abort();
                let _ = recv_handle.await;
            })
        });
    });
}

/// Measure send_fin latency while data is flowing on other streams.
fn bench_send_fin_under_load(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("send_fin_under_load", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (mut client_io, server_io) = tokio::io::duplex(4 * 1024 * 1024);
                let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
                let session = Arc::new(Session::new_server(
                    server_io,
                    padding,
                    SessionConfig::default(),
                ));

                let settings = format!("v=2\npadding-md5={}", session.padding_md5());
                write_frame(&mut client_io, Command::Settings, 0, settings.as_bytes()).await;

                let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(256);
                let sess = session.clone();
                let recv_handle = tokio::spawn(async move {
                    sess.recv_loop(new_stream_tx, CancellationToken::new())
                        .await
                });

                // Create stream 1 and start flowing data through it
                write_frame(&mut client_io, Command::Syn, 1, &[]).await;
                let mut stream1 = new_stream_rx.recv().await.unwrap();

                // Spawn a task that continuously writes data through stream 1
                let writer_handle = tokio::spawn(async move {
                    let data = vec![0xAB_u8; 4096];
                    for _ in 0..200 {
                        if stream1.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    drop(stream1);
                });

                // While data is flowing, send FIN for new streams
                for stream_id in 2..=10u32 {
                    write_frame(&mut client_io, Command::Syn, stream_id, &[]).await;
                    let stream = new_stream_rx.recv().await.unwrap();
                    stream.send_fin().await.unwrap();
                }

                let _ = writer_handle.await;
                recv_handle.abort();
                let _ = recv_handle.await;
            })
        });
    });
}

criterion_group!(benches, bench_send_fin_idle, bench_send_fin_under_load);
criterion_main!(benches);
