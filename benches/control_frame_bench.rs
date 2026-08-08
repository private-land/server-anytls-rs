//! RED/GREEN benchmark: control frame latency.
//!
//! Measures round-trip time for control frames (SYN → SynAck) both when idle
//! and under data load, to expose flush/mutex contention issues.

use criterion::{Criterion, criterion_group, criterion_main};
use server_anytls_rs::core::frame::{Command, FrameHeader, HEADER_SIZE};
use server_anytls_rs::core::padding::{DEFAULT_SCHEME, PaddingFactory};
use server_anytls_rs::core::session::{Session, SessionConfig};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

/// Read frames from client_io until we find a specific command, return elapsed time.
async fn read_until_command<R: AsyncReadExt + Unpin>(r: &mut R, target_cmd: Command) {
    let mut hdr_buf = [0u8; HEADER_SIZE];
    loop {
        r.read_exact(&mut hdr_buf).await.unwrap();
        let hdr = FrameHeader::decode(&hdr_buf);
        if hdr.length > 0 {
            let mut skip = vec![0u8; hdr.length as usize];
            r.read_exact(&mut skip).await.unwrap();
        }
        if hdr.command == target_cmd {
            break;
        }
    }
}

/// Measure control frame latency when idle (no data load).
fn bench_control_frame_idle(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("control_frame_idle_synack", |b| {
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

                let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
                let sess = session.clone();
                let recv_handle = tokio::spawn(async move {
                    sess.recv_loop(new_stream_tx, CancellationToken::new())
                        .await
                });

                // Read back ServerSettings frame first
                read_until_command(&mut client_io, Command::ServerSettings).await;

                // Now measure SYN → SynAck latency (10 streams)
                for stream_id in 1..=10u32 {
                    write_frame(&mut client_io, Command::Syn, stream_id, &[]).await;
                    // Consume the stream on server side
                    let _stream = new_stream_rx.recv().await.unwrap();
                    // Caller is responsible for sending SynAck (like handler.rs does)
                    session.handshake_success(stream_id).await.unwrap();
                    // Read back SynAck from client side
                    read_until_command(&mut client_io, Command::SynAck).await;
                }

                recv_handle.abort();
                let _ = recv_handle.await;
            })
        });
    });
}

/// Measure control frame latency under data load.
/// While data is flowing on stream 1, measure how long it takes to get SynAck for stream 2.
fn bench_control_frame_under_load(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("control_frame_under_load_synack", |b| {
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

                // Read ServerSettings
                read_until_command(&mut client_io, Command::ServerSettings).await;

                // Create stream 1 and start flowing data through it
                write_frame(&mut client_io, Command::Syn, 1, &[]).await;
                let mut stream1 = new_stream_rx.recv().await.unwrap();

                // Spawn a task that writes data through stream 1 continuously
                let sess_write = session.clone();
                let writer_handle = tokio::spawn(async move {
                    let data = vec![0xAB_u8; 4096];
                    for _ in 0..200 {
                        if stream1.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    drop(stream1);
                });

                // While data is flowing, create new streams and measure SynAck latency
                for stream_id in 2..=10u32 {
                    write_frame(&mut client_io, Command::Syn, stream_id, &[]).await;
                    let _stream = new_stream_rx.recv().await.unwrap();
                    // Caller sends SynAck (competes with writer task for write_half mutex)
                    sess_write.handshake_success(stream_id).await.unwrap();
                    // Read until we find SynAck (skipping PSH frames from stream 1)
                    read_until_command(&mut client_io, Command::SynAck).await;
                }

                let _ = writer_handle.await;
                recv_handle.abort();
                let _ = recv_handle.await;
            })
        });
    });
}

criterion_group!(
    benches,
    bench_control_frame_idle,
    bench_control_frame_under_load
);
criterion_main!(benches);
