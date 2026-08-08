//! RED/GREEN benchmark: copy_bidirectional buffer size (8KB vs 64KB).
//!
//! Simulates the relay path: data flows through Stream (which uses channels)
//! and measures how copy_bidirectional buffer size affects throughput.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use server_anytls_rs::core::frame::{Command, FrameHeader, HEADER_SIZE};
use server_anytls_rs::core::padding::{DEFAULT_SCHEME, PaddingFactory};
use server_anytls_rs::core::session::{Session, SessionConfig};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

const TOTAL_BYTES: usize = 4 * 1024 * 1024; // 4MB of payload

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

/// Benchmark copy_bidirectional with configurable buffer size.
/// Simulates: client → PSH frames → recv_loop → Stream → copy → remote_write
fn bench_relay(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("relay_copy");
    group.throughput(Throughput::Bytes(TOTAL_BYTES as u64));
    group.sample_size(15);

    for &buf_size in &[8192usize, 65536] {
        group.bench_function(format!("copy_bidirectional_{}k", buf_size / 1024), |b| {
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
                    write_frame(&mut client_io, Command::Syn, 1, &[]).await;

                    let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
                    let sess = session.clone();
                    let recv_handle = tokio::spawn(async move {
                        sess.recv_loop(new_stream_tx, CancellationToken::new())
                            .await
                    });

                    let mut stream = new_stream_rx.recv().await.unwrap();

                    // Feed PSH frames from "client" side
                    let frame_data = vec![0xAB_u8; 4096];
                    let frame_count = TOTAL_BYTES / 4096;
                    let feeder = tokio::spawn(async move {
                        for _ in 0..frame_count {
                            write_frame(&mut client_io, Command::Psh, 1, &frame_data).await;
                        }
                        // Send Fin to close the stream's data channel
                        write_frame(&mut client_io, Command::Fin, 1, &[]).await;
                        client_io
                    });

                    // "remote" end — a duplex pipe that discards writes and provides EOF on read
                    let (mut remote, mut remote_sink) = tokio::io::duplex(256 * 1024);
                    // Close remote's write side immediately (no data flows remote→stream)
                    remote_sink.shutdown().await.unwrap();
                    drop(remote_sink);

                    // Run copy_bidirectional with the specific buffer size
                    let _ = tokio::io::copy_bidirectional_with_sizes(
                        &mut stream,
                        &mut remote,
                        buf_size,
                        buf_size,
                    )
                    .await;

                    let _client_io = feeder.await.unwrap();
                    recv_handle.abort();
                    let _ = recv_handle.await;
                })
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_relay);
criterion_main!(benches);
