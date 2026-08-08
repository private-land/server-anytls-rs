//! Benchmark: stream throughput under channel backpressure.
//!
//! Simulates a slow consumer that can't keep up with incoming PSH frames,
//! causing channel pressure. Measures whether streams survive and deliver
//! all data despite temporary channel fullness.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use server_anytls_rs::core::frame::{Command, FrameHeader, HEADER_SIZE};
use server_anytls_rs::core::padding::{DEFAULT_SCHEME, PaddingFactory};
use server_anytls_rs::core::session::{Session, SessionConfig};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const TOTAL_BYTES: usize = 2 * 1024 * 1024; // 2MB payload

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

/// Benchmark: burst-send frames faster than consumer reads them.
/// This exercises the channel backpressure path.
fn bench_channel_pressure(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("channel_pressure");
    group.throughput(Throughput::Bytes(TOTAL_BYTES as u64));
    group.sample_size(10);

    group.bench_function("burst_send_slow_consumer", |b| {
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

                // Burst-send all frames as fast as possible
                let frame_data = vec![0xAB_u8; 4096];
                let frame_count = TOTAL_BYTES / 4096;
                let feeder = tokio::spawn(async move {
                    for _ in 0..frame_count {
                        write_frame(&mut client_io, Command::Psh, 1, &frame_data).await;
                    }
                    write_frame(&mut client_io, Command::Fin, 1, &[]).await;
                    client_io
                });

                // Slow consumer: read with small buffer, adding micro-delays
                let mut total = 0;
                let mut buf = [0u8; 1024]; // small read buffer to simulate slow consumer
                while total < TOTAL_BYTES {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    total += n;
                }
                assert_eq!(
                    total, TOTAL_BYTES,
                    "stream lost data: expected {} but got {}",
                    TOTAL_BYTES, total
                );

                let _client_io = feeder.await.unwrap();
                recv_handle.abort();
                let _ = recv_handle.await;
            })
        });
    });

    group.finish();
}

criterion_group!(benches, bench_channel_pressure);
criterion_main!(benches);
