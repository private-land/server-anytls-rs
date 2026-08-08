//! RED/GREEN benchmark: Stream::poll_write allocation overhead.
//!
//! Measures the cost of writing data through a Stream, which currently
//! allocates via Bytes::copy_from_slice on every call.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use server_anytls_rs::core::session::DEFAULT_STREAM_CHANNEL_CAPACITY;
use server_anytls_rs::core::stream::{Stream, WriteCommand};
use tokio::io::AsyncWriteExt;

const WRITE_COUNT: usize = 10_000;
const WRITE_SIZE: usize = 4096;

fn bench_stream_write(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let total_bytes = (WRITE_COUNT * WRITE_SIZE) as u64;

    let mut group = c.benchmark_group("stream_write");
    group.throughput(Throughput::Bytes(total_bytes));
    group.sample_size(20);

    group.bench_function("poll_write_alloc", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (session_tx, mut session_rx) = tokio::sync::mpsc::channel::<WriteCommand>(256);
                let (_data_tx, mut stream) =
                    Stream::new(1, session_tx, DEFAULT_STREAM_CHANNEL_CAPACITY);

                // Drain the channel in a background task
                let drain = tokio::spawn(async move { while session_rx.recv().await.is_some() {} });

                let data = vec![0xAB_u8; WRITE_SIZE];
                for _ in 0..WRITE_COUNT {
                    stream.write_all(&data).await.unwrap();
                }
                drop(stream);
                let _ = drain.await;
            })
        });
    });

    group.finish();
}

criterion_group!(benches, bench_stream_write);
criterion_main!(benches);
