//! Benchmark: write_cmd channel capacity impact on download throughput.
//!
//! Compares capacity 256 vs 1024 with multiple concurrent streams writing
//! through the shared write_cmd channel (the download path).

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use server_anytls_rs::core::frame::{Command, FrameHeader, HEADER_SIZE};
use server_anytls_rs::core::padding::{DEFAULT_SCHEME, PaddingFactory};
use server_anytls_rs::core::session::{Session, SessionConfig};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const STREAM_COUNT: usize = 5;
const WRITES_PER_STREAM: usize = 100;
const CHUNK_SIZE: usize = 4096;
const TOTAL_BYTES: usize = STREAM_COUNT * WRITES_PER_STREAM * CHUNK_SIZE; // 2MB

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

async fn run_multi_stream_download(write_cmd_capacity: usize) {
    let (mut client_io, server_io) = tokio::io::duplex(4 * 1024 * 1024);
    let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
    let config = SessionConfig {
        write_cmd_capacity,
        ..SessionConfig::default()
    };
    let session = Arc::new(Session::new_server(server_io, padding, config));

    let settings = format!("v=2\npadding-md5={}", session.padding_md5());
    write_frame(&mut client_io, Command::Settings, 0, settings.as_bytes()).await;

    // Create streams
    for i in 1..=STREAM_COUNT as u32 {
        write_frame(&mut client_io, Command::Syn, i, &[]).await;
    }

    let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(16);
    let sess = session.clone();
    let recv_handle = tokio::spawn(async move {
        sess.recv_loop(new_stream_tx, CancellationToken::new())
            .await
    });

    let mut streams = Vec::new();
    for _ in 0..STREAM_COUNT {
        streams.push(new_stream_rx.recv().await.unwrap());
    }

    // All streams write concurrently through shared write_cmd channel
    let chunk = vec![0xCD_u8; CHUNK_SIZE];
    let mut write_handles = Vec::new();
    for mut stream in streams {
        let data = chunk.clone();
        write_handles.push(tokio::spawn(async move {
            for _ in 0..WRITES_PER_STREAM {
                stream.write_all(&data).await.unwrap();
            }
        }));
    }

    // Drain output
    let drain = tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        loop {
            match client_io.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });

    for h in write_handles {
        h.await.unwrap();
    }

    drain.abort();
    recv_handle.abort();
    let _ = recv_handle.await;
}

fn bench_write_cmd_capacity(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("write_cmd_capacity");
    group.throughput(Throughput::Bytes(TOTAL_BYTES as u64));
    group.sample_size(20);

    group.bench_function("capacity_256_5streams", |b| {
        b.iter(|| rt.block_on(run_multi_stream_download(256)));
    });

    group.bench_function("capacity_512_5streams", |b| {
        b.iter(|| rt.block_on(run_multi_stream_download(512)));
    });

    group.bench_function("capacity_1024_5streams", |b| {
        b.iter(|| rt.block_on(run_multi_stream_download(1024)));
    });

    group.finish();
}

criterion_group!(benches, bench_write_cmd_capacity);
criterion_main!(benches);
