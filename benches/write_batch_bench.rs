//! RED/GREEN benchmark: session write/read throughput.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use server_anytls_rs::core::frame::{Command, FrameHeader, HEADER_SIZE};
use server_anytls_rs::core::padding::{DEFAULT_SCHEME, PaddingFactory};
use server_anytls_rs::core::session::{Session, SessionConfig};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const FRAME_COUNT: usize = 500;
const FRAME_SIZE: usize = 4096;

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

/// Write path: Stream.write → channel → write_task → transport → reader.
fn bench_write_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let total_bytes = (FRAME_COUNT * FRAME_SIZE) as u64;

    let mut group = c.benchmark_group("write_path");
    group.throughput(Throughput::Bytes(total_bytes));
    group.sample_size(20);

    group.bench_function("session_write_throughput", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Use two separate duplex pairs to avoid shutdown issues:
                // pair1: client_write → server_read (for sending Settings/Syn to recv_loop)
                // pair2: server_write → client_read (recv_loop writes PSH back)
                //
                // Actually, use a single duplex but with explicit abort for cleanup.
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

                // Writer: push data through Stream
                let write_data = vec![0xAB_u8; FRAME_SIZE];
                for _ in 0..FRAME_COUNT {
                    stream.write_all(&write_data).await.unwrap();
                }
                drop(stream);

                // Read back all PSH frames from client side.
                // We know exactly how many payload bytes to expect.
                let mut total_payload = 0usize;
                let mut hdr_buf = [0u8; HEADER_SIZE];
                while total_payload < total_bytes as usize {
                    client_io.read_exact(&mut hdr_buf).await.unwrap();
                    let hdr = FrameHeader::decode(&hdr_buf);
                    if hdr.length > 0 {
                        let mut skip = vec![0u8; hdr.length as usize];
                        client_io.read_exact(&mut skip).await.unwrap();
                    }
                    if hdr.command == Command::Psh {
                        total_payload += hdr.length as usize;
                    }
                }
                assert_eq!(total_payload, total_bytes as usize);

                // Cleanup: abort recv_loop (it's blocked waiting for more frames)
                recv_handle.abort();
                let _ = recv_handle.await;
            })
        });
    });

    group.finish();
}

/// Read path: client PSH frames → recv_loop → Stream.read.
fn bench_read_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let total_bytes = (FRAME_COUNT * FRAME_SIZE) as u64;

    let mut group = c.benchmark_group("read_path");
    group.throughput(Throughput::Bytes(total_bytes));
    group.sample_size(20);

    group.bench_function("session_read_throughput", |b| {
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

                // Client writes FRAME_COUNT PSH frames then EOF
                let data = vec![0xAB_u8; FRAME_SIZE];
                for _ in 0..FRAME_COUNT {
                    write_frame(&mut client_io, Command::Psh, 1, &data).await;
                }
                drop(client_io);

                // Server reads all data through Stream
                let mut total = 0;
                let mut buf = [0u8; 8192];
                loop {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    total += n;
                }
                assert_eq!(total, FRAME_COUNT * FRAME_SIZE);
                let _ = recv_handle.await;
            })
        });
    });

    group.finish();
}

criterion_group!(benches, bench_write_throughput, bench_read_throughput);
criterion_main!(benches);
