use criterion::{Criterion, criterion_group, criterion_main};
use server_anytls_rs::core::frame::{Command, FrameHeader, HEADER_SIZE};
use server_anytls_rs::core::padding::{DEFAULT_SCHEME, PaddingFactory};
use server_anytls_rs::core::session::{Session, SessionConfig};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio_util::sync::CancellationToken;

fn bench_session_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    c.bench_function("session_psh_1kb_frames", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (mut client_io, server_io) = duplex(1024 * 1024);
                let padding = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
                let session = Arc::new(Session::new_server(
                    server_io,
                    padding,
                    SessionConfig::default(),
                ));
                let (new_stream_tx, mut new_stream_rx) = tokio::sync::mpsc::channel(8);
                let settings = format!("v=2\npadding-md5={}", session.padding_md5());
                write_frame(&mut client_io, Command::Settings, 0, settings.as_bytes()).await;
                let sess = session.clone();
                let handle = tokio::spawn(async move {
                    sess.recv_loop(new_stream_tx, CancellationToken::new())
                        .await
                });
                write_frame(&mut client_io, Command::Syn, 1, &[]).await;
                let mut stream = new_stream_rx.recv().await.unwrap();
                let data = vec![0xAB_u8; 1024];
                for _ in 0..100 {
                    write_frame(&mut client_io, Command::Psh, 1, &data).await;
                }
                let mut total = 0;
                let mut buf = [0u8; 4096];
                while total < 100 * 1024 {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    total += n;
                }
                assert_eq!(total, 100 * 1024);
                drop(client_io);
                let _ = handle.await;
            })
        })
    });
}

async fn write_frame<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    cmd: Command,
    stream_id: u32,
    data: &[u8],
) {
    let header = FrameHeader {
        command: cmd,
        stream_id,
        length: data.len() as u16,
    };
    let mut hdr_buf = [0u8; HEADER_SIZE];
    header.encode(&mut hdr_buf);
    w.write_all(&hdr_buf).await.unwrap();
    if !data.is_empty() {
        w.write_all(data).await.unwrap();
    }
}

criterion_group!(benches, bench_session_throughput);
criterion_main!(benches);
