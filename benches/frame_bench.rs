use criterion::{Criterion, criterion_group, criterion_main};
use server_anytls_rs::core::frame::{Command, FrameHeader, HEADER_SIZE};

fn bench_frame_encode(c: &mut Criterion) {
    let header = FrameHeader {
        command: Command::Psh,
        stream_id: 12345,
        length: 4096,
    };
    let mut buf = [0u8; HEADER_SIZE];
    c.bench_function("frame_encode", |b| {
        b.iter(|| {
            header.encode(std::hint::black_box(&mut buf));
        })
    });
}

fn bench_frame_decode(c: &mut Criterion) {
    let buf: [u8; HEADER_SIZE] = [2, 0x00, 0x30, 0x39, 0x00, 0x10, 0x00];
    c.bench_function("frame_decode", |b| {
        b.iter(|| {
            let _ = FrameHeader::decode(std::hint::black_box(&buf));
        })
    });
}

criterion_group!(benches, bench_frame_encode, bench_frame_decode);
criterion_main!(benches);
