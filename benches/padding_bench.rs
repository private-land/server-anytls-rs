use criterion::{Criterion, criterion_group, criterion_main};
use server_anytls_rs::core::padding::{DEFAULT_SCHEME, PaddingFactory};

fn bench_padding_parse(c: &mut Criterion) {
    c.bench_function("padding_parse", |b| {
        b.iter(|| {
            let _ = PaddingFactory::new(std::hint::black_box(DEFAULT_SCHEME)).unwrap();
        })
    });
}

fn bench_padding_generate(c: &mut Criterion) {
    let factory = PaddingFactory::new(DEFAULT_SCHEME).unwrap();
    c.bench_function("padding_generate_pkt0", |b| {
        b.iter(|| {
            factory.generate_record_payload_sizes(std::hint::black_box(0));
        })
    });
    c.bench_function("padding_generate_pkt2_with_checkmarks", |b| {
        b.iter(|| {
            factory.generate_record_payload_sizes(std::hint::black_box(2));
        })
    });
}

criterion_group!(benches, bench_padding_parse, bench_padding_generate);
criterion_main!(benches);
