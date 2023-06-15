use criterion::{black_box, criterion_main, criterion_group, Criterion};

fn read_boc(filename: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut file = std::fs::File::open(filename).unwrap();
    std::io::Read::read_to_end(&mut file, &mut bytes).unwrap();
    bytes
}

fn bench_boc_write(c: &mut Criterion) {
    let bytes = read_boc("src/tests/data/medium.boc");
    let cell = ton_types::read_single_root_boc(bytes).unwrap();
    let mut g = c.benchmark_group("bench");
    g.measurement_time(std::time::Duration::new(15, 0));
    g.bench_function("boc-write", |b| b.iter( || {
        black_box(ton_types::write_boc(&cell).unwrap());
    }));
}

criterion_group!(
    benches,
    bench_boc_write,
);
criterion_main!(benches);
