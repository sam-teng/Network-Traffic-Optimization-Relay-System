use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use crate::ndcode_tun_engine::NDcodeTunEngine;
use rand::Rng;

fn generate_sample_data(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..size).map(|_| rng.gen::<u8>()).collect()
}

fn bench_outgoing_pipeline(c: &mut Criterion) {
    let engine = NDcodeTunEngine::new();
    let mut group = c.benchmark_group("NDcode3_Outgoing_Encoding");

    // 測試各種標準網路封包大小: 64B (ACK), 1500B (Standard MTU), 8192B (Jumbo Frame)
    let packet_sizes = [64, 512, 1500, 8192];

    for size in packet_sizes.iter() {
        let packet = generate_sample_data(*size);
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let _ = engine.process_outgoing_packet(&packet);
            });
        });
    }
    group.finish();
}

fn bench_incoming_pipeline(c: &mut Criterion) {
    let engine = NDcodeTunEngine::new();
    let mut group = c.benchmark_group("NDcode3_Incoming_Decoding");

    let packet_sizes = [1500, 8192];

    for size in packet_sizes.iter() {
        let raw_packet = generate_sample_data(*size);
        let compressed_payload = engine.process_outgoing_packet(&raw_packet).unwrap();

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let _ = engine.process_incoming_payload(&compressed_payload);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_outgoing_pipeline, bench_incoming_pipeline);
criterion_main!(benches);
