//! Criterion benchmarks: primitives, hybrid vs classical-only components,
//! full handshake latency, record-layer throughput.
//!
//! `cargo bench -p janus-bench`
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey};
use janus_bench::{configs, handshake, rng};
use janus_channel::{ChannelConfig, Deframer, channel};
use janus_core::kem::KemInitiator;
use janus_core::sig::IdentityKeypair;
use ml_dsa::{KeyInit as _, Keypair as _, MlDsa65};
use ml_kem::MlKem768;
use ml_kem::kem::{Decapsulate as _, Encapsulate as _, Kem as _};
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Each primitive on its own (no Janus code involved).
fn primitives(c: &mut Criterion) {
    let mut g = c.benchmark_group("primitive");
    let mut r = rng();

    g.bench_function("x25519 keygen+dh", |b| {
        let peer = PublicKey::from(&EphemeralSecret::random_from_rng(&mut r));
        let mut r = rng();
        b.iter(|| {
            let sk = EphemeralSecret::random_from_rng(&mut r);
            black_box(PublicKey::from(&sk));
            black_box(sk.diffie_hellman(&peer))
        });
    });

    let (dk, ek) = MlKem768::generate_keypair_from_rng(&mut r);
    let (ct, _) = ek.encapsulate_with_rng(&mut r);
    g.bench_function("ml-kem-768 keygen", |b| {
        let mut r = rng();
        b.iter(|| black_box(MlKem768::generate_keypair_from_rng(&mut r)));
    });
    g.bench_function("ml-kem-768 encaps", |b| {
        let mut r = rng();
        b.iter(|| black_box(ek.encapsulate_with_rng(&mut r)));
    });
    g.bench_function("ml-kem-768 decaps", |b| {
        b.iter(|| black_box(dk.decapsulate(&ct)))
    });

    let ed = EdSigningKey::from_bytes(&[7; 32]);
    let ed_vk = ed.verifying_key();
    let ed_sig = ed.sign(b"message");
    g.bench_function("ed25519 sign", |b| {
        b.iter(|| black_box(ed.sign(b"message")))
    });
    g.bench_function("ed25519 verify", |b| {
        b.iter(|| black_box(ed_vk.verify_strict(b"message", &ed_sig)))
    });

    let dsa = ml_dsa::SigningKey::<MlDsa65>::new(&[7; 32].into());
    let dsa_vk = dsa.verifying_key();
    let dsa_sig = dsa
        .expanded_key()
        .sign_deterministic(b"message", b"")
        .unwrap();
    g.bench_function("ml-dsa-65 sign", |b| {
        let mut r = rng();
        b.iter(|| black_box(dsa.expanded_key().sign_randomized(b"message", b"", &mut r)))
    });
    g.bench_function("ml-dsa-65 verify", |b| {
        b.iter(|| black_box(dsa_vk.verify_with_context(b"message", b"", &dsa_sig)))
    });
    g.finish();
}

/// Hybrid components vs. their classical-only counterpart.
fn hybrid_vs_classical(c: &mut Criterion) {
    let mut g = c.benchmark_group("kex (both sides)");
    g.bench_function("x25519 only", |b| {
        let mut r = rng();
        b.iter(|| {
            let a = EphemeralSecret::random_from_rng(&mut r);
            let a_pub = PublicKey::from(&a);
            let bb = EphemeralSecret::random_from_rng(&mut r);
            let b_pub = PublicKey::from(&bb);
            black_box(bb.diffie_hellman(&a_pub));
            black_box(a.diffie_hellman(&b_pub))
        });
    });
    g.bench_function("x25519 + ml-kem-768 (janus)", |b| {
        let mut r = rng();
        b.iter(|| {
            let init = KemInitiator::generate(&mut r);
            let (ct, ss) = init.public().encapsulate(&mut r).unwrap();
            black_box(ss);
            black_box(init.decapsulate(&ct).unwrap())
        });
    });
    g.finish();

    let mut g = c.benchmark_group("auth (sign + verify)");
    let ed = EdSigningKey::from_bytes(&[7; 32]);
    let ed_vk = ed.verifying_key();
    g.bench_function("ed25519 only", |b| {
        b.iter(|| {
            let s = ed.sign(b"transcript hash");
            black_box(ed_vk.verify_strict(b"transcript hash", &s))
        })
    });
    let id = IdentityKeypair::from_seed(&[3; 64]);
    g.bench_function("ed25519 + ml-dsa-65 (janus)", |b| {
        let mut r = rng();
        b.iter(|| {
            let s = id.sign(b"label", b"transcript hash", &mut r).unwrap();
            black_box(id.public().verify(b"label", b"transcript hash", &s))
        })
    });
    g.finish();
}

/// Full in-memory handshake: CPU latency of both sides together.
fn full_handshake(c: &mut Criterion) {
    let (client, server) = configs();
    c.bench_function("handshake/full (client+server, in memory)", |b| {
        b.iter(|| black_box(handshake(&client, &server).unwrap()))
    });
}

/// Record layer: seal on one side, deframe + open on the other.
fn records(c: &mut Criterion) {
    let (client, server) = configs();
    let mut g = c.benchmark_group("record seal+open");
    for size in [64usize, 1024, 16 * 1024] {
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let (cs, ss) = handshake(&client, &server).unwrap();
            let cfg = ChannelConfig::default();
            let (mut tx, _) = channel(cs, cfg).unwrap();
            let (_, mut rx) = channel(ss, cfg).unwrap();
            let msg = vec![0x5a; size];
            let mut d = Deframer::new();
            b.iter(|| {
                d.push(&tx.seal(&msg).unwrap());
                let f = d.next_frame().unwrap().unwrap();
                black_box(rx.open(&f).unwrap())
            });
        });
    }
    g.finish();
}

criterion_group!(
    benches,
    primitives,
    hybrid_vs_classical,
    full_handshake,
    records
);
criterion_main!(benches);
