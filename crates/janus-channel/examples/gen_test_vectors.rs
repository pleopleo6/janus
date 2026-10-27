//! Regenerate `docs/test-vectors/janus-v1.json`.
//!
//! `cargo run -p janus-channel --example gen_test_vectors`
//!
//! Only needed after an intentional wire-format change: the
//! `tests/vectors.rs` test fails until the file is regenerated.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]

use rand_core::SeedableRng as _;

#[path = "../tests/common/vectors.rs"]
#[allow(dead_code)]
mod vectors;

fn main() {
    let mut c = vectors::Source::Record(chacha20::ChaCha20Rng::from_seed([0xc1; 32]), Vec::new());
    let mut s = vectors::Source::Record(chacha20::ChaCha20Rng::from_seed([0x5e; 32]), Vec::new());
    let v = vectors::run(&mut c, &mut s);
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/test-vectors/janus-v1.json");
    std::fs::write(&path, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
    println!("wrote {}", path.display());
}
