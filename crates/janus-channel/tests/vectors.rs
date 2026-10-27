//! The committed test vectors must be reproduced exactly by this
//! implementation. Any change to the wire format, the key schedule, a label
//! or the order in which randomness is drawn makes this test fail.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]

use std::collections::VecDeque;

#[allow(dead_code)] // `Source::Record` is only used by the generator example
mod common {
    pub mod vectors;
}
use common::vectors::{self, Source};

const VECTORS: &str = include_str!("../../../docs/test-vectors/janus-v1.json");

fn draws(v: &serde_json::Value) -> VecDeque<Vec<u8>> {
    v["randomness"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| hex::decode(d["bytes"].as_str().unwrap()).unwrap())
        .collect()
}

#[test]
fn committed_vectors_are_reproduced_exactly() {
    let expected: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let client_draws = draws(&expected["client"]);
    vectors::REPLAYED.with(|r| *r.borrow_mut() = client_draws.iter().cloned().collect());
    let mut c: Source<chacha20::ChaCha20Rng> = Source::Replay(client_draws);
    let mut s: Source<chacha20::ChaCha20Rng> = Source::Replay(draws(&expected["server"]));
    let got = vectors::run(&mut c, &mut s);
    for key in [
        "messages",
        "session_id",
        "intermediate",
        "records",
        "rekey_interval",
    ] {
        assert_eq!(
            got[key], expected[key],
            "{key} differs from the committed vectors"
        );
    }
    for side in ["client", "server"] {
        for key in ["identity_public", "fingerprint"] {
            assert_eq!(got[side][key], expected[side][key], "{side}.{key}");
        }
    }
    // All recorded randomness was consumed.
    for src in [c, s] {
        let Source::Replay(q) = src else {
            unreachable!()
        };
        assert!(q.is_empty(), "unused randomness");
    }
}

#[test]
fn vectors_have_expected_shape() {
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let len = |k: &str| v["messages"][k].as_str().unwrap().len() / 2;
    assert_eq!(len("client_hello"), 1250);
    assert_eq!(len("server_hello"), 6559);
    assert_eq!(len("client_finish"), 5407);
    assert_eq!(v["records"].as_array().unwrap().len(), 5);
}
