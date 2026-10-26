//! Print the handshake message sizes as a Markdown table, next to the sizes
//! the *same* protocol would have with classical primitives only
//! (X25519 + Ed25519).
//!
//! `cargo run -p janus-bench --example sizes`
#![allow(clippy::arithmetic_side_effects)] // sums of small constants

use janus_core::kem::{KEM_CIPHERTEXT_LEN, KEM_PUBLIC_LEN, X25519_PK_LEN};
use janus_core::messages::{
    CLIENT_FINISH_LEN, CLIENT_HELLO_LEN, FINISHED_LEN, HEADER_LEN, RANDOM_LEN, SERVER_HELLO_LEN,
};
use janus_core::sig::{ED25519_PK_LEN, ED25519_SIG_LEN, HYBRID_SIG_LEN, IDENTITY_PUBLIC_LEN};

fn main() {
    // Classical-only variant: same fields, X25519 share instead of the hybrid
    // KEM values, Ed25519 key / signature instead of the hybrid ones.
    let c_hello = HEADER_LEN + RANDOM_LEN + X25519_PK_LEN;
    let c_reply =
        HEADER_LEN + RANDOM_LEN + X25519_PK_LEN + ED25519_PK_LEN + ED25519_SIG_LEN + FINISHED_LEN;
    let c_finish = HEADER_LEN + ED25519_PK_LEN + ED25519_SIG_LEN + FINISHED_LEN;
    let rows = [
        ("ClientHello", CLIENT_HELLO_LEN, c_hello),
        ("ServerHello", SERVER_HELLO_LEN, c_reply),
        ("ClientFinish", CLIENT_FINISH_LEN, c_finish),
        (
            "**Total**",
            CLIENT_HELLO_LEN + SERVER_HELLO_LEN + CLIENT_FINISH_LEN,
            c_hello + c_reply + c_finish,
        ),
    ];
    println!("| Message | Hybrid (bytes) | Classical only (bytes) | Ratio |");
    println!("|---|---:|---:|---:|");
    for (name, h, c) in rows {
        #[allow(clippy::cast_precision_loss)]
        let ratio = h as f64 / c as f64;
        println!("| {name} | {h} | {c} | ×{ratio:.1} |");
    }
    println!();
    println!("Components: KEM public {KEM_PUBLIC_LEN} B, KEM ciphertext {KEM_CIPHERTEXT_LEN} B,");
    println!(
        "identity {IDENTITY_PUBLIC_LEN} B, hybrid signature {HYBRID_SIG_LEN} B (frame headers: +3 B per message)."
    );
}
