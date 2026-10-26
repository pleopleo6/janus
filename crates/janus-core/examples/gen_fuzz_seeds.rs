//! Write honest handshake messages to `fuzz/seeds/<target>/` as starting
//! corpora: random inputs almost never reach the inner checks (the exact
//! lengths and a decodable Ed25519 point are needed first).
//!
//! `cargo run -p janus-core --example gen_fuzz_seeds`
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::Path;

use janus_core::handshake::{self, Config};
use janus_core::sig::IdentityKeypair;

fn main() {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    // Same seeds as the fuzz targets' fixed configuration.
    let c = IdentityKeypair::from_seed(&[1; 64]);
    let s = IdentityKeypair::from_seed(&[2; 64]);
    let client = Config {
        trust: [s.public().fingerprint()].into_iter().collect(),
        identity: c,
    };
    let server = Config {
        trust: [client.identity.public().fingerprint()]
            .into_iter()
            .collect(),
        identity: s,
    };
    let (st, hello) = handshake::client_start(&client, &mut rng);
    let (_, reply) = handshake::server_accept(&server, &hello, &mut rng).unwrap();
    let (finish, _) = st.read_server_hello(&reply, &mut rng).unwrap();

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds");
    for (dir, msg) in [
        ("client_hello", &hello),
        ("server_hello", &reply),
        ("client_finish", &finish),
        ("server_accept", &hello),
    ] {
        let d = root.join(dir);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("honest"), msg).unwrap();
    }
    println!("seeds written to {}", root.display());
}
