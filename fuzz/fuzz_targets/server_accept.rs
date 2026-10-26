//! A server fed an arbitrary first message must fail cleanly (or, for a
//! valid `ClientHello`, produce a well-formed `ServerHello`).
#![no_main]

use std::sync::OnceLock;

use janus_core::handshake::{self, Config};
use janus_core::messages::{ServerHello, SERVER_HELLO_LEN};
use janus_core::sig::IdentityKeypair;
use libfuzzer_sys::fuzz_target;

fn config() -> &'static Config {
    static C: OnceLock<Config> = OnceLock::new();
    C.get_or_init(|| Config {
        identity: IdentityKeypair::from_seed(&[2; 64]),
        trust: [IdentityKeypair::from_seed(&[1; 64]).public().fingerprint()]
            .into_iter()
            .collect(),
    })
}

fuzz_target!(|data: &[u8]| {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    if let Ok((_, reply)) = handshake::server_accept(config(), data, &mut rng) {
        assert_eq!(reply.len(), SERVER_HELLO_LEN);
        assert!(ServerHello::decode(&reply).is_ok());
    }
});
