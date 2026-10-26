#![forbid(unsafe_code)]
//! Shared helpers for the Janus benchmarks (`benches/janus.rs`) and the
//! message-size report (`examples/sizes.rs`).

use janus_core::handshake::{self, Config, Session};
use janus_core::sig::IdentityKeypair;
use rand_core::UnwrapErr;

/// The OS RNG (benchmarks may panic on RNG failure).
pub fn rng() -> UnwrapErr<getrandom::SysRng> {
    UnwrapErr(getrandom::SysRng)
}

/// A client and a server configuration that trust each other.
pub fn configs() -> (Config, Config) {
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
    (client, server)
}

/// One complete in-memory handshake.
///
/// # Errors
/// Only if the handshake fails (it does not between honest peers).
pub fn handshake(client: &Config, server: &Config) -> janus_core::Result<(Session, Session)> {
    let mut rng = rng();
    let (c, m1) = handshake::client_start(client, &mut rng);
    let (s, m2) = handshake::server_accept(server, &m1, &mut rng)?;
    let (m3, cs) = c.read_server_hello(&m2, &mut rng)?;
    Ok((cs, s.read_client_finish(&m3)?))
}
