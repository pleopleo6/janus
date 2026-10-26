//! Test helper: run a real handshake and return both sessions.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use janus_core::handshake::{self, Config, Session};
use janus_core::sig::IdentityKeypair;

pub(crate) fn session_pair() -> (Session, Session) {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
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
    let (c, hello) = handshake::client_start(&client, &mut rng);
    let (s, reply) = handshake::server_accept(&server, &hello, &mut rng).unwrap();
    let (finish, cs) = c.read_server_hello(&reply, &mut rng).unwrap();
    let ss = s.read_client_finish(&finish).unwrap();
    (cs, ss)
}
