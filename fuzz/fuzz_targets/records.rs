//! Arbitrary bytes through the deframer and a live receiver: no panic, and
//! nothing forged is ever accepted (the attacker does not know the keys, so
//! any accepted record would be a forgery).
#![no_main]

use janus_channel::{channel, ChannelConfig, Deframer};
use janus_core::handshake::{self, Config};
use janus_core::sig::IdentityKeypair;
use libfuzzer_sys::fuzz_target;

fn receiver() -> janus_channel::Receiver {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let c = IdentityKeypair::from_seed(&[1; 64]);
    let s = IdentityKeypair::from_seed(&[2; 64]);
    let client = Config {
        trust: [s.public().fingerprint()].into_iter().collect(),
        identity: c,
    };
    let server = Config {
        trust: [client.identity.public().fingerprint()].into_iter().collect(),
        identity: s,
    };
    let (st, m1) = handshake::client_start(&client, &mut rng);
    let (ss, m2) = handshake::server_accept(&server, &m1, &mut rng).expect("honest handshake");
    let (m3, _) = st.read_server_hello(&m2, &mut rng).expect("honest handshake");
    let session = ss.read_client_finish(&m3).expect("honest handshake");
    channel(session, ChannelConfig { rekey_interval: 2 }).expect("channel").1
}

fuzz_target!(|data: &[u8]| {
    let mut rx = receiver();
    let mut d = Deframer::new();
    // Feed in two chunks to exercise partial-frame handling.
    let (a, b) = data.split_at(data.len() / 2);
    for chunk in [a, b] {
        d.push(chunk);
        while let Ok(Some(frame)) = d.next_frame() {
            assert!(rx.open(&frame).is_err(), "forged record accepted");
        }
    }
    let _ = d.finish();
});
