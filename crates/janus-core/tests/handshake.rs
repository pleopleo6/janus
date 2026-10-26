//! End-to-end handshake tests through the public API only.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::OnceLock;

use janus_core::Error;
use janus_core::handshake::{self, Config, Session, TrustStore};
use janus_core::messages::{
    CLIENT_FINISH_LEN, CLIENT_HELLO_LEN, ClientFinish, ClientHello, SERVER_HELLO_LEN, ServerHello,
};
use janus_core::schedule::Role;
use janus_core::sig::IdentityKeypair;
use proptest::prelude::*;
use rand_core::UnwrapErr;

type Rng = UnwrapErr<getrandom::SysRng>;

fn rng() -> Rng {
    UnwrapErr(getrandom::SysRng)
}

struct Peers {
    client: Config,
    server: Config,
}

/// Identities are generated once: ML-DSA key generation is the slow part and
/// is irrelevant to what these tests check.
fn peers() -> &'static Peers {
    static PEERS: OnceLock<Peers> = OnceLock::new();
    PEERS.get_or_init(|| {
        let c = IdentityKeypair::from_seed(&[1; 64]);
        let s = IdentityKeypair::from_seed(&[2; 64]);
        Peers {
            client: Config {
                trust: [s.public().fingerprint()].into_iter().collect(),
                identity: c,
            },
            server: Config {
                trust: [IdentityKeypair::from_seed(&[1; 64]).public().fingerprint()]
                    .into_iter()
                    .collect(),
                identity: s,
            },
        }
    })
}

/// Raw transcript of one honest run.
struct Run {
    hello: Vec<u8>,
    reply: Vec<u8>,
    finish: Vec<u8>,
}

fn honest_run(client: &Config, server: &Config) -> (Run, Session, Session) {
    let mut rng = rng();
    let (c, hello) = handshake::client_start(client, &mut rng);
    let (s, reply) = handshake::server_accept(server, &hello, &mut rng).unwrap();
    let (finish, cs) = c.read_server_hello(&reply, &mut rng).unwrap();
    let ss = s.read_client_finish(&finish).unwrap();
    (
        Run {
            hello,
            reply,
            finish,
        },
        cs,
        ss,
    )
}

/// Which message of the handshake an attacker tampers with.
#[derive(Debug, Clone, Copy)]
enum Msg {
    Hello,
    Reply,
    Finish,
}

/// Run a handshake where `tamper` is applied to message `which` in flight.
/// Returns `Ok` only if *both* sides accepted.
fn run_with(which: Msg, tamper: impl FnOnce(&mut Vec<u8>)) -> Result<(Session, Session), Error> {
    let p = peers();
    let mut rng = rng();
    let mut tamper = Some(tamper);
    let mut maybe = |m: Msg, bytes: &mut Vec<u8>| {
        if std::mem::discriminant(&m) == std::mem::discriminant(&which)
            && let Some(t) = tamper.take()
        {
            t(bytes);
        }
    };
    let (c, mut hello) = handshake::client_start(&p.client, &mut rng);
    maybe(Msg::Hello, &mut hello);
    let (s, mut reply) = handshake::server_accept(&p.server, &hello, &mut rng)?;
    maybe(Msg::Reply, &mut reply);
    let (mut finish, cs) = c.read_server_hello(&reply, &mut rng)?;
    maybe(Msg::Finish, &mut finish);
    let ss = s.read_client_finish(&finish)?;
    Ok((cs, ss))
}

fn assert_matching(cs: Session, ss: Session) {
    assert_eq!(cs.role(), Role::Client);
    assert_eq!(ss.role(), Role::Server);
    assert_eq!(cs.session_id(), ss.session_id());
    assert_eq!(cs.peer(), peers().server.identity.public());
    assert_eq!(ss.peer(), peers().client.identity.public());
    let (c_send, c_recv) = cs.into_traffic_secrets();
    let (s_send, s_recv) = ss.into_traffic_secrets();
    let key = |t: &janus_core::schedule::TrafficSecret| *t.aead_key_iv().unwrap().key;
    assert_eq!(key(&c_send), key(&s_recv));
    assert_eq!(key(&s_send), key(&c_recv));
    assert_ne!(
        key(&c_send),
        key(&c_recv),
        "directions must use distinct keys"
    );
}

#[test]
fn honest_handshake_succeeds() {
    let p = peers();
    let (run, cs, ss) = honest_run(&p.client, &p.server);
    assert_eq!(run.hello.len(), CLIENT_HELLO_LEN);
    assert_eq!(run.reply.len(), SERVER_HELLO_LEN);
    assert_eq!(run.finish.len(), CLIENT_FINISH_LEN);
    assert_matching(cs, ss);
}

#[test]
fn messages_roundtrip_canonically() {
    let p = peers();
    let (run, _, _) = honest_run(&p.client, &p.server);
    assert_eq!(ClientHello::decode(&run.hello).unwrap().encode(), run.hello);
    assert_eq!(ServerHello::decode(&run.reply).unwrap().encode(), run.reply);
    assert_eq!(
        ClientFinish::decode(&run.finish).unwrap().encode(),
        run.finish
    );
}

#[test]
fn every_session_is_fresh() {
    let p = peers();
    let (r1, a, _) = honest_run(&p.client, &p.server);
    let (r2, b, _) = honest_run(&p.client, &p.server);
    assert_ne!(a.session_id(), b.session_id());
    assert_ne!(r1.hello, r2.hello, "ephemeral keys must differ");
    assert_ne!(r1.reply, r2.reply);
}

#[test]
fn untrusted_server_is_rejected() {
    let p = peers();
    let rogue = Config {
        identity: IdentityKeypair::from_seed(&[3; 64]),
        trust: p.server.trust.clone(),
    };
    let mut rng = rng();
    let (c, hello) = handshake::client_start(&p.client, &mut rng);
    let (_, reply) = handshake::server_accept(&rogue, &hello, &mut rng).unwrap();
    assert_eq!(
        c.read_server_hello(&reply, &mut rng).unwrap_err(),
        Error::UntrustedPeer
    );
}

#[test]
fn untrusted_client_is_rejected() {
    let p = peers();
    let rogue = Config {
        identity: IdentityKeypair::from_seed(&[4; 64]),
        trust: p.client.trust.clone(),
    };
    let mut rng = rng();
    let (c, hello) = handshake::client_start(&rogue, &mut rng);
    let (s, reply) = handshake::server_accept(&p.server, &hello, &mut rng).unwrap();
    let (finish, _) = c.read_server_hello(&reply, &mut rng).unwrap();
    assert_eq!(
        s.read_client_finish(&finish).unwrap_err(),
        Error::UntrustedPeer
    );
}

#[test]
fn empty_trust_store_trusts_nobody() {
    let p = peers();
    let lonely = Config {
        identity: IdentityKeypair::from_seed(&[1; 64]),
        trust: TrustStore::new(),
    };
    let mut rng = rng();
    let (c, hello) = handshake::client_start(&lonely, &mut rng);
    let (_, reply) = handshake::server_accept(&p.server, &hello, &mut rng).unwrap();
    assert_eq!(
        c.read_server_hello(&reply, &mut rng).unwrap_err(),
        Error::UntrustedPeer
    );
}

/// RFC 7748 implementations ignore the top bit of an X25519 public key, so
/// flipping it does not change the X25519 shared secret. The handshake must
/// still fail, because the transcript (hence the signature) covers the exact
/// bytes: this is transcript binding at work.
#[test]
fn x25519_high_bit_flip_is_caught_by_transcript() {
    let err = run_with(Msg::Hello, |m| *m.last_mut().unwrap() ^= 0x80).unwrap_err();
    assert_eq!(err, Error::BadSignature);
}

/// A tampered ML-KEM ciphertext decapsulates to a *different* key (implicit
/// rejection) rather than failing: the client must detect it.
#[test]
fn mlkem_ciphertext_flip_is_rejected() {
    let err = run_with(Msg::Reply, |m| m[34 + 100] ^= 1).unwrap_err();
    assert_eq!(err, Error::BadSignature);
}

/// Replacing the server's signature by one from another session fails.
#[test]
fn signature_from_another_session_is_rejected() {
    let p = peers();
    let (old, _, _) = honest_run(&p.client, &p.server);
    let range =
        janus_core::messages::SERVER_HELLO_ID_END..janus_core::messages::SERVER_HELLO_SIG_END;
    let err = run_with(Msg::Reply, |m| {
        m[range.clone()].copy_from_slice(&old.reply[range])
    })
    .unwrap_err();
    assert_eq!(err, Error::BadSignature);
}

/// Replaying a whole old `ClientFinish` to a fresh server state fails.
#[test]
fn replayed_client_finish_is_rejected() {
    let p = peers();
    let (old, _, _) = honest_run(&p.client, &p.server);
    let err = run_with(Msg::Finish, |m| m.copy_from_slice(&old.finish)).unwrap_err();
    assert_eq!(err, Error::BadSignature);
}

/// Reflection: feeding a peer its own kind of message, or messages out of
/// order, is rejected by the type byte.
#[test]
fn wrong_message_types_are_rejected() {
    let p = peers();
    let (run, _, _) = honest_run(&p.client, &p.server);
    let mut rng = rng();
    assert_eq!(
        handshake::server_accept(&p.server, &run.reply, &mut rng).unwrap_err(),
        Error::UnexpectedMessage
    );
    let (c, _) = handshake::client_start(&p.client, &mut rng);
    assert_eq!(
        c.read_server_hello(&run.hello, &mut rng).unwrap_err(),
        Error::UnexpectedMessage
    );
}

fn msg_strategy() -> impl Strategy<Value = (Msg, usize)> {
    prop_oneof![
        (0..CLIENT_HELLO_LEN).prop_map(|i| (Msg::Hello, i)),
        (0..SERVER_HELLO_LEN).prop_map(|i| (Msg::Reply, i)),
        (0..CLIENT_FINISH_LEN).prop_map(|i| (Msg::Finish, i)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// Round trip: honest runs always succeed with matching keys.
    #[test]
    fn prop_roundtrip(_seed in any::<u64>()) {
        let (cs, ss) = run_with(Msg::Hello, |_| {}).unwrap();
        assert_matching(cs, ss);
    }

    /// Altering any single byte of any message, in any way, makes the
    /// handshake fail on at least one side.
    #[test]
    fn prop_any_byte_flip_fails((which, idx) in msg_strategy(), mask in 1u8..=255) {
        let res = run_with(which, |m| m[idx] ^= mask);
        prop_assert!(res.is_err(), "tampering {which:?}[{idx}] ^= {mask:#04x} went unnoticed");
    }

    /// Truncating or extending any message fails.
    #[test]
    fn prop_length_changes_fail((which, cut) in msg_strategy(), extra in proptest::collection::vec(any::<u8>(), 1..8)) {
        prop_assert!(run_with(which, |m| m.truncate(cut)).is_err());
        prop_assert!(run_with(which, |m| m.extend_from_slice(&extra)).is_err());
    }

    /// The parsers never panic on arbitrary input (a light fuzz; the real
    /// fuzzing lives in `fuzz/`).
    #[test]
    fn prop_parsers_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..7000)) {
        let _ = ClientHello::decode(&bytes);
        let _ = ServerHello::decode(&bytes);
        let _ = ClientFinish::decode(&bytes);
    }
}
