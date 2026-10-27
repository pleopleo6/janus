// Shared by `tests/vectors.rs` and `examples/gen_test_vectors.rs`.
//
// A full Janus v1 exchange is run with *recorded* randomness: every call to
// the RNG is logged as one byte string, in order. The JSON vectors list these
// strings, so another implementation can inject them and must then produce
// byte-identical messages, session id, traffic keys and records.

use std::collections::VecDeque;
use std::convert::Infallible;

use janus_channel::{ChannelConfig, Deframer, Received, channel};
use janus_core::handshake::{self, Config};
use janus_core::sig::IdentityKeypair;
use rand_core::{TryCryptoRng, TryRng};
use serde_json::{Value, json};

pub const CLIENT_SEED: [u8; 64] = [0x11; 64];
pub const SERVER_SEED: [u8; 64] = [0x22; 64];
pub const REKEY_INTERVAL: u64 = 2;
pub const CLIENT_DRAWS: [(&str, usize); 4] = [
    ("X25519 ephemeral secret key", 32),
    ("ML-KEM-768 key generation seed d || z", 64),
    ("client_random", 32),
    ("ML-DSA-65 signing randomness (rnd, hedged signing)", 32),
];
pub const SERVER_DRAWS: [(&str, usize); 4] = [
    ("X25519 ephemeral secret key", 32),
    ("ML-KEM-768 encapsulation randomness m", 32),
    ("server_random", 32),
    ("ML-DSA-65 signing randomness (rnd, hedged signing)", 32),
];
pub const C2S_PLAINTEXTS: [&str; 3] = ["hello", "post-quantum", "world"];
pub const S2C_PLAINTEXTS: [&str; 1] = ["ack"];

/// RNG source that is either recorded from a generator or replayed.
pub enum Source<R> {
    Record(R, Vec<Vec<u8>>),
    Replay(VecDeque<Vec<u8>>),
}

impl<R: TryRng<Error = Infallible>> TryRng for Source<R> {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        match self {
            Source::Record(r, log) => {
                r.try_fill_bytes(dst)?;
                log.push(dst.to_vec());
            }
            Source::Replay(q) => {
                let next = q
                    .pop_front()
                    .expect("more randomness requested than recorded");
                assert_eq!(
                    next.len(),
                    dst.len(),
                    "randomness drawn in different-sized chunks"
                );
                dst.copy_from_slice(&next);
            }
        }
        Ok(())
    }
}
impl<R: TryRng<Error = Infallible>> TryCryptoRng for Source<R> {}

fn configs() -> (Config, Config) {
    let c = IdentityKeypair::from_seed(&CLIENT_SEED);
    let s = IdentityKeypair::from_seed(&SERVER_SEED);
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

/// Run the exchange and describe every observable output as JSON.
pub fn run<R: TryRng<Error = Infallible>>(
    client_rng: &mut Source<R>,
    server_rng: &mut Source<R>,
) -> Value {
    let (client, server) = configs();
    let (c, hello) = handshake::client_start(&client, client_rng);
    let (s, reply) = handshake::server_accept(&server, &hello, server_rng).expect("server_accept");
    let (finish, cs) = c
        .read_server_hello(&reply, client_rng)
        .expect("read_server_hello");
    let ss = s.read_client_finish(&finish).expect("read_client_finish");
    assert_eq!(cs.session_id(), ss.session_id());
    let session_id = hex::encode(cs.session_id());

    let cfg = ChannelConfig {
        rekey_interval: REKEY_INTERVAL,
    };
    let (mut c_tx, mut c_rx) = channel(cs, cfg).expect("channel");
    let (mut s_tx, mut s_rx) = channel(ss, cfg).expect("channel");

    let mut records = Vec::new();
    for (i, pt) in C2S_PLAINTEXTS.iter().enumerate() {
        let wire = c_tx.seal(pt.as_bytes()).expect("seal");
        assert_eq!(open(&mut s_rx, &wire), Some(pt.as_bytes().to_vec()));
        records.push(json!({
            "direction": "c2s", "seq": i, "epoch": i as u64 / REKEY_INTERVAL,
            "type": "data", "plaintext": pt, "wire": hex::encode(&wire)
        }));
    }
    for (i, pt) in S2C_PLAINTEXTS.iter().enumerate() {
        let wire = s_tx.seal(pt.as_bytes()).expect("seal");
        assert_eq!(open(&mut c_rx, &wire), Some(pt.as_bytes().to_vec()));
        records.push(json!({
            "direction": "s2c", "seq": i, "epoch": i as u64 / REKEY_INTERVAL,
            "type": "data", "plaintext": pt, "wire": hex::encode(&wire)
        }));
    }
    let close = c_tx.close().expect("close");
    assert_eq!(open(&mut s_rx, &close), None);
    records.push(json!({
        "direction": "c2s", "seq": C2S_PLAINTEXTS.len(),
        "epoch": C2S_PLAINTEXTS.len() as u64 / REKEY_INTERVAL,
        "type": "close", "plaintext": "", "wire": hex::encode(&close)
    }));

    let draws = |src: &Source<R>, labels: &[(&str, usize)]| -> Value {
        let Source::Record(_, log) = src else {
            return Value::Null;
        };
        assert_eq!(log.len(), labels.len(), "unexpected number of RNG draws");
        Value::Array(
            log.iter()
                .zip(labels)
                .map(|(b, (what, len))| {
                    assert_eq!(b.len(), *len, "{what}");
                    json!({ "use": what, "bytes": hex::encode(b) })
                })
                .collect(),
        )
    };

    let intermediate = spec_recompute(client_rng, server_rng, &hello, &reply, &finish, &records);
    assert_eq!(
        intermediate["session_id"].as_str(),
        Some(session_id.as_str())
    );

    json!({
        "protocol": "janus/v1",
        "description": "One complete Janus v1 exchange. Inject the listed randomness, in order, into each party; every other field must then be reproduced byte for byte.",
        "client": {
            "identity_seed": hex::encode(CLIENT_SEED),
            "identity_public": hex::encode(client.identity.public().as_bytes()),
            "fingerprint": client.identity.public().fingerprint().to_string(),
            "randomness": draws(client_rng, &CLIENT_DRAWS),
        },
        "server": {
            "identity_seed": hex::encode(SERVER_SEED),
            "identity_public": hex::encode(server.identity.public().as_bytes()),
            "fingerprint": server.identity.public().fingerprint().to_string(),
            "randomness": draws(server_rng, &SERVER_DRAWS),
        },
        "messages": {
            "client_hello": hex::encode(&hello),
            "server_hello": hex::encode(&reply),
            "client_finish": hex::encode(&finish),
        },
        "session_id": session_id,
        "intermediate": intermediate,
        "rekey_interval": REKEY_INTERVAL,
        "records": records,
    })
}

/// Deframe + open one record: `Some(plaintext)` for data, `None` for close.
fn open(rx: &mut janus_channel::Receiver, wire: &[u8]) -> Option<Vec<u8>> {
    let mut d = Deframer::new();
    d.push(wire);
    let frame = d.next_frame().expect("frame").expect("complete frame");
    match rx.open(&frame).expect("open") {
        Received::Data(pt) => Some(pt),
        Received::Close => None,
    }
}

// ─────────────── independent recomputation from docs/PROTOCOL.md ───────────────
//
// Everything below uses the primitive crates directly and follows the text of
// the specification, not janus-core / janus-channel. It recomputes the key
// schedule from the recorded randomness and the wire bytes, and checks it
// against the MACs, session id and records the implementation produced.

use hmac::{KeyInit as _, Mac as _};
use sha2::Digest as _;

fn th(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = sha2::Sha384::new();
    h.update(b"janus/v1 transcript");
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

fn expand_label(secret: &[u8], label: &str, ctx: &[u8], len: usize) -> Vec<u8> {
    let hk = hkdf::Hkdf::<sha2::Sha384>::from_prk(secret).expect("prk length");
    let mut info = Vec::new();
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push((9 + label.len()) as u8);
    info.extend_from_slice(b"janus/v1 ");
    info.extend_from_slice(label.as_bytes());
    info.push(ctx.len() as u8);
    info.extend_from_slice(ctx);
    let mut out = vec![0u8; len];
    hk.expand(&info, &mut out).expect("expand");
    out
}

fn hmac384(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = hmac::Hmac::<sha2::Sha384>::new_from_slice(key).expect("hmac key");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

fn draw_log<R>(src: &Source<R>) -> Vec<Vec<u8>> {
    match src {
        Source::Record(_, log) => log.clone(),
        Source::Replay(_) => Vec::new(),
    }
}

fn spec_recompute<R>(
    client_rng: &Source<R>,
    _server_rng: &Source<R>,
    ch: &[u8],
    sh: &[u8],
    cf: &[u8],
    records: &[Value],
) -> Value {
    let client_draws = match client_rng {
        Source::Record(..) => draw_log(client_rng),
        Source::Replay(_) => REPLAYED.with(|r| r.borrow().clone()),
    };
    let sk_c: [u8; 32] = client_draws[0].as_slice().try_into().expect("sk_c");
    let seed = &client_draws[1];

    // §6.3 step 2: shared secrets from the client's view.
    let x_s: [u8; 32] = sh[1122..1154].try_into().expect("X_s");
    let ss_x = x25519_dalek::x25519(sk_c, x_s);
    let dk = {
        use ml_kem::kem::KeyInit as _;
        let seed = ml_kem::Seed::try_from(seed.as_slice()).expect("seed");
        ml_kem::DecapsulationKey768::new(&seed)
    };
    let ct = ml_kem::ml_kem_768::Ciphertext::try_from(&sh[34..1122]).expect("ct");
    let ss_k = {
        use ml_kem::kem::Decapsulate as _;
        dk.decapsulate(&ct).to_vec()
    };
    let ikm = [ss_k.as_slice(), ss_x.as_slice()].concat();

    // §6.2 steps 5-8.
    let th_kex = th(&[ch, &sh[..1154]]);
    let (prk, _) = hkdf::Hkdf::<sha2::Sha384>::extract(Some(&th_kex), &ikm);
    let prk = prk.to_vec();
    let fk_s = expand_label(&prk, "s finished", b"", 48);
    let fk_c = expand_label(&prk, "c finished", b"", 48);
    assert_eq!(
        hmac384(&fk_s, &th(&[ch, &sh[..6511]])),
        sh[6511..],
        "server Finished (spec §6.2)"
    );
    assert_eq!(
        hmac384(&fk_c, &th(&[ch, sh, &cf[..5359]])),
        cf[5359..],
        "client Finished (spec §6.3)"
    );

    // §6.5.
    let th_final = th(&[ch, sh, cf]);
    let session_id = expand_label(&prk, "exporter", &th_final, 48);

    // §7.2 / §7.3: per-epoch keys, then open every record independently.
    let mut epochs = serde_json::Map::new();
    for (dir, label) in [("c2s", "c2s traffic"), ("s2c", "s2c traffic")] {
        let mut secret = expand_label(&prk, label, &th_final, 48);
        let mut list = Vec::new();
        for e in 0..3u64 {
            let key = expand_label(&secret, "key", b"", 32);
            let iv = expand_label(&secret, "iv", b"", 12);
            for r in records
                .iter()
                .filter(|r| r["direction"] == dir && r["epoch"] == e)
            {
                let wire = hex::decode(r["wire"].as_str().expect("wire")).expect("hex");
                let (header, body) = wire.split_at(3);
                let (seq, sealed) = body.split_at(8);
                let mut nonce = iv.clone();
                for (n, s) in nonce[4..].iter_mut().zip(seq) {
                    *n ^= s;
                }
                let aad = [b"janus/v1 record".as_slice(), header, seq].concat();
                use chacha20poly1305::KeyInit as _;
                use chacha20poly1305::aead::{Aead as _, Payload};
                let pt = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key)
                    .expect("key")
                    .decrypt(
                        &chacha20poly1305::Nonce::try_from(nonce.as_slice()).expect("nonce"),
                        Payload {
                            msg: sealed,
                            aad: &aad,
                        },
                    )
                    .expect("record must open with the spec-derived keys (§7.3)");
                assert_eq!(pt, r["plaintext"].as_str().expect("pt").as_bytes());
            }
            list.push(json!({
                "epoch": e,
                "secret": hex::encode(&secret),
                "key": hex::encode(&key),
                "iv": hex::encode(&iv),
            }));
            secret = expand_label(&secret, "rekey", b"", 48);
        }
        epochs.insert(dir.to_owned(), Value::Array(list));
    }

    json!({
        "ss_mlkem": hex::encode(&ss_k),
        "ss_x25519": hex::encode(ss_x),
        "th_kex": hex::encode(&th_kex),
        "prk": hex::encode(&prk),
        "server_finished_key": hex::encode(&fk_s),
        "client_finished_key": hex::encode(&fk_c),
        "th_final": hex::encode(&th_final),
        "session_id": hex::encode(&session_id),
        "traffic": Value::Object(epochs),
    })
}

thread_local! {
    /// In replay mode the draws are consumed while running; the test stores a
    /// copy here first so the independent recomputation can use them.
    pub static REPLAYED: std::cell::RefCell<Vec<Vec<u8>>> = const { std::cell::RefCell::new(Vec::new()) };
}
