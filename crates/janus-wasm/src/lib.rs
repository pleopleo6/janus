#![forbid(unsafe_code)]
//! Browser bindings for the Janus lab (`web/`).
//!
//! This crate contains no protocol logic of its own: it drives the real
//! `janus-core` handshake and `janus-channel` record layer (compiled to
//! WebAssembly) and reports, step by step, what each side checked. Because the
//! core is sans-IO, "the network" here is simply the byte vectors passed
//! between the two state machines, which lets the page tamper with them.
//!
//! Every method returns a JSON string; the page parses it.

use janus_channel::{Deframer, Received, Receiver, Sender};
use janus_core::handshake::{self, Config, Session};
use janus_core::kem::{MLKEM768_CT_LEN, MLKEM768_EK_LEN, X25519_PK_LEN};
use janus_core::messages::{FINISHED_LEN, HEADER_LEN, RANDOM_LEN};
use janus_core::sig::{
    ED25519_PK_LEN, ED25519_SIG_LEN, IdentityKeypair, MLDSA65_PK_LEN, MLDSA65_SIG_LEN,
};
use rand_core::UnwrapErr;
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Records between two rekeys in the lab: small, so epochs visibly change.
pub const LAB_REKEY_INTERVAL: u64 = 4;

fn rng() -> UnwrapErr<getrandom::SysRng> {
    UnwrapErr(getrandom::SysRng)
}

#[cfg(target_arch = "wasm32")]
fn now_ms() -> f64 {
    web_sys::window()
        .and_then(|w| w.performance())
        .map_or(0.0, |p| p.now())
}

#[cfg(not(target_arch = "wasm32"))]
fn now_ms() -> f64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static T0: OnceLock<Instant> = OnceLock::new();
    T0.get_or_init(Instant::now).elapsed().as_secs_f64() * 1000.0
}

fn to_json<T: Serialize>(v: &T) -> Result<String, JsValue> {
    serde_json::to_string(v).map_err(|e| JsValue::from_str(&e.to_string()))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        },
    )
}

// ───────────────────────────── message layout ─────────────────────────────

/// One field of a wire message.
#[derive(Debug, Serialize, Clone, Copy)]
pub struct Field {
    name: &'static str,
    /// `protocol`, `classical` or `pq`: drives the colour in the page.
    kind: &'static str,
    start: usize,
    len: usize,
    about: &'static str,
}

fn layout(spec: &[(&'static str, &'static str, usize, &'static str)]) -> Vec<Field> {
    let mut start = 0;
    spec.iter()
        .map(|&(name, kind, len, about)| {
            let f = Field {
                name,
                kind,
                start,
                len,
                about,
            };
            start = start.saturating_add(len);
            f
        })
        .collect()
}

const ABOUT_HEADER: &str = "Protocol version and message type. Checked first; both bytes are also bound by the transcript hash.";
const ABOUT_RANDOM: &str =
    "Fresh 32-byte nonce. Makes every transcript unique even if an ephemeral key repeated.";
const ABOUT_FINISHED: &str = "HMAC-SHA-384 over the transcript so far, keyed from the handshake secret. Proves the sender derived the same keys.";
const ABOUT_ED_PK: &str = "Long-term Ed25519 public key, first half of the hybrid identity.";
const ABOUT_DSA_PK: &str = "Long-term ML-DSA-65 public key, second half of the hybrid identity.";
const ABOUT_ED_SIG: &str =
    "Ed25519 signature over the transcript hash, the role label and the full hybrid public key.";
const ABOUT_DSA_SIG: &str = "ML-DSA-65 signature over the same message, with the role label as FIPS 204 context. Both halves must verify.";

/// Field layout of `ClientHello`, `ServerHello`, `ClientFinish`.
pub fn fields(msg: usize) -> Vec<Field> {
    match msg {
        0 => layout(&[
            ("Header", "protocol", HEADER_LEN, ABOUT_HEADER),
            ("Client random", "protocol", RANDOM_LEN, ABOUT_RANDOM),
            (
                "ML-KEM-768 encapsulation key",
                "pq",
                MLKEM768_EK_LEN,
                "Ephemeral post-quantum public key (FIPS 203). The server checks every coefficient is reduced mod q.",
            ),
            (
                "X25519 share",
                "classical",
                X25519_PK_LEN,
                "Ephemeral X25519 public key. Low-order points are rejected as non-contributory.",
            ),
        ]),
        1 => layout(&[
            ("Header", "protocol", HEADER_LEN, ABOUT_HEADER),
            ("Server random", "protocol", RANDOM_LEN, ABOUT_RANDOM),
            (
                "ML-KEM-768 ciphertext",
                "pq",
                MLKEM768_CT_LEN,
                "Encapsulates the post-quantum shared secret. A corrupted ciphertext decapsulates to a different key (implicit rejection), it does not raise an error.",
            ),
            (
                "X25519 share",
                "classical",
                X25519_PK_LEN,
                "Server's ephemeral X25519 public key.",
            ),
            (
                "Ed25519 public key",
                "classical",
                ED25519_PK_LEN,
                ABOUT_ED_PK,
            ),
            ("ML-DSA-65 public key", "pq", MLDSA65_PK_LEN, ABOUT_DSA_PK),
            (
                "Ed25519 signature",
                "classical",
                ED25519_SIG_LEN,
                ABOUT_ED_SIG,
            ),
            ("ML-DSA-65 signature", "pq", MLDSA65_SIG_LEN, ABOUT_DSA_SIG),
            ("Finished MAC", "protocol", FINISHED_LEN, ABOUT_FINISHED),
        ]),
        _ => layout(&[
            ("Header", "protocol", HEADER_LEN, ABOUT_HEADER),
            (
                "Ed25519 public key",
                "classical",
                ED25519_PK_LEN,
                ABOUT_ED_PK,
            ),
            ("ML-DSA-65 public key", "pq", MLDSA65_PK_LEN, ABOUT_DSA_PK),
            (
                "Ed25519 signature",
                "classical",
                ED25519_SIG_LEN,
                ABOUT_ED_SIG,
            ),
            ("ML-DSA-65 signature", "pq", MLDSA65_SIG_LEN, ABOUT_DSA_SIG),
            ("Finished MAC", "protocol", FINISHED_LEN, ABOUT_FINISHED),
        ]),
    }
}

const MESSAGE_NAMES: [&str; 3] = ["ClientHello", "ServerHello", "ClientFinish"];

// ───────────────────────────── handshake report ─────────────────────────────

#[derive(Serialize)]
struct Tamper {
    offset: usize,
    mask: u8,
}

#[derive(Serialize)]
struct Message {
    index: usize,
    name: &'static str,
    from: &'static str,
    len: usize,
    hex: String,
    fields: Vec<Field>,
    tampered: Option<Tamper>,
}

#[derive(Serialize)]
struct Step {
    side: &'static str,
    label: &'static str,
    status: &'static str,
}

#[derive(Serialize)]
struct Phase {
    side: &'static str,
    input: &'static str,
    ms: f64,
}

#[derive(Serialize)]
struct SessionReport {
    client_session_id: String,
    server_session_id: String,
    matches: bool,
    client_sees: String,
    server_sees: String,
}

#[derive(Serialize)]
struct HandshakeReport {
    ok: bool,
    scenario: String,
    messages: Vec<Message>,
    steps: Vec<Step>,
    phases: Vec<Phase>,
    error: Option<String>,
    error_code: Option<String>,
    failed_side: Option<&'static str>,
    session: Option<SessionReport>,
}

const SERVER_HELLO_STEPS: [&str; 3] = [
    "Parse ClientHello",
    "Encapsulate X25519 + ML-KEM-768",
    "Sign transcript (Ed25519 + ML-DSA-65)",
];
const CLIENT_STEPS: [&str; 6] = [
    "Parse ServerHello",
    "Decapsulate X25519 + ML-KEM-768",
    "Server identity is pinned",
    "Hybrid signature valid",
    "Finished MAC valid",
    "Sign and MAC ClientFinish",
];
const SERVER_FINISH_STEPS: [&str; 5] = [
    "Parse ClientFinish",
    "Client identity is pinned",
    "Hybrid signature valid",
    "Finished MAC valid",
    "Derive traffic keys",
];

fn is_parse_error(e: janus_core::Error) -> bool {
    use janus_core::Error as E;
    matches!(
        e,
        E::Malformed | E::UnsupportedVersion | E::UnexpectedMessage | E::InvalidPublicKey
    )
}

/// Index of the step at which an error occurred, for each phase.
fn failed_step(phase: usize, e: janus_core::Error) -> usize {
    use janus_core::Error as E;
    if is_parse_error(e) {
        return 0;
    }
    match (phase, e) {
        (0, E::NonContributory) => 1,
        (0, _) => 2,
        (1, E::NonContributory) => 1,
        (1, E::UntrustedPeer) => 2,
        (1, E::BadSignature) => 3,
        (1, _) => 4,
        (_, E::UntrustedPeer) => 1,
        (_, E::BadSignature) => 2,
        (_, _) => 3,
    }
}

fn error_code(e: janus_core::Error) -> &'static str {
    use janus_core::Error as E;
    match e {
        E::Malformed => "Malformed",
        E::InvalidPublicKey => "InvalidPublicKey",
        E::NonContributory => "NonContributory",
        E::BadSignature => "BadSignature",
        E::UntrustedPeer => "UntrustedPeer",
        E::BadFinished => "BadFinished",
        E::UnsupportedVersion => "UnsupportedVersion",
        E::UnexpectedMessage => "UnexpectedMessage",
        _ => "Internal",
    }
}

fn push_steps(
    steps: &mut Vec<Step>,
    side: &'static str,
    labels: &[&'static str],
    failed: Option<usize>,
) {
    for (i, label) in labels.iter().enumerate() {
        let status = match failed {
            None => "ok",
            Some(f) if i < f => "ok",
            Some(f) if i == f => "fail",
            Some(_) => "skipped",
        };
        steps.push(Step {
            side,
            label,
            status,
        });
    }
}

fn skip_steps(steps: &mut Vec<Step>, side: &'static str, labels: &[&'static str]) {
    for label in labels {
        steps.push(Step {
            side,
            label,
            status: "skipped",
        });
    }
}

// ───────────────────────────── record layer state ─────────────────────────────

struct Chan {
    tx: Sender,
    rx: Receiver,
    /// Server → client direction, used to echo.
    s_tx: Sender,
    c_rx: Receiver,
    last: Option<Vec<u8>>,
    failed: Option<String>,
    closed: bool,
}

#[derive(Serialize)]
struct RecordView {
    hex: String,
    len: usize,
    seq: u64,
    epoch: u64,
    kind: &'static str,
    /// Byte offsets: header 0..3, seq 3..11, ciphertext 11..len-16, tag.
    tampered_offset: Option<usize>,
}

#[derive(Serialize)]
struct Delivery {
    accepted: bool,
    plaintext: Option<String>,
    close: bool,
    error: Option<String>,
    error_code: Option<String>,
}

#[derive(Serialize)]
struct ChannelReport {
    action: String,
    explanation: &'static str,
    records: Vec<RecordView>,
    deliveries: Vec<Delivery>,
    echo: Option<String>,
    receiver_state: &'static str,
    receiver_epoch: u64,
    records_received: u64,
}

fn channel_error_code(e: janus_channel::Error) -> &'static str {
    use janus_channel::Error as E;
    match e {
        E::Malformed => "Malformed",
        E::TooLarge => "TooLarge",
        E::Replay => "Replay",
        E::OutOfOrder => "OutOfOrder",
        E::BadRecord => "BadRecord",
        E::Closed => "Closed",
        E::Truncated => "Truncated",
        E::SequenceExhausted => "SequenceExhausted",
        E::Failed => "Failed",
        _ => "Internal",
    }
}

// ───────────────────────────── the lab ─────────────────────────────

/// The whole lab: three identities, the last handshake and an open channel.
#[wasm_bindgen]
pub struct Lab {
    client: Config,
    server: Config,
    rogue_client: Config,
    rogue_server: Config,
    chan: Option<Chan>,
}

impl core::fmt::Debug for Lab {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Lab")
            .field("channel_open", &self.chan.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for Lab {
    fn default() -> Self {
        Self::new()
    }
}

fn config(seed: u8, trusts: &IdentityKeypair) -> Config {
    Config {
        identity: IdentityKeypair::from_seed(&[seed; 64]),
        trust: [trusts.public().fingerprint()].into_iter().collect(),
    }
}

#[wasm_bindgen]
impl Lab {
    /// Fixed demo identities (seeds are public: this is a demo).
    #[wasm_bindgen(constructor)]
    pub fn new() -> Lab {
        let c = IdentityKeypair::from_seed(&[1; 64]);
        let s = IdentityKeypair::from_seed(&[2; 64]);
        Lab {
            client: config(1, &s),
            server: config(2, &c),
            // Same trust lists as the honest parties, different keys.
            rogue_client: config(66, &s),
            rogue_server: config(77, &c),
            chan: None,
        }
    }

    /// Fingerprints of the four identities and the field layouts.
    pub fn info(&self) -> Result<String, JsValue> {
        #[derive(Serialize)]
        struct Info {
            client: String,
            server: String,
            rogue_client: String,
            rogue_server: String,
            rekey_interval: u64,
            layouts: Vec<Vec<Field>>,
        }
        to_json(&Info {
            client: self.client.identity.public().fingerprint().to_string(),
            server: self.server.identity.public().fingerprint().to_string(),
            rogue_client: self
                .rogue_client
                .identity
                .public()
                .fingerprint()
                .to_string(),
            rogue_server: self
                .rogue_server
                .identity
                .public()
                .fingerprint()
                .to_string(),
            rekey_interval: LAB_REKEY_INTERVAL,
            layouts: (0..3).map(fields).collect(),
        })
    }

    /// Run one handshake.
    ///
    /// - `scenario`: `honest`, `rogue-server` (an attacker answers with its own
    ///   key) or `rogue-client`;
    /// - `tamper_msg` (0–2, or -1): message to alter in flight, at
    ///   `tamper_offset`, XOR `tamper_mask`.
    pub fn handshake(
        &mut self,
        scenario: &str,
        tamper_msg: i32,
        tamper_offset: u32,
        tamper_mask: u8,
    ) -> Result<String, JsValue> {
        self.chan = None;
        let client = if scenario == "rogue-client" {
            &self.rogue_client
        } else {
            &self.client
        };
        let server = if scenario == "rogue-server" {
            &self.rogue_server
        } else {
            &self.server
        };
        let mut r = HandshakeReport {
            ok: false,
            scenario: scenario.to_owned(),
            messages: Vec::new(),
            steps: Vec::new(),
            phases: Vec::new(),
            error: None,
            error_code: None,
            failed_side: None,
            session: None,
        };
        let offset = usize::try_from(tamper_offset).unwrap_or(usize::MAX);
        let tamper = |idx: usize, bytes: &mut Vec<u8>| -> Option<Tamper> {
            if usize::try_from(tamper_msg).ok() != Some(idx) || tamper_mask == 0 {
                return None;
            }
            let b = bytes.get_mut(offset)?;
            *b ^= tamper_mask;
            Some(Tamper {
                offset,
                mask: tamper_mask,
            })
        };
        let record = |r: &mut HandshakeReport, idx: usize, bytes: &[u8], t: Option<Tamper>| {
            r.messages.push(Message {
                index: idx,
                name: MESSAGE_NAMES.get(idx).copied().unwrap_or("?"),
                from: if idx == 1 { "server" } else { "client" },
                len: bytes.len(),
                hex: hex(bytes),
                fields: fields(idx),
                tampered: t,
            });
        };
        let fail = |r: &mut HandshakeReport, side: &'static str, e: janus_core::Error| {
            r.error = Some(e.to_string());
            r.error_code = Some(error_code(e).to_owned());
            r.failed_side = Some(side);
        };

        let mut rng = rng();

        // Flight 1.
        let t0 = now_ms();
        let (c_state, mut m1) = handshake::client_start(client, &mut rng);
        r.phases.push(Phase {
            side: "client",
            input: "start",
            ms: now_ms() - t0,
        });
        let t = tamper(0, &mut m1);
        record(&mut r, 0, &m1, t);

        // Server reads ClientHello.
        let t0 = now_ms();
        let accepted = handshake::server_accept(server, &m1, &mut rng);
        r.phases.push(Phase {
            side: "server",
            input: "ClientHello",
            ms: now_ms() - t0,
        });
        let (s_state, mut m2) = match accepted {
            Ok(v) => {
                push_steps(&mut r.steps, "server", &SERVER_HELLO_STEPS, None);
                v
            }
            Err(e) => {
                push_steps(
                    &mut r.steps,
                    "server",
                    &SERVER_HELLO_STEPS,
                    Some(failed_step(0, e)),
                );
                skip_steps(&mut r.steps, "client", &CLIENT_STEPS);
                skip_steps(&mut r.steps, "server", &SERVER_FINISH_STEPS);
                fail(&mut r, "server", e);
                return to_json(&r);
            }
        };
        let t = tamper(1, &mut m2);
        record(&mut r, 1, &m2, t);

        // Client reads ServerHello.
        let t0 = now_ms();
        let read = c_state.read_server_hello(&m2, &mut rng);
        r.phases.push(Phase {
            side: "client",
            input: "ServerHello",
            ms: now_ms() - t0,
        });
        let (mut m3, c_session) = match read {
            Ok(v) => {
                push_steps(&mut r.steps, "client", &CLIENT_STEPS, None);
                v
            }
            Err(e) => {
                push_steps(
                    &mut r.steps,
                    "client",
                    &CLIENT_STEPS,
                    Some(failed_step(1, e)),
                );
                skip_steps(&mut r.steps, "server", &SERVER_FINISH_STEPS);
                fail(&mut r, "client", e);
                return to_json(&r);
            }
        };
        let t = tamper(2, &mut m3);
        record(&mut r, 2, &m3, t);

        // Server reads ClientFinish.
        let t0 = now_ms();
        let done = s_state.read_client_finish(&m3);
        r.phases.push(Phase {
            side: "server",
            input: "ClientFinish",
            ms: now_ms() - t0,
        });
        let s_session = match done {
            Ok(s) => {
                push_steps(&mut r.steps, "server", &SERVER_FINISH_STEPS, None);
                s
            }
            Err(e) => {
                push_steps(
                    &mut r.steps,
                    "server",
                    &SERVER_FINISH_STEPS,
                    Some(failed_step(2, e)),
                );
                fail(&mut r, "server", e);
                return to_json(&r);
            }
        };

        r.ok = true;
        r.session = Some(SessionReport {
            client_session_id: hex(c_session.session_id()),
            server_session_id: hex(s_session.session_id()),
            matches: c_session.session_id() == s_session.session_id(),
            client_sees: c_session.peer().fingerprint().to_string(),
            server_sees: s_session.peer().fingerprint().to_string(),
        });
        self.chan = open_channel(c_session, s_session);
        to_json(&r)
    }

    /// Whether a channel is open (after a successful handshake).
    pub fn has_channel(&self) -> bool {
        self.chan.is_some()
    }

    /// Client sends `text` to the server; the server echoes it back.
    pub fn send(&mut self, text: &str) -> Result<String, JsValue> {
        let Some(ch) = self.chan.as_mut() else {
            return Err(JsValue::from_str(
                "no channel: run a successful handshake first",
            ));
        };
        let mut rep = ch.report(
            "send",
            "The client seals the message; the server opens it and echoes it back.",
        );
        match seal(&mut ch.tx, text.as_bytes()) {
            Ok(rec) => {
                rep.records.push(view(&rec, "data", None));
                let d = ch.deliver(&rec);
                if let (true, Some(msg)) = (d.accepted, d.plaintext.clone()) {
                    rep.echo = ch.echo(msg.as_bytes());
                }
                rep.deliveries.push(d);
                ch.last = Some(rec);
            }
            Err(e) => rep.deliveries.push(sender_error(e)),
        }
        ch.finish_report(rep)
    }

    /// Run a record-layer attack: `replay`, `reorder`, `tamper`, `truncate`
    /// or `close`.
    pub fn attack(&mut self, kind: &str) -> Result<String, JsValue> {
        let Some(ch) = self.chan.as_mut() else {
            return Err(JsValue::from_str(
                "no channel: run a successful handshake first",
            ));
        };
        let mut rep;
        match kind {
            "replay" => {
                rep = ch.report(
                    kind,
                    "The attacker re-sends the last record. Its sequence number was already used.",
                );
                let rec = match ch.last.clone() {
                    Some(r) => r,
                    None => match seal(&mut ch.tx, b"pay 10 EUR to Mallory") {
                        Ok(r) => {
                            rep.records.push(view(&r, "data", None));
                            rep.deliveries.push(ch.deliver(&r));
                            r
                        }
                        Err(e) => {
                            rep.deliveries.push(sender_error(e));
                            return ch.finish_report(rep);
                        }
                    },
                };
                rep.records.push(view(&rec, "replayed", None));
                rep.deliveries.push(ch.deliver(&rec));
            }
            "reorder" => {
                rep = ch.report(
                    kind,
                    "The client sends two records; the attacker delivers the second one first.",
                );
                let first = seal(&mut ch.tx, b"first");
                let second = seal(&mut ch.tx, b"second");
                match (first, second) {
                    (Ok(a), Ok(b)) => {
                        rep.records.push(view(&b, "data (held back: #1)", None));
                        rep.deliveries.push(ch.deliver(&b));
                        rep.records.push(view(&a, "data (late: #0)", None));
                        rep.deliveries.push(ch.deliver(&a));
                    }
                    (Err(e), _) | (_, Err(e)) => rep.deliveries.push(sender_error(e)),
                }
            }
            "tamper" => {
                rep = ch.report(
                    kind,
                    "The attacker flips one bit of the ciphertext in flight.",
                );
                match seal(&mut ch.tx, b"transfer 10 EUR") {
                    Ok(mut rec) => {
                        let off = 3 + 8 + 2;
                        if let Some(b) = rec.get_mut(off) {
                            *b ^= 0x01;
                        }
                        rep.records.push(view(&rec, "data (tampered)", Some(off)));
                        rep.deliveries.push(ch.deliver(&rec));
                    }
                    Err(e) => rep.deliveries.push(sender_error(e)),
                }
            }
            "truncate" => {
                rep = ch.report(
                    kind,
                    "The attacker cuts the TCP stream. No authenticated Close record was received.",
                );
                let d = match ch.rx.finish() {
                    Ok(()) => Delivery {
                        accepted: true,
                        plaintext: None,
                        close: true,
                        error: None,
                        error_code: None,
                    },
                    Err(e) => receiver_error(e),
                };
                if d.error.is_some() && ch.failed.is_none() && !ch.closed {
                    ch.failed = d.error.clone();
                }
                rep.deliveries.push(d);
            }
            _ => {
                rep = ch.report("close", "The client sends an authenticated Close record (close_notify). The stream can now end safely.");
                match ch.tx.close() {
                    Ok(rec) => {
                        rep.records.push(view(&rec, "close", None));
                        rep.deliveries.push(ch.deliver(&rec));
                    }
                    Err(e) => rep.deliveries.push(sender_error(e)),
                }
            }
        }
        ch.finish_report(rep)
    }
}

fn open_channel(c: Session, s: Session) -> Option<Chan> {
    let cfg = janus_channel::ChannelConfig {
        rekey_interval: LAB_REKEY_INTERVAL,
    };
    let (tx, c_rx) = janus_channel::channel(c, cfg).ok()?;
    let (s_tx, rx) = janus_channel::channel(s, cfg).ok()?;
    Some(Chan {
        tx,
        rx,
        s_tx,
        c_rx,
        last: None,
        failed: None,
        closed: false,
    })
}

fn seal(tx: &mut Sender, pt: &[u8]) -> janus_channel::Result<Vec<u8>> {
    tx.seal(pt)
}

/// View of a sealed record (sequence number read from its header).
fn view(rec: &[u8], kind: &'static str, tampered_offset: Option<usize>) -> RecordView {
    let seq = rec
        .get(3..11)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map_or(0, u64::from_be_bytes);
    RecordView {
        hex: hex(rec),
        len: rec.len(),
        seq,
        epoch: seq.checked_div(LAB_REKEY_INTERVAL).unwrap_or(0),
        kind,
        tampered_offset,
    }
}

fn receiver_error(e: janus_channel::Error) -> Delivery {
    Delivery {
        accepted: false,
        plaintext: None,
        close: false,
        error: Some(e.to_string()),
        error_code: Some(channel_error_code(e).to_owned()),
    }
}

fn sender_error(e: janus_channel::Error) -> Delivery {
    receiver_error(e)
}

impl Chan {
    fn report(&self, action: &str, explanation: &'static str) -> ChannelReport {
        ChannelReport {
            action: action.to_owned(),
            explanation,
            records: Vec::new(),
            deliveries: Vec::new(),
            echo: None,
            receiver_state: "open",
            receiver_epoch: 0,
            records_received: 0,
        }
    }

    fn finish_report(&self, mut rep: ChannelReport) -> Result<String, JsValue> {
        rep.receiver_state = if self.failed.is_some() {
            "failed"
        } else if self.closed {
            "closed"
        } else {
            "open"
        };
        rep.receiver_epoch = self.rx.epoch();
        rep.records_received = self.rx.records_received();
        to_json(&rep)
    }

    /// Network delivery to the server: deframe, then open.
    fn deliver(&mut self, bytes: &[u8]) -> Delivery {
        let mut d = Deframer::new();
        d.push(bytes);
        let frame = match d.next_frame() {
            Ok(Some(f)) => f,
            Ok(None) => return receiver_error(janus_channel::Error::Truncated),
            Err(e) => return receiver_error(e),
        };
        match self.rx.open(&frame) {
            Ok(Received::Data(pt)) => Delivery {
                accepted: true,
                plaintext: Some(String::from_utf8_lossy(&pt).into_owned()),
                close: false,
                error: None,
                error_code: None,
            },
            Ok(Received::Close) => {
                self.closed = true;
                Delivery {
                    accepted: true,
                    plaintext: None,
                    close: true,
                    error: None,
                    error_code: None,
                }
            }
            Err(e) => {
                if !matches!(
                    e,
                    janus_channel::Error::Failed | janus_channel::Error::Closed
                ) {
                    self.failed = Some(e.to_string());
                }
                receiver_error(e)
            }
        }
    }

    /// Server echoes `msg` back on the other direction.
    fn echo(&mut self, msg: &[u8]) -> Option<String> {
        let rec = self.s_tx.seal(msg).ok()?;
        let mut d = Deframer::new();
        d.push(&rec);
        let frame = d.next_frame().ok()??;
        match self.c_rx.open(&frame).ok()? {
            Received::Data(pt) => Some(String::from_utf8_lossy(&pt).into_owned()),
            Received::Close => None,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn hs(lab: &mut Lab, scenario: &str, msg: i32, off: u32) -> Value {
        serde_json::from_str(&lab.handshake(scenario, msg, off, 0x01).unwrap()).unwrap()
    }

    fn failing(v: &Value) -> (String, String) {
        let s = v["steps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["status"] == "fail")
            .unwrap();
        (
            s["side"].as_str().unwrap().into(),
            s["label"].as_str().unwrap().into(),
        )
    }

    #[test]
    fn layouts_cover_messages_exactly() {
        let lens = [
            janus_core::messages::CLIENT_HELLO_LEN,
            janus_core::messages::SERVER_HELLO_LEN,
            janus_core::messages::CLIENT_FINISH_LEN,
        ];
        for (i, len) in lens.into_iter().enumerate() {
            let f = fields(i);
            let last = f.last().unwrap();
            assert_eq!(last.start + last.len, len);
        }
    }

    #[test]
    fn honest_handshake_reports_matching_sessions() {
        let mut lab = Lab::new();
        let v = hs(&mut lab, "honest", -1, 0);
        assert_eq!(v["ok"], true);
        assert_eq!(v["session"]["matches"], true);
        assert_eq!(v["messages"].as_array().unwrap().len(), 3);
        assert!(
            v["steps"]
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s["status"] == "ok")
        );
        assert!(lab.has_channel());
    }

    #[test]
    fn tampering_is_attributed_to_the_right_check() {
        let mut lab = Lab::new();
        // Version byte of ClientHello: the server's parser.
        assert_eq!(
            failing(&hs(&mut lab, "honest", 0, 0)),
            ("server".into(), "Parse ClientHello".into())
        );
        // ML-DSA signature in ServerHello.
        let v = hs(&mut lab, "honest", 1, 5000);
        assert_eq!(
            failing(&v),
            ("client".into(), "Hybrid signature valid".into())
        );
        // Finished MAC of ServerHello.
        let v = hs(&mut lab, "honest", 1, 6550);
        assert_eq!(failing(&v), ("client".into(), "Finished MAC valid".into()));
        // Client Finished MAC.
        let v = hs(&mut lab, "honest", 2, 5400);
        assert_eq!(failing(&v), ("server".into(), "Finished MAC valid".into()));
        assert!(!lab.has_channel());
    }

    #[test]
    fn rogue_parties_are_rejected_at_the_pin_check() {
        let mut lab = Lab::new();
        let v = hs(&mut lab, "rogue-server", -1, 0);
        assert_eq!(
            failing(&v),
            ("client".into(), "Server identity is pinned".into())
        );
        let v = hs(&mut lab, "rogue-client", -1, 0);
        assert_eq!(
            failing(&v),
            ("server".into(), "Client identity is pinned".into())
        );
    }

    #[test]
    fn channel_attacks() {
        let mut lab = Lab::new();
        hs(&mut lab, "honest", -1, 0);
        let v: Value = serde_json::from_str(&lab.send("hello").unwrap()).unwrap();
        assert_eq!(v["deliveries"][0]["plaintext"], "hello");
        assert_eq!(v["echo"], "hello");
        let v: Value = serde_json::from_str(&lab.attack("replay").unwrap()).unwrap();
        assert_eq!(v["deliveries"][0]["error_code"], "Replay");
        assert_eq!(v["receiver_state"], "failed");

        for (kind, code) in [
            ("reorder", "OutOfOrder"),
            ("tamper", "BadRecord"),
            ("truncate", "Truncated"),
        ] {
            hs(&mut lab, "honest", -1, 0);
            let v: Value = serde_json::from_str(&lab.attack(kind).unwrap()).unwrap();
            assert_eq!(v["deliveries"][0]["error_code"], code, "{kind}");
        }

        hs(&mut lab, "honest", -1, 0);
        let v: Value = serde_json::from_str(&lab.attack("close").unwrap()).unwrap();
        assert_eq!(v["deliveries"][0]["close"], true);
        let v: Value = serde_json::from_str(&lab.attack("truncate").unwrap()).unwrap();
        assert_eq!(
            v["deliveries"][0]["accepted"], true,
            "clean close is not truncation"
        );
    }

    #[test]
    fn rekey_epochs_advance() {
        let mut lab = Lab::new();
        hs(&mut lab, "honest", -1, 0);
        let mut last = Value::Null;
        for i in 0..9 {
            last = serde_json::from_str(&lab.send(&format!("m{i}")).unwrap()).unwrap();
        }
        assert_eq!(last["records"][0]["epoch"], 2);
        assert_eq!(last["receiver_epoch"], 2);
    }
}
