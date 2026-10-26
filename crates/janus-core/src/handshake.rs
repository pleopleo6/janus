//! Sans-IO handshake state machines.
//!
//! The handshake is a three-message, mutually-authenticated SIGMA-style
//! protocol ("sign-and-MAC", in the order of TLS 1.3's
//! Certificate / CertificateVerify / Finished):
//!
//! ```text
//!  Client (initiator)                                  Server (responder)
//!  ──────────────────                                  ──────────────────
//!  eph ← KemInitiator::generate
//!                  ClientHello: c_random, eph.public
//!            ─────────────────────────────────────────▶
//!                                                       (ct, ss) ← encapsulate
//!                                                       prk ← Extract(TH(kex), ss)
//!     ServerHello: s_random, ct, id_S,
//!                  sig_S(TH(…id_S)), MAC_S(TH(…sig_S))
//!            ◀─────────────────────────────────────────
//!  ss ← decapsulate; prk ← Extract(TH(kex), ss)
//!  check id_S pinned, sig_S, MAC_S
//!     ClientFinish: id_C, sig_C(TH(…id_C)), MAC_C(TH(…sig_C))
//!            ─────────────────────────────────────────▶
//!                                                       check id_C pinned, sig_C, MAC_C
//!  session keys ← Expand(prk, TH(final))               session keys ← …
//! ```
//!
//! # Why this order in the transcript
//!
//! The transcript is simply *the wire bytes in wire order*: both peers see
//! the same bytes in the same order, so there is no room for the two views
//! to diverge. Each signature covers everything sent so far **including the
//! signer's own identity** (prevents identity misbinding: a signature cannot be
//! moved under another identity), and each MAC covers the signature (TLS 1.3
//! order). The signatures authenticate the *ephemeral* KEM values, which is
//! what makes the keys authenticated; the MACs prove possession of the
//! derived key (key confirmation), which rules out unknown-key-share attacks.
//! The client signature also covers the server's identity and signature, so
//! the client's authentication is bound to *this* server.
//!
//! # State machine
//!
//! Each state is a distinct type and every transition consumes `self`, so
//! the compiler rejects out-of-order calls and an aborted handshake cannot be
//! resumed. Any error is final: the caller must drop the connection.

use core::fmt;

use rand_core::CryptoRng;
use subtle::{Choice, ConstantTimeEq};

use crate::error::{Error, Result};
use crate::kem::KemInitiator;
use crate::messages::{
    self, CLIENT_FINISH_ID_END, CLIENT_FINISH_LEN, CLIENT_FINISH_SIG_END, ClientFinish,
    ClientHello, MessageType, RANDOM_LEN, SERVER_HELLO_ID_END, SERVER_HELLO_KEX_END,
    SERVER_HELLO_LEN, SERVER_HELLO_SIG_END, ServerHello,
};
use crate::schedule::{HandshakeSecret, Hash, Role, TrafficSecret, Transcript, label};
use crate::sig::{Fingerprint, IdentityKeypair, IdentityPublic};

/// Set of pinned peer identities.
///
/// There is no PKI: a peer is accepted iff the fingerprint of its hybrid
/// identity is in this set (SSH `known_hosts` / WireGuard model).
#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    pins: Vec<Fingerprint>,
}

impl TrustStore {
    /// Empty store (trusts nobody).
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin a fingerprint.
    pub fn add(&mut self, fp: Fingerprint) {
        self.pins.push(fp);
    }

    /// Number of pinned identities.
    pub fn len(&self) -> usize {
        self.pins.len()
    }

    /// `true` if nothing is pinned.
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }

    /// Whether `id` is pinned. Scans every entry and compares in constant
    /// time, so timing reveals at most the size of the store.
    pub fn is_trusted(&self, id: &IdentityPublic) -> bool {
        let fp = id.fingerprint();
        let found = self
            .pins
            .iter()
            .fold(Choice::from(0), |acc, pin| acc | pin.ct_eq(&fp));
        bool::from(found)
    }
}

impl FromIterator<Fingerprint> for TrustStore {
    fn from_iter<I: IntoIterator<Item = Fingerprint>>(iter: I) -> Self {
        Self {
            pins: iter.into_iter().collect(),
        }
    }
}

/// Local configuration: who we are and whom we trust.
#[derive(Debug)]
pub struct Config {
    /// Our long-term identity.
    pub identity: IdentityKeypair,
    /// Peers we accept.
    pub trust: TrustStore,
}

/// A completed handshake: authenticated peer and fresh traffic secrets.
pub struct Session {
    role: Role,
    peer: IdentityPublic,
    session_id: Hash,
    send: TrafficSecret,
    recv: TrafficSecret,
}

impl Session {
    /// Our role in the handshake.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The authenticated peer identity.
    pub fn peer(&self) -> &IdentityPublic {
        &self.peer
    }

    /// Unique session identifier, equal on both sides. Can be compared
    /// out-of-band by users or used for channel binding. Not secret.
    pub fn session_id(&self) -> &Hash {
        &self.session_id
    }

    /// Hand the traffic secrets to the record layer: `(send, receive)`.
    pub fn into_traffic_secrets(self) -> (TrafficSecret, TrafficSecret) {
        (self.send, self.recv)
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("role", &self.role)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

/// Append `bytes` to the outgoing message and to the transcript at once, so
/// that what is hashed is by construction what is sent.
fn emit(out: &mut Vec<u8>, transcript: &mut Transcript, bytes: &[u8]) {
    transcript.absorb(bytes);
    out.extend_from_slice(bytes);
}

fn header(ty: MessageType) -> [u8; messages::HEADER_LEN] {
    [messages::VERSION, ty as u8]
}

// ───────────────────────────── client side ─────────────────────────────

/// Start a handshake as the initiator. Returns the state to keep and the
/// `ClientHello` to send.
pub fn client_start<'a, R: CryptoRng + ?Sized>(
    config: &'a Config,
    rng: &mut R,
) -> (ClientAwaitServerHello<'a>, Vec<u8>) {
    let kem = KemInitiator::generate(rng);
    let mut random = [0u8; RANDOM_LEN];
    rng.fill_bytes(&mut random);
    let hello = ClientHello {
        random,
        kem_public: kem.public().clone(),
    }
    .encode();

    let mut transcript = Transcript::new();
    transcript.absorb(&hello);
    (
        ClientAwaitServerHello {
            config,
            kem,
            transcript,
        },
        hello,
    )
}

/// Initiator waiting for `ServerHello`.
pub struct ClientAwaitServerHello<'a> {
    config: &'a Config,
    kem: KemInitiator,
    transcript: Transcript,
}

impl ClientAwaitServerHello<'_> {
    /// Process `ServerHello`. On success, returns the `ClientFinish` to send
    /// and the established session.
    ///
    /// The client may send application data right after `ClientFinish`:
    /// the server is already authenticated and the keys confirmed.
    ///
    /// # Errors
    /// Any parsing, trust, signature or key-confirmation failure. The
    /// handshake must then be abandoned.
    pub fn read_server_hello<R: CryptoRng + ?Sized>(
        self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, Session)> {
        let Self {
            config,
            kem,
            mut transcript,
        } = self;
        let sh = ServerHello::decode(msg)?;
        let [kex, id, sig, fin] = messages::segments(
            msg,
            [
                SERVER_HELLO_KEX_END,
                SERVER_HELLO_ID_END,
                SERVER_HELLO_SIG_END,
                SERVER_HELLO_LEN,
            ],
        )?;

        transcript.absorb(kex);
        let hs =
            HandshakeSecret::derive(&kem.decapsulate(&sh.kem_ciphertext)?, &transcript.current());

        // Trust is checked before the (expensive) signature verification.
        if !config.trust.is_trusted(&sh.identity) {
            return Err(Error::UntrustedPeer);
        }
        transcript.absorb(id);
        sh.identity
            .verify(label::S_SIGNATURE, &transcript.current(), &sh.signature)?;
        transcript.absorb(sig);
        hs.finished_key(Role::Server)?
            .verify(&transcript.current(), &sh.finished)?;
        transcript.absorb(fin);

        // Our own flight.
        let mut out = Vec::with_capacity(CLIENT_FINISH_LEN);
        emit(
            &mut out,
            &mut transcript,
            &header(MessageType::ClientFinish),
        );
        emit(
            &mut out,
            &mut transcript,
            config.identity.public().as_bytes(),
        );
        let signature = config
            .identity
            .sign(label::C_SIGNATURE, &transcript.current(), rng)?;
        emit(&mut out, &mut transcript, &signature.to_bytes());
        let mac = hs.finished_key(Role::Client)?.mac(&transcript.current())?;
        emit(&mut out, &mut transcript, &mac);

        let secrets = hs.into_session(Role::Client, &transcript.current())?;
        Ok((
            out,
            Session {
                role: Role::Client,
                peer: sh.identity,
                session_id: secrets.session_id,
                send: secrets.send,
                recv: secrets.recv,
            },
        ))
    }
}

impl fmt::Debug for ClientAwaitServerHello<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientAwaitServerHello")
    }
}

// ───────────────────────────── server side ─────────────────────────────

/// Process a `ClientHello` as the responder. Returns the state to keep and
/// the `ServerHello` to send.
///
/// Note: the server performs an encapsulation and an ML-DSA signature before
/// the client has proven anything; see `docs/DESIGN.md` (no DoS protection).
///
/// # Errors
/// Parsing errors, or a non-contributory X25519 share.
pub fn server_accept<'a, R: CryptoRng + ?Sized>(
    config: &'a Config,
    msg: &[u8],
    rng: &mut R,
) -> Result<(ServerAwaitClientFinish<'a>, Vec<u8>)> {
    let ch = ClientHello::decode(msg)?;
    let mut transcript = Transcript::new();
    transcript.absorb(msg);

    let (ct, ss) = ch.kem_public.encapsulate(rng)?;
    let mut random = [0u8; RANDOM_LEN];
    rng.fill_bytes(&mut random);

    let mut out = Vec::with_capacity(SERVER_HELLO_LEN);
    emit(&mut out, &mut transcript, &header(MessageType::ServerHello));
    emit(&mut out, &mut transcript, &random);
    emit(&mut out, &mut transcript, &ct.to_bytes());
    let hs = HandshakeSecret::derive(&ss, &transcript.current());
    drop(ss);

    emit(
        &mut out,
        &mut transcript,
        config.identity.public().as_bytes(),
    );
    let signature = config
        .identity
        .sign(label::S_SIGNATURE, &transcript.current(), rng)?;
    emit(&mut out, &mut transcript, &signature.to_bytes());
    let mac = hs.finished_key(Role::Server)?.mac(&transcript.current())?;
    emit(&mut out, &mut transcript, &mac);

    Ok((
        ServerAwaitClientFinish {
            config,
            hs,
            transcript,
        },
        out,
    ))
}

/// Responder waiting for `ClientFinish`.
pub struct ServerAwaitClientFinish<'a> {
    config: &'a Config,
    hs: HandshakeSecret,
    transcript: Transcript,
}

impl ServerAwaitClientFinish<'_> {
    /// Process `ClientFinish` and establish the session.
    ///
    /// # Errors
    /// Any parsing, trust, signature or key-confirmation failure.
    pub fn read_client_finish(self, msg: &[u8]) -> Result<Session> {
        let Self {
            config,
            hs,
            mut transcript,
        } = self;
        let cf = ClientFinish::decode(msg)?;
        let [id, sig, fin] = messages::segments(
            msg,
            [
                CLIENT_FINISH_ID_END,
                CLIENT_FINISH_SIG_END,
                CLIENT_FINISH_LEN,
            ],
        )?;

        if !config.trust.is_trusted(&cf.identity) {
            return Err(Error::UntrustedPeer);
        }
        transcript.absorb(id);
        cf.identity
            .verify(label::C_SIGNATURE, &transcript.current(), &cf.signature)?;
        transcript.absorb(sig);
        hs.finished_key(Role::Client)?
            .verify(&transcript.current(), &cf.finished)?;
        transcript.absorb(fin);

        let secrets = hs.into_session(Role::Server, &transcript.current())?;
        Ok(Session {
            role: Role::Server,
            peer: cf.identity,
            session_id: secrets.session_id,
            send: secrets.send,
            recv: secrets.recv,
        })
    }
}

impl fmt::Debug for ServerAwaitClientFinish<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServerAwaitClientFinish")
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
    //! Active-attacker tests. Tampering tests (in `tests/handshake.rs`) are
    //! caught by the `Finished` MACs alone; these model an attacker who
    //! *terminates* the key exchange itself, hence knows the session keys and
    //! can compute valid MACs, and claims a pinned identity it does not own.
    //! Only the signatures stop it.
    use super::*;
    use crate::kem::KemInitiator;
    use crate::test_util::os_rng;

    fn config(seed: u8, trusted: &[&IdentityPublic]) -> Config {
        Config {
            identity: IdentityKeypair::from_seed(&[seed; 64]),
            trust: trusted.iter().map(|p| p.fingerprint()).collect(),
        }
    }

    /// The attacker answers a `ClientHello` claiming `victim`'s identity,
    /// signing with its own key, with a correct `Finished` MAC.
    fn forge_server_hello(
        victim: &IdentityPublic,
        attacker: &IdentityKeypair,
        client_hello: &[u8],
    ) -> Vec<u8> {
        let mut rng = os_rng();
        let ch = ClientHello::decode(client_hello).unwrap();
        let mut t = Transcript::new();
        t.absorb(client_hello);
        let (ct, ss) = ch.kem_public.encapsulate(&mut rng).unwrap();
        let mut out = Vec::new();
        emit(&mut out, &mut t, &header(MessageType::ServerHello));
        emit(&mut out, &mut t, &[9u8; RANDOM_LEN]);
        emit(&mut out, &mut t, &ct.to_bytes());
        let hs = HandshakeSecret::derive(&ss, &t.current());
        emit(&mut out, &mut t, victim.as_bytes());
        let sig = attacker
            .sign(label::S_SIGNATURE, &t.current(), &mut rng)
            .unwrap();
        emit(&mut out, &mut t, &sig.to_bytes());
        let mac = hs
            .finished_key(Role::Server)
            .unwrap()
            .mac(&t.current())
            .unwrap();
        emit(&mut out, &mut t, &mac);
        out
    }

    #[test]
    fn server_impersonation_is_rejected() {
        let victim = IdentityKeypair::from_seed(&[2; 64]);
        let attacker = IdentityKeypair::from_seed(&[66; 64]);
        let client = config(1, &[victim.public()]);
        let mut rng = os_rng();
        let (c, hello) = client_start(&client, &mut rng);
        let forged = forge_server_hello(victim.public(), &attacker, &hello);
        assert_eq!(
            c.read_server_hello(&forged, &mut rng).unwrap_err(),
            Error::BadSignature
        );
    }

    /// Sanity check of the forgery helper: with the *real* key it succeeds,
    /// so the rejection above is due to the signature and nothing else.
    #[test]
    fn forgery_helper_with_real_key_is_accepted() {
        let victim = IdentityKeypair::from_seed(&[2; 64]);
        let client = config(1, &[victim.public()]);
        let mut rng = os_rng();
        let (c, hello) = client_start(&client, &mut rng);
        let forged = forge_server_hello(victim.public(), &victim, &hello);
        c.read_server_hello(&forged, &mut rng).unwrap();
    }

    /// The attacker runs the client side itself (so it knows the keys) and
    /// claims a pinned client identity it does not own.
    fn forged_client_finish(victim: &IdentityPublic, signer: &IdentityKeypair) -> Result<Session> {
        let mut rng = os_rng();
        let server = config(2, &[victim]);
        let kem = KemInitiator::generate(&mut rng);
        let hello = ClientHello {
            random: [7; RANDOM_LEN],
            kem_public: kem.public().clone(),
        }
        .encode();
        let (s, reply) = server_accept(&server, &hello, &mut rng).unwrap();

        let mut t = Transcript::new();
        t.absorb(&hello);
        let sh = ServerHello::decode(&reply).unwrap();
        let [kex, id, sig, fin] = messages::segments(
            &reply,
            [
                SERVER_HELLO_KEX_END,
                SERVER_HELLO_ID_END,
                SERVER_HELLO_SIG_END,
                SERVER_HELLO_LEN,
            ],
        )
        .unwrap();
        t.absorb(kex);
        let hs =
            HandshakeSecret::derive(&kem.decapsulate(&sh.kem_ciphertext).unwrap(), &t.current());
        for part in [id, sig, fin] {
            t.absorb(part);
        }
        let mut out = Vec::new();
        emit(&mut out, &mut t, &header(MessageType::ClientFinish));
        emit(&mut out, &mut t, victim.as_bytes());
        let sig = signer
            .sign(label::C_SIGNATURE, &t.current(), &mut rng)
            .unwrap();
        emit(&mut out, &mut t, &sig.to_bytes());
        let mac = hs
            .finished_key(Role::Client)
            .unwrap()
            .mac(&t.current())
            .unwrap();
        emit(&mut out, &mut t, &mac);
        s.read_client_finish(&out)
    }

    #[test]
    fn client_impersonation_is_rejected() {
        let victim = IdentityKeypair::from_seed(&[1; 64]);
        let attacker = IdentityKeypair::from_seed(&[66; 64]);
        assert_eq!(
            forged_client_finish(victim.public(), &attacker).unwrap_err(),
            Error::BadSignature
        );
        // Control: the same forgery path with the real key is accepted.
        forged_client_finish(victim.public(), &victim).unwrap();
    }
}
