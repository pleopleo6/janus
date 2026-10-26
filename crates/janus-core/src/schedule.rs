//! Transcript hash and key schedule (HKDF-SHA-384).
//!
//! ```text
//!   TH(x)     = SHA-384("janus/v1 transcript" ‖ wire bytes of everything up to x)
//!
//!   prk       = HKDF-Extract(salt = TH(kex), ikm = ss_mlkem ‖ ss_x25519)
//!   fk_s      = Expand-Label(prk, "s finished", "",        48)
//!   fk_c      = Expand-Label(prk, "c finished", "",        48)
//!   c2s_0     = Expand-Label(prk, "c2s traffic", TH(final), 48)
//!   s2c_0     = Expand-Label(prk, "s2c traffic", TH(final), 48)
//!   session_id= Expand-Label(prk, "exporter",    TH(final), 48)
//!
//!   per direction, epoch n:
//!   key_n     = Expand-Label(secret_n, "key",   "", 32)
//!   iv_n      = Expand-Label(secret_n, "iv",    "", 12)
//!   secret_n+1= Expand-Label(secret_n, "rekey", "", 48)
//! ```
//!
//! # Why these choices
//!
//! - **SHA-384**: ML-KEM-768 and ML-DSA-65 target NIST category 3 (≈ AES-192).
//!   SHA-256's 128-bit collision resistance would be the weakest link of the
//!   transcript; SHA-384 matches the PQ parameters (same reasoning as TLS
//!   suites pairing P-384 with SHA-384).
//! - **Transcript as HKDF salt**: `TH(kex)` covers both randoms, the initiator's
//!   ML-KEM encapsulation key and X25519 share, and the responder's ciphertext
//!   and X25519 share. Using it as the salt makes the PRK a function of
//!   `(ss_mlkem, ss_x25519, all KEM public values)`, which is exactly what the
//!   X-Wing combiner hashes. Binding the X25519 values matters because X25519
//!   is not IND-CCA as a KEM on its own; binding the ML-KEM ciphertext is
//!   needed for the "KEM combiner" security proofs (Giacon–Heuer–Poettering,
//!   Bindel et al.). HKDF-Extract is a dual PRF in either argument, so the PRK
//!   stays pseudorandom as long as *either* shared secret is.
//! - **Labels**: every derived value has its own label, so no two values can
//!   ever be equal (domain separation). Labels are encoded as in TLS 1.3's
//!   `HkdfLabel` (output length, length-prefixed `"janus/v1 " ‖ label`,
//!   length-prefixed context), which makes the `info` string injective.
//! - **Finished keys have an empty context**: the PRK already depends on
//!   `TH(kex)`, and the MAC itself covers the transcript at its position.
//! - **Traffic secrets use `TH(final)`**: the session keys commit to the whole
//!   handshake, including both identities and signatures.
//! - **Rekey** ratchets the secret forward with a one-way function and the old
//!   secret is zeroized: compromising epoch `n` reveals nothing about
//!   epochs `< n` (forward secrecy within a session).

use core::fmt;

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha384};
use subtle::ConstantTimeEq;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};
use crate::kem::HybridSharedSecret;

/// SHA-384 output length.
pub const HASH_LEN: usize = 48;
/// A transcript hash value.
pub type Hash = [u8; HASH_LEN];
/// ChaCha20-Poly1305 key length.
pub const AEAD_KEY_LEN: usize = 32;
/// ChaCha20-Poly1305 nonce length.
pub const AEAD_IV_LEN: usize = 12;

/// Every label used by Janus, in one place.
pub mod label {
    /// Prefix of every HKDF label (protocol name and version).
    pub const PREFIX: &[u8] = b"janus/v1 ";
    /// Prefix absorbed first into every transcript hash.
    pub const TRANSCRIPT: &[u8] = b"janus/v1 transcript";
    /// Responder key-confirmation key.
    pub const S_FINISHED: &[u8] = b"s finished";
    /// Initiator key-confirmation key.
    pub const C_FINISHED: &[u8] = b"c finished";
    /// Initiator → responder traffic secret.
    pub const C2S_TRAFFIC: &[u8] = b"c2s traffic";
    /// Responder → initiator traffic secret.
    pub const S2C_TRAFFIC: &[u8] = b"s2c traffic";
    /// Session identifier (channel binding / user-visible check).
    pub const EXPORTER: &[u8] = b"exporter";
    /// AEAD key of a traffic epoch.
    pub const KEY: &[u8] = b"key";
    /// AEAD IV of a traffic epoch.
    pub const IV: &[u8] = b"iv";
    /// Next traffic secret.
    pub const REKEY: &[u8] = b"rekey";
    /// Hybrid-signature role label of the responder (signs `TH(server id)`).
    pub const S_SIGNATURE: &[u8] = b"janus/v1 server signature";
    /// Hybrid-signature role label of the initiator (signs `TH(client id)`).
    pub const C_SIGNATURE: &[u8] = b"janus/v1 client signature";
}

/// Running transcript hash.
#[derive(Clone)]
pub(crate) struct Transcript(Sha384);

impl Transcript {
    pub(crate) fn new() -> Self {
        let mut h = Sha384::new();
        h.update(label::TRANSCRIPT);
        Self(h)
    }

    pub(crate) fn absorb(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    /// Hash of everything absorbed so far (the running state is kept).
    pub(crate) fn current(&self) -> Hash {
        self.0.clone().finalize().into()
    }
}

/// TLS 1.3-style `HKDF-Expand-Label`.
fn expand_label(hk: &Hkdf<Sha384>, label: &[u8], context: &[u8], out: &mut [u8]) -> Result<()> {
    let out_len = u16::try_from(out.len()).map_err(|_| Error::Internal)?;
    let label_len = label
        .len()
        .checked_add(label::PREFIX.len())
        .and_then(|n| u8::try_from(n).ok())
        .ok_or(Error::Internal)?;
    let ctx_len = u8::try_from(context.len()).map_err(|_| Error::Internal)?;
    hk.expand_multi_info(
        &[
            &out_len.to_be_bytes(),
            &[label_len],
            label::PREFIX,
            label,
            &[ctx_len],
            context,
        ],
        out,
    )
    .map_err(|_| Error::Internal)
}

/// Which side of the handshake we are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The initiator ("client"), which sends `ClientHello`.
    Client,
    /// The responder ("server").
    Server,
}

/// The handshake PRK, held as a keyed HMAC state. Its SHA-384 cores are
/// zeroized on drop (see the `hmac_state_is_zeroize_on_drop` test).
pub(crate) struct HandshakeSecret {
    hk: Hkdf<Sha384>,
}

impl HandshakeSecret {
    pub(crate) fn derive(ss: &HybridSharedSecret, th_kex: &Hash) -> Self {
        Self {
            hk: Hkdf::<Sha384>::new(Some(th_kex), ss.as_bytes()),
        }
    }

    /// Key-confirmation key of the side that *sends* the `Finished` MAC.
    pub(crate) fn finished_key(&self, sender: Role) -> Result<FinishedKey> {
        let label = match sender {
            Role::Client => label::C_FINISHED,
            Role::Server => label::S_FINISHED,
        };
        let mut k = Zeroizing::new([0u8; HASH_LEN]);
        expand_label(&self.hk, label, &[], k.as_mut_slice())?;
        Ok(FinishedKey(k))
    }

    /// Derive the session secrets. Consumes the PRK, which is then zeroized.
    pub(crate) fn into_session(self, role: Role, th_final: &Hash) -> Result<SessionSecrets> {
        let mut c2s = Zeroizing::new([0u8; HASH_LEN]);
        let mut s2c = Zeroizing::new([0u8; HASH_LEN]);
        let mut id = [0u8; HASH_LEN];
        expand_label(&self.hk, label::C2S_TRAFFIC, th_final, c2s.as_mut_slice())?;
        expand_label(&self.hk, label::S2C_TRAFFIC, th_final, s2c.as_mut_slice())?;
        expand_label(&self.hk, label::EXPORTER, th_final, &mut id)?;
        let (c2s, s2c) = (TrafficSecret::new(c2s, 0), TrafficSecret::new(s2c, 0));
        let (send, recv) = match role {
            Role::Client => (c2s, s2c),
            Role::Server => (s2c, c2s),
        };
        Ok(SessionSecrets {
            send,
            recv,
            session_id: id,
        })
    }
}

/// HMAC-SHA-384 key for a `Finished` message.
pub(crate) struct FinishedKey(Zeroizing<Hash>);

impl FinishedKey {
    pub(crate) fn mac(&self, th: &Hash) -> Result<Hash> {
        let mut m = <Hmac<Sha384> as KeyInit>::new_from_slice(self.0.as_slice())
            .map_err(|_| Error::Internal)?;
        m.update(th);
        Ok(m.finalize().into_bytes().into())
    }

    /// Constant-time check of a received `Finished` MAC.
    pub(crate) fn verify(&self, th: &Hash, tag: &[u8]) -> Result<()> {
        let expected = self.mac(th)?;
        if bool::from(expected.as_slice().ct_eq(tag)) {
            Ok(())
        } else {
            Err(Error::BadFinished)
        }
    }
}

/// Output of a completed handshake (before it is attached to a peer).
pub(crate) struct SessionSecrets {
    pub(crate) send: TrafficSecret,
    pub(crate) recv: TrafficSecret,
    pub(crate) session_id: Hash,
}

/// Traffic secret of one direction, at one epoch.
///
/// Zeroized on drop. [`TrafficSecret::next`] consumes `self`, so an old
/// epoch's secret cannot outlive the ratchet step.
#[derive(ZeroizeOnDrop)]
pub struct TrafficSecret {
    secret: Zeroizing<Hash>,
    #[zeroize(skip)]
    epoch: u64,
}

impl TrafficSecret {
    fn new(secret: Zeroizing<Hash>, epoch: u64) -> Self {
        Self { secret, epoch }
    }

    /// Epoch number (0 right after the handshake, +1 at every rekey).
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// ChaCha20-Poly1305 key and IV of this epoch.
    ///
    /// # Errors
    /// [`Error::Internal`] only (HKDF output lengths are constants).
    pub fn aead_key_iv(&self) -> Result<AeadKeyMaterial> {
        let hk = self.hkdf()?;
        let mut m = AeadKeyMaterial {
            key: Zeroizing::new([0u8; AEAD_KEY_LEN]),
            iv: Zeroizing::new([0u8; AEAD_IV_LEN]),
        };
        expand_label(&hk, label::KEY, &[], m.key.as_mut_slice())?;
        expand_label(&hk, label::IV, &[], m.iv.as_mut_slice())?;
        Ok(m)
    }

    /// Ratchet to the next epoch. The current secret is zeroized.
    ///
    /// # Errors
    /// [`Error::Internal`] if the epoch counter would overflow.
    pub fn next(self) -> Result<Self> {
        let hk = self.hkdf()?;
        let mut next = Zeroizing::new([0u8; HASH_LEN]);
        expand_label(&hk, label::REKEY, &[], next.as_mut_slice())?;
        let epoch = self.epoch.checked_add(1).ok_or(Error::Internal)?;
        Ok(Self::new(next, epoch))
    }

    fn hkdf(&self) -> Result<Hkdf<Sha384>> {
        Hkdf::<Sha384>::from_prk(self.secret.as_slice()).map_err(|_| Error::Internal)
    }

    #[cfg(test)]
    pub(crate) fn expose(&self) -> &Hash {
        &self.secret
    }
}

/// AEAD key and static IV of one direction and epoch. Zeroized on drop.
///
/// The IV is not secret in the AEAD sense, but deriving it (rather than
/// using zeros) means nonces are unpredictable to an outside observer, as in
/// TLS 1.3.
pub struct AeadKeyMaterial {
    /// ChaCha20-Poly1305 key.
    pub key: Zeroizing<[u8; AEAD_KEY_LEN]>,
    /// Static IV, XORed with the record sequence number to form the nonce.
    pub iv: Zeroizing<[u8; AEAD_IV_LEN]>,
}

impl fmt::Debug for AeadKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AeadKeyMaterial(<redacted>)")
    }
}

impl fmt::Debug for TrafficSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrafficSecret")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
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

    /// Secrets must not linger in the HMAC state once dropped.
    ///
    /// `hmac` 0.13 does not mark `Hmac` itself as `ZeroizeOnDrop`, but its
    /// only fields are two SHA-384 block cores (the key-dependent inner/outer
    /// states) and a block buffer. With the `zeroize` features enabled those
    /// zeroize themselves on drop, which is what this test pins down: if a
    /// dependency update drops that guarantee, the build of this test fails.
    #[test]
    fn hmac_state_is_zeroize_on_drop() {
        fn assert_zod<T: ZeroizeOnDrop>() {}
        assert_zod::<sha2::block_api::Sha512VarCore>();
        assert_zod::<sha2::Sha384>();
        assert_zod::<TrafficSecret>();
    }

    fn dummy_secret(b: u8) -> TrafficSecret {
        TrafficSecret::new(Zeroizing::new([b; HASH_LEN]), 0)
    }

    #[test]
    fn labels_are_domain_separated() {
        let hk = Hkdf::<Sha384>::from_prk(&[1u8; HASH_LEN]).unwrap();
        let mut outs = Vec::new();
        for l in [
            label::S_FINISHED,
            label::C_FINISHED,
            label::C2S_TRAFFIC,
            label::S2C_TRAFFIC,
            label::EXPORTER,
            label::KEY,
            label::IV,
            label::REKEY,
        ] {
            let mut o = [0u8; 12];
            expand_label(&hk, l, &[], &mut o).unwrap();
            outs.push(o);
        }
        for (i, a) in outs.iter().enumerate() {
            for b in &outs[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    /// The output length is part of the label, so a 12-byte output is not a
    /// prefix of a 32-byte output under the same label.
    #[test]
    fn output_length_is_bound() {
        let hk = Hkdf::<Sha384>::from_prk(&[1u8; HASH_LEN]).unwrap();
        let (mut a, mut b) = ([0u8; 12], [0u8; 32]);
        expand_label(&hk, label::KEY, &[], &mut a).unwrap();
        expand_label(&hk, label::KEY, &[], &mut b).unwrap();
        assert_ne!(a, b[..12]);
    }

    #[test]
    fn rekey_changes_keys_and_increments_epoch() {
        let s0 = dummy_secret(9);
        let m0 = s0.aead_key_iv().unwrap();
        let s1 = s0.next().unwrap();
        assert_eq!(s1.epoch(), 1);
        let m1 = s1.aead_key_iv().unwrap();
        assert_ne!(*m0.key, *m1.key);
        assert_ne!(*m0.iv, *m1.iv);
        // Deterministic: both peers ratchet to the same value.
        assert_eq!(
            dummy_secret(9).next().unwrap().expose(),
            dummy_secret(9).next().unwrap().expose()
        );
    }

    #[test]
    fn transcript_is_streaming_and_input_sensitive() {
        let mut a = Transcript::new();
        a.absorb(b"ab");
        let mut b = Transcript::new();
        b.absorb(b"a");
        b.absorb(b"b");
        assert_eq!(a.current(), b.current());
        b.absorb(b"");
        assert_eq!(a.current(), b.current());
        let mut c = Transcript::new();
        c.absorb(b"ac");
        assert_ne!(a.current(), c.current());
    }
}
