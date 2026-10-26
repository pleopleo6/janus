//! Hybrid identities and signatures: Ed25519 + ML-DSA-65.
//!
//! An identity is a pair of long-term keys. A hybrid signature is valid only
//! if **both** component signatures are valid ("AND" combiner): forging one
//! requires breaking Ed25519 *and* ML-DSA-65.
//!
//! # Binding the two halves together (anti-stripping)
//!
//! With a naive AND combiner, the two halves are independent: an attacker who
//! can break one scheme could take the *other* half of an honest hybrid
//! signature and re-attach it to a hybrid key of its own choosing. To prevent
//! such key-substitution / "stripping" games, each component signs the same
//! message
//!
//! ```text
//! M' = "janus/v1/hybrid-sig" ‖ len(label):u8 ‖ label ‖ hybrid_public_key ‖ msg
//! ```
//!
//! where `hybrid_public_key = ed25519_pk ‖ mldsa_pk` is the **full** hybrid
//! key. Each signature therefore commits to the other scheme's public key.
//! `label` separates protocol roles ("server signs the transcript" vs. "client
//! signs the transcript"), so a signature produced in one role is never valid
//! in another. For ML-DSA the label is *additionally* passed as the FIPS 204
//! context string, the scheme's native domain-separation mechanism.
//!
//! # Variants used
//! - Ed25519 (RFC 8032, pure), verified with `verify_strict`, which rejects
//!   non-canonical `S`, small-order `R` and weak public keys (no malleability).
//! - ML-DSA-65 (FIPS 204, pure, *hedged*): signing mixes fresh randomness into
//!   the nonce, as recommended by FIPS 204 §3.4 to resist fault and
//!   side-channel attacks. The deterministic variant is only used by tests.

use core::fmt;

use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
use ml_dsa::{Keypair as _, MlDsa65, SigningKey as DsaSigningKey, VerifyingKey as DsaVerifyingKey};
use rand_core::CryptoRng;
use sha2::{Digest, Sha384};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::kem::HexPrefix;

/// Ed25519 public key length.
pub const ED25519_PK_LEN: usize = 32;
/// Ed25519 signature length.
pub const ED25519_SIG_LEN: usize = 64;
/// ML-DSA-65 public key length (FIPS 204, Table 2).
pub const MLDSA65_PK_LEN: usize = 1952;
/// ML-DSA-65 signature length (FIPS 204, Table 2).
pub const MLDSA65_SIG_LEN: usize = 3309;
/// Encoded [`IdentityPublic`]: `ed25519_pk ‖ mldsa_pk`.
pub const IDENTITY_PUBLIC_LEN: usize = ED25519_PK_LEN + MLDSA65_PK_LEN;
/// Encoded [`HybridSignature`]: `ed25519_sig ‖ mldsa_sig`.
pub const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + MLDSA65_SIG_LEN;
/// Secret seed of an identity: `ed25519_seed ‖ mldsa_xi`.
pub const IDENTITY_SEED_LEN: usize = 64;
/// Length of an identity [`Fingerprint`].
pub const FINGERPRINT_LEN: usize = 48;

/// Domain-separation prefix of every hybrid-signed message.
const SIG_PREFIX: &[u8] = b"janus/v1/hybrid-sig";
/// Domain-separation prefix of identity fingerprints.
const FINGERPRINT_PREFIX: &[u8] = b"janus/v1/fingerprint";

/// A long-term hybrid signing identity.
///
/// Secret keys are zeroized on drop (`ed25519-dalek` and `ml-dsa` are built
/// with their `zeroize` feature).
pub struct IdentityKeypair {
    ed: EdSigningKey,
    dsa: DsaSigningKey<MlDsa65>,
    public: IdentityPublic,
}

impl IdentityKeypair {
    /// Generate a new identity from 64 bytes of randomness.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut seed = Zeroizing::new([0u8; IDENTITY_SEED_LEN]);
        rng.fill_bytes(seed.as_mut_slice());
        Self::from_seed(&seed)
    }

    /// Deterministically derive an identity from its secret seed
    /// (`ed25519_seed ‖ mldsa_xi`, both 32 bytes, as defined by RFC 8032 §5.1.5
    /// and FIPS 204 Algorithm 6).
    pub fn from_seed(seed: &[u8; IDENTITY_SEED_LEN]) -> Self {
        let (ed_seed, dsa_seed) = seed.split_at(32);
        let mut ed_bytes = Zeroizing::new([0u8; 32]);
        ed_bytes.copy_from_slice(ed_seed);
        let mut xi = ml_dsa::Seed::default();
        xi.copy_from_slice(dsa_seed);

        let ed = EdSigningKey::from_bytes(&ed_bytes);
        let dsa = DsaSigningKey::<MlDsa65>::from_seed(&xi);
        xi.zeroize();
        let public = IdentityPublic::from_keys(ed.verifying_key(), dsa.verifying_key());
        Self { ed, dsa, public }
    }

    /// Export the secret seed (for storage). Handle with care.
    pub fn to_seed(&self) -> Zeroizing<[u8; IDENTITY_SEED_LEN]> {
        let mut out = Zeroizing::new([0u8; IDENTITY_SEED_LEN]);
        let (a, b) = out.split_at_mut(32);
        a.copy_from_slice(self.ed.as_bytes());
        b.copy_from_slice(self.dsa.as_seed().as_slice());
        out
    }

    /// The public half of this identity.
    pub fn public(&self) -> &IdentityPublic {
        &self.public
    }

    /// Produce a hybrid signature over `msg` in the role given by `label`.
    ///
    /// # Errors
    /// [`Error::Internal`] if `label` is longer than 255 bytes (all labels are
    /// compile-time constants, so this is unreachable in practice).
    pub fn sign<R: CryptoRng + ?Sized>(
        &self,
        label: &[u8],
        msg: &[u8],
        rng: &mut R,
    ) -> Result<HybridSignature> {
        let m = signed_message(label, &self.public, msg)?;
        let ed = self.ed.sign(&m).to_bytes();
        let dsa = self
            .dsa
            .expanded_key()
            .sign_randomized(&m, label, rng)
            .map_err(|_| Error::Internal)?
            .encode();
        HybridSignature::from_parts(&ed, dsa.as_slice())
    }

    /// Deterministic variant, for reproducible tests only.
    #[cfg(test)]
    pub(crate) fn sign_deterministic(&self, label: &[u8], msg: &[u8]) -> Result<HybridSignature> {
        let m = signed_message(label, &self.public, msg)?;
        let ed = self.ed.sign(&m).to_bytes();
        let dsa = self
            .dsa
            .expanded_key()
            .sign_deterministic(&m, label)
            .map_err(|_| Error::Internal)?
            .encode();
        HybridSignature::from_parts(&ed, dsa.as_slice())
    }

    #[cfg(test)]
    pub(crate) fn mldsa_sign_raw_deterministic(&self, msg: &[u8], ctx: &[u8]) -> Vec<u8> {
        self.dsa
            .expanded_key()
            .sign_deterministic(msg, ctx)
            .map(|s| s.encode().to_vec())
            .unwrap_or_default()
    }
}

impl fmt::Debug for IdentityKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityKeypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// The public half of a hybrid identity: `ed25519_pk ‖ mldsa_pk`.
#[derive(Clone)]
pub struct IdentityPublic {
    ed: EdVerifyingKey,
    dsa: DsaVerifyingKey<MlDsa65>,
    bytes: Box<[u8; IDENTITY_PUBLIC_LEN]>,
}

impl IdentityPublic {
    fn from_keys(ed: EdVerifyingKey, dsa: DsaVerifyingKey<MlDsa65>) -> Self {
        let mut bytes = Box::new([0u8; IDENTITY_PUBLIC_LEN]);
        let (a, b) = bytes.split_at_mut(ED25519_PK_LEN);
        a.copy_from_slice(ed.as_bytes());
        b.copy_from_slice(dsa.encode().as_slice());
        Self { ed, dsa, bytes }
    }

    /// Parse and validate an encoded identity.
    ///
    /// # Errors
    /// - [`Error::Malformed`] on a length mismatch;
    /// - [`Error::InvalidPublicKey`] if the Ed25519 key does not decompress or
    ///   is a small-order ("weak") point.
    ///
    /// Every 1952-byte string decodes to *some* ML-DSA-65 key (`t1` is a
    /// packing of 10-bit values, all in range), so there is nothing to check
    /// on that half. To keep the encoding canonical, we still re-encode and
    /// compare.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != IDENTITY_PUBLIC_LEN {
            return Err(Error::Malformed);
        }
        let (ed, dsa) = bytes
            .split_first_chunk::<ED25519_PK_LEN>()
            .ok_or(Error::Malformed)?;
        let ed = EdVerifyingKey::from_bytes(ed).map_err(|_| Error::InvalidPublicKey)?;
        if ed.is_weak() {
            return Err(Error::InvalidPublicKey);
        }
        let enc =
            ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(dsa).map_err(|_| Error::Malformed)?;
        let dsa = DsaVerifyingKey::<MlDsa65>::decode(&enc);
        let parsed = Self::from_keys(ed, dsa);
        // Ed25519 point decoding accepts a few non-canonical encodings;
        // re-encoding guarantees one byte string per identity.
        if !bool::from(parsed.bytes.as_slice().ct_eq(bytes)) {
            return Err(Error::InvalidPublicKey);
        }
        Ok(parsed)
    }

    /// Canonical encoding.
    pub fn as_bytes(&self) -> &[u8; IDENTITY_PUBLIC_LEN] {
        &self.bytes
    }

    /// Stable, short identifier of this identity, used for pinning.
    ///
    /// `SHA-384("janus/v1/fingerprint" ‖ ed25519_pk ‖ mldsa_pk)`. The full hybrid
    /// key is hashed so that pinning a fingerprint pins *both* halves.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut h = Sha384::new();
        h.update(FINGERPRINT_PREFIX);
        h.update(self.bytes.as_slice());
        Fingerprint(h.finalize().into())
    }

    /// Verify a hybrid signature produced by [`IdentityKeypair::sign`] with
    /// the same `label` and `msg`.
    ///
    /// Both component signatures are always checked (no short-circuit), and
    /// the result is the AND of both.
    ///
    /// # Errors
    /// [`Error::BadSignature`] unless both signatures are valid.
    pub fn verify(&self, label: &[u8], msg: &[u8], sig: &HybridSignature) -> Result<()> {
        let m = signed_message(label, self, msg)?;
        let ed_ok = ed25519_verify_raw(&self.ed, &m, &sig.ed);
        let dsa_ok = mldsa_verify_raw(&self.dsa, &m, label, sig.dsa.as_slice());
        if ed_ok & dsa_ok {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }
}

impl PartialEq for IdentityPublic {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.bytes.as_slice().ct_eq(other.bytes.as_slice()))
    }
}
impl Eq for IdentityPublic {}

impl fmt::Debug for IdentityPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("IdentityPublic")
            .field(&self.fingerprint())
            .finish()
    }
}

/// `M' = prefix ‖ len(label) ‖ label ‖ hybrid_pk ‖ msg` (see module docs).
fn signed_message(label: &[u8], pk: &IdentityPublic, msg: &[u8]) -> Result<Vec<u8>> {
    let label_len = u8::try_from(label.len()).map_err(|_| Error::Internal)?;
    let mut m = Vec::new();
    m.extend_from_slice(SIG_PREFIX);
    m.push(label_len);
    m.extend_from_slice(label);
    m.extend_from_slice(pk.as_bytes());
    m.extend_from_slice(msg);
    Ok(m)
}

/// Plain Ed25519 verification (`verify_strict`). Exposed to the crate so that
/// external test vectors exercise exactly the call Janus makes.
pub(crate) fn ed25519_verify_raw(
    vk: &EdVerifyingKey,
    msg: &[u8],
    sig: &[u8; ED25519_SIG_LEN],
) -> bool {
    let sig = ed25519_dalek::Signature::from_bytes(sig);
    vk.verify_strict(msg, &sig).is_ok()
}

/// Plain ML-DSA-65 verification with a FIPS 204 context string. A signature
/// that does not even decode (bad hint encoding, norm too large) is invalid.
pub(crate) fn mldsa_verify_raw(
    vk: &DsaVerifyingKey<MlDsa65>,
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> bool {
    match ml_dsa::Signature::<MlDsa65>::try_from(sig) {
        Ok(sig) => vk.verify_with_context(msg, ctx, &sig),
        Err(_) => false,
    }
}

/// A hybrid signature: `ed25519_sig ‖ mldsa_sig`.
///
/// Parsing only checks the length; the components are decoded during
/// verification, so that every decoding failure is reported uniformly as
/// [`Error::BadSignature`].
#[derive(Clone, PartialEq, Eq)]
pub struct HybridSignature {
    ed: [u8; ED25519_SIG_LEN],
    dsa: Box<[u8; MLDSA65_SIG_LEN]>,
}

impl HybridSignature {
    fn from_parts(ed: &[u8; ED25519_SIG_LEN], dsa: &[u8]) -> Result<Self> {
        let dsa: [u8; MLDSA65_SIG_LEN] = dsa.try_into().map_err(|_| Error::Internal)?;
        Ok(Self {
            ed: *ed,
            dsa: Box::new(dsa),
        })
    }

    /// Parse an encoded hybrid signature (length check only).
    ///
    /// # Errors
    /// [`Error::Malformed`] on a length mismatch.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HYBRID_SIG_LEN {
            return Err(Error::Malformed);
        }
        let (ed, dsa) = bytes
            .split_first_chunk::<ED25519_SIG_LEN>()
            .ok_or(Error::Malformed)?;
        Self::from_parts(ed, dsa).map_err(|_| Error::Malformed)
    }

    /// Canonical encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_SIG_LEN);
        out.extend_from_slice(&self.ed);
        out.extend_from_slice(self.dsa.as_slice());
        out
    }
}

impl fmt::Debug for HybridSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridSignature")
            .field("ed25519", &HexPrefix(&self.ed))
            .field("mldsa65", &HexPrefix(self.dsa.as_slice()))
            .finish()
    }
}

/// SHA-384 fingerprint of an [`IdentityPublic`]. Compared in constant time.
#[derive(Clone, Copy)]
pub struct Fingerprint(pub [u8; FINGERPRINT_LEN]);

impl ConstantTimeEq for Fingerprint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Fingerprint {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}
impl Eq for Fingerprint {}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({:?})", HexPrefix(&self.0))
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
    use crate::test_util::os_rng;

    const LABEL: &[u8] = b"test label";

    #[test]
    fn sign_verify_roundtrip() {
        let mut rng = os_rng();
        let id = IdentityKeypair::generate(&mut rng);
        let sig = id.sign(LABEL, b"hello", &mut rng).unwrap();
        let sig = HybridSignature::from_bytes(&sig.to_bytes()).unwrap();
        let pk = IdentityPublic::from_bytes(id.public().as_bytes()).unwrap();
        pk.verify(LABEL, b"hello", &sig).unwrap();
    }

    #[test]
    fn seed_roundtrip() {
        let id = IdentityKeypair::generate(&mut os_rng());
        let id2 = IdentityKeypair::from_seed(&id.to_seed());
        assert_eq!(id.public(), id2.public());
    }

    #[test]
    fn wrong_message_label_or_key_fails() {
        let mut rng = os_rng();
        let id = IdentityKeypair::generate(&mut rng);
        let other = IdentityKeypair::generate(&mut rng);
        let sig = id.sign(LABEL, b"hello", &mut rng).unwrap();
        let pk = id.public();
        assert_eq!(pk.verify(LABEL, b"hellO", &sig), Err(Error::BadSignature));
        assert_eq!(
            pk.verify(b"other label", b"hello", &sig),
            Err(Error::BadSignature)
        );
        assert_eq!(
            other.public().verify(LABEL, b"hello", &sig),
            Err(Error::BadSignature)
        );
    }

    /// The core hybrid property: corrupting either half alone is enough to
    /// make verification fail.
    #[test]
    fn both_halves_are_required() {
        let mut rng = os_rng();
        let id = IdentityKeypair::generate(&mut rng);
        let good = id.sign(LABEL, b"m", &mut rng).unwrap().to_bytes();

        let mut bad_ed = good.clone();
        bad_ed[5] ^= 0x01;
        let mut bad_dsa = good.clone();
        bad_dsa[ED25519_SIG_LEN + 100] ^= 0x01;
        for bytes in [bad_ed, bad_dsa] {
            let sig = HybridSignature::from_bytes(&bytes).unwrap();
            assert_eq!(
                id.public().verify(LABEL, b"m", &sig),
                Err(Error::BadSignature)
            );
        }
    }

    /// Anti-stripping: a half-signature taken from identity A does not verify
    /// under a hybrid identity B that shares the same key for that half.
    #[test]
    fn halves_cannot_be_transplanted() {
        let mut rng = os_rng();
        let a = IdentityKeypair::generate(&mut rng);
        let b = IdentityKeypair::generate(&mut rng);
        // Hybrid key mixing A's Ed25519 key with B's ML-DSA key.
        let mut mixed = *b.public().as_bytes();
        mixed[..ED25519_PK_LEN].copy_from_slice(&a.public().as_bytes()[..ED25519_PK_LEN]);
        let mixed = IdentityPublic::from_bytes(&mixed).unwrap();

        let sig_a = a.sign(LABEL, b"m", &mut rng).unwrap();
        let m_mixed = signed_message(LABEL, &mixed, b"m").unwrap();
        // A's Ed25519 half was computed over a message naming A's full key,
        // so it is not valid for the message naming the mixed key.
        assert!(!ed25519_verify_raw(&mixed.ed, &m_mixed, &sig_a.ed));
    }

    #[test]
    fn rejects_bad_identity_encodings() {
        assert_eq!(
            IdentityPublic::from_bytes(&[0u8; 10]).unwrap_err(),
            Error::Malformed
        );
        let id = IdentityKeypair::generate(&mut os_rng());
        // Small-order Ed25519 point (the identity, encoded as y = 1).
        let mut weak = *id.public().as_bytes();
        weak[..32].copy_from_slice(&{
            let mut p = [0u8; 32];
            p[0] = 1;
            p
        });
        assert_eq!(
            IdentityPublic::from_bytes(&weak).unwrap_err(),
            Error::InvalidPublicKey
        );
    }

    #[test]
    fn fingerprint_depends_on_both_halves() {
        let id = IdentityKeypair::generate(&mut os_rng());
        let fp = id.public().fingerprint();
        let mut bytes = *id.public().as_bytes();
        bytes[IDENTITY_PUBLIC_LEN - 1] ^= 1;
        let other = IdentityPublic::from_bytes(&bytes).unwrap();
        assert_ne!(fp, other.fingerprint());
    }

    #[test]
    fn deterministic_signing_is_deterministic() {
        let id = IdentityKeypair::from_seed(&[7u8; IDENTITY_SEED_LEN]);
        let s1 = id.sign_deterministic(LABEL, b"x").unwrap();
        let s2 = id.sign_deterministic(LABEL, b"x").unwrap();
        assert_eq!(s1, s2);
        id.public().verify(LABEL, b"x", &s1).unwrap();
    }
}
