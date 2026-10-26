//! Hybrid key encapsulation: X25519 + ML-KEM-768.
//!
//! The two components are run side by side and their shared secrets are
//! concatenated (`ss_mlkem ‖ ss_x25519`). The concatenation alone is **not** a
//! secure combiner: it only becomes one once it is fed to HKDF together with a
//! hash of every public key and ciphertext exchanged (see
//! [`crate::schedule`]). This mirrors the X-Wing / TLS-hybrid design, where
//! the classical ciphertext and public key must be bound into the KDF because
//! X25519 alone is not IND-CCA secure as a KEM.
//!
//! Shape of the exchange (the handshake initiator is the "decapsulator"):
//!
//! ```text
//!   initiator                                   responder
//!   KemInitiator::generate()
//!         ── KemPublic  (mlkem_ek ‖ x25519_pk) ──▶
//!                                               KemPublic::encapsulate()
//!         ◀── KemCiphertext (mlkem_ct ‖ x25519_pk) ──
//!   KemInitiator::decapsulate()
//! ```
//!
//! Byte order follows the `X25519MLKEM768` TLS code point
//! (draft-ietf-tls-ecdhe-mlkem): ML-KEM component first, X25519 second, both
//! on the wire and in the shared secret. X-Wing uses the same order. Nothing
//! in Janus depends on it for security (both parts have fixed lengths, so the
//! encoding is unambiguous), but matching deployed designs avoids surprises.
//!
//! Both sides use fresh ephemeral keys for every handshake; that is what
//! gives Janus forward secrecy. [`KemInitiator::decapsulate`] consumes
//! `self`, so the ephemeral secret cannot be reused by construction.

use core::fmt;

use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport, KeyInit};
use ml_kem::{DecapsulationKey768, EncapsulationKey768};
use rand_core::CryptoRng;
use subtle::{Choice, ConstantTimeEq};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};

/// Length of an X25519 public key.
pub const X25519_PK_LEN: usize = 32;
/// Length of an ML-KEM-768 encapsulation key (FIPS 203, Table 3).
pub const MLKEM768_EK_LEN: usize = 1184;
/// Length of an ML-KEM-768 ciphertext (FIPS 203, Table 3).
pub const MLKEM768_CT_LEN: usize = 1088;
/// Length of an ML-KEM seed `d ‖ z` (FIPS 203, §7.1).
pub const MLKEM_SEED_LEN: usize = 64;
/// Length of each component shared secret.
pub const COMPONENT_SS_LEN: usize = 32;

/// Encoded [`KemPublic`]: `mlkem_ek ‖ x25519_pk`.
pub const KEM_PUBLIC_LEN: usize = X25519_PK_LEN + MLKEM768_EK_LEN;
/// Encoded [`KemCiphertext`]: `mlkem_ct ‖ x25519_pk`.
pub const KEM_CIPHERTEXT_LEN: usize = X25519_PK_LEN + MLKEM768_CT_LEN;
/// Length of the concatenated [`HybridSharedSecret`].
pub const HYBRID_SS_LEN: usize = 2 * COMPONENT_SS_LEN;

/// The initiator's ephemeral hybrid key pair.
///
/// Holds secret material: zeroized on drop by the underlying crates
/// (`x25519-dalek` and `ml-kem`, both built with their `zeroize` feature).
pub struct KemInitiator {
    x25519: EphemeralSecret,
    mlkem: DecapsulationKey768,
    public: KemPublic,
}

impl KemInitiator {
    /// Generate a fresh ephemeral key pair.
    ///
    /// Randomness is drawn in a fixed, documented order so that known-answer
    /// tests can drive this exact code path: 32 bytes for the X25519 scalar,
    /// then 64 bytes for the ML-KEM seed `d ‖ z`.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let x25519 = EphemeralSecret::random_from_rng(rng);

        let mut seed = Zeroizing::new(ml_kem::Seed::default());
        rng.fill_bytes(seed.as_mut_slice());
        // `KeyInit::new` borrows the seed, so our zeroizing copy is the only one.
        let mlkem = DecapsulationKey768::new(&seed);

        let public = KemPublic {
            x25519: X25519Public::from(&x25519),
            mlkem: mlkem.encapsulation_key().clone(),
        };
        Self {
            x25519,
            mlkem,
            public,
        }
    }

    /// The public half, to be sent to the responder.
    pub fn public(&self) -> &KemPublic {
        &self.public
    }

    /// Recover the hybrid shared secret from the responder's ciphertext.
    ///
    /// Consumes `self`: an ephemeral key is used exactly once.
    ///
    /// # Errors
    /// [`Error::NonContributory`] if the responder's X25519 share is a
    /// small-order point. ML-KEM decapsulation never fails: an invalid
    /// ciphertext yields a pseudo-random key (implicit rejection, FIPS 203
    /// §6.3), which then makes key confirmation fail.
    pub fn decapsulate(self, ct: &KemCiphertext) -> Result<HybridSharedSecret> {
        let ss_x = self.x25519.diffie_hellman(&ct.x25519);
        if !ss_x.was_contributory() {
            return Err(Error::NonContributory);
        }
        let mut ss_k = self.mlkem.decapsulate(&ct.mlkem);
        let out = HybridSharedSecret::from_parts(ss_k.as_slice(), ss_x.as_bytes());
        ss_k.as_mut_slice().zeroize();
        out
    }
}

impl fmt::Debug for KemInitiator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KemInitiator")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// The initiator's public hybrid share: `mlkem_ek ‖ x25519_pk`.
#[derive(Clone, PartialEq, Eq)]
pub struct KemPublic {
    x25519: X25519Public,
    mlkem: EncapsulationKey768,
}

impl KemPublic {
    /// Parse and validate an encoded share.
    ///
    /// # Errors
    /// - [`Error::Malformed`] on a length mismatch;
    /// - [`Error::InvalidPublicKey`] if the ML-KEM key fails the FIPS 203
    ///   §7.2 "modulus check" (some coefficient is not reduced mod q).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEM_PUBLIC_LEN {
            return Err(Error::Malformed);
        }
        let (k, x) = bytes
            .split_last_chunk::<X25519_PK_LEN>()
            .ok_or(Error::Malformed)?;
        let ek =
            ml_kem::kem::Key::<EncapsulationKey768>::try_from(k).map_err(|_| Error::Malformed)?;
        let mlkem = EncapsulationKey768::new(&ek).map_err(|_| Error::InvalidPublicKey)?;
        // Any 32-byte string is a valid X25519 public key (RFC 7748 §5);
        // small-order points are caught by the contributory check instead.
        Ok(Self {
            x25519: X25519Public::from(*x),
            mlkem,
        })
    }

    /// Canonical encoding.
    pub fn to_bytes(&self) -> [u8; KEM_PUBLIC_LEN] {
        let mut out = [0u8; KEM_PUBLIC_LEN];
        let (k, x) = out.split_at_mut(MLKEM768_EK_LEN);
        x.copy_from_slice(self.x25519.as_bytes());
        k.copy_from_slice(self.mlkem.to_bytes().as_slice());
        out
    }

    /// Responder side: encapsulate a fresh hybrid secret to this share.
    ///
    /// Randomness order (for KATs): 32 bytes X25519 scalar, then the 32-byte
    /// ML-KEM message `m`.
    ///
    /// # Errors
    /// [`Error::NonContributory`] if the initiator's X25519 share is a
    /// small-order point.
    pub fn encapsulate<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<(KemCiphertext, HybridSharedSecret)> {
        let eph = EphemeralSecret::random_from_rng(rng);
        let eph_pub = X25519Public::from(&eph);
        let ss_x = eph.diffie_hellman(&self.x25519);
        if !ss_x.was_contributory() {
            return Err(Error::NonContributory);
        }
        let (ct, mut ss_k) = self.mlkem.encapsulate_with_rng(rng);
        let ss = HybridSharedSecret::from_parts(ss_k.as_slice(), ss_x.as_bytes());
        ss_k.as_mut_slice().zeroize();
        Ok((
            KemCiphertext {
                x25519: eph_pub,
                mlkem: ct,
            },
            ss?,
        ))
    }
}

impl fmt::Debug for KemPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KemPublic")
            .field("x25519", &HexPrefix(self.x25519.as_bytes()))
            .finish_non_exhaustive()
    }
}

/// The responder's reply: `mlkem_ct ‖ x25519_pk`.
#[derive(Clone, PartialEq, Eq)]
pub struct KemCiphertext {
    x25519: X25519Public,
    mlkem: ml_kem::ml_kem_768::Ciphertext,
}

impl KemCiphertext {
    /// Parse an encoded ciphertext. Only the length is checked: every
    /// 1088-byte string is a syntactically valid ML-KEM-768 ciphertext.
    ///
    /// # Errors
    /// [`Error::Malformed`] on a length mismatch.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEM_CIPHERTEXT_LEN {
            return Err(Error::Malformed);
        }
        let (c, x) = bytes
            .split_last_chunk::<X25519_PK_LEN>()
            .ok_or(Error::Malformed)?;
        let mlkem = ml_kem::ml_kem_768::Ciphertext::try_from(c).map_err(|_| Error::Malformed)?;
        Ok(Self {
            x25519: X25519Public::from(*x),
            mlkem,
        })
    }

    /// Canonical encoding.
    pub fn to_bytes(&self) -> [u8; KEM_CIPHERTEXT_LEN] {
        let mut out = [0u8; KEM_CIPHERTEXT_LEN];
        let (c, x) = out.split_at_mut(MLKEM768_CT_LEN);
        x.copy_from_slice(self.x25519.as_bytes());
        c.copy_from_slice(self.mlkem.as_slice());
        out
    }
}

impl fmt::Debug for KemCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KemCiphertext")
            .field("x25519", &HexPrefix(self.x25519.as_bytes()))
            .finish_non_exhaustive()
    }
}

/// `ss_mlkem ‖ ss_x25519`, the input keying material of the key schedule.
///
/// ML-KEM first, as in `X25519MLKEM768` and X-Wing (see the module docs).
/// Both halves are 32 bytes, so the concatenation is unambiguous.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridSharedSecret([u8; HYBRID_SS_LEN]);

impl HybridSharedSecret {
    fn from_parts(mlkem: &[u8], x25519: &[u8]) -> Result<Self> {
        if x25519.len() != COMPONENT_SS_LEN || mlkem.len() != COMPONENT_SS_LEN {
            return Err(Error::Internal);
        }
        let mut out = Self([0u8; HYBRID_SS_LEN]);
        let (a, b) = out.0.split_at_mut(COMPONENT_SS_LEN);
        a.copy_from_slice(mlkem);
        b.copy_from_slice(x25519);
        Ok(out)
    }

    /// Raw bytes, for the key schedule only.
    pub(crate) fn as_bytes(&self) -> &[u8; HYBRID_SS_LEN] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn mlkem_part(&self) -> &[u8] {
        self.0.split_at(COMPONENT_SS_LEN).0
    }

    #[cfg(test)]
    pub(crate) fn x25519_part(&self) -> &[u8] {
        self.0.split_at(COMPONENT_SS_LEN).1
    }
}

impl ConstantTimeEq for HybridSharedSecret {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl fmt::Debug for HybridSharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HybridSharedSecret(<redacted>)")
    }
}

/// Debug helper printing the first bytes of a public value.
pub(crate) struct HexPrefix<'a>(pub(crate) &'a [u8]);

impl fmt::Debug for HexPrefix<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0.iter().take(8) {
            write!(f, "{b:02x}")?;
        }
        if self.0.len() > 8 {
            f.write_str("…")?;
        }
        Ok(())
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

    #[test]
    fn roundtrip() {
        let mut rng = os_rng();
        let init = KemInitiator::generate(&mut rng);
        let pk = KemPublic::from_bytes(&init.public().to_bytes()).unwrap();
        let (ct, ss_r) = pk.encapsulate(&mut rng).unwrap();
        let ct = KemCiphertext::from_bytes(&ct.to_bytes()).unwrap();
        let ss_i = init.decapsulate(&ct).unwrap();
        assert!(bool::from(ss_i.ct_eq(&ss_r)));
    }

    #[test]
    fn tampered_mlkem_ciphertext_changes_secret() {
        let mut rng = os_rng();
        let init = KemInitiator::generate(&mut rng);
        let (ct, ss_r) = init.public().encapsulate(&mut rng).unwrap();
        let mut bytes = ct.to_bytes();
        bytes[10] ^= 1;
        let ss_i = init
            .decapsulate(&KemCiphertext::from_bytes(&bytes).unwrap())
            .unwrap();
        // Implicit rejection: no error, but a different (pseudo-random) key.
        assert!(!bool::from(ss_i.ct_eq(&ss_r)));
        assert_eq!(ss_i.x25519_part(), ss_r.x25519_part());
    }

    #[test]
    fn rejects_small_order_x25519() {
        let mut rng = os_rng();
        let init = KemInitiator::generate(&mut rng);
        let (ct, _) = init.public().encapsulate(&mut rng).unwrap();
        let mut bytes = ct.to_bytes();
        bytes[MLKEM768_CT_LEN..].fill(0); // the identity point
        let ct = KemCiphertext::from_bytes(&bytes).unwrap();
        assert_eq!(init.decapsulate(&ct).unwrap_err(), Error::NonContributory);

        let mut pk = KemInitiator::generate(&mut rng).public().to_bytes();
        pk[MLKEM768_EK_LEN..].fill(0);
        let pk = KemPublic::from_bytes(&pk).unwrap();
        assert_eq!(
            pk.encapsulate(&mut rng).unwrap_err(),
            Error::NonContributory
        );
    }

    #[test]
    fn rejects_bad_lengths() {
        assert_eq!(KemPublic::from_bytes(&[]).unwrap_err(), Error::Malformed);
        assert_eq!(
            KemPublic::from_bytes(&[0u8; KEM_PUBLIC_LEN + 1]).unwrap_err(),
            Error::Malformed
        );
        assert_eq!(
            KemCiphertext::from_bytes(&[0u8; KEM_CIPHERTEXT_LEN - 1]).unwrap_err(),
            Error::Malformed
        );
    }
}
