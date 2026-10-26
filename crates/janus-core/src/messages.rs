//! Wire format of the three handshake messages.
//!
//! Every message has a **fixed length** determined by its type, starts with a
//! two-byte header `version ‖ type`, and is a plain concatenation of
//! fixed-size fields. There are no optional fields, no extensions and no
//! variable-length encodings, so the parser has very little attack surface:
//! it checks the header, then the exact length, then validates each field.
//!
//! ```text
//! ClientHello  = 01 01 ‖ client_random[32] ‖ kem_public[1216]                      (1250)
//! ServerHello  = 01 02 ‖ server_random[32] ‖ kem_ciphertext[1120]
//!                      ‖ server_identity[1984] ‖ server_signature[3373]
//!                      ‖ server_finished[48]                                        (6559)
//! ClientFinish = 01 03 ‖ client_identity[1984] ‖ client_signature[3373]
//!                      ‖ client_finished[48]                                        (5407)
//! ```
//!
//! Checks happen in a fixed order (version, type, length, fields) so that
//! errors are deterministic, which keeps fuzzing reproducible.

use crate::error::{Error, Result};
use crate::kem::{KEM_CIPHERTEXT_LEN, KEM_PUBLIC_LEN, KemCiphertext, KemPublic};
use crate::schedule::HASH_LEN;
use crate::sig::{HYBRID_SIG_LEN, HybridSignature, IDENTITY_PUBLIC_LEN, IdentityPublic};

/// The only protocol version this implementation speaks.
pub const VERSION: u8 = 1;
/// Length of the `version ‖ type` header.
pub const HEADER_LEN: usize = 2;
/// Length of the per-side random nonces.
pub const RANDOM_LEN: usize = 32;
/// Length of a `Finished` MAC (HMAC-SHA-384).
pub const FINISHED_LEN: usize = HASH_LEN;

/// Message type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Initiator's first flight.
    ClientHello = 1,
    /// Responder's only flight.
    ServerHello = 2,
    /// Initiator's second flight.
    ClientFinish = 3,
}

/// `ClientHello` total length.
pub const CLIENT_HELLO_LEN: usize = HEADER_LEN + RANDOM_LEN + KEM_PUBLIC_LEN;

/// End offset of the key-exchange part of `ServerHello`.
pub const SERVER_HELLO_KEX_END: usize = HEADER_LEN + RANDOM_LEN + KEM_CIPHERTEXT_LEN;
/// End offset of the identity in `ServerHello`.
pub const SERVER_HELLO_ID_END: usize = SERVER_HELLO_KEX_END + IDENTITY_PUBLIC_LEN;
/// End offset of the signature in `ServerHello`.
pub const SERVER_HELLO_SIG_END: usize = SERVER_HELLO_ID_END + HYBRID_SIG_LEN;
/// `ServerHello` total length.
pub const SERVER_HELLO_LEN: usize = SERVER_HELLO_SIG_END + FINISHED_LEN;

/// End offset of the identity in `ClientFinish`.
pub const CLIENT_FINISH_ID_END: usize = HEADER_LEN + IDENTITY_PUBLIC_LEN;
/// End offset of the signature in `ClientFinish`.
pub const CLIENT_FINISH_SIG_END: usize = CLIENT_FINISH_ID_END + HYBRID_SIG_LEN;
/// `ClientFinish` total length.
pub const CLIENT_FINISH_LEN: usize = CLIENT_FINISH_SIG_END + FINISHED_LEN;

/// Expected total length of a message of the given type.
pub fn expected_len(ty: MessageType) -> usize {
    match ty {
        MessageType::ClientHello => CLIENT_HELLO_LEN,
        MessageType::ServerHello => SERVER_HELLO_LEN,
        MessageType::ClientFinish => CLIENT_FINISH_LEN,
    }
}

/// Initiator → responder, first flight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// Fresh initiator nonce.
    pub random: [u8; RANDOM_LEN],
    /// Ephemeral hybrid KEM public key.
    pub kem_public: KemPublic,
}

/// Responder → initiator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    /// Fresh responder nonce.
    pub random: [u8; RANDOM_LEN],
    /// Hybrid KEM ciphertext.
    pub kem_ciphertext: KemCiphertext,
    /// Responder long-term identity.
    pub identity: IdentityPublic,
    /// Responder signature over `TH(… ‖ identity)`.
    pub signature: HybridSignature,
    /// Responder key confirmation over `TH(… ‖ signature)`.
    pub finished: [u8; FINISHED_LEN],
}

/// Initiator → responder, second flight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientFinish {
    /// Initiator long-term identity.
    pub identity: IdentityPublic,
    /// Initiator signature over `TH(… ‖ identity)`.
    pub signature: HybridSignature,
    /// Initiator key confirmation over `TH(… ‖ signature)`.
    pub finished: [u8; FINISHED_LEN],
}

/// Panic-free cursor over an input buffer.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(n).ok_or(Error::Malformed)?;
        self.0 = tail;
        Ok(head)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let (head, tail) = self.0.split_first_chunk::<N>().ok_or(Error::Malformed)?;
        self.0 = tail;
        Ok(*head)
    }

    fn finish(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }
}

/// Check the header and the exact length, and return a reader positioned
/// after the header.
fn open(bytes: &[u8], ty: MessageType) -> Result<Reader<'_>> {
    let mut r = Reader(bytes);
    let [version, msg_type] = r.take_array::<HEADER_LEN>()?;
    if version != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if msg_type != ty as u8 {
        return Err(Error::UnexpectedMessage);
    }
    if bytes.len() != expected_len(ty) {
        return Err(Error::Malformed);
    }
    Ok(r)
}

fn header(ty: MessageType) -> [u8; HEADER_LEN] {
    [VERSION, ty as u8]
}

impl ClientHello {
    /// Strict parser.
    ///
    /// # Errors
    /// [`Error::UnsupportedVersion`], [`Error::UnexpectedMessage`],
    /// [`Error::Malformed`] or [`Error::InvalidPublicKey`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = open(bytes, MessageType::ClientHello)?;
        let random = r.take_array()?;
        let kem_public = KemPublic::from_bytes(r.take(KEM_PUBLIC_LEN)?)?;
        r.finish()?;
        Ok(Self { random, kem_public })
    }

    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CLIENT_HELLO_LEN);
        out.extend_from_slice(&header(MessageType::ClientHello));
        out.extend_from_slice(&self.random);
        out.extend_from_slice(&self.kem_public.to_bytes());
        out
    }
}

impl ServerHello {
    /// Strict parser.
    ///
    /// # Errors
    /// [`Error::UnsupportedVersion`], [`Error::UnexpectedMessage`],
    /// [`Error::Malformed`] or [`Error::InvalidPublicKey`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = open(bytes, MessageType::ServerHello)?;
        let random = r.take_array()?;
        let kem_ciphertext = KemCiphertext::from_bytes(r.take(KEM_CIPHERTEXT_LEN)?)?;
        let identity = IdentityPublic::from_bytes(r.take(IDENTITY_PUBLIC_LEN)?)?;
        let signature = HybridSignature::from_bytes(r.take(HYBRID_SIG_LEN)?)?;
        let finished = r.take_array()?;
        r.finish()?;
        Ok(Self {
            random,
            kem_ciphertext,
            identity,
            signature,
            finished,
        })
    }

    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SERVER_HELLO_LEN);
        out.extend_from_slice(&header(MessageType::ServerHello));
        out.extend_from_slice(&self.random);
        out.extend_from_slice(&self.kem_ciphertext.to_bytes());
        out.extend_from_slice(self.identity.as_bytes());
        out.extend_from_slice(&self.signature.to_bytes());
        out.extend_from_slice(&self.finished);
        out
    }
}

impl ClientFinish {
    /// Strict parser.
    ///
    /// # Errors
    /// [`Error::UnsupportedVersion`], [`Error::UnexpectedMessage`],
    /// [`Error::Malformed`] or [`Error::InvalidPublicKey`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = open(bytes, MessageType::ClientFinish)?;
        let identity = IdentityPublic::from_bytes(r.take(IDENTITY_PUBLIC_LEN)?)?;
        let signature = HybridSignature::from_bytes(r.take(HYBRID_SIG_LEN)?)?;
        let finished = r.take_array()?;
        r.finish()?;
        Ok(Self {
            identity,
            signature,
            finished,
        })
    }

    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CLIENT_FINISH_LEN);
        out.extend_from_slice(&header(MessageType::ClientFinish));
        out.extend_from_slice(self.identity.as_bytes());
        out.extend_from_slice(&self.signature.to_bytes());
        out.extend_from_slice(&self.finished);
        out
    }
}

/// Split `bytes` at the given increasing offsets (the last must be the
/// length). Used to hash the *received* bytes into the transcript in the same
/// chunks the sender hashed them.
pub(crate) fn segments<const K: usize>(bytes: &[u8], ends: [usize; K]) -> Result<[&[u8]; K]> {
    let mut out: [&[u8]; K] = [&[]; K];
    let mut rest = bytes;
    let mut start = 0usize;
    for (slot, end) in out.iter_mut().zip(ends) {
        let len = end.checked_sub(start).ok_or(Error::Internal)?;
        let (head, tail) = rest.split_at_checked(len).ok_or(Error::Malformed)?;
        *slot = head;
        rest = tail;
        start = end;
    }
    if rest.is_empty() {
        Ok(out)
    } else {
        Err(Error::Malformed)
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

    #[test]
    fn sizes_match_the_documentation() {
        assert_eq!(CLIENT_HELLO_LEN, 1250);
        assert_eq!(SERVER_HELLO_LEN, 6559);
        assert_eq!(CLIENT_FINISH_LEN, 5407);
    }

    #[test]
    fn header_checks_come_first() {
        let mut m = vec![0u8; CLIENT_HELLO_LEN];
        m[0] = 2;
        m[1] = 1;
        assert_eq!(
            ClientHello::decode(&m).unwrap_err(),
            Error::UnsupportedVersion
        );
        m[0] = 1;
        m[1] = 2;
        assert_eq!(
            ClientHello::decode(&m).unwrap_err(),
            Error::UnexpectedMessage
        );
        assert_eq!(ClientHello::decode(&[]).unwrap_err(), Error::Malformed);
        assert_eq!(ClientHello::decode(&[1]).unwrap_err(), Error::Malformed);
        assert_eq!(
            ClientHello::decode(&[1, 1, 0]).unwrap_err(),
            Error::Malformed
        );
    }

    #[test]
    fn segments_split_exactly() {
        let b = [1u8, 2, 3, 4, 5];
        let [a, c, d] = segments(&b, [1, 3, 5]).unwrap();
        assert_eq!((a, c, d), (&b[..1], &b[1..3], &b[3..]));
        assert!(segments(&b, [1, 3, 4]).is_err());
        assert!(segments(&b, [1, 3, 6]).is_err());
        assert!(segments(&b, [3, 1, 5]).is_err());
    }
}
