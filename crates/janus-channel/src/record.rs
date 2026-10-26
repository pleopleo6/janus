//! Encrypted records: ChaCha20-Poly1305 with counter nonces.
//!
//! ```text
//! record frame = type:u8 ‖ len:u16be ‖ seq:u64be ‖ AEAD(key_e, nonce, pt, aad)
//! nonce        = iv_e ⊕ (0^32 ‖ seq:u64be)                       (TLS 1.3, RFC 8446 §5.3)
//! aad          = "janus/v1 record" ‖ type ‖ len ‖ seq
//! epoch e      = seq / rekey_interval
//! ```
//!
//! # Design decisions
//!
//! - **Distinct keys per direction** (from the handshake): a record can never
//!   be reflected back to its sender, and the two sides never share a
//!   (key, nonce) pair even though both start at `seq = 0`.
//! - **Nonce = IV ⊕ seq**: unique per key as long as `seq` never repeats,
//!   which the sender enforces (it never reuses or wraps the counter). The
//!   derived IV makes nonces unpredictable to outsiders.
//! - **Explicit sequence number**: TLS 1.3 keeps it implicit. Sending it costs
//!   8 bytes but lets the receiver tell replays from reorderings, and would
//!   allow an unreliable transport later. It is authenticated through the AAD
//!   *and* through the nonce.
//! - **Strict ordering**: over TCP, records must arrive exactly in order:
//!   `seq < expected` is a replay, `seq > expected` a drop/reorder. Both are
//!   rejected *before* decryption.
//! - **Fail closed**: any error permanently fails the receiving direction, so
//!   an attacker gets at most one decryption attempt per connection (no
//!   repeated-forgery oracle).
//! - **Header in the AAD**: the frame type and length are authenticated, so
//!   a `Data` record cannot be turned into a `Close` (or vice versa), and a
//!   truncated body fails authentication.
//! - **Deterministic rekey**: both sides ratchet the traffic secret every
//!   `rekey_interval` records (one-way HKDF step, old key zeroized). No
//!   message is needed, but both peers must use the same interval.
//! - **Authenticated close**: a `Close` record ("close_notify") marks the end
//!   of the stream; EOF without it is reported as [`Error::Truncated`].

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use janus_core::handshake::Session;
use janus_core::schedule::{AEAD_IV_LEN, TrafficSecret};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::framing::{FRAME_HEADER_LEN, Frame, FrameType};

/// Largest plaintext per record (as in TLS).
pub const MAX_PLAINTEXT_LEN: usize = 16 * 1024;
/// Sequence number length.
pub const SEQ_LEN: usize = 8;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Bytes added by encryption to a plaintext (excluding the frame header).
pub const RECORD_OVERHEAD: usize = SEQ_LEN + TAG_LEN;
/// Largest record body.
pub const MAX_RECORD_BODY_LEN: usize = RECORD_OVERHEAD + MAX_PLAINTEXT_LEN;
/// Default number of records between two rekeys.
pub const DEFAULT_REKEY_INTERVAL: u64 = 1 << 16;

/// Domain-separation prefix of the record AAD.
const AAD_PREFIX: &[u8] = b"janus/v1 record";

/// Record-layer parameters. Must be identical on both sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelConfig {
    /// Ratchet the traffic secret every this many records (per direction).
    pub rekey_interval: u64,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            rekey_interval: DEFAULT_REKEY_INTERVAL,
        }
    }
}

/// Turn an established session into the two halves of a channel.
///
/// # Errors
/// [`Error::Internal`] if `rekey_interval` is zero or key derivation fails.
pub fn channel(session: Session, config: ChannelConfig) -> Result<(Sender, Receiver)> {
    if config.rekey_interval == 0 {
        return Err(Error::Internal);
    }
    let (send, recv) = session.into_traffic_secrets();
    Ok((
        Sender {
            keys: Ratchet::new(send, config.rekey_interval)?,
            next_seq: 0,
            closed: false,
        },
        Receiver {
            keys: Ratchet::new(recv, config.rekey_interval)?,
            expected_seq: 0,
            state: RecvState::Open,
        },
    ))
}

/// Keys of one epoch of one direction.
struct EpochKeys {
    secret: TrafficSecret,
    cipher: ChaCha20Poly1305,
    iv: Zeroizing<[u8; AEAD_IV_LEN]>,
}

impl EpochKeys {
    fn new(secret: TrafficSecret) -> Result<Self> {
        let m = secret.aead_key_iv().map_err(|_| Error::Internal)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(m.key.as_slice()).map_err(|_| Error::Internal)?;
        Ok(Self {
            secret,
            cipher,
            iv: m.iv,
        })
    }

    fn nonce(&self, seq: u64) -> Nonce {
        let mut n = Nonce::default();
        n.copy_from_slice(self.iv.as_slice());
        // The last 8 bytes of the 12-byte nonce are XORed with the counter.
        for (b, s) in n
            .iter_mut()
            .skip(AEAD_IV_LEN - SEQ_LEN)
            .zip(seq.to_be_bytes())
        {
            *b ^= s;
        }
        n
    }
}

/// The current epoch's keys plus the logic to move to the next epoch.
struct Ratchet {
    current: Option<EpochKeys>,
    interval: u64,
}

impl Ratchet {
    fn new(secret: TrafficSecret, interval: u64) -> Result<Self> {
        Ok(Self {
            current: Some(EpochKeys::new(secret)?),
            interval,
        })
    }

    /// Keys for record `seq`, ratcheting forward if `seq` starts a new epoch.
    /// Epochs only move forward; the old keys are dropped (and zeroized).
    fn keys_for(&mut self, seq: u64) -> Result<&EpochKeys> {
        let target = seq.checked_div(self.interval).ok_or(Error::Internal)?;
        loop {
            let cur = self.current.take().ok_or(Error::Internal)?;
            if cur.secret.epoch() >= target {
                return Ok(self.current.insert(cur));
            }
            let next = cur.secret.next().map_err(|_| Error::Internal)?;
            self.current = Some(EpochKeys::new(next)?);
        }
    }

    fn epoch(&self) -> u64 {
        self.current.as_ref().map_or(0, |k| k.secret.epoch())
    }
}

fn aad(header: &[u8; FRAME_HEADER_LEN], seq: &[u8; SEQ_LEN]) -> Vec<u8> {
    [AAD_PREFIX, header, seq].concat()
}

/// Sending half of a channel.
pub struct Sender {
    keys: Ratchet,
    next_seq: u64,
    closed: bool,
}

impl Sender {
    /// Encrypt one application message into a frame ready to be written.
    ///
    /// # Errors
    /// [`Error::TooLarge`], [`Error::Closed`] after [`Sender::close`], or
    /// [`Error::SequenceExhausted`].
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.seal_frame(FrameType::Data, plaintext)
    }

    /// Produce the authenticated `Close` record. No more data can be sent.
    ///
    /// # Errors
    /// [`Error::Closed`] if already closed, [`Error::SequenceExhausted`].
    pub fn close(&mut self) -> Result<Vec<u8>> {
        let frame = self.seal_frame(FrameType::Close, &[])?;
        self.closed = true;
        Ok(frame)
    }

    /// Number of records sent so far.
    pub fn records_sent(&self) -> u64 {
        self.next_seq
    }

    /// Current key epoch.
    pub fn epoch(&self) -> u64 {
        self.keys.epoch()
    }

    fn seal_frame(&mut self, ty: FrameType, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.closed {
            return Err(Error::Closed);
        }
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(Error::TooLarge);
        }
        let seq = self.next_seq;
        // Refuse the last value rather than ever wrapping around.
        let next = seq.checked_add(1).ok_or(Error::SequenceExhausted)?;
        let body_len = RECORD_OVERHEAD
            .checked_add(plaintext.len())
            .ok_or(Error::TooLarge)?;
        let header = Frame::header(ty, body_len)?;
        let seq_bytes = seq.to_be_bytes();

        let keys = self.keys.keys_for(seq)?;
        let ct = keys
            .cipher
            .encrypt(
                &keys.nonce(seq),
                Payload {
                    msg: plaintext,
                    aad: &aad(&header, &seq_bytes),
                },
            )
            .map_err(|_| Error::Internal)?;

        let mut out = Vec::with_capacity(FRAME_HEADER_LEN.saturating_add(body_len));
        out.extend_from_slice(&header);
        out.extend_from_slice(&seq_bytes);
        out.extend_from_slice(&ct);
        self.next_seq = next;
        Ok(out)
    }
}

impl core::fmt::Debug for Sender {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sender")
            .field("next_seq", &self.next_seq)
            .field("epoch", &self.keys.epoch())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

/// What a valid record contained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// Application data.
    Data(Vec<u8>),
    /// The peer cleanly closed its sending direction.
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecvState {
    Open,
    Closed,
    Failed,
}

/// Receiving half of a channel.
pub struct Receiver {
    keys: Ratchet,
    expected_seq: u64,
    state: RecvState,
}

impl Receiver {
    /// Authenticate and decrypt one frame.
    ///
    /// # Errors
    /// See [`Error`]. Any error other than [`Error::Closed`] permanently
    /// fails this receiver.
    pub fn open(&mut self, frame: &Frame) -> Result<Received> {
        match self.state {
            RecvState::Failed => return Err(Error::Failed),
            RecvState::Closed => return Err(Error::Closed),
            RecvState::Open => {}
        }
        let res = self.open_inner(frame);
        match &res {
            Ok(Received::Close) => self.state = RecvState::Closed,
            Ok(Received::Data(_)) => {}
            Err(_) => self.state = RecvState::Failed,
        }
        res
    }

    /// Call when the transport reports end of stream.
    ///
    /// # Errors
    /// [`Error::Truncated`] unless a valid `Close` record was received.
    pub fn finish(&self) -> Result<()> {
        if self.state == RecvState::Closed {
            Ok(())
        } else {
            Err(Error::Truncated)
        }
    }

    /// Number of records accepted so far.
    pub fn records_received(&self) -> u64 {
        self.expected_seq
    }

    /// Current key epoch.
    pub fn epoch(&self) -> u64 {
        self.keys.epoch()
    }

    fn open_inner(&mut self, frame: &Frame) -> Result<Received> {
        if !matches!(frame.ty, FrameType::Data | FrameType::Close) {
            return Err(Error::Malformed);
        }
        let header = Frame::header(frame.ty, frame.body.len())?;
        let (seq_bytes, ct) = frame
            .body
            .split_first_chunk::<SEQ_LEN>()
            .ok_or(Error::Malformed)?;
        let seq = u64::from_be_bytes(*seq_bytes);
        if seq < self.expected_seq {
            return Err(Error::Replay);
        }
        if seq > self.expected_seq {
            return Err(Error::OutOfOrder);
        }
        let next = seq.checked_add(1).ok_or(Error::SequenceExhausted)?;

        let keys = self.keys.keys_for(seq)?;
        let pt = keys
            .cipher
            .decrypt(
                &keys.nonce(seq),
                Payload {
                    msg: ct,
                    aad: &aad(&header, seq_bytes),
                },
            )
            .map_err(|_| Error::BadRecord)?;
        self.expected_seq = next;
        match frame.ty {
            FrameType::Close => Ok(Received::Close),
            _ => Ok(Received::Data(pt)),
        }
    }
}

impl core::fmt::Debug for Receiver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Receiver")
            .field("expected_seq", &self.expected_seq)
            .field("epoch", &self.keys.epoch())
            .field("state", &self.state)
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
    use crate::test_support::session_pair;

    #[test]
    fn sequence_numbers_never_wrap() {
        let (c, s) = session_pair();
        let (mut tx, _) = channel(c, ChannelConfig::default()).unwrap();
        let (_, mut rx) = channel(s, ChannelConfig::default()).unwrap();
        tx.next_seq = u64::MAX;
        assert_eq!(tx.seal(b"x").unwrap_err(), Error::SequenceExhausted);
        // Receiver side: the last sequence number is refused too.
        rx.expected_seq = u64::MAX;
        let frame = Frame {
            ty: FrameType::Data,
            body: [&u64::MAX.to_be_bytes()[..], &[0u8; TAG_LEN]].concat(),
        };
        assert_eq!(rx.open(&frame).unwrap_err(), Error::SequenceExhausted);
    }

    #[test]
    fn nonce_is_iv_xor_seq() {
        let (c, _) = session_pair();
        let (send, _) = c.into_traffic_secrets();
        let k = EpochKeys::new(send).unwrap();
        assert_eq!(k.nonce(0).as_slice(), k.iv.as_slice());
        let n = k.nonce(0x0102);
        assert_eq!(n[..10], k.iv[..10]);
        assert_eq!(n[10], k.iv[10] ^ 0x01);
        assert_eq!(n[11], k.iv[11] ^ 0x02);
    }

    #[test]
    fn zero_rekey_interval_is_rejected() {
        let (c, _) = session_pair();
        assert!(channel(c, ChannelConfig { rekey_interval: 0 }).is_err());
    }
}
