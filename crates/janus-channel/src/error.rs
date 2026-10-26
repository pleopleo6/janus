//! Record-layer errors. All of them are fatal for the receiving direction.

/// Every way the record layer can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Bad frame header (unknown type, impossible length).
    #[error("malformed frame")]
    Malformed,
    /// Plaintext larger than [`crate::MAX_PLAINTEXT_LEN`].
    #[error("plaintext too large")]
    TooLarge,
    /// A record with an already-seen sequence number (replay).
    #[error("replayed record")]
    Replay,
    /// A record from the future: one or more records were dropped or
    /// reordered. On a reliable transport this means tampering.
    #[error("out-of-order record")]
    OutOfOrder,
    /// AEAD authentication failed (forged, corrupted or misdirected record).
    #[error("record authentication failed")]
    BadRecord,
    /// The peer closed this direction; nothing more may be received.
    #[error("channel closed by peer")]
    Closed,
    /// The stream ended without an authenticated `Close` record: data may have
    /// been cut off by an attacker.
    #[error("truncated stream (no close_notify)")]
    Truncated,
    /// The 64-bit sequence space is exhausted.
    #[error("sequence numbers exhausted")]
    SequenceExhausted,
    /// A previous error already made this direction unusable.
    #[error("channel failed earlier")]
    Failed,
    /// Key schedule error (unreachable in practice).
    #[error("internal error")]
    Internal,
}

/// Convenience alias.
pub type Result<T> = core::result::Result<T, Error>;
