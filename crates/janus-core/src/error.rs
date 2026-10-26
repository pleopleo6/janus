//! Error type shared by every `janus-core` module.
//!
//! Errors are deliberately coarse: a peer learns nothing from *which* check
//! failed beyond what the protocol already reveals (the connection is
//! aborted). Variants exist for local diagnostics and tests, not for the wire.

/// Every way a Janus operation can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Input has the wrong length or an invalid structure.
    #[error("malformed input")]
    Malformed,
    /// A public key failed validation (wrong encoding, small order, …).
    #[error("invalid public key")]
    InvalidPublicKey,
    /// An X25519 exchange produced the all-zero output (peer sent a
    /// small-order point), so it contributes no secrecy.
    #[error("non-contributory X25519 exchange")]
    NonContributory,
    /// At least one of the two signatures of a hybrid signature is invalid.
    #[error("signature verification failed")]
    BadSignature,
    /// The peer's identity is not in the set of trusted identities.
    #[error("untrusted peer identity")]
    UntrustedPeer,
    /// The peer's key-confirmation MAC does not match.
    #[error("key confirmation failed")]
    BadFinished,
    /// The peer speaks a protocol version we do not support.
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    /// A message arrived that is not valid in the current handshake state.
    #[error("unexpected message")]
    UnexpectedMessage,
    /// Internal invariant violated (should be unreachable).
    #[error("internal error")]
    Internal,
}

/// Convenience alias.
pub type Result<T> = core::result::Result<T, Error>;
