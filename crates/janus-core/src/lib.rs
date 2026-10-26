#![forbid(unsafe_code)]
//! Sans-IO core of the Janus hybrid post-quantum handshake.
//!
//! - [`kem`]: hybrid X25519 + ML-KEM-768 key encapsulation;
//! - [`sig`]: hybrid Ed25519 + ML-DSA-65 identities and signatures.
//!
//! **Not production-ready**: see the repository README and `docs/DESIGN.md`.

pub mod error;
pub mod kem;
pub mod sig;

pub use error::{Error, Result};

#[cfg(test)]
mod kat_tests;
#[cfg(test)]
mod test_util;
