#![forbid(unsafe_code)]
//! Sans-IO core of the Janus hybrid post-quantum handshake.
//!
//! - [`kem`]: hybrid X25519 + ML-KEM-768 key encapsulation;
//! - [`sig`]: hybrid Ed25519 + ML-DSA-65 identities and signatures;
//! - [`messages`]: strict, fixed-length wire format;
//! - [`schedule`]: transcript hash and HKDF-SHA-384 key schedule;
//! - [`handshake`]: typestate client / server state machines.
//!
//! "Sans-IO" means this crate never touches a socket: callers feed it the
//! bytes they received and send the bytes it returns. That keeps the
//! protocol logic deterministic and testable without a network.
//!
//! ```
//! # use janus_core::{handshake::{self, Config, TrustStore}, sig::IdentityKeypair};
//! # let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
//! let alice = IdentityKeypair::generate(&mut rng);
//! let bob = IdentityKeypair::generate(&mut rng);
//! let client = Config { trust: [bob.public().fingerprint()].into_iter().collect(), identity: alice };
//! let server = Config { trust: [client.identity.public().fingerprint()].into_iter().collect(), identity: bob };
//!
//! let (c, hello) = handshake::client_start(&client, &mut rng);
//! let (s, reply) = handshake::server_accept(&server, &hello, &mut rng)?;
//! let (finish, client_session) = c.read_server_hello(&reply, &mut rng)?;
//! let server_session = s.read_client_finish(&finish)?;
//! assert_eq!(client_session.session_id(), server_session.session_id());
//! # Ok::<(), janus_core::Error>(())
//! ```
//!
//! **Not production-ready**: see the repository README and `docs/DESIGN.md`.

pub mod error;
pub mod handshake;
pub mod kem;
pub mod messages;
pub mod schedule;
pub mod sig;

pub use error::{Error, Result};

#[cfg(test)]
mod kat_tests;
#[cfg(test)]
mod test_util;
