#![forbid(unsafe_code)]
//! Janus record layer: AEAD-protected, counter-nonce, replay-rejecting records.
//!
//! - [`framing`]: `type ‖ len ‖ body` frames and an incremental, sans-IO
//!   [`Deframer`];
//! - [`record`]: ChaCha20-Poly1305 [`Sender`] / [`Receiver`] built from a
//!   completed [`janus_core::handshake::Session`].
//!
//! ```
//! # fn session_pair() -> (janus_core::handshake::Session, janus_core::handshake::Session) {
//! #     use janus_core::{handshake::{self, Config}, sig::IdentityKeypair};
//! #     let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
//! #     let (a, b) = (IdentityKeypair::from_seed(&[1; 64]), IdentityKeypair::from_seed(&[2; 64]));
//! #     let client = Config { trust: [b.public().fingerprint()].into_iter().collect(), identity: a };
//! #     let server = Config { trust: [client.identity.public().fingerprint()].into_iter().collect(), identity: b };
//! #     let (c, m1) = handshake::client_start(&client, &mut rng);
//! #     let (s, m2) = handshake::server_accept(&server, &m1, &mut rng).unwrap();
//! #     let (m3, cs) = c.read_server_hello(&m2, &mut rng).unwrap();
//! #     (cs, s.read_client_finish(&m3).unwrap())
//! # }
//! use janus_channel::{channel, ChannelConfig, Deframer, Received};
//!
//! let (client_session, server_session) = session_pair();
//! let (mut tx, _) = channel(client_session, ChannelConfig::default())?;
//! let (_, mut rx) = channel(server_session, ChannelConfig::default())?;
//!
//! let mut wire = Deframer::new();
//! wire.push(&tx.seal(b"hello")?);
//! wire.push(&tx.close()?);
//! let frame = wire.next_frame()?.expect("complete frame");
//! assert_eq!(rx.open(&frame)?, Received::Data(b"hello".to_vec()));
//! assert_eq!(rx.open(&wire.next_frame()?.expect("close"))?, Received::Close);
//! rx.finish()?; // clean end of stream
//! # Ok::<(), janus_channel::Error>(())
//! ```

pub mod error;
pub mod framing;
pub mod record;

pub use error::{Error, Result};
pub use framing::{Deframer, Frame, FrameType};
pub use record::{
    ChannelConfig, MAX_PLAINTEXT_LEN, MAX_RECORD_BODY_LEN, RECORD_OVERHEAD, Received, Receiver,
    Sender, channel,
};

#[cfg(test)]
mod test_support;
