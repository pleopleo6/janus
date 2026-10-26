//! Stream framing, sans-IO.
//!
//! Everything Janus sends over a byte stream is a frame:
//!
//! ```text
//! frame = type:u8 ‖ len:u16be ‖ body[len]
//! ```
//!
//! - `Handshake` frames carry one `janus-core` handshake message, in clear.
//! - `Data` / `Close` frames carry an encrypted record (see [`crate::record`]).
//!
//! The [`Deframer`] accumulates bytes read from the transport and yields
//! complete frames. It validates the header *before* buffering the body, so a
//! peer cannot make it allocate more than one maximal frame.

use crate::error::{Error, Result};
use crate::{MAX_RECORD_BODY_LEN, RECORD_OVERHEAD};

/// Frame header length.
pub const FRAME_HEADER_LEN: usize = 3;
/// Largest handshake message (`ServerHello`).
pub const MAX_HANDSHAKE_BODY_LEN: usize = janus_core::messages::SERVER_HELLO_LEN;

/// Frame types. The values are arbitrary but distinct from the handshake
/// message types, so the two layers cannot be confused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Plaintext handshake message.
    Handshake = 0x16,
    /// Encrypted application data.
    Data = 0x17,
    /// Encrypted, authenticated end of stream ("close_notify").
    Close = 0x15,
}

impl FrameType {
    fn from_u8(b: u8) -> Result<Self> {
        match b {
            0x16 => Ok(Self::Handshake),
            0x17 => Ok(Self::Data),
            0x15 => Ok(Self::Close),
            _ => Err(Error::Malformed),
        }
    }

    /// Admissible body lengths for this type.
    fn check_len(self, len: usize) -> Result<()> {
        let ok = match self {
            Self::Handshake => (1..=MAX_HANDSHAKE_BODY_LEN).contains(&len),
            Self::Data => (RECORD_OVERHEAD..=MAX_RECORD_BODY_LEN).contains(&len),
            // A close record has an empty plaintext.
            Self::Close => len == RECORD_OVERHEAD,
        };
        if ok { Ok(()) } else { Err(Error::Malformed) }
    }
}

/// A complete frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Frame type.
    pub ty: FrameType,
    /// Frame body.
    pub body: Vec<u8>,
}

impl Frame {
    /// Header bytes of a frame of this type and body length.
    ///
    /// # Errors
    /// [`Error::Malformed`] if `len` is not admissible for `ty`.
    pub fn header(ty: FrameType, len: usize) -> Result<[u8; FRAME_HEADER_LEN]> {
        ty.check_len(len)?;
        let len = u16::try_from(len).map_err(|_| Error::Malformed)?;
        let [hi, lo] = len.to_be_bytes();
        Ok([ty as u8, hi, lo])
    }

    /// Serialize the frame.
    ///
    /// # Errors
    /// [`Error::Malformed`] if the body length is not admissible.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN.saturating_add(self.body.len()));
        out.extend_from_slice(&Self::header(self.ty, self.body.len())?);
        out.extend_from_slice(&self.body);
        Ok(out)
    }

    /// Wrap a handshake message.
    ///
    /// # Errors
    /// [`Error::Malformed`] if the message is empty or too long.
    pub fn handshake(msg: &[u8]) -> Result<Vec<u8>> {
        Self {
            ty: FrameType::Handshake,
            body: msg.to_vec(),
        }
        .encode()
    }
}

/// Incremental frame parser.
#[derive(Debug, Default)]
pub struct Deframer {
    buf: Vec<u8>,
    failed: bool,
}

impl Deframer {
    /// New, empty deframer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append bytes read from the transport.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Extract the next complete frame, if any.
    ///
    /// # Errors
    /// [`Error::Malformed`] on an invalid header; the deframer is then
    /// permanently failed (a stream cannot be resynchronised).
    pub fn next_frame(&mut self) -> Result<Option<Frame>> {
        if self.failed {
            return Err(Error::Failed);
        }
        let Some((&[ty, hi, lo], rest)) = self.buf.split_first_chunk::<FRAME_HEADER_LEN>() else {
            return Ok(None);
        };
        let len = usize::from(u16::from_be_bytes([hi, lo]));
        let ty = match FrameType::from_u8(ty).and_then(|t| t.check_len(len).map(|()| t)) {
            Ok(t) => t,
            Err(e) => {
                self.failed = true;
                return Err(e);
            }
        };
        let Some(body) = rest.get(..len) else {
            return Ok(None);
        };
        let frame = Frame {
            ty,
            body: body.to_vec(),
        };
        self.buf.drain(..FRAME_HEADER_LEN.saturating_add(len));
        Ok(Some(frame))
    }

    /// Call at end of stream.
    ///
    /// # Errors
    /// [`Error::Truncated`] if a partial frame is still buffered.
    pub fn finish(&self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Error::Truncated)
        }
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
    fn byte_by_byte_delivery() {
        let f1 = Frame::handshake(b"hello").unwrap();
        let f2 = Frame::handshake(b"world!").unwrap();
        let stream = [f1, f2].concat();
        let mut d = Deframer::new();
        let mut got = Vec::new();
        for b in stream {
            d.push(&[b]);
            while let Some(f) = d.next_frame().unwrap() {
                got.push(f.body);
            }
        }
        assert_eq!(got, vec![b"hello".to_vec(), b"world!".to_vec()]);
        d.finish().unwrap();
    }

    #[test]
    fn rejects_bad_headers_and_stays_failed() {
        let mut d = Deframer::new();
        d.push(&[0x99, 0, 1, 0]);
        assert_eq!(d.next_frame().unwrap_err(), Error::Malformed);
        assert_eq!(d.next_frame().unwrap_err(), Error::Failed);

        let mut d = Deframer::new();
        d.push(&[0x16, 0xff, 0xff]); // handshake frame larger than any message
        assert_eq!(d.next_frame().unwrap_err(), Error::Malformed);

        let mut d = Deframer::new();
        d.push(&[0x15, 0, 1, 0]); // close record of the wrong size
        assert_eq!(d.next_frame().unwrap_err(), Error::Malformed);
    }

    #[test]
    fn partial_frame_at_eof_is_truncation() {
        let f = Frame::handshake(b"hello").unwrap();
        let mut d = Deframer::new();
        d.push(&f[..f.len() - 1]);
        assert!(d.next_frame().unwrap().is_none());
        assert_eq!(d.finish().unwrap_err(), Error::Truncated);
    }
}
