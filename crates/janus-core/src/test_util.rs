//! Test-only helpers.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use core::convert::Infallible;
use rand_core::{TryCryptoRng, TryRng};

/// The OS RNG, made infallible (tests may panic).
pub(crate) fn os_rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
    rand_core::UnwrapErr(getrandom::SysRng)
}

/// A "random" source that replays fixed bytes, so that known-answer tests
/// can drive the *production* code paths (which take an RNG) with the
/// randomness prescribed by a test vector. Panics when exhausted, so a test
/// also checks that exactly the expected amount of randomness is consumed.
pub(crate) struct ReplayRng {
    bytes: Vec<u8>,
    pos: usize,
}

impl ReplayRng {
    pub(crate) fn new(chunks: &[&[u8]]) -> Self {
        Self {
            bytes: chunks.concat(),
            pos: 0,
        }
    }

    pub(crate) fn assert_exhausted(&self) {
        assert_eq!(
            self.pos,
            self.bytes.len(),
            "not all replayed randomness was consumed"
        );
    }
}

impl TryRng for ReplayRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let end = self.pos.checked_add(dst.len()).unwrap();
        assert!(end <= self.bytes.len(), "ReplayRng exhausted");
        dst.copy_from_slice(&self.bytes[self.pos..end]);
        self.pos = end;
        Ok(())
    }
}

// Not actually cryptographically secure: test vectors only.
impl TryCryptoRng for ReplayRng {}

/// Minimal parser for the `key = value` KAT files in `tests/kat/`.
pub(crate) fn parse_kat(text: &str) -> Vec<std::collections::HashMap<String, String>> {
    let mut cases = Vec::new();
    let mut cur = std::collections::HashMap::new();
    for line in text.lines().chain(std::iter::once("")) {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            if !cur.is_empty() {
                cases.push(std::mem::take(&mut cur));
            }
            continue;
        }
        let (k, v) = line
            .split_once(" = ")
            .unwrap_or((line.trim_end_matches(" ="), ""));
        cur.insert(k.trim().to_owned(), v.trim().to_owned());
    }
    cases
}

pub(crate) fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}
