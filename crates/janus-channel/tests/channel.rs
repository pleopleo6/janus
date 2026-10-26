//! Record-layer tests over real handshake sessions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use janus_channel::{
    ChannelConfig, Deframer, Error, Frame, FrameType, MAX_PLAINTEXT_LEN, Received, Receiver,
    Sender, channel,
};
use janus_core::handshake::{self, Config, Session};
use janus_core::sig::IdentityKeypair;
use proptest::prelude::*;

fn session_pair() -> (Session, Session) {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let c = IdentityKeypair::from_seed(&[1; 64]);
    let s = IdentityKeypair::from_seed(&[2; 64]);
    let client = Config {
        trust: [s.public().fingerprint()].into_iter().collect(),
        identity: c,
    };
    let server = Config {
        trust: [client.identity.public().fingerprint()]
            .into_iter()
            .collect(),
        identity: s,
    };
    let (c, m1) = handshake::client_start(&client, &mut rng);
    let (s, m2) = handshake::server_accept(&server, &m1, &mut rng).unwrap();
    let (m3, cs) = c.read_server_hello(&m2, &mut rng).unwrap();
    (cs, s.read_client_finish(&m3).unwrap())
}

/// Client sender + server receiver, and the reverse direction.
struct Pair {
    c_tx: Sender,
    c_rx: Receiver,
    s_tx: Sender,
    s_rx: Receiver,
}

fn pair_with(c_cfg: ChannelConfig, s_cfg: ChannelConfig) -> Pair {
    let (cs, ss) = session_pair();
    let (c_tx, c_rx) = channel(cs, c_cfg).unwrap();
    let (s_tx, s_rx) = channel(ss, s_cfg).unwrap();
    Pair {
        c_tx,
        c_rx,
        s_tx,
        s_rx,
    }
}

fn pair(interval: u64) -> Pair {
    let cfg = ChannelConfig {
        rekey_interval: interval,
    };
    pair_with(cfg, cfg)
}

/// Parse one complete frame from wire bytes.
fn frame(bytes: &[u8]) -> Frame {
    let mut d = Deframer::new();
    d.push(bytes);
    let f = d.next_frame().unwrap().unwrap();
    d.finish().unwrap();
    f
}

fn data(r: Received) -> Vec<u8> {
    match r {
        Received::Data(d) => d,
        Received::Close => panic!("unexpected close"),
    }
}

#[test]
fn bidirectional_roundtrip() {
    let mut p = pair(1000);
    for i in 0..20u8 {
        let msg = vec![i; usize::from(i) * 50];
        assert_eq!(
            data(p.s_rx.open(&frame(&p.c_tx.seal(&msg).unwrap())).unwrap()),
            msg
        );
        assert_eq!(
            data(p.c_rx.open(&frame(&p.s_tx.seal(&msg).unwrap())).unwrap()),
            msg
        );
    }
}

#[test]
fn max_size_and_empty_records() {
    let mut p = pair(1000);
    let big = vec![0xab; MAX_PLAINTEXT_LEN];
    assert_eq!(
        data(p.s_rx.open(&frame(&p.c_tx.seal(&big).unwrap())).unwrap()),
        big
    );
    assert_eq!(
        data(p.s_rx.open(&frame(&p.c_tx.seal(&[]).unwrap())).unwrap()),
        b""
    );
    assert_eq!(
        p.c_tx.seal(&vec![0; MAX_PLAINTEXT_LEN + 1]).unwrap_err(),
        Error::TooLarge
    );
}

#[test]
fn replay_is_rejected_and_fails_the_channel() {
    let mut p = pair(1000);
    let r0 = p.c_tx.seal(b"pay alice 10").unwrap();
    p.s_rx.open(&frame(&r0)).unwrap();
    assert_eq!(p.s_rx.open(&frame(&r0)).unwrap_err(), Error::Replay);
    // Even a perfectly valid next record is now refused.
    let r1 = p.c_tx.seal(b"next").unwrap();
    assert_eq!(p.s_rx.open(&frame(&r1)).unwrap_err(), Error::Failed);
}

#[test]
fn reordering_is_rejected() {
    let mut p = pair(1000);
    let r0 = p.c_tx.seal(b"first").unwrap();
    let r1 = p.c_tx.seal(b"second").unwrap();
    assert_eq!(p.s_rx.open(&frame(&r1)).unwrap_err(), Error::OutOfOrder);
    assert_eq!(p.s_rx.open(&frame(&r0)).unwrap_err(), Error::Failed);
}

#[test]
fn dropped_record_is_detected() {
    let mut p = pair(1000);
    let _lost = p.c_tx.seal(b"lost").unwrap();
    let r1 = p.c_tx.seal(b"after").unwrap();
    assert_eq!(p.s_rx.open(&frame(&r1)).unwrap_err(), Error::OutOfOrder);
}

/// Rewriting the explicit sequence number to the expected value does not
/// help: the nonce and AAD both depend on it.
#[test]
fn forged_sequence_number_fails_authentication() {
    let mut p = pair(1000);
    let _r0 = p.c_tx.seal(b"zero").unwrap();
    let mut r1 = p.c_tx.seal(b"one").unwrap();
    r1[3..11].copy_from_slice(&0u64.to_be_bytes());
    assert_eq!(p.s_rx.open(&frame(&r1)).unwrap_err(), Error::BadRecord);
}

#[test]
fn reflection_is_rejected() {
    // The client's own record fed back to the client: different direction key.
    let mut p = pair(1000);
    let r0 = p.c_tx.seal(b"echo?").unwrap();
    assert_eq!(p.c_rx.open(&frame(&r0)).unwrap_err(), Error::BadRecord);
}

#[test]
fn stream_cut_without_close_is_truncation() {
    let mut p = pair(1000);
    p.s_rx
        .open(&frame(&p.c_tx.seal(b"part 1").unwrap()))
        .unwrap();
    // The attacker drops everything after this point and closes TCP.
    assert_eq!(p.s_rx.finish().unwrap_err(), Error::Truncated);
}

#[test]
fn truncated_record_body_is_rejected() {
    let mut p = pair(1000);
    let r = p.c_tx.seal(b"some data that will be cut").unwrap();
    // Cut the body and fix the header length so framing still parses.
    let mut cut = r[..r.len() - 5].to_vec();
    let len = u16::try_from(cut.len() - 3).unwrap().to_be_bytes();
    cut[1..3].copy_from_slice(&len);
    assert_eq!(p.s_rx.open(&frame(&cut)).unwrap_err(), Error::BadRecord);

    // Partial frame at EOF.
    let mut d = Deframer::new();
    d.push(&r[..r.len() - 1]);
    assert!(d.next_frame().unwrap().is_none());
    assert_eq!(d.finish().unwrap_err(), Error::Truncated);
}

#[test]
fn clean_close() {
    let mut p = pair(1000);
    p.s_rx.open(&frame(&p.c_tx.seal(b"bye").unwrap())).unwrap();
    let close = p.c_tx.close().unwrap();
    assert_eq!(p.c_tx.seal(b"more").unwrap_err(), Error::Closed);
    assert_eq!(p.s_rx.open(&frame(&close)).unwrap(), Received::Close);
    p.s_rx.finish().unwrap();
    assert_eq!(p.s_rx.open(&frame(&close)).unwrap_err(), Error::Closed);
}

/// An empty `Data` record has exactly the size of a `Close` record; flipping
/// the type byte must not turn it into a valid close (type is in the AAD).
#[test]
fn data_cannot_be_turned_into_close() {
    let mut p = pair(1000);
    let mut r = p.c_tx.seal(&[]).unwrap();
    assert_eq!(r[0], FrameType::Data as u8);
    r[0] = FrameType::Close as u8;
    assert_eq!(p.s_rx.open(&frame(&r)).unwrap_err(), Error::BadRecord);
}

#[test]
fn rekey_happens_on_schedule_on_both_sides() {
    let mut p = pair(3);
    for i in 0..10u64 {
        assert_eq!(p.c_tx.records_sent(), i);
        let msg = i.to_be_bytes();
        let got = data(p.s_rx.open(&frame(&p.c_tx.seal(&msg).unwrap())).unwrap());
        assert_eq!(got, msg);
        assert_eq!(p.c_tx.epoch(), i / 3);
        assert_eq!(p.s_rx.epoch(), i / 3);
    }
}

/// After a rekey the old epoch's key no longer decrypts: two senders that
/// disagree on the interval diverge exactly at the first boundary.
#[test]
fn mismatched_rekey_interval_fails_at_first_boundary() {
    let mut p = pair_with(
        ChannelConfig { rekey_interval: 3 },
        ChannelConfig { rekey_interval: 4 },
    );
    for _ in 0..3 {
        p.s_rx.open(&frame(&p.c_tx.seal(b"ok").unwrap())).unwrap();
    }
    // Record 3: the client is in epoch 1, the server still in epoch 0.
    assert_eq!(
        p.s_rx
            .open(&frame(&p.c_tx.seal(b"boom").unwrap()))
            .unwrap_err(),
        Error::BadRecord
    );
}

#[test]
fn identical_plaintexts_give_distinct_ciphertexts() {
    let mut p = pair(2);
    let a = p.c_tx.seal(b"same").unwrap();
    let b = p.c_tx.seal(b"same").unwrap();
    let c = p.c_tx.seal(b"same").unwrap(); // next epoch
    assert_ne!(a[11..], b[11..]);
    assert_ne!(b[11..], c[11..]);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    /// Any single-byte alteration of a record is rejected.
    #[test]
    fn prop_any_byte_flip_is_rejected(
        msg in proptest::collection::vec(any::<u8>(), 0..300),
        idx in any::<prop::sample::Index>(),
        mask in 1u8..=255,
    ) {
        let mut p = pair(1000);
        let mut r = p.c_tx.seal(&msg).unwrap();
        let i = idx.index(r.len());
        r[i] ^= mask;
        let mut d = Deframer::new();
        d.push(&r);
        // Either the frame header is now invalid / incomplete, or the
        // record layer rejects it.
        match d.next_frame() {
            Err(_) | Ok(None) => {}
            Ok(Some(f)) => prop_assert!(p.s_rx.open(&f).is_err()),
        }
    }

    /// A random interleaving of messages in both directions, crossing several
    /// rekeys, is delivered intact and in order.
    #[test]
    fn prop_roundtrip_across_rekeys(
        msgs in proptest::collection::vec((any::<bool>(), proptest::collection::vec(any::<u8>(), 0..200)), 1..40),
        interval in 1u64..6,
    ) {
        let mut p = pair(interval);
        for (to_server, m) in &msgs {
            let got = if *to_server {
                p.s_rx.open(&frame(&p.c_tx.seal(m).unwrap())).unwrap()
            } else {
                p.c_rx.open(&frame(&p.s_tx.seal(m).unwrap())).unwrap()
            };
            prop_assert_eq!(data(got), m.clone());
        }
    }

    /// The deframer never panics and never yields an invalid frame.
    #[test]
    fn prop_deframer_total(chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..64), 0..20)) {
        let mut d = Deframer::new();
        for c in &chunks {
            d.push(c);
            while let Ok(Some(f)) = d.next_frame() {
                prop_assert!(Frame::header(f.ty, f.body.len()).is_ok());
            }
        }
    }
}
