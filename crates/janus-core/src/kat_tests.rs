//! Known-answer tests.
//!
//! Sources:
//! - RFC 7748 §6.1 (X25519) and RFC 8032 §7.1 test 1 (Ed25519), inline below;
//! - Wycheproof (C2SP) vectors for ML-KEM-768, ML-DSA-65, X25519 and Ed25519,
//!   subsets of which are stored in `tests/kat/` (see the file headers).
//!
//! Whenever possible the vectors are pushed through the *production* wrappers
//! (`KemInitiator::generate`, `KemPublic::encapsulate`, …) using
//! [`ReplayRng`] to inject the randomness the vector prescribes, rather than
//! through the underlying crates directly. That way the tests check our
//! plumbing (byte order, which bytes are drawn from the RNG and when, length
//! checks), not just RustCrypto.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use subtle::ConstantTimeEq;

use crate::error::Error;
use crate::kem::{KemCiphertext, KemInitiator, KemPublic};
use crate::sig::{self, ED25519_PK_LEN, IdentityKeypair, IdentityPublic};
use crate::test_util::{ReplayRng, hex, parse_kat};

// RFC 7748 §6.1.
const ALICE_SK: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const ALICE_PK: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const BOB_SK: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const BOB_PK: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
const X25519_SHARED: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

const MLKEM_DECAPS: &str = include_str!("../tests/kat/mlkem768_decaps.txt");
const MLKEM_ENCAPS: &str = include_str!("../tests/kat/mlkem768_encaps.txt");
const MLDSA_VERIFY: &str = include_str!("../tests/kat/mldsa65_verify.txt");
const MLDSA_SIGN: &str = include_str!("../tests/kat/mldsa65_sign_seed.txt");
const X25519_WP: &str = include_str!("../tests/kat/x25519.txt");
const ED25519_WP: &str = include_str!("../tests/kat/ed25519.txt");

/// RFC 7748 through `KemInitiator` (Alice) and `KemPublic::encapsulate` (Bob),
/// with the ML-KEM half taken from the first Wycheproof vector.
#[test]
fn rfc7748_through_hybrid_wrappers() {
    let case = &parse_kat(MLKEM_DECAPS)[0];
    let mut rng = ReplayRng::new(&[&hex(ALICE_SK), &hex(&case["seed"])]);
    let alice = KemInitiator::generate(&mut rng);
    rng.assert_exhausted();
    let pk = alice.public().to_bytes();
    assert_eq!(&pk[..1184], hex(&case["ek"]).as_slice());
    assert_eq!(&pk[1184..], hex(ALICE_PK).as_slice());

    let mut rng = ReplayRng::new(&[&hex(BOB_SK), &[0x42; 32]]);
    let (ct, ss_bob) = alice.public().encapsulate(&mut rng).unwrap();
    rng.assert_exhausted();
    assert_eq!(&ct.to_bytes()[1088..], hex(BOB_PK).as_slice());
    assert_eq!(ss_bob.x25519_part(), hex(X25519_SHARED).as_slice());

    let ss_alice = alice.decapsulate(&ct).unwrap();
    assert!(bool::from(ss_alice.ct_eq(&ss_bob)));
}

/// Wycheproof `mlkem_768_test`: keygen from seed, then decapsulation.
#[test]
fn mlkem768_keygen_and_decaps() {
    let cases = parse_kat(MLKEM_DECAPS);
    assert!(cases.len() > 20);
    for case in &cases {
        let id = &case["tcId"];
        let mut rng = ReplayRng::new(&[&hex(ALICE_SK), &hex(&case["seed"])]);
        let alice = KemInitiator::generate(&mut rng);

        let mut ct = hex(&case["c"]);
        ct.extend_from_slice(&hex(BOB_PK));
        match case["result"].as_str() {
            "valid" => {
                assert_eq!(
                    &alice.public().to_bytes()[..1184],
                    hex(&case["ek"]).as_slice(),
                    "tc {id}: ek"
                );
                let ss = alice
                    .decapsulate(&KemCiphertext::from_bytes(&ct).unwrap())
                    .unwrap();
                assert_eq!(ss.mlkem_part(), hex(&case["K"]).as_slice(), "tc {id}: K");
                assert_eq!(ss.x25519_part(), hex(X25519_SHARED).as_slice());
            }
            // The only invalid cases kept are wrong-length ciphertexts.
            _ => assert_eq!(
                KemCiphertext::from_bytes(&ct).unwrap_err(),
                Error::Malformed,
                "tc {id}"
            ),
        }
    }
}

/// Wycheproof `mlkem_768_encaps_test`, incl. the FIPS 203 modulus check.
#[test]
fn mlkem768_encaps() {
    let cases = parse_kat(MLKEM_ENCAPS);
    let (mut valid, mut invalid) = (0, 0);
    for case in &cases {
        let id = &case["tcId"];
        let mut pk = hex(&case["ek"]);
        pk.extend_from_slice(&hex(ALICE_PK));
        match case["result"].as_str() {
            "valid" => {
                valid += 1;
                let pk = KemPublic::from_bytes(&pk).unwrap();
                let mut rng = ReplayRng::new(&[&hex(BOB_SK), &hex(&case["m"])]);
                let (ct, ss) = pk.encapsulate(&mut rng).unwrap();
                rng.assert_exhausted();
                let ct = ct.to_bytes();
                assert_eq!(&ct[..1088], hex(&case["c"]).as_slice(), "tc {id}: c");
                assert_eq!(&ct[1088..], hex(BOB_PK).as_slice());
                assert_eq!(ss.mlkem_part(), hex(&case["K"]).as_slice(), "tc {id}: K");
            }
            _ => {
                invalid += 1;
                let err = KemPublic::from_bytes(&pk).unwrap_err();
                assert!(
                    matches!(err, Error::InvalidPublicKey | Error::Malformed),
                    "tc {id}: {err:?}"
                );
            }
        }
    }
    assert!(valid > 10 && invalid > 10);
}

/// Wycheproof `x25519_test`, through `KemPublic::encapsulate`: the vector's
/// private key is injected as our ephemeral scalar and its public key as the
/// peer's share. All-zero outputs must be rejected.
#[test]
fn x25519_wycheproof() {
    let ek = &parse_kat(MLKEM_ENCAPS)
        .into_iter()
        .find(|c| c["result"] == "valid")
        .unwrap()["ek"];
    let cases = parse_kat(X25519_WP);
    let mut rejected = 0;
    for case in &cases {
        let id = &case["tcId"];
        let mut pk = hex(ek);
        pk.extend_from_slice(&hex(&case["public"]));
        let pk = KemPublic::from_bytes(&pk).unwrap();
        let mut rng = ReplayRng::new(&[&hex(&case["private"]), &[0u8; 32]]);
        let res = pk.encapsulate(&mut rng);
        if case["flags"].contains("ZeroSharedSecret") {
            rejected += 1;
            assert_eq!(res.unwrap_err(), Error::NonContributory, "tc {id}");
        } else {
            let (_, ss) = res.unwrap();
            assert_eq!(ss.x25519_part(), hex(&case["shared"]).as_slice(), "tc {id}");
        }
    }
    assert!(rejected > 0);
}

/// Wycheproof `mldsa_65_verify_test`, on the exact verification call used by
/// `IdentityPublic::verify`.
#[test]
fn mldsa65_verify() {
    let cases = parse_kat(MLDSA_VERIFY);
    for case in &cases {
        let id = &case["tcId"];
        let expect = case["result"] == "valid";
        let pk = hex(&case["pk"]);
        let ok = match ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(pk.as_slice()) {
            Ok(enc) => {
                let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&enc);
                sig::mldsa_verify_raw(
                    &vk,
                    &hex(&case["msg"]),
                    &hex(&case["ctx"]),
                    &hex(&case["sig"]),
                )
            }
            Err(_) => false,
        };
        assert_eq!(ok, expect, "tc {id} ({})", case["flags"]);
    }
}

/// Wycheproof `mldsa_65_sign_seed_test`: our `IdentityKeypair::from_seed`
/// derives the expected ML-DSA key, and deterministic signing matches.
#[test]
fn mldsa65_keygen_and_sign() {
    for case in &parse_kat(MLDSA_SIGN) {
        let id = &case["tcId"];
        let mut seed = [0u8; 64];
        seed[32..].copy_from_slice(&hex(&case["seed"]));
        let kp = IdentityKeypair::from_seed(&seed);
        assert_eq!(
            &kp.public().as_bytes()[ED25519_PK_LEN..],
            hex(&case["pk"]).as_slice(),
            "tc {id}: pk"
        );
        let sig = kp.mldsa_sign_raw_deterministic(&hex(&case["msg"]), &hex(&case["ctx"]));
        assert_eq!(sig, hex(&case["sig"]), "tc {id}: sig");
    }
}

/// RFC 8032 §7.1 TEST 1, through `IdentityKeypair::from_seed`.
#[test]
fn rfc8032_test1() {
    let sk = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let pk = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let sig = hex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(&sk);
    let kp = IdentityKeypair::from_seed(&seed);
    assert_eq!(&kp.public().as_bytes()[..32], pk.as_slice());

    let vk = ed25519_dalek::VerifyingKey::from_bytes(pk.as_slice().try_into().unwrap()).unwrap();
    assert!(sig::ed25519_verify_raw(
        &vk,
        b"",
        sig.as_slice().try_into().unwrap()
    ));
}

/// Wycheproof `ed25519_test` with `verify_strict`. "acceptable" vectors are
/// implementation-defined; we only require that `valid` passes and `invalid`
/// fails, and additionally that malleable signatures are rejected.
#[test]
fn ed25519_wycheproof() {
    for case in &parse_kat(ED25519_WP) {
        let id = &case["tcId"];
        let pk: [u8; 32] = hex(&case["pk"]).try_into().unwrap();
        let sig = hex(&case["sig"]);
        let ok = match (
            ed25519_dalek::VerifyingKey::from_bytes(&pk),
            <[u8; 64]>::try_from(sig.as_slice()),
        ) {
            (Ok(vk), Ok(sig)) => sig::ed25519_verify_raw(&vk, &hex(&case["msg"]), &sig),
            _ => false,
        };
        match case["result"].as_str() {
            "valid" => assert!(ok, "tc {id} ({})", case["flags"]),
            "invalid" => assert!(!ok, "tc {id} ({})", case["flags"]),
            _ => {
                if case["flags"].contains("SignatureMalleability") {
                    assert!(!ok, "tc {id}: malleable signature accepted");
                }
            }
        }
    }
}

/// Wycheproof ML-DSA public keys, combined with an Ed25519 key, round-trip
/// through `IdentityPublic::from_bytes` byte-for-byte.
#[test]
fn identity_public_parses_kat_keys() {
    let ed_pk = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    for case in parse_kat(MLDSA_SIGN).iter().take(3) {
        let mut bytes = ed_pk.clone();
        bytes.extend_from_slice(&hex(&case["pk"]));
        let id = IdentityPublic::from_bytes(&bytes).unwrap();
        assert_eq!(id.as_bytes().as_slice(), bytes.as_slice());
    }
}
