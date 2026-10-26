# Known-answer test vectors

Subsets of [Wycheproof](https://github.com/C2SP/wycheproof) (`testvectors_v1/`,
Apache-2.0), converted to a minimal `key = value` format (one blank-line
separated block per test case) so the tests need no JSON dependency.

| File                    | Source file                      | Kept                                   |
|-------------------------|----------------------------------|----------------------------------------|
| `mlkem768_decaps.txt`   | `mlkem_768_test.json`            | 24 valid + 4 wrong-length ciphertexts  |
| `mlkem768_encaps.txt`   | `mlkem_768_encaps_test.json`     | valid + unreduced / wrong-length keys  |
| `mldsa65_verify.txt`    | `mldsa_65_verify_test.json`      | ≤ 3 per (result, flags) combination    |
| `mldsa65_sign_seed.txt` | `mldsa_65_sign_seed_test.json`   | 6 deterministic signatures             |
| `x25519.txt`            | `x25519_test.json`               | ≤ 2 per flag combination               |
| `ed25519.txt`           | `ed25519_test.json`              | ≤ 4 per (result, flags) combination    |

The tests themselves live in `src/kat_tests.rs` (they need crate-private
accessors to the shared secrets).
