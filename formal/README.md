# Formal model (Tamarin)

[`janus.spthy`](janus.spthy) models the Janus v1 handshake
([`docs/PROTOCOL.md`](../docs/PROTOCOL.md) §6) in the symbolic
(Dolev–Yao) model with the [Tamarin prover](https://tamarin-prover.com).

> **Status: all lemmas verified** with Tamarin 1.12.0 / Maude 3.5.1
> (`./run.sh`). This is a proof about the *symbolic model* below, under its
> abstractions — not about the Rust code, and not a computational proof.

| Lemma | Result | Steps | Time¹ |
|---|---|---|---|
| `executable` | verified (exists-trace) | 23 | ≈ 3.5 min |
| `session_key_secrecy` | verified | 267 | 47 s |
| `server_authentication` | verified | 70 | 10 s |
| `client_authentication_injective` | verified | 40 | 9 s |

¹ Wall clock, one lemma per process, Apple Silicon laptop.

### Sanity checks (the lemmas are not vacuous)

Each check removes one exception from a real lemma, so Tamarin must find an
attack:

| Weakened lemma | Expected | Result |
|---|---|---|
| server authentication without the "both signature schemes broken" exception | attack | **falsified**, 26-step trace (127 s) |
| client authentication without the "client key revealed" exception | attack | **falsified**, 32-step trace (84 s) |
| key secrecy without the "both KEMs broken" exception (and as an `exists-trace` passive attack) | attack | **inconclusive**: Tamarin ran out of resources after ≈ 46 min and ≈ 58 min |

The third check is still open: it is not known whether the model lets
Tamarin rebuild the key from both broken KEM secrets in reasonable time.
The `executable` lemma does show that honest runs reach `Secret`, so
`session_key_secrecy` is not vacuously true.

## Attacker

Controls the network and may at any time reveal any agent's long-term keys,
break Ed25519 or ML-DSA-65 (sign as anyone), or break X25519 or ML-KEM-768
(recover any session's ephemeral secret).

## Lemmas

| Lemma | Claim |
|---|---|
| `executable` | an honest run where both sides accept the same key exists |
| `session_key_secrecy` | the key stays secret unless **both** KEMs are broken, or the peer's key leaked **before** acceptance, or **both** signature schemes are broken (forward secrecy: later leaks do not help) |
| `server_authentication` | a client that accepts really talked to the pinned server, with the same transcript; compromise of the client's own key is not an exception (KCI resistance) |
| `client_authentication_injective` | each accepted `ClientFinish` comes from a distinct run of the pinned client (no replay); KCI resistant |

## Abstractions

- SHA-384, HKDF and HMAC are a free hash over tagged tuples; the streaming
  transcript hash is modelled as a hash chain.
- ML-KEM-768 is an ideal KEM. X25519 is modelled as a DHKEM (as in HPKE):
  the server encapsulates a fresh secret to the client's ephemeral key. The
  term algebra has no equations; "breaking" a KEM reveals the shared secrets
  it protects in **every** session, the strongest form of the assumption.
  Low-order X25519 points are not modelled (rejected in code, tested with
  Wycheproof).
- Signatures are ideal; "breaking" a scheme gives the attacker every
  agent's signing key for it.
- Implicit rejection, lengths and parsing are not modelled (covered by the
  tests and fuzzing). The record layer is not modelled.

Why these choices: a first version with Tamarin's Diffie-Hellman theory,
`decaps` equations and full transcript re-hashing was faithful but did not
terminate even on the executability lemma. The abstractions above keep the
security-relevant structure (what is signed, MACed and fed to the KDF) while
making the search tractable.

## Running

```sh
brew install tamarin-prover/tap/tamarin-prover
./formal/run.sh
```
