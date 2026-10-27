# Formal model (Tamarin)

[`janus.spthy`](janus.spthy) models the Janus v1 handshake
([`docs/PROTOCOL.md`](../docs/PROTOCOL.md) §6) in the symbolic
(Dolev–Yao) model with the [Tamarin prover](https://tamarin-prover.com).

> **Status: written, not yet machine-checked.** Tamarin could not be
> installed in the environment where the model was written. Until
> `./run.sh` reports every lemma as *verified*, treat the model as a draft:
> it may not even parse.

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

- SHA-384, HKDF and HMAC are a free hash over tagged tuples; ML-KEM is an
  ideal KEM; signatures are ideal. Implicit rejection, lengths and parsing
  are not modelled (they are covered by the tests and fuzzing).
- "Breaking" a primitive gives the attacker the secrets of **every** agent
  or session for that primitive, the strongest form of the assumption.
- The record layer is not modelled.

## Running

```sh
brew install tamarin-prover/tap/tamarin-prover
./formal/run.sh
```
