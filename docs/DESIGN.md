# Janus — design notes

> **Status: educational / portfolio project. Not production-ready, not
> audited.** The handshake has a machine-checked *symbolic* Tamarin
> model ([`formal/`](../formal/)); there is no computational proof. This
> document explains what Janus tries to achieve, how, and — just as
> importantly — what it does **not** guarantee.

## 1. Goals and non-goals

**Goals**

- A mutually authenticated key exchange whose secrecy survives the break of
  *either* X25519 *or* ML-KEM-768, and whose authentication survives the
  break of *either* Ed25519 *or* ML-DSA-65.
- Forward secrecy: compromise of long-term keys does not expose past sessions.
- A small, readable, strictly parsed protocol with a sans-IO core that can be
  tested exhaustively without a network.
- No home-made primitives; `#![forbid(unsafe_code)]`; no panics reachable
  from network input.

**Non-goals**: negotiation (cipher suites, versions, extensions), PKI,
session resumption, 0-RTT, identity hiding, datagram transport, DoS
resistance. Each of these is a deliberate simplification (see §7).

## 2. Primitives

| Role                 | Primitive                         | Crate (version)              | Why |
|----------------------|-----------------------------------|------------------------------|-----|
| KEM, classical       | X25519 (RFC 7748)                 | `x25519-dalek` 3.0           | widely deployed, fast, small |
| KEM, post-quantum    | ML-KEM-768 (FIPS 203)             | `ml-kem` 0.3                 | NIST category 3, the de-facto hybrid choice (`X25519MLKEM768`) |
| Signature, classical | Ed25519 (RFC 8032), `verify_strict` | `ed25519-dalek` 3.0        | strict verification: no malleability, rejects small-order keys |
| Signature, PQ        | ML-DSA-65 (FIPS 204), hedged      | `ml-dsa` 0.1                 | category 3 to match ML-KEM-768 |
| Hash / KDF / MAC     | SHA-384, HKDF-SHA-384, HMAC-SHA-384 | `sha2` 0.11, `hkdf`/`hmac` 0.13 | 192-bit collision resistance matches category 3 |
| AEAD                 | ChaCha20-Poly1305 (RFC 8439)      | `chacha20poly1305` 0.11      | constant-time in software, 256-bit key (Grover leaves ~128 bits) |
| Constant-time / wipe | `subtle`, `zeroize`               |                              | |

**On crate maturity.** `ml-dsa` reached 0.1.0 in May 2026 and `ml-kem` 0.3 in
April 2026; the whole RustCrypto stack (`rand_core` 0.10, `digest` 0.11,
dalek 3.0) moved to new major versions in 2026. The APIs used here were read
from the published sources, not assumed. None of these PQ crates has had a
public third-party audit at the time of writing. If that is a concern, the
natural alternative is `aws-lc-rs` (FIPS-validated AWS-LC, ML-KEM and ML-DSA
available), at the cost of a C/assembly dependency.

**A dependency incident during development.** `cargo audit` flagged
RUSTSEC-2026-0385 (non-constant-time mask generation in `ctutils` < 0.4.4, a
transitive dependency of `ml-kem`/`ml-dsa`). The fixed releases require Rust
1.87, so the MSRV was raised rather than staying on a vulnerable version. It
was raised again to **1.88** for `sha2` 0.11.1, which fixes undefined
behaviour (Stacked Borrows) in its AArch64 backend. CI checks the MSRV and runs
`cargo audit` and `cargo deny` on every push; Dependabot is enabled.

## 3. Handshake

### 3.1 Messages

All messages have a fixed length and a `version ‖ type` header; there are no
optional or variable-length fields.

```text
ClientHello  (I→R) = 01 01 ‖ c_random[32] ‖ mlkem_ek[1184] ‖ x25519_I[32]          1250 B
ServerHello  (R→I) = 01 02 ‖ s_random[32] ‖ mlkem_ct[1088] ‖ x25519_R[32]
                           ‖ id_R[1984] ‖ sig_R[3373] ‖ fin_R[48]                   6559 B
ClientFinish (I→R) = 01 03 ‖ id_I[1984] ‖ sig_I[3373] ‖ fin_I[48]                   5407 B

id  = ed25519_pk[32] ‖ mldsa65_pk[1952]
sig = ed25519_sig[64] ‖ mldsa65_sig[3309]
```

The hybrid KEM layout (ML-KEM first, X25519 second, on the wire and in the
shared secret) is that of the `X25519MLKEM768` TLS code point and of X-Wing.

Parsing order is fixed: version → type → exact length → each field
(ML-KEM modulus check per FIPS 203 §7.2, Ed25519 point decoding, rejection
of small-order and non-canonical Ed25519 keys). A fuzz target checks that
every accepted message is canonical (`encode(decode(m)) == m`).

### 3.2 Flow

```text
 Client                                                     Server
 eph ← (ML-KEM-768 keypair, X25519 keypair)       fresh per handshake
                ClientHello ─────────────────────▶
                                                  (ct, ss) ← Encaps(eph_pk)
                                                  prk ← HKDF-Extract(TH(kex), ss)
                ◀───────────────────── ServerHello: ct, id_R,
                                         sig_R(TH(…‖id_R)), MAC_R(TH(…‖sig_R))
 ss ← Decaps(ct); prk ← …
 pinned(id_R)? sig_R? MAC_R?
                ClientFinish: id_I, sig_I(TH(…‖id_I)), MAC_I(TH(…‖sig_I)) ──▶
                                                  pinned(id_I)? sig_I? MAC_I?
 traffic keys ← Expand(prk, TH(final))            traffic keys ← …
```

This is a SIGMA-style "sign-and-MAC" protocol, in the same order as TLS 1.3's
Certificate / CertificateVerify / Finished. The sans-IO implementation uses
**typestates**: each state is its own type, each transition consumes it, so
out-of-order calls do not compile and a failed handshake cannot be resumed.

### 3.3 Transcript

`TH(x) = SHA-384("janus/v1 transcript" ‖ every wire byte up to x)`.

*Why this order?* The transcript is the wire bytes in wire order, so the two
peers' views cannot diverge. The receiver hashes the bytes it **received**
(split at fixed offsets), and the sender hashes exactly what it sends through
a single `emit` helper — there is no re-encoding step that could differ.

- Each signature covers everything before it **including the signer's own
  identity**: the signature cannot be re-attributed to another identity
  (identity misbinding).
- Each MAC covers the signature before it: key confirmation for the whole
  flight; together with the signatures this rules out unknown-key-share.
- The client's signature also covers the server's identity and signature,
  binding the client's authentication to *this* server.
- Even bits that the primitive ignores are bound: flipping the top bit of an
  X25519 share does not change the X25519 output (RFC 7748 masks it), but it
  changes `TH`, so the signature fails. There is a test for exactly this.

### 3.4 Key schedule

```text
ikm        = ss_mlkem ‖ ss_x25519                         (64 B)
prk        = HKDF-Extract(salt = TH(kex), ikm)
fk_R, fk_I = Expand-Label(prk, "s finished" / "c finished", "", 48)
c2s, s2c   = Expand-Label(prk, "c2s traffic" / "s2c traffic", TH(final), 48)
session_id = Expand-Label(prk, "exporter", TH(final), 48)

Expand-Label(k, label, ctx, L) = HKDF-Expand(k, L:u16 ‖ len ‖ "janus/v1 " ‖ label ‖ len ‖ ctx, L)
```

- **Combiner.** `TH(kex)` covers both randoms, the ML-KEM encapsulation key and
  ciphertext, and both X25519 shares. As HKDF salt, it makes the PRK a function
  of both shared secrets *and all public KEM values* — what X-Wing hashes
  explicitly. HKDF-Extract (HMAC) is a dual PRF, so the PRK stays pseudorandom
  if **either** shared secret is. Binding the X25519 values is needed because
  X25519 alone is not an IND-CCA KEM.
- **Domain separation.** Every derived value has its own label; the
  TLS-style encoding (with output length and length prefixes) makes the HKDF
  `info` injective, so no two derivations can collide. A unit test checks that
  all labels yield distinct outputs.
- **SHA-384**, not SHA-256: the category-3 PQ parameters would otherwise be
  bounded by SHA-256's 128-bit collision resistance in the transcript.
- **Finished keys** have an empty context (the PRK already depends on `TH(kex)`,
  and the MAC input is the transcript). **Traffic secrets** depend on
  `TH(final)`, so the session keys commit to both identities and signatures.

### 3.5 Hybrid signatures and anti-stripping

Each half of a hybrid signature signs the same message:

```text
M' = "janus/v1 hybrid-sig" ‖ len(label) ‖ label ‖ (ed25519_pk ‖ mldsa_pk) ‖ TH
```

The full hybrid public key inside `M'` prevents "stripping": half of an honest
signature cannot be re-attached to a different hybrid key that shares only
that half. The role label (`janus/v1 server signature` / `… client
signature`) separates the two roles; for ML-DSA it is also passed as the FIPS
204 *context string*. Both halves are always verified (no short-circuit) and
the result is their AND.

### 3.6 Trust model

No PKI. Each side holds a set of pinned identity fingerprints
(`SHA-384("janus/v1 fingerprint" ‖ id)`, i.e. of **both** halves), like SSH
`known_hosts` or WireGuard. The store is scanned in constant time. Both sides
also display the session id, which users can compare out of band.

## 4. Record layer

```text
frame  = type:u8 ‖ len:u16 ‖ body           type ∈ {Handshake 0x16, Data 0x17, Close 0x15}
record = seq:u64 ‖ ChaCha20-Poly1305(key_e, iv_e ⊕ seq, pt, aad = "janus/v1 record" ‖ type ‖ len ‖ seq)
epoch e = seq / N;  secret_{e+1} = Expand-Label(secret_e, "rekey", "", 48);  key_e, iv_e = Expand-Label(secret_e, "key"/"iv")
```

| Property            | Mechanism |
|---------------------|-----------|
| Confidentiality / integrity | ChaCha20-Poly1305 with per-direction keys |
| Nonce uniqueness    | `iv ⊕ seq`, counter never reused, never wraps (`u64::MAX` refused) |
| No reflection       | distinct `c2s` / `s2c` keys |
| Replay / reordering / drops | explicit `seq`, strict `seq == expected`, checked before decryption |
| Type / length integrity | header in the AAD (a `Data` record cannot become `Close`) |
| Truncation          | authenticated `Close` record; EOF without it ⇒ `Truncated` |
| Forward secrecy within a session | one-way rekey every N records, old keys zeroized |
| No decryption oracle | any error permanently fails the receiving direction |

*Explicit vs implicit sequence numbers.* TLS 1.3 keeps the counter implicit.
Janus sends it (8 extra bytes) to report replays and reorderings distinctly,
and to leave the door open to an unreliable transport; it is authenticated
twice (AAD and nonce). Over TCP the policy is strict in-order delivery.

## 5. Implementation hygiene

- **Sans-IO**: `janus-core` and `janus-channel` never touch a socket; the CLI
  is a thin tokio driver. Every protocol path is unit-testable.
- **No panics on input**: workspace lints deny `unwrap`, `expect`, `panic`,
  indexing/slicing and warn on unchecked arithmetic in library code; parsers
  use `split_first_chunk`/`split_at_checked`. Fuzzed (§9).
- **Constant time**: fingerprints, MACs and secret comparisons use `subtle`;
  the primitives' constant-time behaviour is that of the underlying crates.
- **Zeroization**: shared secrets, PRKs, traffic secrets, AEAD keys/IVs,
  seeds and secret keys are `Zeroize`/`ZeroizeOnDrop` (directly or through the
  crates' `zeroize` features). `hmac` 0.13 does not mark `Hmac` as
  `ZeroizeOnDrop`, but its fields (SHA-384 cores, block buffer) are; a
  compile-time test pins that down.

## 6. Threat model

The attacker:

1. controls the network (Dolev–Yao): reads, drops, injects, reorders,
   replays and modifies messages, and can run its own sessions with honest
   parties;
2. may record traffic today and own a large quantum computer later
   ("harvest now, decrypt later");
3. may break **one** of the two primitives of each pair (classical or PQ),
   but not both;
4. may later steal long-term identity keys (forward secrecy);
5. may steal the long-term key of one party and try to impersonate *others*
   to it (key-compromise impersonation).

Under these assumptions Janus aims for (informally): session-key secrecy and
authentication of both peers (if at least one primitive of each pair holds),
forward secrecy, KCI resistance (impersonating B to A needs B's signing keys,
not A's), no identity misbinding / unknown key share, and channel integrity
including replay, reordering and truncation detection.

## 7. What is **not** guaranteed

- **Symbolic proof only, no audit.** Session-key secrecy, forward secrecy
  and (injective, KCI-resistant) mutual authentication of the handshake are
  machine-checked by Tamarin for the symbolic model in [`formal/`](../formal/):
  a Dolev–Yao attacker that may also reveal long-term keys and break any
  primitive, the properties holding while one primitive of each pair holds.
  The model treats hashes, KEMs and signatures as ideal and does not cover
  the record layer, parsing or the Rust code itself. There is no
  computational (game-based) proof and no review by cryptographers.
- **No identity hiding.** Identities are sent in clear: a passive observer
  learns who is talking to whom (TLS 1.3 encrypts certificates; Janus does not).
- **No deniability.** Both parties sign the transcript, so a transcript is
  transferable evidence of participation (unlike Signal's X3DH / PQXDH).
- **No DoS protection.** The server performs an encapsulation and an ML-DSA
  signature before the client has proven anything; there are no cookies or
  rate limits.
- **No PKI, revocation or key rotation.** Pins are managed by hand; a wrong pin
  is a silent MITM unless users compare session ids.
- **Identity files are only as strong as their passphrase.** `keygen
  --encrypt` seals the seed with XChaCha20-Poly1305 under an Argon2id key
  (64 MiB, t=3, parameters authenticated); without `--encrypt` the seed is
  stored in clear (mode 0600) and the CLI warns on every use. A decrypted key
  lives in process memory for the whole session.
- **Traffic analysis.** No padding: record lengths and timing leak.
- **Side channels.** Timing / power behaviour depends on the RustCrypto and
  dalek implementations; Rust gives no constant-time guarantee across compiler
  versions. The PQ crates are young and unaudited.
- **Best-effort zeroization.** Moves, stack spills, register contents, swap
  and core dumps can retain copies; plaintext handed to the application is not
  wiped; intermediate HKDF blocks inside `hkdf` are not wiped.
- **RNG.** Everything depends on the OS RNG (probed at startup, then trusted).
- **Rekey interval** must be configured identically on both sides; there is
  no `KeyUpdate` message.
- **Single version, no negotiation.** A future v2 would need explicit
  downgrade protection (the version byte is already in the transcript).
- **Server confirmation of the client** is implicit in the protocol: like TLS
  1.3, the client could send data after `ClientFinish` before knowing the
  server accepted it. The demo CLI adds an explicit acceptance receipt (the
  server's first record is empty) and the client waits for it, but this is an
  application convention, not part of the handshake.
- **No multi-session / multi-user security analysis**, no bounds on the
  number of sessions per identity.

## 8. Comparison

| | **Janus** | **X-Wing** | **PQXDH** (Signal) | **TLS 1.3 + `X25519MLKEM768`** |
|---|---|---|---|---|
| What it is | interactive AKE + channel | a hybrid **KEM** only | asynchronous AKE (prekeys) | full protocol, hybrid key share |
| Hybrid KEM | X25519 + ML-KEM-768 | X25519 + ML-KEM-768 | X25519 + Kyber-1024 | X25519 + ML-KEM-768 |
| Combiner | HKDF-Extract with salt = transcript of all KEM values | SHA3-256 over `ss_M`, `ss_X`, `ct_X`, `pk_X` and a fixed label | KDF over the X3DH DH outputs ‖ KEM secret | concatenation fed into the TLS key schedule, transcript-bound |
| PQ authentication | **yes** (ML-DSA-65 AND Ed25519) | n/a | **no** (XEdDSA only) | not yet standard (ML-DSA / composite certs are drafts) |
| Deniability | no (signatures) | n/a | yes (DH-based) | no |
| Identity hiding | no | n/a | n/a (server-mediated) | yes (encrypted certificates) |
| Negotiation | none (fixed suite) | n/a | none | full (versions, groups, suites) |
| Trust | pinned fingerprints | n/a | safety numbers | X.509 PKI |

- **X-Wing** is a KEM, not a protocol. It hashes only the X25519 ciphertext and
  public key alongside the two secrets, because ML-KEM's own FO transform
  already binds its ciphertext and key. Janus binds *everything* through the
  transcript salt — more than strictly needed, but it costs nothing and does
  not rely on ML-KEM's internal binding. Janus could adopt X-Wing as its KEM
  directly; it does not, to keep the two components visible for teaching.
- **PQXDH** targets asynchronous messaging with prekeys and keeps
  authentication classical: a future quantum attacker cannot decrypt recorded
  sessions but could impersonate. Janus is interactive and authenticates with
  both a classical and a PQ signature, giving up deniability.
- **TLS 1.3 hybrid** uses the same KEM layout. Janus is a deliberately tiny
  subset — one suite, no negotiation, no PKI, no resumption — with PQ
  authentication that TLS deployments do not have yet, but without TLS's
  identity hiding, maturity and analysis.

## 9. Measurements and testing

*Measured on the development machine (Apple Silicon, macOS, release build).
Reproduce with `cargo bench -p janus-bench` and
`cargo run -p janus-bench --example sizes`.*

### Message sizes

| Message | Hybrid (bytes) | Same protocol, classical only (bytes) | Ratio |
|---|---:|---:|---:|
| ClientHello | 1250 | 66 | ×18.9 |
| ServerHello | 6559 | 210 | ×31.2 |
| ClientFinish | 5407 | 146 | ×37.0 |
| **Total** | **13216** | 422 | ×31.3 |

(+3 bytes of framing per message.) The bulk is post-quantum: the two hybrid
signatures (2 × 3373 B) and identities (2 × 1984 B) account for 80 % of the
handshake. A `ServerHello` no longer fits in a single 1500-byte packet, which
matters for UDP-based designs, not for TCP.

### CPU cost

| Operation | Time | vs classical |
|---|---:|---:|
| X25519 keygen + DH | 44 µs | |
| ML-KEM-768 keygen / encaps / decaps | 29 / 23 / 27 µs | |
| Ed25519 sign / verify | 12 / 32 µs | |
| ML-DSA-65 sign (hedged) / verify | 328 / 34 µs | |
| **Key exchange, both sides**: X25519 only | 88 µs | 1× |
| **Key exchange, both sides**: X25519 + ML-KEM-768 (Janus) | 177 µs | **×2.0** |
| **Sign + verify**: Ed25519 only | 44 µs | 1× |
| **Sign + verify**: Ed25519 + ML-DSA-65 (Janus) | 431 µs | **×9.8** |
| **Full handshake** (client + server CPU, in memory) | **1.23 ms** | |
| Record seal + open, 64 B / 1 KiB / 16 KiB | 1.5 / 4.0 / 51 µs | ≈ 300 MiB/s at 16 KiB |

Reading: the post-quantum KEM is cheap (it only doubles the cost of X25519);
the expensive part is ML-DSA *signing* (rejection sampling, ~7× an X25519
operation), done once per side per handshake. Over loopback TCP the demo CLI
reports ≈ 1 ms per handshake, i.e. the protocol is CPU-bound, not
round-trip-bound, on a LAN.

### Testing strategy

- **Formal model** ([`formal/`](../formal/)): Tamarin proves session-key
  secrecy, forward secrecy, KCI-resistant server authentication and
  injective client authentication of the handshake in the symbolic model.
- **KATs**: RFC 7748, RFC 8032 and Wycheproof (ML-KEM-768 keygen / encaps /
  decaps incl. unreduced keys, ML-DSA-65 keygen / signing / verification,
  X25519 low-order points, Ed25519 malleability), injected through the
  *production* wrappers with a replaying RNG.
- **Property tests** (`proptest`): handshake round trips; any single-byte
  alteration or length change of any handshake message fails; any byte flip of
  a record is rejected; random bidirectional traffic across rekeys round-trips.
- **Adversarial tests**: impersonation by an active attacker that knows the
  session keys, replay, reflection, reordering, truncation, type confusion,
  untrusted peers, rekey mismatch.
- **Mutation checks** (manual): disabling signature verification, removing the
  header from the AAD, removing the sequence check or the rekey each make at
  least one test fail. This found a real gap: the tamper-based property tests
  alone did *not* catch disabled signature verification (the `Finished` MACs
  catch tampering), which is why the impersonation tests exist.
- **Fuzzing** (`cargo-fuzz`, 5 targets): see [`fuzz/README.md`](../fuzz/README.md).
