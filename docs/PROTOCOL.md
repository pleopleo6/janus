# Janus v1 — protocol specification

This document specifies Janus v1 precisely enough to write an
interoperable implementation. [`DESIGN.md`](DESIGN.md) explains *why* things
are the way they are; this document only says *what* they are. Conformance
is checked with the test vectors in
[`test-vectors/janus-v1.json`](test-vectors/janus-v1.json) (§9).

> Janus is an educational project. This specification has not been reviewed
> and must not be used to protect real data.

The key words MUST, MUST NOT and SHOULD are used as in RFC 2119.

## 1. Notation

- `‖` is byte-string concatenation; `""` is the empty string.
- `u8(x)`, `u16(x)`, `u64(x)` are big-endian unsigned encodings of 1, 2, 8 bytes.
- `"text"` denotes the ASCII bytes of `text`, without terminator.
- `x[a..b]` is the slice of bytes `a` (inclusive) to `b` (exclusive).
- Lengths are in bytes.

## 2. Primitives

| Name | Definition |
|---|---|
| `H(x)` | SHA-384 (FIPS 180-4), 48-byte output |
| `HMAC(k, x)` | HMAC-SHA-384 (RFC 2104), 48-byte output |
| `Extract(salt, ikm)` | HKDF-Extract with SHA-384 (RFC 5869) |
| `Expand(prk, info, L)` | HKDF-Expand with SHA-384 (RFC 5869) |
| `X25519(k, u)` | RFC 7748 |
| ML-KEM-768 | FIPS 203: `KeyGen_internal(d, z)`, `Encaps_internal(ek, m)`, `Decaps` |
| Ed25519 | RFC 8032, pure Ed25519 |
| ML-DSA-65 | FIPS 204, pure `ML-DSA.Sign` / `ML-DSA.Verify` with context string |
| AEAD | ChaCha20-Poly1305 (RFC 8439), 32-byte key, 12-byte nonce, 16-byte tag |

### 2.1 Expand-Label

```text
Expand-Label(secret, label, context, L) =
    Expand(secret, u16(L) ‖ u8(9 + len(label)) ‖ "janus/v1 " ‖ label ‖ u8(len(context)) ‖ context, L)
```

`secret` is used directly as the HKDF PRK. `len(label) ≤ 246` and
`len(context) ≤ 255` always hold for the labels below.

### 2.2 Labels

| Constant | Bytes |
|---|---|
| transcript prefix | `"janus/v1 transcript"` |
| signature prefix | `"janus/v1 hybrid-sig"` |
| fingerprint prefix | `"janus/v1 fingerprint"` |
| record AAD prefix | `"janus/v1 record"` |
| server signature role | `"janus/v1 server signature"` |
| client signature role | `"janus/v1 client signature"` |
| Expand-Label labels | `"s finished"`, `"c finished"`, `"c2s traffic"`, `"s2c traffic"`, `"exporter"`, `"key"`, `"iv"`, `"rekey"` |

## 3. Identities

An identity secret is a 64-byte seed `ed_seed[32] ‖ xi[32]`.

- The Ed25519 key pair is derived from `ed_seed` as in RFC 8032 §5.1.5.
- The ML-DSA-65 key pair is `ML-DSA.KeyGen_internal(xi)` (FIPS 204, Algorithm 6).

The public identity is `id = ed_pk[32] ‖ mldsa_pk[1952]` (1984 bytes),
`mldsa_pk` being `pkEncode` (FIPS 204, Algorithm 22).

**Validation.** A receiver MUST reject `id` unless:

1. `ed_pk` decodes to a curve point (RFC 8032 §5.1.3);
2. that point is not of small order;
3. re-encoding both halves gives back exactly the received 1984 bytes.

**Fingerprint.** `fp(id) = H("janus/v1 fingerprint" ‖ id)`, 48 bytes, shown
as lowercase hex. Peers are authorised by comparing fingerprints with a local
set of pinned values, in constant time.

## 4. Hybrid signatures

To sign message `msg` in role `label`, a party with identity `id` computes

```text
M'  = "janus/v1 hybrid-sig" ‖ u8(len(label)) ‖ label ‖ id ‖ msg
sig = Ed25519.Sign(ed_sk, M') ‖ ML-DSA-65.Sign(mldsa_sk, M', ctx = label)        (64 + 3309 bytes)
```

ML-DSA signing SHOULD be hedged (32 bytes of fresh randomness, FIPS 204 §3.4).

Verification computes the same `M'` and MUST accept only if **both**:

- Ed25519 verification of the first 64 bytes succeeds with the strict rules
  (canonical `S`, `R` not of small order, as `verify_strict` in
  `ed25519-dalek`), and
- `ML-DSA.Verify(mldsa_pk, M', sig[64..3373], ctx = label)` succeeds
  (a signature that fails `sigDecode` is invalid).

Implementations SHOULD evaluate both checks before combining the results.

## 5. Handshake messages

Every message starts with `version = 0x01` and a type byte. All lengths are
fixed. A receiver MUST check, in this order: version (else abort with
*unsupported version*), type (else *unexpected message*), exact total length
(else *malformed*), then each field.

### 5.1 ClientHello (type 0x01), 1250 bytes

| Offset | Length | Field |
|---:|---:|---|
| 0 | 1 | version = `0x01` |
| 1 | 1 | type = `0x01` |
| 2 | 32 | `client_random` |
| 34 | 1184 | `ek`: ML-KEM-768 encapsulation key |
| 1218 | 32 | `X_c`: client X25519 public key |

The server MUST apply the FIPS 203 §7.2 modulus check to `ek`.

### 5.2 ServerHello (type 0x02), 6559 bytes

| Offset | Length | Field |
|---:|---:|---|
| 0 | 2 | `0x01 0x02` |
| 2 | 32 | `server_random` |
| 34 | 1088 | `ct`: ML-KEM-768 ciphertext |
| 1122 | 32 | `X_s`: server X25519 public key |
| 1154 | 1984 | `id_s`: server identity |
| 3138 | 3373 | `sig_s`: hybrid signature |
| 6511 | 48 | `fin_s`: server Finished MAC |

### 5.3 ClientFinish (type 0x03), 5407 bytes

| Offset | Length | Field |
|---:|---:|---|
| 0 | 2 | `0x01 0x03` |
| 2 | 1984 | `id_c`: client identity |
| 1986 | 3373 | `sig_c`: hybrid signature |
| 5359 | 48 | `fin_c`: client Finished MAC |

## 6. Handshake procedure

Let `CH`, `SH`, `CF` be the three messages exactly as sent on the wire, and

```text
TH(x) = H("janus/v1 transcript" ‖ x)
```

### 6.1 Client: first flight

1. Draw `sk_c` (32 bytes) and set `X_c = X25519(sk_c, 9)`.
2. Draw `d ‖ z` (64 bytes) and set `(ek, dk) = ML-KEM-768.KeyGen_internal(d, z)`.
3. Draw `client_random` (32 bytes). Send `CH`.

### 6.2 Server

1. Parse and validate `CH` (§5.1).
2. Draw `sk_s` (32 bytes); `X_s = X25519(sk_s, 9)`; `ss_x = X25519(sk_s, X_c)`.
   Abort if `ss_x` is all zeros.
3. Draw `m` (32 bytes); `(ss_k, ct) = ML-KEM-768.Encaps_internal(ek, m)`.
4. Draw `server_random` (32 bytes).
5. `TH_kex = TH(CH ‖ SH[0..1154])`.
6. `prk = Extract(salt = TH_kex, ikm = ss_k ‖ ss_x)`.
7. `sig_s = Sign(server, "janus/v1 server signature", TH(CH ‖ SH[0..3138]))`.
8. `fk_s = Expand-Label(prk, "s finished", "", 48)`;
   `fin_s = HMAC(fk_s, TH(CH ‖ SH[0..6511]))`. Send `SH`.

### 6.3 Client: second flight

1. Parse and validate `SH` (§5.2).
2. `ss_x = X25519(sk_c, X_s)`, abort if all zeros; `ss_k = ML-KEM-768.Decaps(dk, ct)`.
3. Compute `TH_kex` and `prk` as in §6.2.
4. Abort unless `fp(id_s)` is pinned.
5. Verify `sig_s` (§4) with role `"janus/v1 server signature"` over
   `TH(CH ‖ SH[0..3138])`; abort on failure.
6. Verify `fin_s == HMAC(fk_s, TH(CH ‖ SH[0..6511]))` in constant time; abort on failure.
7. Build `CF`: `sig_c = Sign(client, "janus/v1 client signature", TH(CH ‖ SH ‖ CF[0..1986]))`,
   `fk_c = Expand-Label(prk, "c finished", "", 48)`,
   `fin_c = HMAC(fk_c, TH(CH ‖ SH ‖ CF[0..5359]))`. Send `CF`.

### 6.4 Server: completion

1. Parse and validate `CF` (§5.3).
2. Abort unless `fp(id_c)` is pinned.
3. Verify `sig_c` and `fin_c` as in §6.3, steps 5–6, with the client role.

### 6.5 Session secrets (both sides)

```text
TH_final   = TH(CH ‖ SH ‖ CF)
c2s_0      = Expand-Label(prk, "c2s traffic", TH_final, 48)
s2c_0      = Expand-Label(prk, "s2c traffic", TH_final, 48)
session_id = Expand-Label(prk, "exporter",    TH_final, 48)
```

The client sends with `c2s` and receives with `s2c`; the server the reverse.
`session_id` is public and equal on both sides. All ephemeral secrets
(`sk_c`, `sk_s`, `dk`, `ss_x`, `ss_k`, `prk`, finished keys) MUST be erased
once the session secrets are derived.

### 6.6 Errors

Any failure aborts the handshake: the implementation closes the transport
without sending anything. There are no alert messages.

## 7. Record layer

### 7.1 Framing

Everything on the byte stream is a frame:

```text
frame = type:u8 ‖ len:u16 ‖ body[len]
```

| Type | Name | Admissible `len` |
|---|---|---|
| `0x16` | Handshake: body is one message of §5 | 1 – 6559 |
| `0x17` | Data | 24 – 16408 |
| `0x15` | Close | exactly 24 |

A receiver MUST abort on an unknown type or an inadmissible length, before
buffering the body.

### 7.2 Keys and epochs

Each direction keeps a sequence number `seq`, starting at 0 and incremented
per record, and a rekey interval `N` (configuration, equal on both sides;
default 65536). Record `seq` belongs to epoch `e = ⌊seq / N⌋`:

```text
secret_0     = c2s_0 or s2c_0
secret_{e+1} = Expand-Label(secret_e, "rekey", "", 48)
key_e        = Expand-Label(secret_e, "key",   "", 32)
iv_e         = Expand-Label(secret_e, "iv",    "", 12)
```

A sender MUST NOT use `seq = 2^64 − 1` (it never wraps). Secrets of past
epochs MUST be erased.

### 7.3 Record protection

```text
header = type ‖ u16(8 + len(pt) + 16)
nonce  = iv_e XOR (0x00000000 ‖ u64(seq))
aad    = "janus/v1 record" ‖ header ‖ u64(seq)
frame  = header ‖ u64(seq) ‖ ChaCha20-Poly1305.Seal(key_e, nonce, pt, aad)
```

`pt` is at most 16384 bytes; a Close record has an empty `pt`.

### 7.4 Record reception

The receiver keeps `expected` (initially 0). For each Data or Close frame:

1. `seq < expected` → abort (*replay*); `seq > expected` → abort (*out of order*).
2. Derive the epoch keys for `seq`, decrypt with the same `nonce` and `aad`;
   abort on authentication failure.
3. `expected = seq + 1`. A Close record ends the direction; any later record
   MUST be rejected.

Any abort is permanent for that direction. If the transport ends before a
Close record was received, the receiver MUST report a truncation error
rather than a clean end of stream.

### 7.5 Acceptance receipt (application convention)

The handshake does not tell the client whether the server accepted it. The
reference implementation (`janus-tokio`, CLI) adds a convention: right after
the handshake, the server sends one Data record with an empty `pt`, and the
client reports the session as established only once it has decrypted it.
Empty Data records carry no application data and MUST NOT be interpreted as
end of stream.

## 8. Randomness consumption

For reproducibility of the test vectors, the reference implementation draws
randomness in exactly these calls:

| Party | Order | Length | Use |
|---|---:|---:|---|
| client | 1 | 32 | X25519 secret key `sk_c` |
| client | 2 | 64 | ML-KEM seed `d ‖ z` |
| client | 3 | 32 | `client_random` |
| client | 4 | 32 | ML-DSA hedged signing randomness |
| server | 1 | 32 | X25519 secret key `sk_s` |
| server | 2 | 32 | ML-KEM encapsulation message `m` |
| server | 3 | 32 | `server_random` |
| server | 4 | 32 | ML-DSA hedged signing randomness |

## 9. Test vectors

[`test-vectors/janus-v1.json`](test-vectors/janus-v1.json) contains both
identity seeds, every random string consumed (in the order of §8), the three
handshake messages, the session id, and five records (three client→server
records crossing a rekey with `N = 2`, one server→client record, one
Close). An implementation conforms if, given the same seeds and randomness,
it produces the same bytes for every field, and accepts the records.

The reference implementation checks this on every test run
(`crates/janus-channel/tests/vectors.rs`); regenerate with
`cargo run -p janus-channel --example gen_test_vectors` after an intentional
change.
