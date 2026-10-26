# Janus

A hybrid post-quantum secure channel in Rust: mutually-authenticated key
exchange combining **X25519 + ML-KEM-768** for confidentiality and
**Ed25519 + ML-DSA-65** for authentication, followed by a
ChaCha20-Poly1305 record layer.

> [!WARNING]
> **Janus is an educational / portfolio project. It is NOT production-ready.**
> It has not been audited, its protocol has not been formally analysed, and the
> post-quantum crates it relies on are young. Do not use it to protect real
> data. See [`docs/DESIGN.md`](docs/DESIGN.md) for what is and is *not*
> guaranteed.

## Why "hybrid"?

Each half of the protocol uses one classical and one post-quantum primitive,
so that an attacker has to break **both** to win:

| Goal              | Classical | Post-quantum | Combination                                      |
|-------------------|-----------|--------------|--------------------------------------------------|
| Key exchange      | X25519    | ML-KEM-768   | HKDF over `ss_x25519 ‖ ss_mlkem` + transcript    |
| Authentication    | Ed25519   | ML-DSA-65    | **both** signatures must verify, else abort      |
| Record protection | —         | —            | ChaCha20-Poly1305 (256-bit key, PQ-safe enough)  |

## Workspace layout

| Crate                                        | Role                                                         |
|----------------------------------------------|--------------------------------------------------------------|
| [`janus-core`](crates/janus-core)            | primitive wrappers, key schedule, sans-IO handshake machine  |
| [`janus-channel`](crates/janus-channel)      | record encryption / decryption, framing, rekey, anti-replay  |
| [`janus-cli`](crates/janus-cli)              | TCP demo client / server (tokio)                             |
| [`janus-bench`](crates/janus-bench)          | criterion benchmarks                                         |
| [`fuzz`](fuzz)                               | `cargo-fuzz` targets for the message parsers                 |

No cryptographic primitive is implemented here: everything comes from
RustCrypto (`ml-kem`, `ml-dsa`, `hkdf`, `hmac`, `sha2`, `chacha20poly1305`)
and dalek (`x25519-dalek`, `ed25519-dalek`). The project code is
`#![forbid(unsafe_code)]`.

## Demo

```sh
cargo build --release
J=target/release/janus

SERVER_FP=$($J keygen --out server.id)     # prints the fingerprint
CLIENT_FP=$($J keygen --out client.id)

$J serve --echo --id server.id --trust "$CLIENT_FP" &
$J connect 127.0.0.1:7878 --id client.id --trust "$SERVER_FP"
```

```text
[janus] handshake ok in 1.1 ms (6663 B sent, 6562 B received)
[janus] peer: c7326eb8d58d6b6bacb0441f0b5276f9e78f8ce860e615dd2cbcb2dfa4a5d1e3…
[janus] session id: 31b6 3e8c 1c71 b177 8fbd 2d1e dd17 942d
[janus] type messages, Ctrl-D to close
hello post-quantum world
< hello post-quantum world
```

Both sides print the same *session id*: comparing it out of band (like a
Signal safety number) confirms there is no man in the middle. Peers are
authenticated by pinned fingerprints only (no PKI). Identity files are
**unencrypted** on disk (mode 0600).

Without `--echo`, the server chats over stdin/stdout with one client at a
time.

## Building and testing

```sh
cargo test --workspace --release   # release: ML-DSA is slow in debug builds
cargo clippy --workspace --all-targets -- -D warnings
```

Fuzzing: see [`fuzz/README.md`](fuzz/README.md).

## License

MIT — see [LICENSE](LICENSE).
