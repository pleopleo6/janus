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

## Building and testing

```sh
cargo test --workspace --release   # release: ML-DSA is slow in debug builds
cargo clippy --workspace --all-targets -- -D warnings
```

## License

MIT — see [LICENSE](LICENSE).
