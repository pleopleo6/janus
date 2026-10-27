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
| Key exchange      | X25519    | ML-KEM-768   | HKDF over `ss_mlkem ‖ ss_x25519` + transcript    |
| Authentication    | Ed25519   | ML-DSA-65    | **both** signatures must verify, else abort      |
| Record protection | —         | —            | ChaCha20-Poly1305 (256-bit key, PQ-safe enough)  |

## Post-quantum tunnel

`janus tunnel` + `janus serve --forward` protect **any existing TCP
service** (a database, SSH, an internal HTTP API) without modifying it, like
`stunnel` or `spiped` but with a hybrid post-quantum handshake:

```sh
# on the server, in front of a service listening on 127.0.0.1:5432
janus serve --listen 0.0.0.0:7878 --forward 127.0.0.1:5432 --id server.id --trust "$CLIENT_FP"
# on the client
janus tunnel --listen 127.0.0.1:15432 --to server.example:7878 --id client.id --trust "$SERVER_FP"
psql -h 127.0.0.1 -p 15432 …   # unmodified client, traffic is now protected
```

## As a library

`janus-tokio` turns any tokio transport into an authenticated, encrypted
`AsyncRead + AsyncWrite` stream:

```rust
let tcp = tokio::net::TcpStream::connect("server.example:7878").await?;
let mut stream = janus_tokio::connect(tcp, &config, janus_tokio::Options::default()).await?;
stream.write_all(b"hello").await?;   // sealed into ChaCha20-Poly1305 records
stream.shutdown().await?;            // authenticated close_notify
```

`connect` returns only after the server accepted the client; reads end with
`UnexpectedEof` if the peer's stream is cut without an authenticated close.

## Handshake lab (browser)

`web/` is a single-page lab that runs the real `janus-core` and
`janus-channel` code, compiled to WebAssembly. It shows the three handshake
messages byte by byte (post-quantum, classical and protocol fields), lets you
flip any byte in flight and see which check rejects it, replays canned attacks
(impostor peers, version downgrade, the ignored X25519 top bit, a forged
ML-DSA half, …) and drives the encrypted channel through replay, reordering,
bit flips, truncation and rekeys.

```sh
./web/build.sh                       # rebuild web/pkg (prebuilt copy committed)
python3 -m http.server -d web 8000   # then open http://localhost:8000
```

Scenarios have direct links, e.g. `#x25519`, `#mldsa`, `#rogue-server`.

## Documentation

- [`docs/PROTOCOL.md`](docs/PROTOCOL.md): byte-exact specification for
  interoperable implementations, with
  [test vectors](docs/test-vectors/janus-v1.json) (every random input, all
  intermediate secrets) and an independent
  [Python verifier](docs/test-vectors/verify.py) of the key schedule.
- [`docs/DESIGN.md`](docs/DESIGN.md): protocol, key schedule, threat model,
  **what is not guaranteed**, comparison with X-Wing / PQXDH / TLS 1.3 hybrid,
  measurements.
- [`fuzz/README.md`](fuzz/README.md): fuzz targets and results.

At a glance: a handshake is **13.2 kB** (vs 0.4 kB for the same protocol with
classical primitives only) and costs **≈ 1.2 ms** of CPU for both sides
together; see the design notes for details.

## Workspace layout

| Crate                                        | Role                                                         |
|----------------------------------------------|--------------------------------------------------------------|
| [`janus-core`](crates/janus-core)            | primitive wrappers, key schedule, sans-IO handshake machine  |
| [`janus-channel`](crates/janus-channel)      | record encryption / decryption, framing, rekey, anti-replay  |
| [`janus-tokio`](crates/janus-tokio)          | async `JanusStream` (`AsyncRead`/`AsyncWrite`), `connect` / `accept` |
| [`janus-cli`](crates/janus-cli)              | `janus` CLI: keygen, chat, echo, TCP tunnel                  |
| [`janus-bench`](crates/janus-bench)          | criterion benchmarks and message-size report                 |
| [`janus-wasm`](crates/janus-wasm)            | WebAssembly bindings for the browser lab (`web/`)            |
| [`fuzz`](fuzz)                               | `cargo-fuzz` targets (parsers, server, record layer)         |

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

The client reports the session only after the server's acceptance receipt
(an empty encrypted record under the server→client key), so a client the
server refuses gets a clear error instead of a session that silently dies.

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
