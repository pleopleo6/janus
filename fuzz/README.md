# Fuzzing

Requires a nightly toolchain and [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz):

```sh
rustup toolchain install nightly
cargo install --locked cargo-fuzz
cargo run -p janus-core --example gen_fuzz_seeds        # refresh fuzz/seeds/
cargo +nightly fuzz run -O server_hello fuzz/corpus/server_hello fuzz/seeds/server_hello -- -max_len=8192
```

| Target          | What it checks                                                                 |
|-----------------|--------------------------------------------------------------------------------|
| `client_hello`  | strict parser never panics; accepted inputs are canonical (`encode(decode(x)) == x`) |
| `server_hello`  | same                                                                           |
| `client_finish` | same                                                                           |
| `server_accept` | a server fed arbitrary bytes fails cleanly, or replies with a valid `ServerHello` |
| `records`       | deframer + live receiver: no panic, and no forged record is ever accepted      |

`fuzz/seeds/` holds honest messages (from a real handshake between the fixed
test identities) so that the fuzzer starts past the length checks. The
working corpora (`fuzz/corpus/`) and crash artifacts are git-ignored.

## Results so far

Local smoke campaign (Apple Silicon, 2 minutes per target, all in parallel,
seeded with `fuzz/seeds/`): **no crash, no assertion failure**.

| Target          | Executions | Coverage (edges) |
|-----------------|-----------:|-----------------:|
| `client_hello`  | 29.7 M     | 118   |
| `server_hello`  | 1.74 M     | 391   |
| `client_finish` | 1.72 M     | 385   |
| `server_accept` | 466 k      | 2022  |
| `records`       | 22.7 k     | 3476  |

`records` is slow by construction: a receiver is permanently failed by its
first error, so every input needs a fresh session (one full handshake). Two
minutes is a smoke test, not a campaign; longer runs are welcome.
