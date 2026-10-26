#!/usr/bin/env sh
# Rebuild the browser lab's WebAssembly module into web/pkg/.
# Requires: rustup target add wasm32-unknown-unknown
#           cargo install --locked wasm-bindgen-cli --version 0.2.129
set -eu
cd "$(dirname "$0")/.."
cargo build --release --target wasm32-unknown-unknown -p janus-wasm
wasm-bindgen --target web --no-typescript --out-dir web/pkg \
  target/wasm32-unknown-unknown/release/janus_wasm.wasm
echo "Built web/pkg. Serve with: python3 -m http.server -d web 8000"
