#!/usr/bin/env sh
# Prove every lemma of the Janus Tamarin model.
# Install: brew install tamarin-prover/tap/tamarin-prover  (brings Maude)
set -eu
cd "$(dirname "$0")"
tamarin-prover --prove janus.spthy "$@" 2>&1 | tee proof.log
grep -E "^\s+[a-z_]+ \((all-traces|exists-trace)\): (verified|falsified|analysis incomplete)" proof.log
