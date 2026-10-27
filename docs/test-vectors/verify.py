#!/usr/bin/env python3
"""Independent check of the Janus v1 test vectors, Python standard library only.

Starting from the two shared secrets recorded in the vectors (X25519 and
ML-KEM are not in the standard library), this script re-implements the
symmetric half of docs/PROTOCOL.md: transcript hashes, HKDF-SHA-384 key
schedule, Finished MACs, session id, fingerprints and the per-epoch traffic
keys. It then checks every value against the vectors and against the
Finished MACs embedded in the actual handshake messages.

    python3 docs/test-vectors/verify.py
"""
import hashlib
import hmac
import json
import pathlib
import struct
import sys

V = json.loads((pathlib.Path(__file__).parent / "janus-v1.json").read_text())
h = bytes.fromhex
failures = 0


def check(name, got, want):
    global failures
    ok = got == want
    failures += not ok
    print(f"{'ok  ' if ok else 'FAIL'} {name}")


def th(*parts):  # §6: TH(x) = H("janus/v1 transcript" || x)
    return hashlib.sha384(b"janus/v1 transcript" + b"".join(parts)).digest()


def extract(salt, ikm):  # RFC 5869
    return hmac.new(salt, ikm, hashlib.sha384).digest()


def expand(prk, info, n):  # RFC 5869
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha384).digest()
        out, i = out + t, i + 1
    return out[:n]


def expand_label(secret, label, ctx, n):  # §2.1
    label = b"janus/v1 " + label.encode()
    info = struct.pack(">H", n) + bytes([len(label)]) + label + bytes([len(ctx)]) + ctx
    return expand(secret, info, n)


ch, sh, cf = (h(V["messages"][k]) for k in ("client_hello", "server_hello", "client_finish"))
iv_ = V["intermediate"]

check("message lengths (§5)", (len(ch), len(sh), len(cf)), (1250, 6559, 5407))
check("headers (§5)", (ch[:2], sh[:2], cf[:2]), (b"\x01\x01", b"\x01\x02", b"\x01\x03"))
for side in ("client", "server"):
    pub = h(V[side]["identity_public"])
    fp = hashlib.sha384(b"janus/v1 fingerprint" + pub).hexdigest()
    check(f"{side} fingerprint (§3)", fp, V[side]["fingerprint"])
check("identities on the wire (§5)", (sh[1154:3138], cf[2:1986]),
      (h(V["server"]["identity_public"]), h(V["client"]["identity_public"])))

th_kex = th(ch, sh[:1154])
check("TH(kex) (§6.2)", th_kex.hex(), iv_["th_kex"])
prk = extract(th_kex, h(iv_["ss_mlkem"]) + h(iv_["ss_x25519"]))
check("prk = Extract(TH(kex), ss_mlkem || ss_x25519) (§6.2)", prk.hex(), iv_["prk"])
fk_s = expand_label(prk, "s finished", b"", 48)
fk_c = expand_label(prk, "c finished", b"", 48)
check("server Finished MAC in ServerHello (§6.2)",
      hmac.new(fk_s, th(ch, sh[:6511]), hashlib.sha384).digest(), sh[6511:])
check("client Finished MAC in ClientFinish (§6.3)",
      hmac.new(fk_c, th(ch, sh, cf[:5359]), hashlib.sha384).digest(), cf[5359:])
th_final = th(ch, sh, cf)
check("TH(final) (§6.5)", th_final.hex(), iv_["th_final"])
check("session id (§6.5)", expand_label(prk, "exporter", th_final, 48).hex(), V["session_id"])

for direction, label in (("c2s", "c2s traffic"), ("s2c", "s2c traffic")):
    secret = expand_label(prk, label, th_final, 48)
    for e in iv_["traffic"][direction]:
        got = (secret.hex(), expand_label(secret, "key", b"", 32).hex(),
               expand_label(secret, "iv", b"", 12).hex())
        check(f"{direction} epoch {e['epoch']} secret/key/iv (§7.2)", got, (e["secret"], e["key"], e["iv"]))
        secret = expand_label(secret, "rekey", b"", 48)

for r in V["records"]:
    w = h(r["wire"])
    want_type = 0x15 if r["type"] == "close" else 0x17
    hdr_ok = w[0] == want_type and struct.unpack(">H", w[1:3])[0] == len(w) - 3
    seq_ok = struct.unpack(">Q", w[3:11])[0] == r["seq"]
    check(f"record {r['direction']} seq {r['seq']} framing (§7.1, §7.3)", (hdr_ok, seq_ok), (True, True))

print(f"\n{'all checks passed' if failures == 0 else f'{failures} check(s) failed'}")
sys.exit(1 if failures else 0)
