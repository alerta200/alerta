"""nxpack.py — a tiny, stdlib-only sealed container for distributing the tuned defender weights.

WHY THIS EXISTS. Nexus's moat is the trained local defender model. The licence module states the
gate plainly: "the tuned weights are only distributed to licensees." This module is the mechanism —
the vendor SEALS the adapter with a random content key, ships the (useless-without-the-key)
ciphertext, and puts the key inside the buyer's *signed licence token*. The token is emailed only to
the paying customer, so only a licensee ever holds the key that opens the pack.

HONEST SCOPE (same ethos as license.py). This is a distribution gate, not anti-piracy DRM. The
source is open and the key travels with the licence, so a licensee who leaks their token also leaks
the key — that boundary is legal (BUSL) + honour, exactly like the licence itself. What the seal
buys over shipping raw weights: possessing the ciphertext alone is not enough, and tampering is
detected. That is the honest, proportionate goal.

CRYPTO. Stdlib only (the whole product ships zero-dependency and runs air-gapped — pulling a crypto
library would break that promise). The construction is a textbook encrypt-then-MAC, composing the
standard HMAC-SHA256 PRF — no home-grown primitive:
  * derive two independent subkeys from the content key:  ke = HMAC(key,"nxpack-enc"),
    km = HMAC(key,"nxpack-mac");
  * CTR keystream:  block_i = HMAC-SHA256(ke, nonce || big-endian-uint64(i)),  ciphertext = pt XOR ks;
  * tag = HMAC-SHA256(km, header || nonce || ciphertext), verified in constant time before decrypt.
A fresh 16-byte nonce per seal keeps the keystream unique. Integrity is checked before any plaintext
is returned (encrypt-then-MAC).

FORMAT:  b"NXP1" | nonce[16] | ciphertext | tag[32]      (tag covers magic+nonce+ciphertext)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct

MAGIC = b"NXP1"
_NONCE = 16
_TAG = 32


def new_key() -> bytes:
    """A fresh 32-byte content key. Base64-encode it (key_b64) to carry in a licence token."""
    return os.urandom(32)


def key_to_b64(key: bytes) -> str:
    return base64.urlsafe_b64encode(key).decode().rstrip("=")


def key_from_b64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _keystream(ke: bytes, nonce: bytes, n: int) -> bytes:
    """HMAC-SHA256 CTR keystream of at least n bytes."""
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hmac.new(ke, nonce + struct.pack(">Q", counter), hashlib.sha256).digest()
        counter += 1
    return bytes(out[:n])


def _subkeys(key: bytes) -> tuple[bytes, bytes]:
    ke = hmac.new(key, b"nxpack-enc", hashlib.sha256).digest()
    km = hmac.new(key, b"nxpack-mac", hashlib.sha256).digest()
    return ke, km


def seal(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt-then-MAC `plaintext` under `key`. Returns the self-describing sealed blob."""
    ke, km = _subkeys(key)
    nonce = os.urandom(_NONCE)
    ct = bytes(a ^ b for a, b in zip(plaintext, _keystream(ke, nonce, len(plaintext))))
    tag = hmac.new(km, MAGIC + nonce + ct, hashlib.sha256).digest()
    return MAGIC + nonce + ct + tag


def open_(blob: bytes, key: bytes) -> bytes:
    """Verify the tag (constant-time) then decrypt. Raises ValueError on a bad key/format/tamper."""
    if len(blob) < len(MAGIC) + _NONCE + _TAG or blob[:len(MAGIC)] != MAGIC:
        raise ValueError("not an nxpack container (bad magic or truncated)")
    body = blob[len(MAGIC):]
    nonce, ct, tag = body[:_NONCE], body[_NONCE:-_TAG], body[-_TAG:]
    ke, km = _subkeys(key)
    expect = hmac.new(km, MAGIC + nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(expect, tag):
        raise ValueError("nxpack integrity check failed — wrong key or corrupted/tampered pack")
    return bytes(a ^ b for a, b in zip(ct, _keystream(ke, nonce, len(ct))))
