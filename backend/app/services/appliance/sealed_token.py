"""Seal a secret to one supervisor for the heartbeat response (#3631).

The heartbeat response can cross a plain-HTTP hop: a control-plane member's
supervisor calls the in-cluster api Service over HTTP, and the frontend
forwards a remote supervisor's request to the api over HTTP. The k3s join
token handed to a node being promoted must not travel there in clear.

So the supervisor sends a fresh X25519 public key in its heartbeat body
(``join_token_public_key``; generated per supervisor process, never stored)
and the api returns the token sealed to it: an ephemeral X25519 key
exchange, HKDF-SHA256, then ChaCha20-Poly1305 with the appliance id as
associated data. Only the process that sent the key can open it.

The key is trusted only because the request's signature covered the body
(signature version 2): a key in a body the signature does not cover could be
anyone's, so the caller seals only for a body-bound principal.

Wire form: ``base64(ephemeral_public(32) || nonce(12) || ciphertext)``.
The supervisor's ``spatium_supervisor.sealed_token`` opens it; the two must
agree byte for byte (``_INFO`` included).
"""

from __future__ import annotations

import base64
import binascii
import os
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_INFO = b"spatiumddi sealed token v1"


class SealError(ValueError):
    """The recipient key is not a usable X25519 public key."""


def _derive_key(shared: bytes, ephemeral_pub: bytes, recipient_pub: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_INFO + ephemeral_pub + recipient_pub,
    ).derive(shared)


def seal(plaintext: str, recipient_public_key_b64: str, appliance_id: uuid.UUID) -> str:
    """Seal ``plaintext`` to the supervisor key ``recipient_public_key_b64``
    (base64 of the raw 32-byte X25519 public key)."""
    try:
        recipient_raw = base64.b64decode(recipient_public_key_b64, validate=True)
        recipient = X25519PublicKey.from_public_bytes(recipient_raw)
    except (binascii.Error, ValueError) as exc:
        raise SealError(f"recipient key: {exc}") from exc
    ephemeral = X25519PrivateKey.generate()
    ephemeral_pub = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    try:
        shared = ephemeral.exchange(recipient)
    except ValueError as exc:  # OpenSSL refuses a low-order point itself
        raise SealError(f"recipient key: {exc}") from exc
    if shared == bytes(32):
        # A low-order point gives an all-zero secret: refuse rather than
        # encrypt under a key anyone can compute.
        raise SealError("recipient key is a low-order point")
    key = _derive_key(shared, ephemeral_pub, recipient_raw)
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(
        nonce, plaintext.encode("utf-8"), str(appliance_id).encode("ascii")
    )
    return base64.b64encode(ephemeral_pub + nonce + ciphertext).decode("ascii")


__all__ = ["SealError", "seal"]
