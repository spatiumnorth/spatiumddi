"""Open a secret the control plane sealed to this supervisor process (#3631).

The heartbeat response can cross a plain-HTTP hop (a control-plane member
calls the in-cluster api Service over HTTP; the frontend forwards to the api
over HTTP), so the k3s join token for a node being promoted is not sent in
clear. The supervisor puts the public half of an X25519 key in its signed
heartbeat body (``join_token_public_key``); the control plane returns the
token sealed to it (``desired_k3s_join_token_sealed``).

The key pair lives in this process's memory only: generated on first use,
never written to disk, so a token sealed to it cannot be opened later from
anything an attacker could copy off the node.

Must agree byte for byte with the backend's
``app.services.appliance.sealed_token``: ephemeral X25519, HKDF-SHA256 with
``_INFO + ephemeral_public + recipient_public``, ChaCha20-Poly1305 with the
appliance id as associated data, wire form
``base64(ephemeral_public(32) || nonce(12) || ciphertext)``.
"""

from __future__ import annotations

import base64
import binascii
import threading
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_INFO = b"spatiumddi sealed token v1"

_lock = threading.Lock()
_private_key: X25519PrivateKey | None = None


def _key() -> X25519PrivateKey:
    global _private_key
    with _lock:
        if _private_key is None:
            _private_key = X25519PrivateKey.generate()
        return _private_key


def _public_raw() -> bytes:
    return _key().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def public_key_b64() -> str:
    """The public key to send in the heartbeat body."""
    return base64.b64encode(_public_raw()).decode("ascii")


def open_sealed(sealed_b64: str, appliance_id: uuid.UUID | str) -> str | None:
    """Return the plaintext, or ``None`` when it does not open (sealed to
    another key, tampered with, or malformed)."""
    try:
        raw = base64.b64decode(sealed_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < 32 + 12 + 16:
        return None
    ephemeral_pub, nonce, ciphertext = raw[:32], raw[32:44], raw[44:]
    try:
        shared = _key().exchange(X25519PublicKey.from_public_bytes(ephemeral_pub))
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=_INFO + ephemeral_pub + _public_raw(),
        ).derive(shared)
        plaintext = ChaCha20Poly1305(key).decrypt(
            nonce, ciphertext, str(appliance_id).encode("ascii")
        )
    except (InvalidTag, ValueError):
        return None
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError:
        return None


__all__ = ["open_sealed", "public_key_b64"]
