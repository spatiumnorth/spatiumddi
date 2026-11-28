"""Passphrase-wrapped envelope for the ``secrets.enc`` payload of a
backup archive (issue #117 Phase 1a).

The shape we emit + accept is a single JSON document:

.. code-block:: json

    {
      "v": 1,
      "kdf": "pbkdf2-hmac-sha256",
      "iterations": 600000,
      "salt": "<32 hex chars>",
      "nonce": "<24 hex chars>",
      "ciphertext": "<hex>",
      "hint": "<operator-supplied label or empty>"
    }

* **PBKDF2-HMAC-SHA256** at 600 000 iterations (OWASP 2023 floor)
  derives a 32-byte AES-256 key from the operator's passphrase + a
  fresh per-backup 16-byte salt.
* **AES-256-GCM** encrypts the secret payload (a JSON dict carrying
  the source install's ``SECRET_KEY`` and any other operator-supplied
  metadata). The 12-byte nonce is random per backup; GCM's auth tag
  (16 bytes) is appended to the ciphertext by the cryptography
  library.
* The serialised envelope is human-inspectable — operators can
  ``unzip backup.zip secrets.enc | jq .`` to confirm they have the
  right archive without supplying the passphrase.

Restoring decrypts in the obvious order: derive the key from
passphrase + salt, run AES-GCM decrypt over the ciphertext+tag,
parse the resulting JSON. A wrong passphrase yields
``BackupCryptoError`` (raised from cryptography's
``InvalidTag``) rather than producing garbage plaintext.
"""

from __future__ import annotations

import json
import os
import zlib
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# OWASP 2023 floor for PBKDF2-HMAC-SHA256. 600 k iterations on a
# typical workstation costs ~0.3 s — annoying enough to bracket
# brute-force, fast enough that operators don't notice it on the
# legitimate path.
_PBKDF2_ITERATIONS = 600_000
_SALT_BYTES = 16
_NONCE_BYTES = 12
_KEY_BYTES = 32  # AES-256
_ENVELOPE_VERSION = 1

# The band of envelope-declared iteration counts ``decrypt_secrets``
# will honour (#1568). The count comes from the archive, which is
# untrusted until the passphrase check passes: a crafted envelope
# could declare 10**12 iterations and pin the api CPU deriving a key
# for an archive restore will refuse anyway, and a count far under
# the OWASP floor is not an envelope this build wrote. Envelopes
# outside the band are refused before any derivation happens.
_MIN_PBKDF2_ITERATIONS = 100_000
_MAX_PBKDF2_ITERATIONS = 10_000_000


class BackupCryptoError(Exception):
    """Raised when a backup envelope can't be decrypted or parsed.

    Distinct from ``BackupArchiveError`` so the API layer can tell
    "you typed the wrong passphrase" apart from "the zip is
    malformed" without staring at tracebacks.
    """


#: The 422 detail every write path returns for a hint that gives the
#: passphrase away. One string so the three endpoints cannot drift.
HINT_REVEALS_PASSPHRASE = (
    "passphrase_hint must not contain the passphrase — the hint is stored "
    "unencrypted in every archive (manifest.json and the secrets.enc header), "
    "in the API response and in the audit log"
)


def hint_reveals_passphrase(passphrase: str | None, hint: str | None) -> bool:
    """True when ``hint`` contains ``passphrase``.

    The hint is written in clear next to the ciphertext it unlocks —
    deliberately, so an operator can tell archives apart without the
    passphrase. That makes a hint which *is* the passphrase (the field
    sits directly under the passphrase input, and gets the paste meant
    for it) a silent total loss: ``secrets.enc`` then protects nothing.

    Case-insensitive substring match: a hint that only re-cases the
    passphrase, or wraps it in other text, gives it away just as well.
    The passphrase minimum of 8 characters keeps this from catching a
    hint that merely shares a short word with it.
    """
    if not passphrase or not hint:
        return False
    secret = passphrase.strip().casefold()
    return bool(secret) and secret in hint.casefold()


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_BYTES,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_secrets(
    payload: dict[str, Any],
    *,
    passphrase: str,
    hint: str | None = None,
) -> bytes:
    """Encrypt ``payload`` with a fresh AES-GCM key derived from
    ``passphrase``. Returns the JSON envelope as UTF-8 bytes ready
    to write into ``secrets.enc``.
    """
    if not passphrase:
        raise BackupCryptoError("passphrase is required to encrypt secrets")
    if hint_reveals_passphrase(passphrase, hint):
        # The API refuses this combination; a row saved before that
        # check existed can still carry it. Dropping the hint keeps the
        # scheduled backup running while not writing the key beside the
        # lock. ``build_backup_archive`` logs it.
        hint = None
    salt = os.urandom(_SALT_BYTES)
    nonce = os.urandom(_NONCE_BYTES)
    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ciphertext = aes.encrypt(nonce, plaintext, associated_data=None)
    envelope = {
        "v": _ENVELOPE_VERSION,
        "kdf": "pbkdf2-hmac-sha256",
        "iterations": _PBKDF2_ITERATIONS,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "hint": (hint or "").strip()[:200],
    }
    return json.dumps(envelope, indent=2, sort_keys=True).encode("utf-8")


def decrypt_secrets(envelope_bytes: bytes, *, passphrase: str) -> dict[str, Any]:
    """Decrypt a ``secrets.enc`` envelope. Raises
    :class:`BackupCryptoError` on any wrong-shape / wrong-passphrase
    failure.
    """
    if not passphrase:
        raise BackupCryptoError("passphrase is required to decrypt secrets")
    try:
        envelope = json.loads(envelope_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupCryptoError("secrets.enc is not a valid JSON envelope") from exc
    if not isinstance(envelope, dict):
        raise BackupCryptoError("secrets.enc envelope is not a JSON object")
    if envelope.get("v") != _ENVELOPE_VERSION:
        raise BackupCryptoError(
            f"unsupported secrets envelope version: {envelope.get('v')!r} "
            f"(this build expects {_ENVELOPE_VERSION})"
        )
    try:
        salt = bytes.fromhex(envelope["salt"])
        nonce = bytes.fromhex(envelope["nonce"])
        ciphertext = bytes.fromhex(envelope["ciphertext"])
        iterations = int(envelope.get("iterations", _PBKDF2_ITERATIONS))
    except (KeyError, ValueError, TypeError) as exc:
        raise BackupCryptoError("secrets envelope is missing required fields") from exc
    # We derive at the envelope's declared iteration count — that
    # locks the cost factor to whatever was used at backup time, so
    # an operator who tightens iterations in a future build can still
    # decrypt older archives. The count is archive-controlled input,
    # though, so it is confined to a sane band first (#1568).
    if not _MIN_PBKDF2_ITERATIONS <= iterations <= _MAX_PBKDF2_ITERATIONS:
        raise BackupCryptoError(
            f"secrets envelope declares {iterations} PBKDF2 iterations, outside "
            f"the accepted band {_MIN_PBKDF2_ITERATIONS}..{_MAX_PBKDF2_ITERATIONS}"
        )
    # Malformed salt / nonce values make the KDF and AES-GCM raise
    # ValueError; wrap those as BackupCryptoError so a malformed
    # envelope is a clean 400 on restore, not an uncaught 500 (#1568).
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=_KEY_BYTES,
            salt=salt,
            iterations=iterations,
        )
        key = kdf.derive(passphrase.encode("utf-8"))
        aes = AESGCM(key)
        plaintext = aes.decrypt(nonce, ciphertext, associated_data=None)
    except InvalidTag as exc:
        raise BackupCryptoError(
            "decryption failed — passphrase mismatch or corrupted archive"
        ) from exc
    except ValueError as exc:
        raise BackupCryptoError(f"secrets envelope is malformed: {exc}") from exc
    try:
        return json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupCryptoError(
            "decrypted payload is not valid JSON — archive may be corrupted"
        ) from exc


# ── Whole-archive encryption (#1362) ───────────────────────────────────
#
# ``secrets.enc`` above wraps a small JSON document. The database dump is
# large, so it is encrypted as a stream of independently authenticated
# AES-256-GCM chunks rather than one buffer: the dump is deflated and
# encrypted a chunk at a time while it is read from disk.
#
# Layout of the encrypted member (everything the decryptor needs sits in
# the header, so the member is self-describing)::
#
#     magic        8   b"SPDDIENC"
#     version      1   1
#     iterations   4   PBKDF2-HMAC-SHA256 iteration count, big endian
#     salt        16   fresh per archive
#     nonce_pfx    4   random per archive
#     chunk_size   4   plaintext bytes per chunk (the last one may be short)
#     chunk*          [ct_len: 4][ciphertext + 16-byte GCM tag]
#
# Chunk ``i`` is sealed under nonce ``nonce_pfx || i`` (8 bytes, big
# endian) with the header and one "final chunk" byte as associated data.
# The header binds every chunk to this archive and its parameters; the
# counter nonce stops chunks being reordered or dropped from the middle; the
# final flag stops the stream being truncated at a chunk boundary. A
# passphrase mismatch, a flipped bit anywhere, or a cut-off tail all surface
# as :class:`BackupCryptoError`.
#
# The key is the same PBKDF2 derivation ``secrets.enc`` uses, with a salt of
# its own, from the target's existing passphrase.
STREAM_MAGIC = b"SPDDIENC"
_STREAM_VERSION = 1
_STREAM_CHUNK_BYTES = 1024 * 1024
_MAX_STREAM_CHUNK_BYTES = 16 * 1024 * 1024
_GCM_TAG_BYTES = 16
_STREAM_NONCE_PREFIX_BYTES = 4
# magic + version + iterations + salt + nonce prefix + chunk size
_STREAM_HEADER_BYTES = 8 + 1 + 4 + _SALT_BYTES + _STREAM_NONCE_PREFIX_BYTES + 4


def _stream_nonce(prefix: bytes, index: int) -> bytes:
    return prefix + index.to_bytes(8, "big")


def _stream_aad(header: bytes, final: bool) -> bytes:
    return header + (b"\x01" if final else b"\x00")


class DumpStreamEncryptor:
    """Deflates and encrypts a byte stream: ``write`` plaintext in, collect
    the ciphertext it returns, then ``finish`` for the last chunk. The
    first thing to collect is the header, returned by :meth:`header`."""

    def __init__(self, passphrase: str, *, chunk_bytes: int = _STREAM_CHUNK_BYTES) -> None:
        if not passphrase:
            raise BackupCryptoError("passphrase is required to encrypt the archive")
        salt = os.urandom(_SALT_BYTES)
        self._prefix = os.urandom(_STREAM_NONCE_PREFIX_BYTES)
        self._chunk = chunk_bytes
        self._header = (
            STREAM_MAGIC
            + bytes([_STREAM_VERSION])
            + _PBKDF2_ITERATIONS.to_bytes(4, "big")
            + salt
            + self._prefix
            + chunk_bytes.to_bytes(4, "big")
        )
        self._aes = AESGCM(_derive_key(passphrase, salt))
        self._zlib = zlib.compressobj(6)
        self._buf = bytearray()
        self._index = 0

    def header(self) -> bytes:
        return self._header

    def _seal(self, plaintext: bytes, *, final: bool) -> bytes:
        ct = self._aes.encrypt(
            _stream_nonce(self._prefix, self._index),
            plaintext,
            _stream_aad(self._header, final),
        )
        self._index += 1
        return len(ct).to_bytes(4, "big") + ct

    def write(self, data: bytes) -> bytes:
        self._buf += self._zlib.compress(data)
        out = bytearray()
        while len(self._buf) > self._chunk:
            out += self._seal(bytes(self._buf[: self._chunk]), final=False)
            del self._buf[: self._chunk]
        return bytes(out)

    def finish(self) -> bytes:
        self._buf += self._zlib.flush()
        out = bytearray()
        while len(self._buf) > self._chunk:
            out += self._seal(bytes(self._buf[: self._chunk]), final=False)
            del self._buf[: self._chunk]
        out += self._seal(bytes(self._buf), final=True)
        return bytes(out)


def decrypt_dump_stream(data: bytes, *, passphrase: str, max_bytes: int) -> bytes:
    """Reverse :class:`DumpStreamEncryptor`. ``max_bytes`` caps the inflated
    size: the stream is untrusted until every chunk has authenticated, and a
    crafted one must not be able to inflate without bound. Raises
    :class:`BackupCryptoError` for a wrong passphrase, tampering, truncation
    or a malformed header."""
    if not passphrase:
        raise BackupCryptoError("passphrase is required to decrypt the archive")
    if len(data) < _STREAM_HEADER_BYTES or data[:8] != STREAM_MAGIC:
        raise BackupCryptoError("encrypted database member is malformed (bad header)")
    header = data[:_STREAM_HEADER_BYTES]
    if header[8] != _STREAM_VERSION:
        raise BackupCryptoError(f"unsupported archive encryption version: {header[8]}")
    iterations = int.from_bytes(header[9:13], "big")
    salt = header[13 : 13 + _SALT_BYTES]
    prefix = header[13 + _SALT_BYTES : 13 + _SALT_BYTES + _STREAM_NONCE_PREFIX_BYTES]
    chunk_bytes = int.from_bytes(header[-4:], "big")
    if not _MIN_PBKDF2_ITERATIONS <= iterations <= _MAX_PBKDF2_ITERATIONS:
        raise BackupCryptoError(
            f"encrypted database member declares {iterations} PBKDF2 iterations, outside "
            f"the accepted band {_MIN_PBKDF2_ITERATIONS}..{_MAX_PBKDF2_ITERATIONS}"
        )
    if not 0 < chunk_bytes <= _MAX_STREAM_CHUNK_BYTES:
        raise BackupCryptoError("encrypted database member declares an invalid chunk size")
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=_KEY_BYTES, salt=salt, iterations=iterations
    ).derive(passphrase.encode("utf-8"))
    aes = AESGCM(key)
    inflater = zlib.decompressobj()
    out = bytearray()
    pos = _STREAM_HEADER_BYTES
    index = 0
    saw_final = False
    while pos < len(data):
        if saw_final:
            raise BackupCryptoError("encrypted database member has data after its final chunk")
        if pos + 4 > len(data):
            raise BackupCryptoError("encrypted database member is truncated")
        ct_len = int.from_bytes(data[pos : pos + 4], "big")
        pos += 4
        if ct_len < _GCM_TAG_BYTES or ct_len > chunk_bytes + _GCM_TAG_BYTES:
            raise BackupCryptoError("encrypted database member has an invalid chunk length")
        if pos + ct_len > len(data):
            raise BackupCryptoError("encrypted database member is truncated")
        ct = data[pos : pos + ct_len]
        pos += ct_len
        # The final flag is authenticated, not stored: try the not-final
        # reading first, and the final one only for the last bytes of the
        # stream. A chunk that opens under neither is a failure.
        final = pos == len(data)
        try:
            plain = aes.decrypt(_stream_nonce(prefix, index), ct, _stream_aad(header, final))
        except InvalidTag as exc:
            raise BackupCryptoError(
                "decryption failed — passphrase mismatch, corrupted or truncated archive"
            ) from exc
        index += 1
        saw_final = final
        try:
            out += inflater.decompress(plain, max(max_bytes - len(out), 0) + 1)
            if inflater.unconsumed_tail:
                raise BackupCryptoError("decrypted dump exceeds the size cap")
        except zlib.error as exc:
            raise BackupCryptoError("decrypted dump is not a valid deflate stream") from exc
        if len(out) > max_bytes:
            raise BackupCryptoError("decrypted dump exceeds the size cap")
    if not saw_final:
        raise BackupCryptoError("encrypted database member is truncated (no final chunk)")
    try:
        out += inflater.flush()
    except zlib.error as exc:
        raise BackupCryptoError("decrypted dump is not a valid deflate stream") from exc
    if not inflater.eof:
        raise BackupCryptoError("decrypted dump is truncated")
    return bytes(out)
