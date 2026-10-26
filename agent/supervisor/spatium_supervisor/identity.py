"""Ed25519 identity for the supervisor (#170 Wave A2).

The supervisor generates an Ed25519 keypair on first boot, persists
the private key on ``/var/lib/spatium-supervisor/identity/`` (which is
bind-mounted from ``/var/persist/spatium-supervisor/`` on the
appliance host — survives slot swaps verbatim), and submits the
public half to the control plane as part of the register flow.

On subsequent boots the keypair is loaded from disk — never
regenerated unless the operator explicitly re-keys via the fleet UI
(future Wave B+).

File layout under ``identity/``:

* ``identity.key``        — PEM-encoded Ed25519 private key, mode 0600
* ``identity.pub.der``    — DER-encoded Ed25519 public key
* ``identity.pub.sha256`` — hex sha256 of identity.pub.der (the
                             fingerprint the control plane stores)
* ``appliance_id``        — UUID returned by ``/supervisor/register``
                             on first successful claim; absent until
                             the supervisor has registered

The fingerprint file is convenience for ``docker exec`` debugging —
operators can compare the on-disk fingerprint to the fleet UI without
re-deriving it.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from . import appliance_state

# File names — kept module-level so tests can reference them without
# duplicating literals.
PRIVATE_KEY_FILENAME = "identity.key"
PUBLIC_KEY_FILENAME = "identity.pub.der"
FINGERPRINT_FILENAME = "identity.pub.sha256"
APPLIANCE_ID_FILENAME = "appliance_id"
# Cleartext session token cached after /supervisor/register so the
# supervisor's /poll + /heartbeat calls authenticate across a
# restart between register and approval. Cleared once mTLS lands
# (Wave C2/D) — the cert is the identity from then on.
SESSION_TOKEN_FILENAME = "session_token"


@dataclass(frozen=True)
class Identity:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    public_key_der: bytes
    fingerprint: str  # sha256(public_key_der) hex


def _identity_dir(state_dir: Path) -> Path:
    return state_dir / "identity"


def load_or_generate(state_dir: Path) -> tuple[Identity, bool]:
    """Return (identity, generated_new). On first call: generate +
    persist. On subsequent calls: load from disk.

    The boolean is for the caller's audit log line — supervisors
    should log loudly the first time they mint an identity (it's the
    moment of unique cryptographic existence), but not on every boot.
    """
    identity_dir = _identity_dir(state_dir)
    identity_dir.mkdir(parents=True, exist_ok=True)
    private_path = identity_dir / PRIVATE_KEY_FILENAME

    if private_path.exists():
        return _load_from_disk(state_dir), False

    return _generate_and_persist(state_dir), True


def _load_from_disk(state_dir: Path) -> Identity:
    identity_dir = _identity_dir(state_dir)
    private_path = identity_dir / PRIVATE_KEY_FILENAME

    raw = private_path.read_bytes()
    priv = load_pem_private_key(raw, password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise RuntimeError(
            f"{private_path} is not an Ed25519 private key — refusing to load."
        )
    pub = priv.public_key()
    der = pub.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    return Identity(
        private_key=priv,
        public_key=pub,
        public_key_der=der,
        fingerprint=hashlib.sha256(der).hexdigest(),
    )


def _generate_and_persist(state_dir: Path) -> Identity:
    identity_dir = _identity_dir(state_dir)
    private_path = identity_dir / PRIVATE_KEY_FILENAME
    public_path = identity_dir / PUBLIC_KEY_FILENAME
    fingerprint_path = identity_dir / FINGERPRINT_FILENAME

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    pem = priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    der = pub.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(der).hexdigest()

    # Write the private key first via an atomic temp-then-rename so a
    # crash between write + chmod doesn't leave a key file mode-0644.
    tmp = private_path.with_suffix(".tmp")
    tmp.write_bytes(pem)
    tmp.chmod(0o600)
    tmp.replace(private_path)

    public_path.write_bytes(der)
    public_path.chmod(0o644)

    fingerprint_path.write_text(fingerprint + "\n")
    fingerprint_path.chmod(0o644)

    return Identity(
        private_key=priv,
        public_key=pub,
        public_key_der=der,
        fingerprint=fingerprint,
    )


def load_appliance_id(state_dir: Path) -> uuid.UUID | None:
    """Return the registered appliance_id, or None if the supervisor
    hasn't successfully registered yet."""
    path = _identity_dir(state_dir) / APPLIANCE_ID_FILENAME
    if not path.exists():
        return None
    try:
        return uuid.UUID(path.read_text().strip())
    except ValueError:
        return None


def save_appliance_id(state_dir: Path, appliance_id: uuid.UUID) -> None:
    """Persist the appliance_id returned by /supervisor/register.
    Atomic write so a crash mid-write doesn't leave a corrupt file."""
    path = _identity_dir(state_dir) / APPLIANCE_ID_FILENAME
    tmp = path.with_suffix(".tmp")
    tmp.write_text(str(appliance_id) + "\n")
    tmp.chmod(0o644)
    tmp.replace(path)


def clear_appliance_id(state_dir: Path) -> None:
    """Drop the cached appliance_id. Used by the revoked re-register
    path, which re-bootstraps from a fresh pairing code."""
    path = _identity_dir(state_dir) / APPLIANCE_ID_FILENAME
    path.unlink(missing_ok=True)


def load_session_token(state_dir: Path) -> str | None:
    """Return the cleartext session token cached after register, or
    None when no token has been persisted (fresh install, or already
    cleared post-mTLS)."""
    path = _identity_dir(state_dir) / SESSION_TOKEN_FILENAME
    if not path.exists():
        return None
    try:
        return path.read_text().strip() or None
    except OSError:
        return None


def save_session_token(state_dir: Path, token: str) -> None:
    """Persist the session token returned by /supervisor/register.
    Mode 0600 — the cleartext token is a bearer secret until mTLS
    takes over."""
    path = _identity_dir(state_dir) / SESSION_TOKEN_FILENAME
    tmp = path.with_suffix(".tmp")
    # #555 — set 0600 AT creation (not write_text + chmod after, which left
    # the bearer token briefly world-readable). Reuse the shared owner-only
    # writer so the O_EXCL/O_NOFOLLOW hardening lives in exactly one place.
    appliance_state._write_owner_only(tmp, token + "\n")
    tmp.replace(path)


def clear_session_token(state_dir: Path) -> None:
    """Drop the cached session token. Called once the supervisor
    switches to mTLS (cert issuance via the future poll loop)."""
    path = _identity_dir(state_dir) / SESSION_TOKEN_FILENAME
    path.unlink(missing_ok=True)
