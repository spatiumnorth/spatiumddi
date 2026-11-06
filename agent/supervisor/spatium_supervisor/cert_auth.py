"""Supervisor-side cert auth (#170 Wave D follow-up).

The supervisor's heartbeat picks up the control-plane-signed X.509
cert + CA chain on the first heartbeat after admin approval (see
``SupervisorHeartbeatResponse.cert_pem``). This module:

* Persists the cert + CA chain under ``{state_dir}/tls/`` so a
  supervisor restart finds them again.
* Loads them back on subsequent boots.
* Builds the auth headers the backend's ``cert_auth.py`` middleware
  validates: ``X-Appliance-Cert`` (base64 PEM), ``X-Appliance-
  Timestamp`` (ISO 8601 UTC), ``X-Appliance-Signature-Version`` (``2``),
  ``X-Appliance-Nonce``, ``X-Appliance-Content-SHA256`` and
  ``X-Appliance-Signature`` (base64 Ed25519 over
  :func:`canonical_payload_v2`).

The private key never leaves disk — we only sign payloads with it.
The signed payload (#3631) binds the method, the path AND query string
exactly as sent, a hash of the exact body bytes, a fresh nonce, the
timestamp and the appliance id, and the control plane accepts each
signature once. So every call site signs the bytes it sends: serialise a
JSON body once with :func:`encode_json` and send those bytes as
``content=``, rather than letting httpx serialise ``json=`` separately.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# The signature form; the control plane reads it from
# ``X-Appliance-Signature-Version`` and never checks a request carrying it
# against the older form.
SIGNATURE_VERSION = "2"

# Headers for a JSON body sent as pre-encoded bytes.
JSON_CONTENT_TYPE = {"Content-Type": "application/json"}

CERT_FILENAME = "cert.pem"
CA_CHAIN_FILENAME = "ca-chain.pem"


def _tls_dir(state_dir: Path) -> Path:
    return state_dir / "tls"


def save_cert(state_dir: Path, cert_pem: str, ca_chain_pem: str) -> None:
    """Persist the cert + CA chain. Idempotent — re-saving identical
    bytes is a no-op (the supervisor heartbeat-loop calls this every
    tick once approved; we only write when content changes to avoid
    pointless disk churn)."""
    tls_dir = _tls_dir(state_dir)
    tls_dir.mkdir(parents=True, exist_ok=True)

    cert_path = tls_dir / CERT_FILENAME
    if not _content_matches(cert_path, cert_pem):
        _atomic_write(cert_path, cert_pem)
    ca_path = tls_dir / CA_CHAIN_FILENAME
    if not _content_matches(ca_path, ca_chain_pem):
        _atomic_write(ca_path, ca_chain_pem)


def load_cert(state_dir: Path) -> str | None:
    """Return the persisted cert PEM, or ``None`` when not yet approved."""
    path = _tls_dir(state_dir) / CERT_FILENAME
    if not path.exists():
        return None
    try:
        return path.read_text(encoding="ascii")
    except OSError:
        return None


def clear_cert(state_dir: Path) -> None:
    """Drop the cached cert + CA chain. Used during revoke-recovery
    (#170 Wave E follow-up) — the cert was issued against the old
    appliance_id which no longer exists on the control plane;
    presenting it for mTLS would just fail. The supervisor falls back
    to session-token auth on the new register call + receives a fresh
    cert when an admin approves the re-pair."""
    tls_dir = _tls_dir(state_dir)
    (tls_dir / CERT_FILENAME).unlink(missing_ok=True)
    (tls_dir / CA_CHAIN_FILENAME).unlink(missing_ok=True)


def _content_matches(path: Path, body: str) -> bool:
    if not path.exists():
        return False
    try:
        return path.read_text(encoding="ascii") == body
    except OSError:
        return False


def _atomic_write(path: Path, body: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(body, encoding="ascii")
    tmp.chmod(0o644)
    tmp.replace(path)


def encode_json(body: object) -> bytes:
    """Serialise a JSON request body once, so the bytes signed are the bytes
    sent (pass them as ``content=`` with :data:`JSON_CONTENT_TYPE`)."""
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def canonical_payload_v2(
    method: str,
    target: str,
    timestamp: str,
    nonce: str,
    appliance_id: str,
    content_sha256: str,
) -> bytes:
    """The signed bytes. Must match the backend's ``_canonical_payload_v2``
    byte for byte."""
    return "\n".join(
        (
            "spatium-appliance-v2",
            method.upper(),
            target,
            timestamp,
            nonce,
            appliance_id,
            content_sha256,
        )
    ).encode("utf-8")


def build_auth_headers(
    method: str,
    target: str,
    cert_pem: str,
    private_key: Ed25519PrivateKey,
    appliance_id: uuid.UUID | str,
    body: bytes = b"",
    *,
    content_sha256: str | None = None,
) -> dict[str, str]:
    """Build the cert-auth headers for one request.

    ``target`` is the path plus ``?`` and the query string exactly as the
    request sends it (``/api/v1/.../upload/<id>?packets=3``). ``body`` is the
    exact body bytes; a caller streaming a body it has hashed itself passes
    ``content_sha256`` instead. Build these per request, never once for a
    retry: the control plane accepts each signature once."""
    timestamp = datetime.now(UTC).isoformat(timespec="seconds")
    nonce = secrets.token_hex(16)
    digest = content_sha256 or hashlib.sha256(body).hexdigest()
    payload = canonical_payload_v2(
        method, target, timestamp, nonce, str(appliance_id), digest
    )
    signature = private_key.sign(payload)
    return {
        "X-Appliance-Cert": base64.b64encode(cert_pem.encode("ascii")).decode("ascii"),
        "X-Appliance-Timestamp": timestamp,
        "X-Appliance-Signature-Version": SIGNATURE_VERSION,
        "X-Appliance-Nonce": nonce,
        "X-Appliance-Content-SHA256": digest,
        "X-Appliance-Signature": base64.b64encode(signature).decode("ascii"),
    }


__all__ = [
    "JSON_CONTENT_TYPE",
    "SIGNATURE_VERSION",
    "build_auth_headers",
    "canonical_payload_v2",
    "encode_json",
    "load_cert",
    "save_cert",
]
