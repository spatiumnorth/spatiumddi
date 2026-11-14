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
import threading
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

# The response header a control plane that checks version 2 sets on every
# heartbeat answer. An older control plane sets nothing, ignores
# ``X-Appliance-Signature-Version`` and checks only the legacy form, so every
# version-2 request to it would be refused: its heartbeat would fall back to
# the session token, and every proxy channel (k8s, nettool, storage, pcap)
# would answer 403 until the control plane is upgraded.
SIGNATURE_VERSIONS_HEADER = "X-Appliance-Signature-Versions"

# What this process signs with: ``"v2"`` until a heartbeat answer shows the
# control plane does not check it, then ``"legacy"`` (the form that control
# plane checks). Once a heartbeat answer has advertised version 2, this
# process never signs the legacy form again, so a later answer with the
# header stripped cannot move it back. Shared by the heartbeat and the proxy
# threads.
_mode_lock = threading.Lock()
_signing_mode = "v2"
_v2_confirmed = False

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


def register_proof_payload(fingerprint: str, timestamp: str, nonce: str) -> bytes:
    """The bytes signed to show this supervisor holds the key it registers
    with. Must match the backend's ``register_proof_payload`` byte for byte."""
    return "\n".join(("spatium-register-v1", fingerprint, timestamp, nonce)).encode("utf-8")


def register_proof_fields(private_key: Ed25519PrivateKey, fingerprint: str) -> dict[str, str]:
    """Fresh ``proof_*`` fields for one registration request. A control plane
    that predates them ignores them. Build per attempt: each is accepted once."""
    timestamp = datetime.now(UTC).isoformat(timespec="seconds")
    nonce = secrets.token_hex(16)
    signature = private_key.sign(register_proof_payload(fingerprint, timestamp, nonce))
    return {
        "proof_timestamp": timestamp,
        "proof_nonce": nonce,
        "proof_signature": base64.b64encode(signature).decode("ascii"),
    }


def note_control_plane_signature_support(headers: object) -> str | None:
    """Record what the control plane's heartbeat answer advertises.

    ``headers`` is the 200 response's headers (anything with ``.get``).
    Returns the new signing mode when this call changed it, else ``None``,
    so the caller can log the switch once."""
    global _signing_mode, _v2_confirmed
    raw = headers.get(SIGNATURE_VERSIONS_HEADER) if hasattr(headers, "get") else None
    advertised = {v.strip() for v in str(raw or "").split(",") if v.strip()}
    with _mode_lock:
        before = _signing_mode
        if SIGNATURE_VERSION in advertised:
            _v2_confirmed = True
            _signing_mode = "v2"
        elif not _v2_confirmed:
            _signing_mode = "legacy"
        return _signing_mode if _signing_mode != before else None


def signing_mode() -> str:
    with _mode_lock:
        return _signing_mode


def _reset_signing_mode() -> None:
    """Back to the start-of-process state (tests)."""
    global _signing_mode, _v2_confirmed
    with _mode_lock:
        _signing_mode = "v2"
        _v2_confirmed = False


def _legacy_headers(
    method: str,
    target: str,
    cert_pem: str,
    private_key: Ed25519PrivateKey,
    appliance_id: uuid.UUID | str,
) -> dict[str, str]:
    """The pre-#3631 form, for a control plane that checks nothing else: a
    signature over the method, the bare path (that control plane drops the
    query), the timestamp and the appliance id, and no version header."""
    timestamp = datetime.now(UTC).isoformat(timespec="seconds")
    path = target.split("?", 1)[0]
    payload = f"{method.upper()} {path}\n{timestamp}\n{appliance_id}".encode("utf-8")
    return {
        "X-Appliance-Cert": base64.b64encode(cert_pem.encode("ascii")).decode("ascii"),
        "X-Appliance-Timestamp": timestamp,
        "X-Appliance-Signature": base64.b64encode(private_key.sign(payload)).decode(
            "ascii"
        ),
    }


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
    retry: the control plane accepts each signature once.

    Against a control plane that has shown it does not check version 2
    (:func:`note_control_plane_signature_support`), these are the legacy
    headers that control plane does check."""
    if signing_mode() == "legacy":
        return _legacy_headers(method, target, cert_pem, private_key, appliance_id)
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
    "SIGNATURE_VERSIONS_HEADER",
    "build_auth_headers",
    "canonical_payload_v2",
    "encode_json",
    "load_cert",
    "note_control_plane_signature_support",
    "register_proof_fields",
    "register_proof_payload",
    "save_cert",
    "signing_mode",
]
