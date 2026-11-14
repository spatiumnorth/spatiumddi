"""Cert-based mTLS-equivalent auth for supervisor endpoints (#170 Wave D follow-up).

Replaces the Wave-B1 session-token interim on
``POST /api/v1/appliance/supervisor/heartbeat`` and
``POST /api/v1/appliance/supervisor/poll`` once the supervisor has
been approved and picked up its X.509 cert via heartbeat.

True mTLS — the supervisor presenting its client cert during the
TLS handshake — needs nginx to terminate TLS and forward the cert
to the api via ``X-SSL-Client-Cert``. SpatiumDDI's frontend nginx
doesn't do that today, and dev runs are plain HTTP against
localhost. Until that lands, we accept the cert + an Ed25519
signature over a per-request payload in custom headers. The
private key never leaves /var/persist/spatium-supervisor; the
signature proves possession of the key bound to the cert; the
cert chain proves the appliance was approved by an admin. Same
security properties as mTLS; just a different transport for the
cert + signature.

Header contract (signature version 2, #3631):

* ``X-Appliance-Cert``              — base64(PEM cert from
                                       ``appliance.cert_pem``).
* ``X-Appliance-Timestamp``         — ISO 8601 UTC. Server requires
                                       ±300 s skew.
* ``X-Appliance-Signature-Version`` — ``2``. Present = the request is
                                       held to this form, never the
                                       legacy one.
* ``X-Appliance-Nonce``             — 32 hex chars, fresh per request, so
                                       two genuine identical requests in
                                       the same second still differ.
* ``X-Appliance-Content-SHA256``    — hex SHA-256 of the exact body bytes.
* ``X-Appliance-Signature``         — base64(Ed25519 signature over
                                       :func:`_canonical_payload_v2`:
                                       method, path + raw query string,
                                       timestamp, nonce, appliance_id and
                                       the body hash).

A signature is accepted once: after it verifies, a hash of it is claimed in
Redis (``SET NX EX``) for longer than the skew window, so a captured header
set cannot be sent again. Redis is shared by every api replica, which a
multi-node control plane needs. When Redis cannot be reached the claim fails
OPEN with a warning: the signature still binds the method, the full target
and the body, so what a repeat could do in that window is send the identical
request again; failing closed would stop every supervisor heartbeat in the
fleet for the length of a Redis failover (non-negotiable #5).

Legacy form (supervisors older than #3631): no version header, signature
over ``f"{method} {path}\\n{timestamp}\\n{appliance_id}"``. Accepted only
while ``settings.appliance_legacy_signature_allowed`` is set, and logged per
appliance (``appliance_cert_auth_legacy_signature``) so the end of the
compatibility window is observable. It is claimed once like the current
form, with one allowance: having no nonce, two genuine legacy requests to the
same path in the same second sign identically (an older supervisor's proxy
poll, its reply, and its next poll often do), so a repeat carrying the same
body within two seconds of the first use is accepted. Any other repeat, and
any repeat of a streamed upload, whose body is not read here, is refused.

Server-side validation (this module):

1. Decode + parse the cert.
2. Verify chain against the appliance_ca singleton row.
3. Verify cert not expired.
4. Verify the cert's subject CN parses as a UUID + matches a live
   appliance row in ``approved`` state.
5. Verify the cert's pubkey matches the appliance row's
   ``public_key_der`` (defence-in-depth against an old cert being
   replayed after the supervisor re-keyed).
6. Verify timestamp within ±300 s of server time.
7. Verify the signature against the cert's pubkey + the canonical
   payload (the body hash is computed from the body the api received,
   except on a streamed upload, where the route compares it afterwards).
8. Claim the signature as used (refuse a repeat).

On success, returns the ``Appliance`` row so the endpoint handler
can read it without re-fetching. On failure, raises 403 with a
generic "invalid client cert" message (401 for a repeated signature,
:class:`CertAuthReplayed`) — never leaks which step
failed (timing-side-channel + auth-error-disclosure hygiene).

The session-token interim path stays in place as a fallback when
the cert headers are absent: pending_approval rows still need the
session token because their cert doesn't exist yet. The handler
dispatches to whichever auth produced a valid principal.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

import structlog
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from fastapi import HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.redis_client import make_async_redis
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    Appliance,
    ApplianceCA,
)

logger = structlog.get_logger(__name__)

# Skew tolerance for X-Appliance-Timestamp. 5 minutes lines up with
# OAuth2's nbf/exp convention and with typical NTP drift on a fresh
# appliance host before chrony locks in.
_SKEW_TOLERANCE_SECONDS = 300

# The current signature form, carried in ``X-Appliance-Signature-Version``.
SIGNATURE_VERSION = "2"

# Set on every heartbeat answer to the forms this control plane checks
# (comma-separated). A supervisor that sees no such header is talking to a
# control plane older than #3631 and signs the legacy form for it; one that
# has seen it never does again in that process.
SIGNATURE_VERSIONS_HEADER = "X-Appliance-Signature-Versions"

# How long an accepted signature is remembered. A timestamp is accepted from
# ``now - skew`` to ``now + skew``, so a signature stamped at the far edge
# stays acceptable for twice the skew; a minute on top covers clock steps
# between api replicas.
_REPLAY_TTL_SECONDS = 2 * _SKEW_TOLERANCE_SECONDS + 60

# A legacy-form signature (no nonce) seen again with the same body this soon
# after its first use is an older supervisor sending two identical requests
# in one second, not a repeat; see :func:`_claim_signature`.
_LEGACY_REPEAT_WINDOW_S = 2.0

_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

# Legacy-form use, per appliance, in this process: (count, last logged at).
# Logged on first use and then at most every ``_LEGACY_LOG_INTERVAL_S``.
_LEGACY_LOG_INTERVAL_S = 900.0
_legacy_use: dict[uuid.UUID, tuple[int, float]] = {}


@dataclass(frozen=True)
class CertAuthPrincipal:
    """The result of validating cert-auth headers. Carries the loaded
    appliance row so the endpoint handler doesn't need a re-fetch."""

    appliance: Appliance
    # ``"v2"`` when the signature covered the target and the body (so every
    # field in the body is the supervisor's own); ``"legacy"`` otherwise.
    scheme: Literal["v2", "legacy"] = "v2"
    # The body hash the signature covers. On a streamed upload the api has
    # not read the body yet, so the route compares it once it has.
    content_sha256: str | None = None

    @property
    def body_bound(self) -> bool:
        return self.scheme == "v2"


class CertAuthFailed(HTTPException):
    """Generic 403 — never expose which step failed."""

    def __init__(self, reason: str, status_code: int = status.HTTP_403_FORBIDDEN) -> None:
        super().__init__(status_code, "Invalid appliance client cert.")
        # Stash the reason on the exception for the route handler's
        # structured-log line; the operator-facing detail stays
        # generic.
        self.reason = reason


class CertAuthReplayed(CertAuthFailed):
    """401 — a valid signature that has already been accepted once. Not a
    reason to fall back to another credential: the request is a repeat."""

    def __init__(self) -> None:
        super().__init__("signature already used", status.HTTP_401_UNAUTHORIZED)


def _b64decode(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CertAuthFailed(f"{field} not base64") from exc


def _canonical_payload(method: str, path: str, timestamp: str, appliance_id: str) -> bytes:
    """The legacy form's signed bytes (supervisors older than #3631). Order
    matters:
    ``method`` + ``path`` lock the signature to the specific request;
    ``timestamp`` defeats replay; ``appliance_id`` prevents a
    supervisor reusing a signature meant for one row against another's
    endpoint."""
    return f"{method.upper()} {path}\n{timestamp}\n{appliance_id}".encode()


def _canonical_payload_v2(
    method: str,
    target: str,
    timestamp: str,
    nonce: str,
    appliance_id: str,
    content_sha256: str,
) -> bytes:
    """The bytes a current supervisor signs (#3631). ``target`` is the path
    plus ``?`` and the raw query string when there is one, so a changed
    query (``?error=`` on the capture upload) breaks the signature;
    ``content_sha256`` binds the body. Must match the supervisor's
    ``cert_auth.canonical_payload_v2`` byte for byte."""
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


def request_target(request: Request) -> str:
    """Path plus the raw query string, as the supervisor signed it."""
    query = request.scope.get("query_string", b"").decode("latin-1")
    return request.url.path + (f"?{query}" if query else "")


async def _claim_signature(
    appliance_id: uuid.UUID,
    signature: bytes,
    *,
    legacy_body_sha256: str | None = None,
) -> bool:
    """Record ``signature`` as used. True on its first use; False when it
    has been accepted before. Fails open (True) with a warning when Redis
    cannot be reached; see the module docstring for why.

    ``legacy_body_sha256`` is set for a legacy-form request whose body the
    api has read. That form has no nonce, so an older supervisor's poll, its
    reply and its next poll can land in one second and the two polls sign
    identically. A repeat is therefore accepted when it carries the same
    body as the first use and arrives within
    :data:`_LEGACY_REPEAT_WINDOW_S` of it; any other repeat is refused."""
    key = f"appliance_sig:{appliance_id}:{hashlib.sha256(signature).hexdigest()}"
    now = time.time()
    value = f"{legacy_body_sha256 or '-'}:{now:.3f}"
    try:
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
        try:
            if await r.set(key, value, ex=_REPLAY_TTL_SECONDS, nx=True):
                return True
            if legacy_body_sha256 is None:
                return False
            first = await r.get(key)
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — never stop the fleet on a Redis blip
        logger.warning(
            "appliance_cert_auth_replay_guard_unavailable",
            appliance_id=str(appliance_id),
            error=str(exc)[:200],
        )
        return True
    if isinstance(first, bytes):
        first = first.decode("ascii", "replace")
    body_hash, _, first_at = str(first or "").rpartition(":")
    try:
        age = now - float(first_at)
    except ValueError:
        return False
    return body_hash == legacy_body_sha256 and 0 <= age <= _LEGACY_REPEAT_WINDOW_S


def _note_legacy_use(appliance_id: uuid.UUID) -> None:
    count, last = _legacy_use.get(appliance_id, (0, 0.0))
    count += 1
    now = time.monotonic()
    if count == 1 or now - last >= _LEGACY_LOG_INTERVAL_S:
        logger.warning(
            "appliance_cert_auth_legacy_signature",
            appliance_id=str(appliance_id),
            uses_in_this_process=count,
            hint=(
                "this appliance's supervisor signs requests in the pre-#3631 form; "
                "upgrade it, then set APPLIANCE_LEGACY_SIGNATURE_ALLOWED=false"
            ),
        )
        last = now
    _legacy_use[appliance_id] = (count, last)


def legacy_signature_use() -> dict[str, int]:
    """Legacy-form requests accepted by this process, per appliance id."""
    return {str(k): v[0] for k, v in _legacy_use.items()}


async def authenticate_cert(
    request: Request,
    db: AsyncSession,
    *,
    body_streamed: bool = False,
) -> CertAuthPrincipal | None:
    """Validate cert-auth headers on ``request`` against the appliance
    row + CA.

    The body hash is computed from ``await request.body()``. A route that
    streams its body (``body_streamed=True``) cannot have it read here; the
    declared ``X-Appliance-Content-SHA256`` is verified as signed, returned
    on the principal, and the route must compare it with the bytes it
    receives before it keeps them.

    Returns ``None`` when the headers are absent (route falls back to
    the session-token path); raises :class:`CertAuthFailed` (403) when
    headers are present but invalid.

    Doesn't touch ``request.state`` — the caller decides how to thread
    the principal into the handler.
    """
    cert_header = request.headers.get("X-Appliance-Cert")
    sig_header = request.headers.get("X-Appliance-Signature")
    ts_header = request.headers.get("X-Appliance-Timestamp")
    if cert_header is None or sig_header is None or ts_header is None:
        return None  # fall through to session-token path

    # ── 1. Parse the cert. ─────────────────────────────────────────
    try:
        cert_pem = _b64decode(cert_header, "X-Appliance-Cert")
        cert = x509.load_pem_x509_certificate(cert_pem)
    except (ValueError, CertAuthFailed) as exc:
        raise CertAuthFailed(f"cert parse: {exc}") from exc

    # ── 2. Verify chain against the appliance_ca singleton. ────────
    ca_row = await db.get(ApplianceCA, 1)
    if ca_row is None:
        raise CertAuthFailed("CA not initialised")
    try:
        ca_cert = x509.load_pem_x509_certificate(ca_row.cert_pem.encode("ascii"))
    except ValueError as exc:
        raise CertAuthFailed(f"CA cert parse: {exc}") from exc
    ca_pubkey = ca_cert.public_key()
    if not isinstance(ca_pubkey, RSAPublicKey):
        raise CertAuthFailed("CA pubkey not RSA")
    try:
        # x509.verify_directly_issued_by lands in cryptography 40+;
        # for the version pinned in this repo we use the manual path
        # of verifying signature + comparing issuer.
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        ca_pubkey.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm or hashes.SHA256(),
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise CertAuthFailed(f"chain verify: {exc}") from exc

    # ── 3. Expiry. ────────────────────────────────────────────────
    now = datetime.now(UTC)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    if now < not_before or now > not_after:
        raise CertAuthFailed(f"cert expired or not yet valid (window {not_before} → {not_after})")

    # ── 4. Subject CN → appliance row. ────────────────────────────
    try:
        cn_attr = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0]
        cn_value = cn_attr.value
        if isinstance(cn_value, bytes):
            cn_value = cn_value.decode("ascii")
        appliance_id = uuid.UUID(cn_value)
    except (IndexError, ValueError) as exc:
        raise CertAuthFailed(f"subject CN: {exc}") from exc
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise CertAuthFailed("appliance row not found")
    if row.state != APPLIANCE_STATE_APPROVED:
        raise CertAuthFailed(f"appliance state {row.state!r} != approved")

    # ── 5. Cert pubkey == row pubkey. ─────────────────────────────
    cert_pubkey = cert.public_key()
    if not isinstance(cert_pubkey, Ed25519PublicKey):
        raise CertAuthFailed("cert pubkey not Ed25519")
    from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
        Encoding,
        PublicFormat,
    )

    cert_pubkey_der = cert_pubkey.public_bytes(
        encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
    )
    if cert_pubkey_der != row.public_key_der:
        raise CertAuthFailed("cert pubkey != row pubkey (re-keyed?)")

    # ── 6. Timestamp skew. ────────────────────────────────────────
    try:
        ts = datetime.fromisoformat(ts_header)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
    except ValueError as exc:
        raise CertAuthFailed(f"timestamp parse: {exc}") from exc
    skew = abs((now - ts).total_seconds())
    if skew > _SKEW_TOLERANCE_SECONDS:
        raise CertAuthFailed(f"timestamp skew {skew:.0f}s > {_SKEW_TOLERANCE_SECONDS}s")

    # ── 7. Signature over the canonical payload. ──────────────────
    signature = _b64decode(sig_header, "X-Appliance-Signature")
    version = request.headers.get("X-Appliance-Signature-Version")
    scheme: Literal["v2", "legacy"]
    content_sha256: str | None = None
    legacy_body_sha256: str | None = None
    if version is not None:
        # The header names the form, so a current supervisor's request can
        # never be checked as the legacy one.
        if version != SIGNATURE_VERSION:
            raise CertAuthFailed(f"unknown signature version {version!r}")
        nonce = request.headers.get("X-Appliance-Nonce", "")
        declared = request.headers.get("X-Appliance-Content-SHA256", "")
        if not _NONCE_RE.match(nonce):
            raise CertAuthFailed("nonce missing or malformed")
        if not _SHA256_HEX_RE.match(declared):
            raise CertAuthFailed("content hash missing or malformed")
        if body_streamed:
            content_sha256 = declared
        else:
            content_sha256 = hashlib.sha256(await request.body()).hexdigest()
            if content_sha256 != declared:
                raise CertAuthFailed("body does not match its signed hash")
        payload = _canonical_payload_v2(
            request.method,
            request_target(request),
            ts_header,
            nonce,
            str(appliance_id),
            content_sha256,
        )
        scheme = "v2"
    else:
        if not settings.appliance_legacy_signature_allowed:
            raise CertAuthFailed("legacy signature form not accepted")
        if not body_streamed:
            legacy_body_sha256 = hashlib.sha256(await request.body()).hexdigest()
        payload = _canonical_payload(
            request.method,
            request.url.path,
            ts_header,
            str(appliance_id),
        )
        scheme = "legacy"
    try:
        cert_pubkey.verify(signature, payload)
    except InvalidSignature as exc:
        raise CertAuthFailed(f"signature: {exc}") from exc

    # ── 8. Single use. ────────────────────────────────────────────
    if not await _claim_signature(appliance_id, signature, legacy_body_sha256=legacy_body_sha256):
        raise CertAuthReplayed()
    if scheme == "legacy":
        _note_legacy_use(appliance_id)

    return CertAuthPrincipal(appliance=row, scheme=scheme, content_sha256=content_sha256)


_REGISTER_PROOF_PREFIX = "spatium-register-v1"
_REGISTER_PROOF_TTL_SECONDS = 2 * _SKEW_TOLERANCE_SECONDS + 60


def register_proof_payload(fingerprint: str, timestamp: str, nonce: str) -> bytes:
    """The bytes a supervisor signs to show it holds the private key behind
    the public key it registers with. Must match the supervisor's
    ``cert_auth.register_proof_payload`` byte for byte."""
    return "\n".join((_REGISTER_PROOF_PREFIX, fingerprint, timestamp, nonce)).encode("utf-8")


class RegisterProofUnavailable(Exception):
    """The nonce store could not be reached; the caller answers 503."""


async def verify_register_proof(
    pubkey: Ed25519PublicKey,
    fingerprint: str,
    timestamp: str,
    nonce: str,
    signature_b64: str,
) -> bool:
    """True when ``signature_b64`` is the registering key's signature over a
    fresh timestamp and a nonce not seen before. The nonce is spent here, so a
    captured registration cannot be sent again. Raises
    :class:`RegisterProofUnavailable` when the nonce store is unreachable
    (a registration retries; nothing is lost by failing closed)."""
    if not _NONCE_RE.match(nonce):
        return False
    try:
        ts = datetime.fromisoformat(timestamp)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, binascii.Error):
        return False
    if abs((datetime.now(UTC) - ts).total_seconds()) > _SKEW_TOLERANCE_SECONDS:
        return False
    try:
        pubkey.verify(signature, register_proof_payload(fingerprint, timestamp, nonce))
    except InvalidSignature:
        return False
    try:
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
        try:
            return bool(
                await r.set(
                    f"appliance_register_nonce:{fingerprint}:{nonce}",
                    "1",
                    ex=_REGISTER_PROOF_TTL_SECONDS,
                    nx=True,
                )
            )
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001
        raise RegisterProofUnavailable(str(exc)[:200]) from exc


__all__ = [
    "RegisterProofUnavailable",
    "register_proof_payload",
    "verify_register_proof",
    "SIGNATURE_VERSION",
    "SIGNATURE_VERSIONS_HEADER",
    "CertAuthFailed",
    "CertAuthPrincipal",
    "CertAuthReplayed",
    "authenticate_cert",
    "legacy_signature_use",
    "request_target",
]


# Quiet ruff unused-import in the lazy-import block above. Putting the
# imports inside the function body keeps cryptography out of the
# module's import graph until a request actually needs them.
_ = timedelta
