"""A CA-signed statement of which TLS certificates the control plane serves (#1219).

Supervisors on remote appliances pin the control plane's TLS certificate on
first contact and verify every later connection against that pin. The Web UI
certificate is not static, though: a self-signed one is re-minted when a
control-plane member joins or the VIP changes (``bootstrap.py``), and an
operator can upload a new one or have ACME renew it. A supervisor that saw a
new certificate cannot tell a rotation from an interception on its own.

This is how it tells: the appliance CA, whose certificate every approved
supervisor already holds (it rides the first heartbeat after approval), signs
the list of certificates the control plane currently serves. A supervisor
that meets an unfamiliar certificate fetches this list over a connection to
THAT certificate, checks the signature against the CA it already trusts, and
re-pins only if the certificate is on the list.

The list is not a secret, so the endpoint serving it is unauthenticated: an
interceptor gains nothing by reading it, and cannot forge one without the CA
key.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import ApplianceCA, ApplianceCertificate
from app.services.appliance.ca import _load_ca_private_key
from app.services.appliance.deployment import read_deployed_cert

#: RSA-PSS over SHA-256, MGF1 SHA-256, salt the length of the digest. Fixed
#: parameters on purpose: the supervisor verifies with exactly these, and a
#: negotiable algorithm is one more thing an interceptor could downgrade.
PIN_SET_ALGORITHM = "rsa-pss-sha256"
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)

# The endpoint is unauthenticated and building the list reads the TLS Secret
# through the Kubernetes API and signs with the CA key, so a signed list is
# reused for this long rather than letting an anonymous caller turn requests
# into apiserver calls. The cache is keyed on the CA and on the ACTIVE
# ``ApplianceCertificate`` rows (two cheap DB reads per request), so a new
# certificate activated anywhere -- the api, the Celery worker running an ACME
# renewal, the startup bootstrap re-minting a self-signed one -- is listed on
# the very next request. Only a change to the Secret alone (#1215) waits out
# the TTL.
_CACHE_TTL_S = 30.0
_cache: tuple[float, tuple[str, frozenset[str]], dict[str, str]] | None = None


def cert_sha256(cert_pem: str) -> str:
    """SHA-256 of the DER of the FIRST certificate in ``cert_pem`` (the leaf;
    an uploaded or ACME certificate is stored with its chain after it)."""
    leaf = x509.load_pem_x509_certificates(cert_pem.encode("ascii"))[0]
    return hashlib.sha256(leaf.public_bytes(Encoding.DER)).hexdigest()


async def _active_row_fingerprints(db: AsyncSession) -> set[str]:
    rows = (
        (
            await db.execute(
                select(ApplianceCertificate).where(ApplianceCertificate.is_active.is_(True))
            )
        )
        .scalars()
        .all()
    )
    fingerprints: set[str] = set()
    for row in rows:
        if not row.cert_pem:
            continue
        try:
            fingerprints.add(cert_sha256(row.cert_pem))
        except ValueError:
            # An unparseable row vouches for nothing. It must not 500 the
            # endpoint, or every supervisor loses the ability to re-pin.
            continue
    return fingerprints


async def _deployed_fingerprint() -> str | None:
    """The certificate in the TLS Secret, listed ALONGSIDE the active row.

    The active ``ApplianceCertificate`` is what the api deploys into the
    cluster-wide TLS Secret; the Secret is what every node's frontend actually
    serves. They differ when something other than the api rewrites the Secret,
    which #1215 does: a k3s restart puts the first-boot certificate back.
    Listing only the row would make a supervisor refuse the certificate every
    node is really serving. Both are written only by the control plane itself,
    so both are safe to vouch for.
    """
    try:
        deployed = await asyncio.to_thread(read_deployed_cert)
    except Exception:  # noqa: BLE001 — the rows still answer without it
        return None
    if deployed is None:
        return None
    try:
        return cert_sha256(deployed[0])
    except ValueError:
        return None  # an unparseable Secret vouches for nothing; the rows still count


async def signed_pin_set(db: AsyncSession) -> dict[str, str] | None:
    """The served-certificate list, signed by the appliance CA, or None when
    there is no CA yet (nothing has been approved, so no supervisor holds a
    CA to verify with)."""
    global _cache
    ca = await db.get(ApplianceCA, 1)
    if ca is None:
        return None
    rows = await _active_row_fingerprints(db)
    key = (ca.cert_pem, frozenset(rows))
    if _cache is not None and _cache[1] == key and time.monotonic() - _cache[0] < _CACHE_TTL_S:
        return _cache[2]
    deployed = await _deployed_fingerprint()
    if deployed is not None:
        rows.add(deployed)
    payload = json.dumps(
        {
            "version": 1,
            "certs_sha256": sorted(rows),
            "issued_at": datetime.now(UTC).isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    signature = _load_ca_private_key(ca).sign(payload, _PSS, hashes.SHA256())
    ca_der = x509.load_pem_x509_certificate(ca.cert_pem.encode("ascii")).public_bytes(Encoding.DER)
    signed = {
        "payload": base64.b64encode(payload).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
        "algorithm": PIN_SET_ALGORITHM,
        "ca_cert_sha256": hashlib.sha256(ca_der).hexdigest(),
    }
    _cache = (time.monotonic(), key, signed)
    return signed


def clear_cache() -> None:
    """Forget the cached list (tests). Activation needs no call: the cache is
    keyed on the active rows, so a newly activated certificate misses it."""
    global _cache
    _cache = None
