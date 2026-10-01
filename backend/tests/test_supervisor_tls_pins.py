"""The CA-signed list of served certificates supervisors re-pin against (#1219).

A supervisor pins the control plane's TLS certificate on first contact. When
the certificate changes it fetches this list over a connection to the NEW
certificate and re-pins only if the appliance CA vouches for it, so these pin
the contract the supervisor verifies: which certificates are listed, that the
signature is the appliance CA's under exactly the PSS parameters the
supervisor checks with, and that the endpoint answers without auth.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.x509.oid import NameOID
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.models.appliance import ApplianceCertificate
from app.services.appliance import tls_pins
from app.services.appliance.ca import ensure_ca

_URL = "/api/v1/appliance/supervisor/tls-pins"
# What the supervisor verifies with (agent/supervisor/spatium_supervisor/cp_tls.py).
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def _cert_pem(cn: str) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _sha256(pem: str) -> str:
    der = x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


@pytest.fixture(autouse=True)
def _fresh(monkeypatch: pytest.MonkeyPatch) -> None:
    tls_pins.clear_cache()
    # No kube API in tests: nothing deployed unless a test says so.
    monkeypatch.setattr(tls_pins, "read_deployed_cert", lambda: None)


async def _active_cert(db: AsyncSession, pem: str, *, active: bool = True) -> None:
    db.add(
        ApplianceCertificate(
            name=f"c-{uuid.uuid4().hex[:6]}",
            source="self-signed",
            cert_pem=pem,
            key_encrypted=encrypt_str("unused"),
            is_active=active,
            subject_cn="ddi.test",
            sans_json=[],
        )
    )
    await db.commit()


async def test_no_ca_means_nothing_to_sign(client: AsyncClient) -> None:
    """Until something is approved there is no CA, and no supervisor holds
    one to verify with."""
    resp = await client.get(_URL)
    assert resp.status_code == 503


async def test_the_list_names_the_active_certificate_and_is_ca_signed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    ca = await ensure_ca(db_session)
    await db_session.commit()
    active = _cert_pem("active.test")
    await _active_cert(db_session, active)
    await _active_cert(db_session, _cert_pem("retired.test"), active=False)

    resp = await client.get(_URL)  # no Authorization header: unauthenticated
    assert resp.status_code == 200, resp.text
    body = resp.json()
    payload = base64.b64decode(body["payload"])
    signature = base64.b64decode(body["signature"])

    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
    ca_cert.public_key().verify(signature, payload, _PSS, hashes.SHA256())  # raises if not
    assert body["algorithm"] == "rsa-pss-sha256"
    assert (
        body["ca_cert_sha256"]
        == hashlib.sha256(ca_cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    )

    data = json.loads(payload)
    assert data["certs_sha256"] == [_sha256(active)], "only what is served, not a retired cert"
    issued = datetime.fromisoformat(data["issued_at"])
    assert abs(datetime.now(UTC) - issued) < timedelta(minutes=1)


async def test_the_certificate_in_the_tls_secret_is_listed_too(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1215: a k3s restart can put the first-boot certificate back in the
    Secret every frontend serves. It is what supervisors meet, so it must be
    vouched for or they refuse the certificate every node is serving."""
    await ensure_ca(db_session)
    await db_session.commit()
    active = _cert_pem("active.test")
    await _active_cert(db_session, active)
    firstboot = _cert_pem("firstboot.test")
    monkeypatch.setattr(tls_pins, "read_deployed_cert", lambda: (firstboot, "key"))

    data = json.loads(base64.b64decode((await client.get(_URL)).json()["payload"]))
    assert sorted(data["certs_sha256"]) == sorted([_sha256(active), _sha256(firstboot)])


async def test_a_signature_does_not_verify_after_the_list_is_edited(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    ca = await ensure_ca(db_session)
    await db_session.commit()
    await _active_cert(db_session, _cert_pem("active.test"))
    body = (await client.get(_URL)).json()
    data = json.loads(base64.b64decode(body["payload"]))
    data["certs_sha256"].append("ff" * 32)
    forged = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    ca_key = x509.load_pem_x509_certificate(ca.cert_pem.encode()).public_key()
    from cryptography.exceptions import InvalidSignature

    with pytest.raises(InvalidSignature):
        ca_key.verify(base64.b64decode(body["signature"]), forged, _PSS, hashes.SHA256())


async def test_the_list_is_cached_briefly_then_refreshed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The endpoint is unauthenticated and reads the Secret through the kube
    API, so a signed list is reused; but the cache is keyed on the active
    rows, so a certificate activated by ANY process (the Celery worker's ACME
    renewal, the startup bootstrap) is listed on the next request, with no
    cache-clear call that only reaches the process that made it."""
    await ensure_ca(db_session)
    await db_session.commit()
    first = _cert_pem("first.test")
    await _active_cert(db_session, first)
    one = (await client.get(_URL)).json()
    assert (await client.get(_URL)).json() == one, "cached"

    second = _cert_pem("second.test")
    await _active_cert(db_session, second)
    data = json.loads(base64.b64decode((await client.get(_URL)).json()["payload"]))
    assert _sha256(second) in data["certs_sha256"]
