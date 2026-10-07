"""Enrolment context for the device QR code (#906).

The QR carries the control plane's own TLS fingerprint so the mobile client
can machine-check the certificate it is offered, instead of asking the
operator to compare 64 hex characters by eye on a phone — the check people
skim.

That only works if the fingerprint is right. The interesting behaviour is
therefore the REFUSAL: on a deployment where an external proxy or ingress
terminates TLS with a certificate this process has never seen, the honest
answer is "I don't know", not a guess. A wrong fingerprint would make the
client report a mismatch on a correct setup, which teaches operators to click
through the one warning this feature exists to make meaningful.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.appliance import ApplianceCertificate
from app.models.auth import User

_URL = "/api/v1/api-tokens/enrolment-context"


async def _user(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"enrol-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Enrolment User",
        hashed_password=hash_password("x"),
        is_superadmin=False,
    )
    db.add(user)
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _cert(db: AsyncSession, *, fingerprint: str | None, active: bool = True) -> None:
    db.add(
        ApplianceCertificate(
            name=f"c-{uuid.uuid4().hex[:6]}",
            source="self-signed",
            key_encrypted=b"\x00",
            is_active=active,
            subject_cn="ddi.test",
            sans_json=[],
            fingerprint_sha256=fingerprint,
        )
    )
    await db.flush()


async def test_reports_nothing_when_spatiumddi_does_not_manage_tls(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The Compose / plain-Kubernetes case: no managed certificate exists.

    Must say so rather than guess — see the module docstring.
    """
    _, headers = await _user(db_session)
    body = (await client.get(_URL, headers=headers)).json()
    assert body["tls_fingerprint_sha256"] is None
    assert body["fingerprint_source"] is None
    assert body["fingerprint_unavailable_reason"]


async def test_reports_the_active_certificate_fingerprint(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _user(db_session)
    await _cert(db_session, fingerprint="AB" * 32)

    body = (await client.get(_URL, headers=headers)).json()
    assert body["tls_fingerprint_sha256"] == "ab" * 32
    assert body["fingerprint_source"] == "self-signed"
    assert body["fingerprint_unavailable_reason"] is None


async def test_normalises_the_stored_colon_form_to_bare_lower_hex(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Stored fingerprints have carried colons or not depending on which path
    wrote them. The enrolment format specifies hex with colons optional, so
    emitting one canonical form keeps the client's comparison a string
    equality rather than a parse."""
    _, headers = await _user(db_session)
    await _cert(db_session, fingerprint=":".join(["AB"] * 32))

    body = (await client.get(_URL, headers=headers)).json()
    assert body["tls_fingerprint_sha256"] == "ab" * 32


async def test_ignores_an_inactive_certificate(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Only the ACTIVE row is deployed to the TLS secret the frontend serves,
    so an old or superseded certificate must not be advertised as what
    clients will be offered."""
    _, headers = await _user(db_session)
    await _cert(db_session, fingerprint="CD" * 32, active=False)

    body = (await client.get(_URL, headers=headers)).json()
    assert body["tls_fingerprint_sha256"] is None


async def test_ignores_a_pending_csr_row_with_no_fingerprint(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A CSR awaiting the operator's signed certificate is active-but-unusable:
    its cert-derived fields are null."""
    _, headers = await _user(db_session)
    await _cert(db_session, fingerprint=None)

    body = (await client.get(_URL, headers=headers)).json()
    assert body["tls_fingerprint_sha256"] is None
    assert body["fingerprint_unavailable_reason"]


async def test_requires_authentication(client: AsyncClient) -> None:
    assert (await client.get(_URL)).status_code == 401


async def test_does_not_shadow_the_token_by_id_route(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """``/enrolment-context`` is a literal segment sharing a prefix with
    ``GET /{token_id}``. FastAPI matches in registration order, so declaring
    it second would make the UUID param swallow it and 422 the literal."""
    _, headers = await _user(db_session)
    created = await client.post(
        "/api/v1/api-tokens",
        headers=headers,
        json={"name": "enrol-route-test", "stepup_password": "x"},
    )
    assert created.status_code == 201
    token_id = created.json()["id"]

    assert (await client.get(_URL, headers=headers)).status_code == 200
    by_id = await client.get(f"/api/v1/api-tokens/{token_id}", headers=headers)
    assert by_id.status_code == 200
    assert by_id.json()["id"] == token_id
