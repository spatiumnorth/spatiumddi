"""The TLS certificate store has its own permission (#3067).

Every ``/appliance/tls`` and ``/appliance/acme`` route took ``read`` or
``admin`` on ``appliance``, so the only built-in roles that could upload or
issue the certificate a DoT / DoH / DoQ listener serves were Superadmin and
Appliance Operator — and granting ``admin,appliance`` to a DNS team also
granted fleet approve, upgrade and reboot.

The store now checks ``certificate_store``, still accepting the ``appliance``
grant it took before, and making a certificate the Web UI certificate (which
deploys it to nginx) still needs ``admin,appliance``. These drive the real API
as a user holding exactly one role, with the built-in grants taken from
``app.main._BUILTIN_ROLES`` — the rows the api seeds on every start.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.security import create_access_token, hash_password
from app.main import _BUILTIN_ROLES
from app.models.acme_client import ACMEClientAccount, ACMEOrder
from app.models.appliance import ApplianceCertificate
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.settings import PlatformSettings
from app.services import feature_modules
from app.services.acme_client import orchestrator
from app.services.ai.tools.base import REGISTRY, tool_permission_allows

pytestmark = pytest.mark.asyncio

TLS = "/api/v1/appliance/tls"
ACME = "/api/v1/appliance/acme"


@pytest.fixture(autouse=True)
def _reset_module_cache() -> Any:
    feature_modules.invalidate_cache()
    yield
    feature_modules.invalidate_cache()


@pytest.fixture(autouse=True)
def _no_deploy(monkeypatch: pytest.MonkeyPatch) -> None:
    # Off-appliance: activation flips ``is_active`` and deploys nothing.
    monkeypatch.setattr(settings, "appliance_mode", False)


async def _user(
    db: AsyncSession,
    *,
    role: str | None = None,
    permissions: list[dict[str, Any]] | None = None,
) -> tuple[User, dict[str, str]]:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"cs-{tag}",
        email=f"{tag}@example.test",
        display_name="Cert",
        hashed_password=hash_password("x"),
        is_superadmin=False,
    )
    perms = list(_BUILTIN_ROLES[role][1]) if role is not None else list(permissions or [])
    r = Role(name=f"r-{tag}", description="", permissions=perms)
    g = Group(name=f"g-{tag}", description="")
    g.roles = [r]
    g.users = [user]
    db.add_all([user, r, g])
    await db.flush()
    await db.commit()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _chain(cn: str = "dot.example.com") -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert.public_bytes(serialization.Encoding.PEM).decode(), key_pem


def _upload_body(activate: bool, name: str | None = None) -> dict[str, Any]:
    cert_pem, key_pem = _chain()
    return {
        "name": name or f"c-{uuid.uuid4().hex[:6]}",
        "cert_pem": cert_pem,
        "key_pem": key_pem,
        "activate": activate,
    }


async def _enable_acme(db: AsyncSession) -> None:
    row = await db.get(PlatformSettings, 1)
    if row is None:
        row = PlatformSettings(id=1)
        db.add(row)
    row.acme_enabled = True
    await db.commit()


# ── DNS Editor ──────────────────────────────────────────────────────


async def test_dns_editor_lists_uploads_csrs_and_deletes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _user(db_session, role="DNS Editor")

    assert (await client.get(TLS, headers=h)).status_code == 200

    r = await client.post(f"{TLS}/upload", json=_upload_body(activate=False), headers=h)
    assert r.status_code == 201, r.text
    uploaded = r.json()
    assert uploaded["is_active"] is False

    r = await client.post(
        f"{TLS}/csr",
        json={"name": f"csr-{uuid.uuid4().hex[:6]}", "common_name": "dot.example.com"},
        headers=h,
    )
    assert r.status_code == 201, r.text

    r = await client.get(f"{TLS}/{uploaded['id']}", headers=h)
    assert r.status_code == 200

    r = await client.delete(f"{TLS}/{uploaded['id']}", headers=h)
    assert r.status_code == 204, r.text


async def test_dns_editor_cannot_make_a_cert_the_web_ui_cert(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _user(db_session, role="DNS Editor")

    # Upload with activate=true — refused before anything is stored.
    body = _upload_body(activate=True)
    r = await client.post(f"{TLS}/upload", json=body, headers=h)
    assert r.status_code == 403, r.text
    assert "admin" in r.json()["detail"]
    stored = (
        await db_session.execute(
            select(ApplianceCertificate).where(ApplianceCertificate.name == body["name"])
        )
    ).scalar_one_or_none()
    assert stored is None

    # The activate route itself.
    r = await client.post(f"{TLS}/upload", json=_upload_body(activate=False), headers=h)
    cert_id = r.json()["id"]
    r = await client.post(f"{TLS}/{cert_id}/activate", headers=h)
    assert r.status_code == 403
    db_session.expire_all()
    row = await db_session.get(ApplianceCertificate, uuid.UUID(cert_id))
    assert row is not None and row.is_active is False

    # Both refusals are audited.
    denied = (
        (await db_session.execute(select(AuditLog).where(AuditLog.result == "denied")))
        .scalars()
        .all()
    )
    assert len(denied) >= 2


async def test_dns_editor_issues_via_acme_without_activation(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _user(db_session, role="DNS Editor")

    r = await client.put(
        f"{ACME}/account",
        json={"directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory"},
        headers=h,
    )
    assert r.status_code == 200, r.text
    await _enable_acme(db_session)

    with patch("app.tasks.acme.run_acme_order.delay") as delay:
        # The default (activate) would take over the Web UI cert: refused.
        r = await client.post(f"{ACME}/issue", json={"domains": ["dot.example.com"]}, headers=h)
        assert r.status_code == 403, r.text
        delay.assert_not_called()

        r = await client.post(
            f"{ACME}/issue",
            json={"domains": ["dot.example.com"], "activate": False},
            headers=h,
        )
    assert r.status_code == 201, r.text
    assert r.json()["activate"] is False
    delay.assert_called_once()
    order = await db_session.get(ACMEOrder, uuid.UUID(r.json()["id"]))
    assert order is not None and order.activate_on_issue is False

    assert (await client.get(f"{ACME}/orders", headers=h)).status_code == 200
    assert (await client.get(f"{ACME}/account", headers=h)).status_code == 200


async def test_an_order_placed_without_activation_does_not_take_the_web_ui(
    db_session: AsyncSession,
) -> None:
    web_pem, web_key = _chain("ui.example.com")
    from app.core.crypto import encrypt_str

    web = ApplianceCertificate(
        name="web",
        source="uploaded",
        cert_pem=web_pem,
        key_encrypted=encrypt_str(web_key),
        is_active=True,
        subject_cn="ui.example.com",
        sans_json=["ui.example.com"],
    )
    account = ACMEClientAccount(
        directory_url="https://acme-staging-v02.api.letsencrypt.org/directory",
        account_key_encrypted=encrypt_str("x"),
    )
    db_session.add_all([web, account])
    await db_session.flush()
    order = ACMEOrder(
        account_id=account.id,
        domains=["dot.example.com"],
        challenge_type="dns-01",
        status="pending",
        activate_on_issue=False,
    )
    db_session.add(order)
    await db_session.flush()
    web_id = web.id

    chain_pem, key_pem = _chain()
    row = await orchestrator._store_certificate(db_session, order, chain_pem, key_pem)

    assert row.is_active is False
    db_session.expire_all()
    still = await db_session.get(ApplianceCertificate, web_id)
    assert still is not None and still.is_active is True


# ── Roles built on ``appliance`` keep what they had ─────────────────


async def test_admin_appliance_alone_keeps_every_store_action(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _user(db_session, permissions=[{"action": "admin", "resource_type": "appliance"}])

    assert (await client.get(TLS, headers=h)).status_code == 200
    r = await client.post(f"{TLS}/upload", json=_upload_body(activate=True), headers=h)
    assert r.status_code == 201, r.text
    assert r.json()["is_active"] is True
    r = await client.post(f"{TLS}/upload", json=_upload_body(activate=False), headers=h)
    other = r.json()["id"]
    assert (await client.post(f"{TLS}/{other}/activate", headers=h)).status_code == 200
    first = (await client.get(TLS, headers=h)).json()
    inactive = next(c["id"] for c in first if not c["is_active"])
    assert (await client.delete(f"{TLS}/{inactive}", headers=h)).status_code == 204

    r = await client.put(
        f"{ACME}/account",
        json={"directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory"},
        headers=h,
    )
    assert r.status_code == 200, r.text
    await _enable_acme(db_session)
    with patch("app.tasks.acme.run_acme_order.delay"):
        r = await client.post(f"{ACME}/issue", json={"domains": ["ui.example.com"]}, headers=h)
    assert r.status_code == 201, r.text
    assert r.json()["activate"] is True


async def test_read_appliance_alone_still_reads_and_cannot_write(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _user(db_session, permissions=[{"action": "read", "resource_type": "appliance"}])
    assert (await client.get(TLS, headers=h)).status_code == 200
    assert (await client.get(f"{ACME}/orders", headers=h)).status_code == 200
    r = await client.post(f"{TLS}/upload", json=_upload_body(activate=False), headers=h)
    assert r.status_code == 403


async def test_viewer_reads_the_store_and_writes_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _user(db_session, role="Viewer")
    assert (await client.get(TLS, headers=h)).status_code == 200
    r = await client.post(f"{TLS}/upload", json=_upload_body(activate=False), headers=h)
    assert r.status_code == 403


async def test_write_without_delete_cannot_delete(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _user(
        db_session,
        permissions=[
            {"action": "read", "resource_type": "certificate_store"},
            {"action": "write", "resource_type": "certificate_store"},
        ],
    )
    r = await client.post(f"{TLS}/upload", json=_upload_body(activate=False), headers=h)
    assert r.status_code == 201, r.text
    assert (await client.delete(f"{TLS}/{r.json()['id']}", headers=h)).status_code == 403


async def test_a_role_with_neither_grant_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _user(db_session, role="IPAM Editor")
    assert (await client.get(TLS, headers=h)).status_code == 403
    assert (await client.get(f"{ACME}/orders", headers=h)).status_code == 403


# ── Copilot tools + seeding ─────────────────────────────────────────


@pytest.mark.parametrize(
    "tool", ["find_certificates", "count_certificates_expiring", "get_acme_account"]
)
async def test_mcp_tools_take_the_store_read(db_session: AsyncSession, tool: str) -> None:
    t = REGISTRY.get(tool)
    assert t is not None and t.permission is not None

    async def allows(**kw: Any) -> bool:
        u, _ = await _user(db_session, **kw)
        await db_session.refresh(u, ["groups"])
        return tool_permission_allows(u, t.permission)

    assert await allows(role="DNS Editor")
    assert await allows(permissions=[{"action": "read", "resource_type": "certificate_store"}])
    assert await allows(permissions=[{"action": "read", "resource_type": "appliance"}])
    assert not await allows(role="IPAM Editor")


async def test_builtin_roles_seed_the_store_grant() -> None:
    grant = {"action": "admin", "resource_type": "certificate_store"}
    assert grant in _BUILTIN_ROLES["DNS Editor"][1]
    assert grant in _BUILTIN_ROLES["Appliance Operator"][1]
    # Operator keeps the appliance grant it always had.
    assert {"action": "admin", "resource_type": "appliance"} in _BUILTIN_ROLES[
        "Appliance Operator"
    ][1]


# ── Validation additions ────────────────────────────────────────────


async def test_dns_editor_import_signed_cert_with_default_activate_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The CSR → import path defaults ``activate`` to true too; a store-only
    caller must not reach the Web UI that way either."""
    _, h = await _user(db_session, role="DNS Editor")
    r = await client.post(
        f"{TLS}/csr",
        json={"name": f"csr-{uuid.uuid4().hex[:6]}", "common_name": "dot.example.com"},
        headers=h,
    )
    assert r.status_code == 201, r.text
    cert_id = r.json()["id"]
    # Sign the CSR with a throwaway CA so the import would otherwise succeed.
    csr = x509.load_pem_x509_csr(r.json()["csr_pem"].encode())
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test ca")])
    now = datetime.now(UTC)
    signed = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_name)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=90))
        .sign(ca_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )

    r = await client.post(f"{TLS}/{cert_id}/import-cert", json={"cert_pem": signed}, headers=h)
    assert r.status_code == 403, r.text
    db_session.expire_all()
    row = await db_session.get(ApplianceCertificate, uuid.UUID(cert_id))
    assert row is not None and row.cert_pem is None and row.is_active is False

    r = await client.post(
        f"{TLS}/{cert_id}/import-cert",
        json={"cert_pem": signed, "activate": False},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.json()["is_active"] is False


async def test_dns_editor_cannot_delete_the_active_web_ui_cert_on_an_appliance(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.core.crypto import encrypt_str

    pem, key = _chain("ui.example.com")
    web = ApplianceCertificate(
        name=f"web-{uuid.uuid4().hex[:6]}",
        source="uploaded",
        cert_pem=pem,
        key_encrypted=encrypt_str(key),
        is_active=True,
        subject_cn="ui.example.com",
        sans_json=["ui.example.com"],
    )
    db_session.add(web)
    await db_session.flush()
    web_id = web.id
    await db_session.commit()
    _, h = await _user(db_session, role="DNS Editor")
    monkeypatch.setattr(settings, "appliance_mode", True)

    r = await client.delete(f"{TLS}/{web_id}", headers=h)
    assert r.status_code == 409, r.text
    db_session.expire_all()
    assert await db_session.get(ApplianceCertificate, web_id) is not None


async def test_no_store_response_carries_key_material(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _user(db_session, role="DNS Editor")
    body = _upload_body(activate=False)
    r = await client.post(f"{TLS}/upload", json=body, headers=h)
    assert r.status_code == 201, r.text
    cert_id = r.json()["id"]
    for resp in (
        r,
        await client.get(TLS, headers=h),
        await client.get(f"{TLS}/{cert_id}", headers=h),
    ):
        assert "PRIVATE KEY" not in resp.text
        assert "key_encrypted" not in resp.text

    await client.put(
        f"{ACME}/account",
        json={
            "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
            "eab_kid": "kid",
            "eab_hmac_b64": "c2VjcmV0LWhtYWMtdmFsdWU",
        },
        headers=h,
    )
    r = await client.get(f"{ACME}/account", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["eab_hmac_set"] is True
    assert "c2VjcmV0LWhtYWMtdmFsdWU" not in r.text
    assert "account_key" not in r.text


async def test_seeding_grants_the_store_to_an_existing_dns_editor_role(
    db_session: AsyncSession,
) -> None:
    """Upgrade shape: the DNS Editor row exists from an older release without
    the store grant; the startup seed must add it, or upgraders never get it."""
    from app.main import _seed_builtin_roles

    old = [p for p in _BUILTIN_ROLES["DNS Editor"][1] if p["resource_type"] != "certificate_store"]
    existing = (
        await db_session.execute(select(Role).where(Role.name == "DNS Editor"))
    ).scalar_one_or_none()
    if existing is None:
        db_session.add(Role(name="DNS Editor", description="old", is_builtin=True, permissions=old))
    else:
        existing.permissions = old
    await db_session.commit()

    await _seed_builtin_roles()

    db_session.expire_all()
    role = (await db_session.execute(select(Role).where(Role.name == "DNS Editor"))).scalar_one()
    assert {"action": "admin", "resource_type": "certificate_store"} in role.permissions


async def _active_le_web_cert(db: AsyncSession) -> None:
    from app.core.crypto import encrypt_str

    pem, key = _chain("ui.example.com")
    db.add(
        ApplianceCertificate(
            name=f"letsencrypt-{uuid.uuid4().hex[:6]}",
            source="letsencrypt",
            cert_pem=pem,
            key_encrypted=encrypt_str(key),
            is_active=True,
            subject_cn="ui.example.com",
            sans_json=["ui.example.com"],
        )
    )
    await db.commit()


LE_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"


async def test_store_holder_cannot_repoint_the_account_renewing_the_web_ui_cert(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The renewal beat renews the active Let's Encrypt Web UI cert through the
    one ACME account and the api deploys it to nginx. A store-only caller must
    not decide which CA that is, or delete the account and let it lapse."""
    _, admin_h = await _user(
        db_session, permissions=[{"action": "admin", "resource_type": "appliance"}]
    )
    r = await client.put(f"{ACME}/account", json={"directory_url": LE_STAGING}, headers=admin_h)
    assert r.status_code == 200, r.text
    await _active_le_web_cert(db_session)
    monkeypatch.setattr(settings, "appliance_mode", True)
    _, h = await _user(db_session, role="DNS Editor")

    # Contact email only: harmless, allowed.
    r = await client.put(
        f"{ACME}/account",
        json={"directory_url": LE_STAGING, "email": "dns@example.com"},
        headers=h,
    )
    assert r.status_code == 200, r.text

    evil = "https://acme.attacker.example/directory"
    r = await client.put(f"{ACME}/account", json={"directory_url": evil}, headers=h)
    assert r.status_code == 403, r.text
    r = await client.put(
        f"{ACME}/account",
        json={"directory_url": LE_STAGING, "eab_kid": "k", "eab_hmac_b64": "aG1hYw"},
        headers=h,
    )
    assert r.status_code == 403, r.text
    assert (await client.delete(f"{ACME}/account", headers=h)).status_code == 403

    db_session.expire_all()
    account = (await db_session.execute(select(ACMEClientAccount))).scalar_one()
    assert account.directory_url == LE_STAGING
    assert account.eab_kid is None

    # The appliance admin still can.
    r = await client.put(f"{ACME}/account", json={"directory_url": evil}, headers=admin_h)
    assert r.status_code == 200, r.text
    assert (await client.delete(f"{ACME}/account", headers=admin_h)).status_code == 204


async def test_store_holder_manages_the_account_when_it_renews_no_web_ui_cert(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "appliance_mode", True)
    _, h = await _user(db_session, role="DNS Editor")
    r = await client.put(f"{ACME}/account", json={"directory_url": LE_STAGING}, headers=h)
    assert r.status_code == 200, r.text
    r = await client.put(
        f"{ACME}/account",
        json={"directory_url": "https://acme.zerossl.example/directory"},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert (await client.delete(f"{ACME}/account", headers=h)).status_code == 204
