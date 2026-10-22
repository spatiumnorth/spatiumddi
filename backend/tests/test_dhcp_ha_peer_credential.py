"""Kea HA peers authenticate to each other with a generated per-group credential.

Each DHCP server group holds a CA + peer certificate + key (Fernet-encrypted,
``services/dhcp/ha_peer_auth.py``). It reaches the agents in the config bundle
once every Kea member advertises ``ha_peer_tls``, and is never returned by the
API, the copilot tools or the audit log.
"""

from __future__ import annotations

import importlib.util
import pathlib
import uuid
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_dict
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.services.dhcp import agent_token as dhcp_tokens
from app.services.dhcp.config_bundle import build_config_bundle
from app.services.dhcp.ha_peer_auth import group_credential

_MIGRATION = (
    pathlib.Path(__file__).resolve().parents[1]
    / "alembic"
    / "versions"
    / "c8e1f5a92d47_dhcp_ha_peer_credential.py"
)


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"ha-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="HA Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _pair(
    db: AsyncSession, caps_a: list[str] | None, caps_b: list[str] | None
) -> tuple[DHCPServerGroup, DHCPServer, DHCPServer]:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:8]}", mode="hot-standby")
    db.add(grp)
    await db.flush()
    servers = []
    for label, caps, ip in (("a", caps_a, "10.0.0.1"), ("b", caps_b, "10.0.0.2")):
        srv = DHCPServer(
            name=f"{label}-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host=ip,
            port=67,
            server_group_id=grp.id,
            ha_peer_url=f"http://{ip}:8000/",
            agent_capabilities=caps,
            agent_id=uuid.uuid4(),
            agent_registered=True,
            agent_approved=True,
            agent_fingerprint="fp",
        )
        db.add(srv)
        servers.append(srv)
    await db.flush()
    await db.refresh(grp, ["servers"])
    return grp, servers[0], servers[1]


def _key_body(cred: dict[str, str]) -> str:
    # A line from the middle of the PEM — the part that is the secret.
    return cred["key_pem"].splitlines()[1]


# ── generation ───────────────────────────────────────────────────────────────


async def test_a_new_group_gets_an_encrypted_credential(db_session: AsyncSession) -> None:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:8]}")
    db_session.add(grp)
    await db_session.flush()

    token = grp.ha_peer_credential_encrypted
    assert token
    assert b"BEGIN" not in bytes(token)
    cred = decrypt_dict(bytes(token))

    ca = x509.load_pem_x509_certificate(cred["ca_pem"].encode())
    leaf = x509.load_pem_x509_certificate(cred["cert_pem"].encode())
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    # Signed by the group's CA, which is what Kea verifies against.
    leaf.verify_directly_issued_by(ca)
    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
    assert "PRIVATE KEY" in cred["key_pem"]
    # The CA's own key is not kept anywhere: the stored set is exactly these.
    assert set(cred) == {"ca_pem", "cert_pem", "key_pem"}


async def test_two_groups_never_share_a_credential(db_session: AsyncSession) -> None:
    g1 = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:8]}")
    g2 = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:8]}")
    db_session.add_all([g1, g2])
    await db_session.flush()
    c1, c2 = group_credential(g1), group_credential(g2)
    assert c1 and c2
    assert c1["ca_pem"] != c2["ca_pem"]
    assert c1["key_pem"] != c2["key_pem"]


# ── the bundle, and the gate ─────────────────────────────────────────────────


async def test_bundle_carries_the_credential_when_every_peer_supports_it(
    db_session: AsyncSession,
) -> None:
    grp, a, b = await _pair(db_session, ["ha_peer_tls"], ["ha_peer_tls"])
    cred = group_credential(grp)
    assert cred
    for srv in (a, b):
        bundle = await build_config_bundle(db_session, srv)
        assert bundle.failover is not None
        assert bundle.failover.tls_ca_pem == cred["ca_pem"]
        assert bundle.failover.tls_cert_pem == cred["cert_pem"]
        assert bundle.failover.tls_key_pem == cred["key_pem"]
        # ``repr`` of the bundle (what ends up in a traceback) omits it.
        assert _key_body(cred) not in repr(bundle)


@pytest.mark.parametrize(
    "caps_b",
    [None, [], ["something_else"]],
    ids=["never-reported", "older-agent", "other-capability"],
)
async def test_one_older_peer_keeps_the_whole_group_plaintext(
    db_session: AsyncSession, caps_b: list[str] | None
) -> None:
    """Kea's listener cannot accept TLS and plaintext at once, so a pair with
    one older agent must stay as it is on BOTH sides until it upgrades."""
    grp, a, b = await _pair(db_session, ["ha_peer_tls"], caps_b)
    for srv in (a, b):
        bundle = await build_config_bundle(db_session, srv)
        assert bundle.failover is not None
        assert bundle.failover.tls_key_pem is None
        assert bundle.failover.tls_cert_pem is None


async def test_the_gate_opening_and_a_rotation_both_shift_the_etag(
    db_session: AsyncSession,
) -> None:
    grp, a, b = await _pair(db_session, ["ha_peer_tls"], [])
    closed = (await build_config_bundle(db_session, a)).etag

    b.agent_capabilities = ["ha_peer_tls"]
    await db_session.flush()
    opened = (await build_config_bundle(db_session, a)).etag
    assert opened != closed

    from app.services.dhcp.ha_peer_auth import rotate_credential

    rotate_credential(grp)
    await db_session.flush()
    rotated = (await build_config_bundle(db_session, a)).etag
    assert rotated not in (closed, opened)


async def test_a_parked_long_poll_sees_the_partner_and_a_rotation_committed_elsewhere(
    db_session: AsyncSession,
) -> None:
    """The partner's long-poll keeps one session for its whole wait.

    Its group and peer rows are identity-map objects a later query does not
    overwrite, so the gate and the credential must be read from the database.
    The two changes below are made with raw SQL, as another request's commit
    would be — the ORM objects in this session never hear about them.
    """
    grp, a, b = await _pair(db_session, ["ha_peer_tls"], None)
    await db_session.commit()
    first = await build_config_bundle(db_session, a)
    assert first.failover is not None and first.failover.tls_key_pem is None

    # The partner's heartbeat reports the capability.
    await db_session.execute(
        text("UPDATE dhcp_server SET agent_capabilities = CAST(:caps AS jsonb) WHERE id = :id"),
        {"caps": '["ha_peer_tls"]', "id": b.id},
    )
    await db_session.refresh(a)  # what the long-poll loop does on each wake
    opened = await build_config_bundle(db_session, a)
    assert opened.failover is not None
    cred = group_credential(grp)
    assert cred and opened.failover.tls_key_pem == cred["key_pem"]

    # A rotation committed by the rotate endpoint.
    from app.services.dhcp.ha_peer_auth import encrypted_credential

    await db_session.execute(
        text("UPDATE dhcp_server_group SET ha_peer_credential_encrypted = :v WHERE id = :id"),
        {"v": encrypted_credential(), "id": grp.id},
    )
    await db_session.refresh(a)
    rotated = await build_config_bundle(db_session, a)
    assert rotated.failover is not None and rotated.failover.tls_key_pem
    assert rotated.failover.tls_key_pem != opened.failover.tls_key_pem
    assert rotated.etag != opened.etag


async def test_the_long_poll_wire_carries_the_credential(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp, a, b = await _pair(db_session, ["ha_peer_tls"], ["ha_peer_tls"])
    token, _exp = dhcp_tokens.mint_agent_token(
        server_id=str(a.id), agent_id=str(a.agent_id), fingerprint="fp"
    )
    a.agent_token_hash = dhcp_tokens.hash_token(token)
    cred = group_credential(grp)
    assert cred
    await db_session.commit()

    resp = await client.get(
        "/api/v1/dhcp/agents/config", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200, resp.text
    tls = resp.json()["bundle"]["failover"]["tls"]
    assert tls == {
        "ca_pem": cred["ca_pem"],
        "cert_pem": cred["cert_pem"],
        "key_pem": cred["key_pem"],
    }


# ── heartbeat records the capability ─────────────────────────────────────────


async def _agent_headers(db: AsyncSession, srv: DHCPServer) -> dict[str, str]:
    token, _exp = dhcp_tokens.mint_agent_token(
        server_id=str(srv.id), agent_id=str(srv.agent_id), fingerprint="fp"
    )
    srv.agent_token_hash = dhcp_tokens.hash_token(token)
    await db.commit()
    return {"Authorization": f"Bearer {token}"}


async def test_heartbeat_records_the_capability_and_an_older_agent_clears_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _grp, a, _b = await _pair(db_session, None, None)
    headers = await _agent_headers(db_session, a)

    resp = await client.post(
        "/api/v1/dhcp/agents/heartbeat", headers=headers, json={"capabilities": ["ha_peer_tls"]}
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(a)
    assert a.agent_capabilities == ["ha_peer_tls"]

    # A node rolled back to an agent that does not send the field.
    resp = await client.post("/api/v1/dhcp/agents/heartbeat", headers=headers, json={})
    assert resp.status_code == 200, resp.text
    await db_session.refresh(a)
    assert a.agent_capabilities == []


# ── never exposed ────────────────────────────────────────────────────────────


async def test_the_api_reports_only_whether_a_credential_exists(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    grp, _a, _b = await _pair(db_session, ["ha_peer_tls"], ["ha_peer_tls"])
    cred = group_credential(grp)
    assert cred
    await db_session.commit()

    one = await client.get(f"/api/v1/dhcp/server-groups/{grp.id}", headers=headers)
    assert one.status_code == 200, one.text
    body = one.json()
    assert body["ha_peer_credential_set"] is True
    assert body["ha_peer_auth_active"] is True
    listing = await client.get("/api/v1/dhcp/server-groups", headers=headers)
    assert listing.status_code == 200
    for text_ in (one.text, listing.text):
        assert "BEGIN" not in text_
        assert _key_body(cred) not in text_
        assert "ha_peer_credential_encrypted" not in text_


async def test_create_returns_no_credential(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _admin(db_session)
    await db_session.commit()
    resp = await client.post(
        "/api/v1/dhcp/server-groups", headers=headers, json={"name": f"g-{uuid.uuid4().hex[:6]}"}
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["ha_peer_credential_set"] is True
    assert resp.json()["ha_peer_auth_active"] is False
    assert "BEGIN" not in resp.text


async def test_rotate_replaces_the_credential_and_audits_without_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    grp, _a, _b = await _pair(db_session, ["ha_peer_tls"], ["ha_peer_tls"])
    before = group_credential(grp)
    assert before
    group_id = grp.id
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/dhcp/server-groups/{group_id}/ha-peer-credential/rotate", headers=headers
    )
    assert resp.status_code == 200, resp.text
    assert "BEGIN" not in resp.text

    db_session.expire_all()
    reloaded = await db_session.get(DHCPServerGroup, group_id)
    assert reloaded is not None
    after = group_credential(reloaded)
    assert after and after["key_pem"] != before["key_pem"]
    assert after["ca_pem"] != before["ca_pem"]

    audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "rotate", AuditLog.resource_id == str(group_id)
            )
        )
    ).scalar_one()
    blob = f"{audit.old_value} {audit.new_value} {audit.changed_fields}"
    assert _key_body(after) not in blob and _key_body(before) not in blob
    assert "BEGIN" not in blob


async def test_rotate_needs_a_superadmin(client: AsyncClient, db_session: AsyncSession) -> None:
    user = User(
        username=f"ro-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Viewer",
        hashed_password=hash_password("x"),
    )
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add_all([user, grp])
    await db_session.commit()
    resp = await client.post(
        f"/api/v1/dhcp/server-groups/{grp.id}/ha-peer-credential/rotate",
        headers={"Authorization": f"Bearer {create_access_token(str(user.id))}"},
    )
    assert resp.status_code == 403, resp.text


async def test_the_copilot_group_listing_omits_the_credential(db_session: AsyncSession) -> None:
    from app.services.ai.tools.dhcp import ListServerGroupsArgs, list_dhcp_server_groups

    grp, _a, _b = await _pair(db_session, ["ha_peer_tls"], ["ha_peer_tls"])
    cred = group_credential(grp)
    assert cred
    rows: list[dict[str, Any]] = await list_dhcp_server_groups(
        db_session, None, ListServerGroupsArgs()  # type: ignore[arg-type]
    )
    row = next(r for r in rows if r["id"] == str(grp.id))
    assert row["ha_peer_credential_set"] is True
    assert _key_body(cred) not in repr(rows)
    assert "BEGIN" not in repr(rows)


# ── the migration's backfill ─────────────────────────────────────────────────


async def test_the_migration_backfills_every_existing_group(db_session: AsyncSession) -> None:
    """Replay the upgrade against the pre-migration shape. The DDL runs in the
    test's transaction, which the fixture rolls back; nothing commits."""
    spec = importlib.util.spec_from_file_location("m_c8e1f5a92d47", _MIGRATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    ids = []
    for _ in range(2):
        g = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
        db_session.add(g)
        await db_session.flush()
        ids.append(g.id)

    await db_session.execute(
        text("ALTER TABLE dhcp_server_group DROP COLUMN ha_peer_credential_encrypted")
    )
    await db_session.execute(text("ALTER TABLE dhcp_server DROP COLUMN agent_capabilities"))

    def _upgrade(sync_conn) -> None:  # noqa: ANN001
        from alembic.migration import MigrationContext
        from alembic.operations import Operations

        ctx = MigrationContext.configure(sync_conn)
        with Operations.context(ctx):
            module.upgrade()

    conn = await db_session.connection()
    await conn.run_sync(_upgrade)

    rows = (
        await db_session.execute(
            text(
                "SELECT id, ha_peer_credential_encrypted FROM dhcp_server_group "
                "WHERE id = ANY(:ids)"
            ),
            {"ids": ids},
        )
    ).all()
    assert len(rows) == 2
    keys = set()
    for _id, token in rows:
        assert token is not None
        cred = decrypt_dict(bytes(token))
        key = x509.load_pem_x509_certificate(cred["cert_pem"].encode()).public_key()
        assert isinstance(key, ec.EllipticCurvePublicKey)
        keys.add(cred["key_pem"])
    assert len(keys) == 2, "each group gets its own credential"
    caps_col = (
        await db_session.execute(
            text(
                "SELECT count(*) FROM information_schema.columns "
                "WHERE table_name = 'dhcp_server' AND column_name = 'agent_capabilities'"
            )
        )
    ).scalar_one()
    assert caps_col == 1
