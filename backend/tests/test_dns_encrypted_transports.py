"""DoT / DoH listeners + encrypted upstream forwarding (issue #50).

Covers the two control-plane halves:

* the ``PUT /dns/groups/{id}/options`` validation gate, which turns configs
  BIND would reject at load time (or ports that can't bind) into a 422 the
  operator can read;
* config-bundle cert delivery, including the invariant that a group with no
  encrypted listener never carries cert material at all.

The rendering itself is covered agent-side in
``agent/dns/tests/test_encrypted_transport_render.py``.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.appliance import ApplianceCertificate
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSServerOptions
from app.services.dns.agent_config import build_config_bundle

CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIB-test-leaf\n-----END CERTIFICATE-----\n"
KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMIIE-test-key\n-----END PRIVATE KEY-----\n"


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="sa",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _group(db: AsyncSession) -> DNSServerGroup:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    db.add(DNSServer(group_id=group.id, name="ns1", driver="bind9", host="10.0.0.53", port=53))
    await db.flush()
    return group


async def _cert(db: AsyncSession, *, cert_pem: str | None = CERT_PEM) -> ApplianceCertificate:
    row = ApplianceCertificate(
        name=f"c-{uuid.uuid4().hex[:6]}",
        source="upload",
        cert_pem=cert_pem,
        key_encrypted=encrypt_str(KEY_PEM),
        subject_cn="dns.example.test",
        sans_json=["dns.example.test"],
    )
    db.add(row)
    await db.flush()
    return row


# ── Validation gate ─────────────────────────────────────────────────────


async def test_defaults_are_off(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    await db_session.commit()

    r = await client.get(f"/api/v1/dns/groups/{group.id}/options", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["dot_enabled"] is False
    assert body["doh_enabled"] is False
    assert body["dot_port"] == 853
    assert body["doh_port"] == 443
    assert body["doh_path"] == "/dns-query"
    assert body["forward_transport"] == "do53"
    assert body["tls_certificate_id"] is None


async def test_enabling_listener_without_cert_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        headers=headers,
        json={"dot_enabled": True},
    )
    assert r.status_code == 422
    assert "certificate" in r.json()["detail"].lower()
    # #3045: Web UI Certificate is an entry under Appliance -> Fleet, not an
    # Appliance tab; the refusal names it by its real path.
    assert "Appliance → Fleet → Web UI Certificate" in r.json()["detail"]


async def test_enabling_listener_with_csr_pending_cert_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """``cert_pem IS NULL`` is the canonical CSR-pending sentinel — the
    operator generated a CSR but hasn't pasted the signed cert back, so
    there is nothing to serve yet."""
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    cert = await _cert(db_session, cert_pem=None)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        headers=headers,
        json={"dot_enabled": True, "tls_certificate_id": str(cert.id)},
    )
    assert r.status_code == 422
    assert "csr pending" in r.json()["detail"].lower()


async def test_enable_dot_with_cert_succeeds(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    cert = await _cert(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        headers=headers,
        json={"dot_enabled": True, "tls_certificate_id": str(cert.id)},
    )
    assert r.status_code == 200, r.text
    assert r.json()["dot_enabled"] is True
    assert r.json()["tls_certificate_id"] == str(cert.id)


async def test_validation_runs_against_merged_state(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Setting the cert and enabling the listener in two separate calls must
    be accepted exactly like one combined call."""
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    cert = await _cert(db_session)
    await db_session.commit()

    r1 = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        headers=headers,
        json={"tls_certificate_id": str(cert.id)},
    )
    assert r1.status_code == 200
    r2 = await client.put(
        f"/api/v1/dns/groups/{group.id}/options", headers=headers, json={"doh_enabled": True}
    )
    assert r2.status_code == 200, r2.text


async def test_listener_port_53_is_422(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    cert = await _cert(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        headers=headers,
        json={"dot_enabled": True, "dot_port": 53, "tls_certificate_id": str(cert.id)},
    )
    assert r.status_code == 422
    assert "53" in r.json()["detail"]


async def test_dot_and_doh_on_same_port_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    cert = await _cert(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        headers=headers,
        json={
            "dot_enabled": True,
            "dot_port": 8443,
            "doh_enabled": True,
            "doh_port": 8443,
            "tls_certificate_id": str(cert.id),
        },
    )
    assert r.status_code == 422
    assert "differ" in r.json()["detail"]


async def test_forward_tls_without_hostname_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Strict validation with no name to check against isn't validation."""
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        headers=headers,
        json={"forward_transport": "tls", "forward_tls_verify": True},
    )
    assert r.status_code == 422
    assert "forward_tls_hostname" in r.json()["detail"]


async def test_forward_tls_opportunistic_needs_no_hostname(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        headers=headers,
        json={"forward_transport": "tls", "forward_tls_verify": False},
    )
    assert r.status_code == 200, r.text


async def test_forward_transport_https_rejected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """BIND has no client-side HTTP transport, so DoH-upstream is not
    expressible — better a 422 than a config that silently forwards
    plaintext."""
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        headers=headers,
        json={"forward_transport": "https"},
    )
    assert r.status_code == 422


async def test_doh_path_must_be_absolute(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        headers=headers,
        json={"doh_path": "dns-query"},
    )
    assert r.status_code == 422


async def test_clearing_cert_link_survives_exclude_none(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Un-linking the cert (before deleting the cert row) has to be
    expressible — ``exclude_none`` would otherwise drop the explicit null."""
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    cert = await _cert(db_session)
    await db_session.commit()

    await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        headers=headers,
        json={"tls_certificate_id": str(cert.id)},
    )
    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        headers=headers,
        json={"tls_certificate_id": None},
    )
    assert r.status_code == 200, r.text
    assert r.json()["tls_certificate_id"] is None


# ── Config-bundle cert delivery ─────────────────────────────────────────


async def _server_for(db: AsyncSession, group: DNSServerGroup) -> DNSServer:
    row = (
        await db.execute(DNSServer.__table__.select().where(DNSServer.group_id == group.id))
    ).first()
    assert row is not None
    return await db.get(DNSServer, row.id)  # type: ignore[arg-type,return-value]


async def test_bundle_ships_cert_when_listener_enabled(db_session: AsyncSession) -> None:
    group = await _group(db_session)
    cert = await _cert(db_session)
    db_session.add(
        DNSServerOptions(group_id=group.id, dot_enabled=True, tls_certificate_id=cert.id)
    )
    await db_session.flush()
    server = await _server_for(db_session, group)

    bundle = await build_config_bundle(db_session, server)
    tls = bundle["tls_cert"]  # type: ignore[typeddict-item]
    assert tls is not None
    assert tls["cert_pem"] == CERT_PEM
    # The key is Fernet-encrypted at rest and decrypted only for the bundle.
    assert tls["key_pem"] == KEY_PEM


async def test_bundle_omits_cert_when_listeners_off(db_session: AsyncSession) -> None:
    """A group that points at a cert but hasn't enabled a listener must not
    carry key material — no reason to put a private key on the wire."""
    group = await _group(db_session)
    cert = await _cert(db_session)
    db_session.add(DNSServerOptions(group_id=group.id, tls_certificate_id=cert.id))
    await db_session.flush()
    server = await _server_for(db_session, group)

    bundle = await build_config_bundle(db_session, server)
    assert bundle["tls_cert"] is None  # type: ignore[typeddict-item]


async def test_cert_rotation_shifts_etag(db_session: AsyncSession) -> None:
    """Renewal rewrites cert_pem in place. If that didn't move the etag the
    agent would keep serving the expired cert until something else changed."""
    group = await _group(db_session)
    cert = await _cert(db_session)
    db_session.add(
        DNSServerOptions(group_id=group.id, dot_enabled=True, tls_certificate_id=cert.id)
    )
    await db_session.flush()
    server = await _server_for(db_session, group)

    before = await build_config_bundle(db_session, server)
    cert.cert_pem = CERT_PEM.replace("test-leaf", "renewed-leaf")
    await db_session.flush()
    after = await build_config_bundle(db_session, server)

    assert before["etag"] != after["etag"]
    assert before["structural_etag"] != after["structural_etag"]


# ── Reserved / conflicting ports (code-review #4) ───────────────────────


async def test_listener_on_rndc_port_is_422(client: AsyncClient, db_session: AsyncSession) -> None:
    """953 is rndc's control channel and 8053 the statistics channel — both
    hardcoded on loopback in every rendered named.conf. The listeners bind
    ``any`` (which includes loopback), so either would break the daemon
    outright rather than degrading to Do53."""
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    cert = await _cert(db_session)
    await db_session.commit()

    for port in (953, 8053):
        r = await client.put(
            f"/api/v1/dns/groups/{group.id}/options",
            headers=headers,
            json={"dot_enabled": True, "dot_port": port, "tls_certificate_id": str(cert.id)},
        )
        assert r.status_code == 422, f"port {port} should be rejected"
        assert str(port) in r.json()["detail"]


async def test_doh_path_over_column_length_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Longer than String(128) — must 422 at the boundary, not 500 on
    asyncpg's StringDataRightTruncation at commit."""
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        headers=headers,
        json={"doh_path": "/" + "a" * 200},
    )
    assert r.status_code == 422


async def test_forward_tls_hostname_over_column_length_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        headers=headers,
        json={"forward_transport": "tls", "forward_tls_hostname": "h" * 300},
    )
    assert r.status_code == 422


# ── Certificate in-use guard (code-review #5) ───────────────────────────


async def test_delete_cert_in_use_by_listener_is_409(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The FK is ON DELETE SET NULL, so without this guard deleting a cert
    silently drops every encrypted-DNS client in the group with nothing
    warning the operator."""
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    cert = await _cert(db_session)
    db_session.add(
        DNSServerOptions(group_id=group.id, dot_enabled=True, tls_certificate_id=cert.id)
    )
    await db_session.commit()

    r = await client.delete(f"/api/v1/appliance/tls/{cert.id}", headers=headers)
    assert r.status_code == 409, r.text
    # The message must name what's blocking it, not just refuse.
    assert group.name in r.json()["detail"]


async def test_delete_cert_linked_but_listeners_off_succeeds(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A group pointing at the cert with both listeners OFF isn't serving
    anything, so the delete must not be blocked."""
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    cert = await _cert(db_session)
    db_session.add(DNSServerOptions(group_id=group.id, tls_certificate_id=cert.id))
    await db_session.commit()

    r = await client.delete(f"/api/v1/appliance/tls/{cert.id}", headers=headers)
    assert r.status_code == 204, r.text


# ── MCP read tool (#2887) ───────────────────────────────────────────────


async def test_find_dns_encrypted_transports_reports_doq(db_session: AsyncSession) -> None:
    """The copilot read must carry the DoQ toggle + port, like dot_* / doh_*."""
    from app.services.ai.tools.dns import (  # noqa: PLC0415
        FindDNSEncryptedTransportsArgs,
        find_dns_encrypted_transports,
    )

    user = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="sa",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db_session.add(user)
    group = await _group(db_session)
    db_session.add(DNSServerOptions(group_id=group.id, doq_enabled=True, doq_port=8853))
    await db_session.flush()

    out = await find_dns_encrypted_transports(
        db_session, user, FindDNSEncryptedTransportsArgs(group_id=str(group.id))
    )
    assert out["count"] == 1
    row = out["groups"][0]
    assert row["doq_enabled"] is True
    assert row["doq_port"] == 8853


async def _tool_row(db: AsyncSession, group_id: uuid.UUID) -> tuple[dict, dict]:
    from app.services.ai.tools.dns import (  # noqa: PLC0415
        FindDNSEncryptedTransportsArgs,
        find_dns_encrypted_transports,
    )

    user = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="sa",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    out = await find_dns_encrypted_transports(
        db, user, FindDNSEncryptedTransportsArgs(group_id=str(group_id))
    )
    return out["groups"][0], out["summary"]


async def _technitium_group(db: AsyncSession) -> DNSServerGroup:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    db.add(DNSServer(group_id=group.id, name="t1", driver="technitium", host="10.0.0.54", port=53))
    await db.flush()
    return group


async def test_tool_doq_only_technitium_group_is_effective(db_session: AsyncSession) -> None:
    group = await _technitium_group(db_session)
    cert = await _cert(db_session)
    db_session.add(
        DNSServerOptions(group_id=group.id, doq_enabled=True, tls_certificate_id=cert.id)
    )
    await db_session.flush()

    row, summary = await _tool_row(db_session, group.id)
    assert row["listeners_effective"] is True
    assert summary["groups_serving_encrypted"] == 1
    assert summary["groups_with_broken_listener"] == 0


async def test_tool_doq_only_without_cert_is_broken_listener(db_session: AsyncSession) -> None:
    group = await _technitium_group(db_session)
    db_session.add(DNSServerOptions(group_id=group.id, doq_enabled=True))
    await db_session.flush()

    row, summary = await _tool_row(db_session, group.id)
    assert row["listeners_effective"] is False
    assert summary["groups_with_broken_listener"] == 1


async def test_tool_stale_doq_on_bind9_is_not_effective(db_session: AsyncSession) -> None:
    """A row stored before the driver gate must not read as a serving DoQ listener."""
    group = await _group(db_session)  # bind9
    cert = await _cert(db_session)
    db_session.add(
        DNSServerOptions(group_id=group.id, doq_enabled=True, tls_certificate_id=cert.id)
    )
    await db_session.flush()

    row, summary = await _tool_row(db_session, group.id)
    assert row["doq_enabled"] is True
    assert row["listeners_effective"] is False
    assert summary["groups_serving_encrypted"] == 0
    assert summary["groups_with_broken_listener"] == 0
