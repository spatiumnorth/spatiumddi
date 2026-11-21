"""A view's own default forwarders (#3523).

BIND takes ``forwarders`` / ``forward`` inside a ``view { }`` block. These
tests assert on the API's answers, what is stored, and the bundle an agent
would render, never on the validator itself.
"""

from __future__ import annotations

import uuid
from typing import Any

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup
from app.services.dns.agent_config import build_config_bundle


async def _admin(db: AsyncSession) -> dict[str, str]:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"a-{tag}",
        email=f"{tag}@example.com",
        display_name="A",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group(db: AsyncSession, *drivers: str) -> DNSServerGroup:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(group)
    await db.flush()
    for i, driver in enumerate(drivers or ("bind9",)):
        db.add(
            DNSServer(group_id=group.id, name=f"ns{i}", driver=driver, host="127.0.0.1", port=53)
        )
    await db.flush()
    return group


async def _post(client: AsyncClient, hdr: dict, gid: Any, name: str, **extra: Any) -> Any:
    return await client.post(
        f"/api/v1/dns/groups/{gid}/views",
        headers=hdr,
        json={"name": name, "match_clients": ["any"], **extra},
    )


async def _views_in_bundle(db: AsyncSession, group_id: Any) -> dict[str, dict[str, Any]]:
    server = (
        (await db.execute(select(DNSServer).where(DNSServer.group_id == group_id)))
        .scalars()
        .first()
    )
    assert server is not None
    bundle = await build_config_bundle(db, server)
    return {v["name"]: v for v in bundle["views"]}


async def test_view_forwarders_are_stored_audited_and_shipped(
    client: AsyncClient, db_session: AsyncSession
):
    hdr = await _admin(db_session)
    group = await _group(db_session)
    r = await _post(
        client,
        hdr,
        group.id,
        "guest",
        forwarders=["1.1.1.3", " 1.0.0.3 @ 5353"],
        forward_policy="only",
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["forwarders"] == ["1.1.1.3", "1.0.0.3@5353"]
    assert body["forward_policy"] == "only"
    assert body["forward_transport"] == "do53"
    assert (await _post(client, hdr, group.id, "staff")).json()["forwarders"] is None

    views = await _views_in_bundle(db_session, group.id)
    assert views["guest"]["forwarders"] == ["1.1.1.3", "1.0.0.3@5353"]
    assert views["guest"]["forward_policy"] == "only"
    # A view with none ships nothing, so its entry (and the ETag) is as before.
    assert "forwarders" not in views["staff"]
    assert "forward_transport" not in views["guest"]


async def test_updating_forwarders_moves_the_bundle_and_clearing_inherits(
    client: AsyncClient, db_session: AsyncSession
):
    hdr = await _admin(db_session)
    group = await _group(db_session)
    vid = (await _post(client, hdr, group.id, "guest")).json()["id"]
    url = f"/api/v1/dns/groups/{group.id}/views/{vid}"

    r = await client.put(url, headers=hdr, json={"forwarders": ["9.9.9.9"]})
    assert r.status_code == 200, r.text
    assert (await _views_in_bundle(db_session, group.id))["guest"]["forwarders"] == ["9.9.9.9"]
    audit = (
        (await db_session.execute(select(AuditLog).where(AuditLog.resource_id == vid)))
        .scalars()
        .all()
    )
    assert any("forwarders" in (a.changed_fields or []) for a in audit)

    # Unrelated edits leave them alone; null clears back to inheriting.
    r = await client.put(url, headers=hdr, json={"description": "x"})
    assert r.json()["forwarders"] == ["9.9.9.9"]
    r = await client.put(url, headers=hdr, json={"forwarders": None})
    assert r.json()["forwarders"] is None
    assert "forwarders" not in (await _views_in_bundle(db_session, group.id))["guest"]
    r = await client.put(url, headers=hdr, json={"forwarders": ["9.9.9.9"]})
    r = await client.put(url, headers=hdr, json={"forwarders": []})
    assert r.json()["forwarders"] is None


async def test_bad_forwarders_are_refused_with_the_element(
    client: AsyncClient, db_session: AsyncSession
):
    hdr = await _admin(db_session)
    group = await _group(db_session)
    for bad in ("not-an-ip", "1.1.1.1@99999", '1.1.1.1; }; include "x'):
        r = await _post(client, hdr, group.id, "guest", forwarders=[bad])
        assert r.status_code == 422, (bad, r.text)
        assert r.json()["detail"]["field"] == "forwarders"
    r = await _post(client, hdr, group.id, "guest", forwarders=["1.1.1.1"], forward_policy="x")
    assert r.status_code == 422


async def test_view_tls_forwarders_follow_the_group_rules(
    client: AsyncClient, db_session: AsyncSession
):
    hdr = await _admin(db_session)
    group = await _group(db_session)
    # TLS needs the certificate name.
    r = await _post(client, hdr, group.id, "a", forwarders=["1.1.1.3"], forward_transport="tls")
    assert r.status_code == 422
    # BIND has no DoH / DoQ client.
    r = await _post(
        client,
        hdr,
        group.id,
        "a",
        forwarders=["1.1.1.3"],
        forward_transport="https",
        forward_tls_hostname="family.cloudflare-dns.com",
    )
    assert r.status_code == 422
    # One certificate name per forwarder set (#877).
    r = await _post(
        client,
        hdr,
        group.id,
        "a",
        forwarders=["1.1.1.1", "8.8.8.8"],
        forward_transport="tls",
        forward_tls_hostname="one.one.one.one",
    )
    assert r.status_code == 422
    # An encrypted-only upstream over plain DNS (Mullvad).
    r = await _post(client, hdr, group.id, "a", forwarders=["194.242.2.4"])
    assert r.status_code == 422
    r = await _post(
        client,
        hdr,
        group.id,
        "a",
        forwarders=["1.1.1.3"],
        forward_transport="tls",
        forward_tls_hostname="family.cloudflare-dns.com",
    )
    assert r.status_code == 201, r.text
    view = (await _views_in_bundle(db_session, group.id))["a"]
    assert view["forward_transport"] == "tls"
    assert view["forward_tls_hostname"] == "family.cloudflare-dns.com"


async def test_groups_with_other_drivers_refuse_view_forwarders(
    client: AsyncClient, db_session: AsyncSession
):
    hdr = await _admin(db_session)
    group = await _group(db_session, "bind9", "powerdns")
    r = await _post(client, hdr, group.id, "guest", forwarders=["1.1.1.3"])
    assert r.status_code == 422
    assert "BIND9" in r.text
    # A view without them is fine anywhere.
    assert (await _post(client, hdr, group.id, "guest")).status_code == 201
    pdns = await _group(db_session, "technitium")
    assert (await _post(client, hdr, pdns.id, "g", forwarders=["1.1.1.3"])).status_code == 422
