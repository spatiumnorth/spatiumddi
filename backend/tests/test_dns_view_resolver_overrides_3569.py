"""Per-view dnssec-validation / allow-recursion / rate-limit / minimal-responses (#3569).

Assert on the API's answers, what is stored, and the bundle an agent would
render, never on the validator itself.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSServerOptions, DNSTrustAnchor
from app.services.dns.agent_config import build_config_bundle

_KEY = "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3"


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


async def _anchor(db: AsyncSession, group: DNSServerGroup) -> None:
    opts = DNSServerOptions(group_id=group.id)
    db.add(opts)
    await db.flush()
    db.add(
        DNSTrustAnchor(
            server_options_id=opts.id,
            zone_name=".",
            algorithm=8,
            key_tag=20326,
            public_key=_KEY,
            is_initial_key=True,
            added_at=datetime.now(UTC),
        )
    )
    await db.flush()


async def _post(client: AsyncClient, hdr: dict, gid: Any, name: str, **extra: Any) -> Any:
    return await client.post(
        f"/api/v1/dns/groups/{gid}/views",
        headers=hdr,
        json={"name": name, "match_clients": ["any"], **extra},
    )


async def _views_in_bundle(
    db: AsyncSession, group_id: Any, driver: str = "bind9"
) -> dict[str, dict[str, Any]]:
    server = (
        (
            await db.execute(
                select(DNSServer).where(DNSServer.group_id == group_id, DNSServer.driver == driver)
            )
        )
        .scalars()
        .first()
    )
    assert server is not None
    bundle = await build_config_bundle(db, server)
    return {v["name"]: v for v in bundle["views"]}


async def test_overrides_are_stored_audited_and_shipped(
    client: AsyncClient, db_session: AsyncSession
):
    hdr = await _admin(db_session)
    group = await _group(db_session)
    r = await _post(
        client,
        hdr,
        group.id,
        "internal",
        dnssec_validation="auto",
        allow_recursion=["10.0.0.0/8", "localhost"],
        rrl_enabled=True,
        rrl_responses_per_second=5,
        rrl_window=20,
        rrl_slip=1,
        minimal_responses=True,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["dnssec_validation"] == "auto"
    assert body["allow_recursion"] == ["10.0.0.0/8", "localhost"]
    assert body["rrl_responses_per_second"] == 5
    assert (await _post(client, hdr, group.id, "plain")).json()["rrl_enabled"] is None

    views = await _views_in_bundle(db_session, group.id)
    internal = views["internal"]
    assert internal["dnssec_validation"] == "auto"
    assert internal["allow_recursion"] == ["10.0.0.0/8", "localhost"]
    assert internal["rrl_enabled"] is True
    assert (internal["rrl_responses_per_second"], internal["rrl_window"]) == (5, 20)
    assert internal["rrl_slip"] == 1
    assert internal["minimal_responses"] is True
    # A view that sets none ships none, so its entry (and the ETag) is as before.
    for key in (
        "dnssec_validation",
        "allow_recursion",
        "rrl_enabled",
        "rrl_window",
        "minimal_responses",
    ):
        assert key not in views["plain"]


async def test_update_changes_the_bundle_and_null_inherits(
    client: AsyncClient, db_session: AsyncSession
):
    hdr = await _admin(db_session)
    group = await _group(db_session)
    vid = (await _post(client, hdr, group.id, "v")).json()["id"]
    url = f"/api/v1/dns/groups/{group.id}/views/{vid}"

    r = await client.put(
        url, headers=hdr, json={"minimal_responses": False, "dnssec_validation": "no"}
    )
    assert r.status_code == 200, r.text
    v = (await _views_in_bundle(db_session, group.id))["v"]
    # False is an override, not "unset".
    assert v["minimal_responses"] is False
    assert v["dnssec_validation"] == "no"
    audit = (
        (await db_session.execute(select(AuditLog).where(AuditLog.resource_id == vid)))
        .scalars()
        .all()
    )
    assert any("minimal_responses" in (a.changed_fields or []) for a in audit)

    r = await client.put(url, headers=hdr, json={"description": "x"})
    assert r.json()["dnssec_validation"] == "no"
    r = await client.put(
        url, headers=hdr, json={"minimal_responses": None, "dnssec_validation": None}
    )
    assert r.json()["minimal_responses"] is None
    assert r.json()["dnssec_validation"] is None
    v = (await _views_in_bundle(db_session, group.id))["v"]
    assert "minimal_responses" not in v and "dnssec_validation" not in v

    await client.put(url, headers=hdr, json={"allow_recursion": ["any"]})
    r = await client.put(url, headers=hdr, json={"allow_recursion": []})
    assert r.json()["allow_recursion"] is None


async def test_bad_values_are_refused(client: AsyncClient, db_session: AsyncSession):
    hdr = await _admin(db_session)
    group = await _group(db_session)
    assert (await _post(client, hdr, group.id, "a", dnssec_validation="maybe")).status_code == 422
    for bad in ("not an acl", "10.0.0.0/8; }; include x"):
        r = await _post(client, hdr, group.id, "a", allow_recursion=[bad])
        assert r.status_code == 422, (bad, r.text)
        assert r.json()["detail"]["field"] == "allow_recursion"
    for field, value in (
        ("rrl_responses_per_second", 0),
        ("rrl_window", 0),
        ("rrl_slip", 11),
    ):
        assert (await _post(client, hdr, group.id, "a", **{field: value})).status_code == 422


async def test_yes_needs_a_trust_anchor(client: AsyncClient, db_session: AsyncSession):
    hdr = await _admin(db_session)
    group = await _group(db_session)
    r = await _post(client, hdr, group.id, "a", dnssec_validation="yes")
    assert r.status_code == 422, r.text
    assert "trust anchor" in r.text.lower()
    anchored = await _group(db_session)
    await _anchor(db_session, anchored)
    assert (await _post(client, hdr, anchored.id, "a", dnssec_validation="yes")).status_code == 201


async def test_groups_with_other_drivers_refuse_overrides(
    client: AsyncClient, db_session: AsyncSession
):
    hdr = await _admin(db_session)
    group = await _group(db_session, "bind9", "powerdns")
    for extra in (
        {"dnssec_validation": "no"},
        {"allow_recursion": ["any"]},
        {"rrl_enabled": True},
        {"minimal_responses": True},
    ):
        r = await _post(client, hdr, group.id, "v", **extra)
        assert r.status_code == 422, (extra, r.text)
        assert "BIND9" in r.text
    # A view that overrides nothing is fine anywhere, and a pdns bundle never
    # carries the keys even if a row holds them.
    assert (await _post(client, hdr, group.id, "v")).status_code == 201
    only_pdns = await _group(db_session, "powerdns")
    assert (await _post(client, hdr, only_pdns.id, "v", rrl_enabled=True)).status_code == 422
