"""``GET /dns/blocklists/match`` and the RPZ carve-out it relies on (#4250).

The query-details modal asks "is this name blocked for this group / view,
and by which list?" before it offers Block or Allow. The verdict must agree
with what the renderers emit, so the carve-out tests render the same data.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User
from app.models.dns import (
    DNSBlockList,
    DNSBlockListEntry,
    DNSBlockListException,
    DNSServerGroup,
    DNSView,
)
from app.services.dns_blocklist import build_effective_for_group

URL = "/api/v1/dns/blocklists/match"


async def _su(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"su-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="su",
        hashed_password=hash_password("x"),
        is_superadmin=True,
        force_password_change=False,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _scoped(db: AsyncSession, perms: list[dict[str, str]]) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="u",
        hashed_password=hash_password("x"),
        is_superadmin=False,
        force_password_change=False,
    )
    db.add(user)
    await db.flush()
    role = Role(name=f"r-{uuid.uuid4().hex[:6]}", description="", permissions=perms)
    db.add(role)
    await db.flush()
    group = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    group.roles = [role]
    group.users = [user]
    db.add(group)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _list(
    db: AsyncSession,
    name: str,
    *,
    group: DNSServerGroup | None = None,
    view: DNSView | None = None,
    enabled: bool = True,
    source_type: str = "manual",
) -> DNSBlockList:
    bl = DNSBlockList(name=name, enabled=enabled, source_type=source_type)
    if group is not None:
        bl.server_groups = [group]
    if view is not None:
        bl.views = [view]
    db.add(bl)
    await db.flush()
    return bl


def _entry(
    bl: DNSBlockList, domain: str, *, wildcard: bool, source: str = "manual"
) -> DNSBlockListEntry:
    return DNSBlockListEntry(list_id=bl.id, domain=domain, is_wildcard=wildcard, source=source)


@pytest.fixture
async def grp(db_session: AsyncSession) -> DNSServerGroup:
    g = DNSServerGroup(name=f"grp-{uuid.uuid4().hex[:6]}")
    db_session.add(g)
    await db_session.flush()
    return g


async def _get(client: AsyncClient, h: dict[str, str], **params: str) -> dict:
    r = await client.get(URL, params=params, headers=h)
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.asyncio
async def test_wildcard_parent_matches_subdomain(
    client: AsyncClient, db_session: AsyncSession, grp: DNSServerGroup
) -> None:
    h = await _su(db_session)
    bl = await _list(db_session, "wc", group=grp)
    db_session.add(_entry(bl, "example.com", wildcard=True))
    await db_session.commit()

    body = await _get(client, h, domain="Ads.Tracker.Example.com.", group_id=str(grp.id))
    assert body["domain"] == "ads.tracker.example.com"
    assert body["effective"] == "blocked"
    [m] = body["matches"]
    assert (m["entry_domain"], m["is_wildcard"], m["applies_here"], m["excepted"]) == (
        "example.com",
        True,
        True,
        False,
    )
    assert m["list_name"] == "wc"


@pytest.mark.asyncio
async def test_exact_entry_does_not_match_a_subdomain(
    client: AsyncClient, db_session: AsyncSession, grp: DNSServerGroup
) -> None:
    h = await _su(db_session)
    bl = await _list(db_session, "exact", group=grp)
    db_session.add(_entry(bl, "example.com", wildcard=False))
    await db_session.commit()

    sub = await _get(client, h, domain="www.example.com", group_id=str(grp.id))
    assert sub["effective"] == "none" and sub["matches"] == []
    apex = await _get(client, h, domain="example.com", group_id=str(grp.id))
    assert apex["effective"] == "blocked"


@pytest.mark.asyncio
async def test_exception_for_the_subdomain_carves_out_of_a_wildcard_parent(
    client: AsyncClient, db_session: AsyncSession, grp: DNSServerGroup
) -> None:
    h = await _su(db_session)
    bl = await _list(db_session, "carve", group=grp)
    db_session.add(_entry(bl, "example.com", wildcard=True))
    db_session.add(DNSBlockListException(list_id=bl.id, domain="a.example.com"))
    await db_session.commit()

    carved = await _get(client, h, domain="a.example.com", group_id=str(grp.id))
    assert carved["effective"] == "allowed"
    assert carved["matches"][0]["excepted"] is True
    assert [e["domain"] for e in carved["exceptions"]] == ["a.example.com"]
    # The exception also frees names under it, and nothing else.
    assert (await _get(client, h, domain="x.a.example.com", group_id=str(grp.id)))[
        "effective"
    ] == "allowed"
    for still in ("b.example.com", "example.com"):
        assert (await _get(client, h, domain=still, group_id=str(grp.id)))["effective"] == "blocked"


@pytest.mark.asyncio
async def test_more_specific_entry_beats_a_parent_exception(
    client: AsyncClient, db_session: AsyncSession, grp: DNSServerGroup
) -> None:
    h = await _su(db_session)
    bl = await _list(db_session, "spec", group=grp)
    db_session.add(_entry(bl, "ads.example.com", wildcard=False))
    db_session.add(DNSBlockListException(list_id=bl.id, domain="example.com"))
    await db_session.commit()

    assert (await _get(client, h, domain="ads.example.com", group_id=str(grp.id)))[
        "effective"
    ] == "blocked"


@pytest.mark.asyncio
async def test_manual_exception_on_another_list_applies_across_the_scope(
    client: AsyncClient, db_session: AsyncSession, grp: DNSServerGroup
) -> None:
    h = await _su(db_session)
    feed = await _list(db_session, "feed", group=grp, source_type="url")
    mine = await _list(db_session, "mine", group=grp)
    db_session.add(_entry(feed, "example.com", wildcard=True, source="feed"))
    db_session.add(DNSBlockListException(list_id=mine.id, domain="www.example.com"))
    await db_session.commit()

    body = await _get(client, h, domain="www.example.com", group_id=str(grp.id))
    assert body["effective"] == "allowed"
    assert body["matches"][0]["list_name"] == "feed"
    assert body["exceptions"][0]["list_name"] == "mine"


@pytest.mark.asyncio
async def test_scoping_by_group_view_and_enabled(
    client: AsyncClient, db_session: AsyncSession, grp: DNSServerGroup
) -> None:
    h = await _su(db_session)
    other = DNSServerGroup(name=f"other-{uuid.uuid4().hex[:6]}")
    db_session.add(other)
    await db_session.flush()
    view = DNSView(group_id=grp.id, name="guest")
    db_session.add(view)
    await db_session.flush()
    elsewhere = await _list(db_session, "elsewhere", group=other)
    viewed = await _list(db_session, "viewed", view=view)
    off = await _list(db_session, "off", group=grp, enabled=False)
    for bl in (elsewhere, viewed, off):
        db_session.add(_entry(bl, "example.com", wildcard=True))
    await db_session.commit()

    by_group = await _get(client, h, domain="example.com", group_id=str(grp.id))
    assert by_group["effective"] == "none"
    # Rows are still reported, flagged as not applying here.
    assert {m["list_name"]: m["applies_here"] for m in by_group["matches"]} == {
        "elsewhere": False,
        "viewed": False,
        "off": False,
    }
    by_view = await _get(
        client, h, domain="example.com", group_id=str(grp.id), view_id=str(view.id)
    )
    assert by_view["effective"] == "blocked"
    assert {m["list_name"]: m["applies_here"] for m in by_view["matches"]}["viewed"] is True


@pytest.mark.asyncio
async def test_rejects_a_name_that_cannot_be_listed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _su(db_session)
    for bad in ("localhost", "a..b", " "):
        r = await client.get(URL, params={"domain": bad}, headers=h)
        assert r.status_code == 422, bad


@pytest.mark.asyncio
async def test_requires_read_on_dns_blocklist(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    denied = await _scoped(db_session, [{"action": "read", "resource_type": "server"}])
    r = await client.get(URL, params={"domain": "example.com"}, headers=denied)
    assert r.status_code == 403
    allowed = await _scoped(db_session, [{"action": "read", "resource_type": "dns_blocklist"}])
    r = await client.get(URL, params={"domain": "example.com"}, headers=allowed)
    assert r.status_code == 200 and r.json()["effective"] == "none"


# ── What the agent is handed ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_effective_blocklist_hands_the_agent_the_pair_the_carve_out_needs(
    db_session: AsyncSession, grp: DNSServerGroup
) -> None:
    """The agent renders the zone from this pair. Its renderer turns a
    subdomain exception into passthru owners more specific than the parent's
    wildcard (agent/dns/tests/test_rpz_render.py pins that), so the match
    endpoint's "allowed" verdict holds only while both reach the bundle."""
    bl = await _list(db_session, "bundle", group=grp)
    db_session.add(_entry(bl, "example.com", wildcard=True))
    db_session.add(DNSBlockListException(list_id=bl.id, domain="a.example.com"))
    await db_session.commit()

    eff = await build_effective_for_group(db_session, grp.id)
    assert [(e.domain, e.is_wildcard) for e in eff.entries] == [("example.com", True)]
    assert eff.exceptions == {"a.example.com"}
