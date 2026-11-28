"""The ``wol_schedule`` / ``wol_calendar`` / ``routing_policy`` grants the role
picker offers open the routes they describe (#4316).

Before the fix the Wake Scheduler routes checked ``use_network_tools`` alone
and the overlay policy routes ``overlay_network`` alone, so a role granting the
offered type opened nothing.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.main import _BUILTIN_ROLES
from app.models.auth import Group, Role, User

pytestmark = pytest.mark.asyncio

_WAKE = "/api/v1/wake-scheduler"
_OVL = "/api/v1/overlays"


async def _hdr(
    db: AsyncSession, *, role: str | None = None, grants: list[tuple[str, str]] | None = None
) -> dict[str, str]:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"u-{tag}",
        email=f"{tag}@example.test",
        display_name="U",
        hashed_password=hash_password("x"),
    )
    perms = (
        list(_BUILTIN_ROLES[role][1])
        if role is not None
        else [{"action": a, "resource_type": t} for a, t in (grants or [])]
    )
    r = Role(name=f"r-{tag}", description="", permissions=perms)
    g = Group(name=f"g-{tag}", description="")
    g.roles = [r]
    g.users = [user]
    db.add_all([r, g, user])
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _schedule(**kw: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": f"s-{uuid.uuid4().hex[:6]}",
        "target_selector": {"mode": "address_tags", "tags": ["wake:x"]},
        "schedule_cron": "0 7 * * *",
    }
    body.update(kw)
    return body


def _calendar() -> dict[str, Any]:
    return {
        "name": f"c-{uuid.uuid4().hex[:6]}",
        "kind": "ical_url",
        "url": "https://example.test/cal.ics",
    }


async def test_wol_schedule_write_opens_schedules(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _hdr(db_session, grants=[("write", "wol_schedule"), ("read", "wol_schedule")])
    r = await client.post(f"{_WAKE}/schedules", json=_schedule(), headers=h)
    assert r.status_code == 201, r.text
    assert (await client.get(f"{_WAKE}/schedules", headers=h)).status_code == 200
    # ...but not the calendar writes: that is wol_calendar's.
    r = await client.post(f"{_WAKE}/calendars", json=_calendar(), headers=h)
    assert r.status_code == 403


async def test_wol_calendar_write_opens_calendars(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _hdr(db_session, grants=[("write", "wol_calendar")])
    r = await client.post(f"{_WAKE}/calendars", json=_calendar(), headers=h)
    assert r.status_code == 201, r.text
    r = await client.post(f"{_WAKE}/schedules", json=_schedule(), headers=h)
    assert r.status_code == 403


async def test_refusal_names_the_types_checked(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _hdr(db_session, grants=[("read", "ip_space")])
    r = await client.post(f"{_WAKE}/schedules", json=_schedule(), headers=h)
    assert r.status_code == 403
    assert "wol_schedule" in r.json()["detail"]
    r = await client.post(f"{_WAKE}/calendars", json=_calendar(), headers=h)
    assert r.status_code == 403
    assert "wol_calendar" in r.json()["detail"]


async def test_network_tools_and_network_editor_keep_the_scheduler(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    for h in (
        await _hdr(db_session, grants=[("write", "use_network_tools")]),
        await _hdr(db_session, role="Network Editor"),
    ):
        r = await client.post(f"{_WAKE}/schedules", json=_schedule(), headers=h)
        assert r.status_code == 201, r.text
        r = await client.post(f"{_WAKE}/calendars", json=_calendar(), headers=h)
        assert r.status_code == 201, r.text


async def test_viewer_still_refused_the_scheduler(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _hdr(db_session, role="Viewer")
    r = await client.post(f"{_WAKE}/schedules", json=_schedule(), headers=h)
    assert r.status_code == 403


async def _overlay(client: AsyncClient, db: AsyncSession) -> str:
    h = await _hdr(db, grants=[("write", "overlay_network")])
    r = await client.post(_OVL, json={"name": f"o-{uuid.uuid4().hex[:6]}"}, headers=h)
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


_POLICY = {"name": "p", "match_kind": "dscp", "match_value": "EF", "action": "drop"}


async def test_policy_write_needs_routing_policy_as_well(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    oid = await _overlay(client, db_session)
    only_overlay = await _hdr(db_session, grants=[("write", "overlay_network")])
    r = await client.post(f"{_OVL}/{oid}/policies", json=_POLICY, headers=only_overlay)
    assert r.status_code == 403
    assert "routing_policy" in r.json()["detail"]

    both = await _hdr(
        db_session, grants=[("write", "overlay_network"), ("write", "routing_policy")]
    )
    r = await client.post(f"{_OVL}/{oid}/policies", json=_POLICY, headers=both)
    assert r.status_code == 201, r.text
    pid = r.json()["id"]

    only_policy = await _hdr(db_session, grants=[("write", "routing_policy")])
    r = await client.post(f"{_OVL}/{oid}/policies", json=_POLICY, headers=only_policy)
    assert r.status_code == 403  # the overlay itself is still overlay_network's

    r = await client.put(f"{_OVL}/{oid}/policies/{pid}", json={"name": "q"}, headers=only_overlay)
    assert r.status_code == 403
    r = await client.delete(f"{_OVL}/{oid}/policies/{pid}", headers=only_overlay)
    assert r.status_code == 403
    # Listing is the overlay's own read.
    ro = await _hdr(db_session, grants=[("read", "overlay_network")])
    assert (await client.get(f"{_OVL}/{oid}/policies", headers=ro)).status_code == 200


async def test_network_editor_keeps_policy_writes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    oid = await _overlay(client, db_session)
    h = await _hdr(db_session, role="Network Editor")
    r = await client.post(f"{_OVL}/{oid}/policies", json=_POLICY, headers=h)
    assert r.status_code == 201, r.text
