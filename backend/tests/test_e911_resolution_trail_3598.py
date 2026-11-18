"""#3598: the E911 resolution trail has a read surface behind its own permission.

REST list + CSV, the ``e911_resolution_log`` grant (not ``e911_location``,
granted to no builtin role), an audit row for every read, and default-off MCP
tools.
"""

from __future__ import annotations

import csv
import io
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.main import _BUILTIN_ROLES
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.e911 import E911ResolutionLog, EmergencyResponseLocation
from app.services.ai.tools import REGISTRY
from app.services.ai.tools.base import ToolPermissionDenied, effective_tool_names

pytestmark = pytest.mark.asyncio

URL = "/api/v1/e911/resolution-log"


async def _user(
    db: AsyncSession, perms: list[dict] | None, *, superadmin: bool = False
) -> tuple[User, dict[str, str]]:
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="U",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    db.add(u)
    await db.flush()
    if perms is not None:
        role = Role(name=f"r-{uuid.uuid4().hex[:8]}", description="", permissions=perms)
        db.add(role)
        await db.flush()
        g = Group(name=f"g-{uuid.uuid4().hex[:8]}", description="")
        g.roles = [role]
        g.users = [u]
        db.add(g)
        await db.flush()
    await db.commit()
    return u, {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


def _row(minutes_ago: int, **kw: Any) -> E911ResolutionLog:
    base: dict[str, Any] = dict(
        queried_at=datetime.now(UTC) - timedelta(minutes=minutes_ago),
        identity_kind="ip",
        identity_value="10.0.0.1",
        actor_kind="api_token",
        confidence="observed",
    )
    base.update(kw)
    return E911ResolutionLog(**base)


async def _seed(db: AsyncSession) -> tuple[User, EmergencyResponseLocation]:
    pbx, _ = await _user(db, [{"action": "read", "resource_type": "e911_location"}])
    erl = EmergencyResponseLocation(name="HQ-3F", country="US", a1="NY", rd="Broadway")
    db.add(erl)
    await db.flush()
    db.add_all(
        [
            _row(5, identity_value="10.0.0.1", actor_kind="user", actor_id=pbx.id, erl_id=erl.id),
            _row(10, identity_value="10.0.0.2", confidence="degraded", degraded_reason="stale"),
            _row(15, identity_value="aa:bb:cc:00:00:01", identity_kind="mac", confidence="none"),
            _row(
                20,
                caller_key="k",
                window_start=datetime.now(UTC) - timedelta(minutes=20),
                suppressed_count=7,
            ),
        ]
    )
    await db.commit()
    return pbx, erl


async def test_list_newest_first_with_both_row_kinds(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    pbx, erl = await _seed(db_session)
    _, h = await _user(db_session, None, superadmin=True)
    r = await client.get(URL, headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 4
    times = [i["queried_at"] for i in body["items"]]
    assert times == sorted(times, reverse=True)
    assert [i["kind"] for i in body["items"]] == ["lookup", "lookup", "lookup", "counter"]
    first = body["items"][0]
    assert first["actor_label"] == pbx.username and first["erl_name"] == "HQ-3F"
    assert body["items"][3]["suppressed_count"] == 7


async def test_filters_and_pagination(client: AsyncClient, db_session: AsyncSession) -> None:
    pbx, erl = await _seed(db_session)
    _, h = await _user(db_session, None, superadmin=True)

    async def get(**p: Any) -> dict:
        r = await client.get(URL, params=p, headers=h)
        assert r.status_code == 200, r.text
        return r.json()

    assert (await get(identity="10.0.0.2"))["total"] == 1
    assert (await get(identity_kind="mac"))["total"] == 1
    assert (await get(confidence="degraded"))["total"] == 1
    assert (await get(actor_id=str(pbx.id)))["total"] == 1
    assert (await get(erl_id=str(erl.id)))["total"] == 1
    assert (await get(kind="counter"))["total"] == 1
    since = (datetime.now(UTC) - timedelta(minutes=12)).isoformat()
    assert (await get(since=since))["total"] == 2
    assert (await get(until=since))["total"] == 2
    # A LIKE metacharacter matches literally, not everything.
    assert (await get(identity="%"))["total"] == 0
    page = await get(limit=2, offset=3)
    assert page["total"] == 4 and len(page["items"]) == 1
    bad = await client.get(URL, params={"confidence": "bogus"}, headers=h)
    assert bad.status_code == 422


async def test_every_read_is_audited(client: AsyncClient, db_session: AsyncSession) -> None:
    await _seed(db_session)
    su, h = await _user(db_session, None, superadmin=True)

    async def audits() -> list[AuditLog]:
        return list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.resource_type == "e911_resolution_log")
                )
            )
            .scalars()
            .all()
        )

    assert await audits() == []
    assert (await client.get(URL, params={"identity": "10.0.0.2"}, headers=h)).status_code == 200
    assert (await client.get(f"{URL}/export.csv", headers=h)).status_code == 200
    rows = await audits()
    assert sorted(a.action for a in rows) == ["export", "read"]
    read = next(a for a in rows if a.action == "read")
    assert read.user_id == su.id
    assert read.new_value["filters"] == {"identity": "10.0.0.2"}
    assert read.new_value["returned"] == 1


async def test_csv_export_filters_and_defuses_formulas(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _seed(db_session)
    db_session.add(_row(1, identity_value="=cmd|' /C calc'!A0", identity_kind="mac"))
    await db_session.commit()
    _, h = await _user(db_session, None, superadmin=True)
    r = await client.get(f"{URL}/export.csv", params={"identity_kind": "mac"}, headers=h)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == 2
    assert {x["identity_value"] for x in rows} == {"'=cmd|' /C calc'!A0", "aa:bb:cc:00:00:01"}


async def test_rbac_matrix(client: AsyncClient, db_session: AsyncSession) -> None:
    await _seed(db_session)
    cases: dict[str, tuple[list[dict] | None, bool, int]] = {
        "superadmin": (None, True, 200),
        "explicit read grant": (
            [{"action": "read", "resource_type": "e911_resolution_log"}],
            False,
            200,
        ),
        "admin grant": ([{"action": "admin", "resource_type": "e911_resolution_log"}], False, 200),
        # The lookup grant a PBX account holds must not open the trail.
        "e911_location admin": (
            [{"action": "admin", "resource_type": "e911_location"}],
            False,
            403,
        ),
        "unrelated": ([{"action": "read", "resource_type": "subnet"}], False, 403),
    }
    for name, (perms, sup, want) in cases.items():
        _, h = await _user(db_session, perms, superadmin=sup)
        for path in (URL, f"{URL}/export.csv"):
            r = await client.get(path, headers=h)
            assert r.status_code == want, (name, path, r.text)
    # A write verb is not routed at all: the trail is written only by lookups.
    _, h = await _user(db_session, None, superadmin=True)
    assert (await client.post(URL, json={}, headers=h)).status_code in (404, 405)
    # An unauthenticated caller is refused.
    assert (await client.get(URL)).status_code in (401, 403)


async def test_no_builtin_role_names_the_trail_explicitly() -> None:
    for name, (_desc, perms) in _BUILTIN_ROLES.items():
        for p in perms:
            assert p["resource_type"] != "e911_resolution_log", name


async def test_a_denied_read_is_not_audited_as_a_successful_read(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _seed(db_session)
    _, h = await _user(db_session, [{"action": "admin", "resource_type": "e911_location"}])
    assert (await client.get(URL, headers=h)).status_code == 403
    n = (
        await db_session.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.resource_type == "e911_resolution_log",
                AuditLog.action == "read",
                AuditLog.result == "success",
            )
        )
    ).scalar_one()
    assert n == 0


# ── MCP ──────────────────────────────────────────────────────────────


async def _call(db: AsyncSession, user: User, name: str, args: dict | None = None) -> Any:
    # ``effective=None``: the registry's own permission gate still runs; the
    # default-off state is asserted separately below.
    return await REGISTRY.call(name, args or {}, db=db, user=user, effective=None)


async def test_tools_are_default_off_module_tagged_and_permissioned() -> None:
    for name in ("find_e911_resolutions", "count_e911_resolutions"):
        tool = REGISTRY.get(name)
        assert tool is not None
        assert tool.default_enabled is False
        assert tool.module == "network.e911"
        assert tool.permission == ("read", "e911_resolution_log")
        assert not tool.writes


async def test_find_tool_returns_rows_and_audits(db_session: AsyncSession) -> None:
    await _seed(db_session)
    su, _ = await _user(db_session, None, superadmin=True)
    await db_session.refresh(su, ["groups"])
    rows = await _call(db_session, su, "find_e911_resolutions", {"confidence": "degraded"})
    assert len(rows) == 1 and rows[0]["degraded_reason"] == "stale"
    assert await _call(db_session, su, "count_e911_resolutions", {}) == {"count": 4}
    n = (
        await db_session.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.resource_type == "e911_resolution_log", AuditLog.user_id == su.id)
        )
    ).scalar_one()
    assert n == 2


async def test_find_tool_refuses_a_lookup_only_account(db_session: AsyncSession) -> None:
    await _seed(db_session)
    u, _ = await _user(db_session, [{"action": "admin", "resource_type": "e911_location"}])
    await db_session.refresh(u, ["groups"])
    with pytest.raises(ToolPermissionDenied):
        await _call(db_session, u, "find_e911_resolutions", {})


async def test_default_tool_set_leaves_the_trail_tools_out() -> None:
    eligible = effective_tool_names(platform_enabled=None, provider_enabled=None)
    assert "find_e911_location" in eligible
    assert "find_e911_resolutions" not in eligible
    assert "count_e911_resolutions" not in eligible
