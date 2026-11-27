"""REST surface of the commercial-DDI mirror (#4729): CRUD, validation,
permissions, module gating, audit rows, credential handling, test connection,
sync trigger, mirror browse, delete cascade, both dashboard surfaces and the
Copilot read tools."""

from __future__ import annotations

import importlib
import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_str
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.ddi_mirror import DDIMirrorObject, DDIMirrorTarget
from app.models.ipam import IPSpace
from app.services import feature_modules as fm_svc
from app.services.ddi_mirror import infoblox as ib
from app.services.ddi_mirror.base import DDIProviderError, ProbeInfo
from app.services.ddi_mirror.reconcile import reconcile_target
from tests._ddi_mirror_support import FakeWapi

BASE = "/api/v1/migration/ddi-mirror"


async def _user(
    db: AsyncSession, *, superadmin: bool = False, perms: list[dict] | None = None
) -> dict:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="T",
        hashed_password=hash_password("x" * 12),
        auth_source="local",
        is_superadmin=superadmin,
    )
    user.groups = []
    if perms is not None:
        role = Role(name=f"r-{uuid.uuid4().hex[:6]}", description="", permissions=perms)
        group = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
        group.roles = [role]
        user.groups = [group]
        db.add_all([role, group])
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _body(**kw: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": f"gm-{uuid.uuid4().hex[:6]}",
        "base_url": "https://gm.test",
        "username": "admin",
        "password": "s3cret pass!",
    }
    body.update(kw)
    return body


async def _create(client: AsyncClient, h: dict, **kw: Any) -> dict[str, Any]:
    r = await client.post(f"{BASE}/targets", json=_body(**kw), headers=h)
    assert r.status_code == 201, r.text
    return r.json()


@pytest.fixture(autouse=True)
def _no_pause(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ib, "_PAGE_PAUSE_SECONDS", 0)


# ── CRUD, credentials, audit ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_get_list_update_delete_with_audit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _user(db_session, superadmin=True)
    await db_session.commit()
    t = await _create(client, h, name="legacy", description="old estate")
    assert t["vendor"] == "infoblox" and t["verify_tls"] is True
    assert t["sync_interval_seconds"] == 900 and t["page_size"] == 500
    assert t["password_present"] is True and "password" not in t
    assert "s3cret" not in (await client.get(f"{BASE}/targets", headers=h)).text

    rid = uuid.UUID(t["id"])
    row = await db_session.get(DDIMirrorTarget, rid)
    assert bytes(row.password_encrypted) != b"s3cret pass!"
    assert decrypt_str(row.password_encrypted) == "s3cret pass!"

    assert (await client.get(f"{BASE}/targets/{t['id']}", headers=h)).json()["name"] == "legacy"
    assert [x["name"] for x in (await client.get(f"{BASE}/targets", headers=h)).json()] == [
        "legacy"
    ]

    r = await client.put(
        f"{BASE}/targets/{t['id']}", json={"description": "new", "page_size": 100}, headers=h
    )
    assert (
        r.status_code == 200 and r.json()["description"] == "new" and r.json()["page_size"] == 100
    )
    # a blank password keeps the stored one; a non-empty one rotates it
    await client.put(f"{BASE}/targets/{t['id']}", json={"password": ""}, headers=h)
    db_session.expire_all()
    assert (
        decrypt_str((await db_session.get(DDIMirrorTarget, rid)).password_encrypted)
        == "s3cret pass!"
    )
    await client.put(f"{BASE}/targets/{t['id']}", json={"password": "rotated"}, headers=h)
    db_session.expire_all()
    assert decrypt_str((await db_session.get(DDIMirrorTarget, rid)).password_encrypted) == "rotated"

    assert (await client.delete(f"{BASE}/targets/{t['id']}", headers=h)).status_code == 204
    assert (await client.get(f"{BASE}/targets/{t['id']}", headers=h)).status_code == 404

    audits = (
        (
            await db_session.execute(
                select(AuditLog)
                .where(AuditLog.resource_type == "ddi_mirror_target")
                .order_by(AuditLog.timestamp)
            )
        )
        .scalars()
        .all()
    )
    assert [a.action for a in audits][:2] == ["create", "update"] and audits[-1].action == "delete"
    assert all(
        "s3cret" not in str(a.new_value) and "rotated" not in str(a.new_value) for a in audits
    )


@pytest.mark.asyncio
async def test_validation_conflicts_and_unknown_ids(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _user(db_session, superadmin=True)
    await db_session.commit()
    await _create(client, h, name="Dup")
    cases = [
        ({"base_url": "http://gm.test"}, "https"),
        ({"base_url": "https://u:p@gm.test"}, "credentials"),
        ({"base_url": "https://gm.test/wapi/v2.12"}, "scheme + host"),
        ({"sync_interval_seconds": 10}, "60"),
        ({"page_size": 5000}, "50..1000"),
        ({"api_version": "2.12"}, "pattern"),
        ({"password": ""}, "at least 1"),
        ({"username": ""}, "at least 1"),
    ]
    for override, needle in cases:
        r = await client.post(f"{BASE}/targets", json=_body(**override), headers=h)
        assert r.status_code == 422, (override, r.text)
        assert needle in r.text, (override, r.text)
    r = await client.post(f"{BASE}/targets", json=_body(vendor="bluecat"), headers=h)
    assert r.status_code == 422 and "planned but not supported" in r.text
    r = await client.post(f"{BASE}/targets", json=_body(vendor="nope"), headers=h)
    assert r.status_code == 422 and "unknown vendor" in r.text
    assert (
        await client.post(f"{BASE}/targets", json=_body(name="dup"), headers=h)
    ).status_code == 409

    ghost = uuid.uuid4()
    assert (await client.get(f"{BASE}/targets/{ghost}", headers=h)).status_code == 404
    assert (await client.put(f"{BASE}/targets/{ghost}", json={}, headers=h)).status_code == 404
    assert (await client.delete(f"{BASE}/targets/{ghost}", headers=h)).status_code == 404
    assert (await client.post(f"{BASE}/targets/{ghost}/sync", headers=h)).status_code == 404
    assert (await client.get(f"{BASE}/targets/{ghost}/objects", headers=h)).status_code == 404
    assert (await client.get(f"{BASE}/targets/{ghost}/rehearsal", headers=h)).status_code == 404
    assert (await client.get(f"{BASE}/targets/not-a-uuid", headers=h)).status_code == 422


@pytest.mark.asyncio
async def test_changing_the_destination_requires_the_password_again(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _user(db_session, superadmin=True)
    await db_session.commit()
    t = await _create(client, h)
    r = await client.put(
        f"{BASE}/targets/{t['id']}", json={"base_url": "https://evil.test"}, headers=h
    )
    assert r.status_code == 422, r.text
    r = await client.put(
        f"{BASE}/targets/{t['id']}",
        json={"base_url": "https://gm2.test", "password": "pw2"},
        headers=h,
    )
    assert r.status_code == 200 and r.json()["base_url"] == "https://gm2.test"


@pytest.mark.asyncio
async def test_permissions_are_enforced_server_side(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin = await _user(db_session, superadmin=True)
    reader = await _user(
        db_session, perms=[{"action": "read", "resource_type": "ddi_mirror_target"}]
    )
    writer = await _user(
        db_session, perms=[{"action": "write", "resource_type": "ddi_mirror_target"}]
    )
    nobody = await _user(db_session, perms=[])
    await db_session.commit()
    t = await _create(client, admin)

    # no grant at all: refused, never a 500
    for method, path in (
        ("get", "/targets"),
        ("get", f"/targets/{t['id']}"),
        ("get", f"/targets/{t['id']}/objects"),
        ("get", f"/targets/{t['id']}/rehearsal"),
        ("get", "/vendors"),
    ):
        r = await getattr(client, method)(f"{BASE}{path}", headers=nobody)
        assert r.status_code == 403, (path, r.status_code)
    # read grant: can browse, cannot change anything
    assert (await client.get(f"{BASE}/targets", headers=reader)).status_code == 200
    assert (
        await client.get(f"{BASE}/targets/{t['id']}/rehearsal", headers=reader)
    ).status_code == 200
    for r in (
        await client.post(f"{BASE}/targets", json=_body(), headers=reader),
        await client.put(f"{BASE}/targets/{t['id']}", json={"enabled": False}, headers=reader),
        await client.delete(f"{BASE}/targets/{t['id']}", headers=reader),
        await client.post(f"{BASE}/targets/{t['id']}/sync", headers=reader),
        await client.post(f"{BASE}/targets/test", json={}, headers=reader),
    ):
        assert r.status_code == 403, r.text
    # write grant without superadmin still cannot store a credential
    for r in (
        await client.post(f"{BASE}/targets", json=_body(), headers=writer),
        await client.put(f"{BASE}/targets/{t['id']}", json={"enabled": False}, headers=writer),
        await client.post(f"{BASE}/targets/test", json={}, headers=writer),
    ):
        assert r.status_code == 403, r.text
    assert (await client.get(f"{BASE}/targets", headers={})).status_code in (401, 403)


@pytest.mark.asyncio
async def test_module_off_is_404_everywhere(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _user(db_session, superadmin=True)
    await fm_svc.set_module_enabled(db_session, "migration.ddi_mirror", False, user_id=None)
    await db_session.commit()
    fm_svc.invalidate_cache()
    assert (await client.get(f"{BASE}/targets", headers=h)).status_code == 404
    assert (await client.post(f"{BASE}/targets", json=_body(), headers=h)).status_code == 404


# ── vendors, test connection, sync ───────────────────────────────────


@pytest.mark.asyncio
async def test_vendors_lists_supported_and_planned(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _user(db_session, superadmin=True)
    await db_session.commit()
    rows = {v["vendor"]: v for v in (await client.get(f"{BASE}/vendors", headers=h)).json()}
    assert rows["infoblox"]["supported"] is True and "zone" in rows["infoblox"]["kinds"]
    assert rows["bluecat"]["supported"] is False and rows["efficientip"]["supported"] is False


class _Fake:
    seen: list[Any] = []
    fail: DDIProviderError | None = None

    def __init__(self, cfg: Any) -> None:
        _Fake.seen.append(cfg)

    async def __aenter__(self) -> _Fake:
        return self

    async def __aexit__(self, *a: Any) -> None:
        return None

    async def probe(self) -> ProbeInfo:
        if _Fake.fail:
            raise _Fake.fail
        return ProbeInfo(version="WAPI v2.12", detail="grid Infoblox")


@pytest.mark.asyncio
async def test_test_connection(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = importlib.import_module("app.api.v1.ddi_mirror.router")

    monkeypatch.setattr(mod, "get_provider_class", lambda v: _Fake)
    _Fake.seen, _Fake.fail = [], None
    h = await _user(db_session, superadmin=True)
    await db_session.commit()

    r = await client.post(
        f"{BASE}/targets/test",
        json={"base_url": "https://gm.test", "username": "u", "password": "p"},
        headers=h,
    )
    assert r.status_code == 200 and r.json()["ok"] is True and r.json()["version"] == "WAPI v2.12"
    assert _Fake.seen[-1].verify_tls is True  # verified unless explicitly opted out

    _Fake.fail = DDIProviderError("Infoblox WAPI grid returned HTTP 401: nope", status_code=401)
    r = await client.post(
        f"{BASE}/targets/test",
        json={"base_url": "https://gm.test", "username": "u", "password": "p", "verify_tls": False},
        headers=h,
    )
    assert r.json()["ok"] is False and "401" in r.json()["message"]
    assert _Fake.seen[-1].verify_tls is False

    # stored target: uses the stored password; a moved destination needs it re-entered
    _Fake.fail = None
    t = await _create(client, h)
    r = await client.post(f"{BASE}/targets/test", json={"target_id": t["id"]}, headers=h)
    assert r.json()["ok"] is True and _Fake.seen[-1].password == "s3cret pass!"
    r = await client.post(
        f"{BASE}/targets/test",
        json={"target_id": t["id"], "base_url": "https://elsewhere.test"},
        headers=h,
    )
    assert r.status_code == 422
    # bad input
    for body in (
        {},
        {"base_url": "https://gm.test"},
        {"vendor": "bluecat", "base_url": "https://gm.test", "username": "u", "password": "p"},
    ):
        assert (await client.post(f"{BASE}/targets/test", json=body, headers=h)).status_code == 422
    r = await client.post(f"{BASE}/targets/test", json={"target_id": str(uuid.uuid4())}, headers=h)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_sync_queues_and_audits(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = importlib.import_module("app.api.v1.ddi_mirror.router")

    calls: list[tuple] = []

    async def fake_dispatch(task: Any, *args: Any) -> Any:
        calls.append(args)
        return SimpleNamespace(id="task-1")

    monkeypatch.setattr(mod, "dispatch", fake_dispatch)
    h = await _user(db_session, superadmin=True)
    await db_session.commit()
    t = await _create(client, h)
    r = await client.post(f"{BASE}/targets/{t['id']}/sync", headers=h)
    assert r.status_code == 202
    assert (r.json()["status"], r.json()["task_id"]) == ("queued", "task-1")
    assert calls == [(t["id"],)]
    trig = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "ddi_mirror_target", AuditLog.action == "sync"
            )
        )
    ).scalar_one()
    assert trig.resource_id == t["id"]


# ── mirror browse + delete cascade ───────────────────────────────────


async def _synced(client: AsyncClient, db: AsyncSession, h: dict) -> dict[str, Any]:
    t = await _create(client, h, password="secret")
    row = await db.get(DDIMirrorTarget, uuid.UUID(t["id"]))
    s = await reconcile_target(db, row, transport=FakeWapi().transport())
    assert s.ok, s.error
    return t


@pytest.mark.asyncio
async def test_browse_filters_search_and_paging(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _user(db_session, superadmin=True)
    await db_session.commit()
    t = await _synced(client, db_session, h)
    url = f"{BASE}/targets/{t['id']}/objects"

    page = (await client.get(url, headers=h)).json()
    assert page["total"] == 13 and len(page["items"]) == 13
    assert "password" not in str(page)
    nets = (await client.get(url, params={"kind": "network"}, headers=h)).json()
    assert nets["total"] == 3 and {i["value"] for i in nets["items"]} == {
        "10.1.0.0/24",
        "10.2.0.0/24",
        "10.3.0.0/24",
    }
    q = (await client.get(url, params={"q": "PHONES"}, headers=h)).json()
    assert q["total"] == 1 and q["items"][0]["value"] == "10.2.0.0/24"
    p1 = (await client.get(url, params={"limit": 5, "offset": 0}, headers=h)).json()
    p3 = (await client.get(url, params={"limit": 5, "offset": 10}, headers=h)).json()
    assert p1["total"] == 13 and len(p1["items"]) == 5 and len(p3["items"]) == 3
    assert (await client.get(url, params={"kind": "bogus"}, headers=h)).status_code == 422
    assert (await client.get(url, params={"limit": 0}, headers=h)).status_code == 422
    assert (await client.get(url, params={"limit": 5000}, headers=h)).status_code == 422
    assert (await client.get(url, params={"offset": -1}, headers=h)).status_code == 422


@pytest.mark.asyncio
async def test_deleting_a_target_sweeps_its_mirror_and_touches_nothing_live(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _user(db_session, superadmin=True)
    space = IPSpace(name="live", description="")
    db_session.add(space)
    await db_session.commit()
    t = await _synced(client, db_session, h)
    assert await db_session.scalar(select(func.count()).select_from(DDIMirrorObject)) == 13
    assert (await client.delete(f"{BASE}/targets/{t['id']}", headers=h)).status_code == 204
    assert await db_session.scalar(select(func.count()).select_from(DDIMirrorObject)) == 0
    assert await db_session.get(IPSpace, space.id) is not None


# ── dashboards (non-negotiable #15) + Copilot tools (#13) ────────────


@pytest.mark.asyncio
async def test_integrations_dashboard_shows_the_target_and_its_errors(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _user(db_session, superadmin=True)
    await db_session.commit()
    t = await _create(client, h, name="legacy-gm")
    row = await db_session.get(DDIMirrorTarget, uuid.UUID(t["id"]))
    await reconcile_target(db_session, row, transport=_bad_auth_transport())

    r = await client.get("/api/v1/dashboards/integrations/summary", headers=h)
    assert r.status_code == 200, r.text
    panel = next(p for p in r.json()["panels"] if p["kind"] == "ddi_mirror")
    assert panel["enabled"] is True and panel["error_count"] == 1
    assert [x["display"] for x in panel["targets"]] == ["legacy-gm"]
    errs = [e for e in r.json()["recent_errors"] if e["integration"] == "ddi_mirror_target"]
    assert errs and "401" in errs[0]["error_detail"]

    await fm_svc.set_module_enabled(db_session, "migration.ddi_mirror", False, user_id=None)
    await db_session.commit()
    fm_svc.invalidate_cache()
    r = await client.get("/api/v1/dashboards/integrations/summary", headers=h)
    assert next(p for p in r.json()["panels"] if p["kind"] == "ddi_mirror")["enabled"] is False


def _bad_auth_transport() -> Any:
    w = FakeWapi()
    w.require_auth = ("admin", "different")
    return w.transport()


@pytest.mark.asyncio
async def test_copilot_tools_read_the_mirror(client: AsyncClient, db_session: AsyncSession) -> None:
    from app.services.ai.tools import ddi_mirror as tools

    h = await _user(db_session, superadmin=True)
    await db_session.commit()
    t = await _synced(client, db_session, h)
    user = (await db_session.execute(select(User))).scalars().first()

    listed = await tools.list_ddi_mirror_targets(db_session, user, tools.ListTargetsArgs())
    assert listed[0]["object_count"] == 13 and "password" not in str(listed)
    found = await tools.find_ddi_mirror_objects(
        db_session, user, tools.FindObjectsArgs(target_id=t["id"], kind="zone")
    )
    assert {o["name"] for o in found} == {"example.com", "1.10.in-addr.arpa"}
    counted = await tools.count_ddi_mirror_objects(
        db_session, user, tools.CountObjectsArgs(target_id=t["id"])
    )
    assert counted["total"] == 13 and counted["by_kind"]["network"] == 3
    reh = await tools.find_ddi_mirror_rehearsal(
        db_session, user, tools.RehearsalArgs(target_id=t["id"], action="create")
    )
    assert reh["kinds"]["network"]["create"] == 3
    # agrees with REST
    rest = (await client.get(f"{BASE}/targets/{t['id']}/rehearsal", headers=h)).json()
    assert rest["kinds"]["network"]["create"] == reh["kinds"]["network"]["create"]

    for bad in (
        await tools.find_ddi_mirror_objects(db_session, user, tools.FindObjectsArgs(target_id="x")),
        await tools.count_ddi_mirror_objects(
            db_session, user, tools.CountObjectsArgs(target_id=t["id"], kind="nope")
        ),
        await tools.find_ddi_mirror_rehearsal(
            db_session, user, tools.RehearsalArgs(target_id=str(uuid.uuid4()))
        ),
    ):
        assert "error" in bad
