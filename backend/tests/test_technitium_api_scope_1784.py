"""#1784 — the experimental agentless ``technitium_api`` driver refuses what it can't do.

One server per group, Primary zones SpatiumDDI creates, no pools, no group or
zone options, no blocklists. Every refusal names the experimental status and
the reason; BIND9 / PowerDNS / agent-managed Technitium are untouched.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_dict
from app.core.security import create_access_token, hash_password
from app.drivers.dns._cloud_base import CloudDNSConflictError
from app.drivers.dns.technitium_api import TechnitiumAPIDriver
from app.models.auth import User
from app.models.dns import (
    DNSBlockList,
    DNSPool,
    DNSServer,
    DNSServerGroup,
    DNSServerOptions,
    DNSZone,
)

EXPERIMENTAL = "technitium_api is experimental in 1.0"
_CREDS = {"api_url": "https://dns.example.test:53443", "api_token": "tok", "verify_tls": False}


async def _token(db: AsyncSession) -> str:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


async def _group(db: AsyncSession, driver: str | None, *, servers: int = 1) -> DNSServerGroup:
    g = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(g)
    await db.flush()
    db.add(DNSServerOptions(group_id=g.id))
    for _ in range(servers if driver else 0):
        db.add(
            DNSServer(
                group_id=g.id,
                name=f"s-{uuid.uuid4().hex[:6]}",
                driver=driver,
                host="10.0.0.53",
                port=53,
                credentials_encrypted=encrypt_dict(_CREDS) if driver == "technitium_api" else None,
            )
        )
    await db.flush()
    return g


async def _zone(db: AsyncSession, g: DNSServerGroup, **kw: Any) -> DNSZone:
    z = DNSZone(
        group_id=g.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.com.",
        zone_type=kw.pop("zone_type", "primary"),
        kind="forward",
        primary_ns="ns1.example.com.",
        admin_email="admin.example.com.",
        **kw,
    )
    db.add(z)
    await db.flush()
    return z


def _h(t: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {t}"}


def _server_body(driver: str) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": f"n-{uuid.uuid4().hex[:6]}",
        "driver": driver,
        "host": "10.0.0.9",
    }
    if driver == "technitium_api":
        body["cloud_credentials"] = dict(_CREDS)
    return body


def _assert_refused(resp: Any) -> None:
    assert resp.status_code == 422, resp.text
    assert EXPERIMENTAL in str(resp.json()["detail"])


# ── 1. one server per group ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_second_technitium_api_server_refused_on_create(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    t = await _token(db_session)
    g = await _group(db_session, "technitium_api")
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/servers", headers=_h(t), json=_server_body("technitium_api")
    )
    _assert_refused(r)
    assert "one" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_first_technitium_api_server_is_allowed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    t = await _token(db_session)
    g = await _group(db_session, None)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/servers", headers=_h(t), json=_server_body("technitium_api")
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_driver_change_to_technitium_api_refused_when_one_exists(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    t = await _token(db_session)
    g = await _group(db_session, "technitium_api")
    # A technitium_api server in the group + a second server on another
    # driver cannot coexist (single-driver), so build the second one in an
    # otherwise-empty path: change an existing server's driver is refused.
    other = DNSServer(group_id=g.id, name="second", driver="technitium_api", host="h", port=53)
    # Not committed as technitium_api; flip it through the API instead.
    other.driver = "bind9"
    db_session.add(other)
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/groups/{g.id}/servers/{other.id}",
        headers=_h(t),
        json={"driver": "technitium_api", "cloud_credentials": dict(_CREDS)},
    )
    assert r.status_code == 422, r.text
    detail = str(r.json()["detail"])
    assert "technitium_api" in detail


@pytest.mark.asyncio
async def test_move_into_group_with_technitium_api_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    t = await _token(db_session)
    target = await _group(db_session, "technitium_api")
    src = await _group(db_session, "technitium_api")
    moving = (
        await db_session.execute(DNSServer.__table__.select().where(DNSServer.group_id == src.id))
    ).first()
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/groups/{src.id}/servers/{moving.id}",
        headers=_h(t),
        json={"group_id": str(target.id)},
    )
    _assert_refused(r)


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", ["bind9", "powerdns", "technitium"])
async def test_other_drivers_may_have_several_servers(
    client: AsyncClient, db_session: AsyncSession, driver: str
) -> None:
    t = await _token(db_session)
    g = await _group(db_session, driver)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/servers", headers=_h(t), json=_server_body(driver)
    )
    assert r.status_code == 201, r.text


# ── 2. zones: Primary only, unapplied settings refused ───────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "extra",
    [
        {"zone_type": "secondary", "masters": ["10.0.0.1"]},
        {"zone_type": "stub", "masters": ["10.0.0.1"]},
        {"zone_type": "forward", "forwarders": ["9.9.9.9"]},
        {"primary_ns": "ns.example.com."},
        {"admin_email": "hostmaster.example.com."},
        {"refresh": 7200},
        {"ttl": 60},
        {"allow_transfer": ["10.0.0.0/8"]},
        {"also_notify": ["10.0.0.2"]},
        {"allow_query": ["any"]},
        {"notify_enabled": "yes"},
    ],
)
async def test_zone_create_refused_on_technitium_api(
    client: AsyncClient, db_session: AsyncSession, extra: dict[str, Any]
) -> None:
    t = await _token(db_session)
    g = await _group(db_session, "technitium_api")
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/zones",
        headers=_h(t),
        json={"name": "refused.example.com.", **extra},
    )
    _assert_refused(r)


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", ["bind9", "powerdns", "technitium"])
async def test_zone_settings_unaffected_on_other_drivers(
    client: AsyncClient, db_session: AsyncSession, driver: str
) -> None:
    t = await _token(db_session)
    g = await _group(db_session, driver)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/zones",
        headers=_h(t),
        json={
            "name": "ok.example.com.",
            "primary_ns": "ns.example.com.",
            "refresh": 7200,
            "allow_transfer": ["10.0.0.0/8"],
        },
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_zone_update_refuses_changed_unapplied_value_but_allows_resave(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    t = await _token(db_session)
    g = await _group(db_session, "technitium_api")
    z = await _zone(db_session, g, refresh=1234)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{g.id}/zones/{z.id}"
    # Unchanged stored non-default values re-saved with an unrelated change.
    ok = await client.put(
        url,
        headers=_h(t),
        json={"refresh": 1234, "primary_ns": "ns1.example.com.", "color": "red"},
    )
    assert ok.status_code == 200, ok.text
    _assert_refused(await client.put(url, headers=_h(t), json={"refresh": 4321}))
    _assert_refused(await client.put(url, headers=_h(t), json={"allow_transfer": ["any"]}))
    _assert_refused(await client.put(url, headers=_h(t), json={"zone_type": "forward"}))


# ── 3. pools ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pool_create_and_member_refused_on_technitium_api(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    t = await _token(db_session)
    g = await _group(db_session, "technitium_api")
    z = await _zone(db_session, g)
    existing = DNSPool(group_id=g.id, zone_id=z.id, name="old", record_name="old", record_type="A")
    db_session.add(existing)
    await db_session.commit()
    _assert_refused(
        await client.post(
            f"/api/v1/dns/groups/{g.id}/zones/{z.id}/pools",
            headers=_h(t),
            json={"name": "web", "record_name": "www"},
        )
    )
    _assert_refused(
        await client.post(
            f"/api/v1/dns/pools/{existing.id}/members",
            headers=_h(t),
            json={"address": "10.0.0.5"},
        )
    )


@pytest.mark.asyncio
async def test_pool_create_unaffected_on_bind9(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    t = await _token(db_session)
    g = await _group(db_session, "bind9")
    z = await _zone(db_session, g)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/zones/{z.id}/pools",
        headers=_h(t),
        json={"name": "web", "record_name": "www"},
    )
    assert r.status_code == 201, r.text


# ── 4. group options, catalog zones, blocklists ──────────────────────────


@pytest.mark.asyncio
async def test_group_options_refused_only_when_changed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    t = await _token(db_session)
    g = await _group(db_session, "technitium_api")
    await db_session.commit()
    url = f"/api/v1/dns/groups/{g.id}/options"
    # Re-saving the stored (default) value is fine.
    assert (
        await client.put(url, headers=_h(t), json={"recursion_enabled": True})
    ).status_code == 200
    _assert_refused(await client.put(url, headers=_h(t), json={"recursion_enabled": False}))
    _assert_refused(await client.put(url, headers=_h(t), json={"forwarders": ["9.9.9.9"]}))


@pytest.mark.asyncio
async def test_group_options_unaffected_on_bind9(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    t = await _token(db_session)
    g = await _group(db_session, "bind9")
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/groups/{g.id}/options", headers=_h(t), json={"recursion_enabled": False}
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_catalog_zones_refused_on_technitium_api(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    t = await _token(db_session)
    g = await _group(db_session, "technitium_api")
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/groups/{g.id}", headers=_h(t), json={"catalog_zones_enabled": True}
    )
    _assert_refused(r)


@pytest.mark.asyncio
async def test_blocklist_assignment_refused_on_technitium_api(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    t = await _token(db_session)
    g = await _group(db_session, "technitium_api")
    bl = DNSBlockList(name=f"bl-{uuid.uuid4().hex[:6]}", category="custom", source_type="manual")
    db_session.add(bl)
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/blocklists/{bl.id}/assignments",
        headers=_h(t),
        json={"server_group_ids": [str(g.id)]},
    )
    _assert_refused(r)
    bind = await _group(db_session, "bind9")
    await db_session.commit()
    ok = await client.put(
        f"/api/v1/dns/blocklists/{bl.id}/assignments",
        headers=_h(t),
        json={"server_group_ids": [str(bind.id)]},
    )
    assert ok.status_code == 200, ok.text


# ── 5. visible status ────────────────────────────────────────────────────


def test_capabilities_flag_experimental() -> None:
    assert TechnitiumAPIDriver().capabilities()["experimental"] is True
    from app.drivers.dns import get_driver

    for name in ("bind9", "powerdns", "technitium"):
        assert not get_driver(name).capabilities().get("experimental")


@pytest.mark.asyncio
async def test_existing_violating_group_keeps_working_and_warns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    t = await _token(db_session)
    g = await _group(db_session, "technitium_api", servers=2)
    z = await _zone(db_session, g)
    db_session.add(DNSPool(group_id=g.id, zone_id=z.id, name="p", record_name="p", record_type="A"))
    clean = await _group(db_session, "bind9")
    await db_session.commit()
    groups = {x["id"]: x for x in (await client.get("/api/v1/dns/groups", headers=_h(t))).json()}
    warnings = " ".join(groups[str(g.id)]["scope_warnings"])
    assert EXPERIMENTAL in warnings
    assert "2 technitium_api servers" in warnings
    assert "pool" in warnings
    assert groups[str(clean.id)]["scope_warnings"] == []
    one = (await client.get(f"/api/v1/dns/groups/{g.id}", headers=_h(t))).json()
    assert one["scope_warnings"]


# ── driver: adoption ─────────────────────────────────────────────────────


class _Resp:
    status_code = 200

    def __init__(self, payload: Any) -> None:
        self._p = payload

    def json(self) -> Any:
        return self._p


class _Client:
    def __init__(self, responses: list[Any]) -> None:
        self.r = list(responses)

    async def __aenter__(self) -> _Client:
        return self

    async def __aexit__(self, *a: Any) -> bool:
        return False

    async def get(self, path: str, params: Any = None) -> _Resp:
        return _Resp(self.r.pop(0))


def _ok(x: Any) -> dict[str, Any]:
    return {"status": "ok", "response": x}


_EXISTS = {"status": "error", "errorMessage": "Zone already exists: a.example.com"}


class _Z:
    name = "a.example.com."
    zone_type = "primary"


class _S:
    id = "x"
    credentials_encrypted = b"x"


def _drv(monkeypatch: pytest.MonkeyPatch, responses: list[Any]) -> TechnitiumAPIDriver:
    d = TechnitiumAPIDriver()
    c = _Client(responses)
    monkeypatch.setattr(TechnitiumAPIDriver, "_client", lambda *a, **k: c)
    monkeypatch.setattr(TechnitiumAPIDriver, "_load_credentials", lambda self, s: dict(_CREDS))
    return d


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("ztype", "records", "why"),
    [
        ("Secondary", [], "Secondary"),
        ("Forwarder", [], "Forwarder"),
        ("Primary", [{"type": "SOA"}, {"type": "NS"}, {"type": "A"}], "1 record"),
    ],
)
async def test_existing_non_empty_or_non_primary_zone_is_not_adopted(
    monkeypatch: pytest.MonkeyPatch, ztype: str, records: list[Any], why: str
) -> None:
    d = _drv(
        monkeypatch,
        [
            _EXISTS,
            _ok({"zones": [{"name": "a.example.com", "type": ztype}], "totalPages": 1}),
            _ok({"records": records}),
        ],
    )
    with pytest.raises(CloudDNSConflictError) as ei:
        await d.apply_zone_change(_S(), _Z(), "create")
    assert EXPERIMENTAL in str(ei.value)
    assert why in str(ei.value)


@pytest.mark.asyncio
async def test_existing_empty_primary_zone_is_adopted(monkeypatch: pytest.MonkeyPatch) -> None:
    d = _drv(
        monkeypatch,
        [
            _EXISTS,
            _ok({"zones": [{"name": "a.example.com", "type": "Primary"}], "totalPages": 1}),
            _ok({"records": [{"type": "SOA"}, {"type": "NS"}]}),
        ],
    )
    assert await d.apply_zone_change(_S(), _Z(), "create") is False


# ── validation pass: preview/commit agreement, ways out, Copilot ─────────


@pytest.mark.asyncio
async def test_zone_move_preview_reports_the_refusal_the_commit_raises(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Preview and commit agree: the preview names the refusal (and the UI
    blocks on it) instead of the operator finding out at commit."""
    t = await _token(db_session)
    src = await _group(db_session, "bind9")
    dst = await _group(db_session, "technitium_api")
    z = await _zone(db_session, src, zone_type="secondary")
    await db_session.commit()
    base = f"/api/v1/dns/groups/{src.id}/zones/{z.id}/move"
    pv = await client.post(f"{base}/preview", headers=_h(t), json={"target_group_id": str(dst.id)})
    assert pv.status_code == 200, pv.text
    refusal = pv.json()["technitium_api_refusal"]
    assert refusal and EXPERIMENTAL in refusal and "secondary" in refusal
    cm = await client.post(
        f"{base}/commit",
        headers=_h(t),
        json={"target_group_id": str(dst.id), "confirmation_zone_name": z.name},
    )
    assert cm.status_code == 422, cm.text
    assert cm.json()["detail"] == refusal


@pytest.mark.asyncio
async def test_zone_move_preview_clean_for_a_fitting_zone_and_other_targets(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    t = await _token(db_session)
    src = await _group(db_session, "bind9")
    dst = await _group(db_session, "technitium_api")
    other = await _group(db_session, "bind9")
    z = DNSZone(group_id=src.id, name=f"m{uuid.uuid4().hex[:6]}.example.com.", kind="forward")
    db_session.add(z)
    await db_session.commit()
    base = f"/api/v1/dns/groups/{src.id}/zones/{z.id}/move/preview"
    for target in (dst, other):
        pv = await client.post(base, headers=_h(t), json={"target_group_id": str(target.id)})
        assert pv.status_code == 200, pv.text
        assert pv.json()["technitium_api_refusal"] is None


@pytest.mark.asyncio
async def test_catalog_zones_can_be_turned_off_on_technitium_api(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Turning an unapplied setting OFF is the way out, not a new setting."""
    t = await _token(db_session)
    g = await _group(db_session, "technitium_api")
    g.catalog_zones_enabled = True
    await db_session.commit()
    url = f"/api/v1/dns/groups/{g.id}"
    assert (
        await client.put(url, headers=_h(t), json={"catalog_zones_enabled": True})
    ).status_code == 200
    r = await client.put(url, headers=_h(t), json={"catalog_zones_enabled": False})
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_stored_option_can_be_cleared_back_to_default(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    t = await _token(db_session)
    g = await _group(db_session, "technitium_api")
    await db_session.commit()
    opts = (
        await client.get(f"/api/v1/dns/groups/{g.id}/options", headers=_h(t))
    ).json()  # what the UI loads
    row = await db_session.get(DNSServerOptions, uuid.UUID(opts["id"]))
    assert row is not None
    row.forwarders = ["9.9.9.9"]
    await db_session.commit()
    url = f"/api/v1/dns/groups/{g.id}/options"
    # Unchanged re-save, then cleared: both fine. A different value: refused.
    assert (
        await client.put(url, headers=_h(t), json={"forwarders": ["9.9.9.9"]})
    ).status_code == 200
    _assert_refused(await client.put(url, headers=_h(t), json={"forwarders": ["1.1.1.1"]}))
    r = await client.put(url, headers=_h(t), json={"forwarders": []})
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_zone_field_can_be_put_back_to_default_and_ui_resave_passes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    t = await _token(db_session)
    g = await _group(db_session, "technitium_api")
    z = await _zone(db_session, g, ttl=300)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{g.id}/zones/{z.id}"
    # What ZoneModal sends on Save with nothing edited.
    ui = {
        "name": z.name.rstrip("."),
        "zone_type": "primary",
        "kind": "forward",
        "view_id": None,
        "primary_ns": "ns1.example.com.",
        "admin_email": "admin.example.com.",
        "ttl": 300,
        "dnssec_enabled": False,
        "color": None,
        "domain_id": None,
        "customer_id": None,
    }
    r = await client.put(url, headers=_h(t), json=ui)
    assert r.status_code == 200, r.text
    r = await client.put(url, headers=_h(t), json={**ui, "ttl": 3600, "primary_ns": ""})
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_copilot_create_zone_is_held_to_the_rest_scope(db_session: AsyncSession) -> None:
    """The Copilot fronts the REST API and must not be a way around its 422s."""
    from app.services.ai.operations import CreateDNSZoneArgs, get_operation

    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(user)
    g = await _group(db_session, "technitium_api")
    b = await _group(db_session, "bind9")
    await db_session.flush()
    op = get_operation("create_dns_zone")
    assert op is not None
    for bad in ({"zone_type": "secondary"}, {"ttl": 300}, {"primary_ns": "ns1.example.com."}):
        args = CreateDNSZoneArgs(name="c.example.com", group_id=str(g.id), **bad)
        pv = await op.preview(db_session, user, args)
        assert pv.ok is False and EXPERIMENTAL in pv.detail
        with pytest.raises(ValueError, match="experimental in 1.0"):
            await op.apply(db_session, user, args)
    # A plain Primary is fine, and other drivers are untouched.
    assert (
        await op.preview(
            db_session, user, CreateDNSZoneArgs(name="ok.example.com", group_id=str(g.id))
        )
    ).ok
    assert (
        await op.preview(
            db_session,
            user,
            CreateDNSZoneArgs(name="b.example.com", group_id=str(b.id), ttl=300),
        )
    ).ok


@pytest.mark.asyncio
async def test_real_create_response_is_never_read_as_adoption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Technitium's real create answer (``WebServiceZonesApi.CreateZoneAsync``
    always writes ``domain``) is a create: no adoption probe follows."""
    d = _drv(monkeypatch, [_ok({"domain": "a.example.com"})])
    assert await d.apply_zone_change(_S(), _Z(), "create") is True


@pytest.mark.asyncio
async def test_other_create_error_is_never_read_as_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.drivers.dns._cloud_base import CloudDNSError

    d = _drv(monkeypatch, [{"status": "error", "errorMessage": "Access was denied."}])
    with pytest.raises(CloudDNSError) as ei:
        await d.apply_zone_change(_S(), _Z(), "create")
    assert not isinstance(ei.value, CloudDNSConflictError)


@pytest.mark.asyncio
async def test_sub_apex_ns_delegation_is_not_adopted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only the apex NS is Technitium's own; a delegation is operator data."""
    d = _drv(
        monkeypatch,
        [
            _EXISTS,
            _ok({"zones": [{"name": "a.example.com", "type": "Primary"}], "totalPages": 1}),
            _ok(
                {
                    "records": [
                        {"type": "SOA", "name": "a.example.com"},
                        {"type": "NS", "name": "a.example.com"},
                        {"type": "NS", "name": "child.a.example.com"},
                    ]
                }
            ),
        ],
    )
    with pytest.raises(CloudDNSConflictError):
        await d.apply_zone_change(_S(), _Z(), "create")
