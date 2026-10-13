"""The built-in DNS and DHCP Editors can do the everyday writes they promise (#1861).

Both roles promised "Full CRUD" on their resources while nearly every DNS and
DHCP write route also took ``SuperAdmin``, so an Editor filled in New DHCP
Scope or Add Zone and met "Superadmin required". The everyday data routes now
check the role's own resource permission, with ``delete`` for a delete;
infrastructure (server groups, servers, server options, TSIG keys, DNSSEC,
blocklist subscriptions, failover, importers) stays superadmin-only.

Every test here drives the real API as a user holding exactly one built-in
role, with the grants taken from ``app.main._BUILTIN_ROLES`` — the rows the
api seeds on every start — so a test fails when a role and the routes drift
apart, not only when a route changes.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.main import _BUILTIN_ROLES
from app.models.auth import Group, Role, User
from app.models.dhcp import DHCPScope, DHCPServerGroup
from app.models.dns import DNSBlockList, DNSServerGroup, DNSZone
from app.models.ipam import IPBlock, IPSpace, Subnet

pytestmark = pytest.mark.asyncio

CIDR = "198.51.100.0/24"


async def _headers(
    db: AsyncSession,
    *,
    role: str | None = None,
    permissions: list[dict[str, Any]] | None = None,
    superadmin: bool = False,
) -> dict[str, str]:
    """A user holding exactly one role: a built-in one by name, or ``permissions``."""
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"ed-{tag}",
        email=f"{tag}@example.test",
        display_name="Editor",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    if role is not None or permissions is not None:
        perms = list(_BUILTIN_ROLES[role][1]) if role is not None else list(permissions or [])
        r = Role(name=f"r-{tag}", description="", permissions=perms)
        g = Group(name=f"g-{tag}", description="")
        g.roles = [r]
        g.users = [user]
        db.add_all([r, g])
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _dns_group(db: AsyncSession) -> DNSServerGroup:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    return grp


async def _zone(db: AsyncSession, grp: DNSServerGroup) -> DNSZone:
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(zone)
    await db.flush()
    return zone


async def _subnet_and_dhcp_group(db: AsyncSession) -> tuple[Subnet, DHCPServerGroup]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=CIDR, name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=CIDR, name="s")
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add_all([subnet, grp])
    await db.flush()
    return subnet, grp


def _ok(resp: Any, *codes: int) -> dict[str, Any]:
    assert resp.status_code in codes, f"{resp.request.method} {resp.request.url}: {resp.text}"
    return resp.json() if resp.content else {}


# ── DNS ────────────────────────────────────────────────────────────────────


async def test_dns_editor_creates_edits_and_deletes_a_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, role="DNS Editor")
    grp = await _dns_group(db_session)
    await db_session.commit()
    base = f"/api/v1/dns/groups/{grp.id}/zones"

    zone = _ok(await client.post(base, headers=h, json={"name": "editor.example."}), 201)
    _ok(await client.put(f"{base}/{zone['id']}", headers=h, json={"ttl": 7200}), 200)
    # Sending the current value of a superadmin-only field back is not a change.
    _ok(
        await client.put(
            f"{base}/{zone['id']}", headers=h, json={"ttl": 3600, "dnssec_enabled": False}
        ),
        200,
    )
    rec = _ok(
        await client.post(
            f"{base}/{zone['id']}/records",
            headers=h,
            json={"name": "www", "record_type": "A", "value": "192.0.2.10"},
        ),
        201,
    )
    _ok(await client.delete(f"{base}/{zone['id']}/records/{rec['id']}", headers=h), 204)
    _ok(await client.delete(f"{base}/{zone['id']}", headers=h), 204)


async def test_dns_editor_is_refused_dnssec_tls_probing_and_permanent_delete(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, role="DNS Editor")
    grp = await _dns_group(db_session)
    zone = await _zone(db_session, grp)
    await db_session.commit()
    base = f"/api/v1/dns/groups/{grp.id}/zones"

    for body in ({"name": "signed.example.", "dnssec_enabled": True},):
        r = await client.post(base, headers=h, json=body)
        assert r.status_code == 403, r.text
        assert "DNSSEC" in r.text
    for body in ({"dnssec_enabled": True}, {"auto_tls_probe": True}):
        r = await client.put(f"{base}/{zone.id}", headers=h, json=body)
        assert r.status_code == 403, (body, r.text)
    zone_id = zone.id
    r = await client.delete(f"{base}/{zone_id}?permanent=true", headers=h)
    assert r.status_code == 403, r.text
    db_session.expire_all()
    still = await db_session.get(DNSZone, zone_id)
    assert still is not None and still.deleted_at is None


async def test_dns_editor_manages_views_and_acls(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, role="DNS Editor")
    grp = await _dns_group(db_session)
    await db_session.commit()
    g = f"/api/v1/dns/groups/{grp.id}"

    view = _ok(
        await client.post(
            f"{g}/views", headers=h, json={"name": "internal", "match_clients": ["10.0.0.0/8"]}
        ),
        201,
    )
    _ok(await client.put(f"{g}/views/{view['id']}", headers=h, json={"description": "LAN"}), 200)
    _ok(await client.delete(f"{g}/views/{view['id']}", headers=h), 204)

    acl = _ok(
        await client.post(
            f"{g}/acls", headers=h, json={"name": "lan", "entries": [{"value": "10.0.0.0/8"}]}
        ),
        201,
    )
    _ok(
        await client.put(
            f"{g}/acls/{acl['id']}",
            headers=h,
            json={"entries": [{"value": "10.0.0.0/8"}, {"value": "172.16.0.0/12"}]},
        ),
        200,
    )
    _ok(await client.delete(f"{g}/acls/{acl['id']}", headers=h), 204)


async def test_dns_editor_maintains_blocklist_entries_and_exceptions(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, role="DNS Editor")
    bl = DNSBlockList(name=f"bl-{uuid.uuid4().hex[:6]}")
    db_session.add(bl)
    await db_session.flush()
    await db_session.commit()
    b = f"/api/v1/dns/blocklists/{bl.id}"

    entry = _ok(await client.post(f"{b}/entries", headers=h, json={"domain": "bad.example"}), 201)
    _ok(
        await client.put(f"{b}/entries/{entry['id']}", headers=h, json={"domain": "worse.example"}),
        200,
    )
    _ok(await client.delete(f"{b}/entries/{entry['id']}", headers=h), 204)
    exc = _ok(await client.post(f"{b}/exceptions", headers=h, json={"domain": "ok.example"}), 201)
    _ok(
        await client.put(f"{b}/exceptions/{exc['id']}", headers=h, json={"reason": "vendor"}),
        200,
    )
    _ok(await client.delete(f"{b}/exceptions/{exc['id']}", headers=h), 204)


async def test_dns_editor_is_refused_dns_infrastructure(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, role="DNS Editor")
    grp = await _dns_group(db_session)
    zone = await _zone(db_session, grp)
    bl = DNSBlockList(name=f"bl-{uuid.uuid4().hex[:6]}")
    db_session.add(bl)
    await db_session.flush()
    await db_session.commit()
    g = f"/api/v1/dns/groups/{grp.id}"
    calls = [
        ("POST", "/api/v1/dns/groups", {"name": "edge"}),
        ("DELETE", g, None),
        ("POST", f"{g}/servers", {"name": "ns9", "driver": "bind9", "host": "192.0.2.9"}),
        ("PUT", f"{g}/options", {"forwarders": ["192.0.2.53"]}),
        ("POST", f"{g}/tsig-keys", {"name": "k1"}),
        ("POST", f"{g}/zones/{zone.id}/dnssec/sign", {}),
        ("POST", "/api/v1/dns/dnssec-policies", {"name": "p"}),
        ("POST", "/api/v1/dns/blocklists", {"name": "new"}),
        ("PUT", f"/api/v1/dns/blocklists/{bl.id}/assignments", {"server_group_ids": []}),
        ("POST", f"/api/v1/dns/blocklists/{bl.id}/refresh", None),
    ]
    for method, url, body in calls:
        r = await client.request(method, url, headers=h, json=body)
        assert r.status_code == 403, f"{method} {url}: {r.status_code} {r.text}"
        assert r.json()["detail"] == "Superadmin required", f"{method} {url}: {r.text}"
    # GSLB pools: the role holds only read on manage_dns_pools, so the router
    # refuses before the handler's own superadmin gate is reached.
    r = await client.post(f"{g}/zones/{zone.id}/pools", headers=h, json={"name": "web"})
    assert r.status_code == 403, r.text


async def test_dns_viewer_is_refused_the_everyday_writes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, role="Viewer")
    grp = await _dns_group(db_session)
    zone = await _zone(db_session, grp)
    bl = DNSBlockList(name=f"bl-{uuid.uuid4().hex[:6]}")
    db_session.add(bl)
    await db_session.flush()
    await db_session.commit()
    g = f"/api/v1/dns/groups/{grp.id}"
    calls = [
        ("POST", f"{g}/zones", {"name": "v.example."}),
        ("PUT", f"{g}/zones/{zone.id}", {"ttl": 60}),
        ("DELETE", f"{g}/zones/{zone.id}", None),
        ("POST", f"{g}/views", {"name": "v"}),
        ("POST", f"{g}/acls", {"name": "a"}),
        ("POST", f"/api/v1/dns/blocklists/{bl.id}/entries", {"domain": "x.example"}),
    ]
    for method, url, body in calls:
        r = await client.request(method, url, headers=h, json=body)
        assert r.status_code == 403, f"{method} {url}: {r.status_code} {r.text}"
    # ...while it can still read.
    _ok(await client.get(f"{g}/zones", headers=h), 200)


async def test_a_zone_write_needs_dns_zone_not_just_dns_record(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # The DNS router admits a write on any of its three types; the zone
    # routes additionally check their own, so a records-only role cannot
    # create or delete zones.
    h = await _headers(db_session, permissions=[{"action": "admin", "resource_type": "dns_record"}])
    grp = await _dns_group(db_session)
    zone = await _zone(db_session, grp)
    await db_session.commit()
    g = f"/api/v1/dns/groups/{grp.id}"
    assert (
        await client.post(f"{g}/zones", headers=h, json={"name": "r.example."})
    ).status_code == 403
    assert (await client.delete(f"{g}/zones/{zone.id}", headers=h)).status_code == 403
    assert (
        await client.post(
            f"{g}/zones/{zone.id}/records",
            headers=h,
            json={"name": "a", "record_type": "A", "value": "192.0.2.1"},
        )
    ).status_code == 201


async def test_deleting_takes_delete_not_write(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(
        db_session,
        permissions=[
            {"action": "read", "resource_type": "*"},
            {"action": "write", "resource_type": "dns_zone"},
            {"action": "write", "resource_type": "dns_group"},
            {"action": "write", "resource_type": "dhcp_scope"},
        ],
    )
    grp = await _dns_group(db_session)
    zone = await _zone(db_session, grp)
    subnet, dgrp = await _subnet_and_dhcp_group(db_session)
    scope = DHCPScope(group_id=dgrp.id, subnet_id=subnet.id, name="s")
    db_session.add(scope)
    await db_session.flush()
    await db_session.commit()

    assert (
        await client.delete(f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}", headers=h)
    ).status_code == 403
    assert (await client.delete(f"/api/v1/dhcp/scopes/{scope.id}", headers=h)).status_code == 403
    # ...though the same role can edit both.
    _ok(
        await client.put(
            f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}", headers=h, json={"ttl": 120}
        ),
        200,
    )
    _ok(await client.put(f"/api/v1/dhcp/scopes/{scope.id}", headers=h, json={"name": "s2"}), 200)


async def test_a_replace_import_that_removes_records_takes_delete(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.models.dns import DNSRecord

    h = await _headers(
        db_session,
        permissions=[
            {"action": "read", "resource_type": "*"},
            {"action": "write", "resource_type": "dns_record"},
        ],
    )
    grp = await _dns_group(db_session)
    zone = await _zone(db_session, grp)
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            name="old",
            fqdn=f"old.{zone.name}",
            record_type="A",
            value="192.0.2.20",
        )
    )
    await db_session.flush()
    await db_session.commit()
    url = f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/import/commit"
    zone_file = f"$ORIGIN {zone.name}\nnew 3600 IN A 192.0.2.21\n"

    r = await client.post(
        url, headers=h, json={"zone_file": zone_file, "conflict_strategy": "replace"}
    )
    assert r.status_code == 403, r.text
    # A merge removes nothing, so write is enough.
    _ok(
        await client.post(
            url, headers=h, json={"zone_file": zone_file, "conflict_strategy": "merge"}
        ),
        200,
    )


# ── DHCP ───────────────────────────────────────────────────────────────────


async def test_dhcp_editor_manages_scopes_pools_and_statics(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, role="DHCP Editor")
    subnet, grp = await _subnet_and_dhcp_group(db_session)
    await db_session.commit()

    scope = _ok(
        await client.post(
            f"/api/v1/dhcp/subnets/{subnet.id}/dhcp-scopes",
            headers=h,
            json={"group_id": str(grp.id), "name": "staff"},
        ),
        201,
    )
    s = f"/api/v1/dhcp/scopes/{scope['id']}"
    _ok(await client.put(s, headers=h, json={"enabled": False}), 200)

    pool = _ok(
        await client.post(
            f"{s}/pools",
            headers=h,
            json={"start_ip": "198.51.100.100", "end_ip": "198.51.100.150"},
        ),
        201,
    )
    _ok(
        await client.put(
            f"/api/v1/dhcp/pools/{pool['id']}", headers=h, json={"end_ip": "198.51.100.160"}
        ),
        200,
    )
    _ok(await client.delete(f"/api/v1/dhcp/pools/{pool['id']}", headers=h), 204)

    static = _ok(
        await client.post(
            f"{s}/statics",
            headers=h,
            json={"ip_address": "198.51.100.20", "mac_address": "02:00:00:00:00:20"},
        ),
        201,
    )
    _ok(
        await client.put(
            f"/api/v1/dhcp/statics/{static['id']}", headers=h, json={"hostname": "printer"}
        ),
        200,
    )
    _ok(await client.delete(f"/api/v1/dhcp/statics/{static['id']}", headers=h), 204)

    _ok(await client.delete(s, headers=h), 204)


async def test_dhcp_editor_manages_group_level_dhcp_data(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, role="DHCP Editor")
    subnet, grp = await _subnet_and_dhcp_group(db_session)
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id, name="s")
    db_session.add(scope)
    await db_session.flush()
    await db_session.commit()
    g = f"/api/v1/dhcp/server-groups/{grp.id}"

    cc = _ok(await client.post(f"{g}/client-classes", headers=h, json={"name": "printers"}), 201)
    _ok(
        await client.put(
            f"/api/v1/dhcp/client-classes/{cc['id']}", headers=h, json={"description": "x"}
        ),
        200,
    )
    _ok(await client.delete(f"/api/v1/dhcp/client-classes/{cc['id']}", headers=h), 204)

    tpl = _ok(
        await client.post(
            f"{g}/option-templates",
            headers=h,
            json={"name": "office", "options": {"domain-name-servers": ["192.0.2.53"]}},
        ),
        201,
    )
    _ok(
        await client.post(
            f"/api/v1/dhcp/scopes/{scope.id}/apply-option-template",
            headers=h,
            json={"template_id": tpl["id"]},
        ),
        200,
    )
    _ok(
        await client.put(
            f"/api/v1/dhcp/option-templates/{tpl['id']}", headers=h, json={"description": "x"}
        ),
        200,
    )
    _ok(await client.delete(f"/api/v1/dhcp/option-templates/{tpl['id']}", headers=h), 204)

    blk = _ok(
        await client.post(f"{g}/mac-blocks", headers=h, json={"mac_address": "02:00:00:00:00:99"}),
        201,
    )
    _ok(
        await client.put(
            f"/api/v1/dhcp/mac-blocks/{blk['id']}", headers=h, json={"description": "lost"}
        ),
        200,
    )
    _ok(await client.delete(f"/api/v1/dhcp/mac-blocks/{blk['id']}", headers=h), 204)

    pxe = _ok(
        await client.post(
            f"{g}/pxe-profiles", headers=h, json={"name": "lab", "next_server": "192.0.2.5"}
        ),
        201,
    )
    _ok(
        await client.put(
            f"/api/v1/dhcp/pxe-profiles/{pxe['id']}", headers=h, json={"description": "x"}
        ),
        200,
    )
    _ok(await client.delete(f"/api/v1/dhcp/pxe-profiles/{pxe['id']}", headers=h), 204)

    phone = _ok(await client.post(f"{g}/phone-profiles", headers=h, json={"name": "desk"}), 201)
    _ok(
        await client.put(
            f"/api/v1/dhcp/phone-profiles/{phone['id']}", headers=h, json={"description": "x"}
        ),
        200,
    )
    _ok(await client.delete(f"/api/v1/dhcp/phone-profiles/{phone['id']}", headers=h), 204)


async def test_dhcp_editor_is_refused_permanent_scope_delete(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, role="DHCP Editor")
    subnet, grp = await _subnet_and_dhcp_group(db_session)
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id, name="s")
    db_session.add(scope)
    await db_session.flush()
    await db_session.commit()
    scope_id = scope.id
    r = await client.delete(f"/api/v1/dhcp/scopes/{scope_id}?permanent=true", headers=h)
    assert r.status_code == 403, r.text
    db_session.expire_all()
    row = (
        await db_session.execute(
            select(DHCPScope)
            .where(DHCPScope.id == scope_id)
            .execution_options(include_deleted=True)
        )
    ).scalar_one()
    assert row.deleted_at is None


async def test_dhcp_editor_is_refused_dhcp_infrastructure(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, role="DHCP Editor")
    _subnet, grp = await _subnet_and_dhcp_group(db_session)
    await db_session.commit()
    g = f"/api/v1/dhcp/server-groups/{grp.id}"
    calls = [
        ("POST", "/api/v1/dhcp/server-groups", {"name": "edge"}),
        ("PUT", g, {"description": "x"}),
        ("DELETE", g, None),
        ("POST", "/api/v1/dhcp/servers", {"name": "kea9", "driver": "kea", "host": "192.0.2.9"}),
        ("POST", f"{g}/failover/relationships", {"name": "r"}),
        ("POST", "/api/v1/dhcp/import/kea/preview", {}),
    ]
    for method, url, body in calls:
        r = await client.request(method, url, headers=h, json=body)
        assert r.status_code == 403, f"{method} {url}: {r.status_code} {r.text}"
        assert r.json()["detail"] == "Superadmin required", f"{method} {url}: {r.text}"


async def test_dhcp_viewer_is_refused_the_everyday_writes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, role="Viewer")
    subnet, grp = await _subnet_and_dhcp_group(db_session)
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id, name="s")
    db_session.add(scope)
    await db_session.flush()
    await db_session.commit()
    g = f"/api/v1/dhcp/server-groups/{grp.id}"
    calls = [
        (
            "POST",
            f"/api/v1/dhcp/subnets/{subnet.id}/dhcp-scopes",
            {"group_id": str(grp.id), "name": "v"},
        ),
        ("PUT", f"/api/v1/dhcp/scopes/{scope.id}", {"name": "v"}),
        ("DELETE", f"/api/v1/dhcp/scopes/{scope.id}", None),
        (
            "POST",
            f"/api/v1/dhcp/scopes/{scope.id}/statics",
            {"ip_address": "198.51.100.30", "mac_address": "02:00:00:00:00:30"},
        ),
        ("POST", f"{g}/client-classes", {"name": "c"}),
        ("POST", f"{g}/mac-blocks", {"mac_address": "02:00:00:00:00:31"}),
    ]
    for method, url, body in calls:
        r = await client.request(method, url, headers=h, json=body)
        assert r.status_code == 403, f"{method} {url}: {r.status_code} {r.text}"
    _ok(await client.get(f"/api/v1/dhcp/scopes/{scope.id}", headers=h), 200)


async def test_superadmin_keeps_every_write(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _headers(db_session, superadmin=True)
    subnet, dgrp = await _subnet_and_dhcp_group(db_session)
    await db_session.commit()
    _ok(await client.post("/api/v1/dns/groups", headers=h, json={"name": "sa-grp"}), 201)
    _ok(await client.post("/api/v1/dhcp/server-groups", headers=h, json={"name": "sa-dhcp"}), 201)
    scope = _ok(
        await client.post(
            f"/api/v1/dhcp/subnets/{subnet.id}/dhcp-scopes",
            headers=h,
            json={"group_id": str(dgrp.id), "name": "sa"},
        ),
        201,
    )
    _ok(await client.delete(f"/api/v1/dhcp/scopes/{scope['id']}?permanent=true", headers=h), 204)


async def test_auditor_reads_the_audit_log(client: AsyncClient, db_session: AsyncSession) -> None:
    # #1862 — the Auditor's grant now names the type the audit routes check.
    h = await _headers(db_session, role="Auditor")
    await db_session.commit()
    _ok(await client.get("/api/v1/audit?limit=5", headers=h), 200)
    _ok(await client.get("/api/v1/audit/integrity", headers=h), 200)
