"""Dynamic-update (RFC 2136) ACLs on DNS zones (issue #641)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.agents import _auth_agent
from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.drivers.dns import get_driver
from app.drivers.dns.base import UpdateAclEntry
from app.main import app
from app.models.auth import User
from app.models.dns import (
    DNSRecord,
    DNSServer,
    DNSServerGroup,
    DNSTSIGKey,
    DNSView,
    DNSZone,
    DNSZoneUpdateAcl,
)
from app.services.dns.ingest import IncomingRecord, reconcile_external_records

# ── Driver capability + validation (pure) ───────────────────────────────────


def test_bind9_caps_full_surface() -> None:
    caps = get_driver("bind9").dynamic_update_caps
    # P1 coarse allow-update + P2 fine-grained update-policy.
    assert caps.supports_ip_acl is True
    assert caps.supports_tsig_acl is True
    assert caps.supports_name_scoping is True
    assert caps.supports_per_type is True


def test_bind9_validate_accepts_ip_and_tsig_with_spoof_warning() -> None:
    drv = get_driver("bind9")
    warnings = drv.validate_update_acl(
        "example.com.",
        [
            UpdateAclEntry(match_kind="ip", ip_cidr="10.0.0.0/24"),
            UpdateAclEntry(match_kind="tsig_key", tsig_key_name="dc01-ddns."),
        ],
    )
    # IP entries are UDP-spoofable → a warning, but accepted.
    assert any("spoofable" in w.lower() for w in warnings)


def test_bind9_accepts_fine_grained_update_policy() -> None:
    # P2: name-scope + per-type + deny are all valid for BIND9 now.
    drv = get_driver("bind9")
    warns = drv.validate_update_acl(
        "example.com.",
        [
            UpdateAclEntry(
                match_kind="tsig_key",
                tsig_key_name="dc01.",
                name_scope="subdomain",
                name_pattern="wks.example.com.",
                record_types=("A", "AAAA"),
            ),
            UpdateAclEntry(
                match_kind="tsig_key", action="deny", tsig_key_name="dc01.", name_scope="zonesub"
            ),
        ],
    )
    assert warns == []  # TSIG-only, no spoofable-IP warnings


def test_bind9_rejects_ip_mixed_with_update_policy() -> None:
    drv = get_driver("bind9")
    with pytest.raises(ValueError, match="update-policy"):
        drv.validate_update_acl(
            "example.com.",
            [
                UpdateAclEntry(match_kind="ip", ip_cidr="10.0.0.0/24"),
                UpdateAclEntry(
                    match_kind="tsig_key",
                    tsig_key_name="k.",
                    name_scope="zonesub",
                    record_types=("PTR",),
                ),
            ],
        )


def test_bind9_requires_name_pattern_for_named_scope() -> None:
    drv = get_driver("bind9")
    with pytest.raises(ValueError, match="name_pattern"):
        drv.validate_update_acl(
            "example.com.",
            [UpdateAclEntry(match_kind="tsig_key", tsig_key_name="k.", name_scope="subdomain")],
        )


def test_control_plane_renders_update_policy() -> None:
    from app.drivers.dns.base import ZoneData
    from app.drivers.dns.bind9 import _render_update_clause

    z = ZoneData(
        name="example.com.",
        zone_type="primary",
        kind="forward",
        ttl=3600,
        refresh=1,
        retry=1,
        expire=1,
        minimum=1,
        primary_ns="ns1.example.com.",
        admin_email="admin.example.com.",
        serial=1,
        dynamic_update_enabled=True,
        update_acl=(
            UpdateAclEntry(
                match_kind="tsig_key",
                tsig_key_name="dc01.",
                name_scope="subdomain",
                name_pattern="wks.example.com.",
                record_types=("A", "AAAA"),
            ),
            UpdateAclEntry(
                match_kind="tsig_key", action="deny", tsig_key_name="dc01.", name_scope="zonesub"
            ),
        ),
    )
    out = _render_update_clause(z)
    assert out.startswith("update-policy {")
    assert "grant dc01. subdomain wks.example.com. A AAAA;" in out
    assert "deny dc01. zonesub;" in out


def test_cloud_driver_has_no_dynamic_update_surface() -> None:
    caps = get_driver("route53").dynamic_update_caps
    assert not any([caps.supports_ip_acl, caps.supports_tsig_acl, caps.supports_name_scoping])
    with pytest.raises(ValueError, match="does not support"):
        get_driver("route53").validate_update_acl(
            "example.com.", [UpdateAclEntry(match_kind="ip", ip_cidr="10.0.0.0/24")]
        )


# ── Ingest-back reconcile ───────────────────────────────────────────────────


async def _group_zone(db: AsyncSession, *, dynamic: bool = True) -> DNSZone:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    zone = DNSZone(
        group_id=group.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.com.",
        zone_type="primary",
        kind="forward",
        dynamic_update_enabled=dynamic,
    )
    db.add(zone)
    await db.flush()
    return zone


async def test_reconcile_managed_name_wins_and_external_mirrored(
    db_session: AsyncSession,
) -> None:
    zone = await _group_zone(db_session)
    # A control-plane-managed record.
    db_session.add(DNSRecord(zone_id=zone.id, name="www", record_type="A", value="10.0.0.1"))
    await db_session.flush()

    incoming = [
        # Collides with a managed (name,type) → skipped.
        IncomingRecord(name="www", record_type="A", value="10.0.0.99"),
        # New external writer record → mirrored.
        IncomingRecord(name="dc01", record_type="A", value="10.0.0.5"),
        # Daemon-owned → ignored.
        IncomingRecord(name="@", record_type="SOA", value="ns1. admin. 1 2 3 4 5"),
    ]
    result = await reconcile_external_records(db_session, zone, incoming)
    assert result.added == 1
    assert result.skipped_managed == 1
    assert result.skipped_ignored == 1

    rows = (
        (await db_session.execute(DNSRecord.__table__.select().where(DNSRecord.zone_id == zone.id)))
        .mappings()
        .all()
    )
    externals = [r for r in rows if r["import_source"] == "ddns_external"]
    assert len(externals) == 1
    assert externals[0]["name"] == "dc01"
    # www stayed managed (10.0.0.1), not overwritten by the external 10.0.0.99.
    www = [r for r in rows if r["name"] == "www"]
    assert len(www) == 1 and www[0]["value"] == "10.0.0.1"


async def test_reconcile_removes_vanished_external(db_session: AsyncSession) -> None:
    zone = await _group_zone(db_session)
    await reconcile_external_records(
        db_session, zone, [IncomingRecord(name="dc01", record_type="A", value="10.0.0.5")]
    )
    # Next sweep: dc01 gone upstream → its mirror is removed.
    result = await reconcile_external_records(db_session, zone, [])
    assert result.removed == 1
    remaining = (
        (await db_session.execute(DNSRecord.__table__.select().where(DNSRecord.zone_id == zone.id)))
        .mappings()
        .all()
    )
    assert remaining == []


# ── Config bundle wiring ────────────────────────────────────────────────────


async def test_bundle_ships_acl_without_secret(db_session: AsyncSession) -> None:
    from app.services.dns.agent_config import build_config_bundle

    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    server = DNSServer(group_id=group.id, name="ns1", driver="bind9", host="10.0.0.53", port=53)
    key = DNSTSIGKey(
        group_id=group.id,
        name="dc01-ddns.",
        algorithm="hmac-sha256",
        secret_encrypted=encrypt_str("c2VjcmV0"),
    )
    zone = DNSZone(
        group_id=group.id,
        name="dyn.example.com.",
        zone_type="primary",
        kind="forward",
        dynamic_update_enabled=True,
    )
    db_session.add_all([server, key, zone])
    await db_session.flush()
    db_session.add_all(
        [
            DNSZoneUpdateAcl(
                zone_id=zone.id, seq=0, action="grant", match_kind="ip", ip_cidr="10.0.0.0/24"
            ),
            DNSZoneUpdateAcl(
                zone_id=zone.id, seq=1, action="grant", match_kind="tsig_key", tsig_key_id=key.id
            ),
        ]
    )
    await db_session.commit()

    bundle = await build_config_bundle(db_session, server)
    zpayload = next(z for z in bundle["zones"] if z["name"] == "dyn.example.com.")
    assert zpayload["dynamic_update_enabled"] is True
    acl = zpayload["update_acl"]
    assert {e["match_kind"] for e in acl} == {"ip", "tsig_key"}
    tsig_entry = next(e for e in acl if e["match_kind"] == "tsig_key")
    assert tsig_entry["tsig_key_name"] == "dc01-ddns."
    # The secret must never ride in the ACL payload.
    assert "secret" not in tsig_entry
    assert "c2VjcmV0" not in str(acl)


# ── API surface ─────────────────────────────────────────────────────────────


async def _superadmin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    u = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="sa",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return u, {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _bind9_group_zone_key(
    db: AsyncSession,
) -> tuple[DNSServerGroup, DNSZone, DNSTSIGKey]:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    db.add(DNSServer(group_id=group.id, name="ns1", driver="bind9", host="10.0.0.53", port=53))
    key = DNSTSIGKey(
        group_id=group.id,
        name="dc01-ddns.",
        algorithm="hmac-sha256",
        secret_encrypted=encrypt_str("c2VjcmV0"),
    )
    zone = DNSZone(group_id=group.id, name="api.example.com.", zone_type="primary", kind="forward")
    db.add_all([key, zone])
    await db.flush()
    return group, zone, key


async def test_put_and_get_update_acl_roundtrip(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _superadmin(db_session)
    group, zone, key = await _bind9_group_zone_key(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/zones/{zone.id}/update-acl",
        headers=headers,
        json={
            "dynamic_update_enabled": True,
            "entries": [
                {"match_kind": "ip", "ip_cidr": "10.0.0.5"},
                {"match_kind": "tsig_key", "tsig_key_id": str(key.id)},
            ],
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dynamic_update_enabled"] is True
    assert len(body["entries"]) == 2
    # host bits normalised to /32.
    ip_entry = next(e for e in body["entries"] if e["match_kind"] == "ip")
    assert ip_entry["ip_cidr"] == "10.0.0.5/32"
    tsig_entry = next(e for e in body["entries"] if e["match_kind"] == "tsig_key")
    assert tsig_entry["tsig_key_name"] == "dc01-ddns."
    assert any("spoofable" in w.lower() for w in body["warnings"])
    # No secret anywhere in the response.
    assert "c2VjcmV0" not in r.text

    g = await client.get(
        f"/api/v1/dns/groups/{group.id}/zones/{zone.id}/update-acl", headers=headers
    )
    assert g.status_code == 200
    assert len(g.json()["entries"]) == 2


async def test_put_accepts_name_scoped_entry(client: AsyncClient, db_session: AsyncSession) -> None:
    """P2: a name-scoped / per-type TSIG grant is now accepted (update-policy)."""
    _, headers = await _superadmin(db_session)
    group, zone, key = await _bind9_group_zone_key(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/zones/{zone.id}/update-acl",
        headers=headers,
        json={
            "entries": [
                {
                    "match_kind": "tsig_key",
                    "tsig_key_id": str(key.id),
                    "name_scope": "subdomain",
                    "name_pattern": "wks.api.example.com.",
                    "record_types": ["A", "AAAA"],
                }
            ]
        },
    )
    assert r.status_code == 200, r.text
    e = r.json()["entries"][0]
    assert e["name_scope"] == "subdomain" and e["record_types"] == ["A", "AAAA"]


async def test_put_rejects_ip_mixed_with_update_policy_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _superadmin(db_session)
    group, zone, key = await _bind9_group_zone_key(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/zones/{zone.id}/update-acl",
        headers=headers,
        json={
            "entries": [
                {"match_kind": "ip", "ip_cidr": "10.0.0.0/24"},
                {
                    "match_kind": "tsig_key",
                    "tsig_key_id": str(key.id),
                    "name_scope": "zonesub",
                    "record_types": ["PTR"],
                },
            ]
        },
    )
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "DYNAMIC_UPDATE_UNSUPPORTED"


async def test_cloud_group_caps_unsupported_and_put_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _superadmin(db_session)
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    db_session.add(DNSServer(group_id=group.id, name="cf", driver="route53", host="cloud"))
    zone = DNSZone(
        group_id=group.id, name="cloud.example.com.", zone_type="primary", kind="forward"
    )
    db_session.add(zone)
    await db_session.commit()

    caps = await client.get(f"/api/v1/dns/groups/{group.id}/dynamic-update-caps", headers=headers)
    assert caps.status_code == 200
    assert caps.json()["supported"] is False

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/zones/{zone.id}/update-acl",
        headers=headers,
        json={"entries": [{"match_kind": "ip", "ip_cidr": "10.0.0.0/24"}]},
    )
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "DYNAMIC_UPDATE_UNSUPPORTED"


async def test_ingest_endpoint_handles_split_horizon_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Same zone name across two views must not 500 the ingest endpoint (#641
    review fix): the lookup prefers the global (view_id IS NULL) copy instead
    of `scalar_one_or_none()` raising MultipleResultsFound."""
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    server = DNSServer(group_id=group.id, name="ns1", driver="bind9", host="10.0.0.53", port=53)
    view = DNSView(group_id=group.id, name="internal")
    db_session.add_all([server, view])
    await db_session.flush()
    # A global copy + a view-scoped copy, same name.
    zglobal = DNSZone(
        group_id=group.id,
        name="split.example.com.",
        zone_type="primary",
        kind="forward",
        dynamic_update_enabled=True,
    )
    zview = DNSZone(
        group_id=group.id,
        view_id=view.id,
        name="split.example.com.",
        zone_type="primary",
        kind="forward",
        dynamic_update_enabled=True,
    )
    db_session.add_all([zglobal, zview])
    await db_session.commit()

    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        r = await client.post(
            "/api/v1/dns/agents/ingested-records",
            json={
                "zone_name": "split.example.com",
                "records": [{"name": "dc01", "record_type": "A", "value": "10.0.0.5"}],
            },
        )
    finally:
        app.dependency_overrides.pop(_auth_agent, None)

    assert r.status_code == 200, r.text
    assert r.json()["added"] == 1
    # Mirrored under the global copy, not the view-scoped one.
    externals = (
        (
            await db_session.execute(
                DNSRecord.__table__.select().where(DNSRecord.import_source == "ddns_external")
            )
        )
        .mappings()
        .all()
    )
    assert len(externals) == 1
    assert externals[0]["zone_id"] == zglobal.id


# ── PowerDNS (P3, coarse-only) ───────────────────────────────────────────────


def test_powerdns_caps_coarse_only() -> None:
    caps = get_driver("powerdns").dynamic_update_caps
    assert caps.supports_ip_acl and caps.supports_tsig_acl
    assert not caps.supports_name_scoping and not caps.supports_per_type


def test_powerdns_rejects_fine_grained() -> None:
    with pytest.raises(ValueError, match="scope"):
        get_driver("powerdns").validate_update_acl(
            "z.",
            [
                UpdateAclEntry(
                    match_kind="tsig_key",
                    tsig_key_name="k.",
                    name_scope="subdomain",
                    name_pattern="x.z.",
                )
            ],
        )


def test_powerdns_conf_enables_dnsupdate() -> None:
    from app.drivers.dns.powerdns import render_pdns_conf

    assert "dnsupdate=yes" in render_pdns_conf(api_key="k")


# ── Windows DNS (P3, coarse enum) ────────────────────────────────────────────


def test_windows_caps_coarse_enum() -> None:
    from app.api.v1.dns.router import _caps_out

    caps = get_driver("windows_dns").dynamic_update_caps
    assert caps.coarse_enum_only is True
    assert caps.supports_tsig_acl is True
    assert not caps.supports_name_scoping and not caps.supports_per_type
    # coarse_enum_only ⇒ the feature is "supported" (not outright 422'd).
    assert _caps_out(caps).supported is True


def test_windows_enum_mapping() -> None:
    from app.drivers.dns.windows import windows_dynamic_update_mode

    assert windows_dynamic_update_mode(False, False) == "None"
    assert windows_dynamic_update_mode(True, False) == "Secure"
    assert windows_dynamic_update_mode(True, True) == "NonsecureAndSecure"


def test_windows_ip_entry_warns_not_rejects() -> None:
    warns = get_driver("windows_dns").validate_update_acl(
        "z.", [UpdateAclEntry(match_kind="ip", ip_cidr="10.0.0.0/24")]
    )
    assert any("nonsecure" in w.lower() for w in warns)


def test_windows_rejects_name_scope() -> None:
    with pytest.raises(ValueError, match="scope"):
        get_driver("windows_dns").validate_update_acl(
            "z.",
            [
                UpdateAclEntry(
                    match_kind="tsig_key",
                    tsig_key_name="k.",
                    name_scope="subdomain",
                    name_pattern="x.z.",
                )
            ],
        )


# ── Audit trail for ingested records (#2302) ────────────────────────────────


async def _ingest_post(client: AsyncClient, server: DNSServer, zone_name: str, records: list[dict]):
    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        return await client.post(
            "/api/v1/dns/agents/ingested-records",
            json={"zone_name": zone_name, "records": records},
        )
    finally:
        app.dependency_overrides.pop(_auth_agent, None)


async def test_ingest_audits_adds_and_removes_by_name(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.models.audit import AuditLog

    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    server = DNSServer(group_id=group.id, name="ns1", driver="bind9", host="10.0.0.53", port=53)
    zone = DNSZone(
        group_id=group.id,
        name="aud.example.com.",
        zone_type="primary",
        kind="forward",
        dynamic_update_enabled=True,
    )
    db_session.add_all([server, zone])
    await db_session.commit()

    r = await _ingest_post(
        client,
        server,
        "aud.example.com",
        [{"name": "dc01", "record_type": "A", "value": "10.0.0.5"}],
    )
    assert r.status_code == 200, r.text
    # Next sweep: dc01 withdrawn, dc02 appears.
    r = await _ingest_post(
        client,
        server,
        "aud.example.com",
        [{"name": "dc02", "record_type": "A", "value": "10.0.0.6"}],
    )
    assert r.status_code == 200, r.text
    # Identical sweep: no change, no audit row.
    r = await _ingest_post(
        client,
        server,
        "aud.example.com",
        [{"name": "dc02", "record_type": "A", "value": "10.0.0.6"}],
    )
    assert r.json()["added"] == 0 and r.json()["removed"] == 0

    rows = (
        (
            await db_session.execute(
                select(AuditLog)
                .where(AuditLog.action == "dns.record.external_ingest")
                .order_by(AuditLog.timestamp)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 2  # one summary row per changing batch
    assert rows[0].resource_id == str(zone.id)
    assert [a["fqdn"] for a in rows[0].new_value["added_records"]] == ["dc01.aud.example.com"]
    assert [a["fqdn"] for a in rows[1].new_value["added_records"]] == ["dc02.aud.example.com"]
    removed = rows[1].old_value["removed_records"]
    assert [x["fqdn"] for x in removed] == ["dc01.aud.example.com"]
    assert removed[0]["value"] == "10.0.0.5"
    assert rows[1].new_value["removed"] == 1


async def test_ingest_audit_names_are_capped(client: AsyncClient, db_session: AsyncSession) -> None:
    from app.models.audit import AuditLog

    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    server = DNSServer(group_id=group.id, name="ns1", driver="bind9", host="10.0.0.53", port=53)
    zone = DNSZone(
        group_id=group.id,
        name="cap.example.com.",
        zone_type="primary",
        kind="forward",
        dynamic_update_enabled=True,
    )
    db_session.add_all([server, zone])
    await db_session.commit()

    recs = [{"name": f"h{i}", "record_type": "A", "value": f"10.1.0.{i}"} for i in range(80)]
    r = await _ingest_post(client, server, "cap.example.com", recs)
    assert r.json()["added"] == 80
    row = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "dns.record.external_ingest")
        )
    ).scalar_one()
    assert row.new_value["added"] == 80
    assert len(row.new_value["added_records"]) == 50
    assert row.new_value["truncated"] is True
