"""#2167 — the zone-file import never deletes or edits what something else owns,
and works on one view scope.

Before: ``conflict_strategy=replace`` deleted records IPAM had written (an
address's host record and its aliases), and the records a DNS pool, Tailscale,
NetBird or a Kubernetes cluster maintains. IPAM kept showing addresses whose
records were gone, and each integration recreated (or lost) its rows on its next
sync. The diff also keyed on (name, type, value) with no view, so of two view
twins only one was matched and the other was neither kept nor deleted, and every
created record landed shared (``view_id IS NULL``), rendering into every view.

After: owned rows are filtered with the spreadsheet import's ``managed_by``
(#2139), so the two importers protect the same rows; a protected row is reported
in ``skipped`` by name and reason. The import targets one scope, ``view_id`` or
the shared records, and never touches another.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import (
    DNSPool,
    DNSPoolMember,
    DNSRecord,
    DNSServer,
    DNSServerGroup,
    DNSView,
    DNSZone,
)
from app.models.ipam import IPSpace
from app.models.kubernetes import KubernetesCluster
from app.models.netbird import NetbirdInstance
from app.models.tailscale import TailscaleTenant
from app.services.dns_io import diff_records, parse_zone_file

ZONE = "own.example.edu."


async def _headers(db: AsyncSession) -> dict[str, str]:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"u-{tag}",
        email=f"{tag}@example.test",
        display_name="Test",
        hashed_password=hash_password("x" * 12),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _zone(db: AsyncSession) -> tuple[DNSServerGroup, DNSZone]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="ns1.example.edu",
            name=f"srv-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name=ZONE,
        zone_type="primary",
        kind="forward",
        primary_ns=f"ns1.{ZONE}",
        admin_email=f"admin.{ZONE}",
    )
    db.add(zone)
    await db.flush()
    return grp, zone


def _rec(zone: DNSZone, name: str, rtype: str, value: str, **kw: Any) -> DNSRecord:
    return DNSRecord(
        zone_id=zone.id,
        name=name,
        fqdn=f"{name}.{zone.name}" if name != "@" else zone.name,
        record_type=rtype,
        value=value,
        **kw,
    )


async def _post(
    client: AsyncClient,
    h: dict[str, str],
    grp: DNSServerGroup,
    zone: DNSZone,
    text: str,
    step: str,
    strategy: str = "replace",
    view_id: uuid.UUID | None = None,
    expect: int = 200,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "zone_file": f"$ORIGIN {ZONE}\n$TTL 3600\n{text}",
        "zone_name": ZONE,
        "conflict_strategy": strategy,
    }
    if view_id is not None:
        body["view_id"] = str(view_id)
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/import/{step}", headers=h, json=body
    )
    assert r.status_code == expect, r.text
    out: dict[str, Any] = r.json()
    return out


async def _owned_records(db: AsyncSession, grp: DNSServerGroup, zone: DNSZone) -> dict[str, Any]:
    """One record per owner the import must leave alone, keyed by owner."""
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    pool = DNSPool(group_id=grp.id, zone_id=zone.id, name="web", record_name="pooled")
    tenant = TailscaleTenant(name=f"ts-{uuid.uuid4().hex[:6]}", ipam_space_id=space.id)
    netbird = NetbirdInstance(name=f"nb-{uuid.uuid4().hex[:6]}", ipam_space_id=space.id)
    cluster = KubernetesCluster(
        name=f"k8s-{uuid.uuid4().hex[:6]}",
        api_server_url="https://k8s.example.test:6443",
        ca_bundle_pem="",
        token_encrypted=encrypt_str("faketoken"),
        ipam_space_id=space.id,
        dns_group_id=grp.id,
    )
    db.add_all([pool, tenant, netbird, cluster])
    await db.flush()
    member = DNSPoolMember(pool_id=pool.id, address="10.0.0.50")
    db.add(member)
    await db.flush()
    rows = {
        "ipam-host": _rec(zone, "host1", "A", "10.0.0.1", auto_generated=True),
        "ipam-alias": _rec(
            zone, "alias1", "CNAME", f"host1.{ZONE}", auto_generated=True, ip_alias=True
        ),
        "pool": _rec(zone, "pooled", "A", "10.0.0.50", pool_member_id=member.id),
        "tailscale": _rec(zone, "tsnode", "A", "100.64.0.5", tailscale_tenant_id=tenant.id),
        "netbird": _rec(zone, "nbnode", "A", "100.64.1.5", netbird_instance_id=netbird.id),
        "kubernetes": _rec(zone, "ingress", "A", "10.0.0.60", kubernetes_cluster_id=cluster.id),
    }
    db.add_all(rows.values())
    return rows


async def test_replace_keeps_every_owned_record_and_reports_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, zone = await _zone(db_session)
    owned = await _owned_records(db_session, grp, zone)
    old = _rec(zone, "old", "A", "10.0.0.9")
    keep = _rec(zone, "keep", "A", "10.0.0.2")
    db_session.add_all([old, keep])
    await db_session.commit()

    text = "keep IN A 10.0.0.2\nnew IN A 10.0.0.3\n"
    p = await _post(client, h, grp, zone, text, "preview")
    # Only the operator's own record is offered for deletion ...
    assert [c["name"] for c in p["to_delete"]] == ["old"]
    # ... and every owned one is reported by name with its reason.
    for row in owned.values():
        assert any(
            s.startswith(f"{row.name} {row.record_type} ") and "not deleted" in s
            for s in p["skipped"]
        ), (row.name, p["skipped"])

    owned_ids = {owner: row.id for owner, row in owned.items()}
    old_id = old.id
    c = await _post(client, h, grp, zone, text, "commit")
    assert (c["created"], c["deleted"], c["unchanged"]) == (1, 1, 1)
    assert c["skipped"] == p["skipped"]
    db_session.expire_all()
    for owner, rid in owned_ids.items():
        assert await db_session.get(DNSRecord, rid) is not None, owner
    assert await db_session.get(DNSRecord, old_id) is None


async def test_merge_does_not_change_an_owned_record(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, zone = await _zone(db_session)
    owned = await _owned_records(db_session, grp, zone)
    mine = _rec(zone, "mine", "A", "10.0.0.7", ttl=300)
    db_session.add(mine)
    await db_session.commit()

    # Every record named, every TTL different from what the row holds.
    lines = "".join(f"{r.name} 60 IN {r.record_type} {r.value}\n" for r in [*owned.values(), mine])
    p = await _post(client, h, grp, zone, lines, "preview", "merge")
    assert [u["name"] for u in p["to_update"]] == ["mine"]
    assert p["to_create"] == [] and p["to_delete"] == []
    for row in owned.values():
        assert any(s.startswith(f"{row.name} ") and "not changed" in s for s in p["skipped"])

    c = await _post(client, h, grp, zone, lines, "commit", "merge")
    assert c["updated"] == 1
    for row in owned.values():
        await db_session.refresh(row)
        assert row.ttl is None, row.name
    await db_session.refresh(mine)
    assert mine.ttl == 60


async def test_replace_into_a_view_touches_only_that_view(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, zone = await _zone(db_session)
    internal = DNSView(group_id=grp.id, name="internal")
    external = DNSView(group_id=grp.id, name="external")
    db_session.add_all([internal, external])
    await db_session.flush()
    www_in = _rec(zone, "www", "A", "10.0.0.80", view_id=internal.id)
    www_ex = _rec(zone, "www", "A", "10.0.0.80", view_id=external.id)
    stale_in = _rec(zone, "stale", "A", "10.0.0.81", view_id=internal.id)
    stale_ex = _rec(zone, "stale", "A", "10.0.0.81", view_id=external.id)
    shared = _rec(zone, "shared", "A", "10.0.0.82")
    shared_absent = _rec(zone, "everywhere", "A", "10.0.0.83")
    db_session.add_all([www_in, www_ex, stale_in, stale_ex, shared, shared_absent])
    await db_session.commit()

    text = "www IN A 10.0.0.80\nshared IN A 10.0.0.82\nnew IN A 10.0.0.84\n"
    p = await _post(client, h, grp, zone, text, "preview", view_id=internal.id)
    # The internal view's stale row goes; nothing outside the view is offered.
    assert [d["existing_id"] for d in p["to_delete"]] == [str(stale_in.id)]
    # www matches the internal twin; shared is already served in the view by
    # the shared row, so it is neither recreated nor offered for deletion.
    assert {u["existing_id"] for u in p["unchanged"]} == {str(www_in.id), str(shared.id)}
    assert [c["name"] for c in p["to_create"]] == ["new"]
    summary = [s for s in p["skipped"] if "outside this import's scope" in s]
    assert len(summary) == 1
    assert "view internal" in summary[0] and "2 view external" in summary[0]
    assert "2 shared (no view)" in summary[0]

    kept = {
        r.name + str(r.view_id): r.id for r in (www_in, www_ex, stale_ex, shared, shared_absent)
    }
    stale_id, internal_id = stale_in.id, internal.id
    c = await _post(client, h, grp, zone, text, "commit", view_id=internal.id)
    assert (c["created"], c["deleted"]) == (1, 1)
    db_session.expire_all()
    assert await db_session.get(DNSRecord, stale_id) is None
    for label, rid in kept.items():
        assert await db_session.get(DNSRecord, rid) is not None, label
    new = (await db_session.execute(select(DNSRecord).where(DNSRecord.name == "new"))).scalar_one()
    assert new.view_id == internal_id


async def test_replace_without_a_view_touches_only_shared_records(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, zone = await _zone(db_session)
    internal = DNSView(group_id=grp.id, name="internal")
    db_session.add(internal)
    await db_session.flush()
    www_in = _rec(zone, "www", "A", "10.0.0.80", view_id=internal.id)
    only_in = _rec(zone, "inside", "A", "10.0.0.85", view_id=internal.id)
    shared_old = _rec(zone, "gone", "A", "10.0.0.86")
    db_session.add_all([www_in, only_in, shared_old])
    await db_session.commit()

    text = "www IN A 10.0.0.80\nnew IN A 10.0.0.84\n"
    p = await _post(client, h, grp, zone, text, "preview")
    assert [d["existing_id"] for d in p["to_delete"]] == [str(shared_old.id)]
    # A shared copy of a view-only record would render in every view: skipped.
    assert [c["name"] for c in p["to_create"]] == ["new"]
    assert any(s.startswith("www A 10.0.0.80: not created") for s in p["skipped"])

    kept = [www_in.id, only_in.id]
    c = await _post(client, h, grp, zone, text, "commit")
    assert (c["created"], c["deleted"]) == (1, 1)
    db_session.expire_all()
    for rid in kept:
        assert await db_session.get(DNSRecord, rid) is not None
    new = (await db_session.execute(select(DNSRecord).where(DNSRecord.name == "new"))).scalar_one()
    assert new.view_id is None


async def test_a_view_from_another_group_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, zone = await _zone(db_session)
    other, _ = await _zone(db_session)
    foreign = DNSView(group_id=other.id, name="internal")
    db_session.add(foreign)
    await db_session.commit()
    for step in ("preview", "commit"):
        await _post(client, h, grp, zone, "a IN A 10.0.0.1\n", step, view_id=foreign.id, expect=422)


async def test_replace_still_deletes_operator_records(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The positive control: protection does not turn replace into merge."""
    h = await _headers(db_session)
    grp, zone = await _zone(db_session)
    rows = [_rec(zone, f"op{i}", "A", f"10.0.1.{i}") for i in range(3)]
    db_session.add_all(rows)
    await db_session.commit()
    ids = [r.id for r in rows]
    c = await _post(client, h, grp, zone, "op0 IN A 10.0.1.0\n", "commit")
    assert c["deleted"] == 2 and c["skipped"] == []
    db_session.expire_all()
    assert await db_session.get(DNSRecord, ids[0]) is not None
    assert await db_session.get(DNSRecord, ids[1]) is None


# ── the diff, without the endpoint ─────────────────────────────────────────


@dataclass
class _Row:
    id: str
    name: str
    record_type: str
    value: str
    ttl: int | None = None
    priority: int | None = None
    weight: int | None = None
    port: int | None = None
    view_id: object = None
    pool_member_id: object = None
    tailscale_tenant_id: object = None
    netbird_instance_id: object = None
    kubernetes_cluster_id: object = None
    ip_address_id: object = None
    auto_generated: bool = False
    ip_alias: bool = False
    tags: dict | None = None
    import_source: str | None = None


def test_a_record_linked_to_an_ip_is_protected() -> None:
    """``ip_address_id`` alone marks an IPAM record, as in the spreadsheet."""
    parsed = parse_zone_file(f"$ORIGIN {ZONE}\n$TTL 3600\no IN A 10.9.9.9\n", ZONE).records
    existing = [_Row(id="1", name="h", record_type="A", value="10.0.0.1", ip_address_id="x")]
    diff = diff_records(parsed, existing, replace=True)  # type: ignore[arg-type]
    assert diff.to_delete == []
    assert diff.skipped == ["h A 10.0.0.1: not deleted - this record is " + _ipam_reason()]


def test_twins_are_all_matched_or_all_deleted() -> None:
    """Legacy twins (#1230) share a key; every one is judged, none is lost."""
    twins = [_Row(id=str(i), name="t", record_type="A", value="10.0.0.1") for i in (1, 2)]
    keep = parse_zone_file(f"$ORIGIN {ZONE}\n$TTL 3600\nt IN A 10.0.0.1\n", ZONE).records
    diff = diff_records(keep, twins, zone_default_ttl=3600, replace=True)  # type: ignore[arg-type]
    assert {c.existing_id for c in diff.unchanged} == {"1", "2"}
    gone = parse_zone_file(f"$ORIGIN {ZONE}\n$TTL 3600\no IN A 10.9.9.9\n", ZONE).records
    diff = diff_records(gone, twins, replace=True)  # type: ignore[arg-type]
    assert {c.existing_id for c in diff.to_delete} == {"1", "2"}


def _ipam_reason() -> str:
    from app.services.dns_io.spreadsheet import _MANAGED_REASON

    return _MANAGED_REASON["ipam"]


# ── owners found in validation: ACME challenges, dynamic-update clients ────


async def test_replace_keeps_acme_and_dynamic_update_records(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An ACME challenge TXT is ``auto_generated`` but not IPAM's, and a record
    an AD domain controller registered through RFC 2136 (mirrored back by the
    agent as ``import_source="ddns_external"``, #641) carries no owner FK at
    all. Replace deleted the second one AND queued its delete to the live
    zone, so the domain's SRV records vanished from the server."""
    from app.services.dns.ingest import EXTERNAL_IMPORT_SOURCE
    from app.services.dns_io.spreadsheet import _MANAGED_REASON
    from app.services.integration_ownership import ACME_RECORD_TAG

    h = await _headers(db_session)
    grp, zone = await _zone(db_session)
    acme = _rec(
        zone,
        "_acme-challenge",
        "TXT",
        '"tok"',
        auto_generated=True,
        tags={ACME_RECORD_TAG: True},
    )
    srv = _rec(
        zone,
        "_ldap._tcp",
        "SRV",
        f"dc1.{ZONE}",
        priority=0,
        weight=100,
        port=389,
        import_source=EXTERNAL_IMPORT_SOURCE,
    )
    mine = _rec(zone, "mine", "A", "10.0.0.7")
    db_session.add_all([acme, srv, mine])
    await db_session.commit()
    ids = {"acme": acme.id, "srv": srv.id}

    p = await _post(client, h, grp, zone, "new IN A 10.0.0.3\n", "preview")
    assert [d["name"] for d in p["to_delete"]] == ["mine"]
    assert any(
        s.startswith("_acme-challenge TXT ") and _MANAGED_REASON["acme"] in s for s in p["skipped"]
    ), p["skipped"]
    assert any(
        s.startswith("_ldap._tcp SRV ") and _MANAGED_REASON["ddns"] in s for s in p["skipped"]
    ), p["skipped"]
    # The ACME row is not reported as IPAM's: editing an IP address does
    # nothing to it.
    assert not any(
        s.startswith("_acme-challenge") and _MANAGED_REASON["ipam"] in s for s in p["skipped"]
    )

    c = await _post(client, h, grp, zone, "new IN A 10.0.0.3\n", "commit")
    assert (c["created"], c["deleted"]) == (1, 1)
    db_session.expire_all()
    for label, rid in ids.items():
        assert await db_session.get(DNSRecord, rid) is not None, label


def test_managed_by_names_acme_and_dynamic_update_owners() -> None:
    from app.services.dns.ingest import EXTERNAL_IMPORT_SOURCE
    from app.services.dns_io.spreadsheet import managed_by
    from app.services.integration_ownership import ACME_RECORD_TAG

    acme = _Row(
        id="1",
        name="_acme-challenge",
        record_type="TXT",
        value='"t"',
        auto_generated=True,
        tags={ACME_RECORD_TAG: True},
    )
    ddns = _Row(
        id="2", name="pc1", record_type="A", value="10.0.0.9", import_source=EXTERNAL_IMPORT_SOURCE
    )
    imported = _Row(id="3", name="w", record_type="A", value="10.0.0.1", import_source="bind9")
    assert managed_by(acme) == "acme"  # type: ignore[arg-type]
    assert managed_by(ddns) == "ddns"  # type: ignore[arg-type]
    # A record a one-shot importer brought in is the operator's from then on.
    assert managed_by(imported) is None  # type: ignore[arg-type]


def test_an_owned_twin_survives_while_its_operator_twin_goes() -> None:
    """Twins the file omits are each judged on their own owner."""
    twins = [
        _Row(id="1", name="t", record_type="A", value="10.0.0.1"),
        _Row(id="2", name="t", record_type="A", value="10.0.0.1", auto_generated=True),
    ]
    gone = parse_zone_file(f"$ORIGIN {ZONE}\n$TTL 3600\no IN A 10.9.9.9\n", ZONE).records
    diff = diff_records(gone, twins, replace=True)  # type: ignore[arg-type]
    assert [c.existing_id for c in diff.to_delete] == ["1"]
    assert diff.skipped == ["t A 10.0.0.1: not deleted - this record is " + _ipam_reason()]


def test_a_named_record_is_never_deleted_whatever_its_scope() -> None:
    """The file names ``t``: neither the in-scope twin nor the other view's
    copy is offered for deletion."""
    view = uuid.uuid4()
    rows = [
        _Row(id="1", name="t", record_type="A", value="10.0.0.1"),
        _Row(id="2", name="t", record_type="A", value="10.0.0.1"),
        _Row(id="3", name="t", record_type="A", value="10.0.0.1", view_id=view),
    ]
    keep = parse_zone_file(f"$ORIGIN {ZONE}\n$TTL 3600\nt IN A 10.0.0.1\n", ZONE).records
    diff = diff_records(keep, rows, zone_default_ttl=3600, replace=True)  # type: ignore[arg-type]
    assert diff.to_delete == []
    assert {c.existing_id for c in diff.unchanged} == {"1", "2"}
