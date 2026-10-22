"""An address's aliases are told from its host record by a stored marker (#2084).

An A / AAAA alias and the address's own host record are both ``auto_generated``
with ``ip_address_id`` set. The DNS sync loaded the aliases as the host record
(renaming one, or deleting it as "a zone the host does not publish to"), and
the alias lists inferred an alias from ``id != ip.dns_record_id``, so a host
record published into an extra zone was listed, counted and deletable as an
alias. ``dns_record.ip_alias`` now says which is which.
"""

from __future__ import annotations

import importlib.util
import uuid
from pathlib import Path
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSZone
from app.models.ipam import IPAddress, Subnet
from tests.test_ipam_alias_cname_exclusive_2080 import _alloc, _setup


async def _rows(db: AsyncSession, ip_id: str) -> list[DNSRecord]:
    return list(
        (
            await db.execute(
                select(DNSRecord)
                .where(DNSRecord.ip_address_id == uuid.UUID(ip_id))
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )


def _summary(rows: list[DNSRecord], rtype: str) -> list[tuple[str, str]]:
    return sorted((r.name, str(r.zone_id)) for r in rows if r.record_type == rtype)


async def _extra_zone(db: AsyncSession, like: DNSZone) -> DNSZone:
    z = DNSZone(
        group_id=like.group_id,
        name=f"x{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(z)
    await db.commit()
    return z


@pytest.mark.asyncio
@pytest.mark.parametrize("alias_first", [True, False])
async def test_a_alias_in_the_host_zone_survives_a_rename(
    client: AsyncClient, db_session: AsyncSession, alias_first: bool
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    if alias_first:
        # Alias row older than the host row, so no row order can save the old code.
        r = await _alloc(client, headers, sid, "10.98.5.10", "h1")
        ip_id = r.json()["id"]
        await client.post(
            f"/api/v1/ipam/addresses/{ip_id}/aliases",
            headers=headers,
            json={"name": "www", "record_type": "A"},
        )
    else:
        r = await _alloc(
            client,
            headers,
            sid,
            "10.98.5.10",
            "h1",
            aliases=[{"name": "www", "record_type": "A"}],
        )
        ip_id = r.json()["id"]
    assert r.status_code == 201, r.text
    for new_name in ("h1", "h2"):
        put = await client.put(
            f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"hostname": new_name}
        )
        assert put.status_code == 200, put.text
        rows = await _rows(db_session, ip_id)
        assert _summary(rows, "A") == sorted([(new_name, str(zone.id)), ("www", str(zone.id))]), [
            (r.name, r.record_type) for r in rows
        ]
        alias = next(r for r in rows if r.name == "www")
        assert alias.value == "10.98.5.10"
        host = [r for r in rows if r.name == new_name and r.record_type == "A"]
        assert len(host) == 1


@pytest.mark.asyncio
async def test_alias_in_a_zone_the_host_does_not_publish_to_survives(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    other = await _extra_zone(db_session, zone)
    r = await _alloc(
        client, headers, sid, "10.98.5.11", "h1", aliases=[{"name": "www", "record_type": "A"}]
    )
    ip_id = r.json()["id"]
    # The host moves to another zone; the alias stays in the original one.
    put = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}",
        headers=headers,
        json={"dns_zone_id": str(other.id), "hostname": "h1"},
    )
    assert put.status_code == 200, put.text
    rows = await _rows(db_session, ip_id)
    assert ("www", str(zone.id)) in _summary(rows, "A")
    assert [(n, z) for n, z in _summary(rows, "A") if n == "h1"] == [("h1", str(other.id))]


@pytest.mark.asyncio
async def test_default_gateway_name_keeps_the_aliases(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    r = await _alloc(
        client, headers, sid, "10.98.5.12", "h1", aliases=[{"name": "www", "record_type": "A"}]
    )
    ip_id = r.json()["id"]
    put = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"hostname": "gateway"}
    )
    assert put.status_code == 200, put.text
    rows = await _rows(db_session, ip_id)
    assert _summary(rows, "A") == [("www", str(zone.id))]


@pytest.mark.asyncio
async def test_host_in_an_extra_zone_is_not_an_alias(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    extra = await _extra_zone(db_session, zone)
    r = await _alloc(
        client,
        headers,
        sid,
        "10.98.5.13",
        "h1",
        extra_zone_ids=[str(extra.id)],
        aliases=[{"name": "www", "record_type": "A"}],
    )
    assert r.status_code == 201, r.text
    ip_id = r.json()["id"]
    rows = await _rows(db_session, ip_id)
    host_extra = next(x for x in rows if x.zone_id == extra.id)
    assert host_extra.name == "h1"

    listed = await client.get(f"/api/v1/ipam/addresses/{ip_id}/aliases", headers=headers)
    assert [a["name"] for a in listed.json()] == ["www"]
    sub = await client.get(f"/api/v1/ipam/subnets/{sid}/aliases", headers=headers)
    assert [a["name"] for a in sub.json()] == ["www"]
    ips = await client.get(f"/api/v1/ipam/subnets/{sid}/addresses", headers=headers)
    assert [a["alias_count"] for a in ips.json() if a["id"] == ip_id] == [1]

    refused = await client.delete(
        f"/api/v1/ipam/addresses/{ip_id}/aliases/{host_extra.id}", headers=headers
    )
    assert refused.status_code == 409, refused.text
    assert (await _rows(db_session, ip_id)) and any(
        x.id == host_extra.id for x in await _rows(db_session, ip_id)
    )
    # the real alias still deletes
    alias = next(x for x in rows if x.name == "www")
    ok = await client.delete(f"/api/v1/ipam/addresses/{ip_id}/aliases/{alias.id}", headers=headers)
    assert ok.status_code == 204, ok.text


@pytest.mark.asyncio
async def test_every_alias_writer_sets_the_marker_and_hosts_do_not(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    extra = await _extra_zone(db_session, zone)
    r1 = await _alloc(
        client,
        headers,
        sid,
        "10.98.5.14",
        "h1",
        extra_zone_ids=[str(extra.id)],
        aliases=[{"name": "a1", "record_type": "A"}, {"name": "c1", "record_type": "CNAME"}],
    )
    r2 = await client.post(
        f"/api/v1/ipam/subnets/{sid}/next",
        headers=headers,
        json={"hostname": "h2", "aliases": [{"name": "a2", "record_type": "A"}]},
    )
    r3 = await _alloc(client, headers, sid, "10.98.5.30", "h3")
    add = await client.post(
        f"/api/v1/ipam/addresses/{r3.json()['id']}/aliases",
        headers=headers,
        json={"name": "a3", "record_type": "A"},
    )
    assert add.status_code == 201, add.text
    for resp in (r1, r2, r3):
        for rec in await _rows(db_session, resp.json()["id"]):
            is_alias = rec.name in {"a1", "c1", "a2", "a3"}
            assert rec.ip_alias is is_alias, (rec.name, rec.record_type)


@pytest.mark.asyncio
async def test_rename_onto_an_own_alias_keeps_the_alias_an_alias(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Renaming onto an A alias's name is refused (#2106, it used to leave two
    rows at the name); the alias stays an alias and survives a rename away."""
    headers, sid, zone = await _setup(client, db_session)
    r = await _alloc(
        client, headers, sid, "10.98.5.40", "h1", aliases=[{"name": "www", "record_type": "A"}]
    )
    ip_id = r.json()["id"]
    put = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"hostname": "www"}
    )
    assert put.status_code == 409, put.text
    listed = await client.get(f"/api/v1/ipam/addresses/{ip_id}/aliases", headers=headers)
    assert [a["name"] for a in listed.json()] == ["www"]
    # Renaming elsewhere moves the host only; the alias keeps answering.
    put = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"hostname": "h3"}
    )
    assert put.status_code == 200, put.text
    rows = await _rows(db_session, ip_id)
    assert _summary(rows, "A") == sorted([("h3", str(zone.id)), ("www", str(zone.id))])


def _backfill_statement(monkeypatch: pytest.MonkeyPatch) -> Any:
    from alembic import op as alembic_op

    path = next(Path(__file__).parents[1].glob("alembic/versions/b3d7f1a82c54_*.py"))
    spec = importlib.util.spec_from_file_location("mig_2084", path)
    assert spec is not None and spec.loader is not None
    mig = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mig)
    statements: list[Any] = []
    monkeypatch.setattr(alembic_op, "add_column", lambda *a, **k: None, raising=False)
    monkeypatch.setattr(alembic_op, "execute", statements.append, raising=False)
    mig.upgrade()
    assert len(statements) == 1
    return statements[0]


@pytest.mark.asyncio
async def test_upgrade_backfill_classifies_existing_rows(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The migration's backfill marks the aliases already in the database, and
    only them: rows are built the way main left them (no marker), then the
    migration's own UPDATE runs."""
    stmt = _backfill_statement(monkeypatch)
    _, sid, z1 = await _setup(client, db_session)
    z2 = await _extra_zone(db_session, z1)
    z3 = await _extra_zone(db_session, z1)
    rz = DNSZone(group_id=z1.group_id, name="98.10.in-addr.arpa.", kind="reverse")
    db_session.add(rz)
    subnet = await db_session.get(Subnet, uuid.UUID(sid))
    assert subnet is not None

    def ip(addr: str, hostname: str | None, fwd: DNSZone | None, extras: list[str]) -> IPAddress:
        row = IPAddress(
            subnet_id=subnet.id,
            address=addr,
            status="allocated",
            hostname=hostname,
            forward_zone_id=fwd.id if fwd else None,
            extra_zone_ids=extras,
        )
        db_session.add(row)
        return row

    # Mixed-case hostname; the extra zone stored as an upper-case UUID string,
    # which the API accepts and stores as sent.
    i1 = ip("10.98.5.50", "Web", z1, [str(z2.id).upper()])
    i2 = ip("fd00:2084::5", "v6h", z1, [])
    i3 = ip("10.98.5.51", "www", z1, [])  # renamed onto its own alias
    i4 = ip("10.98.5.52", "legacy", None, [])  # no forward zone recorded
    await db_session.flush()

    def rec(i: IPAddress, zone: DNSZone, name: str, rtype: str) -> DNSRecord:
        row = DNSRecord(
            zone_id=zone.id,
            name=name,
            record_type=rtype,
            value=str(i.address) if rtype in ("A", "AAAA") else "x.example.",
            auto_generated=True,
            ip_address_id=i.id,
        )
        db_session.add(row)
        return row

    expect: dict[str, tuple[DNSRecord, bool]] = {
        "host": (rec(i1, z1, "web", "A"), False),
        "host in an extra zone": (rec(i1, z2, "web", "A"), False),
        "CNAME alias": (rec(i1, z1, "www", "CNAME"), True),
        "A alias in the host zone": (rec(i1, z1, "ftp", "A"), True),
        "A alias in a foreign zone": (rec(i1, z3, "mail", "A"), True),
        "A alias named like the host, foreign zone": (rec(i1, z3, "web", "A"), True),
        "PTR": (rec(i1, rz, "50", "PTR"), False),
        "v6 host": (rec(i2, z1, "v6h", "AAAA"), False),
        "v6 AAAA alias": (rec(i2, z1, "v6a", "AAAA"), True),
        "renamed-onto host": (rec(i3, z1, "www", "A"), False),
        "renamed-onto alias": (rec(i3, z1, "www", "A"), True),
        "host, no forward zone": (rec(i4, z1, "legacy", "A"), False),
    }
    await db_session.flush()
    i1.dns_record_id = expect["host"][0].id
    i2.dns_record_id = expect["v6 host"][0].id
    i3.dns_record_id = expect["renamed-onto host"][0].id
    for row, _ in expect.values():
        row.ip_alias = False  # as main stored them
    await db_session.commit()

    await db_session.execute(text(stmt))
    await db_session.commit()
    got = {}
    for label, (row, _) in expect.items():
        await db_session.refresh(row)
        got[label] = row.ip_alias
    assert got == {label: want for label, (_, want) in expect.items()}


@pytest.mark.asyncio
async def test_drift_does_not_report_an_a_alias_as_a_mismatched_host(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Sync DNS's drift report: an A alias is not the host record, so it is not
    a mismatch to be rewritten into the host name."""
    from app.services.dns.sync_check import compute_subnet_dns_drift

    headers, sid, _zone = await _setup(client, db_session)
    r = await _alloc(
        client, headers, sid, "10.98.5.60", "h1", aliases=[{"name": "www", "record_type": "A"}]
    )
    assert r.status_code == 201, r.text
    report = await compute_subnet_dns_drift(db_session, uuid.UUID(sid))
    assert [m.current_name for m in report.mismatched] == []
    assert [s.name for s in report.stale] == []
