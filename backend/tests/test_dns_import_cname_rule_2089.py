"""#2089 — the DNS importers hold a zone to the CNAME rule.

RFC 1034 section 3.6.2 / RFC 2181 section 10.1: a CNAME is the only record at
its name, and never at the apex. The record API enforces it (#1381) through
``app.services.dns.cname_conflict``; the importers stored such rows anyway and
the server then refused the zone. The preview now reports each such record and
the commit skips it, saying why. Within one imported set the non-CNAME data is
kept and the CNAME dropped; against the zone already holding records (the
zone-file merge) the existing records win.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServerGroup, DNSView, DNSZone
from app.services.dns.cname_conflict import NameRow, refused_by_cname_rule
from app.services.dns_import import cname_check
from app.services.dns_import.canonical import (
    ImportedRecord,
    ImportedSOA,
    ImportedZone,
    ImportPreview,
)
from app.services.dns_import.commit import commit_import
from app.services.dns_import.powerdns import _build_imported_zone
from app.services.dns_io import ParsedRecord, apply_cname_rule, diff_records

V1 = uuid.uuid4()
V2 = uuid.uuid4()


# ── the shared in-memory rule ────────────────────────────────────────


def test_batch_keeps_data_and_drops_cname() -> None:
    rows = [
        NameRow("www", "CNAME", "a.example.com."),
        NameRow("WWW", "A", "192.0.2.1"),
        NameRow("ok", "CNAME", "a.example.com."),
    ]
    refused = refused_by_cname_rule(rows)
    assert list(refused) == [0]
    assert "CNAME must be the only record" in refused[0]


def test_batch_second_cname_at_a_name_is_dropped_first_kept() -> None:
    rows = [NameRow("x", "CNAME", "a."), NameRow("x", "CNAME", "b.")]
    assert list(refused_by_cname_rule(rows)) == [1]


def test_batch_apex_cname_refused() -> None:
    for apex in ("@", "", "  "):
        assert 0 in refused_by_cname_rule([NameRow(apex, "CNAME", "a.")])


def test_batch_views_overlap_rules() -> None:
    # A scoped A and a scoped CNAME in different views do not meet ...
    assert (
        refused_by_cname_rule([NameRow("h", "A", "1.1.1.1", V1), NameRow("h", "CNAME", "a.", V2)])
        == {}
    )
    # ... a view-less row renders into every view, so it meets both.
    assert 1 in refused_by_cname_rule(
        [NameRow("h", "A", "1.1.1.1", V1), NameRow("h", "CNAME", "a.")]
    )
    assert 0 in refused_by_cname_rule(
        [NameRow("h", "CNAME", "a.", V2), NameRow("h", "A", "1.1.1.1")]
    )


def test_standing_rows_win() -> None:
    standing = [NameRow("w", "A", "1.1.1.1"), NameRow("c", "CNAME", "t.")]
    new = [NameRow("w", "CNAME", "a."), NameRow("c", "TXT", "x"), NameRow("n", "A", "2.2.2.2")]
    assert sorted(refused_by_cname_rule(new, standing)) == [0, 1]


def test_standing_view_scoped() -> None:
    standing = [NameRow("w", "A", "1.1.1.1", V1)]
    assert 0 in refused_by_cname_rule([NameRow("w", "CNAME", "a.")], standing)
    assert refused_by_cname_rule([NameRow("w", "CNAME", "a.", V2)], standing) == {}


# ── the importers' canonical set ─────────────────────────────────────


def _zone(records: list[ImportedRecord], name: str = "example.com.") -> ImportedZone:
    return ImportedZone(
        name=name,
        zone_type="primary",
        kind="forward",
        soa=ImportedSOA("ns1.example.com.", "admin.example.com.", 1, 3600, 600, 86400, 300, 3600),
        records=records,
    )


def _preview(z: ImportedZone) -> ImportPreview:
    return ImportPreview(
        source="bind9",
        zones=[z],
        conflicts=[],
        warnings=[],
        total_records=len(z.records),
        record_type_histogram={},
    )


def _clash_zone() -> ImportedZone:
    return _zone(
        [
            ImportedRecord("www", "A", "192.0.2.1", 300),
            ImportedRecord("www", "CNAME", "other.example.com.", 300),
            ImportedRecord("@", "CNAME", "elsewhere.example.net.", 300),
            ImportedRecord("good", "CNAME", "www.example.com.", 300),
            ImportedRecord("mail", "MX", "mx.example.com.", 300, priority=10),
        ]
    )


def test_preview_annotation_names_each_record() -> None:
    p = _preview(_clash_zone())
    cname_check.annotate_cname_conflicts(p)
    assert len(p.warnings) == 2
    assert all(cname_check.is_cname_warning(w) for w in p.warnings)
    assert any("www CNAME other.example.com." in w for w in p.warnings)
    assert any("@ CNAME" in w and "apex" in w for w in p.warnings)


def test_clean_zone_has_no_warning() -> None:
    p = _preview(_zone([ImportedRecord("a", "A", "192.0.2.1", 300)]))
    cname_check.annotate_cname_conflicts(p)
    assert p.warnings == []


def test_powerdns_payload_clash_is_found() -> None:
    full: dict[str, Any] = {
        "name": "example.com.",
        "kind": "Native",
        "rrsets": [
            {
                "name": "www.example.com.",
                "type": "A",
                "ttl": 60,
                "records": [{"content": "192.0.2.9", "disabled": False}],
            },
            {
                "name": "www.example.com.",
                "type": "CNAME",
                "ttl": 60,
                "records": [{"content": "x.example.com.", "disabled": False}],
            },
        ],
    }
    z = _build_imported_zone({"name": "example.com."}, full)
    skips = cname_check.cname_skips(z)
    assert [z.records[i].record_type for i in skips] == ["CNAME"]


async def _admin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.mark.asyncio
async def test_commit_skips_the_record_and_lands_the_rest(db_session: AsyncSession) -> None:
    user, _ = await _admin(db_session)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    p = _preview(_clash_zone())
    cname_check.annotate_cname_conflicts(p)  # the plan round-trips with these
    res = await commit_import(
        db_session,
        preview=p,
        target_group_id=grp.id,
        target_view_id=None,
        conflict_actions={},
        current_user=user,
    )
    assert res.zones[0].action_taken == "created"
    assert res.zones[0].records_created == 3
    stored = (await db_session.execute(select(DNSRecord))).scalars().all()
    assert sorted((r.name, r.record_type) for r in stored) == [
        ("good", "CNAME"),
        ("mail", "MX"),
        ("www", "A"),
    ]
    reasons = [w for w in res.warnings if "record not imported" in w]
    assert len(reasons) == 2  # once each: the preview's copies are not doubled
    assert not any(cname_check.is_cname_warning(w) for w in res.warnings)


@pytest.mark.asyncio
async def test_commit_endpoint_end_to_end(db_session: AsyncSession, client: AsyncClient) -> None:
    _, headers = await _admin(db_session)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.commit()
    plan = {
        "source": "bind9",
        "zones": [
            {
                "name": "example.com.",
                "zone_type": "primary",
                "kind": "forward",
                "soa": None,
                "records": [
                    {"name": "www", "record_type": "A", "value": "192.0.2.1", "ttl": 300},
                    {"name": "www", "record_type": "CNAME", "value": "o.example.com.", "ttl": 300},
                ],
            }
        ],
        "conflicts": [],
        "warnings": [],
        "total_records": 2,
        "record_type_histogram": {},
    }
    r = await client.post(
        "/api/v1/dns/import/bind9/commit",
        headers=headers,
        json={"target_group_id": str(grp.id), "plan": plan, "conflict_actions": {}},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_records_created"] == 1
    assert any("record not imported" in w and "CNAME" in w for w in body["warnings"])
    rows = (await db_session.execute(select(DNSRecord))).scalars().all()
    assert [(x.name, x.record_type) for x in rows] == [("www", "A")]


# ── zone-file import into an existing zone ───────────────────────────


ZONE = "merge.example.org."


async def _zone_with(
    db: AsyncSession, rows: list[tuple[str, str, str, uuid.UUID | None]]
) -> tuple[DNSServerGroup, DNSZone]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
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
    for name, rtype, value, view in rows:
        db.add(
            DNSRecord(
                zone_id=zone.id,
                name=name,
                fqdn=f"{name}.{ZONE}",
                record_type=rtype,
                value=value,
                view_id=view,
            )
        )
    await db.commit()
    return grp, zone


def _file(lines: str) -> str:
    return f"$ORIGIN {ZONE}\n$TTL 300\n{lines}"


async def _post(
    client: AsyncClient,
    headers: dict[str, str],
    grp: DNSServerGroup,
    zone: DNSZone,
    lines: str,
    what: str,
    strategy: str = "merge",
) -> dict[str, Any]:
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/import/{what}",
        headers=headers,
        json={"zone_file": _file(lines), "conflict_strategy": strategy},
    )
    assert r.status_code == 200, r.text
    out: dict[str, Any] = r.json()
    return out


@pytest.mark.asyncio
async def test_zone_file_cname_beside_existing_data(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, headers = await _admin(db_session)
    grp, zone = await _zone_with(db_session, [("www", "A", "192.0.2.1", None)])
    lines = "www IN CNAME t.example.org.\nnew IN CNAME t.example.org.\n"
    pv = await _post(client, headers, grp, zone, lines, "preview")
    assert [c["name"] for c in pv["to_create"]] == ["new"]
    assert len(pv["skipped"]) == 1 and "www CNAME" in pv["skipped"][0]
    cm = await _post(client, headers, grp, zone, lines, "commit")
    assert cm["created"] == 1 and len(cm["skipped"]) == 1
    names = {
        (r.name, r.record_type) for r in (await db_session.execute(select(DNSRecord))).scalars()
    }
    assert ("www", "CNAME") not in names and ("new", "CNAME") in names


@pytest.mark.asyncio
async def test_zone_file_a_beside_existing_cname(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, headers = await _admin(db_session)
    grp, zone = await _zone_with(db_session, [("w", "CNAME", "t.example.org.", None)])
    cm = await _post(client, headers, grp, zone, "w IN A 192.0.2.5\nz IN A 192.0.2.6\n", "commit")
    assert cm["created"] == 1 and "w A" in cm["skipped"][0]


def test_zone_file_clash_within_the_file_is_resolved_at_the_diff() -> None:
    """dnspython refuses a CNAME beside other data at parse time (422), so a
    zone-file clash inside one file cannot reach the diff through the endpoint;
    the diff step still holds the rule for any parsed set it is handed."""
    parsed = [
        ParsedRecord("w", "CNAME", "t.example.org."),
        ParsedRecord("w", "TXT", "hi"),
        ParsedRecord("@", "CNAME", "t.example.org."),
    ]
    diff = apply_cname_rule(diff_records(parsed, []), [], replace=False)
    assert [(c.name, c.record_type) for c in diff.to_create] == [("w", "TXT")]
    assert len(diff.skipped) == 2


@pytest.mark.asyncio
async def test_zone_file_view_scoped_existing_record(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, headers = await _admin(db_session)
    grp, zone = await _zone_with(db_session, [])
    view = DNSView(group_id=grp.id, name="internal")
    db_session.add(view)
    await db_session.flush()
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            name="h",
            fqdn=f"h.{ZONE}",
            record_type="A",
            value="10.0.0.1",
            view_id=view.id,
        )
    )
    await db_session.commit()
    # The file's row has no view, so it renders into the "internal" view too.
    cm = await _post(client, headers, grp, zone, "h IN CNAME t.example.org.\n", "commit")
    assert cm["created"] == 0 and len(cm["skipped"]) == 1


@pytest.mark.asyncio
async def test_zone_file_replace_frees_the_name(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, headers = await _admin(db_session)
    grp, zone = await _zone_with(db_session, [("www", "A", "192.0.2.1", None)])
    lines = "www IN CNAME t.example.org.\n"
    # replace deletes the A the file lacks, so the CNAME may land ...
    pv = await _post(client, headers, grp, zone, lines, "preview", "replace")
    assert pv["skipped"] == [] and len(pv["to_create"]) == 1
    # ... while merge keeps it, and refuses.
    pv = await _post(client, headers, grp, zone, lines, "preview", "merge")
    assert len(pv["skipped"]) == 1 and pv["to_create"] == []


@pytest.mark.asyncio
async def test_zone_file_apex_cname_is_not_in_the_dns_python_parse(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """dnspython refuses an apex CNAME beside the SOA/NS itself (422); the rule
    here covers a file with no apex data of its own."""
    _, headers = await _admin(db_session)
    grp, zone = await _zone_with(db_session, [])
    cm = await _post(client, headers, grp, zone, "@ IN CNAME t.example.org.\n", "commit")
    assert cm["created"] == 0 and "apex" in cm["skipped"][0]


# ── validator additions ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_parity_with_the_record_api_check(db_session: AsyncSession) -> None:
    """The in-memory twin answers exactly as ``find_cname_conflict`` does, for
    one standing row and one candidate, across types, views and name case.
    (The apex is the caller's check in both paths, so it is left out here.)"""
    from app.services.dns.cname_conflict import find_cname_conflict

    grp, zone = await _zone_with(db_session, [])
    v1 = DNSView(group_id=grp.id, name="v1")
    v2 = DNSView(group_id=grp.id, name="v2")
    db_session.add_all([v1, v2])
    await db_session.flush()
    views: list[uuid.UUID | None] = [None, v1.id, v2.id]
    types = ["A", "CNAME", "TXT", "MX"]
    cases = 0
    for st_type in types:
        for st_view in views:
            row = DNSRecord(
                zone_id=zone.id,
                name="Host",
                fqdn=f"host.{ZONE}",
                record_type=st_type,
                value="x",
                view_id=st_view,
            )
            db_session.add(row)
            await db_session.flush()
            standing = [NameRow("Host", st_type, "x", st_view)]
            for new_type in types:
                for new_view in views:
                    for spelling in ("host", "HOST", "Host", "other"):
                        db_hit = await find_cname_conflict(
                            db_session,
                            zone.id,
                            view_id=new_view,
                            name=spelling,
                            record_type=new_type,
                        )
                        mem = refused_by_cname_rule(
                            [NameRow(spelling, new_type, "y", new_view)], standing
                        )
                        assert (db_hit is not None) == bool(mem), (
                            st_type,
                            st_view,
                            new_type,
                            new_view,
                            spelling,
                        )
                        cases += 1
            await db_session.delete(row)
            await db_session.flush()
    assert cases == 4 * 3 * 4 * 3 * 4


@pytest.mark.asyncio
async def test_zone_file_trashed_record_blocks_nothing_auto_generated_does(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    from datetime import UTC, datetime

    _, headers = await _admin(db_session)
    grp, zone = await _zone_with(db_session, [])
    db_session.add_all(
        [
            DNSRecord(
                zone_id=zone.id,
                name="gone",
                fqdn=f"gone.{ZONE}",
                record_type="A",
                value="192.0.2.9",
                deleted_at=datetime.now(UTC),
            ),
            DNSRecord(
                zone_id=zone.id,
                name="ipam",
                fqdn=f"ipam.{ZONE}",
                record_type="A",
                value="192.0.2.10",
                auto_generated=True,
            ),
        ]
    )
    await db_session.commit()
    lines = "gone IN CNAME t.example.org.\nipam IN CNAME t.example.org.\n"
    pv = await _post(client, headers, grp, zone, lines, "preview")
    assert [c["name"] for c in pv["to_create"]] == ["gone"]
    assert len(pv["skipped"]) == 1 and pv["skipped"][0].startswith("ipam CNAME")


@pytest.mark.asyncio
async def test_zone_file_replace_commit_swaps_a_for_cname(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, headers = await _admin(db_session)
    grp, zone = await _zone_with(db_session, [("www", "A", "192.0.2.1", None)])
    cm = await _post(
        client, headers, grp, zone, "www IN CNAME t.example.org.\n", "commit", "replace"
    )
    assert cm["created"] == 1 and cm["deleted"] == 1 and cm["skipped"] == []
    rows = (await db_session.execute(select(DNSRecord))).scalars().all()
    assert [(r.name, r.record_type) for r in rows] == [("www", "CNAME")]


@pytest.mark.asyncio
async def test_preview_request_without_strategy_defaults_to_merge(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """An older client posts no ``conflict_strategy`` to the preview."""
    _, headers = await _admin(db_session)
    grp, zone = await _zone_with(db_session, [("www", "A", "192.0.2.1", None)])
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/import/preview",
        headers=headers,
        json={"zone_file": _file("www IN CNAME t.example.org.\n")},
    )
    assert r.status_code == 200, r.text
    assert len(r.json()["skipped"]) == 1


def test_control_char_row_does_not_cost_the_cname_its_place() -> None:
    """A row the commit drops for a control character (#597) never lands, so
    it must not make the CNAME at its name look like a clash."""
    z = _zone(
        [
            ImportedRecord("www", "TXT", "bad\nvalue", 300),
            ImportedRecord("www", "CNAME", "t.example.org.", 300),
        ]
    )
    assert cname_check.cname_skips(z) == {}


def test_copilot_preview_text_counts_the_skips() -> None:
    from app.services.ai.operations_writes import _dns_preview_text

    p = _preview(_clash_zone())
    cname_check.annotate_cname_conflicts(p)
    assert "2 record(s) will NOT be imported" in _dns_preview_text(p)
    assert "NOT be imported" not in _dns_preview_text(_preview(_zone([])))
