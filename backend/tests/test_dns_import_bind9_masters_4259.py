"""#4259 — the BIND9 importer keeps a secondary / stub zone's masters and none of its records.

``type secondary; masters { … };`` (or ``primaries``, or the old ``slave``) was
imported as a secondary with no masters, which the zone API refuses and the
agent leaves out of named.conf, holding the zone file's records nobody serves
(#3838). The masters are read (named lists, ``port``, ``key``, IPv6), the
records are not stored, and a zone with no readable master is left out.
"""

from __future__ import annotations

import io
import tarfile
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.services.dns_import import parse_bind9_archive
from app.services.dns_import.canonical import ImportedZone, ImportPreview
from app.services.dns_import.commit import commit_import

_ZONE = """\
$TTL 3600
@   IN  SOA ns1.example.net. hostmaster.example.net. ( 1 3600 600 86400 300 )
    IN  NS  ns1.example.net.
www IN  A   192.0.2.45
"""


def _archive(conf: str, files: list[str]) -> bytes:
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        for path, content in [("named.conf", conf)] + [(f, _ZONE) for f in files]:
            data = content.encode()
            info = tarfile.TarInfo(path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return bio.getvalue()


def _parse(conf: str, files: list[str] | None = None) -> ImportPreview:
    return parse_bind9_archive(_archive(conf, files or ["db.a", "db.b", "db.p"]))


def _by_name(p: ImportPreview) -> dict[str, ImportedZone]:
    return {z.name: z for z in p.zones}


_PRIMARY = 'zone "p.test" { type primary; file "db.p"; };\n'


@pytest.mark.parametrize("kw", ["masters", "primaries"])
def test_masters_and_primaries_keywords(kw: str) -> None:
    conf = _PRIMARY + f'zone "s1.test" {{ type secondary; {kw} {{ 192.0.2.1; }}; file "db.a"; }};'
    z = _by_name(_parse(conf))["s1.test."]
    assert z.zone_type == "secondary"
    assert z.masters == ["192.0.2.1"]
    assert z.records == []
    assert any("records come from the masters; 2 record(s)" in w for w in z.parse_warnings)
    # the primary zone keeps its records
    assert len(_by_name(_parse(conf))["p.test."].records) == 2


def test_slave_and_stub_types() -> None:
    conf = (
        _PRIMARY
        + 'zone "a.test" { type slave; masters { 192.0.2.1; }; file "db.a"; };\n'
        + 'zone "b.test" { type stub; masters { 192.0.2.2; }; file "db.b"; };'
    )
    zones = _by_name(_parse(conf))
    assert zones["a.test."].zone_type == "secondary" and zones["a.test."].masters == ["192.0.2.1"]
    assert zones["b.test."].zone_type == "stub" and zones["b.test."].masters == ["192.0.2.2"]
    assert zones["b.test."].records == []


def test_port_key_and_ipv6() -> None:
    conf = (
        'zone "a.test" { type secondary; file "db.a"; masters port 5353 '
        "{ 192.0.2.1; 192.0.2.2 port 53; 2001:db8::1 key tsig1; 192.0.2.3 port 5300; }; };"
    )
    z = _by_name(_parse(conf))["a.test."]
    assert z.masters == ["192.0.2.1@5353", "192.0.2.2", "2001:db8::1@5353", "192.0.2.3@5300"]
    assert any("key" in w and "not imported" in w for w in z.parse_warnings)


def test_named_list_reference_resolves() -> None:
    conf = (
        "masters corp port 5353 { 192.0.2.1; 2001:db8::5; };\n"
        "primaries more { 198.51.100.7; corp; };\n"
        'zone "a.test" { type secondary; masters { corp; }; file "db.a"; };\n'
        'zone "b.test" { type secondary; primaries { more; 203.0.113.9; }; file "db.b"; };'
    )
    zones = _by_name(_parse(conf))
    assert zones["a.test."].masters == ["192.0.2.1@5353", "2001:db8::5@5353"]
    assert zones["b.test."].masters == [
        "198.51.100.7",
        "192.0.2.1@5353",
        "2001:db8::5@5353",
        "203.0.113.9",
    ]


def test_unresolvable_masters_skip_the_zone_with_a_warning() -> None:
    conf = (
        _PRIMARY
        + 'zone "a.test" { type secondary; masters { nosuchlist; }; file "db.a"; };\n'
        + 'zone "b.test" { type secondary; file "db.b"; };'
    )
    p = _parse(conf)
    assert list(_by_name(p)) == ["p.test."]
    assert any("a.test." in w and "skipped" in w and "no primary server" in w for w in p.warnings)
    assert any("b.test." in w and "skipped" in w for w in p.warnings)


def test_partly_unresolvable_masters_keep_the_readable_ones() -> None:
    conf = 'zone "a.test" { type secondary; masters { 192.0.2.1; nosuch; }; file "db.a"; };'
    z = _by_name(_parse(conf))["a.test."]
    assert z.masters == ["192.0.2.1"]
    assert any("nosuch" in w for w in z.parse_warnings)


def test_default_primaries_is_not_a_masters_list() -> None:
    conf = (
        'catalog-zones { zone "c.test" default-primaries { 192.0.2.99; }; };\n'
        'zone "a.test" { type secondary; masters { 192.0.2.1; }; file "db.a"; };'
    )
    assert _by_name(_parse(conf))["a.test."].masters == ["192.0.2.1"]


@pytest.mark.asyncio
async def test_commit_stores_masters_and_no_records(db_session: AsyncSession) -> None:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add_all([user, grp])
    await db_session.flush()
    conf = (
        _PRIMARY
        + 'zone "s1.test" { type secondary; masters { 192.0.2.1; }; file "db.a"; };\n'
        + 'zone "s2.test" { type secondary; primaries port 5353 { 192.0.2.2; }; file "db.b"; };'
    )
    res = await commit_import(
        db_session,
        preview=_parse(conf),
        target_group_id=grp.id,
        target_view_id=None,
        conflict_actions={},
        current_user=user,
    )
    assert [z.action_taken for z in res.zones] == ["created"] * 3
    zones = {z.name: z for z in (await db_session.execute(select(DNSZone))).scalars().all()}
    assert zones["s1.test."].masters == ["192.0.2.1"]
    assert zones["s2.test."].masters == ["192.0.2.2@5353"]
    rows = (await db_session.execute(select(DNSRecord))).scalars().all()
    assert {r.zone_id for r in rows} == {zones["p.test."].id}


@pytest.mark.asyncio
async def test_commit_refuses_a_masterless_secondary_from_a_client_plan(
    db_session: AsyncSession,
) -> None:
    """The plan round-trips the client; the commit holds it to the zone API's rule."""
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add_all([user, grp])
    await db_session.flush()
    z = ImportedZone(name="x.test.", zone_type="secondary", kind="forward", soa=None, records=[])
    res = await commit_import(
        db_session,
        preview=ImportPreview(
            source="bind9",
            zones=[z],
            conflicts=[],
            warnings=[],
            total_records=0,
            record_type_histogram={},
        ),
        target_group_id=grp.id,
        target_view_id=None,
        conflict_actions={},
        current_user=user,
    )
    assert res.zones[0].action_taken == "failed"
    assert "requires at least one master" in (res.zones[0].error or "")
    assert (await db_session.execute(select(DNSZone))).scalars().all() == []
