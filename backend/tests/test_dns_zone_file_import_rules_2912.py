"""#2912 / #2913 / #2914 — the zone-file import holds each row to the record
API's rules, keeps TTL 0, reports an out-of-range TTL, and names the rows of a
type it does not store."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord
from app.services.dns_io import parse_zone_file
from tests.test_dns_zone_file_import_ownership_2167 import ZONE, _headers, _post, _rec, _zone


def _skipped_text(out: dict) -> str:
    return "\n".join(out["skipped"])


async def test_bad_owners_are_left_out_and_listed(client: AsyncClient, db_session: AsyncSession):
    h = await _headers(db_session)
    grp, zone = await _zone(db_session)
    text = "ok1 300 IN A 192.0.2.14\nunder_score 300 IN A 192.0.2.10\na\\032b 300 IN A 192.0.2.11\n"
    prev = await _post(client, h, grp, zone, text, "preview", "merge")
    assert [c["name"] for c in prev["to_create"]] == ["ok1"]
    assert "under_score A 192.0.2.10: skipped" in _skipped_text(prev)
    assert "check-names" in _skipped_text(prev)
    done = await _post(client, h, grp, zone, text, "commit", "merge")
    assert done["created"] == 1
    rows = (await db_session.execute(select(DNSRecord.name))).scalars().all()
    assert sorted(rows) == ["ok1"]


async def test_underscore_txt_and_srv_owners_still_import(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    grp, zone = await _zone(db_session)
    text = '_dmarc 300 IN TXT "v=DMARC1; p=none"\n_sip._tcp 300 IN SRV 1 2 5060 sip.' + ZONE + "\n"
    done = await _post(client, h, grp, zone, text, "commit", "merge")
    assert done["created"] == 2
    assert done["skipped"] == []


async def test_ttl_zero_is_kept_and_big_ttl_is_reported(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    grp, zone = await _zone(db_session)
    db_session.add(_rec(zone, "keep300", "A", "192.0.2.15", ttl=300))
    await db_session.flush()
    text = (
        "ttl0 0 IN A 192.0.2.13\n"
        "bigttl 4294967295 IN A 192.0.2.12\n"
        "keep300 4294967295 IN A 192.0.2.15\n"
    )
    prev = await _post(client, h, grp, zone, text, "preview", "merge")
    assert [c["name"] for c in prev["to_create"]] == ["ttl0"]
    assert prev["to_create"][0]["ttl"] == 0
    assert prev["to_update"] == []
    assert "bigttl A 192.0.2.12: skipped - TTL 4294967295" in _skipped_text(prev)
    await _post(client, h, grp, zone, text, "commit", "merge")
    ttls = {r.name: r.ttl for r in (await db_session.execute(select(DNSRecord))).scalars().all()}
    assert ttls == {"ttl0": 0, "keep300": 300}


async def test_merge_to_ttl_zero_updates_an_explicit_ttl(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    grp, zone = await _zone(db_session)
    db_session.add(_rec(zone, "w", "A", "192.0.2.15", ttl=300))
    await db_session.flush()
    await _post(client, h, grp, zone, "w 0 IN A 192.0.2.15\n", "commit", "merge")
    row = (await db_session.execute(select(DNSRecord))).scalar_one()
    await db_session.refresh(row)
    assert row.ttl == 0


async def test_unsupported_types_are_named(client: AsyncClient, db_session: AsyncSession):
    h = await _headers(db_session)
    grp, zone = await _zone(db_session)
    text = 'a1 300 IN A 192.0.2.20\nhinfo1 300 IN HINFO "PC" "Linux"\n'
    prev = await _post(client, h, grp, zone, text, "preview", "merge")
    assert prev["record_count"] == 1
    assert "HINFO: 1 record(s) skipped" in _skipped_text(prev)
    done = await _post(client, h, grp, zone, text, "commit", "merge")
    assert done["created"] == 1
    assert "HINFO" in _skipped_text(done)


def test_parser_keeps_zero_and_flags_big():
    z = parse_zone_file("$TTL 60\na 0 IN A 1.2.3.4\nb 4294967295 IN A 1.2.3.5\n", ZONE)
    by = {r.name: r for r in z.records}
    assert by["a"].ttl == 0 and by["a"].bad_ttl is None
    assert by["b"].ttl is None and by["b"].bad_ttl == 4294967295


# A real-world zone with every supported type and the owner shapes a zone file
# carries: apex, wildcard, underscore TXT / SRV / TLSA owners, a $ORIGIN
# change, an IDN owner, absolute and relative names, a multi-string TXT.
_BROAD = f"""$TTL 3600
@ IN NS ns1.{ZONE}
@ 300 IN MX 10 mail
@ IN TXT "v=spf1 -all"
@ IN CAA 0 issue "letsencrypt.org"
ns1 IN A 192.0.2.53
mail IN A 192.0.2.25
www IN AAAA 2001:db8::1
alias IN CNAME www
*.wild IN A 192.0.2.99
_dmarc IN TXT "v=DMARC1; p=none"
_acme-challenge IN TXT "abc123"
_sip._tcp IN SRV 10 20 5060 sip.{ZONE}
_443._tcp.www IN TLSA 3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
ssh IN SSHFP 1 1 0123456789abcdef0123456789abcdef01234567
long IN TXT "part-one" "part-two"
abs.{ZONE} IN A 192.0.2.7
xn--bcher-kva IN A 192.0.2.8
naptr IN NAPTR 100 10 "U" "E2U+sip" "!^.*$!sip:info@example.com!" .
svc IN SVCB 1 www alpn="h2"
@ IN HTTPS 1 . alpn="h2,h3"
loc IN LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m
$ORIGIN sub.{ZONE}
host IN A 192.0.2.30
"""


async def test_a_broad_valid_zone_imports_every_row(client: AsyncClient, db_session: AsyncSession):
    h = await _headers(db_session)
    grp, zone = await _zone(db_session)
    prev = await _post(client, h, grp, zone, _BROAD, "preview", "merge")
    assert prev["skipped"] == [], prev["skipped"]
    assert len(prev["to_create"]) == prev["record_count"]
    done = await _post(client, h, grp, zone, _BROAD, "commit", "merge")
    assert done["skipped"] == []
    assert done["created"] == prev["record_count"]
    names = set((await db_session.execute(select(DNSRecord.name))).scalars().all())
    assert {
        "@",
        "*.wild",
        "_sip._tcp",
        "_443._tcp.www",
        "host.sub",
        "abs",
        "xn--bcher-kva",
    } <= names


async def test_replace_keeps_a_record_whose_file_row_has_a_bad_ttl(
    client: AsyncClient, db_session: AsyncSession
):
    """A row withheld for its TTL is still in the file: a replace must not
    read the record it names as absent and delete it."""
    h = await _headers(db_session)
    grp, zone = await _zone(db_session)
    db_session.add(_rec(zone, "keep300", "A", "192.0.2.15", ttl=300))
    await db_session.flush()
    text = "keep300 4294967295 IN A 192.0.2.15\nnew 60 IN A 192.0.2.16\n"
    prev = await _post(client, h, grp, zone, text, "preview", "replace")
    assert prev["to_delete"] == []
    assert prev["to_update"] == []
    assert "keep300 A 192.0.2.15: skipped - TTL 4294967295" in _skipped_text(prev)
    await _post(client, h, grp, zone, text, "commit", "replace")
    ttls = {r.name: r.ttl for r in (await db_session.execute(select(DNSRecord))).scalars().all()}
    assert ttls == {"keep300": 300, "new": 60}


async def test_out_of_zone_and_bad_rows_are_skipped_with_a_capped_list(
    client: AsyncClient, db_session: AsyncSession
):
    from app.api.v1.dns.router import _IMPORT_SKIPPED_MAX

    h = await _headers(db_session)
    grp, zone = await _zone(db_session)
    n = _IMPORT_SKIPPED_MAX + 25
    text = "ok 300 IN A 192.0.2.1\n" + "".join(f"bad_{i} 300 IN A 192.0.2.2\n" for i in range(n))
    prev = await _post(client, h, grp, zone, text, "preview", "merge")
    assert len(prev["skipped"]) == _IMPORT_SKIPPED_MAX + 1
    assert prev["skipped"][-1] == "... and 25 more row(s) left alone"
    done = await _post(client, h, grp, zone, text, "commit", "merge")
    assert done["created"] == 1
    assert done["skipped"] == prev["skipped"]
