"""#2187 - a zone's own export re-imports as no change.

The record API stores a name target without its trailing dot, relative to the
zone. The writer forced a dot on it (``mail`` became the absolute ``mail.``),
and the diff compared the value text exactly, so exporting a zone and importing
the file back planned a delete + create for every such record.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.dns_io import ParsedRecord, diff_records, parse_zone_file
from tests.test_dns_import_export import _admin_auth, _make_zone

_RECORDS = [
    {"name": "@", "record_type": "MX", "value": "mail", "priority": 10},
    {
        "name": "_sip._tcp",
        "record_type": "SRV",
        "value": "sip",
        "priority": 1,
        "weight": 5,
        "port": 5060,
    },
    {"name": "www", "record_type": "CNAME", "value": "web"},
    {"name": "abs", "record_type": "CNAME", "value": "target.other.net."},
    {"name": "sub", "record_type": "NS", "value": "ns.sub"},
    {"name": "10", "record_type": "PTR", "value": "host"},
    {"name": "old", "record_type": "DNAME", "value": "new"},
    {"name": "txt", "record_type": "TXT", "value": "v=spf1 -all"},
    {"name": "txt2", "record_type": "TXT", "value": 'say "hi" \\ there'},
]


async def _seed(client: AsyncClient, db: AsyncSession) -> tuple[str, str, dict[str, str]]:
    headers = await _admin_auth(db)
    group, zone = await _make_zone(db)
    base = f"/api/v1/dns/groups/{group.id}/zones/{zone.id}"
    for rec in _RECORDS:
        r = await client.post(f"{base}/records", json=rec, headers=headers)
        assert r.status_code in (200, 201), (rec, r.text)
    return base, str(zone.id), headers


@pytest.mark.asyncio
@pytest.mark.parametrize("strategy", ["replace", "merge"])
async def test_export_reimports_as_no_change(
    client: AsyncClient, db_session: AsyncSession, strategy: str
) -> None:
    base, _, headers = await _seed(client, db_session)
    export = await client.get(f"{base}/export", headers=headers)
    assert export.status_code == 200
    preview = await client.post(
        f"{base}/import/preview",
        json={
            "zone_file": export.text,
            "zone_name": "example.com.",
            "conflict_strategy": strategy,
        },
        headers=headers,
    )
    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert body["to_create"] == []
    assert body["to_delete"] == []
    assert body["to_update"] == []


@pytest.mark.asyncio
async def test_export_keeps_relative_targets_relative(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    base, _, headers = await _seed(client, db_session)
    text = (await client.get(f"{base}/export", headers=headers)).text
    parsed = parse_zone_file(text, "example.com.")
    values = {(r.name, r.record_type): r.value for r in parsed.records}
    # Read back against $ORIGIN, a relative target is the same in-zone name.
    assert values[("www", "CNAME")] == "web.example.com."
    assert values[("@", "MX")] == "mail.example.com."
    assert values[("abs", "CNAME")] == "target.other.net."


def test_diff_names_compare_normalised() -> None:
    from dataclasses import dataclass

    @dataclass
    class Row:
        id: str
        name: str
        record_type: str
        value: str
        ttl: int | None = None
        priority: int | None = None
        weight: int | None = None
        port: int | None = None
        view_id: None = None
        managed_by: None = None

    existing = [Row("1", "www", "CNAME", "Web"), Row("2", "w2", "CNAME", "web")]
    parsed = [
        ParsedRecord("www", "CNAME", "web.example.com."),
        ParsedRecord("w2", "CNAME", "WEB.example.com."),
    ]
    d = diff_records(parsed, existing, zone_name="example.com.", replace=True)  # type: ignore[arg-type]
    assert not d.to_create and not d.to_delete and len(d.unchanged) == 2
