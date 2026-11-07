"""#3673 — an importer holds the source SOA RNAME to Add Zone's rule (#2916).

A value Add Zone refuses was stored as written and the agent then served
``admin.{zone}`` with nothing said. Now it is left empty, with a preview warning.
"""

from __future__ import annotations

import io
import tarfile
import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServerGroup, DNSZone
from app.services.dns_import.canonical import ImportedSOA, ImportedZone, ImportPreview
from app.services.dns_import.commit import _zone_kwargs_from_parsed
from app.services.dns_import.powerdns import _parse_soa_content
from app.services.dns_import.soa_mailbox import annotate_admin_email
from app.services.dns_import.technitium import _soa_from_rdata

OK = "hostmaster.example.com."
UNDERSCORE = "hostmaster.under_score.example.com."
ESCAPED = r"john\.doe.example.com."

_NAMED = "".join(
    f'zone "{n}" {{ type master; file "{n}.zone"; }};\n'
    for n in ("ok.test", "under.test", "esc.test")
)


def _zone(n: str, rname: str) -> str:
    return (
        f"$TTL 3600\n@ IN SOA ns1.{n}. {rname} ( 1 3600 1800 1209600 3600 )\n"
        f"  IN NS ns1.{n}.\nns1 IN A 192.0.2.1\n"
    )


def _archive() -> bytes:
    members = [("etc/named.conf", _NAMED)] + [
        (f"var/named/{n}.zone", _zone(n, r))
        for n, r in (("ok.test", OK), ("under.test", UNDERSCORE), ("esc.test", ESCAPED))
    ]
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        for path, content in members:
            data = content.encode()
            info = tarfile.TarInfo(path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return bio.getvalue()


def _preview_of(soas: dict[str, str]) -> ImportPreview:
    zones = [
        ImportedZone(
            name=n,
            zone_type="primary",
            kind="forward",
            soa=ImportedSOA("ns1.x.", rname, 1, 3600, 1800, 1209600, 3600, 3600),
            records=[],
        )
        for n, rname in soas.items()
    ]
    return ImportPreview(
        source="powerdns",
        zones=zones,
        conflicts=[],
        warnings=[],
        total_records=0,
        record_type_histogram={},
    )


@pytest.mark.asyncio
async def test_bind9_import_keeps_valid_and_drops_refused_rname(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    user = User(
        username="adm3673",
        email="adm3673@example.com",
        display_name="adm3673",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db_session.add(user)
    group = DNSServerGroup(name=f"g3673-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    token = create_access_token(str(user.id))
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    pre = await client.post(
        "/api/v1/dns/import/bind9/preview",
        headers=headers,
        files={"file": ("b.tar.gz", _archive(), "application/gzip")},
        data={"target_group_id": str(group.id)},
    )
    assert pre.status_code == 200, pre.text
    plan = pre.json()
    warnings = " ".join(plan["warnings"])
    assert "under.test." in warnings and "under_score" in warnings
    assert "esc.test." in warnings and "john" in warnings
    assert "ok.test." not in warnings
    assert len(plan["warnings"]) == 2

    res = await client.post(
        "/api/v1/dns/import/bind9/commit",
        headers=headers,
        json={"target_group_id": str(group.id), "plan": plan, "conflict_actions": {}},
    )
    assert res.status_code == 200, res.text
    zones = {
        z.name: z.admin_email
        for z in (
            await db_session.execute(select(DNSZone).where(DNSZone.group_id == group.id))
        ).scalars()
    }
    assert zones == {
        "ok.test.": "hostmaster.example.com",
        "under.test.": "",
        "esc.test.": "",
    }


def test_powerdns_and_technitium_soa_are_held_to_the_rule() -> None:
    pdns = {
        "ok.test.": _parse_soa_content(f"ns1.ok.test. {OK} 1 3600 1800 1209600 3600", 3600),
        "under.test.": _parse_soa_content(
            f"ns1.u.test. {UNDERSCORE} 1 3600 1800 1209600 3600", 3600
        ),
        "esc.test.": _parse_soa_content(f"ns1.e.test. {ESCAPED} 1 3600 1800 1209600 3600", 3600),
    }
    tech = _soa_from_rdata({"primaryNameServer": "ns1.t.test", "responsiblePerson": ESCAPED}, 3600)
    for label, soas in (
        ("pdns", {n: s.admin_email for n, s in pdns.items() if s}),
        ("tech", {"ok.test.": OK, "esc.test.": tech.admin_email}),
    ):
        prev = _preview_of(soas)
        annotate_admin_email(prev)
        flagged = [n for n in soas if any(f"Zone {n!r}" in w for w in prev.warnings)]
        assert flagged == [n for n in soas if n != "ok.test."], label
        for z in prev.zones:
            kwargs = _zone_kwargs_from_parsed(
                z,
                name=z.name.rstrip("."),
                target_group_id=uuid.uuid4(),
                target_view_id=None,
                source="powerdns",
                now=datetime.now(UTC),
            )
            expect = "hostmaster.example.com" if z.name == "ok.test." else ""
            assert kwargs["admin_email"] == expect, (label, z.name)
