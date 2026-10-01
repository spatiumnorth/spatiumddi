"""Record names BIND refuses never reach the database (#1378).

The record API checked every owner with the RFC 2181 rule, which allows ``_``,
so ``bad_name A 192.0.2.33`` answered 201. BIND loads a primary zone under
``check-names primary fail`` and the agent renders no check-names option, so
the agent's named-checkzone refused the zone file ("bad owner name
(check-names)") and the agent quarantined the server's whole config bundle:
the record was never served and no later change on that server applied.

``bind_check_names_error`` is BIND's rule; create, update, bulk create and the
Copilot refuse what it refuses with a 422 (a ValueError for the Copilot). The
cases mirror what named-checkzone ``-k fail`` refuses and loads, so the API is
never stricter than BIND either.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dns_names import bind_check_names_error
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.services.ai.operations import CreateDNSRecordArgs, get_operation

ZONE = "drill.test."
DRILL_NS = "drill-ns.example."
REV4 = "2.0.192.in-addr.arpa."
REV6 = "8.b.d.0.1.0.0.2.ip6.arpa."
MSDCS = "_msdcs.drill.test."

# ── The rule, case by case against BIND ─────────────────────────────────────
# Each case is one zone file run through named-checkzone 9.20.29 with the
# agent's flags (-i none -k fail) on the appliance's dns-bind9 image (issues
# run 20261001, drills cn-matrix c01-c40 and cn-matrix-2 m01-m28); the case id
# is the drill's. A refused case names the label BIND refused.

BIND_REFUSES = [
    ("c01", "A", "bad_name.drill.test.", "192.0.2.33", ZONE, "bad_name"),
    ("c02", "A", "x.bad_name.drill.test.", "192.0.2.33", ZONE, "bad_name"),
    ("c05", "AAAA", "bad_name.drill.test.", "2001:db8::33", ZONE, "bad_name"),
    ("c06", "MX", "_mail.drill.test.", f"10 mx.{DRILL_NS}", ZONE, "_mail"),
    ("c07", "MX", "mx.drill.test.", f"10 _mx.{DRILL_NS}", ZONE, "_mx"),
    ("c10", "SRV", "_sip._udp.drill.test.", f"10 5 5060 _sip.{DRILL_NS}", ZONE, "_sip"),
    ("c12", "NS", "sub.drill.test.", f"_ns.{DRILL_NS}", ZONE, "_ns"),
    ("c16", "PTR", f"5.{REV4}", f"_bad.{DRILL_NS}", REV4, "_bad"),
    ("c25", "SVCB", "svc.drill.test.", f"1 _bad.{DRILL_NS}", ZONE, "_bad"),
    ("c26", "HTTPS", "web.drill.test.", f"1 _bad.{DRILL_NS}", ZONE, "_bad"),
    ("c34", "A", "_x.drill.test.", "192.0.2.50", "_x.drill.test.", "_x"),
    ("c35", "MX", "mxr.drill.test.", "10 _mx", ZONE, "_mx"),
    ("c40", "PTR", "1." + "0." * 23 + REV6, f"_bad.{DRILL_NS}", REV6, "_bad"),
    ("m02", "A", f"dc1.{MSDCS}", "192.0.2.9", MSDCS, "_msdcs"),
    ("m03", "A", f"x.gc.{MSDCS}", "192.0.2.9", MSDCS, "_msdcs"),
    ("m04", "A", "gc._msdcs._x.drill.test.", "192.0.2.9", "_msdcs._x.drill.test.", "_msdcs"),
    ("m07", "MX", "gc._msdcs.drill.test.", f"10 mx.{DRILL_NS}", ZONE, "_msdcs"),
    ("m13", "AAAA", "x._spf.drill.test.", "2001:db8::2", ZONE, "_spf"),
    ("m14", "MX", "x._spf.drill.test.", f"10 mx.{DRILL_NS}", ZONE, "_spf"),
    ("m16", "A", "x.drill._spf.", "127.0.0.2", "x.drill._spf.", "_spf"),
    ("m20", "SVCB", "svc.drill.test.", f"1 _bad.{DRILL_NS} alpn=h2", ZONE, "_bad"),
    ("m24", "PTR", f"x._dns-sd._udp.{REV4}", f"_bad.{DRILL_NS}", REV4, "_bad"),
    ("m26", "MX", "mx.drill.test.", f"10 gc._msdcs.{DRILL_NS}", ZONE, "_msdcs"),
    ("m27", "SRV", "_ldap._tcp.drill.test.", f"0 100 389 gc._msdcs.{DRILL_NS}", ZONE, "_msdcs"),
    ("m28", "A", f"*.gc.{MSDCS}", "192.0.2.9", MSDCS, "_msdcs"),
    # The API's own value shapes: MX / SRV targets without the inline priority.
    ("api-mx", "MX", "mx.drill.test.", f"_mx.{DRILL_NS}", ZONE, "_mx"),
    ("api-srv", "SRV", "_sip._udp.drill.test.", f"_sip.{DRILL_NS}", ZONE, "_sip"),
]

BIND_LOADS = [
    ("c03", "A", "*.wild.drill.test.", "192.0.2.40", ZONE),
    ("c04", "A", "*.drill.test.", "192.0.2.41", ZONE),
    ("c08", "MX", "nullmx.drill.test.", "0 .", ZONE),
    ("c09", "SRV", "_sip._tcp.drill.test.", f"10 5 5060 sip.{DRILL_NS}", ZONE),
    ("c11", "SRV", "_none._tcp.drill.test.", "0 0 0 .", ZONE),
    ("c13", "CNAME", "_cn.drill.test.", f"host.{DRILL_NS}", ZONE),
    ("c14", "CNAME", "cnt.drill.test.", f"_bad.{DRILL_NS}", ZONE),
    ("c15", "PTR", "_ptr.drill.test.", f"_bad.{DRILL_NS}", ZONE),
    ("c17", "PTR", f"6.{REV4}", f"host.{DRILL_NS}", REV4),
    ("c18", "PTR", f"b._dns-sd._udp.{REV4}", f"_bad.{DRILL_NS}", REV4),
    ("c19", "A", f"gc.{MSDCS}", "192.0.2.9", MSDCS),
    ("c20", "SRV", f"_ldap._tcp.{MSDCS}", f"0 100 389 dc1.{DRILL_NS}", MSDCS),
    ("c21", "TXT", "_dmarc.drill.test.", '"v=DMARC1; p=none"', ZONE),
    ("c21", "TXT", "_acme-challenge.drill.test.", '"token"', ZONE),
    ("c22", "TLSA", "_443._tcp.drill.test.", "3 1 1 " + "ab" * 32, ZONE),
    ("c23", "NAPTR", "naptr.drill.test.", f'100 10 "S" "SIP+D2U" "" _sip._udp.{DRILL_NS}', ZONE),
    ("c24", "DNAME", "dn.drill.test.", f"_bad.{DRILL_NS}", ZONE),
    ("c27", "A", "1host.drill.test.", "192.0.2.42", ZONE),
    ("c27", "A", "host-1.drill.test.", "192.0.2.43", ZONE),
    ("c33", "MX", "*.mxw.drill.test.", f"10 mx.{DRILL_NS}", ZONE),
    ("c38", "A", "ok.drill.test.", "192.0.2.34", ZONE),
    ("c39", "NS", "_sub.drill.test.", f"ns1.{DRILL_NS}", ZONE),
    ("m01", "AAAA", f"gc.{MSDCS}", "2001:db8::9", MSDCS),
    ("m05", "A", "gc._msdcs.drill.test.", "192.0.2.9", ZONE),
    ("m06", "A", "GC._MSDCS.drill.test.", "192.0.2.9", ZONE),
    ("m08", "A", "_spf.drill.test.", "127.0.0.2", ZONE),
    ("m09", "A", "x._spf.drill.test.", "127.0.0.2", ZONE),
    ("m10", "A", "bad_name._spf.drill.test.", "127.0.0.2", ZONE),
    ("m11", "A", "x._spf_verify.drill.test.", "127.0.0.2", ZONE),
    ("m12", "A", "x._spf_rate.drill.test.", "127.0.0.2", ZONE),
    ("m15", "A", "_spf.drill.test.", "127.0.0.2", "_spf.drill.test."),
    ("m17", "A", "x._SPF.drill.test.", "127.0.0.2", ZONE),
    ("m18", "SVCB", "svc.drill.test.", f"0 _bad.{DRILL_NS}", ZONE),
    ("m19", "HTTPS", "web.drill.test.", f"0 _bad.{DRILL_NS}", ZONE),
    ("m21", "HTTPS", "web.drill.test.", "1 . alpn=h2", ZONE),
    ("m22", "SVCB", "_8443._https.api.drill.test.", f"1 api.{DRILL_NS}", ZONE),
    ("m23", "PTR", f"db._dns-sd._udp.{REV4}", f"_bad.{DRILL_NS}", REV4),
    ("m25", "PTR", f"r._dns-sd._udp.{REV4}", f"_bad.{DRILL_NS}", REV4),
    ("m25", "PTR", f"lb._dns-sd._udp.{REV4}", f"_bad.{DRILL_NS}", REV4),
    ("m25", "PTR", f"dr._dns-sd._udp.{REV4}", f"_bad.{DRILL_NS}", REV4),
    # Beyond the drill: an IDN owner as stored (its A-label), mixed case, the apex.
    ("idn", "A", "xn--bcher-kva.drill.test.", "192.0.2.44", ZONE),
    ("case", "A", "Mixed.drill.test.", "192.0.2.45", ZONE),
    ("apex", "A", ZONE, "192.0.2.46", ZONE),
]


@pytest.mark.parametrize(
    ("case", "rtype", "owner", "value", "origin", "bad"),
    BIND_REFUSES,
    ids=[f"{c[0]}-{c[1]}" for c in BIND_REFUSES],
)
def test_bind_refuses_these(
    case: str, rtype: str, owner: str, value: str, origin: str, bad: str
) -> None:
    err = bind_check_names_error(rtype, owner, value, origin=origin)
    assert err is not None, case
    assert f"'{bad}'" in err, (case, err)
    assert "host name" in err


@pytest.mark.parametrize(
    ("case", "rtype", "owner", "value", "origin"),
    BIND_LOADS,
    ids=[f"{c[0]}-{c[1]}-{i}" for i, c in enumerate(BIND_LOADS)],
)
def test_bind_loads_these(case: str, rtype: str, owner: str, value: str, origin: str) -> None:
    assert bind_check_names_error(rtype, owner, value, origin=origin) is None, case


def test_an_edit_checks_only_what_it_changes() -> None:
    assert bind_check_names_error("MX", "_mx.drill.test.", "_t.drill.test.", origin=ZONE)
    assert (
        bind_check_names_error(
            "MX", "_mx.drill.test.", "ok.drill.test.", origin=ZONE, check_owner=False
        )
        is None
    )
    assert (
        bind_check_names_error(
            "MX", "mx.drill.test.", "_t.drill.test.", origin=ZONE, check_target=False
        )
        is None
    )


# ── The API ─────────────────────────────────────────────────────────────────


async def _admin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"cn-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Check-names Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _zone(db: AsyncSession, name: str | None = None) -> DNSZone:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="10.0.0.1",
            name=f"srv-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name=name or f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
        ttl=3600,
    )
    db.add(zone)
    await db.flush()
    return zone


def _url(zone: DNSZone) -> str:
    return f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/records"


async def _names(db: AsyncSession, zone: DNSZone) -> list[tuple[str, str]]:
    rows = await db.execute(
        select(DNSRecord.name, DNSRecord.record_type).where(DNSRecord.zone_id == zone.id)
    )
    return sorted((n, t) for n, t in rows.all())


async def test_create_refuses_what_bind_refuses_and_keeps_597s_names(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session)
    await db_session.commit()

    for body in (
        {"name": "bad_name", "record_type": "A", "value": "192.0.2.33"},
        {"name": "bad_name", "record_type": "AAAA", "value": "2001:db8::33"},
        {"name": "_mail", "record_type": "MX", "value": f"mx.{zone.name}", "priority": 10},
        {"name": "mx", "record_type": "MX", "value": f"_mx.{zone.name}", "priority": 10},
        {"name": "sub", "record_type": "NS", "value": "_ns.example.net."},
        {
            "name": "_sip._udp",
            "record_type": "SRV",
            "value": f"_sip.{zone.name}",
            "priority": 10,
            "weight": 5,
            "port": 5060,
        },
    ):
        resp = await client.post(_url(zone), headers=headers, json=body)
        assert resp.status_code == 422, (body, resp.text)
        assert "host name" in resp.json()["detail"], resp.text
    assert await _names(db_session, zone) == []

    for body in (
        {"name": "ok", "record_type": "A", "value": "192.0.2.34"},
        {"name": "*.wild", "record_type": "A", "value": "192.0.2.40"},
        {"name": "_acme-challenge", "record_type": "TXT", "value": '"token"'},
        {
            "name": "_sip._tcp",
            "record_type": "SRV",
            "value": f"ok.{zone.name}",
            "priority": 10,
            "weight": 5,
            "port": 5060,
        },
        {"name": "mx", "record_type": "MX", "value": f"ok.{zone.name}", "priority": 10},
    ):
        resp = await client.post(_url(zone), headers=headers, json=body)
        assert resp.status_code == 201, (body, resp.text)


async def test_an_underscore_zone_takes_only_the_a_records_bind_allows(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The zone's own labels count, and so do BIND's two exceptions: Active
    Directory's gc._msdcs.<forest> and an SPF "exists" label (cases c19, m02,
    m09 above)."""
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session, name=f"_msdcs.c{uuid.uuid4().hex[:6]}.example.")
    await db_session.commit()

    resp = await client.post(
        _url(zone), headers=headers, json={"name": "dc1", "record_type": "A", "value": "192.0.2.9"}
    )
    assert resp.status_code == 422, resp.text
    assert "'_msdcs'" in resp.json()["detail"]
    for body in (
        {"name": "gc", "record_type": "A", "value": "192.0.2.9"},
        {"name": "gc", "record_type": "AAAA", "value": "2001:db8::9"},
        {"name": "x._spf", "record_type": "A", "value": "127.0.0.2"},
        {"name": "guid", "record_type": "CNAME", "value": "dc1.example.net."},
    ):
        resp = await client.post(_url(zone), headers=headers, json=body)
        assert resp.status_code == 201, (body, resp.text)


async def test_an_edit_is_checked_for_what_it_changes_only(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session)
    good = DNSRecord(
        zone_id=zone.id, name="ok", fqdn=f"ok.{zone.name}", record_type="A", value="192.0.2.34"
    )
    # A row stored before the rule: an unrelated edit must still go through.
    legacy = DNSRecord(
        zone_id=zone.id,
        name="bad_name",
        fqdn=f"bad_name.{zone.name}",
        record_type="A",
        value="192.0.2.33",
    )
    mx = DNSRecord(
        zone_id=zone.id,
        name="mx",
        fqdn=f"mx.{zone.name}",
        record_type="MX",
        value=f"ok.{zone.name}",
        priority=10,
    )
    db_session.add_all([good, legacy, mx])
    await db_session.commit()

    resp = await client.put(f"{_url(zone)}/{good.id}", headers=headers, json={"name": "bad_2"})
    assert resp.status_code == 422, resp.text
    resp = await client.put(f"{_url(zone)}/{mx.id}", headers=headers, json={"value": "_t."})
    assert resp.status_code == 422, resp.text

    resp = await client.put(f"{_url(zone)}/{legacy.id}", headers=headers, json={"ttl": 120})
    assert resp.status_code == 200, resp.text
    # A form that resubmits the row's own name with its edit changes no name.
    resp = await client.put(
        f"{_url(zone)}/{legacy.id}", headers=headers, json={"name": "bad_name", "ttl": 60}
    )
    assert resp.status_code == 200, resp.text
    resp = await client.put(f"{_url(zone)}/{legacy.id}", headers=headers, json={"name": "good"})
    assert resp.status_code == 200, resp.text


async def test_bulk_create_refuses_the_batch(client: AsyncClient, db_session: AsyncSession) -> None:
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session)
    await db_session.commit()

    resp = await client.post(
        f"{_url(zone)}/bulk-create",
        headers=headers,
        json={
            "records": [
                {"name": "ok", "record_type": "A", "value": "192.0.2.34"},
                {"name": "bad_name", "record_type": "A", "value": "192.0.2.33"},
            ]
        },
    )
    assert resp.status_code == 422, resp.text
    assert await _names(db_session, zone) == []


async def test_the_copilot_refuses_what_bind_refuses(db_session: AsyncSession) -> None:
    user, _headers = await _admin(db_session)
    zone = await _zone(db_session)
    await db_session.commit()

    op = get_operation("create_dns_record")
    assert op is not None
    args = CreateDNSRecordArgs(
        zone_id=str(zone.id), name="bad_name", record_type="A", value="192.0.2.33"
    )
    preview = await op.preview(db_session, user, args)
    assert preview.ok is False and "host name" in preview.detail
    with pytest.raises(ValueError, match="host name"):
        await op.apply(db_session, user, args)


# ── Rows stored before the rule ─────────────────────────────────────────────


async def test_the_name_conformance_report_lists_rows_bind_refuses(
    db_session: AsyncSession,
) -> None:
    """A row stored before the API refused it keeps failing BIND's check. The
    #597 report is where an operator finds such rows, so it lists them."""
    from app.services.dns_names_report import scan_name_conformance

    zone = await _zone(db_session)
    rows = {
        "bad": DNSRecord(
            zone_id=zone.id,
            name="bad_name",
            fqdn=f"bad_name.{zone.name}",
            record_type="A",
            value="192.0.2.33",
        ),
        "mx": DNSRecord(
            zone_id=zone.id,
            name="mx",
            fqdn=f"mx.{zone.name}",
            record_type="MX",
            value=f"_mx.{zone.name}",
            priority=10,
        ),
        "txt": DNSRecord(
            zone_id=zone.id,
            name="_acme-challenge",
            fqdn=f"_acme-challenge.{zone.name}",
            record_type="TXT",
            value='"token"',
        ),
        "ok": DNSRecord(
            zone_id=zone.id, name="ok", fqdn=f"ok.{zone.name}", record_type="A", value="192.0.2.34"
        ),
    }
    db_session.add_all(rows.values())
    await db_session.commit()

    report = await scan_name_conformance(db_session)
    cat = next(c for c in report["categories"] if c["category"] == "dns_record_name")
    listed = {e["id"]: e["reason"] for e in cat["examples"]}
    assert set(listed) == {str(rows["bad"].id), str(rows["mx"].id)}, listed
    assert "'bad_name'" in listed[str(rows["bad"].id)]
    assert "'_mx'" in listed[str(rows["mx"].id)]
    assert cat["total"] == 2
