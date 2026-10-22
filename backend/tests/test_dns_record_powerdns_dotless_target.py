"""A dot-less name target is refused on a PowerDNS group (#2060).

PowerDNS's API refuses a CNAME / PTR / MX / … target written without its
trailing dot (``422 Not in expected format (parsed as 'db1.example.com.')``,
verified against pdns-auth 5.0.7). The record API stored such a value as
typed, so the operator got a 201 for a record the agent could not apply: the
record op failed and retried until its budget ran out, and every structural
reconcile of the zone was refused whole.

The agent now qualifies a dot-less target against the zone (so rows that
already exist are served as BIND9 serves them); the API refuses a NEW one on a
PowerDNS group, naming both spellings it could mean, because an operator there
is used to absolute names and serving ``db1.example.com.<zone>.`` for
``db1.example.com`` would be a wrong answer nobody asked for. Create, update,
bulk create and the Copilot all refuse it; other drivers are unchanged.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.services.ai.operations import CreateDNSRecordArgs, get_operation
from app.services.dns.name_targets import dotless_target, dotless_target_error

# ── which values carry a dot-less target ────────────────────────────────────


@pytest.mark.parametrize(
    ("rtype", "value", "target"),
    [
        ("CNAME", "db1.example.com", "db1.example.com"),
        ("CNAME", "www", "www"),
        ("CNAME", "@", "@"),
        ("PTR", "host.example.com", "host.example.com"),
        ("NS", "ns1.example.net", "ns1.example.net"),
        ("DNAME", "other.example", "other.example"),
        ("ALIAS", "lb.example.net", "lb.example.net"),
        ("MX", "mail", "mail"),
        ("MX", "10 mail.example.com", "mail.example.com"),
        ("SRV", "sip.example.com", "sip.example.com"),
        ("SRV", "0 5 5060 sip", "sip"),
        ("HTTPS", "1 web alpn=h2", "web"),
        ("SVCB", "1 svc.example.com", "svc.example.com"),
        ("NAPTR", '100 10 "u" "E2U+sip" "" sip', "sip"),
    ],
)
def test_a_dotless_target_is_found(rtype: str, value: str, target: str) -> None:
    assert dotless_target(rtype, value) == target


@pytest.mark.parametrize(
    ("rtype", "value"),
    [
        ("CNAME", "db1.example.com."),
        ("PTR", "host.example.com."),
        ("MX", "0 ."),
        ("MX", "mail.example.com."),
        ("SRV", "0 0 0 ."),
        ("HTTPS", "1 . alpn=h2"),
        ("NAPTR", '100 10 "u" "E2U+sip" "!^.*$!sip:x@y!" .'),
        ("A", "192.0.2.1"),
        ("AAAA", "2001:db8::1"),
        ("TXT", "v=spf1 -all"),
        ("CAA", '0 issue "letsencrypt.org"'),
    ],
)
def test_an_absolute_target_or_no_target_passes(rtype: str, value: str) -> None:
    assert dotless_target(rtype, value) is None
    assert dotless_target_error(rtype, value, "example.com.") is None


def test_the_refusal_names_both_spellings() -> None:
    err = dotless_target_error("CNAME", "db1.example.com", "example.com")
    assert err is not None
    assert "'db1.example.com.'" in err
    assert "'db1.example.com.example.com.'" in err
    assert err.startswith("CNAME record value:")
    at = dotless_target_error("CNAME", "@", "example.com.")
    assert at is not None and "'example.com.'" in at


# ── the API ─────────────────────────────────────────────────────────────────


async def _admin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"dt-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Dotless Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _zone(db: AsyncSession, driver: str | None) -> DNSZone:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    if driver is not None:
        db.add(
            DNSServer(
                group_id=grp.id,
                driver=driver,
                host="10.0.0.1",
                name=f"srv-{uuid.uuid4().hex[:6]}",
                is_primary=True,
                is_enabled=True,
            )
        )
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
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


async def _values(db: AsyncSession, zone: DNSZone) -> list[str]:
    rows = await db.execute(select(DNSRecord.value).where(DNSRecord.zone_id == zone.id))
    return sorted(v for (v,) in rows.all())


_DOTLESS = [
    {"name": "db", "record_type": "CNAME", "value": "db1.example.com"},
    {"name": "p", "record_type": "PTR", "value": "host.example.com"},
    {"name": "mx", "record_type": "MX", "value": "mail", "priority": 10},
    {
        "name": "_sip._tcp",
        "record_type": "SRV",
        "value": "sip.example.com",
        "priority": 0,
        "weight": 5,
        "port": 5060,
    },
]


async def test_create_refuses_a_dotless_target_on_powerdns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session, "powerdns")
    await db_session.commit()

    for body in _DOTLESS:
        resp = await client.post(_url(zone), headers=headers, json=body)
        assert resp.status_code == 422, (body, resp.text)
        detail = resp.json()["detail"]
        assert "record value" in detail and "trailing dot" in detail, detail
    assert await _values(db_session, zone) == []

    resp = await client.post(
        _url(zone),
        headers=headers,
        json={"name": "db", "record_type": "CNAME", "value": "db1.example.com."},
    )
    assert resp.status_code == 201, resp.text


@pytest.mark.parametrize("driver", ["bind9", None])
async def test_other_groups_keep_the_zone_file_reading(
    client: AsyncClient, db_session: AsyncSession, driver: str | None
) -> None:
    """BIND9 (and a group with no server yet) store the value as typed."""
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session, driver)
    await db_session.commit()

    resp = await client.post(
        _url(zone),
        headers=headers,
        json={"name": "db", "record_type": "CNAME", "value": "www"},
    )
    assert resp.status_code == 201, resp.text


async def test_update_refuses_a_dotless_target_and_leaves_old_rows_editable(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session, "powerdns")
    legacy = DNSRecord(
        zone_id=zone.id,
        name="old",
        fqdn=f"old.{zone.name}",
        record_type="CNAME",
        value="legacy.example.com",
    )
    good = DNSRecord(
        zone_id=zone.id,
        name="new",
        fqdn=f"new.{zone.name}",
        record_type="CNAME",
        value="ok.example.com.",
    )
    db_session.add_all([legacy, good])
    await db_session.commit()

    resp = await client.put(
        f"{_url(zone)}/{good.id}", headers=headers, json={"value": "ok.example.com"}
    )
    assert resp.status_code == 422, resp.text
    assert "trailing dot" in resp.json()["detail"]

    # A row stored before the rule is not re-judged on an unrelated edit,
    # even when its own value is resubmitted with it (the UI form does).
    resp = await client.put(
        f"{_url(zone)}/{legacy.id}",
        headers=headers,
        json={"ttl": 300, "value": "legacy.example.com"},
    )
    assert resp.status_code == 200, resp.text


async def test_bulk_create_refuses_the_batch(client: AsyncClient, db_session: AsyncSession) -> None:
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session, "powerdns")
    await db_session.commit()

    resp = await client.post(
        f"{_url(zone)}/bulk-create",
        headers=headers,
        json={
            "records": [
                {"name": "ok", "record_type": "A", "value": "192.0.2.34"},
                {"name": "db", "record_type": "CNAME", "value": "db1.example.com"},
            ]
        },
    )
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"].startswith("db: CNAME record value")
    assert await _values(db_session, zone) == []


async def test_the_copilot_refuses_a_dotless_target_on_powerdns(
    db_session: AsyncSession,
) -> None:
    user, _headers = await _admin(db_session)
    zone = await _zone(db_session, "powerdns")
    await db_session.commit()

    op = get_operation("create_dns_record")
    assert op is not None
    args = CreateDNSRecordArgs(
        zone_id=str(zone.id), name="db", record_type="CNAME", value="db1.example.com"
    )
    preview = await op.preview(db_session, user, args)
    assert preview.ok is False and "trailing dot" in preview.detail
    with pytest.raises(ValueError, match="trailing dot"):
        await op.apply(db_session, user, args)
