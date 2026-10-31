"""Every path that publishes to DNS validates the owner and the value.

The REST record and address endpoints refuse a blank or malformed host name
and any record value carrying a newline or control character. Three other
paths reached DNS without those rules:

* a DHCP reservation whose hostname was whitespace only was stored verbatim,
  mirrored into IPAM and published as a record owner of blanks;
* the IPAM → DNS sync published whatever hostname a row carried, so a row
  stored by an importer or before a validator existed reached the zone;
* the operation layer behind the requests portal and the Copilot validated
  less than REST (a newline-carrying A value, an integration-only status, a
  malformed reservation hostname were all accepted at submit).

The zone-file writer on the agent has its own guard (agent tests); these pin
the control-plane half.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ipam.router import _sync_dns_record
from app.core.dns_names import (
    publishable_host_owner_error,
    record_value_error,
    validate_optional_hostname,
)
from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User
from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup, DHCPStaticAssignment
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.models.feature_module import FeatureModule
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services import feature_modules
from app.services.ai.operations import (
    CreateDHCPStaticArgs,
    CreateDNSRecordArgs,
    CreateIPAddressArgs,
    _apply_create_dns_record,
)
from app.services.dhcp.static_ipam import upsert_ipam_for_static

INJECTED_A = "10.60.0.9\nevil 300 IN A 198.51.100.7"


# ── Pure helpers ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "name",
    ["", "   ", "\t", " web1", "web1 ", "web 1", "web1\n", "x\nevil", "a\x00b", "@", "-bad"],
)
def test_unpublishable_host_owners(name: str) -> None:
    assert publishable_host_owner_error(name) is not None


@pytest.mark.parametrize("name", ["web1", "web-01.corp", "_svc", "Web1"])
def test_publishable_host_owners(name: str) -> None:
    assert publishable_host_owner_error(name) is None


def test_optional_hostname_folds_blank_to_empty() -> None:
    assert validate_optional_hostname(None) is None
    assert validate_optional_hostname("   ") == ""
    assert validate_optional_hostname(" Web1 ") == "web1"
    with pytest.raises(ValueError):
        validate_optional_hostname("bad host")


@pytest.mark.parametrize(
    ("rtype", "value"),
    [
        ("A", INJECTED_A),
        ("A", "10.0.0.1, 10.0.0.2"),
        ("AAAA", "10.0.0.1"),
        ("TXT", "v=spf1 -all\nevil 300 IN A 198.51.100.7"),
        ("CNAME", "bad target"),
        ("MX", "10 mail.example.com.\nx"),
    ],
)
def test_record_value_refusals(rtype: str, value: str) -> None:
    assert record_value_error(rtype, value) is not None


@pytest.mark.parametrize(
    ("rtype", "value"),
    [
        ("A", "10.0.0.1"),
        ("AAAA", "2001:db8::1"),
        ("TXT", "token value with spaces"),
        ("CNAME", "www.example.com."),
        ("CAA", '0 issue "letsencrypt.org"'),
    ],
)
def test_record_value_accepts(rtype: str, value: str) -> None:
    assert record_value_error(rtype, value) is None


# ── Fixtures ──────────────────────────────────────────────────────────────────


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"pub-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


class _Env:
    subnet: Subnet
    zone: DNSZone
    scope: DHCPScope


async def _env(db: AsyncSession) -> _Env:
    env = _Env()
    grp = DNSServerGroup(name=f"gpub-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="10.9.9.9",
            name=f"ns-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    env.zone = DNSZone(
        group_id=grp.id,
        name=f"pub{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(env.zone)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.61.0.0/16", name="b")
    db.add(block)
    await db.flush()
    env.subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.61.5.0/24",
        name="lan",
        dns_group_ids=[str(grp.id)],
        dns_zone_id=str(env.zone.id),
        dns_inherit_settings=False,
    )
    dgrp = DHCPServerGroup(name=f"dg-{uuid.uuid4().hex[:6]}")
    db.add_all([env.subnet, dgrp])
    await db.flush()
    db.add(
        DHCPServer(
            name=f"k-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host="127.0.0.1",
            server_group_id=dgrp.id,
        )
    )
    env.scope = DHCPScope(
        group_id=dgrp.id, subnet_id=env.subnet.id, name="scope", address_family="ipv4"
    )
    db.add(env.scope)
    await db.flush()
    await db.commit()
    return env


async def _records_at(db: AsyncSession, address: str) -> list[DNSRecord]:
    return list(
        (
            await db.execute(
                select(DNSRecord)
                .where(DNSRecord.value == address, DNSRecord.record_type == "A")
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )


# ── DHCP reservation REST ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_static_whitespace_hostname_stores_blank_and_publishes_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    env = await _env(db_session)
    resp = await client.post(
        f"/api/v1/dhcp/scopes/{env.scope.id}/statics",
        headers=headers,
        json={"ip_address": "10.61.5.20", "mac_address": "aa:bb:cc:dd:ee:20", "hostname": "   "},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["hostname"] == ""
    assert await _records_at(db_session, "10.61.5.20") == []


@pytest.mark.asyncio
async def test_static_update_whitespace_hostname_clears_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    env = await _env(db_session)
    created = await client.post(
        f"/api/v1/dhcp/scopes/{env.scope.id}/statics",
        headers=headers,
        json={"ip_address": "10.61.5.21", "mac_address": "aa:bb:cc:dd:ee:21", "hostname": "h21"},
    )
    assert created.status_code == 201, created.text
    # Negative control: a real hostname is published.
    assert [r.name for r in await _records_at(db_session, "10.61.5.21")] == ["h21"]
    sid = created.json()["id"]
    resp = await client.put(f"/api/v1/dhcp/statics/{sid}", headers=headers, json={"hostname": "  "})
    assert resp.status_code == 200, resp.text
    assert resp.json()["hostname"] == ""
    # The old name's A is retracted, not left served.
    assert await _records_at(db_session, "10.61.5.21") == []


# ── IPAM mirror + sync ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mirror_of_stored_whitespace_hostname_publishes_nothing(
    db_session: AsyncSession,
) -> None:
    env = await _env(db_session)
    st = DHCPStaticAssignment(
        scope_id=env.scope.id,
        ip_address="10.61.5.30",
        mac_address="aa:bb:cc:dd:ee:30",
        hostname="   ",
    )
    db_session.add(st)
    await db_session.flush()
    await upsert_ipam_for_static(db_session, env.scope, st)
    await db_session.flush()
    row = (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.61.5.30"))
    ).scalar_one()
    assert row.hostname == ""
    assert await _records_at(db_session, "10.61.5.30") == []


@pytest.mark.parametrize("hostname", ["web1\nevil", " web1"])
@pytest.mark.asyncio
async def test_sync_skips_an_unpublishable_hostname(
    db_session: AsyncSession, hostname: str
) -> None:
    env = await _env(db_session)
    ip = IPAddress(
        subnet_id=env.subnet.id, address="10.61.5.40", status="allocated", hostname=hostname
    )
    db_session.add(ip)
    await db_session.flush()
    published = await _sync_dns_record(
        db_session, ip, env.subnet, zone_id=env.zone.id, action="create"
    )
    await db_session.flush()
    assert published is False
    assert await _records_at(db_session, "10.61.5.40") == []
    with pytest.raises(HTTPException) as exc:
        await _sync_dns_record(
            db_session, ip, env.subnet, zone_id=env.zone.id, action="create", strict=True
        )
    assert exc.value.status_code == 422


@pytest.mark.asyncio
async def test_sync_retracts_records_once_the_hostname_turns_unpublishable(
    db_session: AsyncSession,
) -> None:
    env = await _env(db_session)
    ip = IPAddress(
        subnet_id=env.subnet.id, address="10.61.5.41", status="allocated", hostname="h41"
    )
    db_session.add(ip)
    await db_session.flush()
    assert await _sync_dns_record(db_session, ip, env.subnet, zone_id=env.zone.id) is True
    await db_session.flush()
    assert [r.name for r in await _records_at(db_session, "10.61.5.41")] == ["h41"]
    ip.hostname = "   "
    await _sync_dns_record(db_session, ip, env.subnet, zone_id=env.zone.id, action="update")
    await db_session.flush()
    assert await _records_at(db_session, "10.61.5.41") == []


# ── Operation layer (requests portal + Copilot) ───────────────────────────────


def test_dns_record_args_refuse_a_newline_value() -> None:
    with pytest.raises(ValidationError):
        CreateDNSRecordArgs(zone_id=str(uuid.uuid4()), name="h", record_type="A", value=INJECTED_A)
    with pytest.raises(ValidationError):
        CreateDNSRecordArgs(
            zone_id=str(uuid.uuid4()), name="x\ny", record_type="A", value="10.0.0.1"
        )
    ok = CreateDNSRecordArgs(
        zone_id=str(uuid.uuid4()), name="H1", record_type="A", value="10.0.0.1"
    )
    assert ok.name == "h1"


def test_dns_record_args_newline_value_refusal_names_the_field() -> None:
    with pytest.raises(ValidationError) as exc:
        CreateDNSRecordArgs(zone_id=str(uuid.uuid4()), name="h", record_type="A", value=INJECTED_A)
    assert [e["loc"] for e in exc.value.errors()] == [("value",)]


def test_ip_address_args_match_the_rest_create_rules() -> None:
    sid = str(uuid.uuid4())
    with pytest.raises(ValidationError):
        CreateIPAddressArgs(subnet_id=sid, address="10.0.0.5", status="kubernetes-node")
    with pytest.raises(ValidationError):
        CreateIPAddressArgs(subnet_id=sid, address="10.0.0.5", hostname="bad host")
    ok = CreateIPAddressArgs(
        subnet_id=sid, address="10.0.0.5", hostname="   ", mac_address="AA-BB-CC-DD-EE-01"
    )
    assert ok.hostname is None
    assert ok.mac_address == "aa:bb:cc:dd:ee:01"


def test_dhcp_static_args_match_the_rest_create_rules() -> None:
    sid = str(uuid.uuid4())
    with pytest.raises(ValidationError):
        CreateDHCPStaticArgs(
            scope_id=sid, ip_address="10.0.0.5", mac_address="aa:bb:cc:dd:ee:01", hostname="a b"
        )
    ok = CreateDHCPStaticArgs(
        scope_id=sid, ip_address="10.0.0.5", mac_address="AA-BB-CC-DD-EE-01", hostname="   "
    )
    assert ok.hostname == ""
    assert ok.mac_address == "aa:bb:cc:dd:ee:01"


@pytest.mark.asyncio
async def test_apply_refuses_a_newline_value_built_without_validation(
    db_session: AsyncSession,
) -> None:
    """The apply step checks the value itself (a stored request predates the model rule)."""
    env = await _env(db_session)
    user = User(
        username=f"ap-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="ap",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db_session.add(user)
    await db_session.flush()
    args = CreateDNSRecordArgs.model_construct(
        zone_id=str(env.zone.id),
        name="h1",
        record_type="A",
        value=INJECTED_A,
        ttl=None,
        priority=None,
        weight=None,
        port=None,
    )
    with pytest.raises(ValueError, match="control character"):
        await _apply_create_dns_record(db_session, user, args)


REQUESTER_PERMS = [
    {"action": "write", "resource_type": "provisioning_request"},
    {"action": "read", "resource_type": "provisioning_request"},
    # Submit refuses a target the requester cannot read.
    {"action": "read", "resource_type": "dns_zone"},
    {"action": "read", "resource_type": "subnet"},
]


async def _requester(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"rq-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="rq",
        hashed_password=hash_password("x"),
    )
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=REQUESTER_PERMS)
    group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
    group.roles = [role]
    user.groups = [group]
    db.add_all([role, group, user])
    await db.flush()
    existing = await db.get(FeatureModule, "governance.requests")
    if existing is None:
        db.add(FeatureModule(id="governance.requests", enabled=True))
    else:
        existing.enabled = True
    await db.flush()
    feature_modules.invalidate_cache()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.mark.asyncio
async def test_portal_refuses_what_rest_refuses_at_submit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    env = await _env(db_session)
    headers = await _requester(db_session)
    await db_session.commit()

    async def submit(kind: str, args: dict) -> int:
        resp = await client.post(
            "/api/v1/requests",
            headers=headers,
            json={"kind": kind, "args": args, "justification": "test"},
        )
        return resp.status_code

    zid = str(env.zone.id)
    assert (
        await submit(
            "dns_record", {"zone_id": zid, "name": "h1", "record_type": "A", "value": INJECTED_A}
        )
        == 400
    )
    named = await client.post(
        "/api/v1/requests",
        headers=headers,
        json={
            "kind": "dns_record",
            "args": {"zone_id": zid, "name": "h1", "record_type": "A", "value": INJECTED_A},
            "justification": "test",
        },
    )
    # The refusal names the field, as the status and hostname refusals do.
    assert "value: Value error, A record value contains" in named.json()["detail"]
    assert (
        await submit(
            "ip_address",
            {"subnet_id": str(env.subnet.id), "address": "10.61.5.50", "status": "kubernetes-node"},
        )
        == 400
    )
    assert (
        await submit(
            "dhcp_reservation",
            {
                "scope_id": str(env.scope.id),
                "ip_address": "10.61.5.51",
                "mac_address": "aa:bb:cc:dd:ee:51",
                "hostname": "bad host",
            },
        )
        == 400
    )
    # Negative control: the well-formed equivalents are accepted.
    assert (
        await submit(
            "dns_record", {"zone_id": zid, "name": "h1", "record_type": "A", "value": "10.61.5.9"}
        )
        == 201
    )
    assert (
        await submit(
            "ip_address",
            {"subnet_id": str(env.subnet.id), "address": "10.61.5.50", "status": "reserved"},
        )
        == 201
    )
