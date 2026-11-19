"""#2075 — a zone's Primary NS (SOA MNAME) must be a host name.

BIND's check-names refuses a zone whose MNAME has an underscore or an over-long
label, so one such zone stopped its group applying; and a single label such as
``ns1`` was served as a name at the root. The REST create, the Copilot create
args and the importer hold the rule. An update holds it for a CHANGED value
only, so a zone stored before the rule stays editable.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.router import ZoneCreate, ZoneUpdate
from app.core.dns_names import primary_ns_error
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServerGroup, DNSZone
from app.services.ai.operations import CreateDNSZoneArgs
from app.services.dns_import.canonical import ImportedSOA, ImportedZone
from app.services.dns_import.commit import _zone_kwargs_from_parsed

# The same lists are in agent/dns/tests/test_zone_apex_render.py and
# frontend/src/lib/primary-ns.test.ts: change all three together, or the API,
# the dialog and the agent's renderer disagree about which Primary NS is good.
BAD = [
    "ns_1.example.test.",
    "a" * 64 + ".example.test.",
    "ns1",
    "ns1.",
    "ns1..example.test.",
    ".example.test.",
    "-ns1.example.test.",
    "ns1-.example.test.",
    "ns1.example.test..",
    "bücher.example.test.",
    ("a" * 63 + ".") * 4 + "test.",
]
GOOD = [
    "ns1.example.test.",
    "ns1.example.test",
    "NS1.Other-Corp.net.",
    "a" * 63 + ".test.",
    "ns1.xn--bcher-kva.example.",
    "1ns.example.test.",
]


@pytest.mark.parametrize("value", BAD)
def test_helper_refuses(value: str) -> None:
    assert primary_ns_error(value) is not None


@pytest.mark.parametrize("value", [*GOOD, ""])
def test_helper_accepts(value: str) -> None:
    assert primary_ns_error(value) is None


@pytest.mark.parametrize("value", BAD)
def test_zone_create_422_names_the_field(value: str) -> None:
    with pytest.raises(ValidationError) as ei:
        ZoneCreate(name="z.test", primary_ns=value)
    errs = ei.value.errors()
    assert errs[0]["loc"] == ("primary_ns",)
    assert "Primary NS" in errs[0]["msg"]


def test_zone_schemas_accept_good_and_unset() -> None:
    assert ZoneCreate(name="z.test", primary_ns="ns1.z.test.").primary_ns == "ns1.z.test."
    assert ZoneCreate(name="z.test").primary_ns == ""
    assert ZoneUpdate().primary_ns is None
    assert ZoneUpdate(primary_ns="").primary_ns == ""


def test_admin_email_is_not_held_to_the_host_name_rule() -> None:
    # RNAME is a mailbox, not a host: an underscore is legal there.
    assert ZoneCreate(name="z.test", admin_email="host_master.z.test.").admin_email


def test_copilot_create_refuses_a_bad_primary_ns() -> None:
    with pytest.raises(ValidationError):
        CreateDNSZoneArgs(name="z.test", primary_ns="ns_1.z.test.")
    assert CreateDNSZoneArgs(name="z.test", primary_ns="ns1.z.test.").primary_ns


def _parsed(mname: str) -> ImportedZone:
    soa = ImportedSOA(
        primary_ns=mname,
        admin_email="h.z.test.",
        serial=1,
        refresh=1,
        retry=1,
        expire=1,
        minimum=1,
        ttl=1,
    )
    return ImportedZone(name="z.test.", zone_type="primary", kind="forward", soa=soa, records=[])


@pytest.mark.parametrize(
    ("mname", "stored"),
    [("ns_1.z.test.", ""), ("localhost.", ""), ("ns1.z.test.", "ns1.z.test")],
)
def test_importer_does_not_store_an_unservable_mname(mname: str, stored: str) -> None:
    kw = _zone_kwargs_from_parsed(
        _parsed(mname),
        name="z.test.",
        target_group_id=uuid.uuid4(),
        target_view_id=None,
        source="bind9",  # type: ignore[arg-type]
        now=datetime.now(UTC),
    )
    assert kw["primary_ns"] == stored


# ── Through the API ─────────────────────────────────────────────────────────


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u2075-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group(db: AsyncSession) -> DNSServerGroup:
    grp = DNSServerGroup(name=f"g2075-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    return grp


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["ns_1.ns-underscore.test.", "a" * 64 + ".x.test.", "ns1"])
async def test_add_zone_refuses_and_stores_nothing(
    client: AsyncClient, db_session: AsyncSession, value: str
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones",
        json={"name": "ns-underscore.test", "primary_ns": value},
        headers=h,
    )
    assert r.status_code == 422, r.text
    assert "primary_ns" in r.text
    listed = await client.get(f"/api/v1/dns/groups/{grp.id}/zones", headers=h)
    assert listed.status_code == 200
    body = listed.json()
    items = body["items"] if isinstance(body, dict) else body
    assert not [z for z in items if z["name"].startswith("ns-underscore.test")]


@pytest.mark.asyncio
async def test_a_stored_bad_value_stays_editable_but_cannot_be_changed_to_another(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A zone stored before #2075 with a single-label Primary NS: the Edit
    dialog re-sends that value with every save, so an unrelated edit must go
    through. Changing it to another non-host name is still refused, and
    changing it to a host name repairs the zone."""
    h = await _headers(db_session)
    grp = await _group(db_session)
    zone = DNSZone(group_id=grp.id, name="legacy.test.", zone_type="primary", primary_ns="ns1")
    db_session.add(zone)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}"

    r = await client.put(url, json={"primary_ns": "ns1", "ttl": 600}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["ttl"] == 600
    assert r.json()["primary_ns"] == "ns1"

    r = await client.put(url, json={"primary_ns": "ns_1.legacy.test."}, headers=h)
    assert r.status_code == 422, r.text
    assert "Primary NS (primary_ns)" in r.text

    r = await client.put(url, json={"primary_ns": "ns1.legacy.test."}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["primary_ns"] == "ns1.legacy.test."
