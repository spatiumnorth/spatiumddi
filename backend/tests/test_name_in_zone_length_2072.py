"""A hostname plus its zone must fit a DNS name (#2072).

``validate_hostname`` caps the hostname alone at 253, but IPAM publishes
``<hostname>.<zone>``: four 60-character labels (243) in a 33-character zone
answered 201, and BIND refused the forward zone and the reverse zone holding
the PTR ("ran out of space"). The rule is the wire limit: 255 octets, i.e.
253 characters of dotted presentation name, each label at most 63.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ipam.router import _sync_dns_record
from app.core.dns_names import bind_check_names_error, name_in_zone_error, name_length_error
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

ZONE = "example-zone.test"  # 17 characters
LONG_HOST = ".".join("abcd"[i] * 60 for i in range(4))  # 243 characters, valid alone


def test_the_limit_is_253_characters_and_63_per_label() -> None:
    fits = ".".join(["a" * 61, "b" * 63, "c" * 63, "d" * 63])
    assert len(fits) == 253
    assert name_length_error(fits) is None
    assert name_length_error(fits + ".") is None  # root dot ignored
    assert "label" in (name_length_error("a" * 64 + ".test") or "")
    assert "255 characters" in (name_length_error(fits + ".e") or "")


def test_a_valid_hostname_in_a_long_zone_is_refused_naming_the_field() -> None:
    assert len(LONG_HOST) == 243
    err = name_in_zone_error(LONG_HOST, ZONE)
    assert err is not None
    assert err.startswith("hostname:")
    assert str(243 + 1 + len(ZONE)) in err
    assert name_in_zone_error("web01", ZONE) is None
    # a trailing root dot on the zone changes nothing
    assert name_in_zone_error("web01", ZONE + ".") is None
    assert name_in_zone_error(LONG_HOST, ZONE + ".") is not None


def test_the_record_check_covers_owner_and_target_lengths() -> None:
    owner = f"{LONG_HOST}.{ZONE}."
    assert bind_check_names_error("TXT", owner, "x", origin=ZONE + ".") is not None
    short = f"w.{ZONE}."
    assert bind_check_names_error("CNAME", short, LONG_HOST, origin=ZONE + ".") is not None
    assert bind_check_names_error("CNAME", short, "web01", origin=ZONE + ".") is None


async def _setup(db: AsyncSession, zone_name: str = ZONE) -> tuple[Subnet, DNSZone]:
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
        name=zone_name + ".",
        zone_type="primary",
        kind="forward",
        primary_ns=f"ns1.{zone_name}.",
        admin_email=f"admin.{zone_name}.",
    )
    db.add(zone)
    await db.flush()
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.82.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.82.1.0/24",
        name="s",
        dns_zone_id=str(zone.id),
        dns_inherit_settings=False,
    )
    db.add(subnet)
    await db.flush()
    return subnet, zone


async def _record_count(db: AsyncSession, zone: DNSZone) -> int:
    return (
        await db.execute(
            select(func.count()).select_from(DNSRecord).where(DNSRecord.zone_id == zone.id)
        )
    ).scalar_one()


@pytest.mark.asyncio
async def test_sync_strict_refuses_and_writes_nothing(db_session: AsyncSession) -> None:
    subnet, zone = await _setup(db_session)
    ip = IPAddress(
        subnet_id=subnet.id, address="10.82.1.10", status="allocated", hostname=LONG_HOST
    )
    db_session.add(ip)
    await db_session.flush()
    with pytest.raises(HTTPException) as exc:
        await _sync_dns_record(db_session, ip, subnet, action="create", strict=True)
    assert exc.value.status_code == 422
    assert "hostname" in exc.value.detail
    assert await _record_count(db_session, zone) == 0


@pytest.mark.asyncio
async def test_sync_non_strict_skips_the_name_and_its_ptr(db_session: AsyncSession) -> None:
    """DDNS / importers: no exception, no A, no PTR, no fqdn."""
    subnet, zone = await _setup(db_session)
    ip = IPAddress(
        subnet_id=subnet.id, address="10.82.1.11", status="allocated", hostname=LONG_HOST
    )
    db_session.add(ip)
    await db_session.flush()
    assert await _sync_dns_record(db_session, ip, subnet, action="create") is False
    assert await _record_count(db_session, zone) == 0
    assert not ip.fqdn


@pytest.mark.asyncio
async def test_a_hostname_that_fits_still_publishes(db_session: AsyncSession) -> None:
    subnet, zone = await _setup(db_session)
    ip = IPAddress(subnet_id=subnet.id, address="10.82.1.12", status="allocated", hostname="web01")
    db_session.add(ip)
    await db_session.flush()
    await _sync_dns_record(db_session, ip, subnet, action="create", strict=True)
    assert ip.fqdn == f"web01.{ZONE}"
    assert await _record_count(db_session, zone) >= 1


@pytest.mark.asyncio
async def test_allocate_ip_api_answers_422_and_stores_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    subnet, zone = await _setup(db_session)
    subnet_id, zone_id = subnet.id, zone.id
    user = User(
        username=f"n-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="n",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db_session.add(user)
    await db_session.flush()
    await db_session.commit()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    resp = await client.post(
        f"/api/v1/ipam/subnets/{subnet_id}/addresses",
        json={"address": "10.82.1.20", "hostname": LONG_HOST, "status": "allocated"},
        headers=headers,
    )
    assert resp.status_code == 422, resp.text
    assert "hostname" in str(resp.json()["detail"])
    # Production's request-scoped session closes uncommitted on the 422; the
    # test client shares one session, so end that transaction the same way.
    await db_session.rollback()
    stored = (
        await db_session.execute(
            select(func.count()).select_from(IPAddress).where(IPAddress.address == "10.82.1.20")
        )
    ).scalar_one()
    assert stored == 0
    count = (
        await db_session.execute(
            select(func.count()).select_from(DNSRecord).where(DNSRecord.zone_id == zone_id)
        )
    ).scalar_one()
    assert count == 0


# ── Validation pass ──────────────────────────────────────────────────────────


def test_the_boundary_sits_between_253_and_254() -> None:
    """Same vectors as ``nameInZoneError`` in ``frontend/src/lib/dnsNames.test.ts``."""
    zone = "z" * 60 + ".test"  # 65
    fits = ".".join(["h" * 63, "i" * 63, "j" * 59])  # 187
    assert len(f"{fits}.{zone}") == 253
    assert name_in_zone_error(fits, zone) is None
    assert name_in_zone_error(fits, zone + ".") is None
    assert name_in_zone_error(fits + ".", zone + "..") is None
    assert "254" in (name_in_zone_error(fits + "j", zone) or "")


def test_owner_length_is_measured_once_when_the_zone_has_no_root_dot() -> None:
    """Synthesised / imported zones may be stored without their root dot. The
    owner passed in already carries the zone, so it must not be counted twice:
    a 253-character owner fits, whichever way the zone is spelled."""
    zone = "z" * 60 + ".test"
    owner = ".".join(["h" * 63, "i" * 63, "j" * 59]) + "." + zone
    assert len(owner) == 253
    for origin in (zone, zone + "."):
        assert bind_check_names_error("A", owner, "10.0.0.1", origin=origin) is None
        assert bind_check_names_error("A", owner + ".", "10.0.0.1", origin=origin) is None
        assert bind_check_names_error("A", "x" + owner, "10.0.0.1", origin=origin) is not None


def test_target_rules_leave_valid_records_alone() -> None:
    """Null MX (RFC 7505) / null SRV (RFC 2782) targets, ``@``, and short
    relative targets pass; a relative target is measured inside the zone."""
    origin = ZONE + "."
    owner = f"w.{ZONE}."
    assert bind_check_names_error("MX", owner, "0 .", origin=origin) is None
    assert bind_check_names_error("MX", owner, ".", origin=origin) is None
    assert bind_check_names_error("SRV", f"_sip._tcp.{ZONE}.", "0 0 0 .", origin=origin) is None
    assert bind_check_names_error("CNAME", owner, "@", origin=origin) is None
    assert bind_check_names_error("NS", f"{ZONE}.", "ns1", origin=origin) is None
    # 243 + zone fits nowhere relative; the same name made absolute fits.
    assert bind_check_names_error("CNAME", owner, LONG_HOST, origin=origin) is not None
    assert bind_check_names_error("CNAME", owner, LONG_HOST + ".", origin=origin) is None
    # A PTR target too: the reverse zone refused the issue's PTR.
    rev = "1.82.10.in-addr.arpa."
    assert (
        bind_check_names_error("PTR", f"20.{rev}", f"{LONG_HOST}.{ZONE}.", origin=rev) is not None
    )


@pytest.mark.asyncio
async def test_non_strict_rename_to_a_long_name_retracts_what_was_published(
    db_session: AsyncSession,
) -> None:
    """DDNS renaming a published host to a name that cannot be published must
    not leave the old A / PTR naming a host the row no longer carries."""
    subnet, zone = await _setup(db_session)
    ip = IPAddress(subnet_id=subnet.id, address="10.82.1.30", status="allocated", hostname="web01")
    db_session.add(ip)
    await db_session.flush()
    assert await _sync_dns_record(db_session, ip, subnet, action="create") is True
    assert await _record_count(db_session, zone) == 1

    ip.hostname = LONG_HOST
    assert await _sync_dns_record(db_session, ip, subnet, action="update") is False
    await db_session.flush()
    left = (
        await db_session.execute(
            select(func.count())
            .select_from(DNSRecord)
            .where(DNSRecord.ip_address_id == ip.id, DNSRecord.auto_generated.is_(True))
        )
    ).scalar_one()
    assert left == 0
    assert ip.fqdn is None
    assert ip.dns_record_id is None
    assert getattr(ip, "_dns_skipped_too_long", False) is True


async def _superadmin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"n-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="n",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _committed_count(model: type, *where: object) -> int:
    """Count rows from a FRESH session: only what was committed is visible,
    so a 422 that committed part of its work shows up here."""
    from tests.conftest import _TestSessionLocal  # noqa: PLC0415

    async with _TestSessionLocal() as fresh:
        stmt = select(func.count()).select_from(model).where(*where)  # type: ignore[arg-type]
        return int((await fresh.execute(stmt)).scalar_one())


@pytest.mark.asyncio
async def test_create_and_next_answer_422_and_commit_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    subnet, zone = await _setup(db_session)
    subnet_id, zone_id = subnet.id, zone.id
    headers = await _superadmin_headers(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/ipam/subnets/{subnet_id}/addresses",
        json={"address": "10.82.1.40", "hostname": LONG_HOST, "status": "allocated"},
        headers=headers,
    )
    assert resp.status_code == 422, resp.text
    resp = await client.post(
        f"/api/v1/ipam/subnets/{subnet_id}/next",
        json={"hostname": LONG_HOST},
        headers=headers,
    )
    assert resp.status_code == 422, resp.text
    assert "hostname" in str(resp.json()["detail"])

    # No rollback first: a fresh session sees only committed rows.
    assert await _committed_count(IPAddress, IPAddress.subnet_id == subnet_id) == 0
    assert await _committed_count(DNSRecord, DNSRecord.zone_id == zone_id) == 0
    await db_session.rollback()


@pytest.mark.asyncio
async def test_edit_ip_answers_422_and_keeps_the_published_name(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    subnet, zone = await _setup(db_session)
    subnet_id = subnet.id
    headers = await _superadmin_headers(db_session)
    await db_session.commit()
    resp = await client.post(
        f"/api/v1/ipam/subnets/{subnet_id}/addresses",
        json={"address": "10.82.1.41", "hostname": "web01", "status": "allocated"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    ip_id = resp.json()["id"]

    resp = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", json={"hostname": LONG_HOST}, headers=headers
    )
    assert resp.status_code == 422, resp.text
    await db_session.rollback()
    assert (
        await _committed_count(
            IPAddress, IPAddress.id == uuid.UUID(ip_id), IPAddress.hostname == "web01"
        )
        == 1
    )


@pytest.mark.asyncio
async def test_sync_dns_reports_the_long_name_as_an_error(db_session: AsyncSession) -> None:
    """The subnet's Sync DNS must not count a name it could not publish."""
    from app.api.v1.ipam.router import DnsSyncCommitRequest, _apply_dns_sync  # noqa: PLC0415

    subnet, zone = await _setup(db_session)
    ip = IPAddress(
        subnet_id=subnet.id, address="10.82.1.50", status="allocated", hostname=LONG_HOST
    )
    db_session.add(ip)
    await db_session.flush()
    created, _updated, _deleted, errors = await _apply_dns_sync(
        db_session, DnsSyncCommitRequest(create_for_ip_ids=[ip.id])
    )
    assert created == 0
    assert len(errors) == 1 and "hostname" in errors[0] and "10.82.1.50" in errors[0]
    assert await _record_count(db_session, zone) == 0
