"""#811 — creating (or flag-flipping) a DNSSEC zone must actually sign it.

``dnssec_enabled=true`` used to set the flag and stop there. On BIND9 that is
enough — it signs inline from the rendered config bundle — but PowerDNS and
Technitium (until #1783) sign only in response to the ``dnssec_sign`` record op, which
neither the REST ``create_zone`` nor the Copilot's ``create_dns_zone``
enqueued. The zone read as DNSSEC-enabled in the UI, in ``GET /zones/{id}``
and in the audit row, and was unsigned on the wire until someone clicked
Sign. Second-order hole: because create never called the driver gate, the
flag was accepted on a ``windows_dns`` group, where nothing will ever sign it
and the sign/unsign endpoints both 422.

These tests pin the fix at every flag-flipping surface:

* REST create enqueues ``dnssec_sign`` (on every driver in the gate set —
  BIND9 ignores the op, so enqueueing uniformly is safe) and refuses the
  flag on a group that could never honour it
* REST update (the generic ``ZoneUpdate`` path) enqueues sign/unsign on a
  flip, mirrors the unsign endpoint's DS/key cleanup, is idempotent on a
  no-change write, and gates like create
* the Copilot's apply enqueues the same op and re-runs the gate at apply
  time (servers can join the group between proposal and approval)
* an empty group still fails soft at create (nobody to disagree yet); the
  op is dropped for lack of a primary and signing starts from a manual
  Sign once servers join
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.router import _DRIVER_GATED_OPERATIONS
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSKey, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services.ai.operations import CreateDNSZoneArgs, get_operation

_SIGNING_DRIVERS = sorted(_DRIVER_GATED_OPERATIONS["dnssec_sign"])

# ── helpers ─────────────────────────────────────────────────────────────────


async def _admin(db: AsyncSession) -> User:
    user = User(
        username=f"dnssec-create-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="DNSSEC Create Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(user)
    await db.flush()
    return user


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = await _admin(db)
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group(db: AsyncSession, driver: str | None) -> DNSServerGroup:
    """A group with one enabled primary server on ``driver`` (None = empty)."""
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
        await db.flush()
    return grp


async def _dnssec_ops(db: AsyncSession, zone_name: str) -> list[DNSRecordOp]:
    # DNSRecordOp keys the zone by NAME (it has no zone_id column).
    res = await db.execute(
        select(DNSRecordOp).where(
            DNSRecordOp.zone_name == zone_name,
            DNSRecordOp.op.in_(["dnssec_sign", "dnssec_unsign"]),
        )
    )
    return list(res.scalars().all())


def _zone_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "name": f"z{uuid.uuid4().hex[:6]}.example.",
        "zone_type": "primary",
        "kind": "forward",
        "primary_ns": "ns1.example.",
        "admin_email": "admin.example.",
    }
    body.update(overrides)
    return body


# ── REST create ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", _SIGNING_DRIVERS)
async def test_create_with_dnssec_enqueues_sign_op(
    client: AsyncClient, db_session: AsyncSession, driver: str
) -> None:
    """The core #811 fix: create enqueues what the Sign button enqueues."""
    headers = await _headers(db_session)
    grp = await _group(db_session, driver)

    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones",
        json=_zone_body(dnssec_enabled=True),
        headers=headers,
    )
    assert resp.status_code == 201, resp.text

    ops = await _dnssec_ops(db_session, resp.json()["name"])
    assert [o.op for o in ops] == ["dnssec_sign"], (
        f"driver {driver!r}: expected exactly one dnssec_sign op at create, "
        f"got {[o.op for o in ops]}"
    )


@pytest.mark.asyncio
async def test_create_with_dnssec_refused_on_non_signing_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The second-order hole: the flag was accepted on windows_dns, where
    nothing will ever sign it and the sign/unsign endpoints both 422."""
    headers = await _headers(db_session)
    grp = await _group(db_session, "windows_dns")

    body = _zone_body(dnssec_enabled=True)
    resp = await client.post(f"/api/v1/dns/groups/{grp.id}/zones", json=body, headers=headers)
    assert resp.status_code == 422, resp.text
    assert "dnssec_sign" in resp.json()["detail"]

    # No orphan row either.
    res = await db_session.execute(select(DNSZone).where(DNSZone.name == body["name"]))
    assert res.scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_create_with_dnssec_fails_soft_on_empty_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """No servers yet: the gate passes (nobody to disagree) and the enqueue
    drops for lack of a primary — flag lands, signing starts from a manual
    Sign once servers join. Same fail-soft the sign endpoint has."""
    headers = await _headers(db_session)
    grp = await _group(db_session, None)

    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones",
        json=_zone_body(dnssec_enabled=True),
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["dnssec_enabled"] is True
    assert await _dnssec_ops(db_session, resp.json()["name"]) == []


@pytest.mark.asyncio
async def test_create_without_dnssec_enqueues_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    grp = await _group(db_session, "powerdns")

    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones", json=_zone_body(), headers=headers
    )
    assert resp.status_code == 201, resp.text
    assert await _dnssec_ops(db_session, resp.json()["name"]) == []


# ── REST update (the generic flag-flip path) ────────────────────────────────


async def _zone_via_api(
    client: AsyncClient,
    db: AsyncSession,
    headers: dict[str, str],
    grp: DNSServerGroup,
    *,
    dnssec: bool,
) -> tuple[uuid.UUID, str]:
    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones",
        json=_zone_body(dnssec_enabled=dnssec),
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return uuid.UUID(resp.json()["id"]), resp.json()["name"]


@pytest.mark.asyncio
async def test_update_flip_on_enqueues_sign(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _headers(db_session)
    grp = await _group(db_session, "powerdns")
    zone_id, zone_name = await _zone_via_api(client, db_session, headers, grp, dnssec=False)

    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone_id}",
        json={"dnssec_enabled": True},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["dnssec_enabled"] is True
    assert [o.op for o in await _dnssec_ops(db_session, zone_name)] == ["dnssec_sign"]


@pytest.mark.asyncio
async def test_update_flip_off_enqueues_unsign_and_clears_key_state(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Mirrors the unsign endpoint: DS cache cleared, DNSKey rows deleted —
    the BIND9 agent only reports signed zones, so nothing else clears them."""
    headers = await _headers(db_session)
    grp = await _group(db_session, "powerdns")
    zone_id, zone_name = await _zone_via_api(client, db_session, headers, grp, dnssec=True)

    zone = await db_session.get(DNSZone, zone_id)
    assert zone is not None
    zone.dnssec_ds_records = ["12345 13 2 ab"]
    db_session.add(DNSKey(zone_id=zone_id, key_tag=12345, key_type="csk"))
    await db_session.commit()

    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone_id}",
        json={"dnssec_enabled": False},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["dnssec_enabled"] is False

    ops = sorted(o.op for o in await _dnssec_ops(db_session, zone_name))
    assert ops == ["dnssec_sign", "dnssec_unsign"]  # sign from create, unsign now

    await db_session.refresh(zone)
    assert zone.dnssec_ds_records is None
    keys = await db_session.execute(select(DNSKey).where(DNSKey.zone_id == zone_id))
    assert keys.scalars().all() == []


@pytest.mark.asyncio
async def test_update_without_flip_enqueues_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Writing the current value back is not a flip — no duplicate ops."""
    headers = await _headers(db_session)
    grp = await _group(db_session, "powerdns")
    zone_id, zone_name = await _zone_via_api(client, db_session, headers, grp, dnssec=True)

    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone_id}",
        json={"dnssec_enabled": True, "ttl": 7200},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    # Only the one op from create — the no-change write added nothing.
    assert [o.op for o in await _dnssec_ops(db_session, zone_name)] == ["dnssec_sign"]


@pytest.mark.asyncio
async def test_update_flip_off_ungated_on_non_signing_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Clearing the flag must work on ANY group (#811 review).

    The pre-#811 bug population is zones whose dnssec_enabled=true was
    accepted on e.g. a windows_dns group. Sign 422s there; if flip-off were
    gated the same way, those zones would be permanently stuck lying. So
    flip-off is ungated — flag cleared, key state cleared, and no unsign op
    queued (nothing was ever signed, and the agentless immediate-apply
    couldn't process the DNSSEC_OP sentinel)."""
    headers = await _headers(db_session)
    grp = await _group(db_session, "windows_dns")
    zone_id, zone_name = await _zone_via_api(client, db_session, headers, grp, dnssec=False)

    # Recreate the legacy state directly — the (fixed) create path refuses it.
    zone = await db_session.get(DNSZone, zone_id)
    assert zone is not None
    zone.dnssec_enabled = True
    zone.dnssec_ds_records = ["12345 13 2 ab"]
    await db_session.commit()

    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone_id}",
        json={"dnssec_enabled": False},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["dnssec_enabled"] is False
    await db_session.refresh(zone)
    assert zone.dnssec_ds_records is None
    assert await _dnssec_ops(db_session, zone_name) == []


@pytest.mark.asyncio
async def test_unsign_endpoint_ungated_on_non_signing_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The dedicated unsign endpoint clears the flag on any group too —
    same _flip_dnssec_off path as the update flip."""
    headers = await _headers(db_session)
    grp = await _group(db_session, "windows_dns")
    zone_id, zone_name = await _zone_via_api(client, db_session, headers, grp, dnssec=False)
    zone = await db_session.get(DNSZone, zone_id)
    assert zone is not None
    zone.dnssec_enabled = True
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone_id}/dnssec/unsign",
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["dnssec_enabled"] is False
    assert await _dnssec_ops(db_session, zone_name) == []


@pytest.mark.asyncio
async def test_update_flip_gated_like_create(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _headers(db_session)
    grp = await _group(db_session, "windows_dns")
    zone_id, _ = await _zone_via_api(client, db_session, headers, grp, dnssec=False)

    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone_id}",
        json={"dnssec_enabled": True},
        headers=headers,
    )
    assert resp.status_code == 422, resp.text
    zone = await db_session.get(DNSZone, zone_id)
    assert zone is not None and zone.dnssec_enabled is False


# ── Copilot apply (lockstep with REST — #798) ───────────────────────────────


@pytest.mark.asyncio
async def test_copilot_apply_enqueues_sign_op(db_session: AsyncSession) -> None:
    user = await _admin(db_session)
    grp = await _group(db_session, "powerdns")
    op = get_operation("create_dns_zone")
    assert op is not None

    result = await op.apply(
        db_session,
        user,
        CreateDNSZoneArgs(
            name=f"z{uuid.uuid4().hex[:6]}.example.com",
            group_id=str(grp.id),
            dnssec_enabled=True,
        ),
    )
    ops = await _dnssec_ops(db_session, result["name"])
    assert [o.op for o in ops] == ["dnssec_sign"]


@pytest.mark.asyncio
async def test_copilot_apply_enforces_driver_gate(db_session: AsyncSession) -> None:
    """Apply runs the driver gate itself (not only preview) — the rationale
    (servers can join a group between proposal and approval) lives on
    _gated_zone_arg_conflict's docstring."""
    user = await _admin(db_session)
    grp = await _group(db_session, "windows_dns")
    op = get_operation("create_dns_zone")
    assert op is not None

    args = CreateDNSZoneArgs(
        name=f"z{uuid.uuid4().hex[:6]}.example.com",
        group_id=str(grp.id),
        dnssec_enabled=True,
    )
    with pytest.raises(ValueError, match="windows_dns"):
        await op.apply(db_session, user, args)
