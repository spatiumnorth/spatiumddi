"""An appliance's DNS agent registers into the appliance's group (#2190).

One roles save on a one-node appliance moved it from BIND9 in group A to
PowerDNS in group B. The save moved the appliance's BIND9 row into B for the
PowerDNS agent to adopt (#1856). But the supervisor labelled the node for
PowerDNS a few seconds before helm-controller rolled ``AGENT_GROUP=B`` into the
dns-powerdns DaemonSet, so the first PowerDNS pod registered with
``AGENT_GROUP=A``: a new row in A (its new agent id matched nothing, and A no
longer had a row with the hostname), which its cached token then kept. B's
zones answered REFUSED, and moving the live row to B was a 409 on the name.

Registration now puts an agent with no row yet that runs on an appliance (its
hostname is one approved appliance's, its driver that appliance's current
engine) in the appliance's ``assigned_dns_group_id``, whatever its env names.
A row found by agent id still never moves (#934).

The rows here are made by the real roles PUT and the real register endpoint.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import Appliance
from app.models.dns import DNSServer
from tests.test_dns_server_group_move import (
    _HOST_1715,
    _agent_register,
    _auth,
    _fleet_appliance,
    _group,
    _roles_url,
    _superadmin,
)

_CAPS = {"can_run_dns_bind9": True, "can_run_dns_powerdns": True}


async def _rows(db: AsyncSession) -> list[tuple[uuid.UUID, uuid.UUID, str, uuid.UUID | None]]:
    db.expire_all()
    rows = (await db.execute(select(DNSServer).order_by(DNSServer.created_at))).scalars().all()
    return [(r.id, r.group_id, r.driver, r.agent_id) for r in rows]


async def _bind9_in_a_then_save_powerdns_in_b(
    client: AsyncClient, db: AsyncSession, monkeypatch: pytest.MonkeyPatch, tag: str
):  # noqa: ANN202
    """The issue's steps 1-3: BIND9 registered in A, then ONE roles PUT to
    PowerDNS in B. Returns (appliance id, A id, B id, the BIND9 row id)."""
    monkeypatch.setenv("DNS_AGENT_KEY", "psk-1715")
    token = await _superadmin(db, f"root2190{tag}")
    group_a = await _group(db, f"grp2190{tag}-a")
    group_b = await _group(db, f"grp2190{tag}-b")
    await db.commit()
    row_id = await _agent_register(
        client, driver="bind9", group=group_a.name, agent_id=uuid.uuid4()
    )
    appliance = await _fleet_appliance(db, group_a, hostname=_HOST_1715, capabilities=_CAPS)
    await db.commit()
    a_id, b_id, app_id = group_a.id, group_b.id, appliance.id

    resp = await client.put(
        _roles_url(app_id),
        json={"roles": ["dns-powerdns"], "dns_group_id": str(b_id)},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text
    db.expire_all()
    app_row = await db.get(Appliance, app_id)
    assert app_row is not None and app_row.assigned_dns_group_id == b_id
    return app_id, a_id, b_id, uuid.UUID(row_id)


@pytest.mark.asyncio
async def test_powerdns_agent_with_the_stale_group_lands_in_the_appliances_group(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE REGRESSION. The first PowerDNS pod registers with the previous
    chart's ``AGENT_GROUP`` (A). It must adopt the appliance's row in B: one
    row, in B, driver powerdns, carried by the PowerDNS agent — and nothing,
    neither a new row nor a ghost of the BIND9 row, left in A."""
    _app, a_id, b_id, row_id = await _bind9_in_a_then_save_powerdns_in_b(
        client, db_session, monkeypatch, "a"
    )
    pdns_agent = uuid.uuid4()

    sid = await _agent_register(client, driver="powerdns", group="grp2190a-a", agent_id=pdns_agent)

    assert sid == str(row_id)
    assert await _rows(db_session) == [(row_id, b_id, "powerdns", pdns_agent)]
    assert a_id not in {g for _id, g, _d, _a in await _rows(db_session)}


@pytest.mark.asyncio
async def test_the_pod_that_rolls_after_registers_into_the_same_row(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The issue's timeline continued: the revision-2 pod (``AGENT_GROUP=B``,
    same per-engine state dir, so the same agent id) re-registers after a
    401/404. Found by its id: the same row, no second one."""
    _app, _a_id, b_id, row_id = await _bind9_in_a_then_save_powerdns_in_b(
        client, db_session, monkeypatch, "b"
    )
    pdns_agent = uuid.uuid4()
    await _agent_register(client, driver="powerdns", group="grp2190b-a", agent_id=pdns_agent)

    sid = await _agent_register(client, driver="powerdns", group="grp2190b-b", agent_id=pdns_agent)

    assert sid == str(row_id)
    assert await _rows(db_session) == [(row_id, b_id, "powerdns", pdns_agent)]


@pytest.mark.asyncio
async def test_a_row_found_by_agent_id_is_never_dragged_by_the_appliance(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#934 stays: registration does not move a row it finds by agent id,
    whether the env or the appliance names another group."""
    monkeypatch.setenv("DNS_AGENT_KEY", "psk-1715")
    group_a = await _group(db_session, "grp2190c-a")
    group_b = await _group(db_session, "grp2190c-b")
    await db_session.commit()
    agent = uuid.uuid4()
    row_id = await _agent_register(client, driver="bind9", group="grp2190c-a", agent_id=agent)
    await _fleet_appliance(db_session, group_b, hostname=_HOST_1715, capabilities=_CAPS)
    await db_session.commit()
    a_id = group_a.id

    sid = await _agent_register(client, driver="bind9", group="grp2190c-b", agent_id=agent)

    assert sid == row_id
    assert await _rows(db_session) == [(uuid.UUID(row_id), a_id, "bind9", agent)]


@pytest.mark.asyncio
async def test_an_agent_on_no_appliance_still_registers_where_its_env_says(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Off an appliance (a compose agent, a host no approved appliance has, an
    engine the appliance does not run), ``AGENT_GROUP`` decides as before."""
    monkeypatch.setenv("DNS_AGENT_KEY", "psk-1715")
    group_a = await _group(db_session, "grp2190d-a")
    group_b = await _group(db_session, "grp2190d-b")
    await _fleet_appliance(db_session, group_b, hostname=_HOST_1715, capabilities=_CAPS)
    await db_session.commit()
    a_id = group_a.id

    # Another host.
    other = await _agent_register(
        client, driver="bind9", group="grp2190d-a", agent_id=uuid.uuid4(), host="compose-ns1"
    )
    # The appliance's host, but an engine it does not run (it runs bind9).
    off_engine = await _agent_register(
        client, driver="powerdns", group="grp2190d-a", agent_id=uuid.uuid4()
    )

    groups = {sid: g for sid, g, _d, _a in await _rows(db_session)}
    assert groups[uuid.UUID(other)] == a_id
    assert groups[uuid.UUID(off_engine)] == a_id


@pytest.mark.asyncio
async def test_a_hostname_two_approved_appliances_share_claims_nothing(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The hostname is only a claim when it is one appliance's (#1749's rule)."""
    monkeypatch.setenv("DNS_AGENT_KEY", "psk-1715")
    group_a = await _group(db_session, "grp2190e-a")
    group_b = await _group(db_session, "grp2190e-b")
    await _fleet_appliance(db_session, group_b, hostname=_HOST_1715, capabilities=_CAPS)
    await _fleet_appliance(db_session, group_b, hostname=_HOST_1715.upper(), capabilities=_CAPS)
    await db_session.commit()
    a_id = group_a.id

    sid = await _agent_register(client, driver="bind9", group="grp2190e-a", agent_id=uuid.uuid4())

    assert {g for _id, g, _d, _a in await _rows(db_session) if _id == uuid.UUID(sid)} == {a_id}
