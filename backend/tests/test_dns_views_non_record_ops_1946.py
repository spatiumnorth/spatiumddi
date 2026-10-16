"""A views render must not retire an op its bundle cannot carry (#1946).

Under split-horizon the render folds record changes into the zone payload and
retires their ops. A ``dnssec_rollover`` (and PowerDNS / Technitium
``dnssec_sign`` / ``dnssec_unsign``) has no carrier in the body: the agent acts
only from the op. It used to be retired as ``applied`` with ``attempts`` 0 and
never shipped, while the endpoint answered ``queued``.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecordOp
from app.services.dns import agent_bundle_store as store
from app.services.dns.agent_bundle_render import render_and_store
from tests.test_dns_agent_bundle_ops_gate import CONFIG_URL, _agent, _op


def _rollover(server_id: uuid.UUID, zone_name: str) -> DNSRecordOp:
    return DNSRecordOp(
        server_id=server_id,
        zone_name=zone_name,
        op="dnssec_rollover",
        record={"name": "@", "type": "DNSSEC_OP", "key_tag": 11437},
        state="pending",
    )


async def _state(db: AsyncSession, op_id: uuid.UUID) -> str:
    db.expire_all()
    return (await db.execute(select(DNSRecordOp.state).where(DNSRecordOp.id == op_id))).scalar_one()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["dnssec_rollover", "dnssec_sign", "dnssec_unsign"])
async def test_views_render_ships_dnssec_ops_and_retires_only_record_ops(
    client: AsyncClient, db_session: AsyncSession, kind: str
) -> None:
    server, zone, headers = await _agent(db_session, views=True)
    dnssec = _rollover(server.id, zone.name)
    dnssec.op = kind
    record_op = _op(server.id, zone, "h1")
    db_session.add_all([dnssec, record_op])
    await db_session.commit()
    dnssec_id, record_id, server_id = dnssec.id, record_op.id, server.id

    outcome = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    assert outcome.bundle is not None and outcome.bundle.ships_ops is False

    # The record op is folded into the body and retired; the DNSSEC op is not.
    assert await _state(db_session, record_id) == "applied"
    assert await _state(db_session, dnssec_id) == "pending"

    resp = await client.get(CONFIG_URL, headers=headers)
    assert resp.status_code == 200, resp.text
    shipped = resp.json()["pending_record_ops"]
    assert [o["op"] for o in shipped] == [kind], shipped
    assert shipped[0]["record"]["key_tag"] == 11437
    # Handed to the agent, not applied until it acks.
    assert await _state(db_session, dnssec_id) == "in_flight"

    # Agent acks on its heartbeat path; once applied it never ships again.
    ack = await client.post(
        f"/api/v1/dns/agents/ops/{dnssec_id}/ack",
        headers=headers,
        json={"result": "ok"},
    )
    assert ack.status_code == 200, ack.text
    assert await _state(db_session, dnssec_id) == "applied"
    again = await client.get(CONFIG_URL, headers=headers)
    assert again.status_code in (200, 304)
    if again.status_code == 200:
        assert again.json()["pending_record_ops"] == []
    assert server_id
