"""Integration tests for the DHCP fingerprint ingestion endpoint.

Covers the upsert path + idempotent re-post + IPAddress stamping +
``user_modified_at`` lock semantics. Doesn't exercise the Celery
task dispatch (we patch it out) or the fingerbank HTTP client
(covered separately in test_fingerbank_service.py).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.dhcp_fingerprint import DHCPFingerprint
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dhcp.agent_token import hash_token, mint_agent_token


async def _make_dhcp_server(db: AsyncSession) -> tuple[DHCPServer, str]:
    g = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:8]}", description="")
    db.add(g)
    await db.flush()
    server = DHCPServer(
        name=f"s-{uuid.uuid4().hex[:8]}",
        host="127.0.0.1",
        port=67,
        driver="kea",
        roles=["primary"],
        status="active",
        server_group_id=g.id,
        agent_id=uuid.uuid4(),
        agent_registered=True,
        agent_approved=True,
        agent_fingerprint="fp",
    )
    db.add(server)
    await db.flush()
    token, _ = mint_agent_token(
        server_id=str(server.id),
        agent_id=str(server.agent_id),
        fingerprint="fp",
    )
    server.agent_token_hash = hash_token(token)
    await db.commit()
    return server, token


@pytest.mark.asyncio
async def test_dhcp_fingerprints_upsert_inserts_new_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, token = await _make_dhcp_server(db_session)

    # The endpoint lazy-imports the task; patch where it's defined.
    with patch("app.tasks.dhcp_fingerprint.lookup_fingerprint_task") as task_mock:
        resp = await client.post(
            "/api/v1/dhcp/agents/dhcp-fingerprints",
            json={
                "fingerprints": [
                    {
                        "mac_address": "aa:bb:cc:11:22:33",
                        "option_55": "1,3,6,15,31,33,43,44,46,47",
                        "option_60": "MSFT 5.0",
                        "option_77": None,
                        "client_id": "01aabbcc112233",
                    }
                ]
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["upserted"] == 1
        assert body["enqueued"] == 1
        # The reporting server rides along so the IP stamp stays in its spaces (#2577).
        task_mock.delay.assert_called_once_with("aa:bb:cc:11:22:33", str(server.id))

    res = await db_session.execute(select(DHCPFingerprint))
    rows = res.scalars().all()
    assert len(rows) == 1
    assert rows[0].option_55 == "1,3,6,15,31,33,43,44,46,47"
    assert rows[0].option_60 == "MSFT 5.0"
    assert rows[0].fingerbank_last_lookup_at is None  # task hasn't run


@pytest.mark.asyncio
async def test_dhcp_fingerprints_idempotent_repost_skips_enqueue(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_dhcp_server(db_session)

    payload = {
        "fingerprints": [
            {
                "mac_address": "aa:bb:cc:dd:ee:01",
                "option_55": "1,3,6,15",
                "option_60": "android-dhcp-13",
                "option_77": None,
                "client_id": None,
            }
        ]
    }

    with patch("app.tasks.dhcp_fingerprint.lookup_fingerprint_task") as task_mock:
        resp1 = await client.post(
            "/api/v1/dhcp/agents/dhcp-fingerprints",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp1.status_code == 200
        assert resp1.json()["enqueued"] == 1
        # Second post — same signature, should NOT re-enqueue.
        resp2 = await client.post(
            "/api/v1/dhcp/agents/dhcp-fingerprints",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp2.status_code == 200
        assert resp2.json()["enqueued"] == 0
        # Total dispatches: only the first.
        assert task_mock.delay.call_count == 1

    res = await db_session.execute(select(DHCPFingerprint))
    rows = res.scalars().all()
    assert len(rows) == 1
    assert rows[0].last_seen_at is not None


@pytest.mark.asyncio
async def test_dhcp_fingerprints_changed_signature_reenqueues(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_dhcp_server(db_session)

    base = {
        "mac_address": "aa:bb:cc:dd:ee:02",
        "option_55": "1,3,6,15",
        "option_60": "vendor-A",
        "option_77": None,
        "client_id": None,
    }
    changed = {**base, "option_60": "vendor-B"}

    with patch("app.tasks.dhcp_fingerprint.lookup_fingerprint_task") as task_mock:
        await client.post(
            "/api/v1/dhcp/agents/dhcp-fingerprints",
            json={"fingerprints": [base]},
            headers={"Authorization": f"Bearer {token}"},
        )
        await client.post(
            "/api/v1/dhcp/agents/dhcp-fingerprints",
            json={"fingerprints": [changed]},
            headers={"Authorization": f"Bearer {token}"},
        )
        # Both posts dispatched: signature changed.
        assert task_mock.delay.call_count == 2


@pytest.mark.asyncio
async def test_stamp_matching_ips_respects_user_modified_at(
    db_session: AsyncSession,
) -> None:
    """user_modified_at lock prevents stamping over operator edits."""
    from app.services.profiling.passive import stamp_matching_ips

    mac = "aa:bb:cc:dd:ee:03"
    # Two IPs with the same MAC — one locked, one not.
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="", is_default=True)
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.1.0.0/16", name="b")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.1.1.0/24", name="s")
    db_session.add(subnet)
    await db_session.flush()
    ip_open = IPAddress(subnet_id=subnet.id, address="10.1.1.10", mac_address=mac, status="dhcp")
    ip_locked = IPAddress(
        subnet_id=subnet.id,
        address="10.1.1.11",
        mac_address=mac,
        status="dhcp",
        user_modified_at=datetime.now(UTC),
    )
    db_session.add_all([ip_open, ip_locked])
    await db_session.commit()

    fp = DHCPFingerprint(
        mac_address=mac,
        option_55="1,3,6",
        option_60=None,
        fingerbank_device_name="Pixel 7",
        fingerbank_device_class="Phone",
        fingerbank_manufacturer="Google",
    )
    db_session.add(fp)
    await db_session.commit()

    stamped = await stamp_matching_ips(db_session, fingerprint=fp)
    await db_session.commit()
    assert stamped == 1

    await db_session.refresh(ip_open)
    await db_session.refresh(ip_locked)
    assert ip_open.device_type == "Pixel 7"
    assert ip_open.device_manufacturer == "Google"
    # Locked row stays untouched.
    assert ip_locked.device_type is None
    assert ip_locked.device_manufacturer is None
