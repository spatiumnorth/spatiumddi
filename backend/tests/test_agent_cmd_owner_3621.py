"""#3621 — a command-channel result is accepted only from the appliance the
command was queued for.

``agent_cmd.deliver_result`` used to match on the request id alone, so any
approved appliance holding a valid supervisor cert could answer another
appliance's nettool / storage command. The pcap channel is DB-backed and
already binds the capture to its appliance; it is pinned here too.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.pcap import PacketCapture
from app.services.appliance import agent_cmd, cert_auth

CHANNELS = [
    (agent_cmd.CHANNEL_NETTOOL, "/api/v1/appliance/supervisor/nettool/reply/"),
    (agent_cmd.CHANNEL_STORAGE, "/api/v1/appliance/supervisor/storage/reply/"),
]


async def _appliance(db: AsyncSession) -> Appliance:
    der = os.urandom(32)
    row = Appliance(
        id=uuid.uuid4(),
        hostname=f"own-{uuid.uuid4().hex[:8]}",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
    )
    db.add(row)
    await db.commit()
    return row


def _auth_as(monkeypatch: pytest.MonkeyPatch, row: Appliance) -> None:
    """Make the cert gate authenticate as ``row`` (the real gate, patched below it)."""

    async def _authenticate(_request: Any, _db: Any, **_kw: Any) -> Any:
        return SimpleNamespace(appliance=row, content_sha256=None)

    monkeypatch.setattr(cert_auth, "authenticate_cert", _authenticate)


@pytest.mark.asyncio
@pytest.mark.parametrize(("channel", "url"), CHANNELS)
async def test_reply_route_refuses_another_appliance_and_accepts_the_owner(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    channel: str,
    url: str,
) -> None:
    target = await _appliance(db_session)
    other = await _appliance(db_session)

    call = asyncio.create_task(
        agent_cmd.enqueue_command(
            target.id, "ping", {"host": "1.1.1.1"}, timeout=5.0, channel=channel
        )
    )
    queued = await agent_cmd.pop_command(target.id, timeout=2.0, channel=channel)
    assert queued is not None
    body = {"request_id": queued.request_id, "result": {"ok": True}}

    _auth_as(monkeypatch, other)
    resp = await client.post(f"{url}{queued.request_id}", json=body)
    assert resp.status_code == 200, resp.text
    assert resp.json()["delivered"] == "stale"
    await asyncio.sleep(0.05)
    assert not call.done(), "another appliance's result resolved the operator's call"

    _auth_as(monkeypatch, target)
    resp = await client.post(f"{url}{queued.request_id}", json=body)
    assert resp.json()["delivered"] == "true"
    outcome = await asyncio.wait_for(call, timeout=2.0)
    assert outcome.result == {"ok": True}


@pytest.mark.asyncio
@pytest.mark.parametrize(("channel", "_url"), CHANNELS)
async def test_owner_records_are_evicted_on_delivery_and_on_timeout(
    channel: str, _url: str
) -> None:
    target = uuid.uuid4()
    dispatch = agent_cmd._queues(channel)
    assert dispatch.owners == {}

    call = asyncio.create_task(
        agent_cmd.enqueue_command(target, "ping", {}, timeout=5.0, channel=channel)
    )
    queued = await agent_cmd.pop_command(target, timeout=2.0, channel=channel)
    assert queued is not None
    assert dispatch.owners == {queued.request_id: target}
    assert agent_cmd.deliver_result(
        agent_cmd.NetToolResult(request_id=queued.request_id, result={}),
        appliance_id=target,
        channel=channel,
    )
    await call
    assert dispatch.owners == {}

    with pytest.raises(TimeoutError):
        await agent_cmd.enqueue_command(target, "ping", {}, timeout=0.1, channel=channel)
    assert dispatch.owners == {}


async def _capture(db: AsyncSession, appliance_id: uuid.UUID) -> PacketCapture:
    cap = PacketCapture(
        vantage_kind="appliance",
        appliance_id=appliance_id,
        vantage_label="appl",
        interface="eth0",
        bpf_filter="port 53",
        snaplen=256,
        max_duration_s=30,
        status="running",
    )
    db.add(cap)
    await db.commit()
    return cap


@pytest.mark.asyncio
async def test_pcap_progress_and_upload_refuse_another_appliance(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = await _appliance(db_session)
    other = await _appliance(db_session)
    cap = await _capture(db_session, target.id)

    _auth_as(monkeypatch, other)
    r = await client.post(
        f"/api/v1/appliance/supervisor/pcap/progress/{cap.id}", json={"packets": 1}
    )
    assert r.status_code == 404, r.text
    r = await client.post(
        f"/api/v1/appliance/supervisor/pcap/upload/{cap.id}", params={"error": "x"}
    )
    assert r.status_code == 404, r.text

    await db_session.refresh(cap)
    assert cap.status == "running"

    _auth_as(monkeypatch, target)
    r = await client.post(
        f"/api/v1/appliance/supervisor/pcap/progress/{cap.id}", json={"packets": 1}
    )
    assert r.status_code == 200, r.text
