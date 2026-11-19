"""Heartbeat persists fleet-firewall prerequisites (issue #285 Phase 1).

The supervisor reports pod/service CIDR, the data-plane backend, all
InternalIPs, and the base-conf marker so the (future) server-side
firewall compiler can scope k3s rules before the LAN-wide base accept is
removed. The handler persists them "only when not None" so a legacy
supervisor never blanks them. Purely additive telemetry — nothing here
renders or applies a firewall.
"""

from __future__ import annotations

import hashlib
import os
import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.settings import PlatformSettings
from app.services.appliance.ca import generate_session_token


async def _approved_supervisor(db: AsyncSession) -> tuple[Appliance, str]:
    s = await db.get(PlatformSettings, 1)
    if s is None:
        s = PlatformSettings(id=1)
        db.add(s)
    s.supervisor_registration_enabled = True  # only register needs it since #2798
    token, token_hash = generate_session_token()
    der = os.urandom(32)
    row = Appliance(
        id=uuid.uuid4(),
        hostname="cp-1",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        session_token_hash=token_hash,
    )
    db.add(row)
    await db.flush()
    return row, token


async def _heartbeat(client: AsyncClient, row: Appliance, token: str, **fields: object) -> None:
    r = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={"appliance_id": str(row.id), "session_token": token, **fields},
    )
    assert r.status_code == 200, r.text


async def test_heartbeat_persists_firewall_prereqs(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    row, token = await _approved_supervisor(db_session)
    await db_session.commit()

    await _heartbeat(
        client,
        row,
        token,
        node_ips=["192.168.1.11", "2001:db8::11"],
        pod_cidr="10.42.0.0/16",
        service_cidr="10.43.0.0/16",
        dataplane_backend="vxlan",
        base_conf_marker="a" * 64,
        base_lanwide_k3s=True,
    )

    db_session.expunge_all()
    fresh = await db_session.get(Appliance, row.id)
    assert fresh is not None
    assert fresh.node_ips == ["192.168.1.11", "2001:db8::11"]
    assert fresh.pod_cidr == "10.42.0.0/16"
    assert fresh.service_cidr == "10.43.0.0/16"
    assert fresh.dataplane_backend == "vxlan"
    assert fresh.base_conf_marker == "a" * 64
    assert fresh.base_lanwide_k3s is True


async def test_heartbeat_omitting_prereqs_leaves_them_alone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    row, token = await _approved_supervisor(db_session)
    await db_session.commit()

    # First heartbeat stamps the prereqs.
    await _heartbeat(
        client,
        row,
        token,
        pod_cidr="10.42.0.0/16",
        base_lanwide_k3s=True,
    )
    # Second heartbeat omits them entirely (legacy supervisor) → unchanged.
    await _heartbeat(client, row, token)

    db_session.expunge_all()
    fresh = await db_session.get(Appliance, row.id)
    assert fresh is not None
    assert fresh.pod_cidr == "10.42.0.0/16"
    assert fresh.base_lanwide_k3s is True
    # node_ips was never sent → stays the column default (empty list).
    assert fresh.node_ips == []


async def test_heartbeat_prereqs_default_empty(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # A fresh row that has never reported prereqs reads back the safe
    # defaults — node_ips [] (NOT NULL), the rest NULL.
    row, _ = await _approved_supervisor(db_session)
    await db_session.commit()
    db_session.expunge_all()
    fresh = await db_session.get(Appliance, row.id)
    assert fresh is not None
    assert fresh.node_ips == []
    assert fresh.pod_cidr is None
    assert fresh.base_conf_marker is None
    assert fresh.base_lanwide_k3s is None
