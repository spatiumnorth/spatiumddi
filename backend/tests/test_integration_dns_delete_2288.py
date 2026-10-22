"""Deleting a k8s / Tailscale / NetBird target must retire its DNS rows (#2288).

``DNSZone`` / ``DNSRecord`` cascade from the target in the database, so the ORM
listener never sees the delete. The delete handlers now mark the affected
groups' bundles dirty; the next bundle must not carry the names and its etag
must move.
"""

from __future__ import annotations

import dataclasses
import json
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPSpace
from app.models.kubernetes import KubernetesCluster
from app.models.netbird import NetbirdInstance
from app.models.tailscale import TailscaleTenant
from app.services.dns.config_bundle import build_config_bundle


async def _admin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


def _k8s(space: IPSpace, grp: DNSServerGroup) -> KubernetesCluster:
    return KubernetesCluster(
        name=f"k-{uuid.uuid4().hex[:6]}",
        api_server_url="https://k8s.example.test",
        token_encrypted=b"x",
        ipam_space_id=space.id,
        dns_group_id=grp.id,
    )


def _ts(space: IPSpace, grp: DNSServerGroup) -> TailscaleTenant:
    return TailscaleTenant(
        name=f"t-{uuid.uuid4().hex[:6]}", ipam_space_id=space.id, dns_group_id=grp.id
    )


def _nb(space: IPSpace, grp: DNSServerGroup) -> NetbirdInstance:
    return NetbirdInstance(
        name=f"n-{uuid.uuid4().hex[:6]}",
        api_key_encrypted=b"x",
        ipam_space_id=space.id,
        dns_group_id=grp.id,
    )


# (id, factory, fk, url, owns the zone too?)
CASES = [
    ("kubernetes", _k8s, "kubernetes_cluster_id", "/api/v1/kubernetes/clusters", False),
    ("tailscale", _ts, "tailscale_tenant_id", "/api/v1/tailscale/tenants", True),
    ("netbird", _nb, "netbird_instance_id", "/api/v1/netbird/instances", True),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("name,factory,fk,url,owns_zone", CASES, ids=[c[0] for c in CASES])
async def test_target_delete_retires_dns_from_the_next_bundle(
    client: AsyncClient, db_session: AsyncSession, name, factory, fk, url, owns_zone
) -> None:
    h = await _admin(db_session)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add_all([space, grp])
    await db_session.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host="10.0.0.1",
        name=f"s-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
    )
    target = factory(space, grp)
    db_session.add_all([server, target])
    await db_session.flush()

    zone_name = f"{uuid.uuid4().hex[:8]}.mirror.example."
    zone = DNSZone(
        group_id=grp.id,
        name=zone_name,
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
        **({fk: target.id} if owns_zone else {}),
    )
    db_session.add(zone)
    await db_session.flush()
    host = f"h{uuid.uuid4().hex[:8]}"
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            name=host,
            fqdn=f"{host}.{zone_name}",
            record_type="A",
            value="10.9.9.9",
            **{fk: target.id},
        )
    )
    target_id, server_id = target.id, server.id
    await db_session.commit()

    before = await build_config_bundle(db_session, server)
    assert host in json.dumps(dataclasses.asdict(before), default=str)
    seq_before = (
        await db_session.execute(
            select(DNSServer.bundle_dirty_seq).where(DNSServer.id == server_id)
        )
    ).scalar_one()

    r = await client.delete(f"{url}/{target_id}", headers=h)
    assert r.status_code == 204, r.text

    db_session.expire_all()
    seq_after = (
        await db_session.execute(
            select(DNSServer.bundle_dirty_seq).where(DNSServer.id == server_id)
        )
    ).scalar_one()
    assert seq_after > seq_before, "the group's stored bundle was not marked stale"
    srv = await db_session.get(DNSServer, server_id)
    after = await build_config_bundle(db_session, srv)
    rendered = json.dumps(dataclasses.asdict(after), default=str)
    assert host not in rendered
    if owns_zone:
        assert zone_name not in rendered
    assert after.etag != before.etag
