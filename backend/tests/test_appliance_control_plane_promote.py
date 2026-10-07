"""Control-plane promote/demote validation (#272 Phase 7).

Covers the batch-to-odd-target even-node guard, seed resolution, the
join-coordinate stamping on promote, and the leave stamping on demote.
The actual k3s reconfigure is the supervisor's host-side runner
(Phase 7b) — these exercise the backend contract / validation only.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    CLUSTER_ROLE_MEMBER,
    CLUSTER_ROLE_PRIMARY,
    Appliance,
)
from app.models.auth import User

pytestmark = pytest.mark.asyncio


async def _admin(db: AsyncSession, *, superadmin: bool = True, username: str = "cpadmin") -> str:
    user = User(
        username=username,
        email=f"{username}@example.com",
        display_name=username,
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=superadmin,
    )
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


async def _appliance(db: AsyncSession, hostname: str, **kw: object) -> Appliance:
    der = os.urandom(32)
    row = Appliance(
        id=uuid.uuid4(),
        hostname=hostname,
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        **kw,  # type: ignore[arg-type]
    )
    db.add(row)
    await db.flush()
    return row


async def _seed(db: AsyncSession) -> Appliance:
    return await _appliance(
        db,
        "seed",
        appliance_variant="control-plane",
        cluster_role=CLUSTER_ROLE_PRIMARY,
        last_seen_ip="10.42.0.6",  # supervisor POD IP — must NOT be used
        node_ip="10.0.0.1",  # real routable node IP — the join target
        k3s_join_token_encrypted=encrypt_str("K10::servertoken"),
    )


def _hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ── promote ──────────────────────────────────────────────────────────


async def test_promote_to_three_ok(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    await _seed(db_session)
    a = await _appliance(db_session, "app1", appliance_variant="appliance")
    b = await _appliance(db_session, "app2", appliance_variant="appliance")
    await db_session.commit()

    resp = await client.post(
        "/api/v1/appliance/fleet/control-plane/promote",
        json={"appliance_ids": [str(a.id), str(b.id)]},
        headers=_hdr(token),
    )
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["appliances"]) == 2

    await db_session.refresh(a)
    assert a.desired_cluster_role == "member"
    assert a.desired_k3s_server_url == "https://10.0.0.1:6443"
    assert a.cluster_join_state == "joining"
    # The (sensitive) token is stamped encrypted, not in the row plaintext.
    assert a.desired_k3s_join_token_encrypted is not None


async def test_promote_even_target_refused(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    await _seed(db_session)
    a = await _appliance(db_session, "app1", appliance_variant="appliance")
    await db_session.commit()

    # 1 seed + 1 promote = 2 → even → refused.
    resp = await client.post(
        "/api/v1/appliance/fleet/control-plane/promote",
        json={"appliance_ids": [str(a.id)]},
        headers=_hdr(token),
    )
    assert resp.status_code == 422
    assert "ODD" in resp.text


async def test_promote_requires_seed_token(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    # Seed without a reported join token.
    await _appliance(
        db_session,
        "seed",
        appliance_variant="control-plane",
        cluster_role=CLUSTER_ROLE_PRIMARY,
        last_seen_ip="10.0.0.1",
    )
    a = await _appliance(db_session, "app1", appliance_variant="appliance")
    b = await _appliance(db_session, "app2", appliance_variant="appliance")
    await db_session.commit()

    resp = await client.post(
        "/api/v1/appliance/fleet/control-plane/promote",
        json={"appliance_ids": [str(a.id), str(b.id)]},
        headers=_hdr(token),
    )
    assert resp.status_code == 409
    assert "join token" in resp.text


async def test_promote_requires_seed_node_ip(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    # Seed reported a token but only a pod IP (no node_ip) — the join URL
    # can't be built from a pod IP, so promote must refuse.
    await _appliance(
        db_session,
        "seed",
        appliance_variant="control-plane",
        cluster_role=CLUSTER_ROLE_PRIMARY,
        last_seen_ip="10.42.0.6",
        k3s_join_token_encrypted=encrypt_str("K10::servertoken"),
    )
    a = await _appliance(db_session, "app1", appliance_variant="appliance")
    b = await _appliance(db_session, "app2", appliance_variant="appliance")
    await db_session.commit()

    resp = await client.post(
        "/api/v1/appliance/fleet/control-plane/promote",
        json={"appliance_ids": [str(a.id), str(b.id)]},
        headers=_hdr(token),
    )
    assert resp.status_code == 409
    assert "node IP" in resp.text


async def test_promote_designates_lone_seed(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    # Single control-plane node with no cluster_role yet → designated.
    seed = await _appliance(
        db_session,
        "seed",
        appliance_variant="control-plane",
        last_seen_ip="10.42.0.7",
        node_ip="10.0.0.9",
        k3s_join_token_encrypted=encrypt_str("K10::tok"),
    )
    a = await _appliance(db_session, "app1", appliance_variant="appliance")
    b = await _appliance(db_session, "app2", appliance_variant="appliance")
    await db_session.commit()

    resp = await client.post(
        "/api/v1/appliance/fleet/control-plane/promote",
        json={"appliance_ids": [str(a.id), str(b.id)]},
        headers=_hdr(token),
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(seed)
    assert seed.cluster_role == CLUSTER_ROLE_PRIMARY


async def test_promote_non_superadmin_403(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session, superadmin=False, username="regular")
    await _seed(db_session)
    a = await _appliance(db_session, "app1", appliance_variant="appliance")
    await db_session.commit()
    resp = await client.post(
        "/api/v1/appliance/fleet/control-plane/promote",
        json={"appliance_ids": [str(a.id)]},
        headers=_hdr(token),
    )
    assert resp.status_code == 403


# ── demote ───────────────────────────────────────────────────────────


async def test_demote_to_one_ok(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    await _seed(db_session)
    m1 = await _appliance(db_session, "m1", cluster_role=CLUSTER_ROLE_MEMBER)
    m2 = await _appliance(db_session, "m2", cluster_role=CLUSTER_ROLE_MEMBER)
    await db_session.commit()

    # 3 members - 2 = 1 → odd → ok.
    resp = await client.post(
        "/api/v1/appliance/fleet/control-plane/demote",
        json={"appliance_ids": [str(m1.id), str(m2.id)]},
        headers=_hdr(token),
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(m1)
    assert m1.desired_cluster_role == "none"
    assert m1.cluster_join_state == "leaving"


async def test_demote_even_remaining_refused(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    await _seed(db_session)
    m1 = await _appliance(db_session, "m1", cluster_role=CLUSTER_ROLE_MEMBER)
    await _appliance(db_session, "m2", cluster_role=CLUSTER_ROLE_MEMBER)
    await db_session.commit()

    # 3 members - 1 = 2 → even → refused.
    resp = await client.post(
        "/api/v1/appliance/fleet/control-plane/demote",
        json={"appliance_ids": [str(m1.id)]},
        headers=_hdr(token),
    )
    assert resp.status_code == 422
    assert "ODD" in resp.text


async def test_demote_refuses_primary(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    seed = await _seed(db_session)
    await _appliance(db_session, "m1", cluster_role=CLUSTER_ROLE_MEMBER)
    await _appliance(db_session, "m2", cluster_role=CLUSTER_ROLE_MEMBER)
    await db_session.commit()

    resp = await client.post(
        "/api/v1/appliance/fleet/control-plane/demote",
        json={"appliance_ids": [str(seed.id)]},
        headers=_hdr(token),
    )
    assert resp.status_code == 422
    assert "seed" in resp.text


# ── dead-node replacement (Phase 9) ──────────────────────────────────


async def test_replace_member_evicts_and_mints_code(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _admin(db_session)
    await _seed(db_session)
    m1 = await _appliance(db_session, "m1", cluster_role=CLUSTER_ROLE_MEMBER, node_ip="10.0.0.2")
    await _appliance(db_session, "m2", cluster_role=CLUSTER_ROLE_MEMBER, node_ip="10.0.0.3")
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/appliance/fleet/control-plane/{m1.id}/replace",
        headers=_hdr(token),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["pairing_code"] and len(body["pairing_code"]) == 8
    assert body["evicted"]["hostname"] == "m1"

    await db_session.refresh(m1)
    assert m1.cluster_role is None
    assert m1.evict_requested is True
    assert m1.cluster_join_state == "evicting"


async def test_replace_refuses_primary(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    seed = await _seed(db_session)
    await _appliance(db_session, "m1", cluster_role=CLUSTER_ROLE_MEMBER)
    await _appliance(db_session, "m2", cluster_role=CLUSTER_ROLE_MEMBER)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/appliance/fleet/control-plane/{seed.id}/replace",
        headers=_hdr(token),
    )
    assert resp.status_code == 422
    assert "seed" in resp.text


async def test_replace_refuses_non_member(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    await _seed(db_session)
    # An approved appliance that never joined the control plane.
    plain = await _appliance(db_session, "agent1", appliance_variant="appliance")
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/appliance/fleet/control-plane/{plain.id}/replace",
        headers=_hdr(token),
    )
    assert resp.status_code == 409
    assert "member" in resp.text


# ── MetalLB control-plane VIP config (Phase 7c) ──────────────────────

_METALLB_URL = "/api/v1/appliance/fleet/control-plane/metallb"


async def test_metallb_get_default(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    await db_session.commit()
    resp = await client.get(_METALLB_URL, headers=_hdr(token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["enabled"] is False
    assert body["pool_addresses"] == []
    assert body["control_plane_vip"] == ""
    # #272 — live-status fields default to false/0 when kubeapi is
    # unavailable (no ServiceAccount mounted under pytest).
    assert body["controller_ready"] is False
    assert body["speakers_ready"] == 0
    assert body["speakers_total"] == 0


async def test_metallb_put_and_get(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    await db_session.commit()
    resp = await client.put(
        _METALLB_URL,
        json={
            "enabled": True,
            "pool_addresses": ["192.168.0.240/29"],
            "control_plane_vip": "192.168.0.241",
        },
        headers=_hdr(token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["control_plane_vip"] == "192.168.0.241"
    # Round-trips through the GET (config fields; status fields default
    # to false/0 in-test and are asserted in test_metallb_get_default).
    got = await client.get(_METALLB_URL, headers=_hdr(token))
    body = got.json()
    assert body["enabled"] is True
    assert body["pool_addresses"] == ["192.168.0.240/29"]
    assert body["control_plane_vip"] == "192.168.0.241"


async def test_metallb_vip_outside_pool_refused(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _admin(db_session)
    await db_session.commit()
    resp = await client.put(
        _METALLB_URL,
        json={
            "enabled": True,
            "pool_addresses": ["192.168.0.240/29"],
            "control_plane_vip": "10.0.0.5",
        },
        headers=_hdr(token),
    )
    assert resp.status_code == 422
    assert "not inside" in resp.text


async def test_metallb_enabled_requires_vip(db_session: AsyncSession, client: AsyncClient) -> None:
    # #272 — enabling MetalLB requires a VIP. The address pool is now
    # OPTIONAL (auto-derived as <vip>/32 when omitted), so the missing-VIP
    # case is what 422s, not a missing pool.
    token = await _admin(db_session)
    await db_session.commit()
    resp = await client.put(
        _METALLB_URL,
        json={"enabled": True, "pool_addresses": [], "control_plane_vip": ""},
        headers=_hdr(token),
    )
    assert resp.status_code == 422
    assert "VIP is required" in resp.text


async def test_metallb_vip_only_autoderives_pool(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    # #272 — enabled + VIP + no pool → succeeds, pool auto-set to <vip>/32.
    # This is the common single-VIP path the operator takes (one field).
    token = await _admin(db_session)
    await db_session.commit()
    resp = await client.put(
        _METALLB_URL,
        json={"enabled": True, "pool_addresses": [], "control_plane_vip": "192.168.0.250"},
        headers=_hdr(token),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["pool_addresses"] == ["192.168.0.250/32"]
    assert body["control_plane_vip"] == "192.168.0.250"


async def test_metallb_invalid_pool_entry(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    await db_session.commit()
    resp = await client.put(
        _METALLB_URL,
        json={"enabled": False, "pool_addresses": ["not-an-ip"], "control_plane_vip": ""},
        headers=_hdr(token),
    )
    assert resp.status_code == 422
    assert "invalid pool entry" in resp.text


async def test_metallb_range_pool_ok(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    await db_session.commit()
    resp = await client.put(
        _METALLB_URL,
        json={
            "enabled": True,
            "pool_addresses": ["192.168.0.240-192.168.0.247"],
            "control_plane_vip": "192.168.0.245",
        },
        headers=_hdr(token),
    )
    assert resp.status_code == 200, resp.text


async def test_metallb_non_superadmin_refused(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _admin(db_session, superadmin=False, username="plainuser")
    await db_session.commit()
    resp = await client.get(_METALLB_URL, headers=_hdr(token))
    assert resp.status_code == 403


# ── BGP mode (issue #566 decision D1) ────────────────────────────────


async def test_metallb_bgp_requires_enabled(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    await db_session.commit()
    resp = await client.put(
        _METALLB_URL,
        json={
            "enabled": False,
            "pool_addresses": [],
            "control_plane_vip": "",
            "bgp_enabled": True,
            "bgp_peers": [{"my_asn": 65000, "peer_asn": 65001, "peer_address": "203.0.113.1"}],
        },
        headers=_hdr(token),
    )
    assert resp.status_code == 422
    assert "BGP mode requires MetalLB" in resp.text


async def test_metallb_bgp_requires_peers(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    await db_session.commit()
    resp = await client.put(
        _METALLB_URL,
        json={
            "enabled": True,
            "pool_addresses": [],
            "control_plane_vip": "192.168.0.241",
            "bgp_enabled": True,
            "bgp_peers": [],
        },
        headers=_hdr(token),
    )
    assert resp.status_code == 422
    assert "at least one BGP peer is required" in resp.text


async def test_metallb_bgp_invalid_asn(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    await db_session.commit()
    resp = await client.put(
        _METALLB_URL,
        json={
            "enabled": True,
            "pool_addresses": [],
            "control_plane_vip": "192.168.0.241",
            "bgp_enabled": True,
            "bgp_peers": [{"my_asn": 0, "peer_asn": 65001, "peer_address": "203.0.113.1"}],
        },
        headers=_hdr(token),
    )
    assert resp.status_code == 422

    resp2 = await client.put(
        _METALLB_URL,
        json={
            "enabled": True,
            "pool_addresses": [],
            "control_plane_vip": "192.168.0.241",
            "bgp_enabled": True,
            "bgp_peers": [
                {
                    "my_asn": 65000,
                    "peer_asn": 4_294_967_296,
                    "peer_address": "203.0.113.1",
                }
            ],
        },
        headers=_hdr(token),
    )
    assert resp2.status_code == 422


async def test_metallb_bgp_put_and_get(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    await db_session.commit()
    resp = await client.put(
        _METALLB_URL,
        json={
            "enabled": True,
            "pool_addresses": [],
            "control_plane_vip": "192.168.0.241",
            "bgp_enabled": True,
            "bgp_peers": [
                {
                    "my_asn": 65000,
                    "peer_asn": 65001,
                    "peer_address": "203.0.113.1",
                    "peer_port": 1179,
                    "hold_time": "90s",
                }
            ],
        },
        headers=_hdr(token),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["bgp_enabled"] is True
    assert body["bgp_peers"] == [
        {
            "my_asn": 65000,
            "peer_asn": 65001,
            "peer_address": "203.0.113.1",
            "peer_port": 1179,
            "hold_time": "90s",
        }
    ]
    # bgp_advertisements auto-derived since none were supplied.
    assert body["bgp_advertisements"] == [
        {
            "ip_address_pools": ["spatium-control-plane"],
            "communities": [],
            "aggregation_length": None,
        }
    ]

    got = await client.get(_METALLB_URL, headers=_hdr(token))
    got_body = got.json()
    assert got_body["bgp_enabled"] is True
    assert got_body["bgp_peers"][0]["peer_address"] == "203.0.113.1"


async def test_metallb_bgp_non_superadmin_refused(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _admin(db_session, superadmin=False, username="plainuser")
    await db_session.commit()
    resp = await client.put(
        _METALLB_URL,
        json={
            "enabled": True,
            "pool_addresses": [],
            "control_plane_vip": "192.168.0.241",
            "bgp_enabled": True,
            "bgp_peers": [{"my_asn": 65000, "peer_asn": 65001, "peer_address": "203.0.113.1"}],
        },
        headers=_hdr(token),
    )
    assert resp.status_code == 403


# ── data-plane resolver VIPs (Phase 10) ──────────────────────────────


async def test_dataplane_vips_put_and_get(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    await db_session.commit()
    resp = await client.put(
        _METALLB_URL,
        json={
            "enabled": True,
            "pool_addresses": ["192.168.0.240/29"],
            "control_plane_vip": "192.168.0.241",
            "dns_vip": "192.168.0.242",
            "dhcp_relay_vip": "192.168.0.243",
        },
        headers=_hdr(token),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["dns_vip"] == "192.168.0.242"
    assert body["dhcp_relay_vip"] == "192.168.0.243"
    got = (await client.get(_METALLB_URL, headers=_hdr(token))).json()
    assert got["dns_vip"] == "192.168.0.242"
    assert got["dhcp_relay_vip"] == "192.168.0.243"


async def test_dataplane_vip_outside_pool_refused(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _admin(db_session)
    await db_session.commit()
    resp = await client.put(
        _METALLB_URL,
        json={
            "enabled": True,
            "pool_addresses": ["192.168.0.240/29"],
            "control_plane_vip": "192.168.0.241",
            "dns_vip": "10.0.0.9",
        },
        headers=_hdr(token),
    )
    assert resp.status_code == 422
    assert "not inside" in resp.text


async def test_dataplane_vip_requires_metallb_enabled(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _admin(db_session)
    await db_session.commit()
    resp = await client.put(
        _METALLB_URL,
        json={
            "enabled": False,
            "pool_addresses": [],
            "control_plane_vip": "",
            "dns_vip": "192.168.0.242",
        },
        headers=_hdr(token),
    )
    assert resp.status_code == 422
    assert "requires MetalLB" in resp.text


async def test_dataplane_vip_must_differ_from_control_plane(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _admin(db_session)
    await db_session.commit()
    resp = await client.put(
        _METALLB_URL,
        json={
            "enabled": True,
            "pool_addresses": ["192.168.0.240/29"],
            "control_plane_vip": "192.168.0.241",
            "dns_vip": "192.168.0.241",
        },
        headers=_hdr(token),
    )
    assert resp.status_code == 422
    assert "differ from the control-plane VIP" in resp.text


async def test_dataplane_dns_and_dhcp_vips_must_differ(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _admin(db_session)
    await db_session.commit()
    resp = await client.put(
        _METALLB_URL,
        json={
            "enabled": True,
            "pool_addresses": ["192.168.0.240/29"],
            "control_plane_vip": "192.168.0.241",
            "dns_vip": "192.168.0.242",
            "dhcp_relay_vip": "192.168.0.242",
        },
        headers=_hdr(token),
    )
    assert resp.status_code == 422
    assert "must differ" in resp.text


# ── etcd snapshots + guided restore (Phase 9b) ───────────────────────

_SNAP_URL = "/api/v1/appliance/fleet/control-plane/etcd-snapshots"
_RESTORE_URL = "/api/v1/appliance/fleet/control-plane/restore"


async def test_etcd_snapshots_unavailable_without_seed(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _admin(db_session)
    await db_session.commit()
    resp = await client.get(_SNAP_URL, headers=_hdr(token))
    assert resp.status_code == 200, resp.text
    assert resp.json()["available"] is False


async def test_etcd_snapshots_lists_seed_inventory(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _admin(db_session)
    seed = await _seed(db_session)
    seed.last_seen_at = datetime.now(UTC)
    seed.etcd_snapshots = [
        {
            "name": "on-demand-seed-1700000000",
            "location": "file:///var/lib/rancher/k3s/server/db/snapshots/on-demand-seed-1700000000",
            "node_name": "seed",
            "size": 1234567,
            "created_at": "2026-06-10T00:00:00Z",
        }
    ]
    await db_session.commit()
    resp = await client.get(_SNAP_URL, headers=_hdr(token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["available"] is True
    assert body["seed_hostname"] == "seed"
    assert len(body["snapshots"]) == 1
    assert body["snapshots"][0]["name"] == "on-demand-seed-1700000000"


async def test_restore_stamps_desired_snapshot(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _admin(db_session)
    seed = await _seed(db_session)
    seed.etcd_snapshots = [{"name": "snap-A", "node_name": "seed"}]
    await db_session.commit()
    resp = await client.post(
        _RESTORE_URL,
        json={"snapshot_name": "snap-A", "confirm_hostname": "seed"},
        headers=_hdr(token),
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(seed)
    assert seed.desired_restore_snapshot == "snap-A"


async def test_restore_wrong_hostname_refused(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _admin(db_session)
    seed = await _seed(db_session)
    seed.etcd_snapshots = [{"name": "snap-A", "node_name": "seed"}]
    await db_session.commit()
    resp = await client.post(
        _RESTORE_URL,
        json={"snapshot_name": "snap-A", "confirm_hostname": "wrong"},
        headers=_hdr(token),
    )
    assert resp.status_code == 422
    assert "hostname" in resp.text
    await db_session.refresh(seed)
    assert seed.desired_restore_snapshot is None


async def test_restore_unknown_snapshot_refused(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _admin(db_session)
    seed = await _seed(db_session)
    seed.etcd_snapshots = [{"name": "snap-A", "node_name": "seed"}]
    await db_session.commit()
    resp = await client.post(
        _RESTORE_URL,
        json={"snapshot_name": "does-not-exist", "confirm_hostname": "seed"},
        headers=_hdr(token),
    )
    assert resp.status_code == 422
    assert "inventory" in resp.text


async def test_restore_in_flight_conflict(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    seed = await _seed(db_session)
    seed.etcd_snapshots = [{"name": "snap-A", "node_name": "seed"}]
    seed.desired_restore_snapshot = "snap-A"
    seed.restore_state = "restoring"
    await db_session.commit()
    resp = await client.post(
        _RESTORE_URL,
        json={"snapshot_name": "snap-A", "confirm_hostname": "seed"},
        headers=_hdr(token),
    )
    assert resp.status_code == 409
    assert "already in flight" in resp.text


async def test_restore_non_superadmin_refused(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _admin(db_session, superadmin=False, username="plain2")
    await _seed(db_session)
    await db_session.commit()
    resp = await client.post(
        _RESTORE_URL,
        json={"snapshot_name": "snap-A", "confirm_hostname": "seed"},
        headers=_hdr(token),
    )
    assert resp.status_code == 403


async def test_replace_accepts_a_failed_joiner(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """A joiner whose join died "already an etcd member" holds a stale etcd
    member under its hostname; Replace is the route that evicts it by name,
    and it used to 409 on the row not being a settled member (sizing
    campaign, 2026-09-02)."""
    token = await _admin(db_session)
    await _seed(db_session)
    await _appliance(db_session, "m1", cluster_role=CLUSTER_ROLE_MEMBER, node_ip="10.0.0.2")
    stuck = await _appliance(
        db_session,
        "m2",
        appliance_variant="appliance",
        cluster_role=None,
        desired_cluster_role=None,
        cluster_join_state="failed",
        cluster_join_reason="this hostname is already an etcd member of the target cluster — evict it",
        node_ip="10.0.0.3",
    )
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/appliance/fleet/control-plane/{stuck.id}/replace",
        headers=_hdr(token),
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(stuck)
    assert stuck.evict_requested is True
    assert stuck.cluster_join_state == "evicting"


async def test_replace_still_refuses_an_in_flight_joiner(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _admin(db_session)
    await _seed(db_session)
    joining = await _appliance(
        db_session,
        "m3",
        appliance_variant="appliance",
        desired_cluster_role="member",
        cluster_join_state="joining",
    )
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/appliance/fleet/control-plane/{joining.id}/replace",
        headers=_hdr(token),
    )
    assert resp.status_code == 409


async def test_replace_accepts_a_failed_joiner_whose_retry_is_still_pending(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """A transient failure keeps the desired-state for the supervisor's
    automatic retry; an operator who calls Replace inside that window is
    overriding the retry on purpose. Live 2026-09-04 01:34Z: with the
    desired-state kept, Replace answered 409 "nothing to evict" — the retry
    half and the Replace half of the same fix contradicted each other."""
    token = await _admin(db_session)
    await _seed(db_session)
    await _appliance(db_session, "m1", cluster_role=CLUSTER_ROLE_MEMBER, node_ip="10.0.0.2")
    stuck = await _appliance(
        db_session,
        "m2",
        appliance_variant="appliance",
        cluster_role=None,
        desired_cluster_role="member",
        cluster_join_state="failed",
        cluster_join_reason="could not reach the seed — check the firewall and tcp/6443 + tcp/2379-2380",
        node_ip="10.0.0.3",
    )
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/appliance/fleet/control-plane/{stuck.id}/replace",
        headers=_hdr(token),
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(stuck)
    assert stuck.evict_requested is True
    assert stuck.cluster_join_state == "evicting"
    # Replace ends the pending retry: no desired role, no join coordinates left behind.
    assert stuck.desired_cluster_role is None
    assert stuck.desired_k3s_server_url is None


# ── promote while an eviction is pending (#1284) ─────────────────────


async def test_promote_refused_while_the_row_is_still_being_evicted(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """Replace clears the row's roles at once, so a guard reading only the
    roles let a promote through while the seed was still evicting the row.
    Until the seed confirms, it removes every etcd member named
    `<hostname>-<8 hex>` on each heartbeat: the node would join, become a
    voter and lose its member on the seed's next tick."""
    token = await _admin(db_session)
    await _seed(db_session)
    await _appliance(db_session, "m1", cluster_role=CLUSTER_ROLE_MEMBER, node_ip="10.0.0.2")
    joiner = await _appliance(
        db_session,
        "m2",
        appliance_variant="appliance",
        cluster_join_state="failed",
        cluster_join_reason="could not reach the seed — check the firewall and tcp/6443 + tcp/2379-2380",
        node_ip="10.0.0.3",
    )
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/appliance/fleet/control-plane/{joiner.id}/replace",
        headers=_hdr(token),
    )
    assert resp.status_code == 200, resp.text

    resp = await client.post(
        "/api/v1/appliance/fleet/control-plane/promote",
        json={"appliance_ids": [str(joiner.id)]},
        headers=_hdr(token),
    )
    assert resp.status_code == 409, resp.text
    assert "still being evicted" in resp.text
    await db_session.refresh(joiner)
    assert joiner.desired_cluster_role is None
    assert joiner.evict_requested is True
    assert joiner.cluster_join_state == "evicting"


@pytest.mark.parametrize("hostname", ["m3", "M3"])
async def test_promote_refused_for_a_box_sharing_a_hostname_being_evicted(
    db_session: AsyncSession, client: AsyncClient, hostname: str
) -> None:
    """A replacement box installed under the dead node's hostname is a row of
    its own, but the seed matches etcd members by hostname: promoted while the
    old row is still evicting, its new member would be removed as the old
    one's. Compared case-blind, so a variant spelling is held too."""
    token = await _admin(db_session)
    await _seed(db_session)
    await _appliance(db_session, "m1", cluster_role=CLUSTER_ROLE_MEMBER, node_ip="10.0.0.2")
    await _appliance(
        db_session,
        "m3",
        appliance_variant="appliance",
        cluster_join_state="evicting",
        evict_requested=True,
        node_ip="10.0.0.3",
    )
    fresh = await _appliance(
        db_session, hostname, appliance_variant="appliance", node_ip="10.0.0.9"
    )
    await db_session.commit()

    resp = await client.post(
        "/api/v1/appliance/fleet/control-plane/promote",
        json={"appliance_ids": [str(fresh.id)]},
        headers=_hdr(token),
    )
    assert resp.status_code == 409, resp.text
    assert "still being evicted" in resp.text
    await db_session.refresh(fresh)
    assert fresh.desired_cluster_role is None
    assert fresh.cluster_join_state is None


async def test_a_settled_eviction_can_be_promoted_again(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """The guard ends with the eviction. Once the row reads `left` the same
    node can be promoted again (why Replace accepts a failed joiner), and so
    can a box under the same hostname: the seed ends its late-arrival watch on
    a name it is asked to join."""
    token = await _admin(db_session)
    await _seed(db_session)
    await _appliance(db_session, "m1", cluster_role=CLUSTER_ROLE_MEMBER, node_ip="10.0.0.2")
    evicted = await _appliance(
        db_session,
        "m2",
        appliance_variant="appliance",
        cluster_join_state="left",
        evict_requested=False,
        node_ip="10.0.0.3",
    )
    await _appliance(
        db_session,
        "m4",
        appliance_variant="appliance",
        cluster_join_state="left",
        evict_requested=False,
        node_ip="10.0.0.4",
    )
    namesake = await _appliance(db_session, "m4", appliance_variant="appliance", node_ip="10.0.0.9")
    await db_session.commit()

    resp = await client.post(
        "/api/v1/appliance/fleet/control-plane/promote",
        json={"appliance_ids": [str(evicted.id), str(namesake.id)]},
        headers=_hdr(token),
    )
    # seed + m1 + two promoted would be four: the count guard, not the
    # eviction guard, must be what answers.
    assert resp.status_code == 422, resp.text
    assert "ODD" in resp.text

    resp = await client.post(
        "/api/v1/appliance/fleet/control-plane/promote",
        json={"appliance_ids": [str(evicted.id)]},
        headers=_hdr(token),
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(evicted)
    assert evicted.desired_cluster_role == "member"
    assert evicted.cluster_join_state == "joining"


# ── #1543: nothing reshapes the cluster mid-upgrade ──────────────────────────

_GUARDED = (
    "promote_control_plane",
    "demote_control_plane",
    "replace_control_plane_member",
    "restore_etcd_snapshot",
    "schedule_appliance_upgrade",
    "schedule_appliance_set_next_boot",
    "schedule_appliance_set_default_slot",
)


def test_every_cluster_reshaping_handler_checks_for_an_upgrade_in_flight() -> None:
    """``assert_no_upgrade_in_flight`` existed for exactly these paths, and
    only backup and factory reset called it."""
    import inspect

    from app.api.v1.appliance import supervisor

    missing = [
        name
        for name in _GUARDED
        if "assert_no_upgrade_in_flight(" not in inspect.getsource(getattr(supervisor, name))
    ]
    assert missing == []


async def test_demote_refused_mid_upgrade(db_session: AsyncSession, client: AsyncClient) -> None:
    from app.models.system_upgrade import SystemUpgradeRun

    token = await _admin(db_session)
    await _seed(db_session)
    m1 = await _appliance(db_session, "m1", cluster_role=CLUSTER_ROLE_MEMBER)
    m2 = await _appliance(db_session, "m2", cluster_role=CLUSTER_ROLE_MEMBER)
    db_session.add(SystemUpgradeRun(kind="rolling", state="running", target_version="2026.10.06-1"))
    await db_session.commit()

    resp = await client.post(
        "/api/v1/appliance/fleet/control-plane/demote",
        json={"appliance_ids": [str(m1.id), str(m2.id)]},
        headers=_hdr(token),
    )
    assert resp.status_code == 409, resp.text
    assert "rolling upgrade" in resp.text
    await db_session.refresh(m1)
    assert m1.cluster_join_state != "leaving"
