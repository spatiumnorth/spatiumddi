"""Fragile-device do-not-probe tests — issue #722.

The load-bearing property is the *direction* of inheritance. Unlike
DDNS, this flag ORs downward: a suppressed space must suppress every
subnet under it, and no descendant may un-set it. If that ever inverts,
a hospital that marked its clinical IPSpace do-not-probe would find one
subnet quietly opted back in and being swept — which is the exact
failure the flag exists to prevent, arriving silently.

Also covers: the three shipped probe origins actually refusing (the
discovery sweep, nmap, the network tools), the superadmin override being
audited and per-request, non-superadmins being refused the override, and
CIDR / hostname target resolution.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.nmap import NmapScan
from app.services.ipam.probe_policy import (
    check_probe_target,
    resolve_probe_policy,
)


async def _make_superadmin(db: AsyncSession) -> tuple[User, str]:
    u = User(
        username=f"admin-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return u, create_access_token(str(u.id))


async def _make_user_with_perm(db: AsyncSession, perm: dict) -> tuple[User, str]:
    u = User(
        username=f"user-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="User",
        hashed_password=hash_password("x"),
        is_superadmin=False,
    )
    db.add(u)
    await db.flush()
    role = Role(name=f"r-{uuid.uuid4().hex[:6]}", description="", permissions=[perm])
    db.add(role)
    await db.flush()
    group = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    group.roles = [role]
    group.users = [u]
    db.add(group)
    await db.flush()
    return u, create_access_token(str(u.id))


async def _make_chain(
    db: AsyncSession,
    *,
    network: str = "10.20.30.0/24",
    block_network: str = "10.20.0.0/16",
) -> tuple[IPSpace, IPBlock, Subnet]:
    space = IPSpace(name=f"probe-space-{uuid.uuid4().hex[:8]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, name="b", network=block_network)
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, name="s", network=network)
    db.add(subnet)
    await db.flush()
    return space, block, subnet


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ── Inheritance semantics ────────────────────────────────────────────


async def test_unflagged_chain_allows(db_session: AsyncSession) -> None:
    _, _, subnet = await _make_chain(db_session)
    verdict = await resolve_probe_policy(db_session, subnet)
    assert verdict.blocked is False
    assert verdict.allowed is True


async def test_subnet_flag_blocks_and_carries_reason(db_session: AsyncSession) -> None:
    _, _, subnet = await _make_chain(db_session)
    subnet.do_not_probe = True
    subnet.do_not_probe_reason = "Alaris pumps — vendor bulletin VB-2024-11"
    await db_session.flush()

    verdict = await resolve_probe_policy(db_session, subnet)
    assert verdict.blocked is True
    assert verdict.source == f"subnet:{subnet.id}"
    assert "VB-2024-11" in verdict.reason
    # The reason has to survive into the operator-facing sentence — a
    # refusal that just says "marked do-not-probe" gets overridden.
    assert "VB-2024-11" in verdict.message()


async def test_block_flag_suppresses_descendant_subnet(db_session: AsyncSession) -> None:
    _, block, subnet = await _make_chain(db_session)
    block.do_not_probe = True
    block.do_not_probe_reason = "OT cell 4"
    await db_session.flush()

    verdict = await resolve_probe_policy(db_session, subnet)
    assert verdict.blocked is True
    assert verdict.source == f"block:{block.id}"
    assert verdict.reason == "OT cell 4"


async def test_space_flag_suppresses_descendant_subnet(db_session: AsyncSession) -> None:
    space, _, subnet = await _make_chain(db_session)
    space.do_not_probe = True
    space.do_not_probe_reason = "Clinical VRF"
    await db_session.flush()

    verdict = await resolve_probe_policy(db_session, subnet)
    assert verdict.blocked is True
    assert verdict.source == f"space:{space.id}"


async def test_descendant_cannot_unset_an_ancestor_flag(db_session: AsyncSession) -> None:
    """THE inheritance property, and the one that must never invert.

    Unlike DDNS — which resolves to the first *non-inheriting* ancestor
    and so lets a descendant override its parent — this flag ORs
    downward. A subnet whose own flag is False, under a suppressed
    space, is still suppressed; there is deliberately no per-level
    inherit toggle to turn it back on.
    """
    space, _, subnet = await _make_chain(db_session)
    space.do_not_probe = True
    subnet.do_not_probe = False
    await db_session.flush()

    verdict = await resolve_probe_policy(db_session, subnet)
    assert verdict.blocked is True
    assert verdict.source == f"space:{space.id}"


async def test_nearest_level_supplies_the_reason(db_session: AsyncSession) -> None:
    """When several levels are flagged, the most specific one explains it."""
    space, block, subnet = await _make_chain(db_session)
    space.do_not_probe = True
    space.do_not_probe_reason = "whole clinical VRF"
    block.do_not_probe = True
    block.do_not_probe_reason = "imaging block"
    subnet.do_not_probe = True
    subnet.do_not_probe_reason = "CT room VLAN"
    await db_session.flush()

    verdict = await resolve_probe_policy(db_session, subnet)
    assert verdict.source == f"subnet:{subnet.id}"
    assert verdict.reason == "CT room VLAN"


async def test_nested_blocks_walk_upward(db_session: AsyncSession) -> None:
    space, parent_block, _ = await _make_chain(db_session)
    child_block = IPBlock(
        space_id=space.id,
        parent_block_id=parent_block.id,
        name="child",
        network="10.20.32.0/20",
    )
    db_session.add(child_block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=child_block.id, name="s2", network="10.20.40.0/24")
    db_session.add(subnet)
    parent_block.do_not_probe = True
    await db_session.flush()

    verdict = await resolve_probe_policy(db_session, subnet)
    assert verdict.blocked is True
    assert verdict.source == f"block:{parent_block.id}"


# ── Target resolution ────────────────────────────────────────────────


async def test_check_probe_target_resolves_a_bare_ip(db_session: AsyncSession) -> None:
    _, _, subnet = await _make_chain(db_session)
    subnet.do_not_probe = True
    await db_session.flush()

    assert (await check_probe_target(db_session, "10.20.30.7")).blocked is True
    assert (await check_probe_target(db_session, "10.99.99.7")).blocked is False


async def test_check_probe_target_resolves_a_cidr_in_both_directions(
    db_session: AsyncSession,
) -> None:
    """A CIDR scan reaches suppressed hosts whether it contains the
    flagged subnet or sits inside it — both are packets on the wire."""
    _, _, subnet = await _make_chain(db_session)
    subnet.do_not_probe = True
    await db_session.flush()

    # Supernet of the flagged subnet.
    assert (await check_probe_target(db_session, "10.20.0.0/16")).blocked is True
    # Slice inside the flagged subnet.
    assert (await check_probe_target(db_session, "10.20.30.128/25")).blocked is True
    # Unrelated range.
    assert (await check_probe_target(db_session, "192.168.5.0/24")).blocked is False


async def test_check_probe_target_matches_a_known_hostname(
    db_session: AsyncSession,
) -> None:
    """Hostnames are matched against IPAM inventory, not resolved
    through DNS — the guard must not depend on a network round-trip it
    cannot see the result of."""
    _, _, subnet = await _make_chain(db_session)
    subnet.do_not_probe = True
    db_session.add(
        IPAddress(
            subnet_id=subnet.id,
            address="10.20.30.9",
            status="allocated",
            hostname="ct-scanner-1",
        )
    )
    await db_session.flush()

    assert (await check_probe_target(db_session, "CT-Scanner-1")).blocked is True
    # FQDN form: the first label is matched against the stored hostname.
    assert (await check_probe_target(db_session, "ct-scanner-1.hospital.example.")).blocked is True
    assert (await check_probe_target(db_session, "unknown-host")).blocked is False


async def test_unmappable_target_is_allowed(db_session: AsyncSession) -> None:
    """Fail-safe direction: what IPAM doesn't know about, nobody flagged."""
    assert (await check_probe_target(db_session, "203.0.113.1")).blocked is False
    assert (await check_probe_target(db_session, "")).blocked is False


# ── Probe origins refuse ─────────────────────────────────────────────


async def test_network_tools_ping_refuses_flagged_target(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_superadmin(db_session)
    _, _, subnet = await _make_chain(db_session)
    subnet.do_not_probe = True
    subnet.do_not_probe_reason = "patient monitors"
    await db_session.commit()

    resp = await client.post(
        "/api/v1/tools/ping", headers=_auth(token), json={"host": "10.20.30.7"}
    )
    assert resp.status_code == 422, resp.text
    assert "patient monitors" in resp.json()["detail"]
    assert "override_do_not_probe" in resp.json()["detail"]


async def test_network_tools_port_test_refuses_flagged_target(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_superadmin(db_session)
    _, _, subnet = await _make_chain(db_session)
    subnet.do_not_probe = True
    await db_session.commit()

    resp = await client.post(
        "/api/v1/tools/port-test",
        headers=_auth(token),
        json={"host": "10.20.30.7", "port": 443},
    )
    assert resp.status_code == 422, resp.text


async def test_nmap_scan_refuses_flagged_target_and_persists_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The refusal happens before the row is written — a doomed scan must
    not leave a queued NmapScan behind."""
    _, token = await _make_superadmin(db_session)
    _, _, subnet = await _make_chain(db_session)
    subnet.do_not_probe = True
    await db_session.commit()

    resp = await client.post(
        "/api/v1/nmap/scans",
        headers=_auth(token),
        json={"target_ip": "10.20.30.7", "preset": "quick"},
    )
    assert resp.status_code == 422, resp.text
    assert (await db_session.scalar(select(func.count()).select_from(NmapScan))) == 0


# ── Override ─────────────────────────────────────────────────────────


async def test_superadmin_override_is_allowed_and_audited(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_superadmin(db_session)
    _, _, subnet = await _make_chain(db_session)
    subnet.do_not_probe = True
    subnet.do_not_probe_reason = "MRI console"
    await db_session.commit()

    resp = await client.post(
        "/api/v1/nmap/scans",
        headers=_auth(token),
        json={
            "target_ip": "10.20.30.7",
            "preset": "quick",
            "override_do_not_probe": True,
        },
    )
    assert resp.status_code == 202, resp.text

    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "probe.do_not_probe_override")
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].new_value is not None
    assert rows[0].new_value["tool"] == "nmap"
    assert rows[0].new_value["reason"] == "MRI console"


async def test_non_superadmin_cannot_override(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The override is not a permission grant. ``use_network_tools`` is a
    routine grant delegated admins hold; the point of the flag is that
    whoever clears it is accountable."""
    _, token = await _make_user_with_perm(
        db_session, {"action": "admin", "resource_type": "use_network_tools"}
    )
    _, _, subnet = await _make_chain(db_session)
    subnet.do_not_probe = True
    await db_session.commit()

    resp = await client.post(
        "/api/v1/tools/ping",
        headers=_auth(token),
        json={"host": "10.20.30.7", "override_do_not_probe": True},
    )
    assert resp.status_code == 403, resp.text
    assert (
        await db_session.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.action == "probe.do_not_probe_override")
        )
    ) == 0


async def test_override_is_per_request_not_a_mode(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_superadmin(db_session)
    _, _, subnet = await _make_chain(db_session)
    subnet.do_not_probe = True
    await db_session.commit()

    first = await client.post(
        "/api/v1/nmap/scans",
        headers=_auth(token),
        json={
            "target_ip": "10.20.30.7",
            "preset": "quick",
            "override_do_not_probe": True,
        },
    )
    assert first.status_code == 202, first.text
    # Nothing was remembered — the next call is refused again.
    second = await client.post(
        "/api/v1/nmap/scans",
        headers=_auth(token),
        json={"target_ip": "10.20.30.7", "preset": "quick"},
    )
    assert second.status_code == 422, second.text


async def test_reprofile_now_refuses_flagged_subnet(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """ "Re-profile now" bypasses the refresh window on purpose — it must
    not bypass this. The operator who clicked it is usually not the one
    who wrote the vendor bulletin onto the subnet."""
    _, token = await _make_superadmin(db_session)
    _, _, subnet = await _make_chain(db_session)
    subnet.do_not_probe = True
    subnet.do_not_probe_reason = "CT console"
    ip = IPAddress(subnet_id=subnet.id, address="10.20.30.11", status="allocated")
    db_session.add(ip)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/ipam/addresses/{ip.id}/profile", headers=_auth(token), json={}
    )
    assert resp.status_code == 422, resp.text
    assert "CT console" in resp.json()["detail"]
    assert (await db_session.scalar(select(func.count()).select_from(NmapScan))) == 0


async def test_copilot_nmap_apply_refuses_flagged_target(
    db_session: AsyncSession,
) -> None:
    """The Copilot's apply path is a separate surface from the REST
    route; a proposal the operator approved is still a scan."""
    from app.services.ai.operations import RunNmapScanArgs, _apply_run_nmap_scan

    user, _ = await _make_superadmin(db_session)
    _, _, subnet = await _make_chain(db_session)
    subnet.do_not_probe = True
    subnet.do_not_probe_reason = "infusion pumps"
    await db_session.flush()

    with pytest.raises(ValueError) as exc:
        await _apply_run_nmap_scan(
            db_session, user, RunNmapScanArgs(target_ip="10.20.30.7", preset="quick")
        )
    assert "infusion pumps" in str(exc.value)
    assert (await db_session.scalar(select(func.count()).select_from(NmapScan))) == 0


async def test_mcp_network_ping_refuses_flagged_target(
    db_session: AsyncSession,
) -> None:
    """MCP tools call the runners directly, so they need the gate too —
    otherwise the copilot is the one surface that still probes."""
    from app.services.ai.tools.nettools import NetworkPingArgs, network_ping

    user, _ = await _make_superadmin(db_session)
    _, _, subnet = await _make_chain(db_session)
    subnet.do_not_probe = True
    subnet.do_not_probe_reason = "patient monitors"
    await db_session.flush()

    result = await network_ping(db_session, user, NetworkPingArgs(host="10.20.30.7"))
    assert "patient monitors" in (result.get("error") or "")
    # A refusal, not a probe result — no exit code was ever produced.
    assert "exit_code" not in result


async def test_cidr_target_with_host_bits_does_not_error(
    db_session: AsyncSession,
) -> None:
    """nmap accepts ``10.20.30.5/24``; Postgres's ``cidr()`` cast does
    not. The guard has to normalise rather than raise a DataError, or a
    mistyped target becomes a 500."""
    _, _, subnet = await _make_chain(db_session)
    subnet.do_not_probe = True
    await db_session.flush()

    verdict = await check_probe_target(db_session, "10.20.30.5/24")
    assert verdict.blocked is True


async def test_soft_deleted_ancestor_still_suppresses(
    db_session: AsyncSession,
) -> None:
    """The session-wide ``deleted_at IS NULL`` filter applies to
    ``db.get()`` too, so a trashed block would truncate the walk and the
    guard would fail OPEN — the one direction it must never fail."""
    from datetime import UTC, datetime

    _, block, subnet = await _make_chain(db_session)
    block.do_not_probe = True
    block.do_not_probe_reason = "OT cell"
    block.deleted_at = datetime.now(UTC)
    await db_session.flush()

    verdict = await resolve_probe_policy(db_session, subnet)
    assert verdict.blocked is True
    assert verdict.source == f"block:{block.id}"


# ── Discovery sweep ──────────────────────────────────────────────────


@pytest.mark.usefixtures("db_session")
async def test_discovery_task_skips_flagged_subnet(db_session: AsyncSession) -> None:
    """The sweep bails before any packet is sent, stamps the run so the
    dispatcher stops re-queueing it, and records why."""
    from app.tasks import ipam_discovery

    _, _, subnet = await _make_chain(db_session)
    subnet.do_not_probe = True
    subnet.do_not_probe_reason = "PTS pneumatic tube"
    subnet.discovery_enabled = True
    await db_session.commit()
    subnet_id = str(subnet.id)

    # The task opens its own engine/session, so patch the sweep itself:
    # if the gate leaks, this raises rather than silently probing.
    async def _explode(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("sweep_subnet must not run on a do-not-probe subnet")

    with patch.object(ipam_discovery, "sweep_subnet", _explode):
        result = await ipam_discovery._run_subnet_discovery_async(subnet_id)

    # The task opens its own engine + session, so its commit is not
    # visible from this test's transaction. What is assertable here is
    # the contract the dispatcher and the operator both read: the run
    # bailed with the do-not-probe code, and it carries the reason.
    assert result["status"] == "skipped"
    assert result["reason"] == "do_not_probe"
    assert result["do_not_probe"]["reason"] == "PTS pneumatic tube"
    assert result["do_not_probe"]["source"] == f"subnet:{subnet_id}"


# ── REST surface ─────────────────────────────────────────────────────


async def test_probe_policy_endpoint_reports_inheritance(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_superadmin(db_session)
    space, _, subnet = await _make_chain(db_session)
    space.do_not_probe = True
    space.do_not_probe_reason = "clinical"
    await db_session.commit()

    resp = await client.get(f"/api/v1/ipam/subnets/{subnet.id}/probe-policy", headers=_auth(token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["do_not_probe"] is True
    # ``inherited`` is what tells the UI that clearing the subnet's own
    # checkbox would change nothing.
    assert body["inherited"] is True
    assert body["source"] == f"space:{space.id}"
    assert body["reason"] == "clinical"


async def test_subnet_update_round_trips_the_flag(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_superadmin(db_session)
    _, _, subnet = await _make_chain(db_session)
    await db_session.commit()

    resp = await client.put(
        f"/api/v1/ipam/subnets/{subnet.id}",
        headers=_auth(token),
        json={"do_not_probe": True, "do_not_probe_reason": "ultrasound carts"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["do_not_probe"] is True
    assert resp.json()["do_not_probe_reason"] == "ultrasound carts"


async def test_bmc_is_an_accepted_ip_role(client: AsyncClient, db_session: AsyncSession) -> None:
    """BMC / IPMI endpoints are the fragile-device class this issue is
    about, so they get a first-class role rather than a tag."""
    _, token = await _make_superadmin(db_session)
    _, _, subnet = await _make_chain(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/addresses",
        headers=_auth(token),
        json={
            "address": "10.20.30.50",
            "hostname": "idrac-1",
            "status": "allocated",
            "role": "bmc",
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["role"] == "bmc"


# ── Copilot ping_host (#3302) ────────────────────────────────────────


async def test_copilot_ping_host_refuses_do_not_probe_target(db_session: AsyncSession) -> None:
    from unittest.mock import AsyncMock

    from app.services.ai.tools import REGISTRY

    user, _ = await _make_superadmin(db_session)
    _, _, subnet = await _make_chain(db_session)
    subnet.do_not_probe = True
    subnet.do_not_probe_reason = "infusion pumps"
    await db_session.flush()

    with patch("asyncio.create_subprocess_exec", AsyncMock()) as spawn:
        out = await REGISTRY.call("ping_host", {"target": "10.20.30.5"}, db=db_session, user=user)
    spawn.assert_not_called()
    assert "infusion pumps" in out["error"]


def test_copilot_probing_tools_are_gated_by_the_network_module() -> None:
    from app.services.ai.tools import REGISTRY
    from app.services.ai.tools.base import effective_tool_names
    from app.services.feature_modules import all_module_ids

    for name in ("ping_host", "tls_cert_check"):
        tool = REGISTRY.get(name)
        assert tool is not None and tool.module == "tools.network", name
    eff = effective_tool_names(
        platform_enabled=None,
        provider_enabled=None,
        enabled_modules=all_module_ids() - {"tools.network"},
    )
    assert "ping_host" not in eff and "tls_cert_check" not in eff
