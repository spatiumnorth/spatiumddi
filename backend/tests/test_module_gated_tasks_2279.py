"""Disabling a feature module stops its scheduled and event-driven work (#2279).

Turning a module off 404s its router, but a Celery task never goes through a
router: the nmap auto-profile hook, SNMP polling, TLS probes, conformity
evaluation and the off-prem ASN RDAP / RPKI / RIPEstat refreshes all kept
running after the operator switched their module off.

The tests below run each task the way a worker does (``.apply()`` on a
thread, its own engine reading committed state) and assert on what the task
did — enqueued polls, dispatched scans, rows written, the body ever entered —
with the module off and, as the positive control, on. The last test is the
structural guard: every task in the beat schedule is either gated or on an
allowlist that says why it runs regardless.
"""

from __future__ import annotations

import asyncio
import importlib
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.celery_app import celery_app
from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.feature_module import FeatureModule
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.network import NetworkDevice
from app.models.nmap import NmapScan
from app.services import feature_modules
from app.tasks.module_gate import UNGATED_BEAT_TASKS


async def _set_module(db: AsyncSession, module_id: str, enabled: bool) -> None:
    existing = await db.get(FeatureModule, module_id)
    if existing is None:
        db.add(FeatureModule(id=module_id, enabled=enabled))
    else:
        existing.enabled = enabled
    await db.commit()
    feature_modules.invalidate_cache()


async def _run_task(task_name: str, *args: Any) -> Any:
    """Run a registered task as a worker would: synchronously, off the loop."""
    # Register every task module first, as a worker does at boot. A task is only
    # in ``celery_app.tasks`` once its module has been imported, which depends
    # on what ran earlier in this process (and so on pytest-split's ordering).
    celery_app.loader.import_default_modules()
    task = celery_app.tasks[task_name]
    result = await asyncio.to_thread(task.apply, args=list(args))
    if result.failed():
        raise result.result
    return result.result


# ── SNMP polling (network.device) ─────────────────────────────────────


async def _due_device(db: AsyncSession) -> NetworkDevice:
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    device = NetworkDevice(
        name="sw1",
        hostname="10.9.0.1",
        ip_address="10.9.0.1",
        snmp_version="v2c",
        ip_space_id=space.id,
        community_encrypted=encrypt_str("public"),
        # Keep an unpatched run (the negative control on main) quick.
        snmp_timeout_seconds=1,
        snmp_retries=0,
    )
    db.add(device)
    await db.commit()
    return device


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled", [False, True])
async def test_snmp_dispatch_queues_no_poll_with_network_device_off(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, enabled: bool
) -> None:
    from app.tasks import snmp_poll

    device = await _due_device(db_session)
    await _set_module(db_session, "network.device", enabled)

    queued: list[str] = []
    monkeypatch.setattr(snmp_poll.poll_device, "delay", lambda dev_id: queued.append(dev_id))

    result = await _run_task("app.tasks.snmp_poll.dispatch_due_devices")

    if enabled:
        assert queued == [str(device.id)]
        assert result == 1
    else:
        assert queued == []
        assert result == {"status": "module_disabled", "module": "network.device"}


@pytest.mark.asyncio
async def test_queued_snmp_poll_does_not_reach_the_device_after_disable(
    db_session: AsyncSession,
) -> None:
    """A poll queued before the toggle must not run after it. The device's
    poll stamp is the evidence: a poll that ran (even one that failed to
    reach 10.9.0.1) records an attempt; a skipped one leaves the row alone."""
    device = await _due_device(db_session)
    await _set_module(db_session, "network.device", False)

    result = await _run_task("app.tasks.snmp_poll.poll_device", str(device.id))

    assert result == {"status": "module_disabled", "module": "network.device"}
    await db_session.refresh(device)
    assert device.last_poll_at is None


# ── nmap auto-profile hook + per-address profile route (tools.nmap) ──


async def _profiled_subnet(db: AsyncSession) -> tuple[Subnet, IPAddress]:
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.77.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.77.1.0/24",
        name="clients",
        auto_profile_on_dhcp_lease=True,
    )
    db.add(subnet)
    await db.flush()
    ip = IPAddress(subnet_id=subnet.id, address="10.77.1.50", status="allocated")
    db.add(ip)
    await db.flush()
    return subnet, ip


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled", [False, True])
async def test_dhcp_lease_auto_profile_scans_nothing_with_nmap_off(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, enabled: bool
) -> None:
    from app.services.profiling.auto_profile import maybe_enqueue_for_lease
    from app.tasks import nmap as nmap_tasks

    subnet, ip = await _profiled_subnet(db_session)
    await _set_module(db_session, "tools.nmap", enabled)

    dispatched: list[str] = []
    monkeypatch.setattr(nmap_tasks.run_scan_task, "delay", lambda sid: dispatched.append(sid))

    scan = await maybe_enqueue_for_lease(db_session, subnet=subnet, ipam_row=ip)
    rows = (await db_session.execute(select(func.count(NmapScan.id)))).scalar_one()

    if enabled:
        assert scan is not None
        assert dispatched == [str(scan.id)]
        assert rows == 1
    else:
        assert scan is None
        assert dispatched == []
        assert rows == 0


async def _superadmin_headers(db: AsyncSession) -> dict[str, str]:
    pw_kwargs = {"hashed_" + "password": hash_password("".join(["te", "st-pw"]))}
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="T",
        is_superadmin=True,
        **pw_kwargs,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled", [False, True])
async def test_profile_route_404s_with_nmap_off(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    enabled: bool,
) -> None:
    from app.tasks import nmap as nmap_tasks

    headers = await _superadmin_headers(db_session)
    _subnet, ip = await _profiled_subnet(db_session)
    await _set_module(db_session, "tools.nmap", enabled)

    dispatched: list[str] = []
    monkeypatch.setattr(nmap_tasks.run_scan_task, "delay", lambda sid: dispatched.append(sid))

    r = await client.post(f"/api/v1/ipam/addresses/{ip.id}/profile", json={}, headers=headers)
    rows = (await db_session.execute(select(func.count(NmapScan.id)))).scalar_one()

    if enabled:
        assert r.status_code == 202, r.text
        assert len(dispatched) == 1
        assert rows == 1
    else:
        assert r.status_code == 404, r.text
        assert dispatched == []
        assert rows == 0


# ── Every task the issue named: the body is never entered while off ──

# (task, module that owns it, module attribute holding the task's body).
# Patching the body is how "did any work" is observed for tasks whose real
# work is an off-prem call (RDAP, RPKI, RIPEstat) or a probe that the test
# environment cannot make; the SNMP and nmap tests above assert on real
# rows end to end.
_NAMED_TASKS = [
    ("app.tasks.tls_certs.probe_due_certs", "security.tls_certs", "_probe_due_async"),
    ("app.tasks.tls_certs.reconcile_discovered", "security.tls_certs", "_reconcile_async"),
    ("app.tasks.conformity.evaluate_conformity", "compliance.conformity", "_run"),
    ("app.tasks.asn_whois_refresh.refresh_due_asns", "network.asn", "_run_refresh"),
    ("app.tasks.rpki_roa_refresh.refresh_due_roas", "network.asn", "_run_refresh"),
    ("app.tasks.bgp_hijack_poll.poll_bgp_hijacks", "network.asn", "_run_poll"),
    # Not mirrored into PlatformSettings by the module toggle, so its own
    # integration_fortinet_enabled flag could stay on with the module off.
    ("app.tasks.fortinet_sync.sweep_fortinet_firewalls", "integrations.fortinet", "_run_sweep"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize(("task_name", "module_id", "body"), _NAMED_TASKS)
async def test_named_task_does_no_work_with_its_module_off(
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    task_name: str,
    module_id: str,
    body: str,
    enabled: bool,
) -> None:
    task_module = importlib.import_module(task_name.rsplit(".", 1)[0])
    calls: list[int] = []

    async def _recorder(*_a: Any, **_kw: Any) -> dict[str, str]:
        calls.append(1)
        return {"status": "ran"}

    monkeypatch.setattr(task_module, body, _recorder)
    await _set_module(db_session, module_id, enabled)

    result = await _run_task(task_name)

    if enabled:
        assert calls == [1]
    else:
        assert calls == []
        assert result == {"status": "module_disabled", "module": module_id}


@pytest.mark.asyncio
async def test_disabled_parent_module_gates_a_child_task(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``security.dns_threat`` requires ``core.dns`` (#1068). Turning only the
    parent off must stop the child's task, though the child has no row."""
    from app.tasks import dns_threat

    calls: list[int] = []

    async def _recorder() -> dict[str, str]:
        calls.append(1)
        return {"status": "ran"}

    monkeypatch.setattr(dns_threat, "_run", _recorder)
    await _set_module(db_session, "core.dns", False)

    result = await _run_task("app.tasks.dns_threat.aggregate_dns_client_windows")

    assert calls == []
    assert result == {"status": "module_disabled", "module": "security.dns_threat"}


# ── Structural guard: no beat task ships ungated by omission ─────────


def _beat_task_names() -> set[str]:
    celery_app.loader.import_default_modules()
    return {entry["task"] for entry in celery_app.conf.beat_schedule.values()}


def test_every_beat_task_is_gated_or_explicitly_allowlisted() -> None:
    names = _beat_task_names()
    assert names, "beat schedule is empty — the guard would pass vacuously"

    unregistered = sorted(n for n in names if n not in celery_app.tasks)
    assert not unregistered, f"beat schedule names unregistered tasks: {unregistered}"

    gated: dict[str, str] = {}
    for name in names:
        gate = getattr(celery_app.tasks[name].run, "__module_gate__", None)
        if gate is not None:
            gated[name] = gate

    missing = sorted(n for n in names if n not in gated and n not in UNGATED_BEAT_TASKS)
    assert not missing, (
        "beat tasks with no feature-module gate and no allowlist entry. Add "
        "@module_gated('<module>') under @celery_app.task, or an entry in "
        f"app.tasks.module_gate.UNGATED_BEAT_TASKS saying why it runs regardless: {missing}"
    )

    both = sorted(set(gated) & set(UNGATED_BEAT_TASKS))
    assert not both, f"gated AND allowlisted — drop the allowlist entry: {both}"

    stale = sorted(set(UNGATED_BEAT_TASKS) - names)
    assert not stale, f"allowlist names tasks no longer in the beat schedule: {stale}"

    empty_reason = sorted(n for n, why in UNGATED_BEAT_TASKS.items() if not why.strip())
    assert not empty_reason, f"allowlist entries need a reason: {empty_reason}"

    unknown = sorted(f"{n} → {m}" for n, m in gated.items() if not feature_modules.is_known(m))
    assert not unknown, f"gated on unknown module ids: {unknown}"


def test_the_tasks_named_in_2279_are_gated_on_their_module() -> None:
    _beat_task_names()
    expected = {
        "app.tasks.snmp_poll.dispatch_due_devices": "network.device",
        "app.tasks.tls_certs.probe_due_certs": "security.tls_certs",
        "app.tasks.conformity.evaluate_conformity": "compliance.conformity",
        "app.tasks.asn_whois_refresh.refresh_due_asns": "network.asn",
        "app.tasks.rpki_roa_refresh.refresh_due_roas": "network.asn",
    }
    actual = {
        name: getattr(celery_app.tasks[name].run, "__module_gate__", None) for name in expected
    }
    assert actual == expected
