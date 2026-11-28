"""Celery tasks audit the operator-visible state they mutate (#1257).

Non-negotiable #4 was only enforced on request handlers. Each test runs the
real task body against a real database and asserts on the ``audit_log`` row
it leaves behind; the last test is the guard that fails when a task module
mutates without any audit path.
"""

from __future__ import annotations

import hashlib
import os
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import APPLIANCE_STATE_REVOKED, Appliance
from app.models.audit import AuditLog
from app.models.dhcp import DHCPLease
from app.models.dns import DNSBlockList
from app.models.ipam import IPAddress
from tests.test_blocklist_feed_refresh_bounded import _make_list, _wire
from tests.test_lease_sweep_lock_order_3605 import _group_with_two_servers


async def _audit(db: AsyncSession, action: str) -> list[AuditLog]:
    rows = await db.execute(
        select(AuditLog).where(AuditLog.action == action).execution_options(populate_existing=True)
    )
    return list(rows.scalars().all())


@pytest.mark.asyncio
async def test_lease_expiry_sweep_writes_one_summary_audit_row(db_session: AsyncSession) -> None:
    from app.tasks import dhcp_lease_cleanup

    subnet, a, _b = await _group_with_two_servers(db_session)
    past = datetime.now(UTC) - timedelta(hours=1)
    for n in range(3):
        ip = f"10.31.1.{80 + n}"
        db_session.add(
            DHCPLease(
                server_id=a.id,
                ip_address=ip,
                mac_address=f"aa:bb:cc:12:57:{n:02x}",
                state="active",
                expires_at=past,
            )
        )
        db_session.add(
            IPAddress(subnet_id=subnet.id, address=ip, status="dhcp", auto_from_lease=True)
        )
    await db_session.commit()

    assert await dhcp_lease_cleanup._sweep() == (3, 0)

    rows = await _audit(db_session, "dhcp-lease-expiry-sweep")
    assert len(rows) == 1  # one per run, not one per address
    assert rows[0].auth_source == "system"
    assert rows[0].new_value["ipam_rows_removed"] == 3
    assert sorted(rows[0].new_value["addresses"]) == ["10.31.1.80", "10.31.1.81", "10.31.1.82"]


@pytest.mark.asyncio
async def test_lease_expiry_sweep_with_nothing_to_do_writes_no_audit_row(
    db_session: AsyncSession,
) -> None:
    from app.tasks import dhcp_lease_cleanup

    assert await dhcp_lease_cleanup._sweep() == (0, 0)
    assert await _audit(db_session, "dhcp-lease-expiry-sweep") == []


@pytest.mark.asyncio
async def test_revoked_appliance_prune_is_audited(db_session: AsyncSession) -> None:
    from app.tasks.prune_revoked_appliances import _sweep

    der = os.urandom(32)
    db_session.add(
        Appliance(
            id=uuid.uuid4(),
            hostname="gone-1257",
            public_key_der=der,
            public_key_fingerprint=hashlib.sha256(der).hexdigest(),
            state=APPLIANCE_STATE_REVOKED,
            revoked_at=datetime.now(UTC) - timedelta(days=400),
        )
    )
    await db_session.commit()

    assert (await _sweep())["removed"] == 1
    rows = await _audit(db_session, "appliance-prune-revoked")
    assert len(rows) == 1
    assert rows[0].new_value["removed"] == 1


@pytest.mark.asyncio
async def test_pairing_code_prune_is_audited(db_session: AsyncSession) -> None:
    from app.tasks.prune_pairing_codes import _sweep
    from tests.test_prune_pairing_codes import _code

    db_session.add(_code(revoked_at=datetime.now(UTC) - timedelta(days=30)))
    await db_session.commit()

    assert (await _sweep())["revoked_removed"] == 1
    rows = await _audit(db_session, "pairing-code-prune")
    assert len(rows) == 1
    assert rows[0].new_value["revoked_removed"] == 1

    # A run that removes nothing leaves no further row.
    await _sweep()
    assert len(await _audit(db_session, "pairing-code-prune")) == 1


@pytest.mark.asyncio
async def test_blocklist_feed_refresh_is_audited_only_when_it_changes_entries(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.tasks import dns as dns_tasks

    bl = await _make_list(db_session)
    await db_session.commit()
    _wire(monkeypatch, db_session, "a.example\nb.example\n")

    await dns_tasks._refresh_blocklist_feed_async(str(bl.id))
    rows = await _audit(db_session, "dns-blocklist-feed-refresh")
    assert len(rows) == 1
    assert rows[0].resource_id == str(bl.id)
    assert rows[0].new_value["added"] == 2

    # Same feed again: nothing changed, so nothing to audit.
    await dns_tasks._refresh_blocklist_feed_async(str(bl.id))
    assert len(await _audit(db_session, "dns-blocklist-feed-refresh")) == 1
    assert (await db_session.get(DNSBlockList, bl.id)) is not None


# Task modules that write rows but carry no audit path, each with why. A module
# not listed here must reference the audit log, or the guard below fails.
_NOT_AUDITED: dict[str, str] = {
    "acme.py": "order rows are internal state; the cert swap is audited in acme_client.orchestrator",
    "agent_bundles.py": "rebuilds a derived config cache; the mutation that caused it was audited",
    "bgp_hijack_poll.py": "records observed events (monitor output), not operator state",
    "dhcp_lease_history_prune.py": "retention pruning of history rows",
    "looking_glass.py": "records observed BGP state from collectors (read-only mirror)",
    "pcap.py": "capture job lifecycle; start/stop are audited by the API handlers",
    "prune_e911_resolution_log.py": "retention pruning of a log table",
    "prune_internal_errors.py": "retention pruning of a log table",
    "prune_logs.py": "retention pruning of log tables",
    "prune_metrics.py": "retention pruning of metric samples",
    "prune_multicast_memberships.py": "retention pruning of observed memberships",
    "subnet_utilization_snapshot.py": "derived time-series samples",
}
_MUTATES = re.compile(r"\bdb\.delete\(|session\.delete\(|\bdelete\(|\bupdate\(|\.add\(|insert\(")


def test_every_task_module_that_writes_has_an_audit_path() -> None:
    tasks_dir = Path(__file__).resolve().parent.parent / "app" / "tasks"
    unaudited = []
    for path in sorted(tasks_dir.glob("*.py")):
        src = path.read_text()
        if _MUTATES.search(src) and not re.search(r"AuditLog|audit|add_system_audit", src):
            unaudited.append(path.name)
    stale = sorted(set(_NOT_AUDITED) - set(unaudited))
    new = sorted(set(unaudited) - set(_NOT_AUDITED))
    assert not new, (
        f"task modules write rows with no audit path: {new}. Audit the mutation (one summary "
        "row per run, app.tasks._system_audit.add_system_audit) or add the module to "
        "_NOT_AUDITED with the reason (#1257, non-negotiable #4)."
    )
    assert not stale, f"_NOT_AUDITED lists modules that now audit or no longer write: {stale}"
