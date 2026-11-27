"""Per-disk SMART / wear on the Fleet view and in the alert framework (#4731).

The supervisor reports a reduced ``smartctl`` reading per disk inside
``cluster_health["disk_health"]``; ``services/appliance/disk_health`` is the
one classifier behind the Fleet chip, the two alert rules and the copilot
tool. The cases that matter: a VM's SMART-less disk is "not available" and
never healthy, an old supervisor is UNKNOWN and never an alarm, and a reading
that vanishes holds an open alert instead of announcing a recovery.
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.alerts import AlertEvent, AlertRule
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.auth import User
from app.services import alerts as alerts_svc
from app.services.appliance import disk_health as dh


def _disk(name: str = "sda", **over: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "name": name,
        "model": "ACME SSD",
        "serial": "S1",
        "firmware": "1.0",
        "protocol": "ata",
        "size_bytes": 480_000_000_000,
        "smart_available": True,
        "smart_passed": True,
        "temperature_c": 31,
        "power_on_hours": 1000,
        "percentage_used": 3,
        "available_spare": None,
        "available_spare_threshold": None,
        "media_errors": None,
        "reallocated_sectors": 0,
        "pending_sectors": 0,
    }
    row.update(over)
    return row


def _block(*disks: dict[str, Any], age: int = 60, smartctl: bool = True) -> dict[str, Any]:
    return {
        "smartctl_available": smartctl,
        "collected_at": int(time.time()) - age,
        "disks": list(disks),
    }


# ── classifier ──────────────────────────────────────────────────────


def test_healthy_disk_has_no_findings() -> None:
    assert dh.evaluate_disks(_block(_disk())) == []


def test_smart_failed_is_critical_and_belongs_to_the_smart_rule() -> None:
    f = dh.evaluate_disks(_block(_disk(smart_passed=False)))
    assert [(x.severity, x.rule, x.kind) for x in f] == [("critical", "smart", "smart_failed")]


def test_sectors_and_media_errors_are_warnings() -> None:
    f = dh.evaluate_disks(
        _block(_disk(pending_sectors=2, reallocated_sectors=8, media_errors=1, name="nvme0n1"))
    )
    assert {x.kind for x in f} == {"pending_sectors", "reallocated_sectors", "media_errors"}
    assert dh.worst_severity(f) == "warning"


def test_wear_threshold_and_exhausted_spare() -> None:
    assert dh.evaluate_disks(_block(_disk(percentage_used=89))) == []
    at90 = dh.evaluate_disks(_block(_disk(percentage_used=90)))
    assert [(x.rule, x.severity) for x in at90] == [("wear", "warning")]
    assert dh.evaluate_disks(_block(_disk(percentage_used=100)))[0].severity == "critical"
    assert dh.evaluate_disks(_block(_disk(percentage_used=50)), wear_threshold=40)
    spare = dh.evaluate_disks(_block(_disk(available_spare=5, available_spare_threshold=10)))
    assert [(x.kind, x.severity) for x in spare] == [("spare_low", "critical")]


def test_a_disk_that_hides_smart_is_not_available_and_not_a_finding() -> None:
    vm = _disk(
        "vda",
        smart_available=False,
        smart_passed=None,
        pending_sectors=None,
        reallocated_sectors=None,
        percentage_used=None,
    )
    block = _block(vm)
    assert dh.evaluate_disks(block) == []
    s = dh.summarise(block)
    assert (s["disk_count"], s["smart_available_count"], s["not_available_count"]) == (1, 0, 1)


def test_staleness_and_malformed_blocks() -> None:
    assert dh.is_current(_block())
    assert not dh.is_current(_block(age=dh.REPORT_MAX_AGE_SECONDS + 5))
    assert not dh.is_current(None)
    assert not dh.is_current({"disks": []})
    assert dh.evaluate_disks("garbage") == []
    assert dh.has_disk_report({"disk_health": {}}) is True
    assert dh.has_disk_report({"kubeapi_ready": True}) is False


def test_default_wear_threshold_matches_the_alert_module() -> None:
    assert alerts_svc.DEFAULT_DISK_WEAR_THRESHOLD == dh.DEFAULT_WEAR_THRESHOLD == 90


# ── alert matchers ──────────────────────────────────────────────────


async def _appliance(
    db: AsyncSession, hostname: str, block: dict | None, *, revoked: bool = False
) -> Appliance:
    der = os.urandom(32)
    ch: dict = {"kubeapi_ready": True}
    if block is not None:
        ch["disk_health"] = block
    row = Appliance(
        id=uuid.uuid4(),
        hostname=hostname,
        public_key_der=der,
        public_key_fingerprint=uuid.uuid4().hex * 2,
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        appliance_variant="control-plane",
        session_token_hash=uuid.uuid4().hex,
        cluster_health=ch,
        revoked_at=datetime.now(UTC) if revoked else None,
    )
    db.add(row)
    await db.flush()
    return row


def _rule(rule_type: str, threshold: int | None = None) -> AlertRule:
    return AlertRule(
        name=f"{rule_type} (test)",
        rule_type=rule_type,
        severity="warning",
        enabled=True,
        threshold_percent=threshold,
    )


@pytest.mark.asyncio
async def test_smart_matcher_fires_per_appliance_and_skips_the_rest(
    db_session: AsyncSession,
) -> None:
    bad = await _appliance(
        db_session, "ddi-bad", _block(_disk(smart_passed=False), _disk("sdb", pending_sectors=4))
    )
    await _appliance(db_session, "ddi-ok", _block(_disk()))
    await _appliance(db_session, "ddi-old", None)
    await _appliance(db_session, "ddi-gone", _block(_disk(smart_passed=False)), revoked=True)
    # A worn disk is the OTHER rule's business.
    await _appliance(db_session, "ddi-worn", _block(_disk(percentage_used=97)))
    await _appliance(
        db_session,
        "ddi-vm",
        _block(_disk("vda", smart_available=False, smart_passed=None, pending_sectors=None)),
    )
    rule = _rule(alerts_svc.RULE_TYPE_APPLIANCE_DISK_SMART_FAILING)
    matches = await alerts_svc._matching_appliance_disk_smart_subjects(
        db_session, rule
    )  # noqa: SLF001
    assert [(m[0], m[1], m[3]) for m in matches] == [(str(bad.id), "ddi-bad", "critical")]
    assert "FAILED" in matches[0][2] and "sda" in matches[0][2] and "sdb" in matches[0][2]


@pytest.mark.asyncio
async def test_wear_matcher_honours_the_rule_threshold(db_session: AsyncSession) -> None:
    worn = await _appliance(db_session, "ddi-worn", _block(_disk(percentage_used=92)))
    await _appliance(db_session, "ddi-mid", _block(_disk(percentage_used=60)))
    rt = alerts_svc.RULE_TYPE_APPLIANCE_DISK_WEAR_HIGH
    default = await alerts_svc._matching_appliance_disk_wear_subjects(  # noqa: SLF001
        db_session, _rule(rt)
    )
    assert [m[0] for m in default] == [str(worn.id)]
    lowered = await alerts_svc._matching_appliance_disk_wear_subjects(  # noqa: SLF001
        db_session, _rule(rt, 50)
    )
    assert len(lowered) == 2


@pytest.mark.asyncio
async def test_a_stale_reading_holds_the_open_event_and_opens_nothing(
    db_session: AsyncSession,
) -> None:
    stale = dh.REPORT_MAX_AGE_SECONDS + 600
    held = await _appliance(db_session, "ddi-held", _block(_disk(), age=stale))
    await _appliance(db_session, "ddi-quiet", _block(_disk(smart_passed=False), age=stale))
    rule = _rule(alerts_svc.RULE_TYPE_APPLIANCE_DISK_SMART_FAILING)
    db_session.add(rule)
    await db_session.flush()
    db_session.add(
        AlertEvent(
            rule_id=rule.id,
            subject_type="appliance",
            subject_id=str(held.id),
            subject_display="ddi-held",
            severity="critical",
            message="x",
            fired_at=datetime.now(UTC),
        )
    )
    await db_session.flush()
    matches = await alerts_svc._matching_appliance_disk_smart_subjects(
        db_session, rule
    )  # noqa: SLF001
    assert [(m[0], m[3]) for m in matches] == [(str(held.id), "critical")]
    assert "unknown is not recovered" in matches[0][2]


@pytest.mark.asyncio
async def test_rules_are_registered_seeded_disabled_and_idempotent(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert alerts_svc.RULE_TYPE_APPLIANCE_DISK_SMART_FAILING in alerts_svc.RULE_TYPES
    assert alerts_svc.RULE_TYPE_APPLIANCE_DISK_WEAR_HIGH in alerts_svc.RULE_TYPES
    await alerts_svc.seed_appliance_disk_health_alert_rules()
    await alerts_svc.seed_appliance_disk_health_alert_rules()
    rows = (
        (
            await db_session.execute(
                select(AlertRule).where(
                    AlertRule.rule_type.in_(
                        [
                            alerts_svc.RULE_TYPE_APPLIANCE_DISK_SMART_FAILING,
                            alerts_svc.RULE_TYPE_APPLIANCE_DISK_WEAR_HIGH,
                        ]
                    )
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 2
    assert all(r.enabled is False for r in rows)
    wear = next(r for r in rows if r.rule_type == alerts_svc.RULE_TYPE_APPLIANCE_DISK_WEAR_HIGH)
    assert wear.threshold_percent == 90


# ── copilot tool + Fleet API ────────────────────────────────────────


async def _admin_user(db: AsyncSession) -> User:
    u = User(
        username=f"sa-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="SA",
        hashed_password=hash_password("x"),
        auth_source="local",
        is_active=True,
        is_superadmin=True,
        force_password_change=False,
    )
    db.add(u)
    await db.flush()
    await db.refresh(u, ["groups"])
    return u


@pytest.mark.asyncio
async def test_copilot_tool_lists_problems_and_names_unreported_nodes(
    db_session: AsyncSession,
) -> None:
    from app.services.ai.tools.appliance import (
        FindApplianceDiskHealthArgs,
        find_appliance_disk_health,
    )

    await _appliance(db_session, "ddi-bad", _block(_disk(smart_passed=False)))
    await _appliance(db_session, "ddi-ok", _block(_disk()))
    await _appliance(db_session, "ddi-old", None)
    admin = await _admin_user(db_session)
    res = await find_appliance_disk_health(db_session, admin, FindApplianceDiskHealthArgs())
    assert [a["hostname"] for a in res["appliances"]] == ["ddi-bad"]
    assert res["not_reporting"] == ["ddi-old"]
    everything = await find_appliance_disk_health(
        db_session, admin, FindApplianceDiskHealthArgs(problems_only=False)
    )
    assert everything["count"] == 3


@pytest.mark.asyncio
async def test_copilot_tool_refuses_a_non_superadmin(db_session: AsyncSession) -> None:
    from app.services.ai.tools.appliance import (
        FindApplianceDiskHealthArgs,
        find_appliance_disk_health,
    )

    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="U",
        hashed_password="x",
        auth_source="local",
        is_active=True,
        is_superadmin=False,
        force_password_change=False,
    )
    db_session.add(u)
    await db_session.flush()
    await db_session.refresh(u, ["groups"])
    res = await find_appliance_disk_health(db_session, u, FindApplianceDiskHealthArgs())
    assert "error" in res and "appliances" not in res


@pytest.mark.asyncio
async def test_fleet_list_carries_the_disk_verdict(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin = await _admin_user(db_session)
    headers = {"Authorization": f"Bearer {create_access_token(str(admin.id))}"}
    await _appliance(db_session, "ddi-bad", _block(_disk(smart_passed=False)))
    await _appliance(db_session, "ddi-ok", _block(_disk()))
    await _appliance(
        db_session,
        "ddi-vm",
        _block(_disk("vda", smart_available=False, smart_passed=None, pending_sectors=None)),
    )
    await _appliance(db_session, "ddi-old", None)
    await _appliance(db_session, "ddi-stale", _block(_disk(), age=dh.REPORT_MAX_AGE_SECONDS + 600))
    await db_session.commit()
    resp = await client.get("/api/v1/appliance/appliances", headers=headers)
    assert resp.status_code == 200, resp.text
    by = {a["hostname"]: a for a in resp.json()["appliances"]}
    assert by["ddi-bad"]["disk_worst_severity"] == "critical"
    assert by["ddi-bad"]["disk_findings"][0]["kind"] == "smart_failed"
    assert by["ddi-ok"]["disk_reported"] and by["ddi-ok"]["disk_worst_severity"] is None
    assert by["ddi-ok"]["disk_smart_available_count"] == 1
    assert by["ddi-vm"]["disk_reported"] and by["ddi-vm"]["disk_smart_available_count"] == 0
    assert by["ddi-old"]["disk_reported"] is False
    assert by["ddi-stale"]["disk_reported"] is False


@pytest.mark.asyncio
async def test_fleet_list_is_refused_without_permission(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/appliance/appliances")
    assert resp.status_code in (401, 403)
