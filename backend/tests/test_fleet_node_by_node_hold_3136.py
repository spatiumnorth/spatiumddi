"""#3136 — a cluster upgraded node by node from Fleet holds the shared role chart too.

The ``spatiumddi-appliance`` HelmChart is one chart for the whole cluster, the
image tag it carries is the writer's own slot's, and every agent pod is
``imagePullPolicy: Never``. A Rolling Upgrade holds it (#1710): a node already
on the run's target writes nothing to it until every node reports the target.
Outside a run there was no hold. ddi-pg upgraded member-1 alone from Fleet
("Schedule OS upgrade", then its reboot): its first heartbeat on the new slot
rewrote the chart with its own tag, the seed's ``dhcp-kea`` and ``dns-bind9``
pods were deleted, their replacements sat in ErrImageNeverPull, and the seed
served no DHCP or DNS for 47 minutes, until its own upgrade had staged.

The contract:

* While the cluster's members report different installed versions, no member
  writes the shared role chart, so it stays on the tag every node is running.
  Each member is told so in its heartbeat as a hold that names the version it
  runs: the supervisor's own rule (a node already on the hold's target writes
  nothing) then defers it, on any supervisor that knows the hold (#1885).
* A member that Fleet has scheduled onto a version it does not run yet hears
  of the hold before its reboot. A fresh boot can apply the chart before its
  first heartbeat's reply (the watchdog pass reads only the kept hold), so the
  hold has to be on the node when it boots the new slot.
* Once every member reports one version there is no hold, and the next
  heartbeat writes the new chart.
* A member that is down counts at the version it last reported, until it is
  back and upgraded or replaced from Fleet.
* Same bytes are never held back: ddi-pg's node-by-node roll re-applies the
  version a node runs under a goal label, and nothing in it may defer.
* A Rolling Upgrade's own hold is unchanged and wins.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.versions import is_installed_target
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    APPLIANCE_STATE_PENDING_APPROVAL,
    Appliance,
)
from app.models.settings import PlatformSettings
from app.services.appliance.ca import generate_session_token

OLD = "2026.10.30-1"
NEW = "2026.10.31-1"
NIGHTLY = "0.0.0-nightly-20261030+0a0a2e8"


async def _row(
    db: AsyncSession,
    hostname: str,
    *,
    role: str | None = "member",
    installed: str | None = OLD,
    desired: str | None = None,
    state: str = APPLIANCE_STATE_APPROVED,
) -> tuple[Appliance, str]:
    """An appliance row with a session token, as a node of the cluster."""
    platform = await db.get(PlatformSettings, 1)
    if platform is None:
        platform = PlatformSettings(id=1)
        db.add(platform)
    platform.supervisor_registration_enabled = True
    token, token_hash = generate_session_token()
    der = os.urandom(32)
    row = Appliance(
        id=uuid.uuid4(),
        hostname=hostname,
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=state,
        deployment_kind="appliance",
        session_token_hash=token_hash,
        cluster_role=role,
        installed_appliance_version=installed,
    )
    if desired is not None:
        # What Fleet's "Schedule OS upgrade" stamps (stamp_desired_slot_image).
        row.desired_appliance_version = desired
        row.desired_slot_image_url = "https://control.example.test/slot.raw.xz"
        row.desired_slot_image_sha256 = "0" * 64
    db.add(row)
    await db.commit()
    return row, token


async def _heartbeat(
    client: AsyncClient, row: Appliance, token: str, *, installed: str | None = None
) -> Any:
    """One heartbeat (reporting ``installed`` when given); its ``shared_chart_hold``."""
    body: dict[str, Any] = {
        "appliance_id": str(row.id),
        "session_token": token,
        "capabilities": {"can_run_observer": True},
    }
    if installed is not None:
        body["installed_appliance_version"] = installed
    r = await client.post("/api/v1/appliance/supervisor/heartbeat", json=body)
    assert r.status_code == 200, r.text
    return r.json().get("shared_chart_hold")


def _refused(installed: str, hold: dict[str, str] | None) -> bool:
    """Would a supervisor on ``installed`` defer its role-chart write under ``hold``?

    The supervisor's rule (``shared_chart_hold_refusal``): only a node already on
    the hold's target writes nothing. The backend's twin of its comparator is
    held to the agent's copy by ``test_nightly_upgrade_cleared_3026.py``."""
    return bool(hold) and is_installed_target(installed, (hold or {}).get("target_version"))


# ── A node upgraded from Fleet, with no Rolling Upgrade running ─────────────


@pytest.mark.asyncio
async def test_a_member_on_a_new_version_is_held_while_the_others_run_the_old_one(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The case ddi-pg saw: member-1 upgraded alone from Fleet. Its first
    heartbeat on the new slot must not let it move the chart onto images only
    it has."""
    await _row(db_session, "seed", role="primary", installed=OLD)
    await _row(db_session, "member-2", installed=OLD)
    member_1, token = await _row(db_session, "member-1", installed=OLD)

    hold = await _heartbeat(client, member_1, token, installed=NEW)

    assert hold == {"run_id": "", "from_tag": OLD, "target_version": NEW}
    assert _refused(NEW, hold)


@pytest.mark.asyncio
async def test_the_members_still_on_the_old_version_write_nothing_either(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Every member is held while the versions differ: the chart then stays on
    the tag every node is running, whichever node was upgraded first."""
    seed, token = await _row(db_session, "seed", role="primary", installed=OLD)
    await _row(db_session, "member-1", installed=NEW)
    await _row(db_session, "member-2", installed=OLD)

    hold = await _heartbeat(client, seed, token, installed=OLD)

    assert hold == {"run_id": "", "from_tag": NEW, "target_version": OLD}
    assert _refused(OLD, hold)


@pytest.mark.asyncio
async def test_the_hold_ends_once_every_member_reports_one_version(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _row(db_session, "seed", role="primary", installed=OLD)
    await _row(db_session, "member-2", installed=OLD)
    member_1, token = await _row(db_session, "member-1", installed=NEW)
    assert await _heartbeat(client, member_1, token, installed=NEW) is not None

    # member-2 and then the seed upgraded the same way.
    await db_session.execute(
        update(Appliance)
        .where(Appliance.hostname.in_(("seed", "member-2")))
        .values(installed_appliance_version=NEW)
    )
    await db_session.commit()

    assert await _heartbeat(client, member_1, token, installed=NEW) is None


@pytest.mark.asyncio
async def test_a_member_that_is_down_on_the_old_version_keeps_the_hold(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A member that stopped heartbeating on the old version still counts, at
    the version it last reported, however long ago that was. It comes back on
    its old slot, and its agents can run only the old tag (they are
    ``imagePullPolicy: Never``): a chart moved while it was away would meet it
    with ErrImageNeverPull, #3136 again on that node. The price: no member
    writes the role chart until that member is back and upgraded, or replaced
    (Fleet's Replace, ``replace_control_plane_member``, clears its role at
    once, and a member with no role does not count)."""
    await _row(db_session, "seed", role="primary", installed=NEW)
    await _row(db_session, "member-2", installed=OLD)
    member_1, token = await _row(db_session, "member-1", installed=NEW)
    await db_session.execute(
        update(Appliance)
        .where(Appliance.hostname == "member-2")
        .values(last_seen_at=datetime.now(UTC) - timedelta(days=2))
    )
    await db_session.commit()

    hold = await _heartbeat(client, member_1, token, installed=NEW)

    assert hold == {"run_id": "", "from_tag": OLD, "target_version": NEW}
    assert _refused(NEW, hold)

    # Replaced from Fleet: the role goes at once, and so does the hold.
    await db_session.execute(
        update(Appliance).where(Appliance.hostname == "member-2").values(cluster_role=None)
    )
    await db_session.commit()

    assert await _heartbeat(client, member_1, token, installed=NEW) is None


@pytest.mark.asyncio
async def test_a_member_scheduled_from_fleet_hears_of_the_hold_before_its_reboot(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The hold must already be on the node when it boots the new slot: the
    first pass there can apply the chart before the first heartbeat's reply.
    Before the reboot it stops nothing: the node does not run NEW yet."""
    await _row(db_session, "seed", role="primary", installed=OLD)
    await _row(db_session, "member-2", installed=OLD)
    member_1, token = await _row(db_session, "member-1", installed=OLD, desired=NEW)

    hold = await _heartbeat(client, member_1, token, installed=OLD)

    assert hold == {"run_id": "", "from_tag": OLD, "target_version": NEW}
    assert not _refused(OLD, hold)
    assert _refused(NEW, hold)


@pytest.mark.asyncio
async def test_the_last_member_to_upgrade_is_not_held_once_it_runs_its_version(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _row(db_session, "seed", role="primary", installed=NEW)
    await _row(db_session, "member-2", installed=NEW)
    member_1, token = await _row(db_session, "member-1", installed=OLD, desired=NEW)

    assert await _heartbeat(client, member_1, token, installed=NEW) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("version", [OLD, NIGHTLY])
async def test_a_reapply_of_the_same_bytes_under_a_goal_label_is_never_held_back(
    client: AsyncClient, db_session: AsyncSession, version: str
) -> None:
    """ddi-pg's three-node walk re-applies the build every node runs, each
    node under a goal label of its own (``<version>+ha-roll-<node>``) so the
    apply is not taken for done. Every node keeps reporting the one version its
    slot carries, and the label never names a version a node runs: no node may
    defer its chart there."""
    await _row(db_session, "seed", role="primary", installed=version)
    await _row(db_session, "member-2", installed=version)
    member_1, token = await _row(
        db_session, "member-1", installed=version, desired=f"{version}+ha-roll-member1"
    )

    for _boot in range(2):  # before its reboot, and on the other slot after it
        hold = await _heartbeat(client, member_1, token, installed=version)
        assert not _refused(version, hold), hold


@pytest.mark.asyncio
async def test_a_single_node_is_never_held(client: AsyncClient, db_session: AsyncSession) -> None:
    seed, token = await _row(db_session, "seed", role="primary", installed=OLD, desired=NEW)

    assert await _heartbeat(client, seed, token, installed=OLD) is None
    assert await _heartbeat(client, seed, token, installed=NEW) is None


@pytest.mark.asyncio
async def test_an_appliance_outside_the_cluster_neither_holds_nor_is_held(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A branch DNS appliance runs its own k3s and its own chart: its version
    is nothing to the cluster's, and the cluster's is nothing to it."""
    await _row(db_session, "seed", role="primary", installed=OLD)
    await _row(db_session, "member-2", installed=OLD)
    member_1, token = await _row(db_session, "member-1", installed=OLD)
    remote, remote_token = await _row(db_session, "branch-dns-1", role=None, installed=NEW)

    assert await _heartbeat(client, member_1, token, installed=OLD) is None
    assert await _heartbeat(client, remote, remote_token, installed=NEW) is None


@pytest.mark.asyncio
async def test_a_member_that_never_reported_a_version_holds_nobody(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _row(db_session, "seed", role="primary", installed=OLD)
    await _row(db_session, "member-2", installed=None)
    member_1, token = await _row(db_session, "member-1", installed=OLD)

    assert await _heartbeat(client, member_1, token, installed=OLD) is None


@pytest.mark.asyncio
async def test_a_row_not_yet_approved_does_not_count(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _row(db_session, "seed", role="primary", installed=OLD)
    await _row(db_session, "member-2", installed=NEW, state=APPLIANCE_STATE_PENDING_APPROVAL)
    member_1, token = await _row(db_session, "member-1", installed=OLD)

    assert await _heartbeat(client, member_1, token, installed=OLD) is None


@pytest.mark.asyncio
async def test_a_rolling_upgrades_own_hold_is_unchanged(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """While a run holds, its hold is the answer, exactly as before: the
    run's nodes hear of it, and a node outside its plan does not, however the
    members' versions differ."""
    from app.models.system_upgrade import SystemUpgradeRun

    run = SystemUpgradeRun(
        kind="cluster_rolling",
        state="running",
        target_version=NEW,
        source_versions={},
        plan={"node_order": ["seed", "member-1"], "slot_image_url": "https://x.test/s.raw.xz"},
        progress={
            "per_node": {"member-1": {"ok": True}},
            "events": [],
            "shared_tags": {
                "mode": "hold",
                "from_tag": OLD,
                "from_version": OLD,
                "to_tag": NEW,
                "nodes": ["seed", "member-1"],
                "placed_at": "2026-10-31T06:00:00Z",
                "released_at": None,
                "release_reason": None,
            },
        },
        lease_holder="worker-a",
    )
    db_session.add(run)
    await db_session.commit()
    await _row(db_session, "seed", role="primary", installed=OLD)
    member_1, token = await _row(db_session, "member-1", installed=NEW)
    outside, outside_token = await _row(db_session, "member-2", installed=OLD)

    assert await _heartbeat(client, member_1, token, installed=NEW) == {
        "run_id": str(run.id),
        "from_tag": OLD,
        "target_version": NEW,
    }
    assert await _heartbeat(client, outside, outside_token, installed=OLD) is None
