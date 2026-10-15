"""Node-local backup destinations on a multi-node appliance (#1838).

A ``local_volume`` target at the default path is the chart's ``backups``
hostPath, mounted on the api and the worker. On a multi-node appliance that
is one directory **per node**: an archive exists only on the disk of the node
whose pod wrote it, and the api replica that answers a request may be on a
different node. A restore, download or drill served there finds nothing.

Moving archives to a cluster-wide store is a network destination's job, so
this module makes the limit visible instead of hiding it:

* :func:`multi_node_warning` — Test connection says plainly that the target
  is per node, when the database says there is more than one control-plane
  node;
* :func:`miss_hint` — a "not found" names the node that answered and, when
  the run row recorded it, the node that holds the archive;
* :func:`listing_note` — a listing says whose view it is, and that the last
  run's archive is elsewhere rather than missing.

``BackupTarget.last_run_node`` is the one fact that is not a guess: the
runner stamps it from the writing pod's ``NODE_NAME``. A holder different
from the answering node proves a second node exists, so those messages need
no member count. Everything else is gated on :func:`control_plane_size`, so a
single-node appliance or a Compose install never sees a cluster caveat.

Removable disks are excluded: their own ``node_name`` config and
``_assert_removable_disk_present`` already say which node the disk is on.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    CLUSTER_ROLE_MEMBER,
    CLUSTER_ROLE_PRIMARY,
    Appliance,
)
from app.models.backup import BackupTarget
from app.services.appliance.removable import REMOVABLE_ROOT

NODE_LOCAL_KIND = "local_volume"

_REMEDY = (
    "Use an S3, SCP, SMB or NFS target for a cluster; a backup kept on one "
    "node is lost with that node."
)


def this_node() -> str:
    """The k8s node this pod runs on; empty off the appliance."""
    return (settings.node_name or "").strip()


def _is_removable(row: BackupTarget) -> bool:
    path = str((row.config or {}).get("path") or "")
    if not path.startswith("/"):
        return False
    root = Path(REMOVABLE_ROOT)
    p = Path(path)
    return p == root or root in p.parents


def applies(row: BackupTarget) -> bool:
    """True for a node-local target served by a pod that knows its node."""
    return row.kind == NODE_LOCAL_KIND and bool(this_node()) and not _is_removable(row)


async def control_plane_size(db: AsyncSession) -> int:
    """Settled control-plane nodes (the ones running an api and a worker).

    0 off the appliance, where no appliance row exists. Mirrors the count
    the supervisor heartbeat uses to size the control-plane workloads.
    """
    n = (
        await db.execute(
            select(func.count())
            .select_from(Appliance)
            .where(
                Appliance.state == APPLIANCE_STATE_APPROVED,
                Appliance.cluster_role.in_((CLUSTER_ROLE_PRIMARY, CLUSTER_ROLE_MEMBER)),
            )
        )
    ).scalar()
    return int(n or 0)


def _held_elsewhere(row: BackupTarget, filename: str | None) -> str | None:
    """The node holding ``filename`` when the run row says it is not this one."""
    holder = (row.last_run_node or "").strip()
    if not holder or holder == this_node():
        return None
    if filename is not None and filename != row.last_run_filename:
        return None
    return holder


def multi_node_warning(row: BackupTarget, cp_size: int) -> str | None:
    """Test-connection warning: this target is per node on this cluster."""
    if not applies(row) or cp_size < 2:
        return None
    path = (row.config or {}).get("path")
    return (
        f"This appliance has {cp_size} control-plane nodes, and a local volume is "
        f"per node: {path} is a separate directory on each one. This check ran on "
        f"node {this_node()}. An archive is written to the disk of whichever node "
        "runs the backup, and a restore, download or drill answered by another "
        f"node's api cannot see it. {_REMEDY}"
    )


def miss_hint(row: BackupTarget, filename: str, cp_size: int) -> str:
    """Appended to an archive "not found": where the archive probably is."""
    if not applies(row):
        return ""
    node = this_node()
    holder = _held_elsewhere(row, filename)
    if holder:
        return (
            f" It was written on node {holder}, and this request was answered by "
            f"the api on node {node}. A local volume is per node, so only node "
            f"{holder} has the file. Nothing was restored or changed. Copy it off "
            f"that node's disk and use Restore from file, or retry (the request "
            f"may reach node {holder}'s api). {_REMEDY}"
        )
    if cp_size < 2:
        return ""
    return (
        f" This request was answered by the api on node {node}. A local volume is "
        "per node on this cluster, so the archive may be on another node's disk; "
        "the pod name in the file name says which pod wrote it. Nothing was "
        f"restored or changed. {_REMEDY}"
    )


def listing_note(row: BackupTarget, filenames: Iterable[str], cp_size: int) -> str | None:
    """Say whose view a listing is, and where the last run's archive went."""
    if not applies(row):
        return None
    node = this_node()
    names = set(filenames)
    last = row.last_run_filename
    holder = _held_elsewhere(row, None)
    if row.last_run_status == "success" and last and last not in names and holder:
        return (
            f"This list is node {node}'s disk only. The last backup, {last}, was "
            f"written on node {holder} and is held there, not missing. {_REMEDY}"
        )
    if cp_size < 2:
        return None
    return (
        f"This list is node {node}'s disk only: a local volume is per node on this "
        f"{cp_size}-node cluster, so archives written on other nodes are not shown. "
        f"{_REMEDY}"
    )


def drill_note(row: BackupTarget, filenames: Iterable[str]) -> str | None:
    """Why a drill on this node cannot see the target's newest archive."""
    if not applies(row):
        return None
    last = row.last_run_filename
    holder = _held_elsewhere(row, None)
    if row.last_run_status != "success" or not last or last in set(filenames) or not holder:
        return None
    return (
        f"the target's newest archive, {last}, was written on node {holder} and this "
        f"drill ran on node {this_node()}; a local volume is per node, so it is not "
        f"visible here. {_REMEDY}"
    )
