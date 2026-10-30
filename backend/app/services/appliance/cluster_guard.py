"""Guard for node-local appliance writes on a multi-node control plane."""

from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.appliance import CLUSTER_ROLES, Appliance


async def control_plane_node_count(db: AsyncSession) -> int:
    """Number of control-plane nodes (``cluster_role`` primary/member)."""
    return (
        await db.execute(
            select(func.count())
            .select_from(Appliance)
            .where(Appliance.cluster_role.in_(CLUSTER_ROLES))
        )
    ).scalar_one()


def clustered_refusal(action: str, nodes: int, alternative: str) -> str:
    return (
        f"{action} is unavailable on a clustered deployment: this endpoint "
        f"acts on whichever node serves the request ({settings.node_name or 'unknown'}), "
        f"not on one you can choose, and this cluster has {nodes} control-plane nodes. "
        + alternative
    )


async def reject_if_clustered(db: AsyncSession, action: str, alternative: str) -> None:
    """Refuse a node-local WRITE when this deployment has more than one
    control-plane node.

    Callers: slot apply / rollback (``slot.py``) and the local reboot
    (``system.py``, #3011). ``schedule_apply``/``schedule_rollback`` and
    ``request_reboot`` write trigger files into
    ``/var/lib/spatiumddi-host/release-state``, which is a hostPath on the
    node the responding pod happens to occupy. That is correct on a
    single-node appliance — there is exactly one node, and it is this one.
    On a cluster it is not: the api Deployment runs one replica per
    control-plane node behind a Service with no session affinity, so the
    node that receives this POST is chosen by the load balancer. The
    operator asks to upgrade an appliance and an arbitrary machine writes
    its inactive slot; addressing a node's own IP does not change that,
    because the IP selects an ingress, not a pod.

    A wrong-node upgrade is silent — 202 Accepted, a real upgrade, on a
    host nobody named — so this refuses rather than guesses. The
    per-appliance endpoints
    (``POST /appliance/appliances/{id}/upgrade``, ``/set-next-boot``,
    ``/set-default-slot``) are the node-addressed path: they stamp desired
    state on that appliance's row and the target node's own supervisor
    writes the trigger on its own disk.

    Counts CONTROL-PLANE nodes, not approved appliances: ``cluster_role`` is
    NULL for a data-plane appliance and for a single node that has not been
    promoted, and becomes primary/member only on promotion. That is the same
    quantity the api Deployment's replica count tracks, so it is exactly the
    condition that makes "which node answered?" ambiguous — a single-node
    control plane with paired data-plane appliances stays unambiguous and
    keeps working.
    """
    nodes = await control_plane_node_count(db)
    if nodes > 1:
        raise HTTPException(status.HTTP_409_CONFLICT, clustered_refusal(action, nodes, alternative))
