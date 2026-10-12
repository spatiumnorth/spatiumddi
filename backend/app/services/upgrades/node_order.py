"""Rolling-upgrade node ordering (#296 Phase D).

Decides which node the orchestrator drives next. Phase D v0 ships an
alphabetical default + a "skip-already-upgraded" filter; the VIP-host
+ DNS-speaker-aware ordering called out in the issue body lives as a
follow-up — it's an operator-UX polish (avoid leaving the VIP-
announcing node for last so the operator's browser doesn't blip mid-
upgrade) that's cleaner to land once Phase G's UI surfaces the order
for inspection.

A future ordering pass might consider:

* Sort the VIP-announcing node to a middle position (not first, so we
  have a chance to fail fast on the spine of the cluster; not last,
  so the operator's browser hits a settled VIP at the end).
* Sort DNS-speaker nodes evenly across the sequence so we never go
  through a stretch where only one DNS node is serving.
* Prefer nodes the operator has tagged ``upgrade-priority=high`` /
  ``low`` for staggered rollouts (Phase H-adjacent).

Today none of these apply — alphabetical is simple, deterministic,
and gives the operator a predictable order they can preview in the
plan endpoint.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def pick_node_order(
    nodes: Iterable[dict[str, Any]],
    *,
    exclude: Iterable[str] | None = None,
) -> list[str]:
    """Return the order in which nodes should be upgraded.

    ``nodes`` is the raw kubeapi NodeList ``items`` array (each entry
    has ``metadata.name``); ``exclude`` is a list of node names already
    processed (resuming an in-flight upgrade hands us those).

    Sort key is the node name, case-insensitive — same lexicographic
    order that ``kubectl get nodes`` shows by default, so the
    orchestrator's preview matches operator expectations.
    """
    skip = set(exclude or ())
    names: list[str] = []
    for node in nodes:
        meta = node.get("metadata") or {}
        name = meta.get("name")
        if not name or name in skip:
            continue
        names.append(name)
    names.sort(key=str.lower)
    return names


def next_node_to_upgrade(
    plan_order: list[str],
    completed_nodes: Iterable[str],
    *,
    defer: str | None = None,
) -> str | None:
    """Pick the next node from the plan that hasn't been completed yet.

    ``plan_order`` is the list returned by ``pick_node_order`` at plan
    time; ``completed_nodes`` is whatever the SystemUpgradeRun row's
    ``progress.per_node`` keys carry for runs that succeeded.

    ``defer`` names a node to take last: the node the drive's own worker
    runs on. Draining it evicts the worker running the drive, so it is
    upgraded only after every other node, by a drive handed to a worker
    elsewhere (#1449).

    Returns ``None`` when every node in the plan has completed — the
    orchestrator transitions to ``state='succeeded'`` then.
    """
    done = set(completed_nodes)
    remaining = [name for name in plan_order if name not in done]
    for name in remaining:
        if name != defer:
            return name
    return remaining[0] if remaining else None
