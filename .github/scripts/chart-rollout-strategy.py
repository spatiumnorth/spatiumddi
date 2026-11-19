#!/usr/bin/env python3
"""Refuse a rendered Deployment whose rollout can wedge on its own anti-affinity (#590, #1541).

Required pod anti-affinity on ``kubernetes.io/hostname`` means one pod of a
component per node. A Deployment that surges first (``maxSurge > 0`` with
``maxUnavailable: 0``) then needs a free node for the incoming pod before it
may retire an outgoing one, and on an appliance, where the replica count is
the node count, there is none: the incoming pod sits Pending and the rollout
never progresses. So every Deployment whose pod template carries a required
anti-affinity term must retire first (``maxSurge: 0``) or use ``Recreate``.

That rule alone cannot see the #1541 case, because the term that blocks a
rollout can come from the pods being REPLACED rather than from the render: a
demote from three nodes to one renders ``replicas: 1`` with no anti-affinity
at all, while the one surviving old pod still carries the 3-node term, which
is symmetric and keeps the new pod off the only node. ``--retire-first
COMPONENT`` asserts that the named component's Deployment retires first in
this render whatever its own affinity says; it fails closed when the render
has no such Deployment, because a guard that cannot find its subject must
not read as a pass.

Reads one or more ``helm template`` streams (files, or ``-`` for stdin).
Exit 0 when every Deployment holds; exit 1 with one line per failure.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable
from typing import Any

import yaml

_COMPONENT = "app.kubernetes.io/component"


def _docs(paths: Iterable[str]) -> Iterable[dict[str, Any]]:
    for path in paths:
        if path == "-":
            text = sys.stdin.read()
        else:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        for doc in yaml.safe_load_all(text):
            if isinstance(doc, dict):
                yield doc


def _required_anti_affinity(dep: dict[str, Any]) -> bool:
    spec = ((dep.get("spec") or {}).get("template") or {}).get("spec") or {}
    anti = (spec.get("affinity") or {}).get("podAntiAffinity") or {}
    return bool(anti.get("requiredDuringSchedulingIgnoredDuringExecution"))


def retires_first(dep: dict[str, Any]) -> bool:
    """True when the rollout removes an old pod before it adds a new one."""
    strategy = (dep.get("spec") or {}).get("strategy") or {}
    if strategy.get("type") == "Recreate":
        return True
    rolling = strategy.get("rollingUpdate") or {}
    # Kubernetes' defaults are 25% / 25%: a surge, so an absent field is not
    # a retire-first strategy.
    surge = rolling.get("maxSurge", "25%")
    unavailable = rolling.get("maxUnavailable", "25%")
    return str(surge) in ("0", "0%") and str(unavailable) not in ("0", "0%")


def check(paths: Iterable[str], retire_first: Iterable[str]) -> list[str]:
    wanted = set(retire_first)
    seen: set[str] = set()
    failures: list[str] = []
    for doc in _docs(paths):
        if doc.get("kind") != "Deployment":
            continue
        meta = doc.get("metadata") or {}
        name = str(meta.get("name") or "?")
        component = str((meta.get("labels") or {}).get(_COMPONENT) or "")
        if component in wanted:
            seen.add(component)
            if not retires_first(doc):
                failures.append(
                    f"{name}: component {component!r} must retire an old pod before "
                    "adding a new one (maxSurge 0 or Recreate); its outgoing pods may "
                    "carry a required anti-affinity term the new one cannot pass"
                )
                continue
        if _required_anti_affinity(doc) and not retires_first(doc):
            failures.append(
                f"{name}: required podAntiAffinity with a surge-first strategy wedges "
                "the rollout once replicas == nodes (use maxSurge 0 or Recreate)"
            )
    for component in sorted(wanted - seen):
        failures.append(f"no Deployment with component {component!r} in the render")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--retire-first", action="append", default=[], metavar="COMPONENT")
    parser.add_argument("files", nargs="+")
    args = parser.parse_args(argv)
    failures = check(args.files, args.retire_first)
    for line in failures:
        print(f"rollout-strategy: {line}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
