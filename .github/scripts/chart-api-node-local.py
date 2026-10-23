#!/usr/bin/env python3
"""The api Service keeps each node's callers on that node's api pod, on the
appliance and nowhere else (#1805).

The supervisor's heartbeat, the DNS and DHCP agents and the frontend's
``/api`` proxy all reach the api through its ClusterIP Service. By default
kube-proxy spreads each new connection over every api pod. After a node's
hard loss, that node's api pod stays an endpoint until the node reads
NotReady (about 40 s), so a share of every other node's requests lands on a
pod that never answers. A heartbeat waits out its whole 40 s timeout there,
and two such waits in a row left a healthy node's heartbeat past the demote
guard's 90 s. ``trafficDistribution: PreferSameNode`` keeps a node's
connections on its own api pod while that pod is ready.

The appliance runs one api pod per control-plane node and sets the value in
its own values (firstboot's HelmChart and the supervisor's HelmChartConfig).
The umbrella chart's default is ``""``: on a BYO-Kubernetes cluster the field
would pin each node's callers to whichever api pod shares their node.

Checks every rendered file for Services labelled
``app.kubernetes.io/component: api``. By default it fails any whose
``spec.trafficDistribution`` is not ``PreferSameNode`` (a render with the
appliance's values). ``--absent`` fails any that carries the field at all
(the default render, which must stay as it was before #1805, and a render
below Kubernetes 1.34, where the API server refuses ``PreferSameNode`` and the
template must omit it).

``--require`` additionally fails when no api Service was checked at all, so
a dedicated render cannot silently stop exercising the template.

Usage: chart-api-node-local.py [--require] [--absent]
           <manifest.yaml> [<manifest.yaml> ...]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

WANT = "PreferSameNode"


def _is_api_service(doc: dict) -> bool:
    if doc.get("kind") != "Service":
        return False
    labels = (doc.get("metadata") or {}).get("labels") or {}
    return labels.get("app.kubernetes.io/component") == "api"


def check(path: Path, absent: bool) -> tuple[list[str], int]:
    problems = []
    checked = 0
    for doc in yaml.safe_load_all(path.read_text()):
        if not isinstance(doc, dict) or not _is_api_service(doc):
            continue
        checked += 1
        name = (doc.get("metadata") or {}).get("name", "<unnamed>")
        got = (doc.get("spec") or {}).get("trafficDistribution")
        if absent and got is not None:
            problems.append(
                f"{path}: Service {name!r} renders trafficDistribution {got}, "
                "which this render must omit: the umbrella default leaves it to "
                "the appliance, and below Kubernetes 1.34 the API server refuses "
                "it (#1805)"
            )
        if not absent and got != WANT:
            problems.append(
                f"{path}: Service {name!r} has trafficDistribution "
                f"{got or 'unset'}, expected {WANT} with the appliance's values: "
                "a lost node's api pod would hold other nodes' requests until "
                "their timeout (#1805)"
            )
    return problems, checked


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", help="rendered manifests")
    parser.add_argument("--require", action="store_true")
    parser.add_argument("--absent", action="store_true")
    args = parser.parse_args(argv)

    problems: list[str] = []
    checked = 0
    for arg in args.files:
        found, n = check(Path(arg), args.absent)
        problems += found
        checked += n
    if args.require and not checked:
        problems.append("no api Service was checked")
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    if not problems:
        state = "omit trafficDistribution" if args.absent else f"carry {WANT}"
        print(f"   api Services {state} ({checked} checked)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
