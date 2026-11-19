#!/usr/bin/env python3
"""A DNS serving container with a liveness probe must carry a startup probe (#2223).

The DNS containers' liveness probe checks that the daemon listens on :53. A
cold start renders and checks every zone before the daemon starts, which at
20,000 zones takes tens of minutes; with liveness running from 30 s after
the container started, a restarted container was killed before named was
up, every time, and never came back (5 of 7 nodes in CrashLoopBackOff in
ddi-pg's scale lab). Kubernetes holds liveness back until a startup probe
has passed once, so the startup probe's budget is what a cold start gets.

The floor (30 min) is deliberately below the shipped default (60 min): the
check exists so a dropped template block or a values typo cannot quietly
restore the 2-minute window, not to second-guess an operator's sizing.

Checks every Pod template container named ``dns-bind9`` / ``dns-powerdns`` /
``dns-technitium`` (the appliance DaemonSets) or ``dns`` (the umbrella
chart's per-server StatefulSet). ``--require`` additionally fails when none
with a liveness probe was found, so a render cannot silently stop
exercising the templates.

Usage: chart-dns-startup-probe.py [--require] <manifest.yaml> [...]
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

import yaml

_NAMES = {"dns-bind9", "dns-powerdns", "dns-technitium", "dns"}
_MIN_BUDGET_SECONDS = 30 * 60


def check(docs: list[Any]) -> tuple[list[str], int]:
    problems: list[str] = []
    seen = 0
    for doc in docs:
        if not isinstance(doc, dict) or doc.get("kind") not in {"DaemonSet", "StatefulSet", "Deployment"}:
            continue
        pod = ((doc.get("spec") or {}).get("template") or {}).get("spec") or {}
        for c in pod.get("containers") or []:
            if c.get("name") not in _NAMES or not c.get("livenessProbe"):
                continue
            seen += 1
            where = f"{doc['kind']}/{doc['metadata'].get('name', '?')} container {c['name']}"
            probe = c.get("startupProbe")
            if not probe:
                problems.append(f"{where}: liveness probe with no startup probe (#2223)")
                continue
            # Kubernetes' own defaults when a field is absent.
            budget = int(probe.get("periodSeconds", 10)) * int(probe.get("failureThreshold", 3))
            if budget < _MIN_BUDGET_SECONDS:
                problems.append(
                    f"{where}: startup probe allows {budget} s, below {_MIN_BUDGET_SECONDS} s (#2223)"
                )
    return problems, seen


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--require", action="store_true")
    ap.add_argument("files", nargs="+")
    args = ap.parse_args()
    problems: list[str] = []
    seen = 0
    for path in args.files:
        with open(path, encoding="utf-8") as fh:
            p, n = check(list(yaml.safe_load_all(fh)))
        problems += [f"{path}: {line}" for line in p]
        seen += n
    if args.require and not seen:
        problems.append("no DNS container with a liveness probe rendered; the check exercised nothing")
    for line in problems:
        print(line, file=sys.stderr)
    if seen and not problems:
        print(f"   DNS startup probe: {seen} container(s) carry one of at least 30 min")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
