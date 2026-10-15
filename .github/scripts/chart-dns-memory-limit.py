#!/usr/bin/env python3
"""A BIND9 DNS agent container must carry a memory limit of at least 1Gi (#1725).

named loads every RPZ zone into memory (about 1.4 kB per entry per zone,
measured) and the agent builds the zones beside it. One ~580k-entry catalog
blocklist in a group with a view took an unlimited ``dns-bind9`` pod to
2.8-3.6 GB, which on a 6 GiB node pushed the node under the kubelet's
eviction threshold: the worker, Postgres and the api were evicted, and then
named was OOM-killed. Without a limit the pod's overload is the node's;
with one it is the pod's own.

The floor (1Gi) is deliberately below the shipped default (2Gi): the check
exists so a values typo or a dropped ``resources`` guard cannot quietly
restore "no limit", not to second-guess an operator's sizing.

Checks every Pod template container named ``dns-bind9`` (the appliance
DaemonSet) or ``dns`` (the umbrella chart's per-server StatefulSet).
``--require`` additionally fails when none was found, so the render in
charts-render-check.sh cannot silently stop exercising the templates.

Usage: chart-dns-memory-limit.py [--require] <manifest.yaml> [...]
"""

from __future__ import annotations

import argparse
import re
import sys
from typing import Any

import yaml

_NAMES = {"dns-bind9", "dns"}
_MIN_BYTES = 1 << 30
_UNITS = {
    "": 1, "k": 10**3, "M": 10**6, "G": 10**9, "T": 10**12,
    "Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30, "Ti": 1 << 40,
}  # fmt: skip


def parse_quantity(value: Any) -> int | None:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([A-Za-z]*)", str(value).strip())
    if not m or m.group(2) not in _UNITS:
        return None
    return int(float(m.group(1)) * _UNITS[m.group(2)])


def check(docs: list[Any]) -> tuple[list[str], int]:
    problems: list[str] = []
    seen = 0
    for doc in docs:
        if not isinstance(doc, dict) or doc.get("kind") not in {"DaemonSet", "StatefulSet", "Deployment"}:
            continue
        pod = ((doc.get("spec") or {}).get("template") or {}).get("spec") or {}
        for c in pod.get("containers") or []:
            if c.get("name") not in _NAMES:
                continue
            seen += 1
            where = f"{doc['kind']}/{doc['metadata'].get('name', '?')} container {c['name']}"
            limit = ((c.get("resources") or {}).get("limits") or {}).get("memory")
            if limit is None:
                problems.append(f"{where}: no memory limit (#1725)")
                continue
            got = parse_quantity(limit)
            if got is None or got < _MIN_BYTES:
                problems.append(f"{where}: memory limit {limit} is below 1Gi (#1725)")
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
        problems.append("no dns-bind9 / dns container rendered; the check exercised nothing")
    for line in problems:
        print(line, file=sys.stderr)
    if seen and not problems:
        print(f"   BIND9 memory limit: {seen} container(s) carry one of at least 1Gi")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
