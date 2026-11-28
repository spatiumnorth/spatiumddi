#!/usr/bin/env python3
"""Refuse a rendered chart where a container lists one env name twice (#4648).

``helm template`` and ``helm lint`` accept a duplicate ``env`` name, and so
does kubeconform; the k3s helm controller's server-side apply does not
("duplicate entries for key [name=...]"), so the workload is never created.
That is how the chart's always-on DNS_AGENT_KEY / DHCP_AGENT_KEY met the
appliance's own ``api.env`` copies and took every fresh install's api down.

Reads ``helm template`` streams; checks every container and init container in
every workload kind. A render with no workload (a Secret-only chart) passes trivially.
"""

from __future__ import annotations

import sys
from collections import Counter
from typing import Any

import yaml

_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}


def _pod_spec(doc: dict[str, Any]) -> dict[str, Any]:
    spec = doc.get("spec") or {}
    if doc["kind"] == "CronJob":
        spec = (spec.get("jobTemplate") or {}).get("spec") or {}
    return (spec.get("template") or {}).get("spec") or {}


def problems(docs: list[Any]) -> list[str]:
    out: list[str] = []
    for doc in docs:
        if not isinstance(doc, dict) or doc.get("kind") not in _KINDS:
            continue
        pod = _pod_spec(doc)
        for c in (pod.get("containers") or []) + (pod.get("initContainers") or []):
            counts = Counter(e.get("name", "") for e in c.get("env") or [])
            for name, n in sorted(counts.items()):
                if n > 1:
                    out.append(
                        f"{doc['kind']}/{doc['metadata']['name']} container "
                        f"{c.get('name')}: env {name} listed {n} times"
                    )
    return out


def main(argv: list[str]) -> int:
    bad: list[str] = []
    for path in argv:
        with open(path) as fh:
            bad += problems([d for d in yaml.safe_load_all(fh) if d])
    for line in bad:
        print(f"FAIL: {line}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: chart-env-unique.py RENDER.yaml...", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1:]))
