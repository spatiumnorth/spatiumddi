#!/usr/bin/env python3
"""The shipped static SCC manifests must equal what the chart renders (#3913).

``values-openshift-certified.yaml`` turns ``openshift.scc.create`` off, so a
cluster admin applies ``charts/spatiumddi/files/openshift/*-scc.yaml`` by hand
instead. Those files are copies of what the ``spatiumddi.openshiftScc`` helper
renders; this fails when they drift, i.e. when the helper gains a capability,
volume type or flag and the copy does not. Only ``metadata.name`` and
``metadata.labels`` may differ (the chart's names carry the release and the
namespace; the static ones are release-independent).

Usage:
    chart-openshift-scc-files.py STATIC_DIR PLAIN_RENDER HOSTNET_RENDER

PLAIN_RENDER: an OpenShift render with DNS + DHCP agents, no hostNetwork.
HOSTNET_RENDER: the same with a DHCP server on ``hostNetwork: true``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

PAIRS = (
    ("dns-agent-scc.yaml", "plain", "dns-agent"),
    ("dhcp-agent-scc.yaml", "plain", "dhcp-agent"),
    ("dhcp-agent-hostnetwork-scc.yaml", "hostnet", "dhcp-agent"),
)


def rendered_scc(path: str, component: str) -> dict:
    docs = [d for d in yaml.safe_load_all(open(path)) if d]
    found = [
        d
        for d in docs
        if d["kind"] == "SecurityContextConstraints"
        and d["metadata"]["labels"].get("app.kubernetes.io/component") == component
    ]
    if len(found) != 1:
        sys.exit(f"FAIL #3913: {path} renders {len(found)} {component} SCCs, want 1")
    return found[0]


def comparable(scc: dict) -> dict:
    scc = dict(scc)
    scc["metadata"] = {"annotations": scc["metadata"].get("annotations")}
    return scc


def main(argv: list[str]) -> int:
    static_dir, plain, hostnet = Path(argv[0]), argv[1], argv[2]
    renders = {"plain": plain, "hostnet": hostnet}
    failures = 0
    for fname, which, component in PAIRS:
        static = yaml.safe_load(open(static_dir / fname))
        chart = rendered_scc(renders[which], component)
        if comparable(static) != comparable(chart):
            print(f"FAIL #3913: {fname} differs from the chart's rendered SCC")
            for key in sorted(set(static) | set(chart)):
                a, b = comparable(static).get(key), comparable(chart).get(key)
                if a != b:
                    print(f"   {key}: static={a!r} chart={b!r}")
            failures += 1
        else:
            print(f"ok #3913: {fname} matches the chart's SCC")
    return 1 if failures else 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1:]))
