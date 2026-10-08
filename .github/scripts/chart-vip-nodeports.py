#!/usr/bin/env python3
"""MetalLB VIP Services must not allocate NodePorts (#1550).

A ``type: LoadBalancer`` Service allocates a NodePort for every port
unless ``allocateLoadBalancerNodePorts: false`` is set. The Services
fronted by MetalLB on purpose — the appliance chart's DNS VIPs and
DHCP relay VIP, and the umbrella chart's frontend control-plane VIP —
are announced by MetalLB in L2 or BGP mode, which never routes via
NodePorts. Each VIP port was therefore also opened as a random
NodePort on every node: an extra, unintended listener, and for the
non-hostNetwork DNS pods one served through the forward path rather
than the scoped input chain.

Checks the given files for those Services and fails any
``type: LoadBalancer`` one whose ``allocateLoadBalancerNodePorts``
is not ``false``. ClusterIP shapes of the same Services (the DNS VIP
toggle off) are ignored — the field only means anything on a
LoadBalancer.

``--require`` fails when no such LoadBalancer Service was checked at
all, so the dedicated renders in charts-render-check.sh cannot
silently stop exercising the templates.

Usage: chart-vip-nodeports.py [--require]
           <manifest.yaml> [<manifest.yaml> ...]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

APPLIANCE_VIP_SERVICES = {"dns-bind9", "dns-powerdns", "dns-technitium", "dhcp-kea-relay"}


def _is_vip_service(doc: dict) -> bool:
    meta = doc.get("metadata") or {}
    if meta.get("name") in APPLIANCE_VIP_SERVICES:
        return True
    labels = meta.get("labels") or {}
    return labels.get("app.kubernetes.io/component") == "frontend"


def check(path: Path) -> tuple[list[str], int]:
    problems = []
    checked = 0
    for doc in yaml.safe_load_all(path.read_text()):
        if not isinstance(doc, dict) or doc.get("kind") != "Service":
            continue
        if not _is_vip_service(doc):
            continue
        spec = doc.get("spec") or {}
        if (spec.get("type") or "ClusterIP") != "LoadBalancer":
            continue
        checked += 1
        name = (doc.get("metadata") or {}).get("name", "<unnamed>")
        if spec.get("allocateLoadBalancerNodePorts") is not False:
            problems.append(
                f"{path}: Service {name!r} is a MetalLB-fronted "
                "LoadBalancer without allocateLoadBalancerNodePorts: "
                "false — every VIP port is also opened as a random "
                "NodePort on every node (#1550)"
            )
    return problems, checked


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", help="rendered manifests")
    parser.add_argument("--require", action="store_true")
    args = parser.parse_args(argv)

    problems: list[str] = []
    checked = 0
    for arg in args.files:
        found, n = check(Path(arg))
        problems.extend(found)
        checked += n
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    if args.require and checked == 0:
        print(
            "FAIL no MetalLB VIP LoadBalancer Service was checked — "
            "the renders no longer exercise the VIP templates (#1550)",
            file=sys.stderr,
        )
        return 1
    if not problems:
        print(
            f"   MetalLB VIP Services allocate no NodePorts "
            f"({checked} service(s) in {len(args.files)} file(s))"
        )
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
