#!/usr/bin/env python3
"""Each MetalLB address is asked for by one Service only (#1510).

MetalLB hands a ``metallb.universe.tf/loadBalancerIPs`` address to one
Service. Without ``allow-shared-ip`` (which would not help on the same port
anyway) every other Service asking for it stays ``<pending>``, and which one
wins depends on creation order. The appliance chart used to render the DNS
VIP annotation on all three engine Services (dns-bind9 / dns-powerdns /
dns-technitium), so on a fresh install the VIP could land on an engine with
no pods, and after an engine switch it stayed on the old, now empty one.

``helm template`` and kubeconform accept that, so this checks the render:

* no two Services in a file may ask for the same address;
* with ``--dns-vip ADDR``, exactly one Service asks for ADDR, it is a
  LoadBalancer, and its selector matches the pod template of every rendered
  DNS engine DaemonSet, so the VIP keeps answering whichever engine runs.

``--require`` (with ``--dns-vip``) fails when no DNS engine DaemonSet was
rendered, so the dedicated render cannot silently stop exercising this.

Usage: chart-lb-address-single-owner.py [--require] [--dns-vip ADDR]
           <manifest.yaml> [<manifest.yaml> ...]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

ANNOTATION = "metallb.universe.tf/loadBalancerIPs"
DNS_ENGINES = {"dns-bind9", "dns-powerdns", "dns-technitium"}


def _addresses(svc: dict) -> list[str]:
    raw = ((svc.get("metadata") or {}).get("annotations") or {}).get(ANNOTATION)
    if not raw:
        return []
    return [a.strip() for a in str(raw).split(",") if a.strip()]


def check(path: Path, dns_vip: str | None) -> tuple[list[str], int]:
    problems: list[str] = []
    owners: dict[str, list[dict]] = {}
    engines: list[dict] = []
    for doc in yaml.safe_load_all(path.read_text()):
        if not isinstance(doc, dict):
            continue
        meta = doc.get("metadata") or {}
        if doc.get("kind") == "Service":
            for addr in _addresses(doc):
                owners.setdefault(addr, []).append(doc)
        elif doc.get("kind") == "DaemonSet" and meta.get("name") in DNS_ENGINES:
            engines.append(doc)

    for addr, svcs in sorted(owners.items()):
        if len(svcs) > 1:
            names = ", ".join(s["metadata"]["name"] for s in svcs)
            problems.append(
                f"{path}: {len(svcs)} Services ask MetalLB for {addr} ({names}); "
                "only the one created first gets it"
            )

    if dns_vip is None:
        return problems, len(engines)

    svcs = owners.get(dns_vip, [])
    if len(svcs) != 1:
        problems.append(
            f"{path}: expected exactly one Service for the DNS VIP {dns_vip}, got {len(svcs)}"
        )
        return problems, len(engines)
    svc = svcs[0]
    name = svc["metadata"]["name"]
    spec = svc.get("spec") or {}
    if spec.get("type") != "LoadBalancer":
        problems.append(f"{path}: DNS VIP Service {name!r} is not a LoadBalancer")
    selector = spec.get("selector") or {}
    if not selector:
        problems.append(f"{path}: DNS VIP Service {name!r} has no selector")
    for ds in engines:
        labels = (
            ((ds.get("spec") or {}).get("template") or {}).get("metadata") or {}
        ).get("labels") or {}
        if any(labels.get(k) != v for k, v in selector.items()):
            problems.append(
                f"{path}: DNS VIP Service {name!r} selector {selector} does not match "
                f"the pods of DaemonSet {ds['metadata']['name']!r}"
            )
    return problems, len(engines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", help="rendered manifests")
    parser.add_argument("--require", action="store_true")
    parser.add_argument("--dns-vip", metavar="ADDR")
    args = parser.parse_args(argv)

    problems: list[str] = []
    engines = 0
    for arg in args.files:
        found, n = check(Path(arg), args.dns_vip)
        problems += found
        engines += n
    if args.require and args.dns_vip and not engines:
        problems.append("no DNS engine DaemonSet was rendered")
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    if not problems:
        suffix = f", DNS VIP follows {engines} engine(s)" if args.dns_vip else ""
        print(f"   every MetalLB address has one Service{suffix}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
