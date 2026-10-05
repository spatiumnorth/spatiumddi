#!/usr/bin/env python3
"""A DNS agent LoadBalancer Service must keep the client address (#1548).

The umbrella chart's per-server DNS agent Service is the resolver
address clients are pointed at. Under the Kubernetes default
``externalTrafficPolicy: Cluster`` kube-proxy SNATs every query to the
node or CNI address, so the DNS server sees two or three addresses for
the whole network: per-client rate limits throttle everyone at once,
and query logs, RPZ hits and client ACLs all key on the wrong address.
Each server is its own single-replica StatefulSet, so ``Local`` costs
nothing — the announcing node is the node running the pod either way.
This is the umbrella-chart twin of PR #1488's ``chart-vip-client-ip.py``
(which covers the appliance chart's MetalLB VIP Services).

Checks every rendered file for Services labelled
``app.kubernetes.io/component: dns-agent`` (headless ones excluded) and
fails any ``type: LoadBalancer`` one whose ``externalTrafficPolicy``
is not ``Local``.

``--require`` additionally fails when no such Service was checked at
all, so the dedicated render in charts-render-check.sh cannot silently
stop exercising the template. ``--expect FIELD=VALUE`` /
``--expect-annotation KEY=VALUE`` assert rendered spec fields and
annotations on every checked Service — that render sets
``loadBalancerIP``, ``loadBalancerSourceRanges``, ``ipFamilyPolicy``
and the MetalLB ``loadBalancerIPs`` annotation through
``server.service``, and this is what proves they reach the Service
instead of being dropped by the template.

Usage: chart-dns-agent-service.py [--require]
           [--expect FIELD=VALUE ...] [--expect-annotation KEY=VALUE ...]
           <manifest.yaml> [<manifest.yaml> ...]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml


def _is_dns_agent_service(doc: dict) -> bool:
    if doc.get("kind") != "Service":
        return False
    spec = doc.get("spec") or {}
    if spec.get("clusterIP") == "None":  # the headless Service
        return False
    labels = (doc.get("metadata") or {}).get("labels") or {}
    return labels.get("app.kubernetes.io/component") == "dns-agent"


def _rendered(value: Any) -> str:
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    return "" if value is None else str(value)


def check(
    path: Path,
    expect: dict[str, str],
    expect_annotations: dict[str, str],
) -> tuple[list[str], int]:
    problems = []
    checked = 0
    for doc in yaml.safe_load_all(path.read_text()):
        if not isinstance(doc, dict) or not _is_dns_agent_service(doc):
            continue
        meta = doc.get("metadata") or {}
        spec = doc.get("spec") or {}
        if (spec.get("type") or "ClusterIP") != "LoadBalancer":
            continue
        checked += 1
        name = meta.get("name", "<unnamed>")
        policy = spec.get("externalTrafficPolicy")
        if policy != "Local":
            problems.append(
                f"{path}: Service {name!r} is a LoadBalancer with "
                f"externalTrafficPolicy {policy or 'unset (Cluster)'} — "
                "clients reach the DNS agent SNATed (#1548)"
            )
        for field, want in expect.items():
            got = _rendered(spec.get(field))
            if got != want:
                problems.append(
                    f"{path}: Service {name!r} spec.{field} is "
                    f"{got or 'unset'}, expected {want} (#1548)"
                )
        annotations = meta.get("annotations") or {}
        for key, want in expect_annotations.items():
            got = _rendered(annotations.get(key))
            if got != want:
                problems.append(
                    f"{path}: Service {name!r} annotation {key} is "
                    f"{got or 'unset'}, expected {want} (#1548)"
                )
    return problems, checked


def _pairs(items: list[str]) -> dict[str, str]:
    out = {}
    for item in items:
        key, sep, value = item.partition("=")
        if not sep:
            raise SystemExit(f"expected KEY=VALUE, got {item!r}")
        out[key] = value
    return out


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", help="rendered manifests")
    parser.add_argument("--require", action="store_true")
    parser.add_argument("--expect", action="append", default=[], metavar="FIELD=VALUE")
    parser.add_argument(
        "--expect-annotation", action="append", default=[], metavar="KEY=VALUE"
    )
    args = parser.parse_args(argv)

    expect = _pairs(args.expect)
    expect_annotations = _pairs(args.expect_annotation)
    problems: list[str] = []
    checked = 0
    for arg in args.files:
        found, n = check(Path(arg), expect, expect_annotations)
        problems += found
        checked += n
    if args.require and not checked:
        problems.append("no DNS agent LoadBalancer Service was checked")
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    if not problems:
        print(
            "   DNS agent LoadBalancer Services keep the client address "
            f"({checked} checked)"
        )
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
