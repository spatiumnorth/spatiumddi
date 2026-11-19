#!/usr/bin/env python3
"""Refuse a Deployment whose pod template changes with its replica count alone (#2450).

On the appliance the supervisor sizes the control plane's replicas to the
node count, so the first promotion takes the frontend from one replica to
three and changes nothing else in its values. The frontend runs on the host
network, binds the node's ports 80 and 443, and retires an old pod before it
starts a new one. A pod template that differs between one replica and three
therefore makes that promotion roll the seed's only frontend pod, and the
seed refuses connections on both ports until the replacement has bound them,
while the browser that drives the promotion is on it. A template that does
not change is only scaled: the seed's pod keeps serving and the new pods
start on the new nodes.

Reads two ``helm template`` streams rendered from the same values apart from
the replica count, and compares each named component's Deployment
``spec.template`` between them. A component missing from either render is a
failure, because a guard that cannot find its subject must not read as a
pass. Exit 0 when every named template is the same in both; exit 1 with one
line per component that differs, naming where.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable
from typing import Any

import yaml

_COMPONENT = "app.kubernetes.io/component"


def templates(path: str) -> dict[str, Any]:
    """The pod template of each Deployment in a render, by component label."""
    with open(path, encoding="utf-8") as fh:
        docs = list(yaml.safe_load_all(fh))
    out: dict[str, Any] = {}
    for doc in docs:
        if not isinstance(doc, dict) or doc.get("kind") != "Deployment":
            continue
        labels = (doc.get("metadata") or {}).get("labels") or {}
        component = str(labels.get(_COMPONENT) or "")
        if component:
            out[component] = (doc.get("spec") or {}).get("template")
    return out


def differences(a: Any, b: Any, path: str) -> list[str]:
    """Where two parsed documents differ, as dotted paths (list items by index)."""
    if isinstance(a, dict) and isinstance(b, dict):
        out: list[str] = []
        for key in sorted(set(a) | set(b), key=str):
            sub = f"{path}.{key}"
            if key not in a:
                out.append(f"{sub} (only in the second render)")
            elif key not in b:
                out.append(f"{sub} (only in the first render)")
            else:
                out.extend(differences(a[key], b[key], sub))
        return out
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        out = []
        for i, (x, y) in enumerate(zip(a, b, strict=True)):
            out.extend(differences(x, y, f"{path}[{i}]"))
        return out
    return [path] if a != b else []


def check(first: str, second: str, components: Iterable[str]) -> list[str]:
    a, b = templates(first), templates(second)
    failures: list[str] = []
    for component in components:
        missing = [path for path, found in ((first, a), (second, b)) if component not in found]
        if missing:
            failures.append(
                f"no Deployment with component {component!r} in {', '.join(missing)}"
            )
            continue
        diff = differences(a[component], b[component], "spec.template")
        if diff:
            failures.append(
                f"component {component!r}: the pod template changes with the replica "
                f"count ({'; '.join(diff)}), so scaling it up rolls every pod it has"
            )
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--component", action="append", required=True, metavar="COMPONENT"
    )
    parser.add_argument("first", help="a render at one replica count")
    parser.add_argument("second", help="the same values at another replica count")
    args = parser.parse_args(argv)
    failures = check(args.first, args.second, args.component)
    for line in failures:
        print(f"template-stable: {line}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
