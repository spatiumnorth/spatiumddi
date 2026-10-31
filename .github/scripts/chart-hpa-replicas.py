#!/usr/bin/env python3
"""A workload a HorizontalPodAutoscaler scales must not render spec.replicas (#3111).

The api Deployment rendered ``replicas: {{ .Values.api.replicas }}`` even with
``api.autoscaling.enabled`` on, the default. Helm 4 applies a release
server-side, so helm owned ``.spec.replicas`` beside the autoscaler, which
writes the same field through the ``scale`` subresource. Once the autoscaler
had moved the count off ``api.replicas``, every ``helm upgrade`` of the
release failed, a no-change ``--reuse-values`` included: ``Apply failed with 1
conflict: conflict with "kube-controller-manager" with subresource "scale"
...: .spec.replicas`` (the manager reads ``k3s`` on k3s). Under Helm 3's
client-side apply the same field reset the count to ``api.replicas`` on every
upgrade, until the autoscaler scaled it back. Kubernetes' guidance for a
workload under an autoscaler, and ``helm create``'s scaffold, leave the field
out of the applied manifest, so the autoscaler alone sets it.

Every HorizontalPodAutoscaler in a render must scale a Deployment,
StatefulSet or ReplicaSet in the same render, and that workload must carry no
``spec.replicas``. It fails closed: an autoscaler whose target is not in the
render is refused, because the guard cannot read what it scales.

``--replicas COMPONENT=N`` (repeatable) checks the other side: the Deployment
labelled ``app.kubernetes.io/component: COMPONENT`` is scaled by no
autoscaler in the render and renders ``spec.replicas: N``. With the
autoscaler off (the appliance's values) helm still sets the count.

``--require`` fails when no autoscaled workload was checked, so a render that
is meant to carry the autoscaler cannot pass by rendering none.

Usage: chart-hpa-replicas.py [--require] [--replicas COMPONENT=N ...]
           <manifest.yaml|-> [<manifest.yaml|-> ...]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

_COMPONENT = "app.kubernetes.io/component"
_SCALABLE = ("Deployment", "StatefulSet", "ReplicaSet")


def _name(doc: dict[str, Any]) -> str:
    return str((doc.get("metadata") or {}).get("name") or "<unnamed>")


def _component(doc: dict[str, Any]) -> str:
    return str(((doc.get("metadata") or {}).get("labels") or {}).get(_COMPONENT) or "")


def check(
    docs: list[dict[str, Any]], where: str, replicas: dict[str, int]
) -> tuple[list[str], int]:
    """The problems in one render, and how many autoscaled workloads it checked."""
    problems: list[str] = []
    workloads = {(d.get("kind"), _name(d)): d for d in docs if d.get("kind") in _SCALABLE}
    scaled: set[tuple[Any, str]] = set()
    checked = 0
    for hpa in docs:
        if hpa.get("kind") != "HorizontalPodAutoscaler":
            continue
        ref = (hpa.get("spec") or {}).get("scaleTargetRef") or {}
        key = (ref.get("kind"), str(ref.get("name") or ""))
        target = workloads.get(key)
        if target is None:
            problems.append(
                f"{where}: HorizontalPodAutoscaler {_name(hpa)!r} scales {key[0]} "
                f"{key[1]!r}, which is not in the render, so its replicas cannot be "
                "checked (#3111)"
            )
            continue
        scaled.add(key)
        checked += 1
        spec = target.get("spec") or {}
        if "replicas" in spec:
            problems.append(
                f"{where}: {key[0]} {key[1]!r} renders spec.replicas: {spec['replicas']} "
                f"while HorizontalPodAutoscaler {_name(hpa)!r} scales it. Helm then "
                "owns the field the autoscaler writes, and once the autoscaler has "
                "moved the count every helm upgrade fails on .spec.replicas under "
                "server-side apply (#3111)"
            )
    for component, want in replicas.items():
        found = [d for d in docs if d.get("kind") == "Deployment" and _component(d) == component]
        if not found:
            problems.append(f"{where}: no Deployment with component {component!r} in the render")
        for d in found:
            key = ("Deployment", _name(d))
            got = (d.get("spec") or {}).get("replicas")
            if key in scaled:
                problems.append(
                    f"{where}: Deployment {key[1]!r} is scaled by a "
                    "HorizontalPodAutoscaler; this render must carry none for "
                    f"{component!r} (#3111)"
                )
            elif got != want:
                problems.append(
                    f"{where}: Deployment {key[1]!r} renders spec.replicas "
                    f"{'unset' if got is None else got}, expected {want}: with no "
                    "autoscaler, helm is what sets the count (#3111)"
                )
    return problems, checked


def _replicas_arg(value: str) -> tuple[str, int]:
    component, sep, count = value.partition("=")
    if not sep or not component or not count.isdigit():
        raise argparse.ArgumentTypeError(f"expected COMPONENT=N, got {value!r}")
    return component, int(count)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", help="rendered manifests, or - for stdin")
    parser.add_argument("--require", action="store_true")
    parser.add_argument("--replicas", action="append", default=[], type=_replicas_arg)
    args = parser.parse_args(argv)

    replicas = dict(args.replicas)
    problems: list[str] = []
    checked = 0
    for arg in args.files:
        text = sys.stdin.read() if arg == "-" else Path(arg).read_text(encoding="utf-8")
        docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
        found, n = check(docs, arg, replicas)
        problems += found
        checked += n
    if args.require and not checked:
        problems.append("no workload scaled by a HorizontalPodAutoscaler was checked")
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    if not problems:
        print(f"   autoscaled workloads render no spec.replicas ({checked} checked)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
