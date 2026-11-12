#!/usr/bin/env python3
"""The node-local api Service exists on the appliance and nowhere else (#3645).

``<release>-api-local`` is a second ClusterIP Service over the api pods with
``internalTrafficPolicy: Local``: a caller on a node reaches only that node's
api pod, so the plain-http supervisor and frontend hop never crosses the node
LAN. It is the appliance's (``api.service.nodeLocal``, set by firstboot and the
supervisor); the umbrella default, Docker Compose and a BYO-Kubernetes install
must render exactly the one api Service they always did, and the frontend's
upstream must follow whichever Service exists.

Default: every file must have NO ``*-api-local`` Service and a frontend whose
``API_UPSTREAM_HOST`` is the plain ``*-api`` one. ``--present``: every file must
have exactly one, with ``internalTrafficPolicy: Local``, the api selector and
port 8000, and the frontend's ``API_UPSTREAM_HOST`` must name it.

Usage: chart-api-local-service.py [--present] <manifest.yaml> [...]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml


def check(path: Path, present: bool) -> list[str]:
    docs = [d for d in yaml.safe_load_all(path.read_text()) if isinstance(d, dict)]
    local = [
        d
        for d in docs
        if d.get("kind") == "Service" and d["metadata"]["name"].endswith("-api-local")
    ]
    main = [
        d
        for d in docs
        if d.get("kind") == "Service"
        and d["metadata"]["name"].endswith("-api")
        and (d["metadata"].get("labels") or {}).get("app.kubernetes.io/component") == "api"
    ]
    problems: list[str] = []
    if not main:
        problems.append(f"{path}: no api Service rendered")
    for svc in main:
        if (svc["spec"].get("internalTrafficPolicy") or "Cluster") != "Cluster":
            problems.append(f"{path}: the main api Service must stay Cluster-routed")
    if not present:
        if local:
            problems.append(f"{path}: renders a node-local api Service it must not (#3645)")
    else:
        if len(local) != 1:
            return problems + [f"{path}: expected one node-local api Service, found {len(local)}"]
        spec = local[0]["spec"]
        if spec.get("internalTrafficPolicy") != "Local":
            problems.append(f"{path}: node-local api Service lacks internalTrafficPolicy: Local")
        if main and spec.get("selector") != main[0]["spec"].get("selector"):
            problems.append(f"{path}: node-local api Service selects different pods")
        if [p.get("port") for p in spec.get("ports", [])] != [8000]:
            problems.append(f"{path}: node-local api Service must expose 8000")
    want = (local[0]["metadata"]["name"] if present and local else main[0]["metadata"]["name"]) if (
        local or main
    ) else ""
    for d in docs:
        if d.get("kind") != "Deployment" or not d["metadata"]["name"].endswith("-frontend"):
            continue
        for c in d["spec"]["template"]["spec"]["containers"]:
            for e in c.get("env", []):
                if e.get("name") == "API_UPSTREAM_HOST":
                    host = e.get("value", "").split(".")[0]
                    if host != want:
                        problems.append(
                            f"{path}: frontend API_UPSTREAM_HOST is {host!r}, expected {want!r}"
                        )
    return problems


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+")
    parser.add_argument("--present", action="store_true")
    args = parser.parse_args(argv)
    problems: list[str] = []
    for arg in args.files:
        problems += check(Path(arg), args.present)
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    if not problems:
        state = "carry" if args.present else "omit"
        print(f"   api renders {state} the node-local Service ({len(args.files)} checked)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
