#!/usr/bin/env python3
"""The CNPG instance pods reach the API server on their own node, on the
appliance and nowhere else (#3021).

Each CNPG instance manager keeps one long-lived connection to the API server
through the ``kubernetes`` Service, which may land on any control-plane node.
After a node's hard loss, a primary whose connection had landed on that node
lost its API server, and its liveness probe's isolation check then asked its
peers. The replica on the lost node did not answer, so the probe failed and
kubelet restarted a healthy primary: the database was away for 25 to 35 s
although the primary had lost nothing it needed. On the appliance every
control-plane node runs an API server on its own address, so the appliance
points each instance at its own node's (``KUBERNETES_SERVICE_HOST`` from the
pod's ``status.hostIP``, ``KUBERNETES_SERVICE_PORT`` 6443): only the loss of
the primary's own node can take its API server away.

The appliance sets ``postgresql.cnpg.nodeLocalApiServer.enabled`` in its own
values (firstboot's HelmChart and the supervisor's HelmChartConfig). The
umbrella chart's default is off: on a BYO-Kubernetes cluster a node need not
serve the API on its own address.

Checks every rendered CNPG ``Cluster``. By default it fails any whose
``spec.env`` does not take ``KUBERNETES_SERVICE_HOST`` from ``status.hostIP``
and set ``KUBERNETES_SERVICE_PORT`` (a render with the appliance's values).
``--absent`` fails any that sets either variable at all (the default render,
which must stay as it was before #3021).

``--require`` additionally fails when no Cluster was checked at all, so a
dedicated render cannot silently stop exercising the template.

Usage: chart-cnpg-node-local-api.py [--require] [--absent] [--port N]
           <manifest.yaml> [<manifest.yaml> ...]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

HOST = "KUBERNETES_SERVICE_HOST"
PORT = "KUBERNETES_SERVICE_PORT"


def _is_cnpg_cluster(doc: dict) -> bool:
    group = str(doc.get("apiVersion", "")).partition("/")[0]
    return doc.get("kind") == "Cluster" and group == "postgresql.cnpg.io"


def _env(doc: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for item in (doc.get("spec") or {}).get("env") or []:
        if isinstance(item, dict) and item.get("name"):
            out[str(item["name"])] = item
    return out


def check(path: Path, absent: bool, port: str) -> tuple[list[str], int]:
    problems = []
    checked = 0
    for doc in yaml.safe_load_all(path.read_text()):
        if not isinstance(doc, dict) or not _is_cnpg_cluster(doc):
            continue
        checked += 1
        name = (doc.get("metadata") or {}).get("name", "<unnamed>")
        env = _env(doc)
        if absent:
            for var in (HOST, PORT):
                if var in env:
                    problems.append(
                        f"{path}: Cluster {name!r} sets {var}, which this render "
                        "must leave alone: the umbrella default keeps the "
                        "kubernetes Service, and a BYO-Kubernetes node need not "
                        "serve the API on its own address (#3021)"
                    )
            continue
        host = env.get(HOST) or {}
        field = ((host.get("valueFrom") or {}).get("fieldRef") or {}).get("fieldPath")
        if field != "status.hostIP" or "value" in host:
            problems.append(
                f"{path}: Cluster {name!r} does not take {HOST} from the pod's "
                f"status.hostIP (got {host or 'unset'}): with the appliance's "
                "values a primary must reach its own node's API server, or a "
                "lost node restarts it (#3021)"
            )
        got_port = (env.get(PORT) or {}).get("value")
        if got_port != port:
            problems.append(
                f"{path}: Cluster {name!r} sets {PORT} to {got_port!r}, expected "
                f"{port!r} (a string, as every env value must be): the API "
                "server's port on the node (#3021)"
            )
    return problems, checked


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", help="rendered manifests")
    parser.add_argument("--require", action="store_true")
    parser.add_argument("--absent", action="store_true")
    parser.add_argument("--port", default="6443")
    args = parser.parse_args(argv)

    problems: list[str] = []
    checked = 0
    for arg in args.files:
        found, n = check(Path(arg), args.absent, args.port)
        problems += found
        checked += n
    if args.require and not checked:
        problems.append("no CNPG Cluster was checked")
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    if not problems:
        state = (
            "keep the kubernetes Service"
            if args.absent
            else f"reach their own node's API server on {args.port}"
        )
        print(f"   CNPG Clusters {state} ({checked} checked)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
