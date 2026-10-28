#!/usr/bin/env python3
"""The api, worker and beat database pools must fit Postgres' max_connections (#2955).

Every api pod holds a request pool (DATABASE_POOL_SIZE + DATABASE_MAX_OVERFLOW,
the application's own 10 + 20 when unset), 2 connections for the after-commit
hooks (#2782) and 1 for the readiness probe (#2944). The HPA can scale the api
to maxReplicas, each worker process holds 1 connection plus 2 hooks, celery-beat
2 hooks. With max_connections 100 and the default HPA (2..10) the api alone
was refused connections under load. The appliance sizes this exactly
(k8s_api.postgres_connection_budget); this asserts every other render does too.

A render is checked when it carries an api Deployment AND a max_connections
(the standalone StatefulSet's ``-c max_connections=N`` or the CNPG Cluster's
parameter). A render with neither (external database, appliance role chart) is
skipped; ``--require`` fails when nothing was checked.

Usage: chart-postgres-connections.py [--require] <manifest.yaml|-> [...]
"""

from __future__ import annotations

import argparse
import re
import sys
from typing import Any

import yaml

DEFAULT_POOL = 10
DEFAULT_OVERFLOW = 20
HOOKS = 2
PROBE = 1
WORKER_SLACK = 1
# superuser_reserved_connections: counted inside max_connections but closed to
# the application role.
SUPERUSER_RESERVED = 3


def _component(doc: dict[str, Any]) -> str:
    return ((doc.get("metadata") or {}).get("labels") or {}).get(
        "app.kubernetes.io/component", ""
    )


def _container_env(doc: dict[str, Any]) -> dict[str, str]:
    pod = ((doc.get("spec") or {}).get("template") or {}).get("spec") or {}
    out: dict[str, str] = {}
    for c in pod.get("containers") or []:
        for e in c.get("env") or []:
            if "value" in e:
                out[e["name"]] = str(e["value"])
    return out


def _concurrency(doc: dict[str, Any]) -> int:
    pod = ((doc.get("spec") or {}).get("template") or {}).get("spec") or {}
    for c in pod.get("containers") or []:
        for a in (c.get("command") or []) + (c.get("args") or []):
            m = re.fullmatch(r"--concurrency[= ](\d+)", str(a))
            if m:
                return int(m.group(1))
    return 1


def _max_connections(docs: list[dict[str, Any]]) -> int | None:
    for d in docs:
        if d.get("kind") == "Cluster":
            v = (((d.get("spec") or {}).get("postgresql") or {}).get("parameters") or {}).get(
                "max_connections"
            )
            if v:
                return int(v)
        if d.get("kind") == "StatefulSet":
            pod = ((d.get("spec") or {}).get("template") or {}).get("spec") or {}
            for c in pod.get("containers") or []:
                for a in c.get("args") or []:
                    m = re.fullmatch(r"max_connections=(\d+)", str(a))
                    if m:
                        return int(m.group(1))
    return None


def check(docs: list[dict[str, Any]]) -> tuple[list[str], bool]:
    api = next(
        (d for d in docs if d.get("kind") == "Deployment" and _component(d) == "api"), None
    )
    limit = _max_connections(docs)
    if api is None or limit is None:
        return [], False
    env = _container_env(api)
    pool = int(env.get("DATABASE_POOL_SIZE", DEFAULT_POOL)) + int(
        env.get("DATABASE_MAX_OVERFLOW", DEFAULT_OVERFLOW)
    )
    pods = int((api.get("spec") or {}).get("replicas") or 1)
    for d in docs:
        if d.get("kind") == "HorizontalPodAutoscaler":
            ref = (d.get("spec") or {}).get("scaleTargetRef") or {}
            if ref.get("kind") == "Deployment" and ref.get("name") == api["metadata"]["name"]:
                pods = max(pods, int(d["spec"].get("maxReplicas") or 0))
    need = pods * (pool + HOOKS + PROBE)
    workers = ""
    for d in docs:
        if d.get("kind") == "Deployment" and _component(d) == "worker":
            reps = int((d.get("spec") or {}).get("replicas") or 1)
            need += reps * (_concurrency(d) * (1 + HOOKS) + WORKER_SLACK)
        if d.get("kind") == "Deployment" and _component(d) == "beat":
            need += HOOKS + 1
    need += SUPERUSER_RESERVED
    if need > limit:
        return [
            f"api {pods} pod(s) x ({pool} pool + {HOOKS} hooks + {PROBE} probe) plus the "
            f"worker and beat pools plus {SUPERUSER_RESERVED} reserved can open {need} "
            f"connections, but max_connections is {limit} (#2955){workers}"
        ], True
    return [], True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--require", action="store_true")
    ap.add_argument("files", nargs="+")
    args = ap.parse_args()
    problems: list[str] = []
    checked = 0
    for f in args.files:
        text = sys.stdin.read() if f == "-" else open(f).read()
        docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
        errs, did = check(docs)
        checked += int(did)
        problems += [f"{f}: {e}" for e in errs]
    for p in problems:
        print(f"chart-postgres-connections: {p}", file=sys.stderr)
    if args.require and not checked:
        print("chart-postgres-connections: no render carried an api + max_connections", file=sys.stderr)
        return 1
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
