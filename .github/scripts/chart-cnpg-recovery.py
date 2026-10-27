#!/usr/bin/env python3
"""Refuse a render whose CNPG WAL can fill the volume (#2317), or whose
replicated Cluster restarts its primary in place on a rolling update (#2831).

Checked on the rendered manifests:

* **Every CloudNativePG ``Cluster`` bounds the WAL it keeps (#2317).** After a
  failover the new primary holds CNPG's HA replication slots for standbys that
  may never follow it. With ``max_slot_wal_keep_size`` unset (PostgreSQL's
  ``-1``) such a slot keeps WAL without limit: a lab primary's pg_wal reached
  26 GB on its node's /var while CNPG read healthy. PostgreSQL keeps the
  LARGER of ``max_slot_wal_keep_size`` and ``wal_keep_size`` (they do not
  add), plus up to ``max_wal_size`` since the last checkpoint, so the check
  is::

      max(wal_keep_size, max_slot_wal_keep_size) + max_wal_size
          <= half the volume pg_wal lives on

  The volume is ``spec.walStorage.size`` when the Cluster has one, otherwise
  ``spec.storage.size``, where the data shares it. A parameter left out takes
  its default: ``wal_keep_size`` CNPG's 512MB, ``max_wal_size`` PostgreSQL's
  1GB. ``max_slot_wal_keep_size`` has no acceptable default and must be set
  to a size.

* **A Cluster with replicas updates its primary by switchover (#2831).** A
  spec change that rolls the instances (a resources or parameter change, on
  an upgrade, a resize or a promote) reaches the primary last. Under CNPG's
  default ``primaryUpdateMethod: restart`` the operator deletes the
  primary's pod while it still serves, and the instance manager's smart
  shutdown turns every new connection away for the whole
  ``smartShutdownTimeout`` (180 s) because the services' pooled sessions
  never end: about three and a half minutes in which nothing new reaches the
  database. ``switchover`` promotes an updated replica first. A Cluster of
  one instance has no replica and is not held to this.

``--require-cluster`` fails a render that has no Cluster, so a render cannot
pass by rendering nothing.

Usage: chart-cnpg-recovery.py [--require-cluster] <manifest.yaml> [...]
"""

from __future__ import annotations

import argparse
import re
import sys
from typing import Any

import yaml

# PostgreSQL memory units are powers of 1024 (kB, MB, GB, TB); Kubernetes
# quantities use Ki/Mi/Gi/Ti for those and k/M/G/T for powers of 1000.
_PG_UNITS = {"kB": 1 / 1024, "MB": 1, "GB": 1024, "TB": 1024 * 1024}
_K8S_UNITS = {
    "Ki": 1 / 1024,
    "Mi": 1,
    "Gi": 1024,
    "Ti": 1024 * 1024,
    "k": 1000 / 1024**2,
    "M": 1000**2 / 1024**2,
    "G": 1000**3 / 1024**2,
    "T": 1000**4 / 1024**2,
}
_DEFAULTS_MB = {"wal_keep_size": 512.0, "max_wal_size": 1024.0}


def pg_size_mb(value: Any) -> float | None:
    """A PostgreSQL size parameter in MiB, or None when it is not a size
    (``-1``, an empty string, a typo). A bare number is megabytes, the unit
    PostgreSQL gives both parameters."""
    m = re.fullmatch(r"\s*(\d+)\s*(kB|MB|GB|TB)?\s*", str(value))
    if not m:
        return None
    return int(m.group(1)) * _PG_UNITS[m.group(2) or "MB"]


def k8s_size_mb(value: Any) -> float | None:
    m = re.fullmatch(r"\s*(\d+)\s*(Ki|Mi|Gi|Ti|k|M|G|T)?\s*", str(value))
    if not m or not m.group(2):
        return None
    return int(m.group(1)) * _K8S_UNITS[m.group(2)]


def check_primary_update(doc: dict) -> list[str]:
    """#2831: with replicas, the primary is updated by a switchover."""
    name = (doc.get("metadata") or {}).get("name", "?")
    spec = doc.get("spec") or {}
    try:
        instances = int(spec.get("instances") or 1)
    except (TypeError, ValueError):
        return [f"Cluster/{name}: instances {spec.get('instances')!r} is not a count"]
    method = spec.get("primaryUpdateMethod")
    if instances > 1 and method != "switchover":
        shown = repr(method) if method is not None else "unset (CNPG's default, restart)"
        return [
            f"Cluster/{name}: {instances} instances with primaryUpdateMethod {shown}; a "
            "rolling update would delete the primary's pod under its clients and its smart "
            "shutdown refuses every new connection for smartShutdownTimeout (#2831)"
        ]
    return []


def check_cluster(doc: dict) -> list[str]:
    name = (doc.get("metadata") or {}).get("name", "?")
    where = f"Cluster/{name}"
    spec = doc.get("spec") or {}
    params = ((spec.get("postgresql") or {}).get("parameters")) or {}
    problems: list[str] = check_primary_update(doc)

    raw_cap = params.get("max_slot_wal_keep_size")
    cap = pg_size_mb(raw_cap) if raw_cap is not None else None
    if cap is None:
        problems.append(
            f"{where}: max_slot_wal_keep_size is {raw_cap!r}; it must be a size, or a "
            "replication slot for a standby that never follows the primary keeps WAL "
            "until the volume is full (#2317)"
        )
        return problems

    sizes: dict[str, float] = {}
    for key, default in _DEFAULTS_MB.items():
        if key not in params:
            sizes[key] = default
            continue
        parsed = pg_size_mb(params[key])
        if parsed is None:
            problems.append(f"{where}: {key} {params[key]!r} is not a size")
            return problems
        sizes[key] = parsed

    wal_volume = spec.get("walStorage") or spec.get("storage") or {}
    volume = k8s_size_mb(wal_volume.get("size"))
    if volume is None:
        problems.append(f"{where}: cannot read the size of the volume pg_wal lives on")
        return problems

    bound = max(sizes["wal_keep_size"], cap) + sizes["max_wal_size"]
    if bound > volume / 2:
        problems.append(
            f"{where}: pg_wal can reach max(wal_keep_size {sizes['wal_keep_size']:.0f}MB, "
            f"max_slot_wal_keep_size {cap:.0f}MB) + max_wal_size {sizes['max_wal_size']:.0f}MB "
            f"= {bound:.0f}MB, over half the {volume:.0f}MiB volume (#2317)"
        )
    return problems


def check(docs: list[Any]) -> tuple[list[str], int]:
    problems: list[str] = []
    clusters = 0
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        group = str(doc.get("apiVersion", "")).partition("/")[0]
        if doc.get("kind") == "Cluster" and group == "postgresql.cnpg.io":
            clusters += 1
            problems += check_cluster(doc)
    return problems, clusters


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--require-cluster", action="store_true")
    ap.add_argument("manifests", nargs="+")
    args = ap.parse_args(argv)

    problems: list[str] = []
    clusters = 0
    for path in args.manifests:
        with (sys.stdin if path == "-" else open(path, encoding="utf-8")) as fh:
            docs = list(yaml.safe_load_all(fh))
        p, c = check(docs)
        problems += [f"{path}: {line}" for line in p]
        clusters += c
    if args.require_cluster and not clusters:
        problems.append("no CloudNativePG Cluster rendered (--require-cluster)")
    for line in problems:
        print(f"FAIL: {line}", file=sys.stderr)
    if not problems and clusters:
        print(f"   cnpg wal cap + primary update: {clusters} Cluster(s) bound pg_wal and "
              "switch over a replicated primary")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
