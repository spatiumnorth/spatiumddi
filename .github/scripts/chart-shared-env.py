#!/usr/bin/env python3
"""Refuse a rendered umbrella chart where api, worker and beat disagree on shared env (#1826).

The api, worker and beat containers run the same image and read the same
``settings``, but the worker is the process that runs alert evaluation and the
rolling-upgrade orchestrator. On the appliance, ``APPLIANCE_MODE`` was written
only under ``api.env``, so the worker ran with it unset and every
``appliance_mode`` gate (``node_pressure``, ``cluster_dns_degraded``, ...)
evaluated as off, with nothing reporting a problem: the render was valid and
every probe passed.

This reads ``helm template`` streams and, for the api, worker and beat
containers, requires every ``--expect NAME`` to be present on all three. It
also takes ``--absent COMPONENT:NAME`` for a container that must NOT carry a
name (the slot-image mirror and migrate Job include the common env block but
must not run in appliance mode: the mirror would try to bootstrap the Web UI
certificate).

It fails closed: a render with no api, worker or beat container is refused,
and so is a run with nothing to expect.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

_COMPONENT = "app.kubernetes.io/component"
# (component label, container name)
_REQUIRED = (("api", "api"), ("worker", "worker"), ("beat", "beat"))


def _containers(docs: list[Any]) -> dict[str, dict[str, Any]]:
    """component label -> {container name -> container} for every Deployment."""
    found: dict[str, dict[str, Any]] = {}
    for doc in docs:
        if not isinstance(doc, dict) or doc.get("kind") != "Deployment":
            continue
        labels = (doc.get("metadata") or {}).get("labels") or {}
        comp = labels.get(_COMPONENT)
        if not comp:
            continue
        spec = ((doc.get("spec") or {}).get("template") or {}).get("spec") or {}
        for c in spec.get("containers") or []:
            found.setdefault(comp, {})[c.get("name", "")] = c
    return found


def _env_names(container: dict[str, Any]) -> list[str]:
    return [e.get("name", "") for e in container.get("env") or []]


def problems(docs: list[Any], expect: list[str], absent: list[tuple[str, str]]) -> list[str]:
    out: list[str] = []
    found = _containers(docs)
    for comp, cname in _REQUIRED:
        container = found.get(comp, {}).get(cname)
        if container is None:
            out.append(
                f"no Deployment with component label '{comp}' and container '{cname}' "
                "to check; a guard that cannot find its subject must not pass"
            )
            continue
        names = _env_names(container)
        for want in expect:
            if want not in names:
                out.append(f"{comp}: container '{cname}' is missing shared env {want}")
        dupes = sorted({n for n in names if names.count(n) > 1})
        for d in dupes:
            out.append(f"{comp}: container '{cname}' sets env {d} more than once")
    for comp, name in absent:
        for cname, container in found.get(comp, {}).items():
            if name in _env_names(container):
                out.append(f"{comp}: container '{cname}' must not carry env {name}")
    return out


def main(argv: list[str]) -> int:
    expect: list[str] = []
    absent: list[tuple[str, str]] = []
    paths: list[str] = []
    it = iter(argv[1:])
    for arg in it:
        if arg == "--expect":
            expect.append(next(it))
        elif arg == "--absent":
            comp, _, name = next(it).partition(":")
            absent.append((comp, name))
        else:
            paths.append(arg)
    if not expect:
        print("chart-shared-env: no --expect given; nothing to check", file=sys.stderr)
        return 1
    docs: list[Any] = []
    for p in paths or ["-"]:
        text = sys.stdin.read() if p == "-" else Path(p).read_text(encoding="utf-8")
        docs.extend(d for d in yaml.safe_load_all(text) if d)
    bad = problems(docs, expect, absent)
    for line in bad:
        print(f"chart-shared-env: {line}", file=sys.stderr)
    if bad:
        return 1
    print(f"chart-shared-env: OK — api, worker and beat all carry {', '.join(expect)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
