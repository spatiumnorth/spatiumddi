#!/usr/bin/env python3
"""Refuse a rendered chart in which the slot-image mirror gets less than the api it runs (#1174).

The slot-image mirror (``templates/slot-image-mirror.yaml``) runs the api's own
image with its default command, so it imports the whole application before it
serves a byte. Its resources were written for a small idle process
(``limits: {cpu: 500m, memory: 256Mi}``), and the application outgrew them. On
the 2026-10-02 nightly image the started mirror holds about 280 MiB of
anonymous memory, and under 256Mi it is OOMKilled while importing (#1174). The
supervisor turns the mirror on on every multi-node control plane, so each one
kept a crash-looping mirror and an air-gapped rolling upgrade had no image
source. The CPU limit matters as well: the import runs on one thread, and half
the api's CPU limit made it more than twice as slow (7.0 s against 3.0 s).

The rule this enforces: in every render that has both, the mirror container's
memory limit and CPU limit are each at least the api container's. Since #1174
the chart derives the mirror's resources from ``api.resources``, so a render
that fails here has a ``slotImageMirror.resources`` override, or a template,
that sized the mirror back down.

The probes follow the same rule, because the process they probe is the same
one: one uvicorn worker that imports the application and runs its startup
before it binds the port, and whose event loop answers late when busy
(#1051). For each probe the api carries, the mirror must carry it too, with a
``timeoutSeconds`` at least the api's and a failure budget
(``initialDelaySeconds + periodSeconds * failureThreshold``, the kubelet's
defaults filling any field left out) at least the api's. The mirror's old
probes killed it about 40 s after a start that had not bound yet, and
#1174's pod logged 12 liveness kills before its OOMKills.

It fails closed. A render that carries the mirror but no api to compare it
with is refused, because a guard that cannot find its reference must not read
as a pass.

Reads one or more ``helm template`` streams (files, or ``-`` for stdin).
Exit 0 when no render carries the mirror (it is off by default) or when every
limit holds; exit 1 with one line per shortfall.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterable
from typing import Any

import yaml

_COMPONENT = "app.kubernetes.io/component"
_API = ("api", "api")  # (component label, container name)
_MIRROR = ("slot-image-mirror", "slot-image-mirror")

_QTY = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]*)\s*$")
_MEMORY_UNITS = {
    "": 1,
    "k": 10**3,
    "M": 10**6,
    "G": 10**9,
    "T": 10**12,
    "Ki": 2**10,
    "Mi": 2**20,
    "Gi": 2**30,
    "Ti": 2**40,
}


def memory_bytes(qty: Any) -> float | None:
    """A Kubernetes memory quantity in bytes; None when absent or unreadable."""
    m = _QTY.match(str(qty if qty is not None else ""))
    if not m or m.group(2) not in _MEMORY_UNITS:
        return None
    return float(m.group(1)) * _MEMORY_UNITS[m.group(2)]


def cpu_millicores(qty: Any) -> float | None:
    """A Kubernetes CPU quantity in millicores; None when absent or unreadable."""
    m = _QTY.match(str(qty if qty is not None else ""))
    if not m or m.group(2) not in ("", "m"):
        return None
    value = float(m.group(1))
    return value if m.group(2) == "m" else value * 1000


def _container(docs: Iterable[Any], component: str, name: str) -> tuple[str, dict] | None:
    """The named container of the Deployment carrying ``component``."""
    for doc in docs:
        if not isinstance(doc, dict) or doc.get("kind") != "Deployment":
            continue
        meta = doc.get("metadata") or {}
        if (meta.get("labels") or {}).get(_COMPONENT) != component:
            continue
        pod = ((doc.get("spec") or {}).get("template") or {}).get("spec") or {}
        for c in pod.get("containers") or []:
            if c.get("name") == name:
                return f"Deployment/{meta.get('name', '?')}", c
    return None


def shortfalls(docs: list[Any]) -> list[str]:
    """One line per way the mirror is configured below the api, in one render."""
    mirror = _container(docs, *_MIRROR)
    if mirror is None:
        return []
    api = _container(docs, *_API)
    if api is None:
        return [
            f"{mirror[0]}: a slot-image mirror is rendered but no api container "
            "(component label 'api', container 'api') to size it against; "
            "refusing rather than passing unchecked"
        ]
    out: list[str] = []
    m_lim = (mirror[1].get("resources") or {}).get("limits") or {}
    a_lim = (api[1].get("resources") or {}).get("limits") or {}
    for key, parse in (("memory", memory_bytes), ("cpu", cpu_millicores)):
        a_val, m_val = a_lim.get(key), m_lim.get(key)
        if a_val is None or m_val is None:
            # No api limit: nothing to hold the mirror to. No mirror limit:
            # unbounded, which is never below the api's.
            continue
        a_num, m_num = parse(a_val), parse(m_val)
        if a_num is None or m_num is None:
            out.append(
                f"{mirror[0]} container {_MIRROR[1]}: limits.{key} {m_val!r} or the "
                f"api's {a_val!r} is not a quantity this check can read"
            )
        elif m_num < a_num:
            out.append(
                f"{mirror[0]} container {_MIRROR[1]}: limits.{key} {m_val} is below "
                f"the api's {a_val} ({api[0]}); the mirror runs the api's image and "
                "imports the whole application (#1174)"
            )
    out.extend(_probe_shortfalls(mirror, api))
    return out


# The kubelet's defaults for a field a probe leaves out.
_PROBE_DEFAULTS = {
    "initialDelaySeconds": 0,
    "periodSeconds": 10,
    "timeoutSeconds": 1,
    "failureThreshold": 3,
}


def _probe_field(probe: dict, key: str) -> float:
    value = probe.get(key)
    return float(_PROBE_DEFAULTS[key] if value is None else value)


def probe_budget_s(probe: dict) -> float:
    """Seconds from the container's start until a probe that never succeeds
    has failed ``failureThreshold`` times: its first period begins after
    ``initialDelaySeconds``."""
    return _probe_field(probe, "initialDelaySeconds") + _probe_field(
        probe, "periodSeconds"
    ) * _probe_field(probe, "failureThreshold")


def _probe_shortfalls(mirror: tuple[str, dict], api: tuple[str, dict]) -> list[str]:
    out: list[str] = []
    for key in ("livenessProbe", "readinessProbe"):
        a_probe = api[1].get(key)
        if not isinstance(a_probe, dict):
            continue
        m_probe = mirror[1].get(key)
        where = f"{mirror[0]} container {_MIRROR[1]}: {key}"
        if not isinstance(m_probe, dict):
            out.append(f"{where} is missing; the api carries one ({api[0]}) (#1174)")
            continue
        m_to, a_to = _probe_field(m_probe, "timeoutSeconds"), _probe_field(a_probe, "timeoutSeconds")
        if m_to < a_to:
            out.append(
                f"{where} timeoutSeconds {m_to:g} is below the api's {a_to:g} ({api[0]}); "
                "the mirror's event loop is the api's (#1174)"
            )
        m_b, a_b = probe_budget_s(m_probe), probe_budget_s(a_probe)
        if m_b < a_b:
            out.append(
                f"{where} gives up after {m_b:g} s, below the api's {a_b:g} s ({api[0]}); "
                "the mirror's cold start is the api's (#1174)"
            )
    return out


def main(argv: list[str]) -> int:
    paths = argv[1:] or ["-"]
    failures: list[str] = []
    seen = 0
    for path in paths:
        stream = sys.stdin if path == "-" else open(path, encoding="utf-8")  # noqa: SIM115
        with stream:
            docs = list(yaml.safe_load_all(stream))
        if _container(docs, *_MIRROR) is not None:
            seen += 1
        failures.extend(f"{path}: {line}" for line in shortfalls(docs))
    for line in failures:
        print(line, file=sys.stderr)
    if failures:
        print(f"{len(failures)} slot-image mirror shortfall(s)", file=sys.stderr)
        return 1
    if seen:
        print(f"slot-image mirror at or above the api in {seen} render(s)")
    else:
        print("no slot-image mirror rendered")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
