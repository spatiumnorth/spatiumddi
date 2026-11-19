#!/usr/bin/env python3
"""The chart's default api and worker sizing must hold what they use (#3110).

The api's HorizontalPodAutoscaler scales on the average share of its request
that each pod uses. Before #3110 the chart requested 256Mi and aimed memory at
80 % of it, about 205 MiB, while one api process (one uvicorn worker) holds
about 305 MiB as soon as it has started. On any cluster with a metrics-server
the autoscaler therefore took an idle install from 2 replicas to its maximum
of 10 within about three minutes, and never came back: a process's memory is
its own baseline, so adding replicas cannot lower the average. The CPU target
was close too: 70 % of a 100m request is 70m, and each of two replicas used
about 100m under the light load the sizing guide measures (amd64).

Measured on one k3s 1.36 node with metrics-server, the chart's defaults and
only the image tag set (``docs/deployment/SIZING.md``, Kubernetes; arm64 and
amd64 within about 6 %). The light load is four clients looping over 29 list
pages with a 0.5 s pause, about 6 requests a second.

Rules, checked in every render that carries the api Deployment:

* Every resource metric the api's autoscaler scales on aims at least at what
  one api pod uses at rest and under the light load: ``averageUtilization``
  % of the container's request is at least ``API_MEMORY_MIB`` of memory and
  ``API_CPU_M`` of CPU. A target below that sends the autoscaler past
  ``minReplicas`` with nothing to spread, and for memory it never returns.
* The api's memory request holds that working set: a pod above its memory
  request is the kubelet's first eviction candidate under node memory
  pressure, whatever its priority (#1828), and the request is what a memory
  target is a share of.
* The api's memory limit is at least ``HEADROOM`` times the most one api
  process held taking all of the light load (``API_PEAK_MIB``), the sizing
  guide's own headroom factor.
* The worker's memory limit is at least ``HEADROOM`` times the most one worker
  pod held with no limit at all (``WORKER_PEAK_MIB``). Its processes grow for
  about the first hour and level off near 1 GiB, so the old 1Gi left about
  0.1 GiB for a burst of work.

The appliance sizes the api and worker limits from the node's RAM
(``k8s_api.control_plane_resources``); run this over the chart's defaults.

``--expect-metrics cpu[,memory]`` also requires the api's autoscaler to scale
on exactly those resources (memory is opt-in since #3110). ``--require`` fails
when no render carried the api Deployment.

Usage: chart-control-plane-footprint.py [--require] [--expect-metrics LIST]
           <manifest.yaml|-> [<manifest.yaml|-> ...]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

import yaml

# Measured per pod at the chart's defaults (#3110, docs/deployment/SIZING.md).
# The most one api pod's working set held at rest and under the light load:
# 373 MiB on two replicas, amd64 (366 on arm64; about 305 at rest on both).
API_MEMORY_MIB = 373
# CPU per api pod under the light load on two replicas, amd64 (55 to 73m on
# arm64); at rest about 3m.
API_CPU_M = 100
# The most one api process held taking all of the light load alone (Docker
# Compose, one process): 469 MiB on arm64, 405 on amd64.
API_PEAK_MIB = 469
# The most one worker pod (four processes) held with no limit: 1084 MiB of
# cgroup memory 28 minutes in (Docker Compose, arm64); 0.87 to 0.99 GiB on
# amd64 once levelled off.
WORKER_PEAK_MIB = 1084
# The sizing guide's headroom over measured use.
HEADROOM = 1.5

_COMPONENT = "app.kubernetes.io/component"
_QTY = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]*)\s*$")
_MIB = {
    "": 1 / 2**20,
    "k": 1e3 / 2**20,
    "M": 1e6 / 2**20,
    "G": 1e9 / 2**20,
    "Ki": 1 / 1024,
    "Mi": 1,
    "Gi": 1024,
    "Ti": 1024 * 1024,
}


def _mib(q: Any) -> float | None:
    m = _QTY.match(str(q)) if q is not None else None
    if not m or m.group(2) not in _MIB:
        return None
    return float(m.group(1)) * _MIB[m.group(2)]


def _millicores(q: Any) -> float | None:
    m = _QTY.match(str(q)) if q is not None else None
    if not m or m.group(2) not in ("", "m"):
        return None
    return float(m.group(1)) * (1 if m.group(2) == "m" else 1000)


def _component(doc: dict[str, Any]) -> str:
    return str(((doc.get("metadata") or {}).get("labels") or {}).get(_COMPONENT) or "")


def _container(doc: dict[str, Any], name: str) -> dict[str, Any] | None:
    pod = ((doc.get("spec") or {}).get("template") or {}).get("spec") or {}
    return next((c for c in pod.get("containers") or [] if c.get("name") == name), None)


def check(
    docs: list[dict[str, Any]], where: str, expect: list[str] | None
) -> tuple[list[str], bool]:
    problems: list[str] = []
    api = next((d for d in docs if d.get("kind") == "Deployment" and _component(d) == "api"), None)
    if api is None:
        return problems, False
    name = (api.get("metadata") or {}).get("name")
    container = _container(api, "api")
    if container is None:
        return [f"{where}: Deployment {name!r} has no container named 'api' (#3110)"], True
    res = container.get("resources") or {}
    requests, limits = res.get("requests") or {}, res.get("limits") or {}

    req_mem = _mib(requests.get("memory"))
    if req_mem is None or req_mem < API_MEMORY_MIB:
        problems.append(
            f"{where}: the api's memory request is {requests.get('memory', 'unset')}, below "
            f"the {API_MEMORY_MIB} MiB one api pod holds at rest and under light load: "
            "the pod runs above its request (#3110)"
        )
    lim_mem = _mib(limits.get("memory"))
    want_lim = API_PEAK_MIB * HEADROOM
    if lim_mem is not None and lim_mem < want_lim:
        problems.append(
            f"{where}: the api's memory limit is {limits['memory']}, below {want_lim:.0f} MiB "
            f"({HEADROOM} x the {API_PEAK_MIB} MiB one api process held taking all of the "
            "light load) (#3110)"
        )

    got_metrics: list[str] = []
    for hpa in docs:
        if hpa.get("kind") != "HorizontalPodAutoscaler":
            continue
        ref = (hpa.get("spec") or {}).get("scaleTargetRef") or {}
        if ref.get("kind") != "Deployment" or ref.get("name") != name:
            continue
        for metric in (hpa.get("spec") or {}).get("metrics") or []:
            resource = metric.get("resource") or {}
            target = resource.get("target") or {}
            rname = resource.get("name")
            got_metrics.append(str(rname))
            if metric.get("type") != "Resource" or target.get("type") != "Utilization":
                continue
            share = float(target.get("averageUtilization") or 0) / 100
            if rname == "memory":
                aim = None if req_mem is None else share * req_mem
                if aim is None or aim < API_MEMORY_MIB:
                    problems.append(
                        f"{where}: the api autoscaler aims memory at "
                        f"{target.get('averageUtilization')} % of {requests.get('memory', 'no request')}"
                        f"{'' if aim is None else f' = {aim:.0f} MiB'}, below the {API_MEMORY_MIB} MiB "
                        "one api pod holds at rest and under light load: it scales to its maximum "
                        "with nothing to spread, and memory does not fall as replicas are added (#3110)"
                    )
            elif rname == "cpu":
                req_cpu = _millicores(requests.get("cpu"))
                aim = None if req_cpu is None else share * req_cpu
                if aim is None or aim < API_CPU_M:
                    problems.append(
                        f"{where}: the api autoscaler aims CPU at "
                        f"{target.get('averageUtilization')} % of {requests.get('cpu', 'no request')}"
                        f"{'' if aim is None else f' = {aim:.0f}m'}, below the {API_CPU_M}m each of "
                        "two api pods uses under light load: light use scales it out (#3110)"
                    )
    if expect is not None and sorted(got_metrics) != sorted(expect):
        problems.append(
            f"{where}: the api autoscaler scales on {sorted(got_metrics) or 'nothing'}, "
            f"expected {sorted(expect)} (#3110: memory is opt-in)"
        )

    worker = next(
        (d for d in docs if d.get("kind") == "Deployment" and _component(d) == "worker"), None
    )
    wcontainer = None if worker is None else _container(worker, "worker")
    if worker is not None and wcontainer is None:
        problems.append(f"{where}: the worker Deployment has no container named 'worker' (#3110)")
    if wcontainer is not None:
        wlim = ((wcontainer.get("resources") or {}).get("limits") or {}).get("memory")
        want_w = WORKER_PEAK_MIB * HEADROOM
        wlim_mib = _mib(wlim)
        if wlim_mib is not None and wlim_mib < want_w:
            problems.append(
                f"{where}: the worker's memory limit is {wlim}, below {want_w:.0f} MiB "
                f"({HEADROOM} x the {WORKER_PEAK_MIB} MiB one worker held with no limit): "
                "it levels off near the limit with no room for a burst (#3110)"
            )
    return problems, True


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", help="rendered manifests, or - for stdin")
    parser.add_argument("--require", action="store_true")
    parser.add_argument("--expect-metrics", default=None, help="e.g. cpu or cpu,memory")
    args = parser.parse_args(argv)
    expect = (
        None if args.expect_metrics is None else [m for m in args.expect_metrics.split(",") if m]
    )

    problems: list[str] = []
    checked = 0
    for arg in args.files:
        text = sys.stdin.read() if arg == "-" else Path(arg).read_text(encoding="utf-8")
        docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
        found, did = check(docs, arg, expect)
        problems += found
        checked += int(did)
    if args.require and not checked:
        problems.append("no render carried the api Deployment")
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    if not problems:
        print(f"   the default sizing holds its measured use ({checked} render(s))")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
