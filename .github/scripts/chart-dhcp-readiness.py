#!/usr/bin/env python3
"""A DHCP agent's readiness probe must not gate on Kea's HA listener (#1589).

TCP 8000 on a DHCP agent pod is the Kea HA hook's peer listener. A
standalone Kea server (no HA) never binds it — nothing else in the pod
listens there — and an HA member binds it only while the HA hook is
loaded. A ``tcpSocket: {port: 8000}`` readiness probe therefore keeps a
healthy standalone pod out of its Service's endpoints forever, and
drops HA pods whenever the listener unbinds.

Readiness has to probe what "ready to serve DHCP" means without HA:
the Kea control socket, the same check the image's own HEALTHCHECK
runs (``test -S /run/kea/kea4-ctrl-socket``; the v6 socket counts too,
for a v6-only server).

Checks every pod template in the given files whose workload is a DHCP
agent — labelled ``app.kubernetes.io/component: dhcp-agent`` (umbrella
chart), ``app.kubernetes.io/name: spatium-dhcp`` (raw manifests) or
named ``dhcp-kea*`` (appliance chart / raw manifests) — and fails any
container whose readinessProbe is a tcpSocket probe on port 8000.

``--require-kea-socket`` additionally fails a checked container whose
readiness probe is not an exec probe testing the Kea control socket.
Apply it to the umbrella chart renders and the raw ``k8s/dhcp``
manifests, whose probe this issue fixes to exactly that. The appliance
chart is exempt from the extra requirement: its probe gates on the
agent's ``.ready`` marker plus UDP/67 bound in /proc/net/udp, which is
at least as strong and equally HA-independent.

``--require`` fails when no DHCP agent container was checked at all,
so a render that silently stops exercising the template cannot pass.

Usage: chart-dhcp-readiness.py [--require] [--require-kea-socket]
           <manifest.yaml> [<manifest.yaml> ...]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

KEA_HA_PORT = 8000
WORKLOAD_KINDS = {"StatefulSet", "DaemonSet", "Deployment", "ReplicaSet"}


def _is_dhcp_agent_workload(doc: dict) -> bool:
    meta = doc.get("metadata") or {}
    name = meta.get("name") or ""
    labels = meta.get("labels") or {}
    template = ((doc.get("spec") or {}).get("template") or {}).get("metadata") or {}
    template_labels = template.get("labels") or {}
    for source in (labels, template_labels):
        if source.get("app.kubernetes.io/component") in ("dhcp-agent", "dhcp-kea"):
            return True
        if source.get("app.kubernetes.io/name") in ("spatium-dhcp", "dhcp-kea"):
            return True
    return name.startswith("dhcp-kea") or name.startswith("dhcp-")


def _containers(doc: dict) -> list[dict]:
    spec = (((doc.get("spec") or {}).get("template") or {}).get("spec")) or {}
    return [c for c in (spec.get("containers") or []) if isinstance(c, dict)]


def check(path: Path, require_kea_socket: bool) -> tuple[list[str], int]:
    problems = []
    checked = 0
    for doc in yaml.safe_load_all(path.read_text()):
        if not isinstance(doc, dict) or doc.get("kind") not in WORKLOAD_KINDS:
            continue
        if not _is_dhcp_agent_workload(doc):
            continue
        workload = (doc.get("metadata") or {}).get("name", "<unnamed>")
        for container in _containers(doc):
            probe = container.get("readinessProbe")
            if not isinstance(probe, dict):
                continue
            checked += 1
            cname = container.get("name", "<unnamed>")
            tcp = probe.get("tcpSocket") or {}
            if tcp.get("port") in (KEA_HA_PORT, str(KEA_HA_PORT)):
                problems.append(
                    f"{path}: {workload} container {cname!r} readinessProbe "
                    f"is tcpSocket port {KEA_HA_PORT}, Kea's HA peer "
                    "listener — a standalone server never binds it, so the "
                    "pod never becomes Ready (#1589); probe the Kea "
                    "control socket instead"
                )
                continue
            if require_kea_socket:
                command = " ".join(
                    str(part) for part in ((probe.get("exec") or {}).get("command") or [])
                )
                if "kea4-ctrl-socket" not in command and "kea6-ctrl-socket" not in command:
                    problems.append(
                        f"{path}: {workload} container {cname!r} readinessProbe "
                        "does not test the Kea control socket "
                        "(/run/kea/kea4-ctrl-socket) — readiness must not "
                        "depend on the HA listener (#1589)"
                    )
    return problems, checked


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", help="rendered or raw manifests")
    parser.add_argument("--require", action="store_true")
    parser.add_argument("--require-kea-socket", action="store_true")
    args = parser.parse_args(argv)

    problems: list[str] = []
    checked = 0
    for arg in args.files:
        found, n = check(Path(arg), args.require_kea_socket)
        problems.extend(found)
        checked += n
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    if args.require and checked == 0:
        print(
            "FAIL no DHCP agent container with a readinessProbe was "
            "checked — the render no longer exercises the DHCP agent "
            "template (#1589)",
            file=sys.stderr,
        )
        return 1
    if not problems:
        print(
            f"   DHCP agent readiness does not gate on the Kea HA port "
            f"({checked} container(s) in {len(args.files)} file(s))"
        )
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
