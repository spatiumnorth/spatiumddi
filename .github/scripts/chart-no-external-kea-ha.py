#!/usr/bin/env python3
"""No Service reachable from outside the cluster may publish Kea's HA port.

TCP 8000 on a DHCP agent pod is the Kea HA hook's dedicated peer listener.
It speaks plain HTTP with no authentication and no TLS, and it accepts the
commands HA peers send each other, lease updates included.
HA peers reach it pod-to-pod — the agent resolves ``ha_peer_url`` to an IP —
and the headless Service carries it for in-cluster DNS names, so nothing
needs it on a NodePort or a LoadBalancer.

Both the umbrella chart's ``dhcp-agent.yaml`` and the raw
``k8s/dhcp/service-dhcp.yaml`` used to list it on the external Service, next
to UDP 67. That was latent while the listener never bound (#1447); once it
binds, every node IP answered it.

``helm lint``, ``helm template`` and kubeconform all accept the port, so
this checks the rendered (or raw) Service objects directly: a ``NodePort``
or ``LoadBalancer`` Service that selects a DHCP agent must not expose port
or targetPort 8000.

Usage: chart-no-external-kea-ha.py <manifest.yaml> [<manifest.yaml> ...]
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

KEA_HA_PORT = 8000
EXTERNAL_TYPES = {"NodePort", "LoadBalancer"}


def _selects_dhcp_agent(svc: dict) -> bool:
    """True for a Service that fronts a DHCP agent pod.

    The umbrella chart labels it ``app.kubernetes.io/component: dhcp-agent``;
    the raw manifests select ``app.kubernetes.io/name: spatium-dhcp``.
    """
    selector = (svc.get("spec") or {}).get("selector") or {}
    labels = (svc.get("metadata") or {}).get("labels") or {}
    for source in (selector, labels):
        if source.get("app.kubernetes.io/component") == "dhcp-agent":
            return True
        if source.get("app.kubernetes.io/name") == "spatium-dhcp":
            return True
    return False


def _exposes_ha_port(port: dict) -> bool:
    for key in ("port", "targetPort"):
        value = port.get(key)
        if value == KEA_HA_PORT or value == str(KEA_HA_PORT):
            return True
    return False


def check(path: Path) -> list[str]:
    problems = []
    for doc in yaml.safe_load_all(path.read_text()):
        if not isinstance(doc, dict) or doc.get("kind") != "Service":
            continue
        spec = doc.get("spec") or {}
        svc_type = spec.get("type") or "ClusterIP"
        if svc_type not in EXTERNAL_TYPES or not _selects_dhcp_agent(doc):
            continue
        for port in spec.get("ports") or []:
            if _exposes_ha_port(port):
                name = (doc.get("metadata") or {}).get("name", "<unnamed>")
                problems.append(
                    f"{path}: Service {name!r} ({svc_type}) publishes TCP "
                    f"{KEA_HA_PORT}, Kea's unauthenticated HA listener; keep it "
                    "on the headless Service only"
                )
    return problems


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    problems = [p for arg in argv for p in check(Path(arg))]
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    if not problems:
        print(f"   no external Service publishes Kea's HA port ({len(argv)} file(s))")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
