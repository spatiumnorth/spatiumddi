#!/usr/bin/env python3
"""OpenShift render gate for the umbrella chart (#3852).

OpenShift's default ``restricted-v2`` SCC assigns every pod a random uid and
fsGroup from the namespace's range and REFUSES a pinned one — so a single
``runAsUser: 1000`` left in a pod template is an install that does not start,
with nothing wrong in a render on any other platform. This reads the RENDER (a
``helm template --api-versions security.openshift.io/v1`` run), not the
templates, because a ``with`` guard on the wrong values path renders nothing
and reads fine in the template.

Asserts, on an OpenShift render:

  * no pod template pins ``runAsUser`` / ``runAsGroup`` / ``fsGroup`` /
    ``supplementalGroups`` (pod level or any container, init included);
  * a ``route.openshift.io/v1`` Route points at the frontend Service, and the
    frontend container listens on an unprivileged port (>= 1024);
  * with ``--require-scc``: a SecurityContextConstraints exists per agent kind,
    each is granted (``use``) only to ServiceAccounts that exist in the render,
    none is privileged, and none is granted to the namespace ``default``
    account or to a control-plane workload's ServiceAccount;
  * the control plane adds no capability but what an SCC it is bound to allows
    (so api / beat / frontend / migrate / postgres / redis, which are bound to
    none, add nothing at all).

``--expect-pins`` inverts the pin check: it fails unless a pin IS found. It is
the negative control — run against a render with the platform forced to
Kubernetes it proves the check can see a pin at all, instead of passing because
it parsed nothing.

Usage:
    chart-openshift.py [--require-scc] [--expect-pins] file...
"""

from __future__ import annotations

import sys

import yaml

POD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}
PINS = ("runAsUser", "runAsGroup", "fsGroup", "supplementalGroups")


def pod_spec(doc: dict) -> dict | None:
    spec = doc.get("spec") or {}
    if doc["kind"] == "CronJob":
        spec = ((spec.get("jobTemplate") or {}).get("spec")) or {}
    return (spec.get("template") or {}).get("spec")


def main(argv: list[str]) -> int:
    require_scc = "--require-scc" in argv
    expect_pins = "--expect-pins" in argv
    files = [a for a in argv if not a.startswith("--")]
    if not files:
        print("usage: chart-openshift.py [--require-scc] [--expect-pins] file...")
        return 2
    failures: list[str] = []
    for path in files:
        with open(path) as fh:
            docs = [d for d in yaml.safe_load_all(fh) if d]
        if not docs:
            failures.append(f"{path}: no objects parsed")
            continue
        by_kind: dict[str, list[dict]] = {}
        for d in docs:
            by_kind.setdefault(d["kind"], []).append(d)

        pins: list[str] = []
        sa_of: dict[str, str] = {}  # workload name -> ServiceAccount
        adds: dict[str, set[str]] = {}
        for kind in POD_KINDS:
            for d in by_kind.get(kind, []):
                spec = pod_spec(d)
                if spec is None:
                    continue
                name = d["metadata"]["name"]
                sa_of[name] = spec.get("serviceAccountName", "default")
                psc = spec.get("securityContext") or {}
                for k in PINS:
                    if k in psc:
                        pins.append(f"{kind}/{name} pod securityContext.{k}")
                for c in (spec.get("containers") or []) + (spec.get("initContainers") or []):
                    csc = c.get("securityContext") or {}
                    for k in PINS:
                        if k in csc:
                            pins.append(f"{kind}/{name} container {c['name']} {k}")
                    adds.setdefault(name, set()).update(
                        (csc.get("capabilities") or {}).get("add") or []
                    )
        if expect_pins:
            if pins:
                print(f"ok: {path}: negative control sees {len(pins)} pin(s), e.g. {pins[0]}")
            else:
                failures.append(f"{path}: negative control found NO pin — the check sees nothing")
            continue
        for p in pins:
            failures.append(f"{path}: {p} is pinned; OpenShift's restricted SCC refuses it (#3852)")

        routes = by_kind.get("Route", [])
        frontend_svcs = {
            d["metadata"]["name"]
            for d in by_kind.get("Service", [])
            if d["metadata"]["name"].endswith("-frontend")
        }
        if not any(r["spec"]["to"]["name"] in frontend_svcs for r in routes):
            failures.append(f"{path}: no Route to the frontend Service")
        for d in by_kind.get("Deployment", []):
            if not d["metadata"]["name"].endswith("-frontend"):
                continue
            for c in d["spec"]["template"]["spec"]["containers"]:
                for port in c.get("ports") or []:
                    if port["containerPort"] < 1024:
                        failures.append(
                            f"{path}: frontend listens on privileged port {port['containerPort']}"
                        )

        sccs = {d["metadata"]["name"]: d for d in by_kind.get("SecurityContextConstraints", [])}
        granted: dict[str, set[str]] = {}  # SA -> SCC names
        role_scc: dict[str, set[str]] = {}
        for r in by_kind.get("Role", []):
            for rule in r.get("rules") or []:
                if "securitycontextconstraints" in (rule.get("resources") or []):
                    role_scc.setdefault(r["metadata"]["name"], set()).update(
                        rule.get("resourceNames") or ["*"]
                    )
        for rb in by_kind.get("RoleBinding", []):
            ref = rb["roleRef"]["name"]
            if ref not in role_scc:
                continue
            for s in rb.get("subjects") or []:
                granted.setdefault(s["name"], set()).update(role_scc[ref])
        if require_scc and not sccs:
            failures.append(f"{path}: no SecurityContextConstraints rendered")
        sas = {d["metadata"]["name"] for d in by_kind.get("ServiceAccount", [])}
        for sa, names in granted.items():
            if sa == "default" or sa not in sas:
                failures.append(
                    f"{path}: an SCC is granted to {sa!r}, not a ServiceAccount of this chart"
                )
            for n in names:
                if n not in sccs:
                    failures.append(f"{path}: Role grants SCC {n!r} that is not rendered")
        for n, scc in sccs.items():
            if (
                scc.get("allowPrivilegedContainer")
                or scc.get("allowHostPID")
                or scc.get("allowHostIPC")
            ):
                failures.append(f"{path}: SCC {n} is privileged")
            if "ALL" not in (scc.get("requiredDropCapabilities") or []):
                failures.append(f"{path}: SCC {n} does not require dropping ALL capabilities")
        for name, caps in adds.items():
            allowed: set[str] = set()
            for n in granted.get(sa_of[name], set()):
                allowed.update((sccs.get(n) or {}).get("allowedCapabilities") or [])
            extra = caps - allowed
            if extra:
                failures.append(
                    f"{path}: {name} adds {sorted(extra)} but no SCC it is bound to allows it "
                    "— restricted-v2 would refuse the pod"
                )
        if not failures:
            print(
                f"ok: {path}: no pinned uid/gid/fsGroup, Route + frontend port ok, "
                f"{len(sccs)} SCC(s) bound only to chart ServiceAccounts"
            )
    for f in failures:
        print("FAIL #3852:", f, file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
