#!/usr/bin/env python3
"""Fail when the operator's RBAC no longer covers what the chart renders.

The operator runs ``helm install|upgrade`` as its own ServiceAccount, so every
kind the chart renders needs create/update/delete rights in
config/rbac/{role,cluster_role}.yaml, and every Role / ClusterRole the chart
renders must be a subset of what the operator itself holds (the API refuses to
create a Role granting more than its creator has: RBAC escalation prevention).

A chart change that adds a template, or widens one of its Roles, would
otherwise pass every chart test and fail only on a cluster, as a Helm error on
the custom resource. This renders the chart in each supported shape and checks.

Needs ``helm`` and PyYAML; ``make operator-check`` runs it in the helm image
(the same one ``make charts-lint`` uses). Exit 0 = covered, 1 = a gap, 2 = the
check could not run (never reported as a pass, which is the failure this repo
has been bitten by before).
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
CHART = ROOT / "charts" / "spatiumddi"
RBAC = ROOT / "operator" / "config" / "rbac"
SAMPLE = ROOT / "operator" / "config" / "samples" / "ddi_v1alpha1_spatiumddi.yaml"

# kind -> (apiGroup, resource, namespaced)
KINDS = {
    "Service": ("", "services", True),
    "ServiceAccount": ("", "serviceaccounts", True),
    "ConfigMap": ("", "configmaps", True),
    "Secret": ("", "secrets", True),
    "PersistentVolumeClaim": ("", "persistentvolumeclaims", True),
    "Deployment": ("apps", "deployments", True),
    "StatefulSet": ("apps", "statefulsets", True),
    "Job": ("batch", "jobs", True),
    "CronJob": ("batch", "cronjobs", True),
    "HorizontalPodAutoscaler": ("autoscaling", "horizontalpodautoscalers", True),
    "Ingress": ("networking.k8s.io", "ingresses", True),
    "Role": ("rbac.authorization.k8s.io", "roles", True),
    "RoleBinding": ("rbac.authorization.k8s.io", "rolebindings", True),
    "Route": ("route.openshift.io", "routes", True),
    "Cluster": ("postgresql.cnpg.io", "clusters", True),
    "SecurityContextConstraints": ("security.openshift.io", "securitycontextconstraints", False),
}
WRITE = ["get", "list", "watch", "create", "update", "patch", "delete"]

AGENTS = [
    "--set", "dnsAgents.enabled=true", "--set", "dnsAgents.servers[0].name=ns1",
    "--set", "dhcpAgents.enabled=true", "--set", "dhcpAgents.servers[0].name=dhcp1",
]  # fmt: skip
EVERYTHING = AGENTS + [
    "--set", "ingress.enabled=true", "--set", "slotImageMirror.enabled=true",
    "--set", "api.autoscaling.enabled=true", "--set", "redis.auth.enabled=true",
    "--set", "postgresql.kind=cnpg", "--set", "postgresql.cnpg.backup.enabled=true",
    "--set", "postgresql.cnpg.caPublisher.enabled=true", "--set", "redis.kind=sentinel",
]  # fmt: skip
# Supported shapes. The appliance-only toggles (api.serviceAccount,
# api.upgradeOrchestratorRBAC, worker.serviceAccount, serviceControlRBAC,
# applianceHostMounts) are deliberately absent: they render ClusterRoles the
# operator does not hold, and docs/deployment/OPERATOR.md says so.
PROFILES = {
    "kubernetes-default": ["--set", "global.platform=kubernetes"],
    "kubernetes-everything": ["--set", "global.platform=kubernetes"] + EVERYTHING,
    "openshift-default": ["--set", "global.platform=openshift"],
    "openshift-agents": ["--set", "global.platform=openshift"] + AGENTS,
    "openshift-everything": ["--set", "global.platform=openshift"] + EVERYTHING
    + ["--set", "openshift.route.host=ddi.example.com"],
}  # fmt: skip


def load_rules(*files: str) -> set[tuple[str, str, str]]:
    held: set[tuple[str, str, str]] = set()
    for f in files:
        doc = yaml.safe_load((RBAC / f).read_text())
        for rule in doc["rules"]:
            for g in rule["apiGroups"]:
                for r in rule["resources"]:
                    for v in rule["verbs"]:
                        if "*" in (g, r, v):
                            sys.exit(f"{f}: wildcard rule {rule}: the operator's RBAC must be explicit")
                        held.add((g, r, v))
    return held


def render(args: list[str]) -> list[dict]:
    cmd = ["helm", "template", "r", str(CHART), "-n", "ns", *args]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        print(f"helm template failed: {out.stderr}", file=sys.stderr)
        sys.exit(2)
    docs = [d for d in yaml.safe_load_all(out.stdout) if d]
    if not docs:
        print("helm template rendered nothing", file=sys.stderr)
        sys.exit(2)
    return docs


def main() -> int:
    role = load_rules("role.yaml")
    cluster = load_rules("cluster_role.yaml")
    sample = yaml.safe_load(SAMPLE.read_text())["spec"]
    sample_file = pathlib.Path("/tmp/operator-sample-values.yaml")
    sample_file.write_text(yaml.safe_dump(sample))

    profiles = dict(PROFILES)
    profiles["sample-cr-kubernetes"] = ["--set", "global.platform=kubernetes", "-f", str(sample_file)]
    profiles["sample-cr-openshift"] = ["--set", "global.platform=openshift", "-f", str(sample_file)]

    problems: list[str] = []
    checked = 0
    for name, args in profiles.items():
        for doc in render(args):
            kind = doc["kind"]
            if kind not in KINDS:
                problems.append(f"[{name}] chart renders kind {kind}, unknown to check_rbac.py "
                                "and so not provably covered by the operator's RBAC")
                continue
            group, resource, namespaced = KINDS[kind]
            held = role if namespaced else cluster
            for verb in WRITE:
                checked += 1
                if (group, resource, verb) not in held:
                    problems.append(f"[{name}] {kind}: operator lacks {verb} on {group or 'core'}/{resource}")
            if kind == "Route" and doc["spec"].get("host") and ("route.openshift.io", "routes/custom-host", "create") not in role:
                problems.append(f"[{name}] Route sets spec.host: operator lacks create on routes/custom-host")
            if kind in ("Role", "ClusterRole"):
                pool = role if kind == "Role" else cluster
                for rule in doc.get("rules", []):
                    for g in rule.get("apiGroups", [""]):
                        for r in rule.get("resources", []):
                            for v in rule["verbs"]:
                                checked += 1
                                if (g, r, v) not in pool:
                                    problems.append(
                                        f"[{name}] {kind} {doc['metadata']['name']} grants {v} on "
                                        f"{g or 'core'}/{r}, which the operator does not hold "
                                        "(escalation prevention would refuse to create it)")
    if checked == 0:
        print("check_rbac: evaluated nothing", file=sys.stderr)
        return 2
    for p in sorted(set(problems)):
        print("FAIL", p)
    print(f"check_rbac: {checked} assertions over {len(profiles)} renders, {len(set(problems))} gap(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
