"""#3620 — the supervisor's namespace Role must let the Fleet workloads list
and restart picker through the kubeapi proxy, and grant nothing broader."""

from __future__ import annotations

import pathlib
import re

import yaml

_ROOT = pathlib.Path(__file__).resolve().parents[3]
_TEMPLATE = _ROOT / "charts/spatiumddi-appliance/templates/supervisor-rbac.yaml"


def _role_rules() -> list[dict]:
    plain = re.sub(r"\{\{.*?\}\}", "", _TEMPLATE.read_text(), flags=re.S)
    docs = [d for d in yaml.safe_load_all(plain) if d]
    role = next(
        d
        for d in docs
        if d.get("kind") == "Role" and d["metadata"]["name"] == "spatium-supervisor-namespace"
    )
    assert role["metadata"]["namespace"] == "spatium"
    return role["rules"]


def _apps_workload_verbs() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for r in _role_rules():
        if r.get("apiGroups") != ["apps"] or r.get("resourceNames"):
            continue
        for res in r["resources"]:
            out.setdefault(res, set()).update(r["verbs"])
    return out


def test_workloads_get_list_patch_and_nothing_more() -> None:
    assert _apps_workload_verbs() == {
        "deployments": {"get", "list", "patch"},
        "statefulsets": {"get", "list", "patch"},
        "daemonsets": {"get", "list", "patch"},
    }


def test_no_other_apps_group_grant_in_the_namespace_role() -> None:
    for r in _role_rules():
        if "apps" in r.get("apiGroups", []):
            assert set(r["resources"]) <= {"deployments", "statefulsets", "daemonsets"}
            assert not set(r["verbs"]) & {"create", "update", "delete", "deletecollection", "*"}
