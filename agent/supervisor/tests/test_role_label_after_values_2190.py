"""A role label never schedules a pod from the previous chart's values (#2190).

One roles save on a one-node appliance moved it from BIND9 in DNS group A to
PowerDNS in group B. The heartbeat reconciled the node labels BEFORE it wrote
the new chart values, and the dns-powerdns DaemonSet already existed (one DNS
key renders all three engines) with the previous chart's ``AGENT_GROUP=A``. So
the label flip alone started a PowerDNS pod in A; it registered a new server row
in A a second before helm-controller rolled the template to B, and its cached
token kept it there. B's zones answered REFUSED.

These tests drive the real ``apply_role_assignment`` / ``reconcile_node_labels``
/ heartbeat lifecycle against a fake kubeapi whose DaemonSet templates follow
the HelmChart values only after helm-controller's upgrade job has run (a few
reads after the write), and record, for every label set, the ``AGENT_GROUP`` a
pod scheduled at that instant would start with.
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
import yaml

from spatium_supervisor import appliance_state, heartbeat, k8s_api, service_lifecycle
from spatium_supervisor.role_orchestrator import compute_target_env, render_env_file

NODE = "ddi1"
DNS_KEY = "a" * 48
DHCP_KEY = "b" * 48
_DAEMONSETS = {
    "dnsBind9": ("dns-bind9", "spatium.io/role-dns-bind9"),
    "dnsPowerdns": ("dns-powerdns", "spatium.io/role-dns-powerdns"),
    "dnsTechnitium": ("dns-technitium", "spatium.io/role-dns-technitium"),
    "dhcpKea": ("dhcp-kea", "spatium.io/role-dhcp"),
}


def _assignment(roles: list[str], dns_group: str) -> dict:
    return {
        "roles": roles,
        "dns_group_name": dns_group,
        "dhcp_group_name": "dhcp-default",
        "dns_agent_key": DNS_KEY,
        "dhcp_agent_key": DHCP_KEY,
    }


class Appliance:
    """A one-node k3s: the role HelmChart, the agent DaemonSets helm-controller
    renders from it (``roll_reads`` template reads after each write), and the
    node's labels. ``started`` records ``(daemonset, AGENT_GROUP)`` for every
    pod a label set would schedule at that moment."""

    def __init__(self, roll_reads: int) -> None:
        self.roll_reads = roll_reads
        self.templates: dict[str, str] = {}  # daemonset -> AGENT_GROUP
        self.pending: dict[str, str] | None = None
        self.reads_since_write = 0
        self.labels: dict[str, str] = {}
        self.started: list[tuple[str, str]] = []
        self.events: list[str] = []

    def roll_now(self) -> None:
        if self.pending is not None:
            self.templates = self.pending
            self.pending = None

    def apply_helmchart(
        self, name: str, *, values: dict, chart_content_b64: str, **_: object
    ):
        assert name == "spatiumddi-appliance"
        base64.b64decode(chart_content_b64)
        doc = yaml.safe_load(yaml.safe_dump(values))
        self.pending = {
            ds: str((doc.get(block) or {}).get("serverGroupName") or "")
            for block, (ds, _label) in _DAEMONSETS.items()
            if (doc.get(block) or {}).get("enabled")
        }
        self.reads_since_write = 0
        self.events.append("values")
        if self.roll_reads == 0:
            self.roll_now()
        return True, None

    def daemonset_template_env(self, name: str, *, env_name: str, **_: object):
        assert env_name == "AGENT_GROUP"
        self.reads_since_write += 1
        if self.pending is not None and self.reads_since_write > self.roll_reads:
            self.roll_now()
        if name not in self.templates:
            return False, None, None
        return True, self.templates[name], None

    def patch_node_labels(self, node: str, diff: dict[str, str | None]):
        assert node == NODE
        self.events.append("labels")
        for key, value in diff.items():
            if value is None:
                self.labels.pop(key, None)
            else:
                if key not in self.labels:
                    for ds, label in _DAEMONSETS.values():
                        if label == key and ds in self.templates:
                            self.started.append((ds, self.templates[ds]))
                self.labels[key] = value
        return True, None


@pytest.fixture()
def clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """A fake monotonic clock that the apply's bounded wait advances."""
    now = [1000.0]

    def _sleep(seconds: float) -> None:
        now[0] += seconds

    monkeypatch.setattr(service_lifecycle, "_sleep", _sleep, raising=False)
    monkeypatch.setattr(service_lifecycle, "_monotonic", lambda: now[0], raising=False)
    monkeypatch.setattr(service_lifecycle, "_label_held_since", {}, raising=False)
    return now


def _appliance(monkeypatch: pytest.MonkeyPatch, roll_reads: int) -> Appliance:
    app = Appliance(roll_reads)
    monkeypatch.setattr(
        appliance_state, "detect_appliance_variant", lambda: "appliance"
    )
    monkeypatch.setattr(
        appliance_state, "read_cluster_join_state", lambda: (None, None)
    )
    monkeypatch.setenv("CONTROL_PLANE_URL", "https://192.0.2.10/")
    monkeypatch.setenv("SPATIUMDDI_VERSION", "2026.10.18-1")
    monkeypatch.setattr(service_lifecycle, "_resolve_node_name", lambda: NODE)
    monkeypatch.setattr(
        service_lifecycle,
        "k3s_available",
        lambda: service_lifecycle.K3sEnvironment(available=True),
    )
    monkeypatch.setattr(service_lifecycle, "_read_chart_tarball", lambda: b"chart")
    monkeypatch.setattr(
        k8s_api, "cluster_node_names", lambda timeout=5.0: ([NODE], None)
    )
    monkeypatch.setattr(k8s_api, "node_role_labels", lambda **_: (set(), None))
    monkeypatch.setattr(k8s_api, "_helmchart_values", lambda *a, **k: {})
    monkeypatch.setattr(k8s_api, "apply_helmchart", app.apply_helmchart)
    monkeypatch.setattr(k8s_api, "patch_node_labels", app.patch_node_labels)
    monkeypatch.setattr(
        k8s_api, "daemonset_template_env", app.daemonset_template_env, raising=False
    )
    return app


def _env(tmp_path: Path, assignment: dict) -> tuple[list[str], Path]:
    env_file = tmp_path / "role-compose.env"
    target = compute_target_env(assignment)
    env_file.write_text(render_env_file(target), encoding="utf-8")
    return target.profiles, env_file


def _bind9_in_a(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, app: Appliance
) -> None:
    """The starting state: BIND9 serving group A, every DNS DaemonSet rendered
    with ``AGENT_GROUP=A`` (one key renders all three engines)."""
    profiles, env_file = _env(tmp_path, _assignment(["dhcp", "dns-bind9"], "A"))
    app.roll_reads = 0
    assert service_lifecycle.apply_role_assignment(profiles, env_file).state == "ready"
    assert app.templates["dns-powerdns"] == "A"
    assert app.labels.get("spatium.io/role-dns-bind9") == "true"
    app.started.clear()
    app.events.clear()


@pytest.mark.parametrize("roll_reads", [1, 3, 8])
def test_the_engine_and_group_swap_never_starts_a_pod_in_the_old_group(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, clock: list[float], roll_reads: int
) -> None:
    """THE REGRESSION. BIND9 in A -> PowerDNS in B in one save: the PowerDNS
    label is set only once the dns-powerdns template carries B, so the only
    pod it starts registers in B."""
    app = _appliance(monkeypatch, roll_reads)
    _bind9_in_a(monkeypatch, tmp_path, app)
    app.roll_reads = roll_reads

    profiles, env_file = _env(tmp_path, _assignment(["dhcp", "dns-powerdns"], "B"))
    result = service_lifecycle.apply_role_assignment(profiles, env_file)

    assert result.state == "ready"
    assert app.events[0] == "values", "the values must be written before any label"
    assert app.labels.get("spatium.io/role-dns-powerdns") == "true"
    assert "spatium.io/role-dns-bind9" not in app.labels
    assert app.started == [("dns-powerdns", "B")]


def test_a_template_that_has_not_rolled_holds_the_label_to_the_next_reconcile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, clock: list[float]
) -> None:
    """helm-controller slower than the apply's bounded wait: the label is held,
    not set with the old group, and the heartbeat's reconcile sets it once the
    template has rolled."""
    app = _appliance(monkeypatch, roll_reads=10_000)
    _bind9_in_a(monkeypatch, tmp_path, app)
    app.roll_reads = 10_000

    profiles, env_file = _env(tmp_path, _assignment(["dhcp", "dns-powerdns"], "B"))
    service_lifecycle.apply_role_assignment(profiles, env_file)
    assert "spatium.io/role-dns-powerdns" not in app.labels
    assert app.started == []

    ok, err = service_lifecycle.reconcile_node_labels(profiles, env_file)
    assert ok, err
    assert "spatium.io/role-dns-powerdns" not in app.labels

    app.roll_now()
    ok, err = service_lifecycle.reconcile_node_labels(profiles, env_file)
    assert ok, err
    assert app.labels.get("spatium.io/role-dns-powerdns") == "true"
    assert app.started == [("dns-powerdns", "B")]


def test_a_hold_is_bounded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, clock: list[float]
) -> None:
    """A template that never converges cannot keep a role off a node for ever."""
    app = _appliance(monkeypatch, roll_reads=10_000)
    _bind9_in_a(monkeypatch, tmp_path, app)
    app.roll_reads = 10_000
    profiles, env_file = _env(tmp_path, _assignment(["dhcp", "dns-powerdns"], "B"))
    service_lifecycle.apply_role_assignment(profiles, env_file)
    assert "spatium.io/role-dns-powerdns" not in app.labels

    clock[0] += service_lifecycle._LABEL_HOLD_MAX_SECONDS
    service_lifecycle.reconcile_node_labels(profiles, env_file)
    assert app.labels.get("spatium.io/role-dns-powerdns") == "true"


def test_a_role_whose_daemonset_does_not_exist_yet_is_labelled_at_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, clock: list[float]
) -> None:
    """Nothing to schedule from: helm creates the DaemonSet from the new values,
    so holding the label would only delay the role."""
    app = _appliance(monkeypatch, roll_reads=10_000)
    profiles, env_file = _env(tmp_path, _assignment(["dns-bind9"], "A"))
    service_lifecycle.apply_role_assignment(profiles, env_file)
    assert app.labels.get("spatium.io/role-dns-bind9") == "true"
    assert clock[0] == 1000.0, "no wait when nothing is stale"


def test_the_heartbeat_writes_the_values_before_it_reconciles_the_labels(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, clock: list[float]
) -> None:
    """The heartbeat half: the apply (values) runs before the label reconcile
    on the tick the role env changed. The reconcile used to run first and flip
    the label onto the previous chart's DaemonSet."""
    app = _appliance(monkeypatch, roll_reads=10_000)
    _bind9_in_a(monkeypatch, tmp_path, app)
    app.roll_reads = 10_000
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    profiles, env_file = _env(tmp_path, _assignment(["dhcp", "dns-powerdns"], "B"))
    rendered = env_file.read_text(encoding="utf-8")

    heartbeat._run_role_lifecycle(state_dir, profiles, rendered, env_file)

    assert app.events[0] == "values"
    assert app.started == []
    assert "spatium.io/role-dns-powerdns" not in app.labels


def test_the_gate_table_matches_the_values_the_chart_renders() -> None:
    """``_ROLE_AGENT_GROUP`` names the role-env key the chart renders into each
    DaemonSet's ``AGENT_GROUP``; it must agree with ``_build_values``."""
    env = {
        "DNS_AGENT_KEY": DNS_KEY,
        "DHCP_AGENT_KEY": DHCP_KEY,
        "AGENT_GROUP": "dns-g",
        "DHCP_AGENT_GROUP": "dhcp-g",
    }
    values = service_lifecycle._build_values(["dhcp", "dns-bind9"], env)
    for role, (_ds, env_key) in service_lifecycle._ROLE_AGENT_GROUP.items():
        block = service_lifecycle._PROFILE_TO_HELM_KEY[role]
        assert values[block]["serverGroupName"] == env[env_key], role  # type: ignore[index]


def test_supervisor_rbac_can_read_role_daemonsets():
    """#2403 — the label gate reads each role DaemonSet's template; without
    RBAC every read is a 403 and the gate never holds. Pin the rule."""
    import pathlib

    import yaml

    root = pathlib.Path(__file__).resolve().parents[3]
    src = (root / "charts/spatiumddi-appliance/templates/supervisor-rbac.yaml").read_text()
    # Strip Helm template directives so the YAML parses.
    import re

    plain = re.sub(r"\{\{.*?\}\}", "", src, flags=re.S)
    docs = [d for d in yaml.safe_load_all(plain) if d]
    role = next(
        d
        for d in docs
        if d.get("kind") == "Role" and d["metadata"]["name"] == "spatium-supervisor-namespace"
    )
    assert any(
        "apps" in r.get("apiGroups", [])
        and "daemonsets" in r.get("resources", [])
        and "get" in r.get("verbs", [])
        for r in role["rules"]
    ), "the supervisor must be able to get role DaemonSets (#2403)"
