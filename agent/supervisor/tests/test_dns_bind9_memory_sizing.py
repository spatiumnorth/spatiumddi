"""dns-bind9's memory limit is sized from node RAM (#2223).

ddi-pg's scale lab hit the fixed 2Gi limit at about 2M records and named was
OOM-killed. The supervisor now writes ``dnsBind9.memory`` into the role chart:
a quarter of the smallest DNS node's RAM, rounded to whole GiB, floor 2Gi, cap
8Gi, request an eighth of the limit. The chart applies it only where
``dnsBind9.resources`` does not set memory itself, so an operator's override
wins; that half is rendered by ``.github/scripts/charts-render-check.sh``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from spatium_supervisor import appliance_state, k8s_api, service_lifecycle
from spatium_supervisor.k8s_api import dns_sizing_memory_mib as real_dns_sizing_memory_mib
from spatium_supervisor.role_orchestrator import compute_target_env, render_env_file

GIB = 1024


# ── the arithmetic ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("node_mib", "limit", "req"),
    [
        (4 * GIB, "2Gi", "256Mi"),  # a quarter is 1Gi: the floor
        (16 * GIB, "4Gi", "512Mi"),
        (64 * GIB, "8Gi", "1024Mi"),  # a quarter is 16Gi: the cap
        (256 * GIB, "8Gi", "1024Mi"),
        (12 * GIB, "3Gi", "384Mi"),
        (2 * GIB, "2Gi", "256Mi"),  # below the floor, never below the old 2Gi
    ],
)
def test_limit_is_a_quarter_of_node_ram_between_2_and_8_gib(
    node_mib: int, limit: str, req: str
) -> None:
    assert k8s_api.dns_bind9_memory(node_mib) == {"limit": limit, "request": req}


def test_a_real_16_gb_node_reads_4gi_not_a_mib_value() -> None:
    """A "16 GB" VM reports a little under 16 GiB (the kernel and firmware
    take some), so the quarter is rounded to whole GiB: the limit moves only
    when the node really changes size, never with a few MiB of MemTotal."""
    assert k8s_api.dns_bind9_memory(15_880)["limit"] == "4Gi"
    assert k8s_api.dns_bind9_memory(16_100)["limit"] == "4Gi"


@pytest.mark.parametrize("unknown", [None, 0, -1])
def test_an_unknown_size_leaves_the_chart_default(unknown: int | None) -> None:
    assert k8s_api.dns_bind9_memory(unknown) == {}


@pytest.mark.parametrize(
    ("quantity", "mib"),
    [("16374512Ki", 15990), ("4Gi", 4096), ("2048Mi", 2048), ("17179869184", 16384), ("x", None)],
)
def test_quantity_mib(quantity: str, mib: int | None) -> None:
    assert k8s_api.quantity_mib(quantity) == mib


# ── which node decides ──────────────────────────────────────────────────────


def _node(name: str, memory: str, *, dns: bool) -> dict:
    labels = {"spatium.io/role-dns-bind9": "true"} if dns else {}
    return {
        "metadata": {"name": name, "labels": labels},
        "status": {"capacity": {"memory": memory}},
    }


def test_the_smallest_dns_node_decides() -> None:
    """One limit for every pod of the DaemonSet, so the smallest node it runs
    on decides. A smaller node without the role does not."""
    doc = {
        "items": [
            _node("a", "64Gi", dns=True),
            _node("b", "16Gi", dns=True),
            _node("c", "4Gi", dns=False),
        ]
    }
    assert k8s_api.dns_sizing_memory_of(doc) == 16 * GIB


def test_with_no_dns_node_labelled_yet_every_node_counts() -> None:
    """The first apply runs before this node's label is patched."""
    doc = {"items": [_node("a", "64Gi", dns=False), _node("b", "16Gi", dns=False)]}
    assert k8s_api.dns_sizing_memory_of(doc) == 16 * GIB


def test_no_capacity_is_unknown() -> None:
    assert k8s_api.dns_sizing_memory_of({"items": [{"metadata": {"name": "a"}}]}) is None
    assert k8s_api.dns_sizing_memory_of({}) is None


def test_the_reader_reports_an_unreadable_node_list_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_a, **_k):
        raise RuntimeError("kubeapi down")

    monkeypatch.setattr(k8s_api, "_request", boom)
    mib, err = real_dns_sizing_memory_mib()
    assert mib is None and "kubeapi down" in (err or "")

    monkeypatch.setattr(k8s_api, "_request", lambda *_a, **_k: (403, "forbidden"))
    assert real_dns_sizing_memory_mib()[0] is None

    body = json.dumps({"items": [_node("a", "16Gi", dns=True)]})
    monkeypatch.setattr(k8s_api, "_request", lambda *_a, **_k: (200, body))
    assert real_dns_sizing_memory_mib() == (16 * GIB, None)


# ── the role apply ──────────────────────────────────────────────────────────


def test_size_dns_bind9_leaves_an_off_block_alone() -> None:
    values = {"dnsBind9": {"enabled": False}}
    assert service_lifecycle.size_dns_bind9(values, 16 * GIB) == values
    on = {"dnsBind9": {"enabled": True, "agentKey": "k"}}
    assert service_lifecycle.size_dns_bind9(on, None) == on
    sized = service_lifecycle.size_dns_bind9(on, 16 * GIB)
    assert sized["dnsBind9"]["memory"] == {"limit": "4Gi", "request": "512Mi"}
    assert "memory" not in on["dnsBind9"]  # not mutated


ASSIGNMENT = {"roles": ["dns-bind9"], "dns_group_name": "default", "dns_agent_key": "a" * 48}


def _apply(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    reader: object,
    assignment: dict = ASSIGNMENT,
) -> tuple[service_lifecycle.LifecycleResult, list[dict]]:
    """A standalone appliance applying ``assignment``, its kubeapi stubbed."""
    written: list[dict] = []
    monkeypatch.setattr(appliance_state, "detect_appliance_variant", lambda: "control-plane")
    monkeypatch.setattr(appliance_state, "read_cluster_join_state", lambda: (None, None))
    monkeypatch.setattr(appliance_state, "is_control_plane_member", lambda: True)
    monkeypatch.setenv("CONTROL_PLANE_URL", "")
    monkeypatch.setattr(
        service_lifecycle,
        "k3s_available",
        lambda: service_lifecycle.K3sEnvironment(available=True),
    )
    monkeypatch.setattr(service_lifecycle, "_read_chart_tarball", lambda: b"chart")
    monkeypatch.setattr(service_lifecycle, "_resolve_node_name", lambda: "n1")
    monkeypatch.setattr(k8s_api, "node_role_labels", lambda **_k: (set(), None))
    monkeypatch.setattr(k8s_api, "dns_sizing_memory_mib", reader)
    monkeypatch.setattr(k8s_api, "patch_node_labels", lambda *_a, **_k: (True, None))

    def apply_helmchart(name: str, **kw: object) -> tuple[bool, None]:
        written.append(kw["values"])  # type: ignore[arg-type]
        return True, None

    monkeypatch.setattr(k8s_api, "apply_helmchart", apply_helmchart)
    env_file = tmp_path / "role-compose.env"
    env_file.write_text(render_env_file(compute_target_env(assignment)), encoding="utf-8")
    result = service_lifecycle.apply_role_assignment(list(assignment["roles"]), env_file)
    return result, written


def test_the_apply_writes_the_sized_limit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    result, written = _apply(monkeypatch, tmp_path, lambda **_k: (64 * GIB, None))
    assert result.state == "ready", result.reason
    assert written[-1]["dnsBind9"]["memory"] == {"limit": "8Gi", "request": "1024Mi"}


def test_an_unreadable_node_list_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Writing the chart without the sizing would put every DNS node back on
    the 2Gi default and restart named cluster-wide; the apply fails instead
    and the next heartbeat retries."""
    result, written = _apply(monkeypatch, tmp_path, lambda **_k: (None, "kubeapi down"))
    assert result.state == "failed"
    assert "node memory" in (result.reason or "")
    assert written == []


def test_a_node_without_dns_does_not_read_node_memory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A DHCP-only node renders no dns-bind9 DaemonSet, so it has nothing to
    size and must not fail over a node list it does not need."""

    def reader(**_k: object) -> tuple[None, str]:
        raise AssertionError("read node memory for a node with no DNS role")

    result, written = _apply(
        monkeypatch,
        tmp_path,
        reader,
        {"roles": ["dhcp"], "dhcp_group_name": "d", "dhcp_agent_key": "b" * 48},
    )
    assert result.state == "ready", result.reason
    assert "memory" not in written[-1]["dnsBind9"]


def test_the_skip_key_carries_the_sizing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A node joining with less RAM moves the limit with nothing in the role
    env changing, so the sizing is in the role apply's skip key."""
    env_file = tmp_path / "role-compose.env"
    env_file.write_text("", encoding="utf-8")
    monkeypatch.setattr(service_lifecycle, "_read_chart_tarball", lambda: b"chart")
    monkeypatch.setattr(k8s_api, "dns_sizing_memory_mib", lambda **_k: (64 * GIB, None))
    big = service_lifecycle.role_release_fingerprint(env_file)
    monkeypatch.setattr(k8s_api, "dns_sizing_memory_mib", lambda **_k: (16 * GIB, None))
    small = service_lifecycle.role_release_fingerprint(env_file)
    monkeypatch.setattr(k8s_api, "dns_sizing_memory_mib", lambda **_k: (16_100, None))
    assert big != small
    assert service_lifecycle.role_release_fingerprint(env_file) == small
