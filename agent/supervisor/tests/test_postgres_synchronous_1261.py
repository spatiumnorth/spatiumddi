"""#1261 — the appliance renders the operator's synchronous-replication setting.

The chart refuses ``number >= instances`` and a single instance, and the
instance count moves with the control-plane size, so the supervisor clamps the
saved setting to the live count rather than render something the chart would
reject (a failed render rolls the release back). A control plane that never
sends the field must change nothing.
"""

from __future__ import annotations

import inspect
import json

import yaml

from spatium_supervisor import heartbeat, k8s_api

_ON = {"enabled": True, "method": "first", "number": 2, "data_durability": "preferred"}


def _render(monkeypatch, instances: int, sync, written: dict | None = None) -> dict:
    written = {} if written is None else written

    def request(method, path, body=None, content_type=None):
        if "/helmchartconfigs" in path:
            if method == "GET":
                return (404, b"") if "doc" not in written else (
                    200, json.dumps({"spec": {"valuesContent": written["doc"]}}).encode())
            written["doc"] = json.loads(body)["spec"]["valuesContent"]
            return (201 if method == "POST" else 200), b"{}"
        if "/helmcharts/" in path:
            return 200, json.dumps({"spec": {"valuesContent": "{}"}}).encode()
        return 404, b""

    monkeypatch.setattr(k8s_api, "_request", request)
    k8s_api.apply_control_plane_overrides(
        instances, "", cnpg_instances=instances, postgres_synchronous=sync
    )
    return yaml.safe_load(written["doc"])["postgresql"]["cnpg"].get("synchronous")


def test_the_saved_setting_is_rendered_into_the_chart_values(monkeypatch) -> None:
    assert _render(monkeypatch, 3, _ON) == {
        "enabled": True,
        "method": "first",
        "number": 2,
        "dataDurability": "preferred",
    }


def test_no_setting_renders_nothing_so_firstboot_values_stand(monkeypatch) -> None:
    assert _render(monkeypatch, 3, None) is None


def test_turning_it_off_switches_off_what_was_rendered(monkeypatch) -> None:
    doc: dict = {}
    assert _render(monkeypatch, 3, _ON, doc)["enabled"] is True
    assert _render(monkeypatch, 3, {"enabled": False}, doc)["enabled"] is False


def test_number_is_clamped_to_the_live_instance_count(monkeypatch) -> None:
    got = _render(monkeypatch, 2, _ON)
    assert got["enabled"] is True and got["number"] == 1


def test_a_single_instance_renders_off_instead_of_failing_the_chart(monkeypatch) -> None:
    assert _render(monkeypatch, 1, _ON) is None


def test_garbage_values_fall_back_to_the_safe_defaults() -> None:
    got = k8s_api.postgres_synchronous_values(
        {"enabled": True, "method": "x", "number": "abc", "data_durability": 5}, 3
    )
    assert got == {"enabled": True, "method": "any", "number": 1, "dataDurability": "required"}
    assert k8s_api.postgres_synchronous_values("nope", 3)["enabled"] is False


def test_the_heartbeat_passes_the_desired_state_to_the_render() -> None:
    src = inspect.getsource(heartbeat.heartbeat_once)
    assert 'body_out.get("desired_postgres_synchronous")' in src
