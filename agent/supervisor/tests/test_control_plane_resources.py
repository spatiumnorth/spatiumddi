"""Appliance-sized api / worker / Postgres limits ride the control-plane overrides.

The 2026-09 resource-floor campaign found the chart's BYO-cluster defaults
(api 512Mi; worker 1Gi at four prefork processes) give way on the appliance
long before the VM does — the api cannot build a 250k-record bundle under
512Mi, the worker OOMs under 20k-device churn with gigabytes free — and that
a ``kubectl set resources`` never survives the next k3s restart. The
supervisor sizes both from the node's RAM and writes them into the same
HelmChartConfig as the replica overrides, where they survive (#272).

#1115 added the third container. The CloudNativePG cluster kept the chart's
1Gi (and shared_buffers 256MB) whatever the node had, and a bulk record load
OOM-killed the primary with 7.6 GiB free on a 12 GiB seed. The three are now
one whole-node budget: a 2 GiB platform reserve, the remainder split api 1/2,
worker 1/4, Postgres 1/4, clamped 1–8 / 1–4 / 1–4 GiB, shared_buffers a
quarter of the Postgres cap.
"""

from __future__ import annotations

import json

import yaml

from spatium_supervisor import k8s_api


class _Recorder:
    """Stand-in for k8s_api._request (same shape as the mirror tests')."""

    def __init__(self, current: str | None = None):
        self._current = current
        self.calls: list[tuple[str, str, bytes | None]] = []

    def __call__(self, method, path, body=None, content_type=None):
        self.calls.append((method, path, body))
        if method == "GET":
            if self._current is None:
                return (404, "")
            return (200, json.dumps({"spec": {"valuesContent": self._current}}))
        return (200 if method == "PATCH" else 201, "{}")

    @property
    def doc(self) -> dict:
        for method, _, body in self.calls:
            if method in ("POST", "PATCH") and body is not None:
                return yaml.safe_load(json.loads(body)["spec"]["valuesContent"])
        raise AssertionError("no HelmChartConfig write recorded")


def _limit(doc: dict, component: str) -> str:
    return doc[component]["resources"]["limits"]["memory"]


def test_sizing_scales_with_ram_inside_the_clamps() -> None:
    # The issue's 8 GiB example: reserve 2 → api 3, worker 1.5, Postgres 1.5.
    eight = k8s_api.control_plane_resources(8192)
    assert _limit(eight, "api") == "3072Mi"
    assert _limit(eight, "worker") == "1536Mi"
    assert _limit(eight, "postgresql") == "1536Mi"
    assert eight["postgresql"]["cnpg"]["parameters"]["shared_buffers"] == "384MB"
    assert eight["worker"]["concurrency"] == 2
    # The issue's 12 GiB seed, whose primary OOMed at the chart's 1Gi.
    twelve = k8s_api.control_plane_resources(12288)
    assert _limit(twelve, "api") == "5120Mi"
    assert _limit(twelve, "worker") == "2560Mi"
    assert _limit(twelve, "postgresql") == "2560Mi"
    assert twelve["postgresql"]["cnpg"]["parameters"]["shared_buffers"] == "640MB"
    assert twelve["worker"]["concurrency"] == 2
    six = k8s_api.control_plane_resources(6144)
    assert _limit(six, "api") == "2048Mi"
    assert _limit(six, "worker") == "1024Mi"
    assert _limit(six, "postgresql") == "1024Mi"
    # Floors: a 2 GiB box still gets the minimum the bundle build needs, and
    # the database never gets less than the chart ships (1Gi, 256MB).
    small = k8s_api.control_plane_resources(2048)
    assert _limit(small, "api") == "1024Mi"
    assert _limit(small, "worker") == "1024Mi"
    assert _limit(small, "postgresql") == "1024Mi"
    assert small["postgresql"]["cnpg"]["parameters"]["shared_buffers"] == "256MB"
    # Ceilings: a 64 GiB box does not hand the api half of it, nor the
    # database a quarter.
    big = k8s_api.control_plane_resources(65536)
    assert _limit(big, "api") == "8192Mi"
    assert _limit(big, "worker") == "4096Mi"
    assert _limit(big, "postgresql") == "4096Mi"
    assert big["postgresql"]["cnpg"]["parameters"]["shared_buffers"] == "1024MB"
    assert big["worker"]["concurrency"] == 4
    # api and worker requests are never set: scheduling on a small node is
    # unchanged. Postgres' request follows shared_buffers — CloudNativePG's
    # webhook refuses a Cluster whose request is below it — floored at the
    # chart's own 256Mi, so the 6 GiB render is exactly the chart's.
    for doc in (six, eight, twelve):
        for component in ("api", "worker"):
            assert "requests" not in doc[component]["resources"]
    assert six["postgresql"]["resources"]["requests"] == {"memory": "256Mi"}
    assert eight["postgresql"]["resources"]["requests"] == {"memory": "384Mi"}
    assert twelve["postgresql"]["resources"]["requests"] == {"memory": "640Mi"}
    assert small["postgresql"]["resources"]["requests"] == {"memory": "256Mi"}
    assert big["postgresql"]["resources"]["requests"] == {"memory": "1024Mi"}
    # The postgresql block never carries the instance count: that is the
    # control-plane size's, merged in by apply_control_plane_overrides.
    assert "instances" not in eight["postgresql"]["cnpg"]


def test_the_budget_fits_the_node_beside_the_reserve() -> None:
    """The point of budgeting the whole node (#1115): api RAM/2 + worker RAM/4
    + Postgres RAM/4 left nothing for the platform, and the 6 GiB members of
    the seven-node lab bottomed out at 551 MiB MemAvailable under load."""
    for mem in (8192, 12288, 16384, 24576):
        s = k8s_api.control_plane_sizing(mem)
        assert s["api"] + s["worker"] + s["postgres"] + 2048 <= mem, (mem, s)
    s = k8s_api.control_plane_sizing(12288)
    assert s == {
        "api": 5120,
        "worker": 2560,
        "postgres": 2560,
        "shared_buffers": 640,
        "postgres_request": 640,
    }


def test_unknown_ram_leaves_the_chart_defaults_alone() -> None:
    assert k8s_api.control_plane_resources(None) == {}
    assert k8s_api.control_plane_resources(0) == {}


def test_the_overrides_carry_the_sizing_and_state_the_redis_kind(monkeypatch) -> None:
    rec = _Recorder()
    monkeypatch.setattr(k8s_api, "_request", rec)

    ok, err = k8s_api.apply_control_plane_overrides(1, "", mem_total_mib=8192)

    assert (ok, err) == (True, None)
    doc = rec.doc
    assert doc["api"]["replicas"] == 1
    assert doc["api"]["resources"] == {"limits": {"memory": "3072Mi"}}
    assert doc["worker"]["concurrency"] == 2
    assert doc["worker"]["resources"] == {"limits": {"memory": "1536Mi"}}
    # #1115 — the database's limit and shared_buffers sit beside the instance
    # count, under the one ``postgresql`` key the chart reads.
    assert doc["postgresql"] == {
        "cnpg": {"instances": 1, "parameters": {"shared_buffers": "384MB"}},
        "resources": {"requests": {"memory": "384Mi"}, "limits": {"memory": "1536Mi"}},
    }
    assert doc["redis"] == {"kind": "sentinel", "sentinel": {"replicas": 1}}


def test_without_a_size_the_document_is_what_it_was(monkeypatch) -> None:
    rec = _Recorder()
    monkeypatch.setattr(k8s_api, "_request", rec)

    ok, _err = k8s_api.apply_control_plane_overrides(3, "10.0.0.9")

    assert ok
    doc = rec.doc
    assert "resources" not in doc["api"] and "resources" not in doc["worker"]
    assert "concurrency" not in doc["worker"]
    assert doc["postgresql"] == {"cnpg": {"instances": 3}}
    assert doc["redis"]["kind"] == "sentinel"


def test_an_operators_own_request_keys_survive_the_merge(monkeypatch) -> None:
    current = yaml.safe_dump(
        {
            "api": {"resources": {"requests": {"cpu": "250m"}, "limits": {"cpu": "2"}}},
            "image": {"tag": "dev-1"},
        },
        sort_keys=True,
    )
    rec = _Recorder(current)
    monkeypatch.setattr(k8s_api, "_request", rec)

    ok, _err = k8s_api.apply_control_plane_overrides(1, "", mem_total_mib=4096)

    assert ok
    doc = rec.doc
    # Sibling keys the supervisor does not own are kept, memory is set (a
    # 4 GiB node is all floors: budget 2048 → api 1024).
    assert doc["api"]["resources"] == {
        "requests": {"cpu": "250m"},
        "limits": {"cpu": "2", "memory": "1024Mi"},
    }
    assert doc["image"]["tag"] == "dev-1"


def test_an_operators_own_postgres_parameters_survive_the_merge(monkeypatch) -> None:
    """shared_buffers lands beside a work_mem the operator set by hand; the
    memory request is the sizing's, at shared_buffers, because CloudNativePG
    refuses a Cluster whose request is below it — an operator's 512Mi under a
    640MB shared_buffers would fail the webhook (#1115)."""
    current = yaml.safe_dump(
        {
            "postgresql": {
                "cnpg": {"parameters": {"work_mem": "32MB"}},
                "resources": {"requests": {"memory": "512Mi"}},
            }
        },
        sort_keys=True,
    )
    rec = _Recorder(current)
    monkeypatch.setattr(k8s_api, "_request", rec)

    ok, _err = k8s_api.apply_control_plane_overrides(3, "", mem_total_mib=12288)

    assert ok
    doc = rec.doc
    assert doc["postgresql"] == {
        "cnpg": {"instances": 3, "parameters": {"work_mem": "32MB", "shared_buffers": "640MB"}},
        "resources": {"requests": {"memory": "640Mi"}, "limits": {"memory": "2560Mi"}},
    }


def test_node_memory_reads_meminfo(tmp_path, monkeypatch) -> None:
    mem = tmp_path / "meminfo"
    mem.write_text("MemTotal:        8123456 kB\nMemFree:  100 kB\n")
    real_open = open

    def fake_open(path, *a, **kw):
        if path == "/proc/meminfo":
            return real_open(mem, *a, **kw)
        return real_open(path, *a, **kw)

    monkeypatch.setattr("builtins.open", fake_open)
    assert k8s_api.node_memory_mib() == 8123456 // 1024
