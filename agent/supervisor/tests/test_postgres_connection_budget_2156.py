"""The Postgres memory limit holds the connections the cluster can open (#2156).

At nine control-plane nodes the CloudNativePG primary was killed by its memory
cgroup at 2479Mi, on a node with 14 GiB free. The limit was sized from the
seed's RAM alone (#1115) while the backends grew with the node count: every
node runs an api pod whose SQLAlchemy pool (10 + 20) is held open at idle, plus
a worker, and the primary runs one WAL sender per replica. The cgroup at the
kill held 1,719,521,280 B of anon memory over ~120 processes (1,174,405,120 B
of it transparent huge pages), 692,191,232 B of shmem (the shared buffers) and
187,273,216 B of kernel memory, 158,326,784 B of it page tables.

The fix closes the envelope from both sides: the api's pool per pod shrinks as
pods are added (``api_db_pool``), and the limit is never below shared_buffers
+ a fixed allowance + the connections that can be open x what one backend
costs (``postgres_connection_budget`` / ``postgres_backend_mib``).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from spatium_supervisor import k8s_api

# The issue's seed: a "12 GiB" VM whose MemTotal sizes the share to exactly
# the 2479Mi limit the primary was killed at.
_ISSUE_SEED_MIB = 11965

# The cgroup's own numbers at the kill (issue body).
_ANON = 1_719_521_280
_SHMEM = 692_191_232
_KERNEL = 187_273_216
_PAGETABLES = 158_326_784
_PROCESSES = 121
_MIB = 1 << 20


def _share_only_limit(mem_mib: int) -> int:
    """The Postgres limit before #2156: a quarter of the budget, 1-4 GiB."""
    budget = max(mem_mib - 2048, 0)
    return int(min(max(budget * 0.25, 1024), 4096))


def test_the_api_pool_shrinks_per_pod_as_pods_are_added() -> None:
    pools = {cp: k8s_api.api_db_pool(cp) for cp in (1, 2, 3, 4, 5, 7, 9, 12, 20)}
    assert pools == {
        1: {"size": 10, "maxOverflow": 20},  # the application's own default
        2: {"size": 10, "maxOverflow": 20},
        3: {"size": 10, "maxOverflow": 20},
        4: {"size": 10, "maxOverflow": 20},
        5: {"size": 10, "maxOverflow": 14},
        7: {"size": 10, "maxOverflow": 7},
        9: {"size": 10, "maxOverflow": 3},
        12: {"size": 10, "maxOverflow": 2},  # the 12-per-pod floor
        20: {"size": 10, "maxOverflow": 2},
    }


@pytest.mark.parametrize(
    ("cp_size", "concurrency", "expected"),
    [
        # api 30 + worker 2 + 1, no WAL sender, reserve 10.
        (1, 2, 43),
        (1, 4, 45),
        # 3 x 33 + 2 WAL senders + 10.
        (3, 2, 111),
        (3, 4, 117),
        # 9 x (13 + 2 + 1) + 8 WAL senders + 10: before #2156 the nine api
        # pools alone could open 270.
        (9, 2, 162),
        (9, 4, 180),
    ],
)
def test_the_connection_budget_at_one_three_and_nine_nodes(
    cp_size: int, concurrency: int, expected: int
) -> None:
    assert k8s_api.postgres_connection_budget(cp_size, concurrency) == expected


def _chart_max_connections() -> int:
    for parent in Path(__file__).resolve().parents:
        values = parent / "charts" / "spatiumddi" / "values.yaml"
        if values.is_file():
            doc = yaml.safe_load(values.read_text(encoding="utf-8"))
            return int(doc["postgresql"]["cnpg"]["parameters"]["max_connections"])
    raise AssertionError("could not find charts/spatiumddi/values.yaml")


@pytest.mark.parametrize("cp_size", range(1, 11))
@pytest.mark.parametrize("concurrency", [2, 4])
def test_the_budget_never_passes_the_charts_max_connections(cp_size: int, concurrency: int) -> None:
    """A pool sized past max_connections is refused at the database instead of
    killed by the cgroup; neither should be reachable up to ten nodes."""
    assert k8s_api.postgres_connection_budget(cp_size, concurrency) <= (_chart_max_connections())
    assert _chart_max_connections() == k8s_api._PG_CHART_MAX_CONNECTIONS


def test_one_backend_costs_at_least_what_the_killed_primary_measured() -> None:
    """~14.2 MiB of private memory and ~1.25 MiB of page tables per process at
    the kill; the constant must not be below that, or the limit is sized for a
    cheaper Postgres than the one that ran."""
    measured_anon = _ANON / _PROCESSES / _MIB
    measured_pt = _PAGETABLES / _PROCESSES / _MIB
    # The live primary's shared_buffers was 774 MiB.
    assert k8s_api.postgres_backend_mib(774) >= measured_anon + measured_pt
    # Page tables grow with shared_buffers: 8 bytes per 4 KiB page mapped.
    assert k8s_api.postgres_backend_mib(256) == 15
    assert k8s_api.postgres_backend_mib(619) == 16
    assert k8s_api.postgres_backend_mib(1024) == 16


def test_the_issue_seed_at_one_three_and_nine_nodes() -> None:
    """The cluster in the report: one node keeps 2479Mi, three take 2651Mi,
    nine 3467Mi — above the ~2479 MiB the cgroup held at the kill, with room
    for the 162 backends nine nodes can now open."""
    limits = {cp: k8s_api.control_plane_sizing(_ISSUE_SEED_MIB, cp)["postgres"] for cp in (1, 3, 9)}
    assert limits == {1: 2479, 3: 2651, 9: 3467}
    killed_at = (_ANON + _SHMEM + _KERNEL) / _MIB
    assert killed_at == pytest.approx(2479, abs=2)
    assert limits[9] > killed_at
    sized = k8s_api.control_plane_sizing(_ISSUE_SEED_MIB, 9)
    assert sized["postgres_connections"] == 162
    # shared_buffers, the request and the worker are the share's, unchanged.
    one = k8s_api.control_plane_sizing(_ISSUE_SEED_MIB, 1)
    for key in ("shared_buffers", "postgres_request", "worker", "api", "concurrency"):
        assert sized[key] == one[key]


@pytest.mark.parametrize("mem_mib", [2048, 3943, 5931, 8192, 11965, 12288, 16384, 24030, 65536])
@pytest.mark.parametrize("cp_size", [1, 3, 5, 7, 9])
def test_the_limit_holds_its_connections_everywhere(mem_mib: int, cp_size: int) -> None:
    s = k8s_api.control_plane_sizing(mem_mib, cp_size)
    need = (
        s["shared_buffers"]
        + k8s_api._PG_FIXED_MIB
        + s["postgres_connections"] * k8s_api.postgres_backend_mib(s["shared_buffers"])
    )
    assert s["postgres"] >= need
    # Only ever a raise over the share, never a cut.
    assert s["postgres"] >= _share_only_limit(mem_mib)
    # The request still follows shared_buffers (CloudNativePG's webhook).
    assert s["postgres_request"] >= s["shared_buffers"]


@pytest.mark.parametrize("mem_mib", [8192, 12288, 16384, 24030, 24576, 65536])
def test_a_single_node_from_eight_gib_is_unchanged(mem_mib: int) -> None:
    """One node's 43-45 connections fit the share from 8 GiB up, so those
    installs render exactly what they did."""
    assert k8s_api.control_plane_sizing(mem_mib, 1)["postgres"] == _share_only_limit(mem_mib)


def test_the_limit_grows_with_the_node_count() -> None:
    for mem in (8192, _ISSUE_SEED_MIB, 16384):
        limits = [k8s_api.control_plane_sizing(mem, cp)["postgres"] for cp in range(1, 10)]
        assert limits == sorted(limits), (mem, limits)
        assert limits[-1] > limits[0], (mem, limits)


class _Recorder:
    def __init__(self) -> None:
        self.bodies: list[bytes] = []

    def __call__(self, method, path, body=None, content_type=None):
        if method == "GET":
            return (404, "")
        if body is not None:
            self.bodies.append(body)
        return (201, "{}")

    @property
    def doc(self) -> dict:
        assert self.bodies, "no HelmChartConfig write recorded"
        return yaml.safe_load(json.loads(self.bodies[-1])["spec"]["valuesContent"])


def test_nine_nodes_write_the_smaller_pool_and_the_larger_limit(monkeypatch) -> None:
    rec = _Recorder()
    monkeypatch.setattr(k8s_api, "_request", rec)
    ok, err = k8s_api.apply_control_plane_overrides(
        9, "", mem_total_mib=_ISSUE_SEED_MIB, cpu_count=6, cnpg_instances=9
    )
    assert (ok, err) == (True, None)
    doc = rec.doc
    assert doc["api"]["replicas"] == 9
    assert doc["api"]["databasePool"] == {"size": 10, "maxOverflow": 3}
    assert doc["postgresql"]["resources"]["limits"] == {"memory": "3467Mi", "cpu": "3000m"}
    assert doc["postgresql"]["cnpg"]["instances"] == 9
    assert doc["postgresql"]["cnpg"]["parameters"] == {"shared_buffers": "619MB"}


def test_the_pool_is_written_even_when_the_ram_is_unknown(monkeypatch) -> None:
    """The pool depends on the node count alone: a nine-node cluster whose seed
    cannot read MemTotal still caps its api connections."""
    rec = _Recorder()
    monkeypatch.setattr(k8s_api, "_request", rec)
    ok, _err = k8s_api.apply_control_plane_overrides(9, "")
    assert ok
    assert rec.doc["api"]["databasePool"] == {"size": 10, "maxOverflow": 3}
    assert "resources" not in rec.doc["postgresql"]


def test_the_chart_renders_the_pool_as_the_apps_env() -> None:
    """``api.databasePool`` reaches the api as the two settings app/config.py
    reads (``database_pool_size`` / ``database_max_overflow``)."""
    for parent in Path(__file__).resolve().parents:
        tpl = parent / "charts" / "spatiumddi" / "templates" / "api.yaml"
        cfg = parent / "backend" / "app" / "config.py"
        if tpl.is_file():
            break
    else:
        raise AssertionError("could not find charts/spatiumddi/templates/api.yaml")
    text = tpl.read_text(encoding="utf-8")
    assert re.search(r"- name: DATABASE_POOL_SIZE\n\s+value: \{\{ \.size \| quote \}\}", text)
    assert re.search(
        r"- name: DATABASE_MAX_OVERFLOW\n\s+value: \{\{ \.maxOverflow \| quote \}\}", text
    )
    settings = cfg.read_text(encoding="utf-8")
    assert "database_pool_size: int = 10" in settings
    assert "database_max_overflow: int = 20" in settings
