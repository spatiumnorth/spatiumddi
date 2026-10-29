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
        # Per node: api 30 + its #2782 hooks 2 + its #2944 readiness probe 1
        # + each worker process with its hooks 2 x (1 + 2) + 1 = 40; no WAL
        # sender; reserve 10 + beat's hooks 2.
        (1, 2, 52),
        (1, 4, 58),
        # 3 x 40 + 2 WAL senders + 12.
        (3, 2, 134),
        (3, 4, 152),
        # 9 x (13 + 2 + 1 + 6 + 1) + 8 WAL senders + 12: before #2156 the nine
        # api pools alone could open 270.
        (9, 2, 227),
        (9, 4, 281),
    ],
)
def test_the_connection_budget_at_one_three_and_nine_nodes(
    cp_size: int, concurrency: int, expected: int
) -> None:
    assert k8s_api.postgres_connection_budget(cp_size, concurrency) == expected


def _chart_max_connections() -> int:
    """The floor the appliance keeps. Since #2955 the chart derives
    ``max_connections`` from its own pools when the value is empty (its
    default), so the appliance must always set one: its floor is the chart's
    pre-#2955 200, kept so an appliance under the crossing does not roll."""
    for parent in Path(__file__).resolve().parents:
        values = parent / "charts" / "spatiumddi" / "values.yaml"
        if values.is_file():
            doc = yaml.safe_load(values.read_text(encoding="utf-8"))
            assert doc["postgresql"]["cnpg"]["parameters"]["max_connections"] in ("", None)
            return 200
    raise AssertionError("could not find charts/spatiumddi/values.yaml")


@pytest.mark.parametrize("cp_size", range(1, 11))
@pytest.mark.parametrize("mem_mib", [8192, 24576])  # two and four worker processes
def test_max_connections_always_covers_the_budget(cp_size: int, mem_mib: int) -> None:
    """A pool sized past max_connections is refused at the database. With the
    #2782 hooks and the #2944 probe the budget passes the chart's 200 from
    five nodes (four worker processes) or seven (two), so the supervisor writes the budget there and
    the chart's own value below it."""
    assert _chart_max_connections() == k8s_api._PG_CHART_MAX_CONNECTIONS
    s = k8s_api.control_plane_sizing(mem_mib, cp_size)
    assert s["max_connections"] >= s["postgres_connections"]
    assert s["max_connections"] == max(_chart_max_connections(), s["postgres_connections"])
    rendered = k8s_api.control_plane_resources(mem_mib, None, cp_size)
    assert rendered["postgresql"]["cnpg"]["parameters"]["max_connections"] == str(
        s["max_connections"]
    )


def test_max_connections_stays_the_charts_up_to_four_nodes() -> None:
    """Below the crossing nothing moves: an install of up to four nodes
    renders the chart's own 200, so the #1005 guard writes nothing for it."""
    for cp in (1, 2, 3, 4):
        for mem in (8192, 24576):
            assert k8s_api.control_plane_sizing(mem, cp)["max_connections"] == 200
    assert [k8s_api.postgres_connection_budget(cp, 2) for cp in range(1, 11)] == [
        52,
        93,
        134,
        175,
        186,
        197,
        207,
        219,
        227,
        241,
    ]
    assert [k8s_api.postgres_connection_budget(cp, 4) for cp in range(1, 11)] == [
        58,
        105,
        152,
        199,
        216,
        233,
        249,
        267,
        281,
        301,
    ]


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
    """The cluster in the report: one node keeps 2479Mi, three take 3019Mi,
    nine 4507Mi — above the ~2479 MiB the cgroup held at the kill, with room
    for the 227 backends nine nodes can now open (#2782's hooks and #2944's
    probe included)."""
    limits = {cp: k8s_api.control_plane_sizing(_ISSUE_SEED_MIB, cp)["postgres"] for cp in (1, 3, 9)}
    assert limits == {1: 2479, 3: 619 + 256 + 134 * 16, 9: 619 + 256 + 227 * 16}
    assert limits == {1: 2479, 3: 3019, 9: 4507}
    killed_at = (_ANON + _SHMEM + _KERNEL) / _MIB
    assert killed_at == pytest.approx(2479, abs=2)
    assert limits[9] > killed_at
    sized = k8s_api.control_plane_sizing(_ISSUE_SEED_MIB, 9)
    assert sized["postgres_connections"] == 227
    assert sized["max_connections"] == 227
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
    """One node's 52-58 connections fit the share from 8 GiB up, so those
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
    assert doc["postgresql"]["resources"]["limits"] == {"memory": "4507Mi", "cpu": "3000m"}
    assert doc["postgresql"]["cnpg"]["instances"] == 9
    assert doc["postgresql"]["cnpg"]["parameters"] == {
        "shared_buffers": "619MB",
        "max_connections": "227",
    }


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
