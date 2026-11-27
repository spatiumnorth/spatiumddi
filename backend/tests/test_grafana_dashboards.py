"""The shipped Grafana dashboards (#4739).

A dashboard that queries a metric nothing emits renders as an empty panel and
nobody notices, which is how docs/OBSERVABILITY.md came to describe dashboards
over metric families that were never exposed. So every metric name a dashboard
queries must be registered by ``backend/app`` (or be a default
``prometheus_client`` / Prometheus series), and no dashboard may pin a
data-source UID: they must import against any Prometheus.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_DASHBOARDS = _REPO_ROOT / "charts" / "spatiumddi" / "dashboards"
_BACKEND_APP = _REPO_ROOT / "backend" / "app"

# The dev container copies only ``backend/``; this runs for real in CI.
pytestmark = pytest.mark.skipif(
    not _DASHBOARDS.is_dir(), reason="dashboards not present in this checkout"
)

_METRIC_RE = re.compile(r"\b(spatiumddi_[a-z0-9_]+|process_[a-z0-9_]+|python_[a-z0-9_]+)\b")
_SUFFIXES = ("_bucket", "_count", "_sum", "_total", "_created")


def _registered_names() -> set[str]:
    """Metric names declared in backend/app (a quoted ``spatiumddi_*`` literal)."""
    names: set[str] = set()
    for path in _BACKEND_APP.rglob("*.py"):
        for m in re.finditer(r"""["'](spatiumddi_[a-z0-9_]+)["']""", path.read_text()):
            names.add(m.group(1))
    return names


def _known(name: str, registered: set[str]) -> bool:
    # Series prometheus_client emits by default, with no spatiumddi code.
    if name.startswith(("process_", "python_")):
        return True
    candidates = {name}
    for suf in _SUFFIXES:
        if name.endswith(suf):
            candidates.add(name[: -len(suf)])
    # Histogram _bucket/_count/_sum are derived from the registered base name.
    return bool(candidates & registered)


def _exprs(node: object) -> list[str]:
    out: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "expr" and isinstance(v, str):
                out.append(v)
            elif k == "query" and isinstance(v, str):
                out.append(v)
            elif k == "query" and isinstance(v, dict) and isinstance(v.get("query"), str):
                out.append(v["query"])
            else:
                out.extend(_exprs(v))
    elif isinstance(node, list):
        for v in node:
            out.extend(_exprs(v))
    return out


def _datasource_uids(node: object) -> list[str]:
    out: list[str] = []
    if isinstance(node, dict):
        ds = node.get("datasource")
        if isinstance(ds, dict) and "uid" in ds:
            out.append(ds["uid"])
        elif isinstance(ds, str):
            out.append(ds)
        for v in node.values():
            out.extend(_datasource_uids(v))
    elif isinstance(node, list):
        for v in node:
            out.extend(_datasource_uids(v))
    return out


def _problems(dash: dict, registered: set[str]) -> list[str]:
    problems: list[str] = []
    names = {m for e in _exprs(dash) for m in _METRIC_RE.findall(e)}
    problems += [f"unknown metric {n}" for n in sorted(names) if not _known(n, registered)]
    problems += [
        f"hard-coded datasource {u!r}" for u in _datasource_uids(dash) if u != "${datasource}"
    ]
    if not any(v.get("type") == "datasource" for v in dash["templating"]["list"]):
        problems.append("no datasource variable")
    return problems


def _files() -> list[pathlib.Path]:
    return sorted(_DASHBOARDS.glob("*.json"))


def test_dashboards_exist() -> None:
    assert {p.stem for p in _files()} >= {
        "spatiumddi-overview",
        "spatiumddi-dns",
        "spatiumddi-dhcp",
        "spatiumddi-ipam",
    }


def test_registered_names_found() -> None:
    # Guards the scan itself: an empty set would make every check vacuous.
    assert "spatiumddi_api_requests_total" in _registered_names()


@pytest.mark.parametrize("path", _files(), ids=lambda p: p.stem)
def test_dashboard_is_valid(path: pathlib.Path) -> None:
    dash = json.loads(path.read_text())
    assert dash["uid"] == path.stem
    assert dash["panels"], "dashboard has no panels"
    assert _exprs(dash), "dashboard has no queries"
    assert _problems(dash, _registered_names()) == []


def test_unique_uids_and_panel_ids() -> None:
    dashes = [json.loads(p.read_text()) for p in _files()]
    assert len({d["uid"] for d in dashes}) == len(dashes)
    for d in dashes:
        ids = [p["id"] for p in d["panels"]]
        assert len(ids) == len(set(ids))


def test_negative_control_unknown_metric_and_datasource() -> None:
    bad = {
        "templating": {"list": [{"type": "datasource"}]},
        "panels": [
            {
                "datasource": {"type": "prometheus", "uid": "abc123"},
                "targets": [{"expr": "rate(spatiumddi_dns_queries_total[5m])"}],
            }
        ],
    }
    problems = _problems(bad, _registered_names())
    assert "unknown metric spatiumddi_dns_queries_total" in problems
    assert "hard-coded datasource 'abc123'" in problems
