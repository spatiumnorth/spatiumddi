"""The shipped Grafana dashboards (#4739).

A dashboard that queries a metric nothing emits renders as an empty panel and
nobody notices, which is how docs/OBSERVABILITY.md came to describe dashboards
over metric families that were never exposed. So every metric name a dashboard
queries must be registered by ``backend/app`` (or be a default
``prometheus_client`` / Prometheus series), and no dashboard may pin a
data-source UID: they must import against any Prometheus.
"""

from __future__ import annotations

import ast
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


def _metric_defs() -> dict[str, tuple[set[str], bool]]:
    """``{metric name: (label names, is it ever updated)}`` from app/metrics.py.

    "Updated" means the module-level constant it is bound to appears in some
    other place in backend/app: a family that is registered but never
    incremented exposes no series, so a panel built on it is empty forever.
    """
    tree = ast.parse((_BACKEND_APP / "metrics.py").read_text())
    sources = [p.read_text() for p in _BACKEND_APP.rglob("*.py")]
    defs: dict[str, tuple[set[str], bool]] = {}
    for node in tree.body:
        if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)):
            continue
        call = node.value
        if not (
            isinstance(call.func, ast.Name) and call.func.id in {"Counter", "Gauge", "Histogram"}
        ):
            continue
        name = ast.literal_eval(call.args[0])
        labels_node = call.args[2] if len(call.args) > 2 else None
        for kw in call.keywords:
            if kw.arg == "labelnames":
                labels_node = kw.value
        labels = set(ast.literal_eval(labels_node)) if labels_node is not None else set()
        const = node.targets[0].id  # type: ignore[attr-defined]
        uses = sum(len(re.findall(rf"\b{const}\b", src)) for src in sources)
        defs[name] = (labels, uses > 1)
    return defs


_SELECTOR_RE = re.compile(r"\b(spatiumddi_[a-z0-9_]+)\s*\{([^}]*)\}")
_MATCHER_LABEL_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=~|!~|!=|=)")
_BY_RE = re.compile(r"\b(?:by|without)\s*\(([^)]*)\)")


def _metric_problems(dash: dict) -> list[str]:
    defs = _metric_defs()
    problems: list[str] = []
    for expr in _exprs(dash):
        base = {
            n: next(
                (b for b in (n, *(n[: -len(s)] for s in _SUFFIXES if n.endswith(s))) if b in defs),
                None,
            )
            for n in _METRIC_RE.findall(expr)
        }
        for name, b in base.items():
            if b is not None and not defs[b][1]:
                problems.append(f"{name} is registered but never updated: no series")
        for name, body in _SELECTOR_RE.findall(expr):
            b = base.get(name)
            if b is None:
                continue
            bad = set(_MATCHER_LABEL_RE.findall(body)) - defs[b][0] - {"job", "instance", "le"}
            problems += [f"{name} has no label {lab!r}" for lab in sorted(bad)]
        # ``by (...)`` is checked only when the expression queries one family.
        families = {b for b in base.values() if b}
        if len(families) == 1:
            (fam,) = families
            for grp in _BY_RE.findall(expr):
                bad = (
                    {x.strip() for x in grp.split(",") if x.strip()}
                    - defs[fam][0]
                    - {"le", "job", "instance"}
                )
                problems += [f"{fam} has no label {lab!r} (grouping)" for lab in sorted(bad)]
    return problems


def _problems(dash: dict, registered: set[str]) -> list[str]:
    problems: list[str] = _metric_problems(dash)
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


def test_negative_control_dead_metric_and_labels() -> None:
    bad = {
        "templating": {"list": [{"type": "datasource"}]},
        "panels": [
            {"targets": [{"expr": 'sum(rate(spatiumddi_auth_login_total{job=~"$job"}[5m]))'}]},
            {
                "targets": [
                    {"expr": 'sum by (nope) (rate(spatiumddi_api_requests_total{bogus="x"}[5m]))'}
                ]
            },
        ],
    }
    problems = _problems(bad, _registered_names())
    assert "spatiumddi_auth_login_total is registered but never updated: no series" in problems
    assert "spatiumddi_api_requests_total has no label 'bogus'" in problems
    assert "spatiumddi_api_requests_total has no label 'nope' (grouping)" in problems
