"""Unit tests for the appliance console dashboard (``spatium-console``).

The console is a standalone host script (Python + rich + psutil) living at
``appliance/mkosi.extra/usr/local/bin/spatium-console`` — it is NOT part of
the ``app`` package, so it is loaded by path here. The whole module skips
cleanly when rich / psutil aren't installed (e.g. the slim API test image) or
when the script isn't present in the checkout, so it never breaks CI; it runs
on the host / appliance where those deps exist.

Covers (Phase 2 INC 10 / P2.3): the pure formatting + classification helpers
(``_format_pod_age`` boundaries, ``_rst_verdict`` thresholds), the 5 s-tier
metric parsers against captured fixture strings (etcd / CNPG / API), and the
§3d sizing invariant — ``render_frame`` renders at every tier without an
exception and always keeps the vitals row + footer on-screen.
"""

from __future__ import annotations

import importlib.util
import io
import re
from datetime import UTC, datetime, timedelta
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

pytest.importorskip("rich")
pytest.importorskip("psutil")

from rich.console import Console  # noqa: E402  (after importorskip by design)

_CONSOLE_PATH = (
    Path(__file__).resolve().parents[2]
    / "appliance"
    / "mkosi.extra"
    / "usr"
    / "local"
    / "bin"
    / "spatium-console"
)

pytestmark = pytest.mark.skipif(
    not _CONSOLE_PATH.exists(),
    reason="spatium-console host script not present in this checkout",
)

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


@pytest.fixture(scope="module")
def m():
    """Load the console host script as an importable module (by path)."""
    loader = SourceFileLoader("spatium_console_under_test", str(_CONSOLE_PATH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class _FakeResp:
    """Minimal urlopen() stand-in: ``.read()`` returns the fixture bytes."""

    def __init__(self, text: str) -> None:
        self._text = text

    def read(self) -> bytes:
        return self._text.encode()


class _FakeTail:
    lines: list[str] = []


# ── pure helpers ──────────────────────────────────────────────────────────


def test_format_pod_age_units(m):
    assert m._format_pod_age("") == ""
    assert m._format_pod_age("not-a-timestamp") == ""
    now = datetime.now(UTC)

    def iso(delta: timedelta) -> str:
        return (now - delta).strftime("%Y-%m-%dT%H:%M:%SZ")

    assert m._format_pod_age(iso(timedelta(seconds=30))).endswith("s")
    assert m._format_pod_age(iso(timedelta(minutes=5))) == "5m"
    assert m._format_pod_age(iso(timedelta(hours=3))) == "3h"
    assert m._format_pod_age(iso(timedelta(days=5))) == "5d"
    # A future timestamp clamps to 0s rather than going negative.
    assert m._format_pod_age((now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")) == "0s"


def test_rst_verdict_thresholds(m):
    assert m._rst_verdict(0) == "quiet"
    # A currently-broken pod is red regardless of the windowed increase.
    assert m._rst_verdict(0, "CrashLoopBackOff") == "red"
    assert m._rst_verdict(1) == "amber"
    assert m._rst_verdict(2) == "amber"
    assert m._rst_verdict(3) == "red"


# ── #2928 windowed restart / etcd deltas ──────────────────────────────────


def _pod(name, restarts, state="Running"):
    return {
        "Names": name,
        "Namespace": "spatium",
        "K8sState": state,
        "Restarts": restarts,
        "RestartedAt": "",
        "Ready": "1/1",
    }


def _recent(m, watch, rows, now):
    m.stamp_recent_restarts(watch, rows, now)
    return {r["Names"]: r["RstRecent"] for r in rows}


def test_restart_fresh_baseline_with_high_lifetime_count_is_quiet(m):
    w = m.CounterWatch(m._RST_WINDOW_S)
    rows = [_pod("api-1", 40)]
    assert _recent(m, w, rows, 0.0) == {"api-1": 0}
    assert m._rst_verdict(rows[0]["RstRecent"], "Running") == "quiet"
    st = m.DashboardState({}, _FakeTail(), "/dev/tty1")
    st.ps_rows = rows
    assert m.overall_verdict(st)[0] == "HEALTHY"


def test_restart_three_in_window_is_red(m):
    w = m.CounterWatch(m._RST_WINDOW_S)
    _recent(m, w, [_pod("api-1", 5)], 0.0)
    rows = [_pod("api-1", 8)]
    assert _recent(m, w, rows, 120.0) == {"api-1": 3}
    assert m._rst_verdict(3, "Running") == "red"
    st = m.DashboardState({}, _FakeTail(), "/dev/tty1")
    st.ps_rows = rows
    verdict, offender = m.overall_verdict(st)
    assert verdict == "CRITICAL"
    assert "flapping" in offender


def test_restart_one_in_window_is_amber(m):
    w = m.CounterWatch(m._RST_WINDOW_S)
    _recent(m, w, [_pod("api-1", 5)], 0.0)
    rows = [_pod("api-1", 6)]
    assert _recent(m, w, rows, 60.0) == {"api-1": 1}
    assert m._rst_verdict(1, "Running") == "amber"
    st = m.DashboardState({}, _FakeTail(), "/dev/tty1")
    st.ps_rows = rows
    assert m.overall_verdict(st)[0] == "HEALTHY"


def test_restarts_older_than_window_are_quiet(m):
    w = m.CounterWatch(m._RST_WINDOW_S)
    _recent(m, w, [_pod("api-1", 5)], 0.0)
    _recent(m, w, [_pod("api-1", 8)], 60.0)
    # Still inside the window at +800 s, then aged out past +960 s.
    assert _recent(m, w, [_pod("api-1", 8)], 800.0) == {"api-1": 3}
    assert _recent(m, w, [_pod("api-1", 8)], 1000.0) == {"api-1": 0}


def test_crashloop_is_red_without_any_history(m):
    w = m.CounterWatch(m._RST_WINDOW_S)
    rows = [_pod("api-1", 30, "CrashLoopBackOff")]
    _recent(m, w, rows, 0.0)
    assert m._rst_verdict(rows[0]["RstRecent"], "CrashLoopBackOff") == "red"
    st = m.DashboardState({}, _FakeTail(), "/dev/tty1")
    st.ps_rows = rows
    assert m.overall_verdict(st)[0] == "CRITICAL"


def test_counter_watch_forgets_vanished_pods_after_the_window(m):
    w = m.CounterWatch(m._RST_WINDOW_S)
    _recent(m, w, [_pod("a", 1), _pod("b", 1)], 0.0)
    _recent(m, w, [_pod("a", 1)], 10.0)
    # "b" is gone from the listing but kept until it has been unseen for a
    # whole window (so one failed cluster_pods cycle cannot wipe it) ...
    assert w.keys() == {"spatium/a", "spatium/b"}
    _recent(m, w, [_pod("a", 1)], 10.0 + m._RST_WINDOW_S + 1)
    # ... and dropped after that.
    assert w.keys() == {"spatium/a"}
    # A recreated pod with a new name starts a fresh baseline.
    assert _recent(m, w, [_pod("a2", 9)], 2000.0) == {"a2": 0}


def test_counter_watch_samples_stay_bounded_at_refresh_cadence(m):
    # The data tier refreshes every DATA_REFRESH_EVERY seconds; a steady
    # counter observed for an hour at that cadence must not grow a deque
    # entry per refresh.
    w = m.CounterWatch(m._RST_WINDOW_S)
    t = 0.0
    while t < 3600:
        w.observe("k", 9, t)
        t += m.DATA_REFRESH_EVERY
    assert len(w._samples["k"]) == 1
    # A counter that moves every refresh is bounded by the window instead.
    w2 = m.CounterWatch(m._RST_WINDOW_S)
    for i in range(2000):
        w2.observe("k", i, i * m.DATA_REFRESH_EVERY)
    assert len(w2._samples["k"]) <= m._RST_WINDOW_S / m.DATA_REFRESH_EVERY + 2


def test_counter_watch_uses_a_monotonic_clock(m):
    import time

    assert m.CounterWatch(m._RST_WINDOW_S)._clock is time.monotonic


def test_failed_pod_listing_does_not_reset_baselines(m):
    # cluster_pods() returns [] on any failure. Treating that as "every pod
    # vanished" would reset every baseline, and a flapping pod would read
    # quiet again on the next good cycle.
    w = m.CounterWatch(m._RST_WINDOW_S)
    _recent(m, w, [_pod("api-1", 5)], 0.0)
    _recent(m, w, [], 5.0)
    assert _recent(m, w, [_pod("api-1", 8)], 10.0) == {"api-1": 3}


def test_counter_reset_is_a_new_baseline_not_a_negative_or_huge_delta(m):
    w = m.CounterWatch(m._RST_WINDOW_S)
    assert w.observe("k", 8, 0.0) == 0
    # The counter drops (pod recreated under the same name / etcd restart).
    assert w.observe("k", 0, 10.0) == 0
    # Increases after the drop count from the new baseline. Subtracting the
    # pre-reset baseline instead would read 3 - 8 as nothing at all.
    assert w.observe("k", 3, 20.0) == 3


def test_counter_reset_keeps_in_window_increases_from_before_it(m):
    w = m.CounterWatch(m._RST_WINDOW_S)
    w.observe("k", 5, 0.0)
    assert w.observe("k", 8, 10.0) == 3
    assert w.observe("k", 1, 20.0) == 3
    assert w.observe("k", 2, 30.0) == 4
    # Once the pre-reset steps age out, only the post-reset one remains.
    assert w.observe("k", 2, 10.0 + m._RST_WINDOW_S + 1) == 1


def test_statefulset_pod_recreated_under_same_name_then_flapping_is_red(m):
    w = m.CounterWatch(m._RST_WINDOW_S)
    _recent(m, w, [_pod("db-0", 12)], 0.0)
    _recent(m, w, [_pod("db-0", 0)], 30.0)
    rows = [_pod("db-0", 3)]
    assert _recent(m, w, rows, 300.0) == {"db-0": 3}
    assert m._rst_verdict(rows[0]["RstRecent"], "Running") == "red"


def test_etcd_failures_after_an_etcd_restart_still_degrade(m):
    w = m.CounterWatch(m._ETCD_FAIL_WINDOW_S)
    _etcd_state(m, w, 40, 0.0)
    # k3s / etcd restarted under a running console: the counter resets.
    st = _etcd_state(m, w, 0, 30.0)
    assert m.overall_verdict(st)[0] == "HEALTHY"
    st = _etcd_state(m, w, 1, 60.0)
    assert m.overall_verdict(st) == ("DEGRADED", "etcd write failures")


def _iso_ago(seconds):
    return (datetime.now(UTC) - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_fresh_console_floors_a_recent_restart_at_amber_never_red(m):
    # The console restarts on every F1 logout, so its baseline is often
    # young. A pod whose last restart is inside the window restarted at
    # least once in it: amber, not quiet. Never red — the count is unknown.
    w = m.CounterWatch(m._RST_WINDOW_S)
    row = _pod("api-1", 40)
    row["RestartedAt"] = _iso_ago(120)
    m.stamp_recent_restarts(w, [row], 0.0)
    assert row["RstRecent"] == 1
    assert m._rst_verdict(row["RstRecent"], "Running") == "amber"
    st = m.DashboardState({}, _FakeTail(), "/dev/tty1")
    st.ps_rows = [row]
    assert m.overall_verdict(st)[0] == "HEALTHY"


def test_restart_floor_ages_out_and_ignores_far_future_timestamps(m):
    w = m.CounterWatch(m._RST_WINDOW_S)
    old = _pod("old", 40)
    old["RestartedAt"] = _iso_ago(m._RST_WINDOW_S + 60)
    skewed = _pod("skewed", 40)
    skewed["RestartedAt"] = _iso_ago(-3600)  # a node clock an hour ahead
    near = _pod("near", 2)
    near["RestartedAt"] = _iso_ago(-5)  # ordinary skew still counts
    junk = _pod("junk", 2)
    junk["RestartedAt"] = "not-a-time"
    assert _recent(m, w, [old, skewed, near, junk], 0.0) == {
        "old": 0,
        "skewed": 0,
        "near": 1,
        "junk": 0,
    }


def test_restart_floor_does_not_mask_a_larger_observed_increase(m):
    w = m.CounterWatch(m._RST_WINDOW_S)
    row = _pod("api-1", 5)
    row["RestartedAt"] = _iso_ago(30)
    _recent(m, w, [row], 0.0)
    row = _pod("api-1", 9)
    row["RestartedAt"] = _iso_ago(5)
    assert _recent(m, w, [row], 60.0) == {"api-1": 4}


def test_health_screen_does_not_colour_a_quiet_lifetime_count(m, monkeypatch):
    monkeypatch.setattr(m, "webui_selfcheck_status", lambda: None, raising=False)
    st = m.DashboardState({}, _FakeTail(), "/dev/tty1")
    quiet = _pod("quiet-pod", 40)
    quiet["RstRecent"] = 0
    hot = _pod("hot-pod", 41)
    hot["RstRecent"] = 3
    st.ps_rows = [quiet, hot]
    con = Console(width=160, record=True, file=io.StringIO(), color_system="standard")
    m._render_health_screen(con, st, [], None)
    lines = con.export_text(styles=True).splitlines()
    quiet_line = next(ln for ln in lines if "quiet-pod" in ln)
    # (The verdict banner names hot-pod too; take the pods-table row.)
    hot_line = next(ln for ln in lines if "hot-pod" in ln and "41" in ln)
    # 33 = yellow, 31 = red (rich "standard" colour system).
    assert "\x1b[2m40" in quiet_line  # dim
    assert "\x1b[33m40" not in quiet_line and "\x1b[1;31m40" not in quiet_line
    assert "31m41" in hot_line


def _etcd_state(m, watch, failed, now):
    st = m.DashboardState({}, _FakeTail(), "/dev/tty1")
    st.etcd = {"has_leader": 1, "is_leader": 1, "proposals_failed": failed}
    st.etcd_failed_recent = watch.observe("etcd", failed, now)
    return st


def test_etcd_counter_nonzero_at_start_is_not_degraded(m):
    w = m.CounterWatch(m._ETCD_FAIL_WINDOW_S)
    st = _etcd_state(m, w, 7, 0.0)
    assert m.overall_verdict(st)[0] == "HEALTHY"
    m.render_kpi_etcd(st)  # lifetime total renders without error


def test_etcd_increase_in_window_degrades_then_clears(m):
    w = m.CounterWatch(m._ETCD_FAIL_WINDOW_S)
    _etcd_state(m, w, 7, 0.0)
    st = _etcd_state(m, w, 8, 60.0)
    assert m.overall_verdict(st) == ("DEGRADED", "etcd write failures")
    st = _etcd_state(m, w, 8, 700.0)
    assert m.overall_verdict(st)[0] == "HEALTHY"


# ── 5 s-tier metric parsers (fixtures captured from the live cluster) ──────


def test_fetch_etcd_health_parses(m, monkeypatch):
    fixture = (
        "etcd_server_has_leader 1\n"
        "etcd_server_is_leader 1\n"
        "etcd_server_proposals_failed_total 0\n"
        "etcd_mvcc_db_total_size_in_use_in_bytes 4.939776e+06\n"
        "etcd_mvcc_db_total_size_in_bytes 8433664\n"
    )
    monkeypatch.setattr(m.urllib.request, "urlopen", lambda *a, **k: _FakeResp(fixture))
    out = m.fetch_etcd_health()
    assert out["has_leader"] == 1
    assert out["proposals_failed"] == 0
    assert out["db_in_use"] == pytest.approx(4_939_776.0)

    def _boom(*a, **k):
        raise OSError("refused")

    monkeypatch.setattr(m.urllib.request, "urlopen", _boom)
    assert m.fetch_etcd_health() == {}


def test_fetch_cnpg_metrics_parses(m, monkeypatch):
    fixture = (
        'cnpg_backends_total{datname="spatiumddi",state="idle"} 9\n'
        'cnpg_backends_total{datname="spatiumddi",state="active"} 1\n'
        "cnpg_backends_waiting_total 0\n"
        'cnpg_pg_database_size_bytes{datname="spatiumddi"} 18013207\n'
        "cnpg_pg_replication_streaming_replicas 0\n"
        "cnpg_pg_replication_in_recovery 0\n"
    )
    monkeypatch.setattr(m.urllib.request, "urlopen", lambda *a, **k: _FakeResp(fixture))
    out = m.fetch_cnpg_metrics("10.0.0.1")
    assert out["backends_idle"] == 9
    assert out["backends_active"] == 1
    assert out["backends_waiting"] == 0
    assert out["db_size_bytes"] == pytest.approx(18_013_207.0)
    assert out["in_recovery"] == 0


def test_fetch_api_metrics_parses(m, monkeypatch):
    fixture = (
        'spatiumddi_api_requests_total{path_template="/x",status_code="200"} 100\n'
        'spatiumddi_api_requests_total{path_template="/y",status_code="200"} 54\n'
        "spatiumddi_api_active_requests 2\n"
    )
    monkeypatch.setattr(m.urllib.request, "urlopen", lambda *a, **k: _FakeResp(fixture))
    # Reset the module-level prev-sample so rate is deterministic (0.0 first call).
    m._API_REQ_PREV = None
    out = m.fetch_api_metrics("10.0.0.1")
    assert out["total"] == 154
    assert out["active"] == 2
    assert out["rate"] == 0.0


def test_metallb_speaker_health(m):
    rows = [
        {"Namespace": "metallb-system", "Names": "speaker-aaa", "Ready": "1/1"},
        {"Namespace": "metallb-system", "Names": "speaker-bbb", "Ready": "0/1"},
        {"Namespace": "spatium", "Names": "api-x", "Ready": "1/1"},
    ]
    assert m.metallb_speaker_health(rows) == (1, 2)
    assert m.metallb_speaker_health([]) == (0, 0)


# ── §3d sizing invariant ───────────────────────────────────────────────────


def _build_state(m, cols: int, rows: int, nodes: int = 1, pods: int = 14):
    st = m.DashboardState({}, _FakeTail(), "/dev/tty1")
    st.role = "control-plane"
    st.cpu_percent = 40.0
    st.ram_used_gib, st.ram_total_gib, st.ram_percent = 2.0, 8.0, 25.0
    st.load_avg = (0.5, 0.4, 0.3)
    st.disks = [("/", 1.0, 8.0, 12.0), ("/var", 5.0, 15.0, 33.0)]
    st.ip_v4 = ["192.168.0.50"]
    st.ip_v6 = []
    st.k3s_state = ("v1.35 · ready", "bold green")
    st.nodes = [
        {"name": f"n{i}", "ready": "True", "roles": "server", "version": "v1.35"}
        for i in range(nodes)
    ]
    st.ps_rows = [
        {
            "Names": f"spatium/pod-{i}",
            "Namespace": "spatium",
            "K8sState": "Running",
            "Status": "Running",
            "State": "Running",
            "Ready": "1/1",
            "Restarts": "0",
            "Node": "n0",
        }
        for i in range(pods)
    ]
    st.term_size = (cols, rows)
    return st


@pytest.mark.parametrize(
    "cols,rows",
    [(213, 52), (120, 30), (80, 24), (80, 20)],
)
def test_render_frame_sizing_invariant(m, cols, rows):
    """render_frame renders at every tier without an exception and ALWAYS
    keeps the vitals row (CPU/RAM) + the F-key footer on-screen, with nothing
    clipped past the terminal height (§3d)."""
    state = _build_state(m, cols, rows)
    console = Console(width=cols, height=rows, file=io.StringIO(), color_system="standard")
    console.print(m.render_frame(state, 1.5))
    out = console.file.getvalue()
    plain = _ANSI.sub("", out)
    assert "CPU" in plain and "RAM" in plain, "vitals row missing"
    assert "F1" in plain and "F5" in plain, "footer F-keys missing"
    lines = plain.split("\n")
    last = max((i for i, ln in enumerate(lines) if ln.strip()), default=0)
    assert last < rows, "content clipped past the terminal height"


def test_render_frame_no_unsafe_glyphs(m):
    """No 256-glyph-console-unsafe characters leak into the rendered frame."""
    state = _build_state(m, 120, 40)
    console = Console(width=120, height=40, file=io.StringIO(), color_system="standard")
    console.print(m.render_frame(state, 1.5))
    bad = re.findall(r"[✓◐○▁-▇▓]", console.file.getvalue())
    assert not bad, f"unsafe glyphs in render: {sorted(set(bad))}"


# ── Pods panel shows the whole cluster (#592) ────────────────────────────────
#
# On a 3-node HA appliance each node's console showed only that node's pods,
# while ``kubectl get pods -A`` showed all of them. An auto-filter kicked in
# above 20 visible pods and kept "problem pods + pods on THIS node"; a 3-node
# appliance idles at ~22, so the filter was effectively always on for exactly
# the deployment where cluster-wide visibility matters most.
#
# It protected nothing either: render_services sorts by _pod_sort_priority
# BEFORE the height clamp, so broken pods float to the top and cannot be
# clipped, and the remainder becomes the "… +N more pods · F3 to list"
# subtitle. Sorting + overflow already do the filter's stated job.


class _StubTail:
    """JournalTail stand-in — render_log only reads ``.lines``."""

    lines: list[str] = []

    def stop(self) -> None:  # pragma: no cover - never called here
        pass


def _pod592(name: str, node: str, state: str = "Running", ready: str = "1/1") -> dict:
    return {
        "Namespace": "spatium",
        "Names": name,
        "Type": "Deployment",
        "Node": node,
        "Ready": ready,
        "Restarts": 0,
        "RestartedAt": "",
        "K8sState": state,
        "PodIP": "10.42.0.1",
        "Ports": "",
        "Age": "5m",
    }


def _idle_three_node_cluster() -> list[dict]:
    """~22 visible pods over three nodes — what a real 3-node appliance idles
    at, and what tripped the old 20-pod threshold."""
    rows = [
        _pod592(f"workload-{node}-{i}", node) for node in ("ddi1", "ddi2", "ddi3") for i in range(7)
    ]
    rows.append(_pod592("migrate-abc", "ddi3", state="Succeeded", ready="0/1"))
    return rows


def _panel_text(m, rows: list[dict], cap: int | None = None) -> str:
    buf = Console(width=200, record=True, file=io.StringIO())
    buf.print(m.render_services("control-plane", rows, cap=cap))
    return _ANSI.sub("", buf.export_text())


def _frame_text(m, rows: list[dict]) -> str:
    """Render the WHOLE frame. This is the path that carried the bug: the
    filter lived in render_frame's caller-side helper, not in render_services,
    so a panel-only test cannot see the regression."""
    state = m.DashboardState(env={}, tail=_StubTail(), tty_path="/dev/tty1")
    state.ps_rows = rows
    buf = Console(width=220, height=70, record=True, file=io.StringIO())
    buf.print(m.render_frame(state, 0.0))
    return _ANSI.sub("", buf.export_text())


def test_frame_shows_pods_from_nodes_other_than_this_one(m) -> None:
    """REGRESSION (#592). The old filter kept pods whose Node == this host.
    None of the fixture's nodes are named after the machine running the test,
    so the pre-fix code renders ZERO workload pods here — the same defect that,
    on a real ddi1, rendered only ddi1's third of the cluster.

    Asserting "at least two distinct nodes" rather than all three: 21 pods
    exceed the panel height, so the last node legitimately overflows into the
    "+N more pods" subtitle. That is the clamp working, not a filter.
    """
    text = _frame_text(m, _idle_three_node_cluster())
    seen = [n for n in ("ddi1", "ddi2", "ddi3") if f"workload-{n}-0" in text]
    assert len(seen) >= 2, f"only saw pods from {seen or 'no nodes'}"
    assert "filtered:" not in text, "the node-local filter label is back"


def test_frame_still_reports_overflow(m) -> None:
    """The subtitle is the operator's cue that the panel is truncated — it is
    what makes dropping the filter safe."""
    text = _frame_text(m, _idle_three_node_cluster())
    assert "more pods" in text
    assert "F3 to list" in text


def test_no_node_local_filter_survives(m) -> None:
    """Gone, not merely re-tuned. A higher threshold would reintroduce the bug
    on a 5- or 7-node cluster."""
    assert not hasattr(m, "_filtered_pods")
    assert not hasattr(m, "_POD_FILTER_THRESHOLD")


def test_completed_jobs_still_hidden(m) -> None:
    """Dropping the node filter must not drop the Succeeded-Job filter — that
    one is load-bearing for panel height (see visible_pods)."""
    assert "migrate-abc" not in _panel_text(m, _idle_three_node_cluster())


def test_problem_pods_sort_above_healthy_ones(m) -> None:
    """The mechanism that actually protects a crash-looping pod."""
    assert m._pod_sort_priority(_pod592("boom", "ddi3", "CrashLoopBackOff", "0/1")) == 0
    assert m._pod_sort_priority(_pod592("wait", "ddi2", "Pending", "0/1")) == 1
    assert m._pod_sort_priority(_pod592("half", "ddi2", "Running", "1/2")) == 2
    assert m._pod_sort_priority(_pod592("fine", "ddi1")) == 3


def test_a_crashloop_on_a_remote_node_survives_a_brutal_clamp(m) -> None:
    """The filter's stated purpose was stopping a crash-looping pod being
    buried under healthy ones. Sort + clamp already guarantee that — even when
    the broken pod is on a REMOTE node and the panel can show one row."""
    rows = _idle_three_node_cluster()
    rows.append(_pod592("boom", "ddi3", state="CrashLoopBackOff", ready="0/1"))
    text = _panel_text(m, rows, cap=1)
    assert "boom" in text, "the crash-looping pod was clipped by the height clamp"
    assert "workload-ddi1-0" not in text, "a healthy pod outranked the crashloop"


def test_clamped_rows_are_reported_not_silently_dropped(m) -> None:
    rows = _idle_three_node_cluster()
    text = _panel_text(m, rows, cap=3)
    # 21 visible (the Succeeded job is filtered out), 3 shown → 18 hidden.
    assert "+18 more pods" in text
    assert "F3 to list" in text


# ── #803 — dashboard rendering polish ─────────────────────────────────


def test_node_column_hidden_on_a_single_node_cluster(m) -> None:
    """It was the same hostname repeated down every row, while NAME — the
    one flexible column — got squeezed to ellipsis behind 12 fixed ones."""
    rows = [_pod592(f"pod-{i}", "ddi1") for i in range(4)]
    text = _panel_text(m, rows)
    assert "NODE" not in text
    assert "ddi1" not in text


def test_node_column_returns_when_there_is_more_than_one_node(m) -> None:
    rows = [_pod592("a", "ddi1"), _pod592("b", "ddi2")]
    text = _panel_text(m, rows)
    assert "NODE" in text
    assert "ddi2" in text


def test_long_pod_names_survive_on_a_wide_console(m) -> None:
    """Two CloudNativePG replicas differ only in their pod hash; the old
    22-char cap cut exactly there and rendered them identically."""
    rows = [
        _pod592("cloudnative-pg-8cc7b886c-g5svx", "ddi1"),
        _pod592("cloudnative-pg-8cc7b886c-r4mgt", "ddi1"),
    ]
    text = _panel_text(m, rows)
    assert "g5svx" in text and "r4mgt" in text


def test_human_cpu_keeps_sub_centicore_readings_honest(m) -> None:
    """``f"{c:.2f}"`` renders 0.00 for every idle pod, which is most of an
    appliance — indistinguishable from truly zero."""
    assert m._human_cpu(1.25) == "1.25"
    assert m._human_cpu(0.30) == "0.30"
    assert m._human_cpu(0.004) == "4m"
    assert m._human_cpu(0.0) == "0"


def test_sanitize_strips_ansi_and_control_bytes(m) -> None:
    """Pod stdout is arbitrary; the console font has 256 glyphs, so an
    escape sequence renders as mojibake."""
    assert m._sanitize_console_text("\x1b[31mred\x1b[0m") == "red"
    assert m._sanitize_console_text("a\x00b\x07c") == "abc"
    assert m._sanitize_console_text("a\tb") == "a b"
    assert m._sanitize_console_text("plain text") == "plain text"


def test_celery_prefix_compaction_returns_the_payload(m) -> None:
    raw = (
        "[2026-08-02 16:55:49,504: INFO/ForkPoolWorker-4] "
        "Task app.tasks.dns_health.probe"
        "[3f2a1b4c-1111-2222-3333-444455556666] succeeded in 0.31s: {'ok': 3}"
    )
    out = m.AppLogTail._compact(raw)
    assert out.startswith("16:55:49 INFO")
    assert "ForkPoolWorker" not in out
    assert "3f2a1b4c" not in out
    assert "{'ok': 3}" in out  # the part worth reading survives
    assert len(out) < len(raw) - 50


NOISE_LINES = [
    "Scheduler: Sending due task app.tasks.x",
    "Task app.tasks.foo received",
    "Task app.tasks.x succeeded in 0.02s: {'status': 'disabled'}",
    # The majority case on a real box: enabled sweeps with nothing to do.
    # Kept to one source line — a wrapped string inside a list reads as a
    # missing comma, which is exactly the mistake the lint guards against.
    # (The four-key form and the `failed`-key veto interaction have their
    # own test below.)
    "Task app.tasks.event_outbox.process succeeded in 0.02s: {'delivered': 0, 'failed': 0}",
    "Task app.tasks.dns.check_all succeeded in 0.02s: None",
    "Task app.tasks.snmp.dispatch succeeded in 0.02s: 0",
    'INFO:   10.42.0.1:8742 - "GET /metrics HTTP/1.1" 200 OK',
    'INFO:   10.42.0.52:1 - "POST /api/v1/appliance/supervisor/heartbeat HTTP/1.1" 200 OK',
]

SIGNAL_LINES = [
    "Task app.tasks.ipam_discovery.dispatch succeeded in 0.04s: 3",
    "Task app.tasks.x succeeded in 0.1s: {'created': 4, 'deleted': 0}",
    "Task app.tasks.x succeeded in 0.02s: {'claimed': 0, 'failed': 2}",
    "Task app.tasks.x received but Failed to connect",
    "Task app.tasks.x succeeded in 0.02s: {'status': 'error'}",
    'INFO:   10.42.0.1 - "GET /api/v1/ipam/subnets HTTP/1.1" 200 OK',
    'INFO:   10.42.0.1 - "GET /metrics HTTP/1.1" 500 Internal Server Error',
    "Task app.tasks.x raised unexpected: ValueError()",
]


@pytest.mark.parametrize("line", NOISE_LINES)
def test_app_log_noise_is_dropped(m, line: str) -> None:
    assert m.AppLogTail._is_noise(line), line


@pytest.mark.parametrize("line", SIGNAL_LINES)
def test_app_log_signal_always_survives(m, line: str) -> None:
    """The filter must fail toward showing too much. A single non-zero
    count, an unrecognised status, or any error marker keeps the line."""
    assert not m.AppLogTail._is_noise(line), line


def test_all_zero_result_beats_the_error_veto_on_a_key_named_failed(m) -> None:
    """``_REAL_ERROR_RE`` matches the bare word "failed", which appears as a
    dict KEY in half these payloads. Having parsed every value and found
    them zero, the line is proof of its own uneventfulness — so the parse
    is checked before the keyword scan, or a key that says nothing failed
    would veto its own filtering."""
    line = "Task app.tasks.x succeeded in 0.02s: {'delivered': 0, 'failed': 0}"
    assert m.AppLogTail._is_noop_result(line)
    assert m.AppLogTail._is_noise(line)


def test_unparseable_result_is_treated_as_interesting(m) -> None:
    """Nested structures aren't parsed; assume they matter."""
    assert not m.AppLogTail._is_noop_result(
        "Task app.tasks.x succeeded in 0.02s: {'rows': [{'a': 0}]}"
    )


# ── #803 code-review follow-ups ───────────────────────────────────────


def test_boolean_false_makes_a_result_interesting(m) -> None:
    """A boolean field is an ASSERTION, not a count. ``{'ok': False}`` is a
    health check reporting a problem; treating False as "nothing" would drop
    it — and since the no-op parse runs ahead of the error veto, nothing
    downstream would rescue it."""
    line = "Task app.tasks.x succeeded in 0.02s: {'ok': False, 'rows_checked': 0, 'broken': 0}"
    assert not m.AppLogTail._is_noop_result(line)
    assert not m.AppLogTail._is_noise(line)
    # And the same shape reporting success stays visible too — polarity
    # must not be the thing that decides.
    assert not m.AppLogTail._is_noise(
        "Task app.tasks.x succeeded in 0.02s: {'ok': True, 'checked': 0}"
    )


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/appliance/supervisor/poll",
        "/api/v1/appliance/supervisor/heartbeat",
        "/api/v1/appliance/supervisor/pcap/poll",
        "/api/v1/appliance/supervisor/k8s-proxy/poll",
    ],
)
def test_every_supervisor_poll_shape_is_filtered(m, path: str) -> None:
    """The bare ``/poll`` has no sub-path, and sub-paths are kebab-case —
    both missed by a naive ``\\w+/poll``."""
    assert m.AppLogTail._is_noise(f'INFO:   10.42.0.52:1 - "POST {path} HTTP/1.1" 200 OK')


def test_level_padding_survives_compaction(m) -> None:
    """A blanket double-space collapse would undo the ``:<5`` padding and
    leave INFO and WARNING ragged against each other."""
    info = m.AppLogTail._compact("[2026-08-02 16:55:49,504: INFO/ForkPoolWorker-4] hello")
    warn = m.AppLogTail._compact("[2026-08-02 16:55:49,504: WARNING/ForkPoolWorker-4] hello")
    assert info.index("hello") == warn.index("hello")


def test_compaction_preserves_column_aligned_payload(m) -> None:
    """``_sanitize_console_text`` deliberately keeps runs of spaces so
    structlog's column-aligned output stays readable."""
    out = m.AppLogTail._compact(
        "[2026-08-02 16:55:49,504: WARNING/MainProcess] "
        "[warning ] alert_unknown_rule_type    rule=abc type=x"
    )
    assert "rule=abc" in out
    assert "    rule=abc" in out  # the alignment run survived


def test_long_component_name_does_not_leak_into_the_body(m) -> None:
    """The prefix used to be re-sliced off the FORMATTED string at a
    hardcoded offset that encoded the padding width, so a component longer
    than it would render its tail twice."""
    line = m.AppLogTail._compact("some message")
    assert line == "some message"
    # The formatting path itself: component and body stay separate.
    for comp in ("api", "spatium-supervisor-extra-long"):
        rendered = f"{comp:<9} {m.AppLogTail._compact('payload here')}"
        assert rendered.endswith("payload here")
        assert rendered.count("payload here") == 1


def test_node_column_uses_the_cluster_node_count_not_pod_placement(m) -> None:
    """A two-node cluster that just lost a node has its pods Pending with no
    Node value — exactly when the operator needs to see WHERE things are.
    Deriving multi-node from pod placement would hide the column then."""
    rows = [_pod592("a", ""), _pod592("b", "")]
    for r in rows:
        r["K8sState"] = "Pending"
        r["Node"] = ""
    text = _panel_text_nodes(m, rows, node_count=2)
    assert "NODE" in text


def _panel_text_nodes(m, rows: list[dict], node_count: int) -> str:
    buf = Console(width=200, record=True, file=io.StringIO())
    buf.print(m.render_services("control-plane", rows, node_count=node_count))
    return _ANSI.sub("", buf.export_text())


def test_bare_scalar_result_is_boring_like_the_dict_form(m) -> None:
    """``beat_tick`` returns ``'ok'`` every 30s; that says exactly as
    little as ``{'status': 'ok'}``, which was already filtered."""
    assert m.AppLogTail._is_noise("Task app.tasks.heartbeat.beat_tick succeeded in 0.004s: 'ok'")
    # A scalar that reports actual work still shows.
    assert not m.AppLogTail._is_noise(
        "Task app.tasks.ipam_discovery.dispatch succeeded in 0.04s: 7"
    )


# ── #779 — Web UI firewall self-check warning ───────────────────────────────
# webui_selfcheck_status() reads the verdict spatiumddi-webui-selfcheck
# writes to /run and returns an identity-row warning for exactly two
# states: a fresh `blocked` (bold red, carrying the script's own detail)
# and a persistent-indeterminate streak (dim yellow — the checker itself
# is broken and must not die silently). Everything else — open,
# scoped-hardened, a single indeterminate, stale, missing, garbage — is
# None, so a healthy or merely-unchecked appliance never shows a false
# alarm. Freshness follows the ttl_s the script ships in the file.


def _selfcheck_state(m, monkeypatch, tmp_path, payload):
    import json as _json

    p = tmp_path / "webui-selfcheck.json"
    p.write_text(_json.dumps(payload))
    monkeypatch.setattr(m, "_WEBUI_SELFCHECK_STATE", p)
    return p


def test_webui_selfcheck_fresh_blocked_is_red_with_detail(m, monkeypatch, tmp_path):
    import time as _time

    _selfcheck_state(
        m,
        monkeypatch,
        tmp_path,
        {
            "status": "blocked",
            "detail": "explicit drop rule for 443",
            "checked_at": int(_time.time()),
            "ttl_s": 900,
        },
    )
    chip = m.webui_selfcheck_status()
    assert chip is not None
    label, style = chip
    assert label.startswith("BLOCKED by firewall")
    # The script's own detail rides along — an explicit drop rule and a
    # missing accept read differently to the operator.
    assert "explicit drop rule for 443" in label
    assert style == "bold red"


@pytest.mark.parametrize("status", ["open", "scoped"])
def test_webui_selfcheck_healthy_states_are_none(m, monkeypatch, tmp_path, status):
    import time as _time

    _selfcheck_state(
        m,
        monkeypatch,
        tmp_path,
        {"status": status, "detail": "x", "checked_at": int(_time.time()), "ttl_s": 900},
    )
    assert m.webui_selfcheck_status() is None


def test_webui_selfcheck_single_indeterminate_is_none(m, monkeypatch, tmp_path):
    import time as _time

    _selfcheck_state(
        m,
        monkeypatch,
        tmp_path,
        {
            "status": "indeterminate",
            "detail": "x",
            "checked_at": int(_time.time()),
            "ttl_s": 900,
            "consecutive_indeterminate": 1,
        },
    )
    assert m.webui_selfcheck_status() is None


def test_webui_selfcheck_persistent_indeterminate_is_yellow(m, monkeypatch, tmp_path):
    import time as _time

    _selfcheck_state(
        m,
        monkeypatch,
        tmp_path,
        {
            "status": "indeterminate",
            "detail": "x",
            "checked_at": int(_time.time()),
            "ttl_s": 900,
            "consecutive_indeterminate": 3,
        },
    )
    chip = m.webui_selfcheck_status()
    assert chip is not None
    assert chip[1] == "yellow"


def test_webui_selfcheck_stale_blocked_is_none(m, monkeypatch, tmp_path):
    import time as _time

    # Older than the file's own ttl: the checker is broken; a verdict that
    # may predate a fixed firewall must not keep alerting.
    _selfcheck_state(
        m,
        monkeypatch,
        tmp_path,
        {
            "status": "blocked",
            "detail": "x",
            "checked_at": int(_time.time()) - 961,
            "ttl_s": 900,
        },
    )
    assert m.webui_selfcheck_status() is None


def test_webui_selfcheck_ttl_comes_from_the_file(m, monkeypatch, tmp_path):
    import time as _time

    # A slower timer ships a bigger ttl_s and stays alertable; the console
    # must follow the file, not a hardcoded constant (a cadence change in
    # the timer unit must not silently suppress the alarm).
    _selfcheck_state(
        m,
        monkeypatch,
        tmp_path,
        {
            "status": "blocked",
            "detail": "x",
            "checked_at": int(_time.time()) - 1200,
            "ttl_s": 3600,
        },
    )
    assert m.webui_selfcheck_status() is not None


def test_webui_selfcheck_missing_or_garbage_is_none(m, monkeypatch, tmp_path):
    monkeypatch.setattr(m, "_WEBUI_SELFCHECK_STATE", tmp_path / "nope.json")
    assert m.webui_selfcheck_status() is None
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    monkeypatch.setattr(m, "_WEBUI_SELFCHECK_STATE", bad)
    assert m.webui_selfcheck_status() is None


def test_overall_verdict_webui_blocked_is_critical(m):
    state = m.DashboardState({}, _FakeTail(), "/dev/tty1")
    verdict, offender = m.overall_verdict(
        state, None, None, ("BLOCKED by firewall — x", "bold red")
    )
    assert verdict == "CRITICAL"
    assert "Web UI" in offender


def test_overall_verdict_webui_yellow_note_is_not_critical(m):
    # The persistent-indeterminate note renders on the identity row but
    # must not flip the box CRITICAL. host_health retrying gives the
    # traversal a deterministic DEGRADED exit before the slot probe.
    state = m.DashboardState({}, _FakeTail(), "/dev/tty1")
    state.host_health = {"verdict": "ok", "failing": [], "retrying": ["ntp"], "restore": False}
    verdict, offender = m.overall_verdict(
        state, None, None, ("firewall self-check unavailable", "yellow")
    )
    assert verdict == "DEGRADED"
    assert "Web UI" not in offender


# ── #999 Part A — storage redundancy on the Disks row ─────────────────────
#
# The console is a THIRD reader of /sys/block (after the supervisor's
# collector and the installer's ``_disk_hazard``) because it shares no
# Python package with either. These build a fake sysfs and run the real
# function against it — a structural check would not catch an inverted
# comparison, and the failure mode of getting this wrong is a console
# reporting HEALTHY over a mirror that is one disk from data loss.


def _fake_md(
    root,
    name,
    *,
    level,
    raid_disks,
    members,
    action="idle",
    completed="none",
    array_state="clean",
):
    """``members`` is ``[(device, state)]`` — the kernel's own strings."""
    md = root / name / "md"
    md.mkdir(parents=True)
    (md / "level").write_text(level + "\n")
    (md / "array_state").write_text(array_state + "\n")
    (md / "raid_disks").write_text(f"{raid_disks}\n")
    (md / "sync_action").write_text(action + "\n")
    (md / "sync_completed").write_text(completed + "\n")
    for dev, state in members:
        (md / f"dev-{dev}").mkdir()
        (md / f"dev-{dev}" / "state").write_text(state + "\n")


def _fake_mpath(root, dm, *, friendly, uuid_, paths):
    """``paths`` is ``[(device, scsi_state_or_None)]``."""
    d = root / dm / "dm"
    d.mkdir(parents=True)
    (d / "uuid").write_text(uuid_ + "\n")
    (d / "name").write_text(friendly + "\n")
    (root / dm / "slaves").mkdir()
    for dev, scsi in paths:
        (root / dm / "slaves" / dev).mkdir()
        if scsi is not None:
            (root / dev / "device").mkdir(parents=True)
            (root / dev / "device" / "state").write_text(scsi + "\n")


def test_storage_summary_silent_without_arrays(m, monkeypatch, tmp_path):
    """The ordinary single-disk appliance: the Disk row is unchanged."""
    root = tmp_path / "block"
    root.mkdir()
    monkeypatch.setattr(m, "_SYS_BLOCK_DIR", str(root))
    assert m.storage_summary() == []


def test_storage_summary_healthy_mirror(m, monkeypatch, tmp_path):
    root = tmp_path / "block"
    root.mkdir()
    _fake_md(
        root,
        "md0",
        level="raid1",
        raid_disks=2,
        members=[("sda1", "in_sync"), ("sdb1", "in_sync")],
    )
    monkeypatch.setattr(m, "_SYS_BLOCK_DIR", str(root))
    text, style, sev = m.storage_summary()[0]
    assert text == "md0 raid1 ok 2/2"
    assert style == "green"
    assert sev == ""


def test_storage_summary_degraded_pair_is_critical(m, monkeypatch, tmp_path):
    """A mirror on its last disk. Capacity looks identical to a healthy
    one, which is exactly why the chip has to exist."""
    root = tmp_path / "block"
    root.mkdir()
    _fake_md(
        root,
        "md0",
        level="raid1",
        raid_disks=2,
        members=[("sda1", "in_sync"), ("sdb1", "faulty")],
    )
    monkeypatch.setattr(m, "_SYS_BLOCK_DIR", str(root))
    text, style, sev = m.storage_summary()[0]
    assert "DEGRADED 1/2" in text
    assert style == "bold red"
    assert sev == "critical"


def test_storage_summary_three_way_mirror_degraded_is_warning(m, monkeypatch, tmp_path):
    """``2 of 3`` is the same word and not the same night as ``1 of 2``."""
    root = tmp_path / "block"
    root.mkdir()
    _fake_md(
        root,
        "md0",
        level="raid1",
        raid_disks=3,
        members=[("sda1", "in_sync"), ("sdb1", "in_sync"), ("sdc1", "faulty")],
    )
    monkeypatch.setattr(m, "_SYS_BLOCK_DIR", str(root))
    text, style, sev = m.storage_summary()[0]
    assert "DEGRADED 2/3" in text
    assert style == "bold yellow"
    assert sev == "warning"


def test_storage_summary_rebuild_percent(m, monkeypatch, tmp_path):
    root = tmp_path / "block"
    root.mkdir()
    _fake_md(
        root,
        "md0",
        level="raid1",
        raid_disks=2,
        members=[("sda1", "in_sync"), ("sdb1", "spare")],
        action="recover",
        completed="300 / 1000",
    )
    monkeypatch.setattr(m, "_SYS_BLOCK_DIR", str(root))
    text, _style, sev = m.storage_summary()[0]
    # Still degraded while it rebuilds — "recovering" alone would read as
    # recovery already achieved.
    assert "DEGRADED 1/2 30%" in text
    assert sev == "critical"


def test_storage_summary_multipath_paths(m, monkeypatch, tmp_path):
    root = tmp_path / "block"
    root.mkdir()
    _fake_mpath(
        root,
        "dm-0",
        friendly="mpatha",
        uuid_="mpath-3600508b4",
        paths=[("sdc", "running"), ("sdd", "offline")],
    )
    monkeypatch.setattr(m, "_SYS_BLOCK_DIR", str(root))
    text, style, sev = m.storage_summary()[0]
    assert text == "mpatha mpath 1/2 paths"
    assert style == "bold yellow"
    assert sev == "warning"


def test_storage_summary_ignores_non_multipath_dm(m, monkeypatch, tmp_path):
    """An LVM LV is a ``dm-*`` too."""
    root = tmp_path / "block"
    root.mkdir()
    _fake_mpath(root, "dm-0", friendly="vg0-lv0", uuid_="LVM-abc", paths=[("sda2", "running")])
    monkeypatch.setattr(m, "_SYS_BLOCK_DIR", str(root))
    assert m.storage_summary() == []


def test_overall_verdict_degraded_array_is_critical(m):
    state = m.DashboardState({}, _FakeTail(), "/dev/tty1")
    state.storage_chips = [("md0 raid1 DEGRADED 1/2", "bold red", "critical")]
    verdict, offender = m.overall_verdict(state)
    assert verdict == "CRITICAL"
    assert "md0" in offender


def test_healthy_chips_render_after_the_capacity_list(m):
    """The vitals row is ``no_wrap`` with a right-hand ellipsis, so what
    is appended last is what a narrow console drops. A never-changing
    green chip has no business evicting the disk readout; a degraded one
    must never be evicted BY it."""
    state = m.DashboardState({}, _FakeTail(), "/dev/tty1")
    state.disks = [("/var", 3.9, 15.2, 26.0)]
    state.storage_chips = [
        ("md1 raid1 ok 2/2", "green", ""),
        ("md0 raid1 DEGRADED 1/2", "bold red", "critical"),
    ]
    line = _ANSI.sub("", m.render_header(state, 0.0).renderable.renderables[-1].plain)
    assert line.index("DEGRADED") < line.index("/var")
    assert line.index("/var") < line.index("ok 2/2")


def test_overall_verdict_reduced_but_survivable_array_is_degraded(m):
    state = m.DashboardState({}, _FakeTail(), "/dev/tty1")
    state.storage_chips = [("md0 raid1 DEGRADED 2/3", "bold yellow", "warning")]
    verdict, offender = m.overall_verdict(state)
    assert verdict == "DEGRADED"
    assert "md0" in offender


def test_storage_summary_failed_to_assemble_is_not_green(m, monkeypatch, tmp_path):
    """The console must not tell the person standing in front of it the
    opposite of what the Fleet screen says.

    An array that failed to assemble reports ``array_state=inactive``
    with ``raid_disks=0``, which falls through every member-count
    comparison — so without reading ``array_state`` the console rendered
    a green ``md127 none ok 0/0`` and left the box verdict HEALTHY while
    the supervisor was reporting the same array as failed.
    """
    root = tmp_path / "block"
    root.mkdir()
    _fake_md(root, "md127", level="none", raid_disks=0, members=[])
    (root / "md127" / "md" / "array_state").write_text("inactive\n")
    monkeypatch.setattr(m, "_SYS_BLOCK_DIR", str(root))
    text, style, sev = m.storage_summary()[0]
    assert "FAILED" in text
    assert style == "bold red"
    assert sev == "critical"


def test_storage_summary_ignores_imsm_container(m, monkeypatch, tmp_path):
    """A metadata container is permanently inactive with raid_disks=0 on
    a healthy box — reporting it would put an unclearable red chip on a
    console that is fine."""
    root = tmp_path / "block"
    root.mkdir()
    _fake_md(root, "md127", level="container", raid_disks=0, members=[])
    (root / "md127" / "md" / "array_state").write_text("inactive\n")
    monkeypatch.setattr(m, "_SYS_BLOCK_DIR", str(root))
    assert m.storage_summary() == []


def test_storage_summary_unreadable_member_count_is_not_dropped(m, monkeypatch, tmp_path):
    """An assembled array that will not say how many members it should
    have used to vanish from the row entirely — which looks exactly like
    a healthy single disk, i.e. the silence this feature exists to end."""
    root = tmp_path / "block"
    root.mkdir()
    _fake_md(root, "md0", level="raid1", raid_disks=2, members=[("sda1", "in_sync")])
    (root / "md0" / "md" / "raid_disks").write_text("garbage\n")
    monkeypatch.setattr(m, "_SYS_BLOCK_DIR", str(root))
    text, style, sev = m.storage_summary()[0]
    assert text == "md0 raid1 state unknown"
    assert style == "bold yellow"
    assert sev == "warning"


def test_overall_verdict_healthy_array_does_not_alarm(m):
    state = m.DashboardState({}, _FakeTail(), "/dev/tty1")
    state.storage_chips = [("md0 raid1 ok 2/2", "green", "")]
    verdict, _offender = m.overall_verdict(state)
    assert verdict == "HEALTHY"


# ── #2974: reboot / poweroff hand the PostgreSQL primary off first ─────────


def test_power_action_in_progress_reads_a_live_marker(m, monkeypatch, tmp_path):
    import os

    marker = tmp_path / "power-action"
    monkeypatch.setattr(m, "POWER_ACTION_MARKER", marker)
    assert m.power_action_in_progress() is None
    marker.write_text(f"{os.getpid()} poweroff\n")
    assert m.power_action_in_progress() == "poweroff"


def test_power_action_in_progress_ignores_a_dead_or_garbled_marker(m, monkeypatch, tmp_path):
    """A wrapper killed outright leaves its marker: that must not pin a
    'REBOOT under way' banner on the console for good."""
    marker = tmp_path / "power-action"
    monkeypatch.setattr(m, "POWER_ACTION_MARKER", marker)
    marker.write_text("999999999 reboot\n")
    assert m.power_action_in_progress() is None
    marker.write_text("garbage\n")
    assert m.power_action_in_progress() is None
    marker.write_text("1 halt\n")
    assert m.power_action_in_progress() is None


def test_a_power_action_under_way_counts_as_a_pending_reboot(m, monkeypatch, tmp_path):
    """The web-UI unit renames its trigger before the handoff: without the
    marker, F9 would say nothing is pending for the whole handoff."""
    import os

    monkeypatch.setattr(m, "_RELEASE_STATE_DIR", tmp_path / "release-state")
    marker = tmp_path / "power-action"
    monkeypatch.setattr(m, "POWER_ACTION_MARKER", marker)
    assert m.reboot_pending() is False
    marker.write_text(f"{os.getpid()} reboot\n")
    assert m.reboot_pending() is True


@pytest.mark.parametrize(("fn", "action"), [("do_reboot", "reboot"), ("do_shutdown", "poweroff")])
def test_console_power_keys_start_the_unit_without_waiting(m, monkeypatch, fn, action):
    """F5 / F6 hand the run to systemd and return at once, so the dashboard
    keeps rendering through a handoff of up to a few minutes."""
    calls = []

    class _Res:
        returncode = 0
        stdout = stderr = ""

    def _run(argv, **kw):
        calls.append(argv)
        return _Res()

    monkeypatch.setattr(m, "confirm_modal", lambda *a, **k: True)
    monkeypatch.setattr(m.subprocess, "run", _run)
    state = m.DashboardState({}, _FakeTail(), "/dev/tty1")
    getattr(m, fn)(Console(file=io.StringIO()), state)
    assert calls == [["systemctl", "start", "--no-block", f"spatium-power-action@{action}.service"]]
    assert "handing off the database primary" in state.status_message


def test_console_power_key_failure_is_reported(m, monkeypatch):
    class _Res:
        returncode = 5
        stdout = ""
        stderr = "Failed to start spatium-power-action@reboot.service: Unit not found.\n"

    monkeypatch.setattr(m, "confirm_modal", lambda *a, **k: True)
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: _Res())
    state = m.DashboardState({}, _FakeTail(), "/dev/tty1")
    m.do_reboot(Console(file=io.StringIO()), state)
    assert "could not be started" in state.status_message
    assert "Unit not found" in state.status_message


def test_console_power_key_declined_starts_nothing(m, monkeypatch):
    monkeypatch.setattr(m, "confirm_modal", lambda *a, **k: False)
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: pytest.fail("nothing should run"))
    m.do_shutdown(Console(file=io.StringIO()), m.DashboardState({}, _FakeTail(), "/dev/tty1"))
