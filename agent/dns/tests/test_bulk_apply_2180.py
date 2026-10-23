"""A bulk BIND9 apply runs its per-zone steps in batches and in parallel (#2180).

Measured on BIND 9.20 (2,000 zones of 37 records, every zone changed), nearly
all of the old ~0.12 s a zone was process start-up: ``named-checkzone``
(~63 ms, most of it BIND's library start, not the zone) and five ``rndc``
calls (~10 ms each). Rendering was 0.2 ms. So the zone check screens zones in
batches through one ``named-checkconf -z`` each, and the rndc calls for
different zones run on a bounded pool.

What must not change, and is pinned here: a refused zone is still found,
held back and reported with ``named-checkzone``'s own reason; the batch can
only CLEAR zones, never refuse one; and each zone's own rndc verbs stay in
order.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.drivers import bind9
from spatium_dns_agent.drivers.base import HeldZone
from spatium_dns_agent.drivers.bind9 import Bind9Driver

SOA = (
    "$TTL 300\n@ IN SOA ns1.{z}. host.{z}. ( {serial} 3600 600 86400 300 )\n"
    "@ IN NS ns1.{z}.\nns1 IN A 192.0.2.53\n"
)


def _zone(
    root: Path, zname: str, serial: int = 1, view: str | None = None, extra: str = ""
) -> Path:
    path = root / "zones" / (view or "") / f"{zname}.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(SOA.format(z=zname, serial=serial) + extra)
    return path


def _stage(tmp_path: Path) -> Path:
    new = tmp_path / "rendered.new"
    new.mkdir(parents=True)
    (new / "named.conf").write_text("options {};\n")
    return new


def _all_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bind9.shutil, "which", lambda name: f"/usr/sbin/{name}")


class Script:
    """A thread-safe ``subprocess.run`` stand-in answering by command."""

    def __init__(self, answer: Callable[[list[str]], tuple[int, str, str]]):
        self.answer = answer
        self.calls: list[list[str]] = []
        self._lock = threading.Lock()

    def __call__(self, cmd: list[str], *a: Any, **kw: Any) -> subprocess.CompletedProcess:
        with self._lock:
            self.calls.append(list(cmd))
        rc, out, err = self.answer(list(cmd))
        return subprocess.CompletedProcess(cmd, rc, out, err)

    def tool(self, name: str) -> list[list[str]]:
        return [c for c in self.calls if Path(c[0]).name == name]


def _scratch_zones(conf: str) -> list[str]:
    """The zone names a scratch ``named-checkconf -z`` config lists."""
    return [
        line.split('"')[1]
        for line in Path(conf).read_text().splitlines()
        if line.startswith("zone ")
    ]


def _checker(
    refused: set[str], batch: str = "honest"
) -> Callable[[list[str]], tuple[int, str, str]]:
    """Answers like BIND 9.20 for zones named in ``refused``.

    ``batch``: ``honest`` (refuses a batch holding a refused zone, reports a
    load for each other zone), ``silent`` (exits 0 but reports nothing),
    ``timeout`` (never answers).
    """

    def answer(cmd: list[str]) -> tuple[int, str, str]:
        tool = Path(cmd[0]).name
        if tool == "named-checkconf" and cmd[1] == "-z":
            if batch == "timeout":
                raise subprocess.TimeoutExpired(cmd, 300)
            if batch == "silent":
                return 0, "", ""
            names = _scratch_zones(cmd[2])
            out = "".join(
                (
                    f"zone {z}/IN: not loaded due to errors.\n"
                    if z in refused
                    else f"zone {z}/IN: loaded serial 1\n"
                )
                for z in names
            )
            return (1 if refused & set(names) else 0), out, ""
        if tool == "named-checkzone" and cmd[-2] in refused:
            return 1, f"dns_rdata_fromtext: {cmd[-1]}:6: near '999.1.1.1': bad dotted quad\n", ""
        return 0, "", ""

    return answer


def _many(new: Path, n: int, view: str | None = None) -> list[str]:
    names = [f"z{i:03d}.test" for i in range(n)]
    for z in names:
        _zone(new, z, view=view)
    return names


# ── the bounded pool ──────────────────────────────────────────────────────────
def test_parallel_map_keeps_input_order(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bind9, "_apply_workers", lambda: 4)
    assert bind9._parallel_map(lambda i: i * 2, range(50)) == [i * 2 for i in range(50)]


def test_parallel_map_raises_what_a_call_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    """A checker that times out must still fail the apply from the pool."""
    monkeypatch.setattr(bind9, "_apply_workers", lambda: 4)

    def boom(i: int) -> int:
        if i == 7:
            raise subprocess.TimeoutExpired(["named-checkzone"], 300)
        return i

    with pytest.raises(subprocess.TimeoutExpired):
        bind9._parallel_map(boom, range(20))


def test_one_worker_runs_serially_on_the_calling_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bind9, "_apply_workers", lambda: 1)
    me = threading.get_ident()
    assert bind9._parallel_map(lambda _i: threading.get_ident(), range(5)) == [me] * 5


def test_workers_follow_the_cgroup_quota_not_the_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """The #980 lesson: a container limited to a fraction of a CPU on a big
    host must not start a pool sized for the host."""
    monkeypatch.setattr(bind9.os, "sched_getaffinity", lambda _pid: set(range(64)))
    monkeypatch.setattr(bind9, "_cgroup_cpu_quota", lambda: 0.25)
    assert bind9._apply_workers() == 1
    monkeypatch.setattr(bind9, "_cgroup_cpu_quota", lambda: 2.5)
    assert bind9._apply_workers() == 3
    monkeypatch.setattr(bind9, "_cgroup_cpu_quota", lambda: None)
    assert bind9._apply_workers() == bind9._APPLY_WORKERS_MAX


# ── the batched zone check ────────────────────────────────────────────────────
def test_a_few_zones_skip_the_batch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    new = _stage(tmp_path)
    _many(new, bind9._CHECK_BATCH_MIN_ZONES - 1)
    _all_tools(monkeypatch)
    run = Script(_checker(set()))
    monkeypatch.setattr(subprocess, "run", run)
    Bind9Driver(tmp_path)._check_zone_files(new)
    assert not run.tool("named-checkconf")
    assert len(run.tool("named-checkzone")) == bind9._CHECK_BATCH_MIN_ZONES - 1


def test_a_clean_batch_clears_every_zone_in_one_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    new = _stage(tmp_path)
    names = _many(new, 40)
    _all_tools(monkeypatch)
    seen: list[str] = []
    honest = _checker(set())

    def answer(cmd: list[str]) -> tuple[int, str, str]:
        if Path(cmd[0]).name == "named-checkconf":
            seen.extend(_scratch_zones(cmd[2]))
        return honest(cmd)

    run = Script(answer)
    monkeypatch.setattr(subprocess, "run", run)
    drv = Bind9Driver(tmp_path)
    drv._check_zone_files(new)
    assert len(run.tool("named-checkconf")) == 1
    assert run.tool("named-checkzone") == []
    assert drv.held_back == ()
    assert sorted(seen) == names
    assert not list(tmp_path.glob(".zone-check-*")), "the scratch config is removed"


def test_scratch_config_names_the_staged_files_with_named_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The batch must test THESE files under the options named runs with,
    and keep a zone name repeated across views apart."""
    new = _stage(tmp_path)
    _many(new, 5, view="internal")
    _many(new, 5, view="external")
    _all_tools(monkeypatch)
    seen: list[str] = []

    def answer(cmd: list[str]) -> tuple[int, str, str]:
        if Path(cmd[0]).name == "named-checkconf":
            seen.append(Path(cmd[2]).read_text())
            return 0, "".join("zone x/IN: loaded serial 1\n" for _ in range(10)), ""
        return 0, "", ""

    monkeypatch.setattr(subprocess, "run", Script(answer))
    Bind9Driver(tmp_path)._check_zone_files(new)
    (conf,) = seen
    assert "check-integrity no;" in conf and "check-names master fail;" in conf
    assert conf.count("view ") == 2, "one scratch view per real view"
    assert f'file "{new}/zones/internal/z000.test.db"' in conf
    assert f'file "{new}/zones/external/z000.test.db"' in conf
    assert "/rendered/zones" not in conf, "never the live tree"


def test_a_batch_that_reports_no_loads_clears_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """rc 0 alone is not a pass: every zone has to be reported loaded."""
    new = _stage(tmp_path)
    _many(new, 20)
    _all_tools(monkeypatch)
    run = Script(_checker({"z004.test"}, batch="silent"))
    monkeypatch.setattr(subprocess, "run", run)
    drv = Bind9Driver(tmp_path)
    drv._check_zone_files(new)
    assert len(run.tool("named-checkzone")) == 20
    assert [h.zone for h in drv.held_back] == ["z004.test"]


def test_a_batch_without_a_verdict_is_not_split(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A timeout says nothing about the zones: no bisection, no clearing."""
    new = _stage(tmp_path)
    _many(new, 40)
    _all_tools(monkeypatch)
    run = Script(_checker(set(), batch="timeout"))
    monkeypatch.setattr(subprocess, "run", run)
    Bind9Driver(tmp_path)._check_zone_files(new)
    assert len(run.tool("named-checkconf")) == 1
    assert len(run.tool("named-checkzone")) == 40


def test_a_refused_batch_is_split_until_the_bad_zone_is_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    new = _stage(tmp_path)
    live = tmp_path / "rendered"
    _many(new, 200)
    _zone(live, "z123.test", serial=0)  # served before, so its last good copy is kept
    _all_tools(monkeypatch)
    run = Script(_checker({"z123.test", "z007.test"}))
    monkeypatch.setattr(subprocess, "run", run)
    drv = Bind9Driver(tmp_path)
    drv._check_zone_files(new)
    checked = [c[-2] for c in run.tool("named-checkzone")]
    assert {"z123.test", "z007.test"} <= set(checked)
    assert len(checked) <= 2 * bind9._CHECK_BATCH_MIN_ZONES, "only the last small halves"
    assert [(h.zone, h.served) for h in drv.held_back] == [
        ("z007.test", False),
        ("z123.test", True),
    ]
    assert all("bad dotted quad" in h.reason for h in drv.held_back)


def test_batched_and_serial_checks_hold_back_the_same_zones(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same input, same ``held_back``, whichever path did the work."""
    refused = {"z010.test", "z011.test", "z099.test"}

    def held(root: Path, min_zones: int) -> tuple[HeldZone, ...]:
        new = _stage(root)
        _many(new, 120, view="v")
        _zone(root / "rendered", "z011.test", serial=0, view="v")
        monkeypatch.setattr(bind9, "_CHECK_BATCH_MIN_ZONES", min_zones)
        monkeypatch.setattr(subprocess, "run", Script(_checker(refused)))
        drv = Bind9Driver(root)
        drv._check_zone_files(new)
        # The staged reason names the staging path; strip the root to compare.
        return tuple(h._replace(reason=h.reason.replace(str(root), "")) for h in drv.held_back)

    _all_tools(monkeypatch)
    serial = held(tmp_path / "a", 10**9)
    batched = held(tmp_path / "b", 8)
    assert serial == batched
    assert [h.zone for h in serial] == ["z010.test", "z011.test", "z099.test"]


def test_a_large_file_is_checked_on_its_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A million-record RPZ never joins a batch, nor the pool."""
    new = _stage(tmp_path)
    _many(new, 20)
    _zone(new, "big.test", extra="x IN A 192.0.2.1\n" * 50)
    monkeypatch.setattr(bind9, "_CHECK_BATCH_MAX_FILE_BYTES", 500)
    _all_tools(monkeypatch)
    in_batch: list[str] = []

    def answer(cmd: list[str]) -> tuple[int, str, str]:
        if Path(cmd[0]).name == "named-checkconf":
            names = _scratch_zones(cmd[2])
            in_batch.extend(names)
            return 0, "".join(f"zone {z}/IN: loaded serial 1\n" for z in names), ""
        return 0, "", ""

    run = Script(answer)
    monkeypatch.setattr(subprocess, "run", run)
    Bind9Driver(tmp_path)._check_zone_files(new)
    assert "big.test" not in in_batch
    assert [c[-2] for c in run.tool("named-checkzone")] == ["big.test"]


# ── the parallel rndc steps keep each zone's own order ────────────────────────
def test_each_zone_reloads_freeze_reload_thaw_in_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live = tmp_path / "rendered"
    names = _many(live, 30)
    monkeypatch.setattr(bind9, "_apply_workers", lambda: 6)
    run = Script(lambda cmd: (0, "", ""))
    monkeypatch.setattr(subprocess, "run", run)
    Bind9Driver(tmp_path)._reload_rendered_zones(["rndc"], already_frozen={("z003.test", None)})
    for z in names:
        verbs = [c[1] for c in run.calls if c[-1] == z]
        assert verbs == (["reload", "thaw"] if z == "z003.test" else ["freeze", "reload", "thaw"])


def test_verification_asks_every_changed_zone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live = tmp_path / "rendered"
    names = _many(live, 30)
    monkeypatch.setattr(bind9, "_apply_workers", lambda: 6)
    monkeypatch.setattr(bind9.shutil, "which", lambda name: f"/usr/sbin/{name}")
    run = Script(lambda cmd: (0, "serial: 1\n", ""))
    monkeypatch.setattr(subprocess, "run", run)
    Bind9Driver(tmp_path)._verify_zones_loaded(["rndc"], None)
    assert sorted(c[-1] for c in run.calls if "zonestatus" in c) == names


def test_a_zone_not_loaded_still_fails_the_parallel_verify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live = tmp_path / "rendered"
    _many(live, 30)
    monkeypatch.setattr(bind9, "_apply_workers", lambda: 6)
    monkeypatch.setattr(bind9, "_ZONE_LOAD_TIMEOUT_S", 0.0)
    monkeypatch.setattr(bind9.shutil, "which", lambda name: f"/usr/sbin/{name}")

    def answer(cmd: list[str]) -> tuple[int, str, str]:
        if cmd[-1] == "z017.test":
            return 1, "", "rndc: 'zonestatus' failed: not loaded\n"
        return 0, "serial: 1\n", ""

    monkeypatch.setattr(subprocess, "run", Script(answer))
    with pytest.raises(RuntimeError, match="z017.test"):
        Bind9Driver(tmp_path)._verify_zones_loaded(["rndc"], None)


# ── against the real checker ─────────────────────────────────────────────────
_REAL = shutil.which("named-checkconf") and shutil.which("named-checkzone")

# Verdicts verified against BIND 9.20 for both checkers.
_CASES = {
    "ok.test": ("ns1 IN A 192.0.2.53\n", True),
    "noglue.test": (None, False),  # in-zone NS without an address
    "wild.test": ("ns1 IN A 192.0.2.53\nfoo.*.y IN A 10.0.0.2\n", False),
    "cname.test": ("ns1 IN A 192.0.2.53\nc IN CNAME a.\nc IN A 10.0.0.1\n", False),
    "mxip.test": ("ns1 IN A 192.0.2.53\n@ IN MX 10 192.0.2.5\n", True),
    "badq.test": ("ns1 IN A 192.0.2.53\nwww IN A 999.1.1.1\n", False),
    "under.test": ("ns1 IN A 192.0.2.53\nun_der IN A 10.0.0.1\n", False),
    "outns.test": ("ns1 IN A 192.0.2.53\n@ IN NS ns.elsewhere.example.\n", True),
    "mxin.test": ("ns1 IN A 192.0.2.53\n@ IN MX 10 nohost.mxin.test.\n", True),
}


@pytest.mark.skipif(not _REAL, reason="needs BIND's named-checkconf and named-checkzone")
@pytest.mark.parametrize("min_zones", [10**9, 2])
def test_the_real_checkers_agree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, min_zones: int
) -> None:
    monkeypatch.setattr(bind9, "_CHECK_BATCH_MIN_ZONES", min_zones)
    new = _stage(tmp_path)
    for z, (body, _ok) in _CASES.items():
        path = new / "zones" / f"{z}.db"
        path.parent.mkdir(parents=True, exist_ok=True)
        soa = f"$TTL 300\n@ IN SOA ns1.{z}. h.{z}. ( 1 3600 600 86400 300 )\n@ IN NS ns1.{z}.\n"
        path.write_text(soa + (body or ""))
    drv = Bind9Driver(tmp_path)
    drv._check_zone_files(new)
    assert sorted(h.zone for h in drv.held_back) == sorted(
        z for z, (_b, ok) in _CASES.items() if not ok
    )


# ── validator additions (#2180): cgroup reads, lost freezes, batch bounds ──────
@pytest.mark.parametrize(
    ("files", "want"),
    [
        ({"cpu.max": "50000 100000\n"}, 0.5),  # v2, half a CPU
        ({"cpu.max": "250000 100000\n"}, 2.5),
        ({"cpu.max": "max 100000\n"}, None),  # v2, unbounded
        ({"cpu.max": "garbage\n"}, None),
        ({"cpu/cpu.cfs_quota_us": "150000\n", "cpu/cpu.cfs_period_us": "100000\n"}, 1.5),
        ({"cpu/cpu.cfs_quota_us": "-1\n", "cpu/cpu.cfs_period_us": "100000\n"}, None),
        ({"cpu/cpu.cfs_quota_us": "x\n", "cpu/cpu.cfs_period_us": "100000\n"}, None),
        ({}, None),  # no cgroup files at all
    ],
)
def test_cgroup_quota_reads_v1_and_v2(
    tmp_path: Path, files: dict[str, str], want: float | None
) -> None:
    for rel, body in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(body)
    assert bind9._cgroup_cpu_quota(tmp_path) == want


@pytest.mark.parametrize("quota", [None, 64.0, 1e9])
def test_the_pool_never_exceeds_its_cap(monkeypatch: pytest.MonkeyPatch, quota: float | None) -> None:
    """A 64-CPU host with no quota (or a nonsense one) still gets at most the cap."""
    monkeypatch.setattr(bind9.os, "sched_getaffinity", lambda _pid: set(range(64)))
    monkeypatch.setattr(bind9, "_cgroup_cpu_quota", lambda: quota)
    assert bind9._apply_workers() == bind9._APPLY_WORKERS_MAX == 8


def test_rndc_that_cannot_start_is_a_non_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_kw: Any) -> None:
        raise BlockingIOError(11, "Resource temporarily unavailable")

    monkeypatch.setattr(subprocess, "run", boom)
    rc, _out, err = bind9._rndc_run(["rndc"], "freeze", "a.test")
    assert rc != 0 and "could not run" in err


def test_a_freeze_pass_that_raises_thaws_every_zone_it_froze(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A zone frozen and then forgotten refuses every RFC 2136 update until
    named restarts. One failure on the pool must not strand the others."""
    new, live = tmp_path / "rendered.new", tmp_path / "rendered"
    names = _many(new, 40)
    _many(live, 40)
    monkeypatch.setattr(bind9, "_apply_workers", lambda: 6)

    def answer(cmd: list[str]) -> tuple[int, str, str]:
        if cmd[1] == "zonestatus" and cmd[-1] == "z017.test":
            raise RuntimeError("something unforeseen")
        return 0, "serial: 1\n", ""

    run = Script(answer)
    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(RuntimeError, match="unforeseen"):
        Bind9Driver(tmp_path)._freeze_before_swap(["rndc"], new, live, None)
    froze = {c[-1] for c in run.calls if c[1] == "freeze"}
    thawed = {c[-1] for c in run.calls if c[1] == "thaw"}
    assert froze == set(names)
    assert thawed == froze


def test_a_reload_that_raises_after_its_freeze_thaws_that_zone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live = tmp_path / "rendered"
    _many(live, 20)
    monkeypatch.setattr(bind9, "_apply_workers", lambda: 4)

    def answer(cmd: list[str]) -> tuple[int, str, str]:
        if cmd[1] == "reload" and cmd[-1] == "z005.test":
            raise BlockingIOError(11, "Resource temporarily unavailable")
        return 0, "", ""

    run = Script(answer)
    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(BlockingIOError):
        Bind9Driver(tmp_path)._reload_rendered_zones(["rndc"], already_frozen=set())
    assert [c[1] for c in run.calls if c[-1] == "z005.test"] == ["freeze", "reload", "thaw"]
    # every other zone still ran its own freeze/reload/thaw
    for z in (f"z{i:03d}.test" for i in range(20) if i != 5):
        assert [c[1] for c in run.calls if c[-1] == z] == ["freeze", "reload", "thaw"]


def test_a_batch_is_cut_at_its_byte_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    new = _stage(tmp_path)
    _many(new, 40)
    size = (new / "zones" / "z000.test.db").stat().st_size
    monkeypatch.setattr(bind9, "_CHECK_BATCH_MAX_BYTES", size * 10)
    _all_tools(monkeypatch)
    sizes: list[int] = []
    honest = _checker(set())

    def answer(cmd: list[str]) -> tuple[int, str, str]:
        if Path(cmd[0]).name == "named-checkconf":
            sizes.append(len(_scratch_zones(cmd[2])))
        return honest(cmd)

    monkeypatch.setattr(subprocess, "run", Script(answer))
    Bind9Driver(tmp_path)._check_zone_files(new)
    assert sizes == [10, 10, 10, 10]


def test_no_scratch_config_means_the_per_zone_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    new = _stage(tmp_path)
    _many(new, 20)
    _all_tools(monkeypatch)

    def no_tmp(*_a: Any, **_kw: Any) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(bind9.tempfile, "mkstemp", no_tmp)
    run = Script(_checker({"z004.test"}))
    monkeypatch.setattr(subprocess, "run", run)
    drv = Bind9Driver(tmp_path)
    drv._check_zone_files(new)
    assert not run.tool("named-checkconf")
    assert len(run.tool("named-checkzone")) == 20
    assert [h.zone for h in drv.held_back] == ["z004.test"]


# Every one verified against BIND 9.20.29: the batch and named-checkzone give
# the same verdict, alone and in a batch with good zones, with and without a
# view. The dangerous direction is a batch clearing what named-checkzone refuses.
_NEGATIVE = {
    "mx-to-ip": ("@ IN MX 10 192.0.2.5\n", True),
    "mx-to-cname": ("c IN CNAME ns1\n@ IN MX 10 c\n", True),
    "mx-bad-syntax": ("@ IN MX ten mail\n", False),
    "cname-and-a": ("c IN CNAME a.\nc IN A 10.0.0.1\n", False),
    "cname-at-apex": ("@ IN CNAME other.example.\n", False),
    "two-cnames": ("c IN CNAME a.\nc IN CNAME b.\n", False),
    "out-of-zone-glue": (
        "sub IN NS ns.other.example.\nns.other.example. IN A 192.0.2.9\n",
        True,
    ),
    "wrong-origin": ("$ORIGIN wrong.example.\nwww IN A 192.0.2.9\n", True),
    "ttl-huge": ("big 4294967295 IN A 10.0.0.1\n", True),
    "ttl-overflow": ("big 99999999999 IN A 10.0.0.1\n", False),
    "dup-diff-ttl": ("d 100 IN A 10.0.0.1\nd 200 IN A 10.0.0.1\n", True),
    "two-soa": ("@ IN SOA ns1 h ( 2 3600 600 86400 300 )\n", False),
    "soa-not-apex": ("sub IN SOA ns1 h ( 2 3600 600 86400 300 )\n", False),
    "underscore-ns-target": ("sub IN NS un_der.example.\n", False),
    "svcb-dns-noalpn": ("_dns IN SVCB 1 ns1 port=853\n", False),
    "ds-at-apex": (
        "@ IN DS 12345 8 2 49FD46E6C4B45C55D4AC69CBD3CD34AC1AFE51DE55E0CA8B6F1E5F1E3A4B6C7D\n",
        False,
    ),
    "ns-and-cname-sub": ("sub IN NS ns1\nsub IN CNAME x.\n", False),
    "include-missing": ("$INCLUDE /nonexistent/x.db\n", False),
    "generate-bad": ("$GENERATE 1-10 h$ A 999.0.0.$\n", False),
    "class-ch": ('c CH TXT "x"\n', False),
    "label-too-long": ("x" * 64 + " IN A 10.0.0.1\n", False),
    "unbalanced-paren": ('n IN TXT ( "x"\n', False),
}


@pytest.mark.skipif(not _REAL, reason="needs BIND's named-checkconf and named-checkzone")
@pytest.mark.parametrize("view", [None, "internal"])
@pytest.mark.parametrize("min_zones", [10**9, 2])
def test_the_real_checkers_agree_on_negative_cases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, view: str | None, min_zones: int
) -> None:
    monkeypatch.setattr(bind9, "_CHECK_BATCH_MIN_ZONES", min_zones)
    new = _stage(tmp_path)
    for i in range(7):
        _zone(new, f"good{i}.test", view=view)
    for case, (body, _ok) in _NEGATIVE.items():
        _zone(new, f"{case}.test", view=view, extra=body)
    drv = Bind9Driver(tmp_path)
    drv._check_zone_files(new)
    assert sorted(h.zone for h in drv.held_back) == sorted(
        f"{c}.test" for c, (_b, ok) in _NEGATIVE.items() if not ok
    )
    # and each refused zone is refused by the batch screen itself, alone
    goods = [(f"good{i}.test", view) for i in range(7)]
    for case, (_b, ok) in _NEGATIVE.items():
        verdict = drv._screen_chunk(new, [*goods, (f"{case}.test", view)])
        assert verdict is ok, case


def test_one_failed_thaw_does_not_cancel_the_others(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``Executor.map`` cancels queued calls once one raises; a thaw pass must
    still reach every zone."""
    monkeypatch.setattr(bind9, "_apply_workers", lambda: 2)
    zones = [(f"z{i:03d}.test", None) for i in range(30)]
    seen: list[str] = []
    lock = threading.Lock()

    def rndc(_base: list[str], *args: str) -> tuple[int, str, str]:
        with lock:
            seen.append(args[1])
        if args[1] == "z001.test":
            raise RuntimeError("unforeseen")
        return 0, "", ""

    monkeypatch.setattr(bind9, "_rndc_run", rndc)
    with pytest.raises(RuntimeError):
        Bind9Driver(tmp_path)._thaw(["rndc"], zones)
    assert sorted(seen) == [z for z, _v in zones]
