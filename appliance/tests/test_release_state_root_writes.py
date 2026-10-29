"""Root host runners never write through a name a pod could have planted.

``/var/lib/spatiumddi/release-state`` is mode 1770 root:2770. The api pod
(uid 1000 plus gid 2770) and the supervisor (uid 100 plus gid 2770) can
create names in it, and the sticky bit only stops them replacing a name
root already owns. Every runner under ``usr/local/bin`` runs as root, so a
redirect, an ``exec 9>`` lock, a fixed temp name, a ``chmod``/``chgrp`` or a
``mv`` onto a name in that directory follows a symlink planted there and
creates, truncates or re-modes any host file; a ``mv`` onto a directory (or a
link to one) moves the file into it.

The same holds one level down in ``pcap/`` and ``storage/``, which the
supervisor owns outright, on a removable disk (whose filesystem decides what
is at a name), and in the supervisor's ``tls/``.

These tests EXECUTE the shipped scripts (paths redirected into a tmp tree,
host tools stubbed) against planted symlinks and directories, and assert the
victim is untouched. They run unprivileged, as CI does: the victim is owned
by the test user, so a write through the link succeeds exactly as root's
would, which is what makes them fail on the unpatched scripts.

HOW TO RUN:  python3 -m pytest appliance/tests/test_release_state_root_writes.py -v
No database, Docker, ISO or root required.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
BIN = REPO / "appliance/mkosi.extra/usr/local/bin"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")

VICTIM_TEXT = "precious\n"


def _victim(tmp_path: Path, name: str = "victim") -> Path:
    v = tmp_path / name
    v.write_text(VICTIM_TEXT)
    v.chmod(0o640)
    return v


def _assert_untouched(v: Path) -> None:
    assert v.read_text() == VICTIM_TEXT
    assert stat.S_IMODE(v.stat().st_mode) == 0o640


def _stub(bindir: Path, name: str, body: str) -> None:
    bindir.mkdir(exist_ok=True)
    p = bindir / name
    p.write_text(body)
    p.chmod(0o755)


def _load(script: str, modname: str):
    loader = importlib.machinery.SourceFileLoader(modname, str(BIN / script))
    spec = importlib.util.spec_from_loader(modname, loader)
    mod = importlib.util.module_from_spec(spec)
    was, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = was
    return mod


# ── the shared shell helper ─────────────────────────────────────────────────

_STATE_WRITE_RE = re.compile(r"^state_write\(\) \{\n.*?^\}\n", re.S | re.M)


def _runners_with_state_write() -> list[Path]:
    return sorted(p for p in BIN.iterdir()
                  if p.is_file() and "\nstate_write() {" in p.read_text(errors="replace"))


def test_every_copy_of_state_write_is_the_same() -> None:
    """The helper is inlined (the runners are dependency-free on purpose);
    the copies must not drift."""
    runners = _runners_with_state_write()
    assert len(runners) >= 15, [p.name for p in runners]
    bodies = {p.name: _STATE_WRITE_RE.search(p.read_text()).group(0) for p in runners}
    assert len(set(bodies.values())) == 1, bodies


def _run_state_write(tmp_path: Path, target: Path, data: str = "new\n", shell: str = "bash"):
    fn = _STATE_WRITE_RE.search((BIN / "spatiumddi-tz-reload").read_text()).group(0)
    return subprocess.run(
        [shell, "-c", fn + f'printf %s "$1" | state_write "{target}"', "sh", data],
        capture_output=True, text=True, timeout=30,
    )


@pytest.mark.parametrize("shell", ["bash", "sh"])
def test_state_write_replaces_a_planted_symlink_and_never_writes_through_it(
    tmp_path: Path, shell: str
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    victim = _victim(tmp_path)
    (state / "x-hash").symlink_to(victim)
    r = _run_state_write(tmp_path, state / "x-hash", shell=shell)
    assert r.returncode == 0, r.stderr
    _assert_untouched(victim)
    assert not (state / "x-hash").is_symlink()
    assert (state / "x-hash").read_text() == "new\n"
    assert stat.S_IMODE((state / "x-hash").stat().st_mode) == 0o644
    assert sorted(p.name for p in state.iterdir()) == ["x-hash"]


def test_state_write_onto_a_directory_fails_and_moves_nothing_into_it(tmp_path: Path) -> None:
    state = tmp_path / "state"
    (state / "x-hash").mkdir(parents=True)
    r = _run_state_write(tmp_path, state / "x-hash")
    assert r.returncode != 0
    assert list((state / "x-hash").iterdir()) == []
    assert sorted(p.name for p in state.iterdir()) == ["x-hash"]


# ── executed runners ────────────────────────────────────────────────────────

def _tz_runner(tmp_path: Path) -> tuple[Path, Path, dict]:
    state = tmp_path / "state"
    state.mkdir()
    (tmp_path / "log").mkdir()
    src = (BIN / "spatiumddi-tz-reload").read_text()
    for a, b in (
        ("/var/lib/spatiumddi/release-state", str(state)),
        ("LOG_DIR=/var/log/spatiumddi", f"LOG_DIR={tmp_path}/log"),
        ("LOCK=/run/", f"LOCK={tmp_path}/"),
    ):
        assert a in src, a
        src = src.replace(a, b)
    script = tmp_path / "tz-reload"
    script.write_text(src)
    bindir = tmp_path / "bin"
    _stub(bindir, "timedatectl",
          '#!/bin/bash\ncase "$1" in list-timezones) echo UTC;; show) echo UTC;; esac\n')
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"}
    return script, state, env


def test_tz_runner_writes_its_sidecars_without_following_planted_links(tmp_path: Path) -> None:
    """The hash and status sidecars are names the api can plant before the
    runner's first write: a redirect onto them truncates the link's target."""
    script, state, env = _tz_runner(tmp_path)
    v_hash, v_status = _victim(tmp_path, "v-hash"), _victim(tmp_path, "v-status")
    (state / "tz-hash").symlink_to(v_hash)
    (state / "tz-status").symlink_to(v_status)
    (state / "tz-pending").write_text("UTC\n")
    r = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stdout + r.stderr
    _assert_untouched(v_hash)
    _assert_untouched(v_status)
    assert (state / "tz-hash").read_text() == "UTC\n"
    assert "state=ok" in (state / "tz-status").read_text()


def test_a_trigger_is_never_renamed_into_a_planted_directory(tmp_path: Path) -> None:
    """``<trigger>.failed.<epoch>`` is predictable. A link to a directory at
    that name made ``mv`` move the trigger (content the api wrote) into
    whatever directory the link names."""
    script, state, env = _tz_runner(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    now = int(time.time())
    for ts in range(now, now + 20):
        (state / f"tz-pending.failed.{ts}").symlink_to(elsewhere)
    (state / "tz-pending").write_text("Not/AZone\n")
    subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True, timeout=30)
    assert list(elsewhere.iterdir()) == []


def _firewall_revert(tmp_path: Path, *, deadline: int):
    state = tmp_path / "state"
    state.mkdir()
    etc = tmp_path / "etc"
    (etc / "nftables.d").mkdir(parents=True)
    (etc / "nftables.conf").write_text("# base\n")
    (etc / "nftables.d/spatium-role.nft").write_text("# tested ruleset\n")
    src = (BIN / "spatiumddi-firewall-revert").read_text()
    for a, b in (
        ("STATE=/var/lib/spatiumddi/release-state", f"STATE={state}"),
        ("/etc/nftables.d/", f"{etc}/nftables.d/"),
        ("NFT_MAIN=/etc/nftables.conf", f"NFT_MAIN={etc}/nftables.conf"),
        ("/tmp/nft-revert.err", f"{tmp_path}/nft-revert.err"),
    ):
        assert a in src, a
        src = src.replace(a, b)
    script = tmp_path / "firewall-revert"
    script.write_text(src)
    bindir = tmp_path / "bin"
    _stub(bindir, "nft", "#!/bin/bash\nexit 0\n")
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}",
           "SPATIUM_FIREWALL_REVERT_LOCK": str(tmp_path / "revert.lock")}
    (state / "firewall-revert-deadline").write_text(f"{deadline}\n")
    return script, state, etc, env


def test_the_firewall_revert_lock_follows_no_planted_symlink(tmp_path: Path) -> None:
    """``exec 9>"$STATE/firewall.lock"`` as root created or truncated
    whatever a link at that name pointed to, on every 15 s tick."""
    script, state, _etc, env = _firewall_revert(tmp_path, deadline=int(time.time()) + 3600)
    victim = _victim(tmp_path)
    (state / "firewall.lock").symlink_to(victim)
    r = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stdout + r.stderr
    _assert_untouched(victim)
    text = (BIN / "spatiumddi-firewall-revert").read_text()
    assert not re.search(r'^LOCK=.*release-state|^LOCK=\$STATE', text, re.M)


def test_the_firewall_revert_restores_nothing_it_did_not_write(tmp_path: Path) -> None:
    """The snapshot decides what the firewall becomes. One the runner did not
    write (here, a symlink to a file of someone else's choosing) is refused,
    and the status sidecar is written without following a planted link."""
    script, state, etc, env = _firewall_revert(tmp_path, deadline=1)
    chosen = tmp_path / "chosen.nft"
    chosen.write_text("# someone else's ruleset\n")
    (state / "firewall-role.nft.last-good").symlink_to(chosen)
    r = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (etc / "nftables.d/spatium-role.nft").read_text() == "# tested ruleset\n"


def test_the_firewall_revert_status_follows_no_planted_symlink(tmp_path: Path) -> None:
    script, state, etc, env = _firewall_revert(tmp_path, deadline=1)
    (state / "firewall-role.nft.last-good").write_text("# last good\n")
    victim = _victim(tmp_path)
    (state / "firewall-applied-status").symlink_to(victim)
    r = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stdout + r.stderr
    _assert_untouched(victim)
    assert (etc / "nftables.d/spatium-role.nft").read_text() == "# last good\n"
    assert (state / "firewall-applied-status").read_text() == "reverted\n"


def test_the_trigger_guard_never_quarantines_into_a_planted_directory(tmp_path: Path) -> None:
    root = tmp_path / "rs"
    root.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    target = tmp_path / "t"
    target.write_text("x\n")
    trig = root / "x-pending"
    trig.symlink_to(target)  # refused: a symlink
    now = int(time.time())
    for ts in range(now, now + 20):
        (root / f"x-pending.rejected.{ts}").symlink_to(elsewhere)
    env = {**os.environ, "SPATIUM_TRIGGER_ROOT": str(root),
           "SPATIUM_TRIGGER_GUARD_LOG": str(tmp_path / "guard.log")}
    r = subprocess.run(["bash", str(BIN / "spatiumddi-trigger-guard"), str(trig)],
                       env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode != 0
    assert list(elsewhere.iterdir()) == []


# ── slot runners' atomic_write / publish_sidecar ────────────────────────────

_SLOT_RUNNERS = ["spatiumddi-slot-upgrade", "spatiumddi-slot-set-next-boot",
                 "spatiumddi-slot-set-default", "spatiumddi-slot-rollback"]


def _fn(script: str, name: str) -> str:
    text = (BIN / script).read_text()
    m = re.search(rf"^{name}\(\) \{{.*?^\}}\n", text, re.S | re.M)
    assert m, f"{script}: no {name}()"
    return m.group(0)


@pytest.mark.parametrize("script", _SLOT_RUNNERS)
def test_atomic_write_never_moves_the_state_into_a_planted_directory(
    tmp_path: Path, script: str
) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    target = tmp_path / "slot-upgrade-pending.state"
    target.symlink_to(elsewhere)
    src = (_fn(script, "fsync_path") + _fn(script, "atomic_write")
           + f'atomic_write "{target}" "done X"\n')
    subprocess.run(["bash", "-c", src], capture_output=True, text=True, timeout=30)
    assert list(elsewhere.iterdir()) == []


def test_publish_sidecar_re_modes_only_a_file_this_script_owns_outright(tmp_path: Path) -> None:
    """chgrp / chmod follow a symlink: publishing a sidecar the api had
    replaced with one re-moded any host file 0660 group 2770."""
    victim = _victim(tmp_path)
    link = tmp_path / "slot-upgrade.progress"
    link.symlink_to(victim)
    src = (f"SIDECAR_GID={os.getgid()}\n" + _fn("spatiumddi-slot-upgrade", "publish_sidecar")
           + f'publish_sidecar "{link}"\n')
    r = subprocess.run(["bash", "-c", src], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    _assert_untouched(victim)
    # ...and a regular file it owns is still published.
    own = tmp_path / "own.state"
    own.write_text("x\n")
    own.chmod(0o644)
    src = (f"SIDECAR_GID={os.getgid()}\n" + _fn("spatiumddi-slot-upgrade", "publish_sidecar")
           + f'publish_sidecar "{own}"\n')
    subprocess.run(["bash", "-c", src], capture_output=True, text=True, timeout=30)
    assert stat.S_IMODE(own.stat().st_mode) == 0o660


# ── python runners ──────────────────────────────────────────────────────────

def test_upgrade_slot_sidecars_use_no_fixed_temp_name(tmp_path: Path) -> None:
    mod = _load("spatium-upgrade-slot", "spatium_upgrade_slot_rs_writes")
    v1, v2 = _victim(tmp_path, "v1"), _victim(tmp_path, "v2")
    progress = tmp_path / "slot-upgrade.progress"
    versions = tmp_path / "slot-versions.json"
    (tmp_path / "slot-upgrade.progress.new").symlink_to(v1)
    (tmp_path / "slot-versions.new").symlink_to(v2)
    mod._PROGRESS_FILE = progress
    mod._write_progress("writing", None, "x")
    mod._write_sidecar(versions, {"slot_a": "1"})
    _assert_untouched(v1)
    _assert_untouched(v2)
    assert '"step": "writing"' in progress.read_text()
    assert '"slot_a": "1"' in versions.read_text()
    assert stat.S_IMODE(progress.stat().st_mode) == 0o644


def test_etcd_evict_state_uses_no_predictable_temp_name(tmp_path: Path) -> None:
    mod = _load("spatium-etcd-evict", "spatium_etcd_evict_rs_writes")
    victim = _victim(tmp_path)
    mod.STATE = tmp_path / "etcd-evict.state"
    (tmp_path / f"etcd-evict.state.{os.getpid()}.new").symlink_to(victim)
    mod.write_state("r1", ["done"])
    _assert_untouched(victim)
    assert mod.STATE.read_text() == "id r1\ndone\n"
    assert stat.S_IMODE(mod.STATE.stat().st_mode) == 0o644


def test_host_migrate_ledger_uses_no_fixed_temp_name(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    patches = tmp_path / "patches"
    patches.mkdir()
    (patches / "001-noop.sh").write_text("#!/bin/sh\nexit 0\n")
    (patches / "001-noop.sh").chmod(0o755)
    (tmp_path / "baked").write_text("2\n")
    (tmp_path / "role-config").write_text("role=full-stack\n")
    (tmp_path / "log").touch()
    v_ledger, v_ver = _victim(tmp_path, "v-ledger"), _victim(tmp_path, "v-ver")
    (state / "host-patches-applied.json.new").symlink_to(v_ledger)
    (state / "host-template-version").symlink_to(v_ver)
    env = {**os.environ,
           "SPATIUM_HOST_PATCH_DIR": str(patches),
           "SPATIUM_HOST_TEMPLATE_VERSION_FILE": str(tmp_path / "baked"),
           "SPATIUM_HOST_STATE_DIR": str(state),
           "SPATIUM_HOST_MIGRATE_LOG": str(tmp_path / "log"),
           "SPATIUM_HOST_ROLE_CONFIG": str(tmp_path / "role-config")}
    subprocess.run(["sh", str(BIN / "spatium-host-migrate")], env=env,
                   capture_output=True, text=True, timeout=60)
    _assert_untouched(v_ledger)
    _assert_untouched(v_ver)


# ── supervisor-owned subdirectories ─────────────────────────────────────────

def test_pcap_runner_writes_nothing_through_names_the_supervisor_prepared(
    tmp_path: Path,
) -> None:
    """``pcap/`` belongs to the supervisor, so it can put a link at any name
    the runner is about to write: the state file, its fixed temp name, the
    capture, tcpdump's stderr."""
    rs = tmp_path / "rs"
    pcap = rs / "pcap"
    pcap.mkdir(parents=True)
    src = (BIN / "spatium-pcap-runner").read_text()
    assert "/var/lib/spatiumddi/release-state/pcap" in src
    script = tmp_path / "pcap-runner"
    script.write_text(src.replace("/var/lib/spatiumddi/release-state/pcap", str(pcap)))
    bindir = tmp_path / "bin"
    # A tcpdump that writes its capture where -w says ("-" = stdout).
    _stub(bindir, "tcpdump", '#!/bin/bash\nw=""\nwhile [ $# -gt 0 ]; do\n'
          '  [ "$1" = -w ] && { w="$2"; shift; }\n  shift\ndone\n'
          'if [ "$w" = - ]; then printf PCAPDATA; else printf PCAPDATA > "$w"; fi\n'
          'echo "1 packets captured" >&2\n')
    _stub(bindir, "logger", "#!/bin/bash\nexit 0\n")
    victims = {n: _victim(tmp_path, f"v-{n}") for n in
               ("c1.state", "c1.state.tmp", "c1.pcap", "c1.stderr")}
    for n, v in victims.items():
        (pcap / n).symlink_to(v)
    (pcap / "c1.request").write_text("capture_id=c1\ninterface=any\nmax_duration_s=5\nbpf=\n")
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "TMPDIR": str(tmp_path)}
    r = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    for v in victims.values():
        _assert_untouched(v)
    assert (pcap / "c1.pcap").read_text() == "PCAPDATA"
    assert "state=done" in (pcap / "c1.state").read_text()


def test_pcap_runner_refuses_a_pcap_directory_that_is_a_symlink(tmp_path: Path) -> None:
    rs = tmp_path / "rs"
    rs.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "c1.request").write_text("capture_id=c1\ninterface=any\nbpf=\n")
    (rs / "pcap").symlink_to(elsewhere)
    src = (BIN / "spatium-pcap-runner").read_text()
    script = tmp_path / "pcap-runner"
    script.write_text(src.replace("/var/lib/spatiumddi/release-state/pcap", str(rs / "pcap")))
    bindir = tmp_path / "bin"
    _stub(bindir, "tcpdump", "#!/bin/bash\nexit 0\n")
    _stub(bindir, "logger", "#!/bin/bash\nexit 0\n")
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "TMPDIR": str(tmp_path)}
    subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True, timeout=60)
    assert sorted(p.name for p in elsewhere.iterdir()) == ["c1.request"]


def test_storage_runner_result_uses_no_fixed_temp_name(tmp_path: Path) -> None:
    storage = tmp_path / "rs" / "storage"
    storage.mkdir(parents=True)
    src = (BIN / "spatiumddi-storage-action").read_text()
    for a, b in (
        ("STATE_DIR=/var/lib/spatiumddi/release-state/storage", f"STATE_DIR={storage}"),
        ("LOG_DIR=/var/log/spatiumddi", f"LOG_DIR={tmp_path}"),
    ):
        assert a in src, a
        src = src.replace(a, b)
    script = tmp_path / "storage-action"
    script.write_text(src)
    victim = _victim(tmp_path)
    (storage / "r1.result.json.new").symlink_to(victim)
    (storage / "r1.request.json").write_text('{"action": "no-such-action"}')
    r = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    _assert_untouched(victim)
    assert '"ok": false' in (storage / "r1.result.json").read_text()


def test_storage_runner_imports_no_module_from_its_working_directory(tmp_path: Path) -> None:
    """The runner works from inside ``storage/``, which the supervisor owns.
    A ``python3 -`` started there puts that directory first on sys.path, so a
    ``json.py`` placed in it would run as root when the request is parsed."""
    storage = tmp_path / "rs" / "storage"
    storage.mkdir(parents=True)
    src = (BIN / "spatiumddi-storage-action").read_text()
    for a, b in (
        ("STATE_DIR=/var/lib/spatiumddi/release-state/storage", f"STATE_DIR={storage}"),
        ("LOG_DIR=/var/log/spatiumddi", f"LOG_DIR={tmp_path}"),
    ):
        assert a in src, a
        src = src.replace(a, b)
    script = tmp_path / "storage-action"
    script.write_text(src)
    marker = tmp_path / "imported-from-storage-dir"
    for mod in ("json", "re", "tempfile"):
        (storage / f"{mod}.py").write_text(
            f"open({str(marker)!r}, 'a').write({mod!r} + '\\n')\n"
        )
    (storage / "r1.request.json").write_text('{"action": "no-such-action"}')
    r = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=60,
                       cwd=tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not marker.exists(), marker.read_text()
    assert '"ok": false' in (storage / "r1.result.json").read_text()


def test_pcap_runner_imports_no_module_from_its_working_directory(tmp_path: Path) -> None:
    """Same for ``pcap/``: the capture opener is a ``python3 -c`` started
    there. A directory at the capture's name makes it raise, and printing the
    traceback imports ``traceback`` (Python 3.13+), from the working
    directory unless Python runs isolated."""
    rs = tmp_path / "rs"
    pcap = rs / "pcap"
    pcap.mkdir(parents=True)
    src = (BIN / "spatium-pcap-runner").read_text()
    script = tmp_path / "pcap-runner"
    script.write_text(src.replace("/var/lib/spatiumddi/release-state/pcap", str(pcap)))
    bindir = tmp_path / "bin"
    _stub(bindir, "tcpdump", "#!/bin/bash\nprintf PCAPDATA\n")
    _stub(bindir, "logger", "#!/bin/bash\nexit 0\n")
    marker = tmp_path / "imported-from-pcap-dir"
    for mod in ("traceback", "linecache"):
        (pcap / f"{mod}.py").write_text(
            f"open({str(marker)!r}, 'a').write({mod!r} + '\\n')\n"
        )
    (pcap / "c1.pcap").mkdir()
    (pcap / "c1.request").write_text("capture_id=c1\ninterface=any\nmax_duration_s=5\nbpf=\n")
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "TMPDIR": str(tmp_path)}
    r = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True,
                       timeout=60, cwd=tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not marker.exists(), marker.read_text()
    assert "state=failed" in (pcap / "c1.state").read_text()


def test_runners_working_inside_a_supervisor_directory_run_python_isolated() -> None:
    """Structural half of the two tests above, for the Python versions whose
    exception display imports nothing: every python3 these runners start
    from inside their directory is ``-I``."""
    for name in ("spatium-pcap-runner", "spatiumddi-storage-action"):
        code = "\n".join(ln for ln in (BIN / name).read_text().splitlines()
                         if not ln.lstrip().startswith("#"))
        calls = re.findall(r"\bpython3\b[^\n]*", code)
        assert calls, name
        for c in calls:
            assert re.match(r"python3 -I\b", c), f"{name}: {c}"


# ── cluster-join's parked manifests ─────────────────────────────────────────

def _aside(tmp_path: Path, call: str) -> subprocess.CompletedProcess[str]:
    fns = (_fn("spatium-cluster-join", "_aside_dir_trusted")
           + _fn("spatium-cluster-join", "_aside_dir_ready"))
    src = (f'MANIFESTS_ASIDE="{tmp_path}/manifests-joined-aside"\n'
           'log() { echo "$*" >&2; }\n' + fns + call + "\n")
    return subprocess.run(["bash", "-c", src], capture_output=True, text=True, timeout=30)


def test_parked_manifests_are_trusted_only_in_a_directory_nobody_else_can_write(
    tmp_path: Path,
) -> None:
    """Whatever is parked there goes back into k3s's auto-deploy directory.
    A directory another writer created at that fixed name (here 0777) would
    decide what the cluster applies."""
    aside = tmp_path / "manifests-joined-aside"
    aside.mkdir()
    aside.chmod(0o777)
    assert _aside(tmp_path, "_aside_dir_trusted").returncode != 0
    aside.chmod(0o755)
    assert _aside(tmp_path, "_aside_dir_trusted").returncode == 0
    aside.rmdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "keep.yaml").write_text("x\n")
    aside.symlink_to(elsewhere)
    assert _aside(tmp_path, "_aside_dir_trusted").returncode != 0
    r = _aside(tmp_path, "_aside_dir_ready")
    assert r.returncode == 0, r.stderr
    assert aside.is_dir() and not aside.is_symlink()
    assert stat.S_IMODE(aside.stat().st_mode) == 0o700
    assert (elsewhere / "keep.yaml").read_text() == "x\n"


def test_a_leave_applies_no_manifest_parked_by_another_writer(tmp_path: Path) -> None:
    """The leave moves whatever is in the fixed-name aside directory into
    k3s's auto-deploy directory, applied with cluster-admin rights. One the
    api made there (any mode it likes) must not be the source."""
    server = tmp_path / "k3s" / "server"
    manifests = server / "manifests"
    manifests.mkdir(parents=True)
    agent = tmp_path / "k3s" / "agent"
    (agent / "images").mkdir(parents=True)
    rs = tmp_path / "release-state"
    aside = rs / "manifests-joined-aside"
    aside.mkdir(parents=True)
    aside.chmod(0o777)
    (aside / "spatium-planted.yaml").write_text("kind: Pod\n")
    (rs / "cluster-leave-pending").write_text("SPATIUMDDI-CLUSTER-LEAVE-CONFIRM-V1\n")
    config = tmp_path / "config.yaml"
    config.write_text("server: https://10.0.0.1:6443\ntoken: x\n")
    (tmp_path / "log").mkdir()
    evict = tmp_path / "spatium-etcd-evict"
    evict.write_text("#!/bin/sh\nexit 0\n")
    evict.chmod(0o755)
    stubs = ("systemctl() { return 0; }\n"
             "wait_ready() { return 0; }\n"
             "clean_k3s_runtime() { :; }\n")
    proc = subprocess.run(
        ["bash", "-c", f'source "{BIN / "spatium-cluster-join"}"\n{stubs}do_leave'],
        env={**os.environ,
             "SPATIUM_CLUSTER_JOIN_LIB": "1",
             "SPATIUM_RELEASE_STATE": str(rs),
             "SPATIUM_K3S_SERVER_DIR": str(server),
             "SPATIUM_K3S_AGENT_DIR": str(agent),
             "SPATIUM_K3S_NODE_PASSWORD": str(tmp_path / "node" / "password"),
             "SPATIUM_K3S_KUBECONFIG": str(tmp_path / "k3s.yaml"),
             "SPATIUM_K3S_CONFIG": str(config),
             "SPATIUM_K3S_DROPIN_DIR": str(tmp_path / "config.yaml.d"),
             "SPATIUM_LOG_DIR": str(tmp_path / "log"),
             "SPATIUM_FLANNEL_SUBNET_ENV": str(tmp_path / "flannel" / "subnet.env"),
             "SPATIUM_CNI_NETWORKS_DIR": str(tmp_path / "cni" / "networks"),
             "SPATIUM_ETCD_EVICT": str(evict)},
        capture_output=True, text=True, check=False, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert not (manifests / "spatium-planted.yaml").exists()


def test_identity_backups_go_into_a_fresh_directory() -> None:
    text = (BIN / "spatium-cluster-join").read_text()
    body = _fn("spatium-cluster-join", "backup_and_wipe_identity")
    assert 'bak=$(mktemp -d "$IDENTITY_BAK_ROOT.$suffix.$(date +%s).XXXXXX")' in body
    assert 'mkdir -p "$bak"\n' not in body
    # Both restores from the parked manifests are gated on the directory.
    assert text.count('_aside_dir_trusted && ls "$MANIFESTS_ASIDE"') == 2
    assert 'mkdir -p "$MANIFESTS_ASIDE"' not in text


# ── whole-tree sweep ────────────────────────────────────────────────────────

_ASSIGN = re.compile(r"^\s*(?:local\s+|export\s+|readonly\s+)?([A-Za-z_]\w*)=(.*)$")


def _shell_scripts():
    for f in sorted(BIN.iterdir()):
        if not f.is_file():
            continue
        first = f.read_text(errors="replace").split("\n", 1)[0]
        if re.match(r"#!\s*/(usr/)?bin/(env\s+)?(ba)?sh\b", first):
            yield f


def _state_vars(text: str) -> set[str]:
    """Variables naming a path in release-state, followed through
    assignments. One assigned from mktemp is excluded: mktemp creates it
    exclusively, so writing to it is safe."""
    vals: dict[str, list[str]] = {}
    for ln in text.splitlines():
        m = _ASSIGN.match(ln)
        if m:
            vals.setdefault(m.group(1), []).append(m.group(2))
    sv: set[str] = set()
    changed = True
    while changed:
        changed = False
        for k, vs in vals.items():
            if k in sv or any("mktemp" in v for v in vs):
                continue
            if any("release-state" in v or any(re.search(r"\$\{?" + s + r"\b", v) for s in sv)
                   for v in vs):
                sv.add(k)
                changed = True
    return sv


def test_no_shell_runner_writes_onto_a_release_state_name_directly() -> None:
    """Redirects, ``exec N>`` and ``mv`` without -T onto a name in
    release-state — the shape every finding above had."""
    bad = []
    for f in _shell_scripts():
        text = f.read_text(errors="replace")
        sv = _state_vars(text)
        if not sv:
            continue
        ref = r'"?\$\{?(?:' + "|".join(sorted(sv)) + r")\b"
        for i, ln in enumerate(text.splitlines(), 1):
            code = ln.split(" #", 1)[0]
            if code.lstrip().startswith("#"):
                continue
            if re.search(r"(?<![0-9&<])>>?\s*" + ref, code):
                bad.append(f"{f.name}:{i}: redirect: {ln.strip()}")
            if re.search(r"(?<![0-9&<])>>?\s*\"?/var/lib/spatiumddi/release-state", code):
                bad.append(f"{f.name}:{i}: redirect: {ln.strip()}")
            m = re.search(r"\bmv\s+((?:-\S+\s+)*)(?:--\s+)?\S+\s+" + ref + r"[^/\s]*\"?\s*(?:$|[|&;)]|2>)", code)
            if m and "T" not in m.group(1):
                bad.append(f"{f.name}:{i}: mv without -T: {ln.strip()}")
    assert not bad, "\n".join(bad)


def test_no_python_runner_writes_release_state_through_a_fixed_temp_name() -> None:
    for name in ("spatium-upgrade-slot", "spatium-etcd-evict", "spatium-host-migrate",
                 "spatiumddi-storage-action"):
        code = "\n".join(ln for ln in (BIN / name).read_text().splitlines()
                         if not ln.lstrip().startswith("#"))
        assert not re.search(r'with_suffix\("\.new"\)|\+ "\.new"|\.new"\)|\.new"$', code, re.M), name
        assert "mkstemp" in code, name


def test_firstboot_re_modes_nothing_in_release_state_by_a_name_it_does_not_own() -> None:
    """firstboot runs while the pods do: its chown / chmod / chgrp on names in
    release-state follow a symlink planted at them."""
    text = (BIN / "spatiumddi-firstboot").read_text()
    assert "chown 100:101 /var/lib/spatiumddi/release-state/pcap" not in text
    assert "chmod 0755 /var/lib/spatiumddi/release-state/pcap" not in text
    assert "&& chown 100:101 . && chmod 0755 . ); then" in text
    assert '> /var/lib/spatiumddi/release-state/host-storage-type' not in text
    loop = text[text.index("for _sc in /var/lib/spatiumddi/release-state/slot-upgrade-pending.state"):]
    loop = loop[: loop.index("done\n")]
    assert '[ ! -L "$_sc" ]' in loop and 'stat -c %u' in loop


def test_removable_prepare_follows_no_symlink_the_disk_carries(tmp_path: Path) -> None:
    """A disk carrying ``spatiumddi -> /etc`` had root chown and chmod 0700
    whatever that named."""
    mp = tmp_path / "removable/usb1"
    mp.mkdir(parents=True)
    target = tmp_path / "target-dir"
    target.mkdir()
    target.chmod(0o755)
    (mp / "spatiumddi").symlink_to(target)
    src = (BIN / "spatiumddi-removable-reload").read_text()
    for a, b in (
        ("APP_UID=1000", f"APP_UID={os.getuid()}"),
        ("APP_GID=1000", f"APP_GID={os.getgid()}"),
        ("LOG_DIR=/var/log/spatiumddi", f"LOG_DIR={tmp_path}"),
        ("ROOT=/var/lib/spatiumddi/removable", f"ROOT={tmp_path}/removable"),
    ):
        assert a in src, a
        src = src.replace(a, b)
    script = tmp_path / "removable-reload"
    script.write_text(src)
    bindir = tmp_path / "bin"
    _stub(bindir, "mountpoint", "#!/bin/bash\nexit 0\n")
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"}
    subprocess.run(["bash", str(script), "--prepare"], env=env,
                   capture_output=True, text=True, timeout=30)
    assert stat.S_IMODE(target.stat().st_mode) == 0o755
