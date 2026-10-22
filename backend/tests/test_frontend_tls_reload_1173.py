"""The frontend reloads nginx in place when its certificate changes (#1173).

The appliance used to apply a new Web UI certificate by rolling the frontend
Deployment. The frontend is hostNetwork with host ports 80/443, so that roll is
terminate-first: each node's web port refused connections until its replacement
pod had started (about 23 s on the seed when a control-plane member joined).

The certificate Secret is mounted as a directory, so the kubelet already updates
``tls.crt`` / ``tls.key`` inside the running pod; nginx only has to be told. The
image's ``frontend/40-tls-reload-watch.sh`` does that with ``nginx -s reload``,
which keeps the listening sockets open. These tests run the script (it is run, not
read) against a fake ``nginx`` on PATH and a certificate directory laid out the
way the kubelet lays out a Secret volume.
"""

from __future__ import annotations

import os
import pathlib
import re
import signal
import subprocess
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "frontend" / "40-tls-reload-watch.sh"
_DOCKERFILE = _REPO_ROOT / "frontend" / "Dockerfile"
_CHART = _REPO_ROOT / "charts" / "spatiumddi" / "templates" / "frontend.yaml"

pytestmark = pytest.mark.skipif(
    not _DOCKERFILE.exists(), reason="frontend/ not present in this checkout (dev container)"
)

_TICK = 0.1  # the watcher's interval under test (5 s in the image)

# Logs every call; ``nginx -t`` fails while $STATE/refuse exists, and
# ``nginx -s reload`` fails while $STATE/down exists (no master running yet).
_FAKE_NGINX = """#!/bin/sh
case "$1" in
  -t)
    if [ -e "$STATE/refuse" ]; then
      echo "-t refused" >> "$LOG"
      echo 'nginx: [emerg] SSL_CTX_use_PrivateKey("/etc/nginx/tls/tls.key") failed (key values mismatch)' >&2
      exit 1
    fi
    echo "-t ok" >> "$LOG"
    echo "nginx: configuration file /etc/nginx/nginx.conf test is successful" >&2
    ;;
  -s)
    if [ -e "$STATE/down" ]; then
      echo "-s $2 failed" >> "$LOG"
      echo 'nginx: [error] open() "/run/nginx.pid" failed (2: No such file or directory)' >&2
      exit 1
    fi
    echo "-s $2" >> "$LOG"
    ;;
esac
exit 0
"""


@dataclass
class _Rig:
    root: pathlib.Path
    tls: pathlib.Path
    state: pathlib.Path
    log: pathlib.Path
    out: pathlib.Path
    err: pathlib.Path
    env: dict[str, str]
    procs: list[subprocess.Popen[bytes]] = field(default_factory=list)
    _gen: int = 0

    def project(self, crt: str, key: str) -> None:
        """Write the pair the way the kubelet's atomic writer updates a Secret
        volume: a fresh timestamped directory, then one rename of ``..data``.
        ``tls.crt`` / ``tls.key`` are symlinks through ``..data``."""
        self._gen += 1
        d = self.tls / f"..2026_10_22_18_00_{self._gen:02d}.000000001"
        d.mkdir()
        (d / "tls.crt").write_text(crt)
        (d / "tls.key").write_text(key)
        tmp = self.tls / "..data_tmp"
        tmp.symlink_to(d.name)
        os.replace(tmp, self.tls / "..data")
        for name in ("tls.crt", "tls.key"):
            link = self.tls / name
            if not link.is_symlink():
                link.symlink_to(f"..data/{name}")

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines() if self.log.exists() else []

    def reloads(self) -> int:
        return self.calls().count("-s reload")

    def launch(self, *, tls_dir: pathlib.Path | None = None) -> subprocess.Popen[bytes]:
        """Run the script as the nginx entrypoint does: a child that must return
        at once. Its own session, so teardown can end the watcher it leaves."""
        env = dict(self.env)
        env["SPATIUM_TLS_DIR"] = str(tls_dir or self.tls)
        with self.out.open("ab") as out, self.err.open("ab") as err:
            proc = subprocess.Popen(
                [str(_SCRIPT)],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                start_new_session=True,
            )
        self.procs.append(proc)
        return proc


def _wait_for(cond: Callable[[], bool], timeout: float = 5.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


@pytest.fixture
def rig(tmp_path: pathlib.Path) -> Iterator[_Rig]:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "nginx"
    fake.write_text(_FAKE_NGINX)
    fake.chmod(0o755)
    tls = tmp_path / "tls"
    tls.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    r = _Rig(
        root=tmp_path,
        tls=tls,
        state=state,
        log=tmp_path / "nginx-calls.log",
        out=tmp_path / "stdout.log",
        err=tmp_path / "stderr.log",
        env={
            "PATH": f"{bindir}:/usr/bin:/bin:/usr/local/bin",
            "SPATIUM_TLS_RELOAD_INTERVAL": str(_TICK),
            "LOG": str(tmp_path / "nginx-calls.log"),
            "STATE": str(state),
        },
    )
    try:
        yield r
    finally:
        for proc in r.procs:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=5)


def _started(rig: _Rig) -> subprocess.Popen[bytes]:
    rig.project("CERT-A", "KEY-A")
    proc = rig.launch()
    assert proc.wait(timeout=5) == 0, rig.err.read_text()
    return proc


def test_the_image_launches_it_and_the_kubelet_can_update_the_files() -> None:
    """The nginx entrypoint runs /docker-entrypoint.d/*.sh only when executable,
    and silently skips one that is not. A subPath mount of the Secret would
    freeze the files at pod start, so the watcher would never see a change."""
    assert os.access(_SCRIPT, os.X_OK), f"{_SCRIPT.name} must be executable"
    dockerfile = _DOCKERFILE.read_text()
    assert re.search(
        r"^COPY 40-tls-reload-watch\.sh /docker-entrypoint\.d/40-tls-reload-watch\.sh$",
        dockerfile,
        re.M,
    )
    chart = _CHART.read_text().splitlines()
    start = next(i for i, line in enumerate(chart) if line.strip() == "- name: tls-cert")
    assert chart[start + 1].strip() == "mountPath: /etc/nginx/tls"
    block: list[str] = []
    for line in chart[start + 1 :]:
        if line.strip().startswith("- ") or not line.startswith(" " * 14):
            break
        block.append(line.strip())
    assert not any(line.startswith("subPath") for line in block), block


def test_it_returns_at_once_so_the_entrypoint_goes_on_to_nginx(rig: _Rig) -> None:
    """The entrypoint runs these scripts one by one inside ``find | sort | while
    read``, then execs nginx. The script must hand back at once and leave the
    loop its remaining lines, while the watcher it forked keeps running."""
    rig.project("CERT-A", "KEY-A")
    env = dict(rig.env, SPATIUM_TLS_DIR=str(rig.tls))
    loop = (
        f'printf "%s\\n" "{_SCRIPT}" next | while read -r f; do '
        '[ "$f" = next ] && { echo saw-next; continue; }; "$f"; done'
    )
    t0 = time.monotonic()
    with rig.out.open("ab") as out, rig.err.open("ab") as err:
        proc = subprocess.Popen(
            ["sh", "-c", loop],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            start_new_session=True,
        )
    rig.procs.append(proc)
    assert proc.wait(timeout=5) == 0
    assert time.monotonic() - t0 < 3
    assert "saw-next" in rig.out.read_text().splitlines()
    assert _group_alive(proc.pid), "the watcher must outlive the entrypoint's loop"


def test_the_first_reading_is_taken_before_nginx_starts(rig: _Rig) -> None:
    """The entrypoint starts nginx as soon as the script returns, and nginx
    loads the pair then. A first reading taken later, in the forked watcher,
    can see a pair the kubelet wrote after nginx loaded its own: the watcher
    then takes the new pair for the one being served and never reloads it,
    the #1219 strand again. So the reading is done before the script returns.
    A slow hash makes the order visible: it has finished by the time the
    script has."""
    slow = rig.root / "slowbin"
    slow.mkdir()
    fake = slow / "sha256sum"
    fake.write_text(
        '#!/bin/sh\nout=$(cksum)\nsleep 0.3\necho read >> "$STATE/readings"\necho "$out"\n'
    )
    fake.chmod(0o755)
    rig.env["PATH"] = f"{slow}:{rig.env['PATH']}"
    _started(rig)
    readings = rig.state / "readings"
    assert readings.exists(), "the script returned before its first reading of the pair"
    assert "read" in readings.read_text().split()


def test_no_certificate_means_no_watcher(rig: _Rig) -> None:
    """Docker Compose (and the chart with frontend.tls.enabled off) mounts no
    certificate: nothing to watch, and nothing is left running."""
    proc = rig.launch(tls_dir=rig.root / "absent")
    assert proc.wait(timeout=5) == 0
    assert "not watching" in rig.out.read_text()
    assert _wait_for(lambda: not _group_alive(proc.pid), timeout=2)
    assert rig.calls() == []


def test_an_unchanged_certificate_is_never_reloaded(rig: _Rig) -> None:
    proc = _started(rig)
    time.sleep(_TICK * 10)
    assert _group_alive(proc.pid), "the watcher must keep running"
    assert rig.calls() == []


def test_a_new_certificate_is_tested_then_reloaded_once(rig: _Rig) -> None:
    _started(rig)
    time.sleep(_TICK * 3)
    rig.project("CERT-B", "KEY-B")
    assert _wait_for(lambda: rig.reloads() == 1)
    time.sleep(_TICK * 10)
    assert rig.calls() == ["-t ok", "-s reload"]
    assert "nginx reload sent" in rig.out.read_text()


def test_restoring_the_previous_certificate_reloads_again(rig: _Rig) -> None:
    """#1219's shape: a revert, then the api writing back the certificate nginx
    served before it. The restored content equals the first, but nginx was
    serving the reverted one, so the restore must reload too."""
    _started(rig)
    rig.project("CERT-B", "KEY-B")
    assert _wait_for(lambda: rig.reloads() == 1)
    rig.project("CERT-A", "KEY-A")
    assert _wait_for(lambda: rig.reloads() == 2)


def test_a_pair_nginx_refuses_is_not_sent_and_is_retried(rig: _Rig) -> None:
    """A key that does not match its certificate: nginx -t refuses it, so no
    reload is sent and nginx keeps serving the pair it has. The refusal is
    logged once, not on every tick, and the watcher keeps testing, so a pair
    that becomes acceptable is reloaded without another change."""
    _started(rig)
    (rig.state / "refuse").touch()
    rig.project("CERT-B", "KEY-WRONG")
    assert _wait_for(lambda: rig.calls().count("-t refused") >= 3)
    assert rig.reloads() == 0
    err = rig.err.read_text()
    assert err.count("nginx -t refused it") == 1, err
    assert "key values mismatch" in err
    (rig.state / "refuse").unlink()
    assert _wait_for(lambda: rig.reloads() == 1)


def test_a_reload_before_nginx_runs_is_retried(rig: _Rig) -> None:
    """The watcher starts before nginx does. A change in that window finds no
    master to signal; it must be retried, not marked done."""
    (rig.state / "down").touch()
    _started(rig)
    rig.project("CERT-B", "KEY-B")
    assert _wait_for(lambda: rig.calls().count("-s reload failed") >= 2)
    assert rig.reloads() == 0
    (rig.state / "down").unlink()
    assert _wait_for(lambda: rig.reloads() == 1)
    time.sleep(_TICK * 5)
    assert rig.reloads() == 1
