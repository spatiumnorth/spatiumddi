"""A trial boot does not commit its slot while one of the slot's images is missing (#1630).

firstboot commits a trial slot (``commit_slot_if_healthy``, grub-set-default)
once the apiserver answers and the control chart is placed. Nothing checked the
slot's images. A slot upgrade whose first boot failed to import the DNS and
DHCP agents' tarballs committed anyway. The swap became durable with
``ErrImageNeverPull`` agents, and no reboot would bring the previous slot
back.

Now the ready branch runs ``slot_images_allow_commit`` before the commit. It
runs ``spatium-k3s-images verify --repair`` (through ``check_slot_images``).
When an image is still missing, a trial boot exits 1 before the commit, so the
previous slot stays the durable default and the next reboot reverts to it, as
a failed host-migrate does (#554). A steady-state boot has nothing to commit
and goes on.

These tests run firstboot's real ready branch and its real functions under
``sh`` (dash on the appliance and on the CI runner). The steps around them are
stubbed, as are the helper and ``is_trial_boot``.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_firstboot_slot_images_gate.py -v
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

FIRSTBOOT = (
    Path(__file__).parent.parent
    / "mkosi.extra"
    / "usr"
    / "local"
    / "bin"
    / "spatiumddi-firstboot"
)
SHELL = shutil.which("dash") or "sh"
HELPER = "/usr/local/bin/spatium-k3s-images"
SCRIPT = FIRSTBOOT.parent / "spatium-k3s-images"


def _lines() -> list[str]:
    return FIRSTBOOT.read_text(encoding="utf-8").splitlines()


def _function(name: str) -> str | None:
    lines = _lines()
    try:
        i = lines.index(f"{name}() {{")
    except ValueError:
        return None
    j = lines.index("}", i + 1)
    return "\n".join(lines[i : j + 1])


# #2109 — the budget the gate hands the helper is worked out from the unit's
# start; this boot "started" 100 s after the kernel and it is now 400 s.
_GATE_PRELUDE = """FIRSTBOOT_TIMEOUT_S=600
FIRSTBOOT_T0=100
SLOT_IMAGES_MARGIN_S=45
"""


def _gate_functions(uptime: str = "echo 400") -> str:
    fns = [_function(n) for n in ("slot_images_budget", "check_slot_images", "slot_images_allow_commit")]
    return "\n".join([_GATE_PRELUDE, f"uptime_s() {{ {uptime}; }}"] + [f for f in fns if f])


def _ready_branch() -> str:
    lines = _lines()
    i = lines.index('if [ "$ready" = 1 ]; then')
    j = lines.index("fi", i + 1)
    return "\n".join(lines[i : j + 1])


def _boot(tmp_path: Path, *, helper_rc: int, trial: bool):
    helper = tmp_path / "spatium-k3s-images"
    helper.write_text(f'#!/bin/sh\necho "$*" >> "{tmp_path}/helper.log"\nexit {helper_rc}\n')
    helper.chmod(0o755)
    selfcheck = tmp_path / "webui-selfcheck"
    selfcheck.write_text("#!/bin/sh\nexit 0\n")
    selfcheck.chmod(0o755)
    real = _gate_functions()
    branch = _ready_branch().replace("/usr/local/bin/spatiumddi-webui-selfcheck", str(selfcheck))
    script = f"""set -eu
STAMP="{tmp_path}/stamp"
BOOTSTRAP_MANIFEST="{tmp_path}/spatium-bootstrap.yaml"
ready=1
date() {{ echo 2026-10-06T20:00:00+00:00; }}
ip() {{ :; }}
tighten_kubeconfig() {{ :; }}
pin_control_failure_policy() {{ :; }}
place_deferred_tls_manifest() {{ :; }}
reassert_control_plane_class() {{ :; }}
place_deferred_control_manifest() {{ :; }}
skip_tls_manifest_reapply() {{ :; }}
commit_slot_if_healthy() {{ echo committed > "{tmp_path}/committed"; }}
is_trial_boot() {{ return {0 if trial else 1}; }}
{real.replace(HELPER, str(helper))}
{branch}
"""
    proc = subprocess.run([SHELL, "-c", script], capture_output=True, text=True, check=False)
    return proc, (tmp_path / "committed").exists()


def test_a_trial_boot_with_an_image_missing_does_not_commit(tmp_path) -> None:
    proc, committed = _boot(tmp_path, helper_rc=1, trial=True)
    assert not committed, (
        "firstboot committed the trial slot while one of its images was missing: the "
        "swap is now durable with agents stuck in ErrImageNeverPull (#1630)"
    )
    assert proc.returncode == 1, "a trial boot that does not commit must leave firstboot failed"
    assert "trial boot: NOT committing this slot; next reboot reverts." in proc.stderr
    # #2109 — a slow import is not a bad slot; the operator is told how to keep it.
    assert "Fleet (Approve trial, on this node's slot) before the next reboot." in proc.stderr
    assert (tmp_path / "helper.log").read_text().split()[:2] == ["verify", "--repair"]


def test_a_trial_boot_with_every_image_present_commits(tmp_path) -> None:
    proc, committed = _boot(tmp_path, helper_rc=0, trial=True)
    assert committed
    assert proc.returncode == 0, proc.stderr


def test_a_steady_state_boot_with_an_image_missing_goes_on(tmp_path) -> None:
    proc, committed = _boot(tmp_path, helper_rc=1, trial=False)
    assert committed, "commit_slot_if_healthy is a no-op on a steady-state boot and must still run"
    assert proc.returncode == 0, proc.stderr
    assert "steady-state boot: nothing to commit; continuing." in proc.stderr


@pytest.mark.parametrize("name", ["check_slot_images", "slot_images_allow_commit"])
def test_the_gate_is_defined_once(name) -> None:
    assert sum(1 for ln in _lines() if ln == f"{name}() {{") == 1


def test_the_gate_sits_right_before_the_commit() -> None:
    branch = [ln.strip() for ln in _ready_branch().splitlines()]
    assert "slot_images_allow_commit || exit 1" in branch, "the ready branch has no image gate (#1630)"
    gate = branch.index("slot_images_allow_commit || exit 1")
    assert branch[gate + 1] == "commit_slot_if_healthy"
    assert branch.index("place_deferred_control_manifest") < gate


# ── #2109: the gate waits on k3s's import, for what is left of its budget ────


def _budget_args(tmp_path: Path, uptime: str) -> list[str]:
    helper = tmp_path / "spatium-k3s-images"
    helper.write_text(f'#!/bin/sh\necho "$*" > "{tmp_path}/args"\nexit 0\n')
    helper.chmod(0o755)
    script = f"set -eu\n{_gate_functions(uptime).replace(HELPER, str(helper))}\ncheck_slot_images\n"
    proc = subprocess.run([SHELL, "-c", script], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    return (tmp_path / "args").read_text().split()


@pytest.mark.parametrize(
    ("uptime", "expected"),
    [
        ("echo 400", ["--max-wait", "255"]),   # 600 - (400 - 100) - 45
        ("echo 650", ["--max-wait", "10"]),    # 5 s left: the floor, a verdict before systemd's kill
        ("echo 700", ["--max-wait", "10"]),    # past the budget: the floor
        ("echo 0", ["--max-wait", "600"]),     # a clock behind T0: never past the unit's timeout
        ("return 1", ["--max-wait", "600"]),   # /proc/uptime unreadable: read as 0, capped
    ],
)
def test_the_gate_gives_the_helper_what_is_left_of_the_units_timeout(tmp_path, uptime, expected) -> None:
    assert _budget_args(tmp_path, uptime) == ["verify", "--repair", *expected]


def test_the_timeout_in_the_script_is_the_units() -> None:
    unit = (FIRSTBOOT.parents[3] / "etc" / "systemd" / "system" / "spatiumddi-firstboot.service").read_text()
    assert "TimeoutStartSec=10min" in unit.splitlines()
    assert "FIRSTBOOT_TIMEOUT_S=600   # TimeoutStartSec=10min in spatiumddi-firstboot.service" in _lines(), (
        "spatiumddi-firstboot sizes the image check's wait to its unit's TimeoutStartSec; "
        "change both together"
    )


def test_uptime_s_reads_whole_seconds_under_the_target_shell() -> None:
    fn = _function("uptime_s")
    assert fn, "uptime_s() is gone"
    proc = subprocess.run([SHELL, "-c", f"set -eu\n{fn}\nuptime_s"], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().isdigit()


class _Healthz(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 — http.server's name
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args) -> None:
        pass


def test_a_trial_boot_commits_once_k3s_finishes_the_import_it_was_running(tmp_path) -> None:
    """End to end with the REAL helper and real processes: the kubelet
    answers, but k3s (a process holding the tarball open, as k3s does for
    the whole import) is still importing the slot's tarball. The gate waits,
    leaves the tarball alone, and commits once the import has ended."""
    images = tmp_path / "images"
    content = tmp_path / "content"
    images.mkdir()
    (content / "ingest").mkdir(parents=True)
    tarball = images / "dns-bind9.tar.zst"
    tarball.write_bytes(b"x" * 4096)
    os.utime(tarball, (1_760_000_000, 1_760_000_000))
    (images / ".cache.json").write_text("{}")
    store = tmp_path / "store"
    store.write_text("")
    k3s = tmp_path / "k3s"
    k3s.write_text(f'#!/bin/sh\ncat "{store}"\n')
    k3s.chmod(0o755)
    done = tmp_path / "import-done"
    # k3s's import: open the tarball, take its time, record it, close it
    importer = subprocess.Popen([sys.executable, "-c", f"""
import json, time
with open({str(tarball)!r}, "rb"):
    open({str(tmp_path / 'opened')!r}, "w").close()
    time.sleep(3)
    st = __import__("os").stat({str(tarball)!r})
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(st.st_mtime)))
    img = "ghcr.io/spatiumnorth/dns-bind9:2026.10.06-1"
    json.dump({{{str(tarball)!r}: {{"size": st.st_size, "modTime": stamp, "images": [img]}}}},
              open({str(images / '.cache.json')!r}, "w"))
    open({str(store)!r}, "w").write(img + "\\n")
open({str(done)!r}, "w").close()
"""])
    server = HTTPServer(("127.0.0.1", 0), _Healthz)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        deadline = time.monotonic() + 10
        while not (tmp_path / "opened").exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        selfcheck = tmp_path / "webui-selfcheck"
        selfcheck.write_text("#!/bin/sh\nexit 0\n")
        selfcheck.chmod(0o755)
        branch = _ready_branch().replace("/usr/local/bin/spatiumddi-webui-selfcheck", str(selfcheck))
        script = f"""set -eu
STAMP="{tmp_path}/stamp"
BOOTSTRAP_MANIFEST="{tmp_path}/spatium-bootstrap.yaml"
ready=1
date() {{ echo 2026-10-06T20:00:00+00:00; }}
ip() {{ :; }}
tighten_kubeconfig() {{ :; }}
pin_control_failure_policy() {{ :; }}
place_deferred_tls_manifest() {{ :; }}
reassert_control_plane_class() {{ :; }}
place_deferred_control_manifest() {{ :; }}
skip_tls_manifest_reapply() {{ :; }}
commit_slot_if_healthy() {{
    if [ -f "{done}" ]; then echo after; else echo before; fi > "{tmp_path}/committed"
}}
is_trial_boot() {{ return 0; }}
{_gate_functions().replace(HELPER, str(SCRIPT))}
{branch}
"""
        env = dict(
            os.environ,
            SPATIUM_K3S_IMAGES_DIR=str(images),
            SPATIUM_K3S_CONTENT_DIR=str(content),
            SPATIUM_K3S_BIN=str(k3s),
            SPATIUM_K3S_KUBELET_HEALTHZ=f"http://127.0.0.1:{server.server_port}/healthz",
        )
        proc = subprocess.run([SHELL, "-c", script], capture_output=True, text=True,
                              check=False, env=env, timeout=120)
    finally:
        server.shutdown()
        importer.wait(timeout=30)

    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert (tmp_path / "committed").read_text().strip() == "after", (
        "the gate judged (and committed) before k3s's import ended (#2109)\n" + out
    )
    assert tarball.stat().st_mtime == 1_760_000_000, "the gate touched the tarball k3s was importing\n" + out
    assert "k3s is importing dns-bind9.tar.zst; waiting for it to finish" in out
    assert "re-importing" not in out
