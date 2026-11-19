"""#2405 — on_failure keeps the install logs when the target has no /var/log.

Executes the real ``on_failure`` + ``_save_install_logs`` against a temp
MOUNT. A root copy that fails early (rsync exit 11 in /usr/lib/modules)
leaves the target mounted with no ``var/log``; the old gate
(``[ -d $MOUNT/var/log ]``) saved nothing and said nothing.
"""

from __future__ import annotations

import os
import subprocess
import textwrap

from _installer_source import extract_fn


def _run(tmp_path, *, mounted: bool, make_dest_unwritable: bool = False):
    mount = tmp_path / "target"
    (mount / "var").mkdir(parents=True)  # /var mounted, no var/log
    live = tmp_path / "live"
    live.mkdir()
    for name in ("install.log", "trace.log", "launch.log"):
        (live / name).write_text(f"content of {name}\n")
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    # mountpoint: a temp dir is never a real mountpoint, so stub it.
    mp = stubs / "mountpoint"
    # Only the target's /var answers "mounted": the gate is the /var
    # partition, never the root (a root-only mount would hide the logs
    # under the real /var on every later boot).
    mp.write_text(
        "#!/bin/sh\n"
        + ('case "$2" in */var) exit 0 ;; esac\nexit 1\n' if mounted else "exit 1\n")
    )
    cl = stubs / "clear"
    cl.write_text("#!/bin/sh\nexit 0\n")
    for f in (mp, cl):
        f.chmod(0o755)
    if make_dest_unwritable:
        # A regular FILE where the directory must go: mkdir -p fails
        # for any uid, root included (a chmod would not stop root).
        (mount / "var" / "log").write_text("not a directory")
    body = extract_fn("on_failure")
    # Cut the interactive tail (read + exec a login shell).
    body = body.split('    echo "Press Enter')[0] + "}\n"
    script = textwrap.dedent(
        f"""
        set -uo pipefail
        MOUNT={mount}
        INSTALL_LOG={live}/install.log
        TRACE_LOG={live}/trace.log
        log() {{ echo "[x] $*" >> "$INSTALL_LOG"; }}
        {extract_fn("_save_install_logs").replace("/var/log/spatium-install-launch.log", str(live / "launch.log"))}
        {body.replace("/var/log/spatium-install-launch.log", str(live / "launch.log"))}
        (exit 11)
        on_failure
        echo "on_failure returned $?"
        """
    )
    env = dict(os.environ, PATH=f"{stubs}:{os.environ['PATH']}")
    r = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env, timeout=30
    )
    return r, mount, live


def _assert_verdict_is_last(out: str, verdict: str) -> None:
    """The verdict prints after the ~90 rows of log tails, so it is still on
    a 50-row console when the installer waits for Enter (#2405 walk)."""
    assert out.index(verdict) > out.index("Installer exited with status")
    assert out.index(verdict) > out.index("Also useful from the shell:")


def test_logs_land_on_target_when_var_log_is_missing(tmp_path):
    r, mount, _ = _run(tmp_path, mounted=True)
    dest = mount / "var/log/spatiumddi/install"
    assert dest.is_dir(), r.stderr
    assert oct(dest.stat().st_mode & 0o777) == "0o755"
    for name in ("install.log", "trace.log", "launch.log"):
        assert (dest / name).read_text() == f"content of {name}\n"
        assert oct((dest / name).stat().st_mode & 0o777) == "0o644"
    assert "Installer logs were saved to the target" in r.stdout
    assert "could NOT be saved" not in r.stdout
    _assert_verdict_is_last(r.stdout, "Installer logs were saved to the target")
    assert "on_failure returned 0" in r.stdout


def test_warns_where_the_logs_remain_when_saving_is_impossible(tmp_path):
    r, mount, live = _run(tmp_path, mounted=True, make_dest_unwritable=True)
    assert "could NOT be saved to the target" in r.stdout
    assert str(live / "install.log") in r.stdout
    assert str(live / "trace.log") in r.stdout
    assert "on_failure returned 0" in r.stdout  # never fails itself
    _assert_verdict_is_last(r.stdout, "could NOT be saved to the target")


def test_not_mounted_writes_nothing_and_warns(tmp_path):
    # Shape of a failure at a wizard prompt: nothing mounted. (var/ exists
    # in the fixture but is not a mountpoint and has no var/log.)
    r, mount, live = _run(tmp_path, mounted=False)
    assert not (mount / "var/log").exists()
    assert "could NOT be saved to the target" in r.stdout
    assert "on_failure returned 0" in r.stdout
