"""spatiumddi-ssh-reload must not leave ssh.service failed (#1632).

Debian trixie runs sshd socket-activated: ``ssh.socket`` holds :22.  A
``systemctl reload ssh.service`` sends SIGHUP, sshd re-execs itself, cannot
bind the port the socket owns and dies, while the reload command itself exits
0 -- so the runner logged success over a failed unit.

These tests extract ``reload_sshd`` / ``current_ssh_port`` from the shipped
script and run them under **bash** against a stub ``systemctl`` that models
that behaviour, then assert on the unit state the stub ends in -- never on the
exit code of the action.

HOW TO RUN: python3 -m pytest appliance/tests/test_ssh_reload_socket_activation.py -v
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parent.parent
    / "mkosi.extra"
    / "usr"
    / "local"
    / "bin"
    / "spatiumddi-ssh-reload"
)

STUB = r"""#!/bin/bash
S="$STATE"
echo "$*" >> "$S/calls"
quiet=""
[ "${1:-}" = "is-active" ] && { shift; [ "${1:-}" = "--quiet" ] && shift; [ -f "$S/$1.active" ]; exit $?; }
case "$1 ${2:-}" in
  "daemon-reload "*) exit 0 ;;
  "reload ssh.service")
    # sshd re-execs on SIGHUP; under socket activation it cannot bind and dies,
    # but ExecReload (sshd -t; kill -HUP) has already exited 0.
    if [ -f "$S/ssh.socket.active" ]; then rm -f "$S/ssh.service.active"; fi
    exit 0 ;;
  "restart ssh.service")
    [ -n "${FAIL_SERVICE_RESTART:-}" ] && exit 1
    touch "$S/ssh.service.active"; exit 0 ;;
  "restart ssh.socket")
    [ -n "${FAIL_SOCKET_RESTART:-}" ] && exit 1
    touch "$S/ssh.socket.active"; exit 0 ;;
  "status "*) echo "stub status"; exit 0 ;;
esac
exit 0
"""


def _functions() -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    out = []
    for name in ("sync_socket_listen", "reload_sshd"):
        m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", text, re.S | re.M)
        assert m, f"{name} not found in the shipped script"
        out.append(m.group(0))
    return "\n".join(out)


def _run(
    tmp_path: Path,
    call: str,
    *,
    socket: bool,
    service: bool,
    env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    stub = bindir / "systemctl"
    stub.write_text(STUB, encoding="utf-8")
    stub.chmod(0o755)
    if socket:
        (state / "ssh.socket.active").touch()
    if service:
        (state / "ssh.service.active").touch()
    tmp_path.mkdir(parents=True, exist_ok=True)
    snippet = (
        f'SOCKET_DROPIN="{tmp_path}/ssh.socket.d/spatiumddi-listen.conf"\nSOCK_ARG=""\n'
        f"{_functions()}\n{call}\n"
    )
    proc = subprocess.run(
        ["bash", "-uo", "pipefail", "-c", snippet],
        capture_output=True,
        text=True,
        env={"PATH": f"{bindir}:/usr/bin:/bin", "STATE": str(state), **(env or {})},
        check=False,
    )
    return proc, state


def test_socket_activated_apply_leaves_the_service_active(tmp_path: Path) -> None:
    proc, state = _run(tmp_path, "reload_sshd; echo rc=$?", socket=True, service=True)
    assert "rc=0" in proc.stdout, proc.stdout + proc.stderr
    assert (state / "ssh.service.active").exists(), "ssh.service was left failed"
    assert (state / "ssh.socket.active").exists()
    calls = (state / "calls").read_text()
    assert "reload ssh.service" not in calls, "a reload re-execs sshd and dies under the socket"
    assert "restart ssh.service" in calls


def test_the_old_reload_would_have_failed_the_unit(tmp_path: Path) -> None:
    # Negative control: the stub really models the bug, so a passing test above
    # is not vacuous.
    proc, state = _run(tmp_path, "systemctl reload ssh.service", socket=True, service=True)
    assert proc.returncode == 0
    assert not (state / "ssh.service.active").exists()


def test_idle_socket_is_not_forced_to_start_sshd(tmp_path: Path) -> None:
    proc, state = _run(tmp_path, "reload_sshd; echo rc=$?", socket=True, service=False)
    assert "rc=0" in proc.stdout
    assert "restart ssh.service" not in (state / "calls").read_text()


def test_a_port_change_rebinds_the_socket(tmp_path: Path) -> None:
    proc, state = _run(tmp_path, "reload_sshd socket; echo rc=$?", socket=True, service=True)
    assert "rc=0" in proc.stdout
    calls = (state / "calls").read_text().splitlines()
    # daemon-reload first (the generator re-reads Port), socket before service.
    assert calls.index("daemon-reload") < calls.index("restart ssh.socket")
    assert calls.index("restart ssh.socket") < calls.index("restart ssh.service")


def test_without_socket_activation_a_reload_is_used_and_verified(tmp_path: Path) -> None:
    proc, state = _run(tmp_path, "reload_sshd; echo rc=$?", socket=False, service=True)
    assert "rc=0" in proc.stdout
    assert "reload ssh.service" in (state / "calls").read_text()
    assert (state / "ssh.service.active").exists()


@pytest.mark.parametrize(
    "env",
    [{"FAIL_SERVICE_RESTART": "1"}, {"FAIL_SOCKET_RESTART": "1"}],
)
def test_a_failed_apply_is_reported_not_swallowed(tmp_path: Path, env: dict[str, str]) -> None:
    arg = "socket" if "FAIL_SOCKET_RESTART" in env else ""
    proc, _ = _run(tmp_path, f"reload_sshd {arg}; echo rc=$?", socket=True, service=True, env=env)
    assert "rc=1" in proc.stdout, proc.stdout + proc.stderr


def test_a_changed_port_writes_the_socket_listen_drop_in(tmp_path: Path) -> None:
    proc, _ = _run(
        tmp_path, 'sync_socket_listen 2222; echo "arg=$SOCK_ARG"', socket=True, service=True
    )
    assert "arg=socket" in proc.stdout, proc.stdout + proc.stderr
    body = (tmp_path / "ssh.socket.d" / "spatiumddi-listen.conf").read_text()
    # ListenStream= resets the unit's own ListenStream=22 before adding ours.
    assert "ListenStream=\nListenStream=2222" in body


def test_an_unchanged_port_does_not_rebind_the_socket(tmp_path: Path) -> None:
    proc, _ = _run(
        tmp_path,
        'sync_socket_listen 2222; SOCK_ARG=""; sync_socket_listen 2222; echo "arg=[$SOCK_ARG]"',
        socket=True,
        service=True,
    )
    assert "arg=[]" in proc.stdout


def test_going_back_to_22_removes_the_drop_in_and_rebinds(tmp_path: Path) -> None:
    proc, _ = _run(
        tmp_path,
        'sync_socket_listen 2222; SOCK_ARG=""; sync_socket_listen 22; echo "arg=$SOCK_ARG"',
        socket=True,
        service=True,
    )
    assert "arg=socket" in proc.stdout
    assert not (tmp_path / "ssh.socket.d" / "spatiumddi-listen.conf").exists()


def test_callers_no_longer_swallow_the_result() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "reload_sshd || true" not in text, (
        "a failed sshd apply must fail the trigger so the hash sidecar stays unwritten"
    )
