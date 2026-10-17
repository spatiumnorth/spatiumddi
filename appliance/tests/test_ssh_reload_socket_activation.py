"""spatiumddi-ssh-reload must not leave ssh.service failed (#1632).

The appliance image enables both ``ssh.socket`` and ``ssh.service``, so sshd
runs socket-activated: the socket holds the port and hands the fd to
``ssh.service``.  A ``systemctl reload ssh.service`` sends SIGHUP, sshd
re-execs itself, cannot bind the port the socket owns and dies, while the
reload command itself exits 0 -- so the runner logged success over a failed
unit.

These tests extract the apply functions from the shipped script and run them
under **bash** against a stub ``systemctl`` that models the systemd behaviour
verified on Debian trixie (systemd 257, openssh-server 1:10.0p1-7+deb13u4):

- a reload under an active socket leaves the service dead, exit 0;
- systemd REFUSES to (re)start an ``Accept=no`` socket while its service is
  active ("Socket service ssh.service already active, refusing").

They assert on the unit state the stub ends in -- never on the exit code of
the action.

HOW TO RUN: python3 -m pytest appliance/tests/test_ssh_reload_socket_activation.py -v
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

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
if [ "${1:-}" = "is-active" ]; then
  shift; [ "${1:-}" = "--quiet" ] && shift; [ -f "$S/$1.active" ]; exit $?
fi
case "$1 ${2:-}" in
  "daemon-reload "*) exit 0 ;;
  "cat ssh.socket") exit 0 ;;
  "reload ssh.service")
    # sshd re-execs on SIGHUP; under socket activation it cannot bind and dies,
    # but ExecReload (sshd -t; kill -HUP) has already exited 0.
    if [ -f "$S/ssh.socket.active" ]; then rm -f "$S/ssh.service.active"; fi
    exit 0 ;;
  "stop ssh.service") rm -f "$S/ssh.service.active"; exit 0 ;;
  "start ssh.service"|"restart ssh.service")
    [ -n "${FAIL_SERVICE_RESTART:-}" ] && { rm -f "$S/ssh.service.active"; exit 1; }
    touch "$S/ssh.service.active"; exit 0 ;;
  "restart ssh.socket")
    rm -f "$S/ssh.socket.active"
    # systemd refuses to start an Accept=no socket while its service runs.
    [ -f "$S/ssh.service.active" ] && exit 1
    if [ -n "${FAIL_SOCKET_RESTART_ONCE:-}" ] && [ ! -f "$S/socket-failed-once" ]; then
      touch "$S/socket-failed-once"; exit 1
    fi
    touch "$S/ssh.socket.active"; exit 0 ;;
  "reload nftables.service") echo reloaded >> "$S/nft-reloads"; exit 0 ;;
  "status "*) echo "stub status"; exit 0 ;;
esac
exit 0
"""

FUNCTIONS = (
    "sync_socket_listen",
    "restore_socket_listen",
    "active_after_settle",
    "reload_sshd",
    "restore_nft_fragment",
)


def _functions() -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    out = []
    for name in FUNCTIONS:
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
    # The shipped script runs under `set -euo pipefail`; so do the tests.
    snippet = (
        f'SOCKET_DROPIN="{tmp_path}/ssh.socket.d/spatiumddi-listen.conf"\n'
        f'NFT_DROPIN="{tmp_path}/50-spatium-ssh.nft"\n'
        'SOCK_ARG=""\nSOCK_PREV_EXISTS=0\nSOCK_PREV_CONTENT=""\nSOCK_ROLLED_BACK=0\n'
        'NFT_PREV_EXISTS=0\nNFT_PREV_CONTENT=""\n'
        f"{_functions()}\n{call}\n"
    )
    proc = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", snippet],
        capture_output=True,
        text=True,
        env={
            "PATH": f"{bindir}:/usr/bin:/bin",
            "STATE": str(state),
            "SSH_SETTLE_SECONDS": "0",
            **(env or {}),
        },
        check=False,
    )
    return proc, state


def _calls(state: Path) -> list[str]:
    return (state / "calls").read_text().splitlines()


def test_socket_activated_apply_leaves_the_service_active(tmp_path: Path) -> None:
    proc, state = _run(tmp_path, "reload_sshd && echo rc=0", socket=True, service=True)
    assert "rc=0" in proc.stdout, proc.stdout + proc.stderr
    assert (state / "ssh.service.active").exists(), "ssh.service was left failed"
    assert (state / "ssh.socket.active").exists()
    calls = _calls(state)
    assert "reload ssh.service" not in calls, "a reload re-execs sshd and dies under the socket"
    assert "restart ssh.service" in calls


def test_the_old_reload_would_have_failed_the_unit(tmp_path: Path) -> None:
    # Negative control: the stub really models the bug, so a passing test above
    # is not vacuous.
    proc, state = _run(tmp_path, "systemctl reload ssh.service", socket=True, service=True)
    assert proc.returncode == 0
    assert not (state / "ssh.service.active").exists()


def test_a_service_an_earlier_reload_left_failed_is_started(tmp_path: Path) -> None:
    # A node upgraded from a build with the bug can carry ssh.service failed;
    # the next apply must clear it, not leave it for the next connection.
    proc, state = _run(tmp_path, "reload_sshd && echo rc=0", socket=True, service=False)
    assert "rc=0" in proc.stdout, proc.stdout + proc.stderr
    assert (state / "ssh.service.active").exists()


def test_a_port_change_stops_the_service_before_rebinding_the_socket(tmp_path: Path) -> None:
    proc, state = _run(tmp_path, "reload_sshd socket && echo rc=0", socket=True, service=True)
    assert "rc=0" in proc.stdout, proc.stdout + proc.stderr
    calls = _calls(state)
    # systemd refuses to start the socket while its service is active, so the
    # stop must come first; the stub fails the restart otherwise.
    assert calls.index("daemon-reload") < calls.index("stop ssh.service")
    assert calls.index("stop ssh.service") < calls.index("restart ssh.socket")
    assert calls.index("restart ssh.socket") < calls.index("restart ssh.service")
    assert (state / "ssh.socket.active").exists()
    assert (state / "ssh.service.active").exists()


def test_a_socket_that_cannot_bind_the_new_port_is_put_back(tmp_path: Path) -> None:
    proc, state = _run(
        tmp_path,
        'sync_socket_listen 2222; SOCK_ARG=""; sync_socket_listen 2223; '
        'reload_sshd "$SOCK_ARG" || echo "rc=1 rolled=$SOCK_ROLLED_BACK"',
        socket=True,
        service=True,
        env={"FAIL_SOCKET_RESTART_ONCE": "1"},
    )
    assert "rc=1 rolled=1" in proc.stdout, proc.stdout + proc.stderr
    body = (tmp_path / "ssh.socket.d" / "spatiumddi-listen.conf").read_text()
    assert "ListenStream=2222" in body and "2223" not in body
    assert (state / "ssh.socket.active").exists(), "socket left down after rollback"
    assert (state / "ssh.service.active").exists(), "sshd left down after rollback"


def test_rolling_back_to_no_drop_in_removes_it(tmp_path: Path) -> None:
    proc, _ = _run(
        tmp_path,
        'sync_socket_listen 2222; reload_sshd "$SOCK_ARG" || echo "rc=1 rolled=$SOCK_ROLLED_BACK"',
        socket=True,
        service=True,
        env={"FAIL_SOCKET_RESTART_ONCE": "1"},
    )
    assert "rc=1 rolled=1" in proc.stdout, proc.stdout + proc.stderr
    assert not (tmp_path / "ssh.socket.d" / "spatiumddi-listen.conf").exists()


def test_an_inactive_socket_is_not_used_to_switch_models(tmp_path: Path) -> None:
    proc, state = _run(tmp_path, "reload_sshd socket && echo rc=0", socket=False, service=True)
    assert "rc=0" in proc.stdout, proc.stdout + proc.stderr
    calls = _calls(state)
    assert "restart ssh.socket" not in calls
    assert "reload ssh.service" in calls
    assert (state / "ssh.service.active").exists()


def test_a_failed_apply_is_reported_not_swallowed(tmp_path: Path) -> None:
    proc, _ = _run(
        tmp_path,
        "reload_sshd || echo rc=1",
        socket=True,
        service=True,
        env={"FAIL_SERVICE_RESTART": "1"},
    )
    assert "rc=1" in proc.stdout, proc.stdout + proc.stderr


def test_a_reload_that_kills_sshd_is_caught_after_the_settle(tmp_path: Path) -> None:
    # The reload path must judge by the unit state, not by `systemctl reload`'s
    # exit code. Model a host whose socket is NOT active per the precheck but
    # whose reload still leaves sshd dead.
    proc, state = _run(
        tmp_path,
        'systemctl() { if [ "$1" = reload ]; then rm -f "$STATE/ssh.service.active"; return 0; fi; '
        'command systemctl "$@"; }; reload_sshd || echo rc=1',
        socket=False,
        service=True,
    )
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


def test_restore_nft_fragment_puts_the_previous_rule_back(tmp_path: Path) -> None:
    proc, state = _run(
        tmp_path,
        'NFT_PREV_EXISTS=1; NFT_PREV_CONTENT="tcp dport 2222 accept"; '
        'echo "tcp dport 2223 accept" > "$NFT_DROPIN"; restore_nft_fragment',
        socket=True,
        service=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert (tmp_path / "50-spatium-ssh.nft").read_text() == "tcp dport 2222 accept\n"
    assert (state / "nft-reloads").exists()


def test_restore_nft_fragment_removes_a_fragment_that_did_not_exist(tmp_path: Path) -> None:
    proc, _ = _run(
        tmp_path,
        'echo "tcp dport 2223 accept" > "$NFT_DROPIN"; restore_nft_fragment',
        socket=True,
        service=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert not (tmp_path / "50-spatium-ssh.nft").exists()


def test_callers_no_longer_swallow_the_result() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "reload_sshd || true" not in text, (
        "a failed sshd apply must fail the trigger so the hash sidecar stays unwritten"
    )
    # Both callers put the firewall back when the socket went back.
    assert text.count('[ "$SOCK_ROLLED_BACK" = 1 ] && restore_nft_fragment') == 2


def test_the_listener_moves_only_after_the_firewall_loaded() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    enabled = text[text.index("    enabled)") : text.index("    disabled)")]
    nft_gate = enabled.index("if ! nft_reload; then")
    assert nft_gate < enabled.index('install -o root -g root -m 0644 "$SSHD_TMP" "$SSHD_DROPIN"')
    assert nft_gate < enabled.index('sync_socket_listen "$PORT"')


# --- #2054: validation must work while ssh.service is down -----------------

SSHD_STUB = r"""#!/bin/bash
# Models sshd -t: needs the privsep dir, then rejects a config with BadDirective.
[ -d "$SSHD_PRIVSEP_DIR" ] || { echo "Missing privilege separation directory: $SSHD_PRIVSEP_DIR" >&2; exit 255; }
if grep -q BadDirective "$3"; then echo "bad config" >&2; exit 255; fi
exit 0
"""


def _validate(tmp_path: Path, body: str) -> tuple[subprocess.CompletedProcess[str], Path]:
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    sshd = bindir / "sshd"
    sshd.write_text(SSHD_STUB, encoding="utf-8")
    sshd.chmod(0o755)
    conf = tmp_path / "test.conf"
    conf.write_text(body, encoding="utf-8")
    privsep = tmp_path / "run-sshd"  # absent: ssh.service is failed
    text = SCRIPT.read_text(encoding="utf-8")
    m = re.search(r"^validate_sshd_config\(\) \{\n.*?^\}\n", text, re.S | re.M)
    assert m, "validate_sshd_config not found in the shipped script"
    proc = subprocess.run(
        [
            "bash",
            "-euo",
            "pipefail",
            "-c",
            f'{m.group(0)}\nif validate_sshd_config "{conf}" "{tmp_path}/v.log"; '
            "then echo VALID; else echo INVALID; fi",
        ],
        capture_output=True,
        text=True,
        env={
            "PATH": f"{bindir}:/usr/bin:/bin",
            "SSHD_PRIVSEP_DIR": str(privsep),
        },
        check=False,
    )
    return proc, privsep


def test_validation_works_while_the_privsep_dir_is_absent(tmp_path: Path) -> None:
    proc, privsep = _validate(tmp_path, "Port 22\n")
    assert "VALID" in proc.stdout.split(), proc.stdout + proc.stderr
    assert privsep.is_dir()
    assert oct(privsep.stat().st_mode & 0o777) == "0o755"


def test_invalid_config_is_still_refused_without_the_privsep_dir(tmp_path: Path) -> None:
    proc, _ = _validate(tmp_path, "BadDirective yes\n")
    assert proc.stdout.split() == ["INVALID"], proc.stdout + proc.stderr


def test_the_runner_validates_through_the_helper() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'validate_sshd_config "$TEST_CONF"' in text
    assert len(re.findall(r"^\s*(?:if ! )?sshd -t", text, re.M)) == 1  # the helper's own
