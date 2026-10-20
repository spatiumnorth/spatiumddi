"""``spatiumddi-snmp-reload``'s config probe must not take the live AgentX socket (#2154).

Since #2154 the rendered ``snmpd.conf`` makes snmpd an AgentX **master** on
``/run/agentx/master`` — that is what lets ``lldpd -x`` register LLDP-MIB.
The runner validates a staged config by foreground-starting a second snmpd
against it (net-snmp has no config-test flag, #550).  Started against the
staged file as-is, that probe would be a second master on the SAME path: a
master unlinks and rebinds its socket on start, so the probe steals the
live daemon's socket — and lldpd's registration with it — and, when the
runner kills it, leaves the path pointing at nothing.  A successful apply
restarts snmpd straight after and recreates the socket, but an apply whose
staged config is REJECTED exits with the old snmpd still running and its
socket gone: LLDP-MIB stays dark until something next restarts snmpd.

These tests run the runner's real probe block (extracted from the shipped
script) under bash with a stub ``snmpd`` on ``PATH`` that records the config
it was handed, and — when a real ``snmpd`` is installed (Debian:
``apt-get install snmpd``) — once more against the real daemon, proving the
AgentX directives parse and that the live socket path is left alone.

HOW TO RUN:
    python3 -m pytest appliance/tests/test_snmp_agentx_probe.py -v

No database, no appliance ISO, no root required.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

RUNNER = (
    Path(__file__).parent.parent
    / "mkosi.extra"
    / "usr"
    / "local"
    / "bin"
    / "spatiumddi-snmp-reload"
)

LIVE_SOCKET = "/run/agentx/master"

# The AgentX block ``backend/app/services/appliance/snmp.py`` renders
# (pinned there by ``test_renders_agentx_master_for_subagents``).  The
# appliance suite cannot import the backend, so it is restated here; the
# assertions below only depend on ``agentXSocket`` being a line of its own.
RENDERED = f"""\
# Managed by SpatiumDDI — edits will be overwritten on next config push.
agentAddress udp:161,udp6:[::1]:161

view all included .1

# AgentX master — lets local subagents (lldpd -x → LLDP-MIB) register.
master agentx
agentXSocket {LIVE_SOCKET}
agentXPerms 0600 0700

rocommunity public 127.0.0.1
"""


def _probe_block() -> str:
    """The runner's probe, from the validate-log assignment through the
    background ``snmpd`` launch — the bytes that ship."""
    lines = RUNNER.read_text(encoding="utf-8").splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.strip().startswith("SNMP_VALIDATE_LOG="))
    end = next(i for i in range(start, len(lines)) if lines[i].strip() == "probe_pid=$!")
    return "\n".join(ln.strip() for ln in lines[start : end + 1])


def _run(tmp_path: Path, path_prefix: str, rendered: str) -> subprocess.CompletedProcess[str]:
    body = tmp_path / "staged.conf"
    body.write_text(rendered, encoding="utf-8")
    log = tmp_path / "validate.log"
    snippet = (
        _probe_block().replace("/tmp/spatium-snmpd-validate.log", str(log))
        + "\nsleep 1\n"
        + 'if kill -0 "$probe_pid" 2>/dev/null; then echo PROBE_ALIVE; fi\n'
        + 'kill "$probe_pid" 2>/dev/null || true\nwait "$probe_pid" 2>/dev/null || true\n'
    )
    return subprocess.run(
        ["bash", "-euo", "pipefail", "-c", snippet],
        capture_output=True,
        text=True,
        env={
            "PATH": f"{path_prefix}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "TMP_BODY": str(body),
            "TMPDIR": str(tmp_path),
        },
        timeout=30,
    )


def test_probe_is_pointed_at_a_throwaway_agentx_socket(tmp_path: Path) -> None:
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    seen = tmp_path / "probe-config.conf"
    (stub_dir / "snmpd").write_text(
        "#!/bin/bash\n"
        "# stub: copy the -c config the probe was handed, then exit\n"
        'while [ $# -gt 0 ]; do [ "$1" = -c ] && cp "$2" ' + str(seen) + "; shift; done\n",
        encoding="utf-8",
    )
    (stub_dir / "snmpd").chmod(0o755)

    res = _run(tmp_path, str(stub_dir), RENDERED)
    assert res.returncode == 0, res.stderr
    assert seen.exists(), "the probe never started snmpd with a -c config"

    probed = seen.read_text(encoding="utf-8").splitlines()
    sockets = [ln for ln in probed if ln.startswith("agentXSocket ")]
    assert len(sockets) == 1, probed
    # Not the live path — that is the whole point.
    assert sockets[0] != f"agentXSocket {LIVE_SOCKET}", sockets
    # ...but the AgentX directives are still in what gets parsed.
    assert "master agentx" in probed
    assert "agentXPerms 0600 0700" in probed
    # Everything else is untouched.
    other = [ln for ln in probed if not ln.startswith("agentXSocket ")]
    assert other == [ln for ln in RENDERED.splitlines() if not ln.startswith("agentXSocket ")]


def test_probe_never_reads_the_staged_file_directly() -> None:
    """Structural: the probe's ``-c`` must be the rewritten copy."""
    block = _probe_block()
    launch = [ln for ln in block.splitlines() if ln.startswith("snmpd ")]
    assert launch and all('-c "$PROBE_BODY"' in ln for ln in launch), launch


@pytest.mark.skipif(shutil.which("snmpd") is None, reason="needs a real net-snmp snmpd")
def test_real_snmpd_parses_the_agentx_block_without_touching_the_live_socket(
    tmp_path: Path,
) -> None:
    """With the real daemon: the probe stays up (= the config parsed) and the
    live socket path — here a stand-in under tmp — is left exactly as it was."""
    live_dir = tmp_path / "live-agentx"
    live_dir.mkdir()
    live = live_dir / "master"
    live.write_text("live snmpd's socket stands here", encoding="utf-8")
    rendered = RENDERED.replace(LIVE_SOCKET, str(live))

    res = _run(tmp_path, "", rendered)
    assert res.returncode == 0, res.stderr
    log = (tmp_path / "validate.log").read_text(encoding="utf-8", errors="replace")
    # Still running after a second = the runner's "config parse OK" verdict.
    assert "PROBE_ALIVE" in res.stdout, log
    assert live.read_text(encoding="utf-8") == "live snmpd's socket stands here"
