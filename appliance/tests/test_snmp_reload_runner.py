"""``spatiumddi-snmp-reload`` — config check vs a snmpd already on UDP 161 (#2376).

These tests EXECUTE the shipped runner against stubbed host tooling.  The
stub ``snmpd`` models the one net-snmp behaviour that mattered (verified
against net-snmp 5.9.4 on Debian 13): it opens EVERY ``agentAddress`` in the
config it is given, in addition to the command-line transport, and exits 1
with ``Error opening specified endpoint "udp:161"`` when something already
holds it.  The image's own snmpd held 161 from boot, so the old check
(which kept the staged ``agentAddress udp:161``) rejected every valid config.

Also pins the image half: snmpd / lldpd must be disabled by preset and by
the postinst, so nothing holds 161 before SNMP is configured.

HOW TO RUN:  python3 -m pytest appliance/tests/test_snmp_reload_runner.py -v
No database, Docker, ISO or root required.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
RUNNER = REPO / "appliance/mkosi.extra/usr/local/bin/spatiumddi-snmp-reload"
POSTINST = REPO / "appliance/mkosi.postinst"
PRESET = REPO / "appliance/mkosi.extra/usr/lib/systemd/system-preset/00-spatiumddi.preset"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")

# Stub net-snmp.  ``$HOST_HOLDS_161`` names a file whose presence means "some
# other snmpd is bound to UDP 161 / the default AgentX socket".
SNMPD_STUB = r"""#!/bin/bash
conf=""
while [ $# -gt 0 ]; do
    case "$1" in
        -c) conf="$2"; shift 2;;
        -Lf) shift 2;;
        *) shift;;
    esac
done
echo "$conf" >> "$STUB_DIR/snmpd-probe-confs"
cp "$conf" "$STUB_DIR/snmpd-probe-conf-copy"
n=0
while IFS= read -r line; do
    n=$((n+1))
    case "$line" in
        BADDIRECTIVE*) echo "$conf: line $n: Error: Blank line following token."; exit 1;;
    esac
done < "$conf"
held=0
[ -e "$HOST_HOLDS_161" ] && held=1
if [ "$held" = 1 ]; then
    if grep -qiE '^[[:space:]]*agentaddress[[:space:]].*161' "$conf"; then
        echo 'Error opening specified endpoint "udp:161"'
        echo 'Server Exiting with code 1'
        exit 1
    fi
    if grep -qiE '^[[:space:]]*master[[:space:]]+agentx' "$conf" \
        && ! grep -qiE '^[[:space:]]*agentxsocket' "$conf"; then
        echo 'Error opening specified endpoint "/var/agentx/master"'
        exit 1
    fi
fi
exec sleep 30
"""

SYSTEMCTL_STUB = r"""#!/bin/bash
echo "$*" >> "$STUB_DIR/systemctl.calls"
case "$1" in
    is-active) exit 0;;
esac
exit 0
"""


@pytest.fixture
def host(tmp_path):
    root = tmp_path / "root"
    for d in ("var/lib/spatiumddi/release-state", "var/log/spatiumddi", "etc/snmp",
              "etc/nftables.d", "var/lib/snmp"):
        (root / d).mkdir(parents=True)
    stub = tmp_path / "stubs"
    stub.mkdir()
    # The runner sets root ownership on what it installs. CI runs these tests
    # unprivileged, so ownership changes are stubbed: chown is a no-op and
    # install drops its -o/-g arguments before calling the real install.
    install_stub = (
        "#!/bin/bash\nargs=()\nwhile [ $# -gt 0 ]; do\n"
        '  case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac\n'
        'done\nexec /usr/bin/install "${args[@]}"\n'
    )
    for name, body in (("snmpd", SNMPD_STUB), ("systemctl", SYSTEMCTL_STUB),
                       ("nft", "#!/bin/bash\nexit 0\n"),
                       ("chown", "#!/bin/bash\nexit 0\n"),
                       ("install", install_stub)):
        p = stub / name
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    src = RUNNER.read_text()
    for a, b in (
        ("TRIGGER=/var/lib", f"TRIGGER={root}/var/lib"),
        ("HASH_SIDECAR=/var/lib", f"HASH_SIDECAR={root}/var/lib"),
        ("STATUS_SIDECAR=/var/lib", f"STATUS_SIDECAR={root}/var/lib"),
        ("LOG_DIR=/var/log/spatiumddi", f"LOG_DIR={root}/var/log/spatiumddi"),
        ("ETC_CONF=/etc/snmp", f"ETC_CONF={root}/etc/snmp"),
        ("USM_STATE=/var/lib", f"USM_STATE={root}/var/lib"),
        ("LOCK=/run/", f"LOCK={tmp_path}/"),
        ("NFT_DROPIN=/etc/nftables.d", f"NFT_DROPIN={root}/etc/nftables.d"),
        ("SNMP_VALIDATE_LOG=/tmp/", f"SNMP_VALIDATE_LOG={tmp_path}/"),
    ):
        assert a in src, a
        src = src.replace(a, b)
    script = tmp_path / "runner.sh"
    script.write_text(src)
    return {"root": root, "stub": stub, "script": script, "tmp": tmp_path}


def run(host, marker="enabled", body="", holds=False):
    h = host
    if holds:
        (h["tmp"] / "held").write_text("")
    trig = h["root"] / "var/lib/spatiumddi/release-state/snmp-config-pending"
    trig.write_text(f"{marker}\nabc123\n{body}")
    env = {
        "PATH": f"{h['stub']}:{os.environ.get('PATH', '/usr/bin:/bin')}",
        "STUB_DIR": str(h["stub"]),
        "HOST_HOLDS_161": str(h["tmp"] / "held"),
        "TMPDIR": str(h["tmp"]),
    }
    r = subprocess.run(["bash", str(h["script"])], capture_output=True, text=True,
                       env=env, timeout=60)
    state = h["root"] / "var/lib/spatiumddi/release-state"
    log = (h["root"] / "var/log/spatiumddi/snmp-reload.log").read_text()
    return r, state, log


RENDERED = (
    "sysContact     \"ops\"\n"
    "agentAddress udp:161,udp6:[::1]:161\n"
    "master agentx\n"
    "view all included .1\n"
    "rocommunity public 10.0.0.0/24 -V all\n"
)


def test_valid_config_is_accepted_while_another_snmpd_holds_161(host):
    r, state, log = run(host, body=RENDERED, holds=True)
    assert r.returncode == 0, log
    assert "snmpd config parse OK" in log
    assert "rejected" not in log
    assert list(state.glob("snmp-config-pending.done.*")), log
    assert not list(state.glob("snmp-config-pending.failed.*"))
    assert (state / "snmp-config-hash").read_text().strip() == "abc123"
    # the live config is the full render, listeners included
    assert "agentAddress udp:161" in (host["root"] / "etc/snmp/snmpd.conf").read_text()


def test_probe_copy_has_no_listener_or_default_agentx_socket(host):
    run(host, body=RENDERED, holds=True)
    probe = (host["stub"] / "snmpd-probe-conf-copy").read_text()
    assert "agentAddress" not in probe
    assert "udp:161" not in probe
    # config the operator wrote is still what gets parsed
    assert "rocommunity public 10.0.0.0/24 -V all" in probe
    assert "/var/agentx/master" not in probe


def test_a_genuinely_bad_config_is_still_rejected(host):
    r, state, log = run(host, body=RENDERED + "BADDIRECTIVE\n", holds=True)
    assert r.returncode == 1
    assert "snmpd rejected the staged config" in log
    assert list(state.glob("snmp-config-pending.failed.*"))  # trigger consumed
    assert not (state / "snmp-config-pending").exists()
    assert not (host["root"] / "var/lib/spatiumddi/release-state/snmp-config-hash").exists()


def test_valid_config_on_a_quiet_host(host):
    r, state, log = run(host, body=RENDERED)
    assert r.returncode == 0, log
    assert "enable --now snmpd" in (host["stub"] / "systemctl.calls").read_text()


def test_disabled_stops_and_disables_snmpd(host):
    r, state, log = run(host, marker="disabled")
    assert r.returncode == 0, log
    assert "disable --now snmpd" in (host["stub"] / "systemctl.calls").read_text()
    assert (state / "snmp-status").read_text().strip() == "stopped"


# ---- image half ---------------------------------------------------------
def test_preset_keeps_snmpd_and_lldpd_off_by_default():
    lines = {ln.strip() for ln in PRESET.read_text().splitlines() if ln.strip() and not ln.startswith("#")}
    assert {"disable snmpd.service", "disable lldpd.service"} <= lines
    assert not any(ln.startswith("enable") for ln in lines)


def test_postinst_disables_snmpd_and_lldpd_not_just_one_symlink():
    src = POSTINST.read_text()
    assert 'disable "$svc.service"' in src
    assert "for svc in snmpd lldpd" in src
