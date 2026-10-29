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

Two follow-ups from the QA walk of PR #2378:

* case 5 — a config line net-snmp logs as an Error (it keeps running) must
  be rejected, and a config that passes the probe but will not START must be
  rolled back to the previous one, with snmpd back up on it;
* case 7 — the operator's enable link lives only in the /etc overlay upper,
  which PID 1 has not loaded at boot, so ``--boot`` (run by
  spatiumddi-optin-services-boot.service) must start snmpd / lldpd when their
  plane is on, and the status sidecar must report what is actually running.

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
#
# Config-line errors are modelled the way net-snmp 5.9.4 really behaves
# (#2376 case 5, verified in a Debian 13 container against a live snmpd on
# 161): it logs "<file>: line N: Error: ..." and KEEPS RUNNING, skipping the
# line.  An unknown token is a Warning, also non-fatal.  ``createUser bob
# SHA`` (no passphrase) segfaults the parser, modelled by CRASHME.
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
        BADDIRECTIVE*) echo "$conf: line $n: Error: Blank line following BADDIRECTIVE token.";;
        "view qa2378view included") echo "$conf: line $n: Error: missing SUBTREE parameter";;
        fooBarToken*) echo "$conf: line $n: Warning: Unknown token: fooBarToken.";;
        # no core file: it would land in the checkout the tests run from
        CRASHME*) ulimit -c 0; kill -SEGV $$;;
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

# Stateful systemctl: enable / active state per unit as marker files in
# $STUB_DIR, so a test can see what the runner left running.  A real start
# of snmpd fails when the INSTALLED config carries FAILSTART (start returns
# non-zero) or DIESTART (start returns 0, the daemon is gone 2 s later) —
# configs the probe passes but the real daemon will not run.  lldpd fails to
# start when $STUB_DIR/lldpd-fails exists.
SYSTEMCTL_STUB = r"""#!/bin/bash
echo "$*" >> "$STUB_DIR/systemctl.calls"
verb="$1"; shift
now=0; quiet=0; units=()
for a in "$@"; do
    case "$a" in
        --now) now=1;;
        --quiet|-q) quiet=1;;
        --*) ;;
        *) units+=("${a%.service}");;
    esac
done
start_unit() {
    u="$1"
    if [ "$u" = snmpd ] && [ -n "${STUB_ETC_CONF:-}" ] && [ -f "$STUB_ETC_CONF" ]; then
        if grep -q FAILSTART "$STUB_ETC_CONF"; then rm -f "$STUB_DIR/active-$u"; return 1; fi
        if grep -q DIESTART "$STUB_ETC_CONF"; then rm -f "$STUB_DIR/active-$u"; return 0; fi
    fi
    if [ "$u" = lldpd ] && [ -e "$STUB_DIR/lldpd-fails" ]; then rm -f "$STUB_DIR/active-$u"; return 1; fi
    touch "$STUB_DIR/active-$u"
}
rc=0
for u in "${units[@]}"; do
    case "$verb" in
        is-active) [ -e "$STUB_DIR/active-$u" ] || rc=3;;
        is-enabled) [ -e "$STUB_DIR/enabled-$u" ] || rc=1;;
        enable) touch "$STUB_DIR/enabled-$u"; [ "$now" = 1 ] && { start_unit "$u" || rc=1; };;
        disable) rm -f "$STUB_DIR/enabled-$u"; [ "$now" = 1 ] && rm -f "$STUB_DIR/active-$u";;
        start|restart) start_unit "$u" || rc=1;;
        stop) rm -f "$STUB_DIR/active-$u";;
        *) ;;
    esac
done
exit $rc
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


def run(host, marker="enabled", body="", holds=False, args=(), trigger=True):
    h = host
    if holds:
        (h["tmp"] / "held").write_text("")
    trig = h["root"] / "var/lib/spatiumddi/release-state/snmp-config-pending"
    if trigger:
        trig.write_text(f"{marker}\nabc123\n{body}")
    env = {
        "PATH": f"{h['stub']}:{os.environ.get('PATH', '/usr/bin:/bin')}",
        "STUB_DIR": str(h["stub"]),
        "STUB_ETC_CONF": str(h["root"] / "etc/snmp/snmpd.conf"),
        "HOST_HOLDS_161": str(h["tmp"] / "held"),
        "TMPDIR": str(h["tmp"]),
    }
    r = subprocess.run(["bash", str(h["script"]), *args], capture_output=True,
                       text=True, env=env, timeout=60)
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


# ---- case 5: a config the probe survives is not "parse OK" (#2376) -------
PREVIOUS = "# previous live config\nrocommunity old 10.0.0.0/24\n"


def _live(host, conf=PREVIOUS, usm="usmUser old\n", active=True, enabled=True):
    """A box already serving SNMP: config + USM state on disk, snmpd up."""
    (host["root"] / "etc/snmp/snmpd.conf").write_text(conf)
    (host["root"] / "var/lib/snmp/snmpd.conf").write_text(usm)
    (host["root"] / "var/lib/spatiumddi/release-state/snmp-config-hash").write_text("old\n")
    if active:
        (host["stub"] / "active-snmpd").write_text("")
    if enabled:
        (host["stub"] / "enabled-snmpd").write_text("")


def _calls(host):
    f = host["stub"] / "systemctl.calls"
    return f.read_text() if f.exists() else ""


def test_a_config_line_error_is_rejected_though_the_probe_stays_up(host):
    # QA's exact body: snmpd logs "line N: Error: missing SUBTREE parameter"
    # and keeps running, which the old check read as "parse OK".
    _live(host)
    r, state, log = run(host, body=RENDERED + "view qa2378view included\n", holds=True)
    assert r.returncode == 1, log
    assert "snmpd rejected the staged config" in log
    assert "missing SUBTREE parameter" in log
    assert "parse OK" not in log
    assert list(state.glob("snmp-config-pending.failed.*"))
    assert not (state / "snmp-config-pending").exists()
    # nothing touched: live config, USM state, the daemon, the hash
    assert (host["root"] / "etc/snmp/snmpd.conf").read_text() == PREVIOUS
    assert (host["root"] / "var/lib/snmp/snmpd.conf").read_text() == "usmUser old\n"
    assert (host["stub"] / "active-snmpd").exists()
    assert "stop" not in _calls(host)
    assert (state / "snmp-config-hash").read_text().strip() == "old"


def test_a_parser_crash_is_rejected(host):
    r, state, log = run(host, body=RENDERED + "CRASHME\n", holds=True)
    assert r.returncode == 1, log
    assert "crashed" in log
    assert list(state.glob("snmp-config-pending.failed.*"))


def test_an_unknown_token_warning_is_not_fatal(host):
    # net-snmp ignores an unknown token and serves the rest of the config.
    r, state, log = run(host, body=RENDERED + "fooBarToken 1\n", holds=True)
    assert r.returncode == 0, log
    assert "snmpd config parse OK" in log
    assert list(state.glob("snmp-config-pending.done.*"))


@pytest.mark.parametrize("marker", ["FAILSTART", "DIESTART"])
def test_a_failed_real_start_restores_the_previous_config(host, marker):
    _live(host)
    r, state, log = run(host, body=RENDERED + f"# {marker}\n", holds=False)
    assert r.returncode == 1, log
    assert "restoring the previous snmpd config" in log
    assert list(state.glob("snmp-config-pending.failed.*"))
    assert not (state / "snmp-config-pending").exists()
    assert (host["root"] / "etc/snmp/snmpd.conf").read_text() == PREVIOUS
    assert (host["root"] / "var/lib/snmp/snmpd.conf").read_text() == "usmUser old\n"
    # back up on the old config, and the status says so
    assert (host["stub"] / "active-snmpd").exists()
    assert (host["stub"] / "enabled-snmpd").exists()
    assert (state / "snmp-status").read_text().strip() == "running"
    assert (state / "snmp-config-hash").read_text().strip() == "old"


def test_a_failed_first_apply_leaves_snmpd_off_and_disabled(host):
    (host["root"] / "etc/snmp/snmpd.conf").write_text(PREVIOUS)
    r, state, log = run(host, body=RENDERED + "# FAILSTART\n")
    assert r.returncode == 1, log
    assert (host["root"] / "etc/snmp/snmpd.conf").read_text() == PREVIOUS
    assert not (host["stub"] / "active-snmpd").exists()
    assert not (host["stub"] / "enabled-snmpd").exists()
    assert (state / "snmp-status").read_text().strip() == "stopped"
    assert not (state / "snmp-config-hash").exists()


# ---- case 7: snmpd is started at boot when SNMP is on (#2376) -------------
def test_boot_starts_snmpd_when_snmp_is_on(host):
    # On disk after a reboot / slot upgrade: config, enable link (in the
    # overlay upper) and hash all present, but PID 1 never started snmpd.
    _live(host, active=False)
    state = host["root"] / "var/lib/spatiumddi/release-state"
    (state / "snmp-status").write_text("running\n")  # stale, from before the boot
    r, _, log = run(host, args=("--boot",), trigger=False)
    assert r.returncode == 0, log
    assert "start snmpd" in _calls(host)
    assert (host["stub"] / "active-snmpd").exists()
    assert (state / "snmp-status").read_text().strip() == "running"


def test_boot_re_enables_snmpd_whose_only_link_was_in_the_old_image(host):
    # Upgrade from a build whose image enabled snmpd: the operator's enable
    # was a no-op, so the new image dropping its link leaves snmpd disabled.
    _live(host, active=False, enabled=False)
    r, state, log = run(host, args=("--boot",), trigger=False)
    assert r.returncode == 0, log
    assert (host["stub"] / "enabled-snmpd").exists()
    assert (host["stub"] / "active-snmpd").exists()
    assert (state / "snmp-status").read_text().strip() == "running"


def test_boot_status_stops_saying_running_when_snmpd_will_not_start(host):
    _live(host, conf=PREVIOUS + "# FAILSTART\n", active=False)
    state = host["root"] / "var/lib/spatiumddi/release-state"
    (state / "snmp-status").write_text("running\n")
    r, _, log = run(host, args=("--boot",), trigger=False)
    assert r.returncode == 0, log
    assert (state / "snmp-status").read_text().strip() == "stopped"


def test_boot_leaves_snmpd_alone_when_snmp_is_off(host):
    state = host["root"] / "var/lib/spatiumddi/release-state"
    (state / "snmp-config-hash").write_text("")
    (state / "snmp-status").write_text("running\n")
    r, _, log = run(host, args=("--boot",), trigger=False)
    assert r.returncode == 0, log
    assert "start" not in _calls(host)
    assert "enable" not in _calls(host).replace("is-enabled", "")
    assert not (host["stub"] / "active-snmpd").exists()
    assert (state / "snmp-status").read_text().strip() == "stopped"


def test_boot_does_not_consume_a_pending_trigger(host):
    # --boot never applies: a pending trigger is the .path unit's to run.
    r, state, log = run(host, body=RENDERED, args=("--boot",))
    assert r.returncode == 0, log
    assert (state / "snmp-config-pending").exists()


# ---- image half ---------------------------------------------------------
def test_preset_keeps_snmpd_and_lldpd_off_by_default():
    lines = {ln.strip() for ln in PRESET.read_text().splitlines() if ln.strip() and not ln.startswith("#")}
    assert {"disable snmpd.service", "disable lldpd.service"} <= lines
    assert not any(ln.startswith("enable") for ln in lines)


def test_postinst_disables_snmpd_and_lldpd_not_just_one_symlink():
    src = POSTINST.read_text()
    assert 'disable "$svc.service"' in src
    assert "for svc in snmpd lldpd" in src


# ---- the boot unit + lldpd -----------------------------------------------
LLDP_RUNNER = REPO / "appliance/mkosi.extra/usr/local/bin/spatiumddi-lldp-reload"
BOOT_UNIT = REPO / "appliance/mkosi.extra/etc/systemd/system/spatiumddi-optin-services-boot.service"


def test_boot_unit_runs_both_runners_after_the_etc_overlay():
    unit = BOOT_UNIT.read_text()
    after = " ".join(ln.split("=", 1)[1] for ln in unit.splitlines() if ln.startswith("After="))
    assert "etc.mount" in after.split()
    assert "Requires=etc.mount" in unit
    execs = [ln.split("=", 1)[1] for ln in unit.splitlines() if ln.startswith("ExecStart=")]
    assert execs == ["-/usr/local/bin/spatiumddi-snmp-reload --boot",
                     "-/usr/local/bin/spatiumddi-lldp-reload --boot"]
    assert "WantedBy=multi-user.target" in unit
    src = POSTINST.read_text()
    assert "spatiumddi-optin-services-boot.service \\" in src  # in the enable loop
    assert 'chmod 0644 "$BUILDROOT/etc/systemd/system/spatiumddi-optin-services-boot.service"' in src


@pytest.fixture
def lldp_host(tmp_path):
    root = tmp_path / "root"
    for d in ("var/lib/spatiumddi/release-state", "var/log/spatiumddi", "etc/lldpd.d",
              "etc/default"):
        (root / d).mkdir(parents=True)
    stub = tmp_path / "stubs"
    stub.mkdir()
    for name, body in (("systemctl", SYSTEMCTL_STUB), ("lldpd", "#!/bin/bash\nexit 0\n"),
                       ("lldpcli", "#!/bin/bash\nexit 0\n")):
        p = stub / name
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    src = LLDP_RUNNER.read_text()
    for a, b in (
        ("TRIGGER=/var/lib", f"TRIGGER={root}/var/lib"),
        ("HASH_SIDECAR=/var/lib", f"HASH_SIDECAR={root}/var/lib"),
        ("STATUS_SIDECAR=/var/lib", f"STATUS_SIDECAR={root}/var/lib"),
        ("LOG_DIR=/var/log/spatiumddi", f"LOG_DIR={root}/var/log/spatiumddi"),
        ("ETC_CONF=/etc/lldpd.d", f"ETC_CONF={root}/etc/lldpd.d"),
        ("ETC_DEFAULT=/etc/default", f"ETC_DEFAULT={root}/etc/default"),
        ("LOCK=/run/", f"LOCK={tmp_path}/"),
    ):
        assert a in src, a
        src = src.replace(a, b)
    script = tmp_path / "lldp.sh"
    script.write_text(src)
    state = root / "var/lib/spatiumddi/release-state"

    def run_boot():
        env = {"PATH": f"{stub}:{os.environ.get('PATH', '/usr/bin:/bin')}",
               "STUB_DIR": str(stub), "TMPDIR": str(tmp_path)}
        r = subprocess.run(["bash", str(script), "--boot"], capture_output=True,
                           text=True, env=env, timeout=60)
        log = (root / "var/log/spatiumddi/lldp-reload.log").read_text()
        return r, log

    return {"stub": stub, "state": state, "run": run_boot}


def test_boot_starts_lldpd_when_lldp_is_on(lldp_host):
    h = lldp_host
    (h["state"] / "lldp-config-hash").write_text("abc\n")
    (h["state"] / "lldp-status").write_text("running\n")
    (h["stub"] / "enabled-lldpd").write_text("")
    r, log = h["run"]()
    assert r.returncode == 0, log
    assert (h["stub"] / "active-lldpd").exists()
    assert (h["state"] / "lldp-status").read_text().strip() == "running"


def test_boot_lldp_status_says_stopped_when_lldpd_will_not_start(lldp_host):
    h = lldp_host
    (h["state"] / "lldp-config-hash").write_text("abc\n")
    (h["state"] / "lldp-status").write_text("running\n")
    (h["stub"] / "lldpd-fails").write_text("")
    r, log = h["run"]()
    assert r.returncode == 0, log
    assert (h["state"] / "lldp-status").read_text().strip() == "stopped"


def test_boot_leaves_lldpd_alone_when_lldp_is_off(lldp_host):
    h = lldp_host
    r, log = h["run"]()
    assert r.returncode == 0, log
    assert not (h["stub"] / "active-lldpd").exists()
