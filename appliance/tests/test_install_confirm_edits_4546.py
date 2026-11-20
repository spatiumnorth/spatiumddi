"""Confirm-menu edits re-run what depends on them, and the input checks (#4546).

A walk through ``spatium-install`` found that the Confirm menu and several
input checks let an install proceed with answers that cannot work:

* a jump from Confirm returned to Confirm as soon as that ONE screen was
  answered, so First node -> Confirm -> Role -> Additional node -> Install
  reached ``do_install`` with no control-plane URL and no pairing code, and a
  later static network overlapping the k3s pod CIDR was never re-checked;
* the static network check accepted a network / broadcast address, loopback,
  multicast, a gateway equal to the host, and an empty resolver list, and
  refused a dotted netmask;
* the control-plane URL was only checked for "not empty";
* Keep /var and STATE ignored what it keeps;
* a handful of smaller screens (Done address, keyboard, SSH keys, Review,
  partition layout).

Every test here DRIVES the real function with stubbed whiptail / lsblk /
ip, because the failures are runtime decisions: which screen runs next,
which row is the default, what is refused. The functions are sliced out of
the script (it ends in ``main "$@"`` and cannot be sourced).

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_install_confirm_edits_4546.py -v
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from _installer_source import PARSER, SRC, extract_fn


@pytest.fixture(autouse=True)
def _needs_bash():
    if not shutil.which("bash"):
        pytest.skip("bash not available")


# Globals every function below reads. Defaults mirror the script's own.
PRELUDE = r"""
set -uo pipefail
log() { echo "LOG: $*" >> "${TRACEF:-/dev/null}"; }
INSTALL_LOG=/dev/null
MAINPID=$$
# The script traces with set -x to fd 19 (BASH_XTRACEFD); a screen that turns
# tracing back on must not write into the value a caller captures from stderr.
exec 19>/dev/null
BASH_XTRACEFD=19
BACKTITLE=t
ROLE=control-plane
CONTROL_PLANE_URL=""
BOOTSTRAP_PAIRING_CODE=""
TARGET_DISK=/dev/sda
TARGET_DISK2=""
TARGET_DISK_BY_ID=""
MIRROR_MODE=no
KEEP_VAR=no
TARGET_ARCH=amd64
HOSTNAME=h1
ADMIN_USER=admin
ADMIN_PASSWORD=""
NET_MODE=dhcp
NET_INTERFACE=""
NET_IP=""
NET_PREFIX=24
NET_GATEWAY=""
NET_DNS="1.1.1.1 1.0.0.1"
NET6_MODE=auto
NET6_IP=""
NET6_PREFIX=64
NET6_GATEWAY=""
NET_MTU=""
TIMEZONE=UTC
FIRMWARE_MODE=uefi
KEYMAP=us
NTP_SERVERS=pool.ntp.org
SSH_AUTHORIZED_KEYS=""
SSH_DISABLE_PASSWORD=no
SET_ROOT_PASSWORD=no
K3S_POD_CIDR=10.42.0.0/16
K3S_SERVICE_CIDR=10.43.0.0/16
CONFIRM_JUMP=""
CONFIRM_DEPS=()
CONFIRM_EDITING=""
FULLY_UNATTENDED=0
PRESEED_HAS_DISK=""
KEPT_ROLE=""; KEPT_POD_CIDR=""; KEPT_SVC_CIDR=""; KEPT_HOSTNAME=""
KEPT_ADMIN_USER=""; KEPT_TIMEZONE=""; KEPT_CONTROL_URL=""; KEPT_NET_MODE=""
KEPT_NET_INTERFACE=""; KEPT_NET_IP=""; KEPT_NET_PREFIX=""; KEPT_NET_GATEWAY=""
KEPT_NET_DNS=""
_dhcp_lease_subnet() { printf '%s' "${LEASE_SUBNET:-192.168.1.0/24}"; }
_preseed_parser_path() { printf '%s' "__PARSER__"; }
"""

#: Scripted whiptail. Each call is matched by its --title and answered from a
#: per-title queue of ``rc|output`` entries (the queue lives in files: the
#: caller captures the call in ``$( )``, a subshell, so in-memory state would
#: be lost). Running out of answers for a title is a harness failure that kills
#: the run rather than a silent default. Calls are traced to $TRACEF as
#: ``W kind|title|default-item`` (plus ``M`` with a menu's tags), and the body
#: text goes to $BODYF.
WHIPTAIL = r"""
_qf() { printf '%s/q.%s' "$QDIR" "$(printf '%s' "$1" | cksum | cut -d' ' -f1)"; }
_qpush() { printf '%s\n' "$2" >> "$(_qf "$1")"; }
whiptail() {
    local title="" kind="" body="" dflt=""
    local -a rest=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --title) title="$2"; shift 2 ;;
            --default-item) dflt="$2"; shift 2 ;;
            --menu|--inputbox|--yesno|--msgbox|--checklist|--radiolist)
                kind="${1#--}"; body="$2"; shift 2 ;;
            --backtitle|--cancel-button|--yes-button|--no-button|--ok-button) shift 2 ;;
            --defaultno|--scrolltext|--nocancel) shift ;;
            *) rest+=("$1"); shift ;;
        esac
    done
    printf 'W %s|%s|%s\n' "$kind" "$title" "$dflt" >> "$TRACEF"
    if [ "$kind" = menu ]; then
        local tags="" n=0 x
        for x in "${rest[@]:3}"; do n=$((n+1)); [ $((n % 2)) -eq 1 ] && tags+=" $x"; done
        printf 'M %s|%s\n' "$title" "$tags" >> "$TRACEF"
    fi
    printf 'B %s\n' "$body" >> "$BODYF"
    # The caller captures this in $( ), a SUBSHELL: queue state has to live
    # in files or every pop is lost when the call returns.
    local qf first
    qf=$(_qf "$title")
    if [ ! -s "$qf" ]; then
        [ "$kind" = msgbox ] && return 0
        echo "HARNESS: no scripted answer for '$title'" >> "$TRACEF"
        # exit would only leave the subshell
        kill -9 "$MAINPID"
    fi
    first=$(head -n1 "$qf")
    tail -n +2 "$qf" > "$qf.n"; mv "$qf.n" "$qf"
    local rc="${first%%|*}" out="${first#*|}"
    [ -n "$out" ] && printf '%s' "$out" >&2
    return "$rc"
}
"""


def _fns(*names: str) -> str:
    """The named functions, verbatim. One that is absent becomes a stub that
    fails when called, so a missing function fails the tests that need it
    instead of the whole module at import."""
    out = []
    for n in names:
        try:
            out.append(extract_fn(n))
        except AssertionError:
            out.append(f'{n}() {{ echo "MISSING {n}" >&2; return 99; }}')
    return "\n".join(out)


def run(
    tmp_path: Path,
    fns: str,
    body: str,
    *,
    answers: dict[str, list[str]] | None = None,
    stubs: str = "",
    timeout: int = 60,
) -> tuple[subprocess.CompletedProcess[str], list[str], str]:
    """Run ``body`` with ``fns`` loaded. Returns (proc, trace, bodies)."""
    trace = tmp_path / "trace"
    bodies = tmp_path / "bodies"
    trace.write_text("")
    bodies.write_text("")
    qdir = tmp_path / "q"
    qdir.mkdir(exist_ok=True)
    for old in qdir.iterdir():
        old.unlink()
    pushes = "\n".join(
        f"_qpush {title!r} {a!r}"
        for title, lst in (answers or {}).items()
        for a in lst
    )
    script = "\n".join(
        [
            PRELUDE.replace("__PARSER__", str(PARSER)),
            f"TRACEF={trace}",
            f"BODYF={bodies}",
            f"QDIR={qdir}",
            WHIPTAIL,
            fns,
            stubs,
            pushes,
            textwrap.dedent(body),
        ]
    )
    proc = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, check=False, timeout=timeout
    )
    return proc, trace.read_text().splitlines(), bodies.read_text()


def titles(trace: list[str]) -> list[str]:
    return [ln.split("|")[1] for ln in trace if ln.startswith("W ")]


# ── B1: the wizard loop re-runs dependents after a Confirm jump ─────────────

_ALL = [
    "welcome", "preflight", "ask_keyboard", "ask_role", "pick_disk",
    "confirm_partition_layout", "ask_hostname", "ask_user_password",
    "ask_ssh_keys", "ask_network", "ask_timezone", "ask_ntp",
    "ask_k3s_cidrs", "ask_application_config", "confirm", "do_install",
]

LOOP_FNS = (
    _fns(
        "_run_confirm_deps",
        "_dep_role_sizing",
        "_dep_cidr_overlap",
        "_dep_password_vs_hostname",
        "_install_consistency_problem",
        "_keep_var_pins_cidrs",
        "_k3s_cidr_error",
        "_ellipsis",
        "_whiptail_height",
        "_whiptail_width",
        "_ssh_key_count",
        "confirm",
    )
)


def _loop_body() -> str:
    body = extract_fn("main")
    return body[body.index("    local -a STEPS=("):body.rindex("}")]


def wizard(tmp_path: Path, stubs: str, answers: dict[str, list[str]], **kw):
    """Run main()'s loop with the REAL confirm / dependents and stub screens."""
    skip = {"confirm", "_run_confirm_deps"}
    screens = "\n".join(
        f'{n}() {{ echo "S {n}" >> "$TRACEF"; return 0; }}'
        for n in _ALL
        if n not in skip
    )
    return run(
        tmp_path,
        LOOP_FNS,
        f"""
{screens}
{stubs}
_loop() {{
{_loop_body()}
}}
_loop
echo "ROLE=$ROLE URL=$CONTROL_PLANE_URL CODE=$BOOTSTRAP_PAIRING_CODE"
""",
        answers=answers,
        **kw,
    )


def visited(trace: list[str]) -> list[str]:
    return [ln[2:] for ln in trace if ln.startswith("S ")]


def after(v: list[str], name: str) -> list[str]:
    """What ran from the LAST visit of ``name`` (the Confirm jump), not the
    first (the initial forward walk)."""
    return v[len(v) - 1 - v[::-1].index(name):]


REVIEW_OK = "0|"


def PICK(tag: str) -> str:
    return f"0|{tag}"


# The real confirm() draws no "S" line of its own, so a sequence below reads
# "screen, screen, ..." with Confirm implied between jumps. ``ask_role`` /
# ``ask_network`` are stubbed to change their answer only on the SECOND visit
# (the Confirm jump); the first is the initial forward walk.
_TOGGLE = r"""
_visit() { eval "_v_$1=\$(( \${_v_$1:-0} + 1 ))"; eval "_n=\$_v_$1"; }
"""


def test_first_node_then_confirm_role_additional_never_installs_without_url(tmp_path):
    """The reproduced case. First node, Confirm -> Role -> Additional node,
    Back out of the URL screen, Install: do_install must not be reached with
    ROLE=appliance and an empty URL + code. Confirm sends the operator to the
    screen that fixes it; only then does the install start."""
    stubs = _TOGGLE + r"""
ask_role() { echo "S ask_role" >> "$TRACEF"; _visit role; [ "$_n" -ge 2 ] && ROLE=appliance; return 0; }
ask_application_config() {
    [ "$ROLE" = appliance ] || return 2
    echo "S ask_application_config" >> "$TRACEF"
    _visit app
    # first visit: the operator backs out; second: fills both in.
    if [ "$_n" -eq 1 ]; then return 1; fi
    CONTROL_PLANE_URL=https://cp.example.com; BOOTSTRAP_PAIRING_CODE=12345678; return 0
}
ask_k3s_cidrs() { echo "S ask_k3s_cidrs" >> "$TRACEF"; [ "$ROLE" = appliance ] && return 2; return 0; }
do_install() { echo "S do_install url=$CONTROL_PLANE_URL code=$BOOTSTRAP_PAIRING_CODE" >> "$TRACEF"; }
"""
    answers = {
        "Review": [REVIEW_OK] * 3,
        "Confirm": [PICK("ask_role"), PICK("install"), PICK("install")],
        "Cannot install yet": ["0|"],
    }
    p, trace, _ = wizard(tmp_path, stubs, answers)
    assert p.returncode == 0, (p.stderr, trace)
    v = visited(trace)
    assert v[-1] == "do_install url=https://cp.example.com code=12345678", v
    assert "do_install url= code=" not in "\n".join(v)
    # the dependents ran after the role edit, in order, before Confirm again;
    # Install was then refused by Confirm itself, which re-opened the URL screen
    assert after(v, "ask_role")[1:] == [
        "ask_k3s_cidrs", "ask_application_config", "ask_application_config",
        "do_install url=https://cp.example.com code=12345678",
    ], v
    assert titles(trace).count("Cannot install yet") == 1


def test_role_switch_to_control_plane_runs_sizing_gate_and_cidr_screen(tmp_path):
    stubs = _TOGGLE + r"""
ROLE=appliance; CONTROL_PLANE_URL=https://x.example; BOOTSTRAP_PAIRING_CODE=12345678
ask_role() { echo "S ask_role" >> "$TRACEF"; _visit role; [ "$_n" -ge 2 ] && ROLE=control-plane; return 0; }
_control_plane_sizing_ok() { echo "S sizing" >> "$TRACEF"; return 0; }
blockdev() { echo 107374182400; }
ask_k3s_cidrs() { echo "S ask_k3s_cidrs" >> "$TRACEF"; return 0; }
ask_application_config() { echo "S ask_application_config" >> "$TRACEF"; return 2; }
do_install() { echo "S do_install" >> "$TRACEF"; }
"""
    answers = {"Review": [REVIEW_OK] * 2, "Confirm": [PICK("ask_role"), PICK("install")]}
    p, trace, _ = wizard(tmp_path, stubs, answers)
    assert p.returncode == 0, (p.stderr, trace)
    v = visited(trace)
    assert after(v, "ask_role") == [
        "ask_role", "sizing", "ask_k3s_cidrs", "ask_application_config", "do_install"
    ], v


def test_declined_sizing_after_role_switch_goes_back_to_the_disk(tmp_path):
    stubs = _TOGGLE + r"""
ROLE=appliance
ask_role() { echo "S ask_role" >> "$TRACEF"; _visit role; [ "$_n" -ge 2 ] && ROLE=control-plane; return 0; }
_control_plane_sizing_ok() { echo "S sizing" >> "$TRACEF"; return 1; }
blockdev() { echo 107374182400; }
ask_k3s_cidrs() { echo "S ask_k3s_cidrs" >> "$TRACEF"; return 0; }
ask_application_config() { return 2; }
do_install() { echo "S do_install" >> "$TRACEF"; }
"""
    answers = {"Review": [REVIEW_OK] * 2, "Confirm": [PICK("ask_role"), PICK("install")]}
    p, trace, _ = wizard(tmp_path, stubs, answers)
    v = visited(trace)
    assert after(v, "ask_role")[:4] == ["ask_role", "sizing", "pick_disk", "confirm_partition_layout"], v


def test_network_edit_rechecks_the_k3s_cidrs_against_the_new_lan(tmp_path):
    """The reproduced overlap: DHCP with the default CIDRs, then Confirm ->
    Network -> static 10.42.0.5/16. The check ran against the lease and was
    never repeated."""
    stubs = _TOGGLE + r"""
ask_network() {
    echo "S ask_network" >> "$TRACEF"; _visit net
    [ "$_n" -ge 2 ] && { NET_MODE=static; NET_IP=10.42.0.5; NET_PREFIX=16; }
    return 0
}
ask_k3s_cidrs() { echo "S ask_k3s_cidrs" >> "$TRACEF"; _visit cidr; [ "$_n" -ge 2 ] && K3S_POD_CIDR=10.100.0.0/16; return 0; }
do_install() { echo "S do_install pod=$K3S_POD_CIDR" >> "$TRACEF"; }
"""
    answers = {"Review": [REVIEW_OK] * 2, "Confirm": [PICK("ask_network"), PICK("install")]}
    p, trace, _ = wizard(tmp_path, stubs, answers)
    assert p.returncode == 0, (p.stderr, trace)
    v = visited(trace)
    assert after(v, "ask_network") == ["ask_network", "ask_k3s_cidrs", "do_install pod=10.100.0.0/16"], v


def test_a_conflict_left_in_place_is_refused_at_install(tmp_path):
    """Back out of the CIDR screen: Confirm still refuses Install."""
    stubs = _TOGGLE + r"""
ask_network() {
    echo "S ask_network" >> "$TRACEF"; _visit net
    [ "$_n" -ge 2 ] && { NET_MODE=static; NET_IP=10.42.0.5; NET_PREFIX=16; }
    return 0
}
ask_k3s_cidrs() { echo "S ask_k3s_cidrs" >> "$TRACEF"; _visit cidr; [ "$_n" -eq 2 ] && return 1; return 0; }
do_install() { echo "S do_install" >> "$TRACEF"; }
"""
    answers = {
        "Review": [REVIEW_OK] * 2,
        "Confirm": [PICK("ask_network"), PICK("install")],
        "Cannot install yet": ["0|"],
    }
    p, trace, bodies = wizard(tmp_path, stubs, answers, timeout=20)
    # (the harness is out of Confirm answers after the refusal and is killed)
    assert "Cannot install yet" in titles(trace), trace
    assert "overlaps" in bodies
    assert not any(ln == "S do_install" for ln in trace)


def test_disk_edit_reruns_the_layout_acknowledgement(tmp_path):
    stubs = _TOGGLE + r"""
pick_disk() { echo "S pick_disk" >> "$TRACEF"; TARGET_DISK=/dev/sdb; return 0; }
confirm_partition_layout() { echo "S confirm_partition_layout" >> "$TRACEF"; return 0; }
do_install() { echo "S do_install" >> "$TRACEF"; }
"""
    answers = {"Review": [REVIEW_OK] * 2, "Confirm": [PICK("pick_disk"), PICK("install")]}
    p, trace, _ = wizard(tmp_path, stubs, answers)
    v = visited(trace)
    assert after(v, "pick_disk") == ["pick_disk", "confirm_partition_layout", "do_install"], v


def test_hostname_edit_rechecks_password_against_it(tmp_path):
    stubs = _TOGGLE + r"""
ADMIN_PASSWORD=hunter2hunter2
ask_hostname() { echo "S ask_hostname" >> "$TRACEF"; _visit host; [ "$_n" -ge 2 ] && HOSTNAME=hunter2hunter2; return 0; }
_check_field_stdin() { [ "$4" = "hunter2hunter2" ] && { echo "same as the hostname"; return 1; }; return 0; }
ask_user_password() { echo "S ask_user_password" >> "$TRACEF"; _visit pw; [ "$_n" -ge 2 ] && ADMIN_PASSWORD=other-password-9; return 0; }
do_install() { echo "S do_install" >> "$TRACEF"; }
"""
    answers = {
        "Review": [REVIEW_OK] * 2,
        "Confirm": [PICK("ask_hostname"), PICK("install")],
        "Password no longer acceptable": ["0|"],
    }
    p, trace, _ = wizard(tmp_path, stubs, answers)
    v = visited(trace)
    assert after(v, "ask_hostname") == ["ask_hostname", "ask_user_password", "do_install"], v


def test_back_out_of_the_edited_screen_runs_no_dependents(tmp_path):
    stubs = _TOGGLE + r"""
ask_role() { echo "S ask_role" >> "$TRACEF"; _visit role; [ "$_n" -ge 2 ] && { ROLE=appliance; return 1; }; return 0; }
ask_k3s_cidrs() { echo "S ask_k3s_cidrs" >> "$TRACEF"; return 0; }
do_install() { echo "S do_install" >> "$TRACEF"; }
"""
    # the operator backs out of the role screen; Confirm then refuses Install
    # (ROLE=appliance with no URL) and opens the URL screen instead
    answers = {
        "Review": [REVIEW_OK] * 2,
        "Confirm": [PICK("ask_role"), PICK("install")],
        "Cannot install yet": ["0|"],
    }
    p, trace, _ = wizard(tmp_path, stubs, answers, timeout=20)
    v = visited(trace)
    assert after(v, "ask_role")[:2] == ["ask_role", "ask_application_config"], v
    assert "Cannot install yet" in titles(trace)


def test_confirm_menu_has_a_row_for_the_role_dependent_answers(tmp_path):
    for role, want, absent in (
        ("control-plane", "ask_k3s_cidrs", "ask_application_config"),
        ("appliance", "ask_application_config", "ask_k3s_cidrs"),
    ):
        p, trace, _ = run(
            tmp_path,
            LOOP_FNS,
            f"ROLE={role}\nCONTROL_PLANE_URL=https://cp.example\nBOOTSTRAP_PAIRING_CODE=12345678\nconfirm",
            answers={"Review": [REVIEW_OK], "Confirm": [PICK("pick_disk")]},
        )
        menu = next(ln for ln in trace if ln.startswith("M Confirm|"))
        tags = menu.split("|")[1].split()
        assert want in tags and absent not in tags, (role, tags)
        assert tags[-1] == "install"


def test_review_shows_the_resolvers_and_unset_url(tmp_path):
    p, trace, bodies = run(
        tmp_path,
        LOOP_FNS,
        """
ROLE=appliance
NET_MODE=static; NET_INTERFACE=eth0; NET_IP=10.0.0.5; NET_PREFIX=24; NET_GATEWAY=10.0.0.1
NET_DNS="9.9.9.9 8.8.4.4"
confirm
""",
        answers={"Review": ["1|"]},
    )
    assert "DNS:         9.9.9.9 8.8.4.4" in bodies
    assert "Control URL: <NOT SET" in bodies
    assert "Pair code:   <NOT SET" in bodies


def test_do_install_asserts_consistency_first():
    body = extract_fn("do_install")
    code = [ln.strip() for ln in body.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    assert code[0] == "do_install() {" and code[1] == "_assert_install_consistent", code[:3]


def test_install_consistency_assert_refuses_an_additional_node_with_no_url(tmp_path):
    fns = _fns(
        "_assert_install_consistent",
        "_install_consistency_problem",
        "_keep_var_pins_cidrs",
        "_k3s_cidr_error",
    )
    stubs = (
        'on_cancel() { echo "CANCEL $1" >> "$TRACEF"; exit 77; }\n'
        'preseed_halt() { echo "HALT $1" >> "$TRACEF"; exit 78; }'
    )
    p, trace, _ = run(tmp_path, fns, "ROLE=appliance\n_assert_install_consistent\necho PASSED", stubs=stubs)
    assert p.returncode == 77, (p.stdout, trace)
    assert "PASSED" not in p.stdout
    p, trace, _ = run(
        tmp_path, fns, "ROLE=appliance\nFULLY_UNATTENDED=1\n_assert_install_consistent\necho PASSED", stubs=stubs
    )
    assert p.returncode == 78, (p.stdout, trace)
    # consistent answers pass
    p, trace, _ = run(
        tmp_path,
        fns,
        "ROLE=appliance\nCONTROL_PLANE_URL=https://cp.example\nBOOTSTRAP_PAIRING_CODE=12345678\n"
        "_assert_install_consistent\necho PASSED",
        stubs=stubs,
    )
    assert p.stdout.strip().endswith("PASSED"), (p.stdout, trace)


def test_install_consistency_assert_refuses_overlapping_cidrs(tmp_path):
    fns = _fns("_install_consistency_problem", "_keep_var_pins_cidrs", "_k3s_cidr_error")
    p, trace, _ = run(
        tmp_path,
        fns,
        'NET_MODE=static; NET_IP=10.42.0.5; NET_PREFIX=16\n_install_consistency_problem; echo',
    )
    assert p.stdout.startswith("ask_k3s_cidrs\t"), p.stdout
    assert "overlaps" in p.stdout


# ── B3: static network validation ──────────────────────────────────────────

STATIC_FNS = _fns("_validate_static_net", "_validate_static_net_shape", "_check_field")


def validate(tmp_path, **env) -> tuple[int, str]:
    base = dict(
        NET_IP="192.168.1.10", NET_PREFIX="24", NET_GATEWAY="192.168.1.1",
        NET_DNS="1.1.1.1", NET6_MODE="auto", NET6_IP="", NET6_PREFIX="64", NET6_GATEWAY="",
    )
    base.update(env)
    sets = "\n".join(f"{k}={v!r}" for k, v in base.items())
    p, _, _ = run(tmp_path, STATIC_FNS, sets + "\n_validate_static_net; echo \"RC=$?\"")
    out = p.stdout
    m = re.search(r"RC=(\d+)\s*$", out)
    assert m, (out, p.stderr)
    return int(m.group(1)), out[: m.start()].strip()


@pytest.mark.parametrize(
    "ip,prefix,gw,needle",
    [
        ("192.168.1.0", "24", "192.168.1.1", "network address"),
        ("192.168.1.255", "24", "192.168.1.1", "broadcast"),
        ("127.0.0.1", "8", "127.0.0.2", "not usable"),
        ("224.0.0.5", "24", "224.0.0.1", "not usable"),
        ("0.0.0.0", "24", "192.168.1.1", "not usable"),
        ("192.168.1.10", "24", "192.168.1.10", "own address"),
    ],
)
def test_unusable_static_addresses_are_refused(tmp_path, ip, prefix, gw, needle):
    rc, out = validate(tmp_path, NET_IP=ip, NET_PREFIX=prefix, NET_GATEWAY=gw)
    assert rc == 1, out
    assert needle in out, out


@pytest.mark.parametrize(
    "ip,prefix,gw",
    [
        ("192.168.1.10", "24", "192.168.1.1"),
        ("10.1.0.0", "8", "10.0.0.1"),
        ("192.168.1.0", "31", "192.168.1.1"),  # /31: both addresses are hosts (RFC 3021)
        ("192.0.2.1", "32", "192.0.2.254"),
    ],
)
def test_usable_static_addresses_still_pass(tmp_path, ip, prefix, gw):
    rc, out = validate(tmp_path, NET_IP=ip, NET_PREFIX=prefix, NET_GATEWAY=gw)
    assert rc == 0, out


@pytest.mark.parametrize(
    "typed,want",
    [
        ("255.255.255.0", "24"),
        ("255.255.254.0", "23"),
        ("255.255.255.255", "32"),
        ("255.0.0.0", "8"),
        ("/24", "24"),
        ("24", "24"),
        (" 255.255.255.0 ", "24"),
        ("255.0.255.0", "255.0.255.0"),  # not contiguous: left for the validator
        ("255.255.255.256", "255.255.255.256"),
        ("banana", "banana"),
    ],
)
def test_dotted_netmask_is_converted(tmp_path, typed, want):
    p, _, _ = run(tmp_path, extract_fn("_netmask_to_prefix"), f'_netmask_to_prefix {typed!r}')
    assert p.stdout == want, p.stderr


NETWORK_FNS = _fns(
    "ask_network",
    "_validate_static_net",
    "_validate_static_net_shape",
    "_check_field",
    "_whiptail_height",
    "_whiptail_width",
    "_ellipsis",
    "_netmask_to_prefix",
)
NETWORK_STUBS = r"""
_net_interfaces() { echo eth0; }
_iface_summary() { echo UP; }
_iface_live_config() { printf '\n\n\n'; }
_ask_mtu() { return 0; }
"""


def _ask_network(tmp_path, entries: list[tuple[str, str]], extra: dict[str, list[str]]):
    """entries: the (ip, prefix, gw, dns)-style box answers in order of asking."""
    answers = {
        "Network": ["0|static"],
        "Network interface": ["0|eth0"],
        "IPv6": ["1|"] * 4,
        "Static network — invalid": ["0|"] * 4,
        "Static IP -address": [f"0|{e[0]}" for e in entries],
        "Static IP -prefix": [f"0|{e[1]}" for e in entries],
        "Static IP -gateway": [f"0|{e[2]}" for e in entries],
        "Static IP -DNS": [f"0|{e[3]}" for e in entries],
    }
    answers.update(extra)
    return run(
        tmp_path,
        NETWORK_FNS,
        'ask_network; echo "RC=$? MODE=$NET_MODE IP=$NET_IP PREFIX=$NET_PREFIX GW=$NET_GATEWAY DNS=[$NET_DNS]"',
        answers=answers,
        stubs=NETWORK_STUBS,
    )


def test_ask_network_takes_a_dotted_mask(tmp_path):
    p, trace, _ = _ask_network(tmp_path, [("192.168.1.10", "255.255.255.0", "192.168.1.1", "9.9.9.9")], {})
    assert "RC=0 MODE=static IP=192.168.1.10 PREFIX=24 GW=192.168.1.1 DNS=[9.9.9.9]" in p.stdout, (p.stdout, trace)
    assert "Static network — invalid" not in titles(trace)


def test_ask_network_refuses_the_network_address_and_asks_again(tmp_path):
    p, trace, _ = _ask_network(
        tmp_path,
        [("192.168.1.0", "24", "192.168.1.1", "9.9.9.9"), ("192.168.1.10", "24", "192.168.1.1", "9.9.9.9")],
        {},
    )
    assert titles(trace).count("Static network — invalid") == 1, trace
    assert "IP=192.168.1.10 " in p.stdout


def test_ask_network_wants_a_decision_about_an_empty_resolver_list(tmp_path):
    # "Enter one": asked again, then given
    p, trace, _ = _ask_network(
        tmp_path,
        [("192.168.1.10", "24", "192.168.1.1", ""), ("192.168.1.10", "24", "192.168.1.1", "9.9.9.9")],
        {"No DNS server": ["1|"]},
    )
    assert titles(trace).count("No DNS server") == 1, trace
    assert "DNS=[9.9.9.9]" in p.stdout
    # "No DNS": a decision, accepted, and the list stays empty
    p, trace, _ = _ask_network(
        tmp_path, [("192.168.1.10", "24", "192.168.1.1", "")], {"No DNS server": ["0|"]}
    )
    assert "DNS=[]" in p.stdout, (p.stdout, trace)
    assert titles(trace).count("No DNS server") == 1


# ── B6: control-plane URL ──────────────────────────────────────────────────


def _field(tmp_path, url: str):
    p, _, _ = run(
        tmp_path,
        _fns("_check_field"),
        f'out=$(_check_field control_plane_url {url!r}); echo "RC=$? OUT=$out"',
    )
    return p.stdout.strip()


@pytest.mark.parametrize(
    "url",
    ["https://cp example.com/", 'https://cp.example.com/"x', "https://cp.example.com/$(id)",
     "ftp://cp.example.com", "https://", "https://:443/", "https://user:pw@cp.example.com/"],
)
def test_bad_control_plane_urls_are_refused(tmp_path, url):
    assert _field(tmp_path, url).startswith("RC=1 "), url


def test_good_and_plain_http_urls(tmp_path):
    assert _field(tmp_path, "https://cp.example.com") == "RC=0 OUT="
    assert _field(tmp_path, "https://10.0.0.5:8443/") == "RC=0 OUT="
    # usable, but with an advisory the wizard turns into a choice
    out = _field(tmp_path, "http://10.0.0.5")
    assert out.startswith("RC=0 OUT=") and "unencrypted" in out


APP_FNS = _fns("ask_application_config", "_check_field")
APP_STUBS = r"""
_probe_control_plane() { echo "SpatiumDDI control plane"; return 0; }
"""


def test_wizard_refuses_a_url_with_a_space_or_quote_and_reasks(tmp_path):
    p, trace, _ = run(
        tmp_path,
        APP_FNS,
        'ROLE=appliance\nask_application_config; echo "RC=$? URL=$CONTROL_PLANE_URL CODE=$BOOTSTRAP_PAIRING_CODE"',
        answers={
            "Control plane URL": ['0|https://a b.example', '0|https://c"d.example', "0|https://cp.example.com"],
            "Control plane URL — invalid": ["0|"] * 2,
            "Control plane reachable": ["0|"],
            "Pairing code": ["0|1234-5678"],
        },
        stubs=APP_STUBS,
    )
    assert "RC=0 URL=https://cp.example.com CODE=12345678" in p.stdout, (p.stdout, trace)
    assert titles(trace).count("Control plane URL — invalid") == 2


def test_wizard_makes_plain_http_an_explicit_choice(tmp_path):
    p, trace, _ = run(
        tmp_path,
        APP_FNS,
        'ROLE=appliance\nask_application_config; echo "RC=$? URL=$CONTROL_PLANE_URL"',
        answers={
            "Control plane URL": ["0|http://10.0.0.5", "0|http://10.0.0.5"],
            "Plain http": ["1|", "0|"],  # Change it, then Use http anyway
            "Control plane reachable": ["0|"],
            "Pairing code": ["0|12345678"],
        },
        stubs=APP_STUBS,
    )
    assert "URL=http://10.0.0.5" in p.stdout, (p.stdout, trace)
    assert titles(trace).count("Plain http") == 2


def _preseed(tmp_path, body: str):
    f = tmp_path / "ps.yaml"
    f.write_text("spatium_preseed:\n" + body, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(PARSER), str(f), str(tmp_path / "env"), str(tmp_path / "secret")],
        capture_output=True, text=True, check=False,
    )


@pytest.mark.parametrize(
    "url", ['"https://cp example.com/"', "'https://cp.example.com/\"x'", "ftp://cp.example.com"]
)
def test_preseed_parser_refuses_a_bad_control_plane_url(tmp_path, url):
    pytest.importorskip("yaml")
    r = _preseed(
        tmp_path,
        f"  role: appliance\n  hostname: n1\n  admin_password: \"ChangeMe!12345\"\n"
        f"  pairing_code: \"12345678\"\n  control_plane_url: {url}\n  network:\n    mode: dhcp\n",
    )
    assert r.returncode == 2, (r.stdout, r.stderr)
    assert "control_plane_url" in r.stderr


def test_preseed_parser_notes_plain_http_and_accepts_it(tmp_path):
    pytest.importorskip("yaml")
    r = _preseed(
        tmp_path,
        "  role: appliance\n  hostname: n1\n  admin_password: \"ChangeMe!12345\"\n"
        "  pairing_code: \"12345678\"\n  control_plane_url: http://10.0.0.5\n  network:\n    mode: dhcp\n",
    )
    assert r.returncode == 0, r.stderr
    assert "unencrypted" in r.stdout


def test_preseed_parser_refuses_an_unusable_static_address(tmp_path):
    pytest.importorskip("yaml")
    r = _preseed(
        tmp_path,
        "  role: control-plane\n  hostname: n1\n  admin_password: \"ChangeMe!12345\"\n"
        "  network:\n    mode: static\n    interface: eth0\n    ip: 192.168.1.0\n"
        "    prefix: 24\n    gateway: 192.168.1.1\n",
    )
    assert r.returncode == 2, (r.stdout, r.stderr)
    assert "network address" in r.stderr


def test_post_install_verification_parses_the_machine_config(tmp_path):
    """The check used to be ``test -s``: a file whose control-plane URL had
    broken out of its quoted string was non-empty and passed."""
    pytest.importorskip("yaml")
    m = re.search(r"_machine_config_parses\(\) \{.*?<<'PY'\n(.*?)\nPY\n", SRC, re.DOTALL)
    assert m, "verification must parse spatium-config.yaml"
    prog = m.group(1)

    def check(url_in_file: str, url_wanted: str) -> int:
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text(
            f'hostname: "h1"\nrole: "appliance"\ncontrol_plane_url: "{url_in_file}"\n', encoding="utf-8"
        )
        return subprocess.run(
            [sys.executable, "-", str(cfg), "h1", "appliance", url_wanted],
            input=prog, text=True, capture_output=True, check=False,
        ).returncode

    assert check("https://cp.example.com", "https://cp.example.com") == 0
    assert check('https://cp.example.com/"x', 'https://cp.example.com/"x') != 0  # broken YAML
    assert check("https://other.example.com", "https://cp.example.com") != 0


# ── B5 / C2: Keep /var and STATE ───────────────────────────────────────────

KEPT_FNS = _fns(
    "_read_kept_answers", "_set_kept_answers", "_keep_var_pins_cidrs", "_apply_kept_answers", "_k3s_cidr_canonical"
)


def _state_dir(tmp_path: Path) -> Path:
    d = tmp_path / "state"
    d.mkdir()
    (d / "spatium-config.yaml").write_text(
        '# comment\nhostname: "dns-east-1"\nadmin_user: "netops"\nrole: "control-plane"\n'
        'control_plane_url: ""\nnetwork_mode: "static"\nnetwork_interface: "eth1"\n'
        'network_ip: "10.9.0.5"\nnetwork_prefix: "24"\nnetwork_gateway: "10.9.0.1"\n'
        'network_dns: "9.9.9.9"\n',
        encoding="utf-8",
    )
    (d / "spatium-preseed.yaml").write_text(
        'spatium_preseed:\n  role: "control-plane"\n  timezone: "Europe/Paris"\n  k3s:\n'
        '    pod_cidr: "10.60.0.0/16"\n    service_cidr: "10.61.0.0/16"\n',
        encoding="utf-8",
    )
    return d


def test_kept_answers_are_read_from_state_and_become_defaults(tmp_path):
    d = _state_dir(tmp_path)
    p, trace, _ = run(
        tmp_path,
        KEPT_FNS,
        f"""
KEEP_VAR=yes
_set_kept_answers "$(_read_kept_answers {str(d)!r})"
_apply_kept_answers; echo "rc=$?"
echo "ROLE=$ROLE HOST=$HOSTNAME USER=$ADMIN_USER TZ=$TIMEZONE POD=$K3S_POD_CIDR SVC=$K3S_SERVICE_CIDR"
echo "NET=$NET_MODE/$NET_INTERFACE/$NET_IP/$NET_PREFIX/$NET_GATEWAY/$NET_DNS"
""",
        stubs="HOSTNAME=",
    )
    out = p.stdout
    assert "rc=0" in out, (out, trace)
    assert "HOST=dns-east-1 USER=netops TZ=Europe/Paris" in out
    assert "POD=10.60.0.0/16 SVC=10.61.0.0/16" in out
    assert "NET=static/eth1/10.9.0.5/24/10.9.0.1/9.9.9.9" in out


def test_kept_defaults_never_overwrite_an_answer(tmp_path):
    d = _state_dir(tmp_path)
    p, _, _ = run(
        tmp_path,
        KEPT_FNS,
        f"""
KEEP_VAR=yes
HOSTNAME=typed-already; ADMIN_USER=bob; NET_IP=10.1.1.1; PRESEED_HAS_TIMEZONE=1
_set_kept_answers "$(_read_kept_answers {str(d)!r})"
_apply_kept_answers
echo "HOST=$HOSTNAME USER=$ADMIN_USER IP=$NET_IP TZ=$TIMEZONE"
""",
    )
    assert "HOST=typed-already USER=bob IP=10.1.1.1 TZ=UTC" in p.stdout


def test_kept_network_never_replaces_an_answered_dhcp_screen(tmp_path):
    # A DHCP answer has an empty NET_IP, exactly like a screen not yet shown:
    # Confirm -> Target disk -> Keep /var used to swap it for the kept static IP.
    d = _state_dir(tmp_path)
    p, _, _ = run(
        tmp_path,
        KEPT_FNS,
        f"""
KEEP_VAR=yes; NET_MODE=dhcp; NET_ANSWERED=1
_set_kept_answers "$(_read_kept_answers {str(d)!r})"
_apply_kept_answers
echo "NET=$NET_MODE/$NET_IP"
""",
    )
    assert "NET=dhcp/" in p.stdout


def test_a_role_different_from_the_kept_data_is_switched_or_refused(tmp_path):
    d = _state_dir(tmp_path)
    script = f"""
KEEP_VAR=yes; ROLE=appliance
_set_kept_answers "$(_read_kept_answers {str(d)!r})"
_apply_kept_answers; echo "rc=$? ROLE=$ROLE"
"""
    p, trace, bodies = run(
        tmp_path, KEPT_FNS, script, answers={"Role is fixed by the kept data": ["0|"]}
    )
    assert "rc=0 ROLE=control-plane" in p.stdout, (p.stdout, trace)
    assert "cannot reuse it" in bodies
    # declining is "pick another disk"
    p, _, _ = run(tmp_path, KEPT_FNS, script, answers={"Role is fixed by the kept data": ["1|"]})
    assert "rc=1 ROLE=appliance" in p.stdout


def test_unreadable_state_pins_nothing(tmp_path):
    p, _, _ = run(
        tmp_path,
        KEPT_FNS,
        f"""
KEEP_VAR=yes
_set_kept_answers "$(_read_kept_answers {str(tmp_path / 'nothing-here')!r})"
_apply_kept_answers; echo "rc=$? ROLE=$ROLE POD=$K3S_POD_CIDR"
_keep_var_pins_cidrs && echo PINNED || echo free
""",
    )
    assert "rc=0 ROLE=control-plane POD=10.42.0.0/16" in p.stdout
    assert "free" in p.stdout


def test_ask_k3s_cidrs_is_pinned_to_the_kept_datastore(tmp_path):
    p, trace, _ = run(
        tmp_path,
        _fns(
            "ask_k3s_cidrs", "_keep_var_pins_cidrs", "_k3s_cidr_error", "_k3s_cidr_canonical",
            "_whiptail_height", "_whiptail_width",
        ),
        """
KEEP_VAR=yes; KEPT_POD_CIDR=10.60.0.0/16; KEPT_SVC_CIDR=10.61.0.0/16
ask_k3s_cidrs; echo "rc=$? POD=$K3S_POD_CIDR SVC=$K3S_SERVICE_CIDR"
""",
    )
    # no summary screen, no way to change them, and the rc says "drew nothing"
    assert "rc=2 POD=10.60.0.0/16 SVC=10.61.0.0/16" in p.stdout, (p.stdout, trace)
    assert titles(trace) == []


def test_pinned_cidrs_overlapping_the_lan_are_explained_not_trapped(tmp_path):
    p, trace, bodies = run(
        tmp_path,
        _fns(
            "ask_k3s_cidrs", "_keep_var_pins_cidrs", "_k3s_cidr_error", "_k3s_cidr_canonical",
            "_whiptail_height", "_whiptail_width",
        ),
        """
KEEP_VAR=yes; KEPT_POD_CIDR=10.60.0.0/16; KEPT_SVC_CIDR=10.61.0.0/16
NET_MODE=static; NET_IP=10.60.0.9; NET_PREFIX=16
ask_k3s_cidrs; echo "rc=$?"
""",
        answers={"k3s ranges are fixed": ["0|"]},
    )
    assert "rc=2" in p.stdout
    assert "overlaps" in bodies and "Erase everything" in bodies


def test_confirm_does_not_refuse_install_on_pinned_cidrs(tmp_path):
    p, _, _ = run(
        tmp_path,
        _fns("_install_consistency_problem", "_keep_var_pins_cidrs", "_k3s_cidr_error"),
        """
KEEP_VAR=yes; KEPT_POD_CIDR=10.60.0.0/16; KEPT_SVC_CIDR=10.61.0.0/16
K3S_POD_CIDR=10.60.0.0/16; K3S_SERVICE_CIDR=10.61.0.0/16
NET_MODE=static; NET_IP=10.60.0.9; NET_PREFIX=16
_install_consistency_problem; echo "[done]"
""",
    )
    assert p.stdout.strip() == "[done]", p.stdout


def test_ask_role_is_pinned_by_kept_data(tmp_path):
    p, trace, bodies = run(
        tmp_path,
        _fns("ask_role"),
        'KEEP_VAR=yes; KEPT_ROLE=control-plane; ROLE=appliance\nask_role; echo "rc=$? ROLE=$ROLE"',
    )
    assert "rc=2 ROLE=control-plane" in p.stdout, (p.stdout, trace)
    assert titles(trace) == []
    # but a Confirm jump says why nothing changed
    p, trace, bodies = run(
        tmp_path,
        _fns("ask_role"),
        'KEEP_VAR=yes; KEPT_ROLE=control-plane; CONFIRM_EDITING=1\nask_role; echo "rc=$?"',
        answers={"Role is fixed": ["0|"]},
    )
    assert "rc=2" in p.stdout and "Erase everything" in bodies


LAYOUT_FNS = _fns("confirm_partition_layout")


def _layout(tmp_path, prelude: str) -> str:
    p, trace, bodies = run(
        tmp_path,
        LAYOUT_FNS,
        prelude + '\nblockdev() { echo 107374182400; }\nconfirm_partition_layout; echo "rc=$?"',
        answers={"Confirm Partition Layout": ["0|erase"]},
    )
    assert "rc=0" in p.stdout, (p.stdout, trace)
    return bodies


def test_layout_screen_for_keep_var_does_not_claim_an_erase(tmp_path):
    body = _layout(tmp_path, "KEEP_VAR=yes")
    assert "ERASED" not in body and "erased" not in body
    assert "REPLACED" in body and "KEPT" in body


def test_layout_screen_names_both_mirror_disks(tmp_path):
    body = _layout(tmp_path, "MIRROR_MODE=yes; TARGET_DISK2=/dev/sdb")
    assert "/dev/sda and /dev/sdb will be ERASED" in body


def test_layout_screen_has_no_bios_boot_row_on_arm64(tmp_path):
    assert "BIOS boot" in _layout(tmp_path, "TARGET_ARCH=amd64")
    assert "BIOS boot" not in _layout(tmp_path, "TARGET_ARCH=arm64")


# ── B7: Done screen address ────────────────────────────────────────────────

IP_STUB = r"""
ip() {
    echo "ip $*" >> "$TRACEF"
    case "$*" in
        *"-4"*"dev eth1"*) printf 'eth1 UP %s\n' "${V4:-}" ;;
        *"-4"*) printf 'eth0 UP 192.168.9.9/24\n' ;;
        *"-6"*"dev eth1"*) printf 'eth1 UP %s\n' "${V6:-}" ;;
    esac
}
"""


def test_done_screen_reads_the_chosen_port_not_the_first_one(tmp_path):
    p, trace, _ = run(
        tmp_path,
        _fns("_done_screen_address"),
        'NET_INTERFACE=eth1; V4=10.9.0.5/24; _done_screen_address',
        stubs=IP_STUB,
    )
    assert p.stdout == "10.9.0.5", (p.stdout, trace)
    assert any("dev eth1" in ln for ln in trace)


def test_done_screen_falls_back_to_a_global_ipv6_address(tmp_path):
    p, trace, _ = run(
        tmp_path,
        _fns("_done_screen_address"),
        'NET_INTERFACE=eth1; V4=""; V6=2001:db8::5/64; _done_screen_address',
        stubs=IP_STUB,
    )
    assert p.stdout == "2001:db8::5", (p.stdout, trace)


# ── B8: keyboard ───────────────────────────────────────────────────────────


def test_apply_keymap_fails_when_the_tools_are_missing(tmp_path):
    p, trace, _ = run(
        tmp_path,
        _fns("_apply_keymap", "_keymap_to_xkb"),
        'PATH=/nonexistent\n_apply_keymap xx; echo "rc=$?"',
    )
    assert "rc=1" in p.stdout, (p.stdout, p.stderr)


def test_a_listed_layout_that_fails_to_apply_is_shown_to_the_operator(tmp_path):
    p, trace, bodies = run(
        tmp_path,
        _fns("ask_keyboard"),
        'ask_keyboard; echo "rc=$? KEYMAP=$KEYMAP"',
        answers={"Keyboard layout": ["0|de"], "Layout not applied": ["0|"]},
        stubs="_apply_keymap() { return 1; }",
    )
    assert "Layout not applied" in titles(trace), (p.stdout, trace)
    assert "rc=0 KEYMAP=de" in p.stdout
    # "Choose again" goes back to the list instead
    p, trace, _ = run(
        tmp_path,
        _fns("ask_keyboard"),
        'ask_keyboard; echo "rc=$? KEYMAP=$KEYMAP"',
        answers={"Keyboard layout": ["0|de", "0|us"], "Layout not applied": ["1|"]},
        stubs="_apply_keymap() { [ \"$1\" = us ]; }",
    )
    assert "KEYMAP=us" in p.stdout, (p.stdout, trace)


# ── B9: SSH keys ───────────────────────────────────────────────────────────

SSH_FNS = _fns("ask_ssh_keys", "_ssh_key_count")


def test_no_key_with_keys_held_asks_first(tmp_path):
    p, trace, bodies = run(
        tmp_path,
        SSH_FNS,
        'SSH_AUTHORIZED_KEYS="ssh-ed25519 AAAA a@b"\nask_ssh_keys; echo "rc=$? KEYS=$(_ssh_key_count)"',
        answers={
            "SSH public key": ["0|skip", "0|done"],
            "Remove the keys?": ["1|"],  # Keep them
            "Disable password SSH?": ["1|"],
        },
    )
    assert "KEYS=1" in p.stdout, (p.stdout, trace)
    assert "Remove the keys?" in titles(trace)
    # and when they say yes, they are removed
    p, trace, _ = run(
        tmp_path,
        SSH_FNS,
        'SSH_AUTHORIZED_KEYS="ssh-ed25519 AAAA a@b"\nask_ssh_keys; echo "rc=$? KEYS=$(_ssh_key_count)"',
        answers={"SSH public key": ["0|skip"], "Remove the keys?": ["0|"]},
    )
    assert "KEYS=0" in p.stdout, (p.stdout, trace)


def test_no_key_with_nothing_held_does_not_ask(tmp_path):
    p, trace, _ = run(
        tmp_path,
        SSH_FNS,
        'ask_ssh_keys; echo "rc=$?"',
        answers={"SSH public key": ["0|skip"]},
    )
    assert "rc=0" in p.stdout
    assert "Remove the keys?" not in titles(trace)
