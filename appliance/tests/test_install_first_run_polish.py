"""First-install polish from the installer walk-through (#4551).

Pure helpers are executed under bash; the screens are driven with a stub
``whiptail`` that records its arguments and answers from a script.

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_install_first_run_polish.py -v
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from _installer_source import SRC, extract_fn

pytestmark = pytest.mark.skipif(not shutil.which("bash"), reason="bash not available")


def bash(script: str, **env: str) -> subprocess.CompletedProcess:
    # A timeout is a failure, not a hang: a stub screen that is asked again
    # and again (a regression to a menu loop) must not wedge the suite.
    return subprocess.run(
        ["timeout", "15", "bash", "-c", script],
        capture_output=True,
        text=True,
        check=False,
        stdin=subprocess.DEVNULL,
        env={**os.environ, "TERM": "dumb", **env},
    )


def fns(*names: str) -> str:
    return "\n".join(extract_fn(n) for n in names)


# ── role: nothing pre-selected ────────────────────────────────────────


def _role_flags(tmp_path: Path, picked: str) -> str:
    log = tmp_path / "args"
    script = f"""
log() {{ :; }}
BACKTITLE=t; ROLE=appliance; ROLE_PICKED="{picked}"
whiptail() {{ printf '%s\\n' "$@" > {log}; return 1; }}   # Back
{extract_fn("ask_role")}
ask_role || true
"""
    bash(script)
    return log.read_text()


def test_role_screen_preselects_nothing_on_first_visit(tmp_path):
    args = _role_flags(tmp_path, "").splitlines()
    i = args.index("add-node")
    assert args[i + 2] == "OFF"
    j = args.index("first-node")
    assert args[j + 2] == "OFF"


def test_role_screen_keeps_the_pick_when_backing_in(tmp_path):
    args = _role_flags(tmp_path, "1").splitlines()
    assert args[args.index("add-node") + 2] == "ON"


def test_role_screen_tells_a_first_install_what_to_choose(tmp_path):
    assert "FIRST INSTALL? Choose" in _role_flags(tmp_path, "")


# ── disk rows ─────────────────────────────────────────────────────────


def test_disk_serial_tag_is_the_tail(tmp_path):
    script = f"""
lsblk() {{ echo 'S3Z9NB0K123456789A'; }}
{fns("_disk_serial_tag")}
_disk_serial_tag /dev/sda
"""
    assert bash(script).stdout == " S/N 3456789A"


def test_disk_serial_tag_empty_without_serial():
    script = f"""
lsblk() {{ echo; }}
{fns("_disk_serial_tag")}
_disk_serial_tag /dev/sda
"""
    assert bash(script).stdout == ""


@pytest.mark.parametrize(
    ("gib", "tag"), [(8, " [too small]"), (31, " [too small]"), (32, ""), (500, "")]
)
def test_disk_small_tag(gib, tag):
    script = f"""
MIN_DISK_GIB=32
{fns("_disk_small_tag")}
_disk_small_tag $(( {gib} * 1024 * 1024 * 1024 ))
"""
    assert bash(script).stdout == tag


def test_disk_small_tag_ignores_garbage():
    script = f"MIN_DISK_GIB=32\n{fns('_disk_small_tag')}\n_disk_small_tag ''; _disk_small_tag x"
    assert bash(script).stdout == ""


def test_pick_disk_uses_both_tags():
    body = extract_fn("pick_disk")
    assert '_disk_serial_tag "/dev/$name"' in body
    assert "_disk_small_tag" in body


def test_keep_var_back_returns_to_the_disk_menu():
    body = extract_fn("pick_disk")
    assert "|| continue 2" in body


# ── timezone ──────────────────────────────────────────────────────────


@pytest.fixture
def zoneinfo(tmp_path):
    root = tmp_path / "zi"
    for rel in (
        "UTC",
        "America/Toronto",
        "America/Argentina/Buenos_Aires",
        "Europe/Berlin",
        "Etc/GMT+5",
    ):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"TZif2")
    return root


def test_tz_regions_lists_only_present_regions(zoneinfo):
    out = bash(fns("_tz_regions") + "\n_tz_regions", ZONEINFO_DIR=str(zoneinfo)).stdout
    assert out.split() == ["America", "Europe"]


def test_tz_zones_are_relative_and_include_subdirs(zoneinfo):
    out = bash(fns("_tz_zones") + "\n_tz_zones America", ZONEINFO_DIR=str(zoneinfo)).stdout
    assert out.split() == ["Argentina/Buenos_Aires", "Toronto"]


@pytest.mark.parametrize(
    ("typed", "want"),
    [
        ("utc", "UTC"),
        ("america/toronto", "America/Toronto"),
        ("America/Toronto", "America/Toronto"),
        ("etc/gmt+5", "Etc/GMT+5"),
        ("Nowhere/City", "Nowhere/City"),
        ("../../etc/passwd", "../../etc/passwd"),
    ],
)
def test_tz_canonical_is_case_insensitive(zoneinfo, typed, want):
    out = bash(fns("_tz_canonical") + f'\n_tz_canonical "{typed}"', ZONEINFO_DIR=str(zoneinfo))
    assert out.stdout == want


def test_ask_timezone_menu_pick_sets_the_zone(zoneinfo, tmp_path):
    answers = tmp_path / "answers"
    answers.write_text("America\nAmerica/Toronto\n")
    script = f"""
log() {{ :; }}
BACKTITLE=t; TIMEZONE=UTC
_check_field() {{ return 0; }}
whiptail() {{ head -n1 {answers} >&2; sed -i 1d {answers}; }}
{fns("_tz_regions", "_tz_zones", "_tz_canonical", "ask_timezone")}
ask_timezone
echo "TZ=$TIMEZONE"
"""
    out = bash(script, ZONEINFO_DIR=str(zoneinfo))
    assert "TZ=America/Toronto" in out.stdout, out.stderr


def test_ask_timezone_other_accepts_lowercase(zoneinfo, tmp_path):
    answers = tmp_path / "answers"
    answers.write_text("other\nutc\n")
    script = f"""
log() {{ :; }}
BACKTITLE=t; TIMEZONE=Europe/Berlin
_check_field() {{ return 0; }}
whiptail() {{ head -n1 {answers} >&2; sed -i 1d {answers}; }}
{fns("_tz_regions", "_tz_zones", "_tz_canonical", "ask_timezone")}
ask_timezone
echo "TZ=$TIMEZONE"
"""
    assert "TZ=UTC" in bash(script, ZONEINFO_DIR=str(zoneinfo)).stdout


# ── clock + NTP ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("typed", "ok"),
    [
        ("2026-11-20 14:05", True),
        ("2026-11-20 14:05:09", True),
        ("2026-02-30 10:00", False),
        ("2026-11-20", False),
        ("20 Nov 2026 14:05", False),
        ("2026-11-20 25:00", False),
        ("", False),
    ],
)
def test_parse_clock_input(typed, ok):
    out = bash(fns("_parse_clock_input") + f'\n_parse_clock_input "{typed}"; echo "rc=$?"')
    assert (f"rc={0 if ok else 1}") in out.stdout
    if ok:
        assert out.stdout.startswith(typed[:16])


def test_preflight_offers_to_set_a_wrong_clock():
    body = extract_fn("preflight")
    assert "_offer_set_clock" in body and "clock_bad=1" in body


def test_ntp_probe_fails_when_chronyd_gets_no_answer(tmp_path):
    (tmp_path / "chronyd").write_text("#!/bin/sh\necho 'No suitable source'\nexit 1\n")
    (tmp_path / "chronyd").chmod(0o755)
    script = f'PATH="{tmp_path}:$PATH"\n{fns("_ntp_probe")}\n_ntp_probe "a.example b.example"; echo "rc=$?"'
    out = bash(script).stdout
    assert "No suitable source" in out and "rc=1" in out


def test_ntp_probe_passes_each_server_as_its_own_directive(tmp_path):
    (tmp_path / "chronyd").write_text('#!/bin/sh\nfor a in "$@"; do echo "ARG:$a"; done\n')
    (tmp_path / "chronyd").chmod(0o755)
    script = f'PATH="{tmp_path}:$PATH"\n{fns("_ntp_probe")}\n_ntp_probe "a.example b.example"'
    out = bash(script).stdout
    assert "ARG:server b.example iburst" in out


# ── Done screen ───────────────────────────────────────────────────────


def _done_src() -> str:
    """do_install has a column-0 brace inside it, so slice by markers."""
    start = SRC.index("    local done_addr=")
    return SRC[start : SRC.index('systemctl reboot\n}', start)]


def test_done_screen_offers_reboot_poweroff_shell_and_login_hints():
    body = _done_src()
    for needle in ('"poweroff"', '"shell"', '"reboot"', "ssh ${ADMIN_USER}@", "certificate warning"):
        assert needle in body, needle


def test_done_screen_certificate_note_only_where_a_web_ui_exists():
    body = _done_src()
    i = body.index("done_cert_note=")
    assert 'if [ "$ROLE" != "appliance" ]' in body[i : i + 200]


# ── headless preseed ──────────────────────────────────────────────────

_PRESEED_BASE = (
    "PRESEED_HAS_ROLE=1 PRESEED_HAS_DISK=1 PRESEED_HAS_HOSTNAME=1 PRESEED_HAS_PASSWORD=1 "
    "PRESEED_HAS_NETWORK=1"
)


def _unattended(role: str, extra: str) -> str:
    script = f"""
ROLE={role}; FULLY_UNATTENDED=0
{_PRESEED_BASE}; {extra}
{fns("compute_unattended", "_unattended_missing")}
compute_unattended
echo "U=$FULLY_UNATTENDED"
_unattended_missing | paste -sd,
"""
    return bash(script).stdout


def test_additional_node_without_timezone_or_k3s_is_fully_unattended():
    out = _unattended("appliance", "PRESEED_HAS_CONTROL_URL=1 PRESEED_HAS_PAIRING_CODE=1")
    assert "U=1" in out


def test_control_plane_without_timezone_is_unattended_but_needs_k3s():
    assert "U=0" in _unattended("control-plane", "")
    assert "U=1" in _unattended("control-plane", "PRESEED_HAS_K3S=1")


def test_missing_fields_are_named():
    assert "k3s" in _unattended("control-plane", "")
    assert "pairing code" in _unattended("appliance", "PRESEED_HAS_CONTROL_URL=1")


def test_ask_timezone_skips_itself_when_unattended():
    script = f"""
log() {{ :; }}
FULLY_UNATTENDED=1; TIMEZONE=UTC
whiptail() {{ echo DREW; }}
{extract_fn("ask_timezone")}
ask_timezone; echo "rc=$?"
"""
    out = bash(script).stdout
    assert "rc=2" in out and "DREW" not in out


def test_check_preseed_reports_what_keeps_a_run_from_unattended():
    assert "Missing: $unattended_missing" in SRC
