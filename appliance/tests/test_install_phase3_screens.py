"""#995 Phase 3 — the eight missing screens and network fixes (15-22).

Phase 1 fixed what was wrong and Phase 2 changed what is accepted; this
phase adds what was never asked. Four of the eight are pure logic that
can be executed rather than grepped (the network fact helpers and the
IPv6 validator), and those get real tests; the screens themselves are
whiptail and get structural ones.

  15  pre-flight system check      19  interface picker, both modes
  16  NTP                          20  pre-fill static from the live lease
  17  keyboard layout              21  static IPv6
  18  SSH authorized_keys          22  CIDR overlap in DHCP mode

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_install_phase3_screens.py -v
"""

from __future__ import annotations

import re
import shutil
import subprocess

import pytest

from _installer_source import CODE, PARSER, extract_fn

RENDERER = PARSER.parent / "spatium-etc-render"


@pytest.fixture(autouse=True)
def _needs_bash():
    if not shutil.which("bash"):
        pytest.skip("bash not available")


def run_validator(**env) -> str:
    """Execute _validate_static_net with the given NET_* values."""
    base = dict(
        NET_IP="192.168.1.10", NET_PREFIX="24", NET_GATEWAY="192.168.1.1",
        NET_DNS="1.1.1.1", NET6_MODE="auto", NET6_IP="", NET6_PREFIX="64",
        NET6_GATEWAY="",
    )
    base.update(env)
    script = "\n".join(f'{k}={v!r}' for k, v in base.items())
    script += "\n" + extract_fn("_validate_static_net") + "\n_validate_static_net\n"
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    return r.stdout.strip()


# ── Item 21 — static IPv6 ─────────────────────────────────────────────


def test_ipv6_auto_is_the_default_and_asks_nothing():
    assert 'NET6_MODE="auto"' in CODE
    assert run_validator() == ""


@pytest.mark.parametrize(
    "ip,prefix,gw",
    [
        ("2001:db8:1::10", "64", ""),
        ("2001:db8:1::10", "64", "2001:db8:1::1"),
        ("2001:db8:1::10", "128", ""),
    ],
)
def test_valid_static_ipv6_accepted(ip, prefix, gw):
    assert run_validator(NET6_MODE="static", NET6_IP=ip, NET6_PREFIX=prefix,
                         NET6_GATEWAY=gw) == ""


def test_a_link_local_gateway_is_accepted():
    """The case a transliteration of the v4 rules gets wrong.

    A router advertising a /64 answers on fe80::…, which is NOT inside
    the prefix — so an in-subnet check would refuse the commonest correct
    answer on every IPv6 network there is.
    """
    assert run_validator(NET6_MODE="static", NET6_IP="2001:db8:1::10",
                         NET6_PREFIX="64", NET6_GATEWAY="fe80::1") == ""


@pytest.mark.parametrize(
    "ip,prefix,gw,expect",
    [
        ("", "64", "", "required"),
        ("fe80::1234", "64", "", "link-local"),
        ("not-an-address", "64", "", "not a valid IPv6"),
        ("192.168.1.5", "64", "", "not a valid IPv6"),
        ("2001:db8:1::10", "200", "", "between 1 and 128"),
        ("2001:db8:1::10", "64", "2001:db8:9::1", "not inside"),
        ("::1", "128", "", "not a host address"),
    ],
)
def test_invalid_static_ipv6_refused(ip, prefix, gw, expect):
    out = run_validator(NET6_MODE="static", NET6_IP=ip, NET6_PREFIX=prefix,
                        NET6_GATEWAY=gw)
    assert expect in out, out


def test_the_renderer_never_emits_a_trailing_comma():
    """The #554 failure, in its v6 form: NetworkManager refuses
    `address1=<ip>/<prefix>,` and the connection then never loads, so the
    appliance comes up with no address at all."""
    fn = extract_fn("_render_ipv6_block", RENDERER.read_text(encoding="utf-8"))
    assert 'address1=$_v6_ip/${_v6_prefix:-64},$_v6_gw' in fn
    assert 'address1=$_v6_ip/${_v6_prefix:-64}"' in fn or \
           'address1=$_v6_ip/${_v6_prefix:-64}\n' in fn


def test_the_renderer_is_posix_sh():
    """spatium-etc-render is #!/bin/sh and runs before NetworkManager. A
    bashism there is a boot-time failure, not a lint nit."""
    body = RENDERER.read_text(encoding="utf-8")
    fn = extract_fn("_render_ipv6_block", body)
    assert body.startswith("#!/bin/sh")
    assert "local " not in fn


# ── Item 19 — the interface picker ────────────────────────────────────


def test_the_picker_is_offered_in_dhcp_mode_too():
    """NetworkManager DHCPs EVERY ethernet port by default, so on a
    multi-NIC server the appliance answered on whichever replied first."""
    fn = extract_fn("ask_network")
    i = fn.index("Network interface")
    # The last `NET_MODE = static` test is the static-only block; the
    # first is the preseed short-circuit at the top of the function,
    # which precedes the picker either way and proves nothing.
    static_block = fn.rindex('if [ "$NET_MODE" = "static" ]; then')
    assert static_block > i, "the picker must not sit inside the static branch"


def test_dhcp_keeps_an_any_port_escape_hatch():
    fn = extract_fn("ask_network")
    assert '"any"' in fn
    assert '[ "$NET_INTERFACE" = "any" ] && NET_INTERFACE=""' in fn


def test_the_rows_say_which_cable_is_plugged_in():
    """Name + MAC — what the old picker showed — answers a question
    nobody has in front of a multi-port server."""
    fn = extract_fn("_iface_summary")
    assert "operstate" in fn
    assert "speed" in fn
    assert "ip -4 -br addr" in fn
    assert "driver" in fn


def test_carrier_is_not_read_directly():
    """Reading /sys/class/net/X/carrier on a DOWN interface returns
    EINVAL, so it cannot be the link signal here."""
    assert "/carrier" not in CODE


def test_a_pinned_dhcp_port_is_actually_rendered():
    """The screen asking is worthless if nothing writes the keyfile."""
    body = RENDERER.read_text(encoding="utf-8")
    assert "NM_DHCP_KEYFILE" in body
    assert "autoconnect-priority=100" in body, (
        "NetworkManager's own auto 'Wired connection N' profiles default "
        "to 0; without a higher priority the first port still wins"
    )


def test_the_confirm_screen_shows_the_chosen_port():
    fn = extract_fn("confirm")
    assert "(on $NET_INTERFACE)" in fn
    assert "(any port)" in fn


# ── Item 20 — pre-fill from the live lease ────────────────────────────


def test_static_offers_the_values_the_box_already_has():
    fn = extract_fn("ask_network")
    assert "_iface_live_config" in fn
    assert "Use these" in fn


def test_the_live_config_reader_skips_the_resolved_stub():
    """/etc/resolv.conf on a systemd-resolved box points at 127.0.0.53,
    which is useless as a value to install on another machine."""
    fn = extract_fn("_iface_live_config")
    assert "127" in fn and "nameserver" in fn


# ── Item 22 — CIDR overlap in DHCP mode ───────────────────────────────


def test_the_overlap_check_knows_the_lan_in_dhcp_mode():
    """It only ever knew the LAN in static mode, so the whole check was
    dead on the path most installs take — including for a site whose LAN
    is 10.42.0.0/16, the k3s pod default this check exists for."""
    fn = extract_fn("_validate_k3s_cidrs")
    assert "_dhcp_lease_subnet" in fn


def test_the_lease_probe_is_inert_in_static_mode():
    fn = extract_fn("_dhcp_lease_subnet")
    assert '[ "$NET_MODE" = "static" ] && return 0' in fn


def test_the_linter_does_not_probe_this_machines_lease():
    """--check-preseed runs on somebody's workstation, whose lease says
    nothing about the appliance's future LAN."""
    i = CODE.index("kerr=$(_k3s_cidr_error")
    assert "_dhcp_lease_subnet" not in CODE[i:i + 200]


def test_the_lease_probe_strips_the_veth_peer_suffix():
    """`ip -br` renders a veth as eth0@if1388, and `ip addr show dev
    eth0@if1388` fails."""
    fn = extract_fn("_dhcp_lease_subnet")
    assert 'sub(/@.*/, "", $1)' in fn


# ── Item 15 — pre-flight ──────────────────────────────────────────────


def test_preflight_reports_the_facts_that_decide_the_install():
    fn = extract_fn("preflight")
    for fact in ("CPU:", "Memory:", "Firmware:", "Disks:", "Network:",
                 "Gateway:", "Resolver:", "Clock:"):
        assert fact in fn, fact


def test_preflight_does_not_probe_the_internet():
    """Non-negotiable #17: SpatiumDDI makes no outbound connection the
    operator did not ask for, and an installer pinging a well-known host
    to draw a green tick would be exactly that. The gateway is on the
    LAN; an air-gapped install is a supported case, not a red line."""
    fn = extract_fn("preflight")
    for host in ("google", "cloudflare", "1.1.1.1", "8.8.8.8", "debian.org",
                 "github", "example.com"):
        assert host not in fn, host


def test_preflight_catches_a_clock_behind_the_build_date():
    """A dead CMOS battery breaks TLS to the control plane and the
    supervisor's pairing, and both fail in ways that read as a
    networking fault."""
    fn = extract_fn("preflight")
    assert "_iso_build_date" in fn
    assert "BEFORE this image was built" in fn


def _iso_build_date(tmp_path, stamp: str) -> str:
    release = tmp_path / "appliance-release"
    release.write_text(stamp)
    script = (
        extract_fn("_release_field")
        + "\n"
        + extract_fn("_iso_build_date")
        + f"\n_iso_build_date {str(release)!r}\n"
    )
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    return r.stdout.strip()


@pytest.mark.parametrize(
    "version",
    ["2026.11.03-1", "1.0.0", "1.0.0-rc.1", "dev-abc1234-9f2e", "0.0.0-nightly-20261110+abc"],
)
def test_the_build_date_comes_from_build_time_not_the_version(tmp_path, version):
    """#1182: it was parsed out of a CalVer version, so from 1.0.0 on the
    clock check would have fallen back to the file's mtime on every
    release ISO."""
    stamp = (
        f'APPLIANCE_VERSION="{version}"\n'
        'BUILD_TIME="2026-11-10T04:12:33+00:00"\n'
        'GIT_SHA="abc"\n'
    )
    assert _iso_build_date(tmp_path, stamp) == "2026-11-10"


def test_a_stamp_without_build_time_falls_back_to_its_mtime(tmp_path):
    """A stamp written by hand or by an older build carries no BUILD_TIME;
    the file's mtime is the build."""
    got = _iso_build_date(tmp_path, 'APPLIANCE_VERSION="dev"\n')
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", got), got


def test_preflight_is_informational_not_a_gate():
    """The one hard refusal is the disk size floor, which pick_disk owns.
    A screen that refused on RAM would stop an operator who knows their
    VM is about to be resized."""
    fn = extract_fn("preflight")
    assert "exit 1" not in fn
    assert "preseed_halt" not in fn


def test_preflight_is_skipped_on_an_unattended_run():
    fn = extract_fn("preflight")
    assert '[ "$FULLY_UNATTENDED" = "1" ]' in fn


# ── Item 17 — keyboard ────────────────────────────────────────────────


def test_the_keymap_is_applied_before_anything_is_typed():
    """The password is the field that matters: on AZERTY or QWERTZ its
    symbols land elsewhere, the installer stores what US produced, and
    the login later fails with no explanation."""
    steps = CODE[CODE.index("local -a STEPS=("):]
    steps = steps[:steps.index(")")]
    assert steps.index("ask_keyboard") < steps.index("ask_user_password")
    assert "_apply_keymap" in extract_fn("ask_keyboard")


def test_an_unloadable_keymap_is_refused_not_silently_ignored():
    fn = extract_fn("ask_keyboard")
    assert "Unknown keymap" in fn


def test_the_keymap_is_persisted_where_both_readers_look():
    """console-setup reads /etc/default/keyboard; systemd-vconsole-setup
    reads /etc/vconsole.conf. Writing one leaves the operator on US at
    exactly the login prompt where a mangled password is least
    explicable."""
    assert "/etc/default/keyboard" in CODE
    assert "/etc/vconsole.conf" in CODE


# ── Item 16 — NTP ─────────────────────────────────────────────────────


def test_ntp_is_written_as_a_chrony_sourcedir_file():
    """Additive, survives a package upgrade rewriting chrony.conf, and is
    a clean seam for the control plane to take over."""
    assert "/etc/chrony/sources.d/spatium-install.sources" in CODE


def test_central_ntp_config_removes_the_install_time_file():
    """Debian's chrony.conf carries `sourcedir /etc/chrony/sources.d`, so
    without this the install-time servers keep being polled alongside the
    ones the control plane set — two sets where the operator configured
    one, and the extra set invisible in the UI that appears to own NTP."""
    runner = (PARSER.parent / "spatiumddi-chrony-reload").read_text(encoding="utf-8")
    assert "spatium-install.sources" in runner
    assert "rm -f \"$INSTALL_SOURCES\"" in runner


def test_ntp_prefills_from_the_dhcp_lease():
    fn = extract_fn("ask_ntp")
    assert "_dhcp_ntp_servers" in fn
    probe = extract_fn("_dhcp_ntp_servers")
    assert "/run/chrony-dhcp" in probe, (
        "NetworkManager drops option-42 servers there and chrony already "
        "reads it, so it is both the least code and the most faithful "
        "answer"
    )


def test_an_empty_ntp_answer_is_a_choice():
    """Air-gapped site with a trusted RTC. Falling back to the pool the
    operator just declined would be the wrong kind of helpful."""
    fn = extract_fn("ask_ntp")
    assert 'if [ -z "$NTP_SERVERS" ]; then' in fn


# ── Item 18 — SSH keys ────────────────────────────────────────────────


def test_keys_are_validated_with_ssh_keygen():
    """A truncated paste is the common failure and a regex on the leading
    'ssh-' waves it through. A key sshd will not load is worse than no
    key: the operator believes they have access."""
    fn = extract_fn("_add_ssh_key")
    assert "ssh-keygen -l -f" in fn


def test_disabling_password_ssh_is_only_offered_with_a_key():
    """Otherwise an operator locks themselves out of a headless box in
    two keystrokes."""
    fn = extract_fn("ask_ssh_keys")
    i = fn.index("Disable password SSH?")
    assert '[ "$(_ssh_key_count)" -gt 0 ]' in fn[:i]


def test_a_bare_word_is_a_github_username_and_anything_odd_is_not():
    """Guessing would turn a typo'd URL into a request to github.com."""
    fn = extract_fn("ask_ssh_keys")
    assert 'https://github.com/$src.keys' in fn
    assert "*[!A-Za-z0-9-]*)" in fn


def test_the_key_lands_where_sshd_reads_it_and_is_owned_by_the_admin():
    assert '"$MOUNT/home/$ADMIN_USER/.ssh/authorized_keys"' in CODE
    assert 'chown -R "$ADMIN_USER:$ADMIN_USER"' in CODE
    assert "chmod 0700" in CODE and "chmod 0600" in CODE


def test_the_password_off_dropin_is_the_one_the_control_plane_manages():
    """So central SSH config later REPLACES this rather than fighting
    it."""
    assert "/etc/ssh/sshd_config.d/spatiumddi.conf" in CODE


# ── Preseed coverage for every new prompt ─────────────────────────────


@pytest.mark.parametrize(
    "marker", ["PRESEED_HAS_KEYMAP", "PRESEED_HAS_NTP", "PRESEED_HAS_SSH_KEYS"]
)
def test_every_new_prompt_can_be_preseeded(marker):
    """The project's own cross-cutting rule for this issue: a prompt with
    no preseed key makes a fully-unattended install impossible."""
    assert marker in CODE, f"{marker} is not consulted by the wizard"
    assert marker in PARSER.read_text(encoding="utf-8")


def test_disabling_password_ssh_headlessly_requires_a_key():
    """Refused, not warned: an unattended install that turns off password
    SSH with no key produces a headless box nobody can reach, and there
    is no operator at the console to notice."""
    body = PARSER.read_text(encoding="utf-8")
    # The first mention is the `known` key set at the top of the file.
    i = body.index('ssh_nopw = ps.get("ssh_disable_password")')
    assert "requires at least one" in body[i:i + 1400]



# ── The wizard loop itself (executable) ───────────────────────────────
#
# The old per-step `case` was pinned by substring assertions that passed
# on inverted routing. The replacement is a linear table plus a three-way
# return, which can be driven directly with stub screens — so these
# assert on where the wizard GOES, not on what the source says.


def _drive(script_steps: str, screens: dict[str, str]) -> list[str]:
    """Run main()'s loop with every screen stubbed. Returns the visit order."""
    body = extract_fn("main")
    loop = body[body.index("    local -a STEPS=("):body.rindex("}")]
    stubs = "\n".join(
        f'{name}() {{ echo "{name}" >&2; return {rc}; }}' for name, rc in screens.items()
    )
    script = f"""
set -uo pipefail
log() {{ :; }}
FULLY_UNATTENDED=0
CONFIRM_JUMP=""
{stubs}
{script_steps}
_loop() {{
{loop}
}}
_loop
"""
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    return [ln for ln in r.stderr.splitlines() if ln and not ln.startswith("+")]


_ALL = [
    "welcome", "preflight", "ask_keyboard", "ask_role", "pick_disk",
    "confirm_partition_layout", "ask_hostname", "ask_user_password",
    "ask_ssh_keys", "ask_network", "ask_timezone", "ask_ntp",
    "ask_k3s_cidrs", "ask_application_config", "confirm", "do_install",
]


def test_the_wizard_loop_walks_every_screen_forward():
    visited = _drive("", {n: 0 for n in _ALL})
    assert visited == _ALL, visited


def test_back_from_confirm_reaches_a_screen_that_actually_draws():
    """The bug: with a partial preseed the three screens before `confirm`
    are inert, so Back landed on one that returned 0 without drawing and
    was routed straight forward again — the confirm screen redrew on
    every press and the disk picker was unreachable, one keystroke from
    an irreversible wipe."""
    screens = {n: 0 for n in _ALL}
    # Inert: preseeded or inert-for-this-role.
    for n in ("ask_ntp", "ask_k3s_cidrs", "ask_application_config"):
        screens[n] = 2
    # confirm says Back once, then OK.
    screens["confirm"] = 1
    visited = _drive('_c=0\nconfirm() { echo confirm >&2; _c=$((_c+1)); [ "$_c" -ge 2 ] && return 0; return 1; }',
                     {k: v for k, v in screens.items() if k != "confirm"})
    # An inert screen is still CALLED — it just returns 2. What matters
    # is that the walk keeps going back through them and reaches
    # ask_timezone, the nearest screen that draws, before confirm redraws.
    after = visited[visited.index("confirm") + 1:]
    assert "ask_timezone" in after, visited
    assert after.index("ask_timezone") < after.index("confirm"), visited


def test_back_walks_through_a_run_of_inert_screens():
    screens = {n: 0 for n in _ALL}
    for n in ("ask_keyboard", "ask_role", "pick_disk", "confirm_partition_layout"):
        screens[n] = 2
    visited = _drive(
        '_h=0\nask_hostname() { echo ask_hostname >&2; _h=$((_h+1)); [ "$_h" -ge 2 ] && return 0; return 1; }',
        {k: v for k, v in screens.items() if k != "ask_hostname"},
    )
    after = visited[visited.index("ask_hostname") + 1:]
    assert "preflight" in after, visited
    # Back walks THROUGH the inert run rather than stopping in it...
    assert after.index("preflight") < after.index("ask_hostname"), visited
    # ...and every one of them is passed over on the way.
    for inert in ("confirm_partition_layout", "pick_disk", "ask_role", "ask_keyboard"):
        assert after.index(inert) < after.index("preflight"), (inert, visited)


def test_backing_past_the_first_screen_does_not_exit_or_loop():
    screens = {n: 0 for n in _ALL}
    for n in ("welcome", "preflight", "ask_keyboard"):
        screens[n] = 2
    visited = _drive(
        '_r=0\nask_role() { echo ask_role >&2; _r=$((_r+1)); [ "$_r" -ge 2 ] && return 0; return 1; }',
        {k: v for k, v in screens.items() if k != "ask_role"},
    )
    assert visited[-1] == "do_install", visited
    assert visited.count("ask_role") == 2, visited


def test_an_inert_screen_does_not_stop_forward_progress():
    screens = {n: 2 for n in _ALL if n != "do_install"}
    screens["do_install"] = 0
    assert _drive("", screens) == _ALL


def test_the_confirm_menu_jumps_straight_to_the_field():
    """#995 item 28. Back used to walk one screen at a time, so fixing the
    hostname from the last screen before a wipe meant pressing Back past
    four screens and OK through them again — on a serial console, at
    exactly the moment the operator has spotted something wrong."""
    screens = {n: 0 for n in _ALL}
    visited = _drive(
        '_c=0\n'
        'confirm() { echo confirm >&2; _c=$((_c+1)); '
        'if [ "$_c" = 1 ]; then CONFIRM_JUMP=ask_hostname; return 1; fi; return 0; }',
        {k: v for k, v in screens.items() if k != "confirm"},
    )
    after = visited[visited.index("confirm") + 1:]
    assert after[0] == "ask_hostname", visited
    # ...and straight BACK to confirm, not onward through the rest of the
    # wizard. Continuing forward was half the cost item 28 said it
    # removed: changing the hostname still meant OK-ing through the
    # password (typed twice — a passwordbox cannot be pre-filled), the
    # keys, the network and everything after.
    assert after[1] == "confirm", visited


def test_every_inert_path_in_the_real_screens_returns_2():
    """The guard the stubbed loop tests could not be.

    `_drive` stubs each screen with a return code the TEST chooses, so it
    pins the dispatcher and says nothing about the 13 hand-written return
    values it depends on. That is exactly how `pick_disk` and
    `confirm_partition_layout` shipped still returning 0 from their
    preseed short-circuit — reintroducing the #554 Back-bounce the whole
    three-way contract exists to kill, for any answer file that pins
    target_disk.

    So: read the real functions, find every early return that fires
    without drawing (a preseed short-circuit, an unattended skip, a
    role-inert screen), and require it to be `return 2`.
    """
    offenders = []
    for name in _ALL:
        if name in ("welcome", "do_install", "confirm"):
            continue  # driven by main() itself, not by a self-guard
        fn = extract_fn(name)
        lines = fn.splitlines()
        for n, line in enumerate(lines):
            code = line.split("#", 1)[0]
            if not re.search(
                r'\[ -n "\$\{PRESEED_HAS_\w+:-\}" \]|"\$FULLY_UNATTENDED" = "1"'
                r'|\[ "\$ROLE" = "appliance" \]|\[ "\$ROLE" != "appliance" \]',
                code,
            ):
                continue
            # The return that belongs to this guard: the next bare return
            # before the block closes.
            for follow in lines[n + 1:n + 8]:
                f = follow.strip().split("#", 1)[0].strip()
                if f.startswith("return "):
                    if f not in ("return 2",):
                        offenders.append(f"{name}: {line.strip()} -> {f}")
                    break
                if f in ("fi", "}"):
                    break
    assert not offenders, (
        "an inert screen returning 0 means 'the operator went forward', so "
        "a Back walk is bounced straight back:\n  " + "\n  ".join(offenders)
    )
