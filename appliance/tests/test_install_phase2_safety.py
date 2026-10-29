"""#995 Phase 2 — the four safety items (11-14).

Phase 1 fixed things that were wrong. Phase 2 changes what the installer
ACCEPTS, which is a different kind of risk: each of these can refuse an
install that used to succeed, so each one's refusal boundary is pinned
here alongside the thing it was meant to catch.

  11  password policy — a floor that refuses, and advice that does not
  12  root is locked unless the operator opts in
  13  the control-plane URL is probed before the disk is wiped
  14  no CIDR screen, and no CIDR drop-in, for an Additional node

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_install_phase2_safety.py -v
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from _installer_source import CODE, SRC, extract_fn


def check_pw(pw: str, user: str = "netops", host: str = "spatium-cp-1"):
    """Run the shared password validator the way the wizard does.

    Value on STDIN, never argv: argv is readable through /proc and lands
    in shell history, and this is the one field where that matters.
    """
    from _installer_source import PARSER

    return subprocess.run(
        [sys.executable, str(PARSER), "--check-field", "admin_password", "-", user, host],
        input=pw,
        capture_output=True,
        text=True,
    )


# ── Item 11 — password policy ─────────────────────────────────────────


@pytest.mark.parametrize(
    "pw,why",
    [
        ("", "empty"),
        ("short", "under the 8-character floor"),
        ("1234567", "one under the floor"),
        ("netops", "equals the username"),
        ("NETOPS", "equals the username, case-insensitively"),
        ("spatium-cp-1", "equals the hostname"),
    ],
)
def test_refused_passwords(pw, why):
    r = check_pw(pw)
    assert r.returncode == 2, f"{pw!r} should be refused ({why}): {r.stdout}"
    assert r.stdout.strip()


@pytest.mark.parametrize(
    "pw,why",
    [
        ("password", "in every breach list"),
        ("aaaaaaaaaa", "one distinct character"),
        ("abababababab", "two distinct characters"),
        ("lowercaseonly", "a single character class"),
    ],
)
def test_weak_passwords_are_advised_not_refused(pw, why):
    """The floor refuses; past it, the operator decides.

    A prompt that refuses a merely-weak password is one an operator
    routes around with something worse they can retype — or abandons for
    the night with the disk half-wiped. Exit 0 with text on stdout is the
    "allowed, but" channel.
    """
    r = check_pw(pw)
    assert r.returncode == 0, f"{pw!r} must not be refused ({why})"
    assert r.stdout.strip(), f"{pw!r} should have produced advice ({why})"


@pytest.mark.parametrize("pw", ["Tr0ub4dor&3x", "correct horse battery x", "8charsss1"])
def test_good_passwords_pass_silently(pw):
    r = check_pw(pw)
    assert r.returncode == 0, r.stdout
    assert r.stdout == "", f"{pw!r} should need no comment, got {r.stdout!r}"


def test_a_password_is_exactly_eight_characters_of_leeway():
    """Pins the boundary itself, so a future edit to the constant is a
    deliberate change rather than an accident."""
    assert check_pw("1234567").returncode == 2
    assert check_pw("12345678").returncode == 0


def test_whitespace_is_content_in_a_password():
    """admin_user gets .strip()ped so the two doors agree; a password must
    not be, or the installer sets one thing and the operator types
    another at the console."""
    r = check_pw("  spaced  pw  ")
    assert r.returncode == 0, r.stdout


def test_the_password_never_travels_in_argv():
    fn = extract_fn("_check_field_stdin")
    assert "--check-field" in fn and '"$kind" -' in fn
    # ...and the prompt uses the stdin variant, not the argv one.
    pw_fn = extract_fn("ask_user_password")
    assert "_check_field_stdin admin_password" in pw_fn
    assert "_check_field admin_password" not in pw_fn


def test_a_refusal_reprompts_and_advice_asks():
    """Different handling, or the "allowed, but" channel is pointless."""
    fn = extract_fn("ask_user_password")
    assert "Password not accepted" in fn      # hard refusal → msgbox → loop
    assert "Use it anyway" in fn              # advisory → yes/no
    assert "--defaultno" in fn


# ── Item 12 — root is locked by default ───────────────────────────────


def test_root_is_locked_unless_the_operator_opts_in():
    assert 'SET_ROOT_PASSWORD="no"' in CODE, "the default must be no"
    i = CODE.index("passwd -l root")
    window = CODE[i - 400:i + 200]
    assert '"$SET_ROOT_PASSWORD" != "yes"' in window


def test_the_root_prompt_defaults_to_leaving_it_locked():
    fn = extract_fn("ask_user_password")
    i = fn.index("Root account")
    assert "--defaultno" in fn[i - 300:i + 300], "a blind Enter must not set it"


def test_both_password_paths_honour_the_opt_in():
    """The plaintext and the crypt(3)-hash branches both used to set root
    unconditionally."""
    i = CODE.index("chpasswd -e")
    window = CODE[i - 300:i + 900]
    assert window.count('"$SET_ROOT_PASSWORD" = "yes"') == 2


def test_the_choice_is_recorded_in_state():
    """So `spatium-state` and a support bundle can explain why root has no
    password, rather than it reading as damage."""
    assert 'root_password_set: "$SET_ROOT_PASSWORD"' in CODE


# ── Item 13 — the control plane is probed before the wipe ─────────────


def test_the_probe_asks_for_the_version_document():
    """Not a reachability ping: the question is "is that MY control
    plane", and a typo landing on another host's web server answers a
    ping perfectly well."""
    fn = extract_fn("_probe_control_plane")
    assert "/api/v1/version" in fn
    # ONE matcher: the extraction's empty result IS the "not a version
    # document" verdict, so there is no second test to disagree with it.
    assert '"version"' in fn, "a 200 from anything else must not pass"
    assert "no version string" in fn
    assert "--max-time" in fn and "--connect-timeout" in fn
    # -L because the appliance frontend 301s http -> https and the
    # supervisor this predicts follows redirects for that reason.
    assert "-fsSL" in fn


def test_the_probe_accepts_the_anonymous_handshake():
    """#2935 — an anonymous caller (this probe has no credential) gets
    ``"product": "SpatiumDDI"`` and no version string, so matching on the
    version alone would call every current control plane the wrong host.
    The version match stays for an older control plane that still sends it."""
    fn = extract_fn("_probe_control_plane")
    assert '"product"' in fn and "SpatiumDDI" in fn
    assert '[ -z "$product" ] && [ -z "$ver" ]' in fn


def _probe(body: str) -> str:
    """Run the shipped probe against a stubbed curl that answers ``body``."""
    import shlex

    fn = extract_fn("_probe_control_plane")
    script = (
        f"curl() {{ printf '%s' {shlex.quote(body)}; return 0; }}\n"
        f"{fn}\n"
        '_probe_control_plane https://cp.example; echo " rc=$?"'
    )
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True).stdout


@pytest.mark.parametrize(
    "body, verdict",
    [
        # What a current control plane tells an anonymous caller (#2935):
        # the placeholder is not presented as a version.
        (
            '{"product":"SpatiumDDI","api_level":1,"restricted":true,"version":"restricted"}',
            "SpatiumDDI control plane rc=0",
        ),
        # Without the placeholder, the product name alone still matches.
        (
            '{"product":"SpatiumDDI","api_level":1,"restricted":true,"version":null}',
            "SpatiumDDI control plane rc=0",
        ),
        # An older control plane, which still sent the version anonymously.
        ('{"version":"2026.10.02-1","latest_version":null}', "SpatiumDDI 2026.10.02-1 rc=0"),
        # Somebody else's web server.
        ("<html><body>It works!</body></html>", "rc=1"),
        ('{"product":"SomethingElse","version":null}', "rc=1"),
    ],
)
def test_the_probe_verdicts(body: str, verdict: str) -> None:
    out = _probe(body).strip()
    assert out.endswith(verdict), out


def test_the_probe_reports_curls_own_error():
    """DNS failure, refused, TLS and timeout need different fixes, and
    curl already distinguishes them."""
    fn = extract_fn("_probe_control_plane")
    assert "curl exited" in fn or "${body:-" in fn


def test_an_unreachable_control_plane_offers_all_three_ways_out():
    fn = extract_fn("ask_application_config")
    for choice in ("retry", "edit", "continue"):
        assert f'"{choice}"' in fn, choice
    assert "Nothing has been written to disk yet" in fn


def test_continuing_past_an_unreachable_control_plane_is_logged():
    fn = extract_fn("ask_application_config")
    assert "Operator continued past an unreachable control plane" in fn


def test_the_pairing_code_is_not_probed():
    """It can only be validated by claiming it, and an unauthenticated
    "is this code valid" endpoint would be an oracle for guessing eight
    digits."""
    fn = extract_fn("_probe_control_plane")
    assert "pairing" not in fn.lower()
    assert "BOOTSTRAP_PAIRING_CODE" not in fn


# ── Item 14 — an Additional node pins no CIDRs ────────────────────────


def test_the_cidr_screen_is_skipped_for_an_additional_node():
    fn = extract_fn("ask_k3s_cidrs")
    head = fn.split('log "Step: ask_k3s_cidrs"', 1)[0]
    assert '[ "$ROLE" = "appliance" ]' in head
    # 2, not 0 — "I drew nothing", so Back walks past instead of being
    # bounced forward. See the state-machine test in phase3.
    assert "return 2" in head


def test_no_cidr_dropin_is_written_for_an_additional_node():
    """The screen being skipped is not enough: the drop-in was written
    unconditionally, and a drop-in that disagrees with the cluster a node
    later joins makes `k3s server --server` refuse to start."""
    i = CODE.index("spatium-cidrs.yaml")
    window = CODE[i - 700:i + 1200]
    assert 'rm -f "$MOUNT/etc/rancher/k3s/config.yaml.d/spatium-cidrs.yaml"' in window
    assert 'if [ "$ROLE" = "appliance" ]; then' in window


def test_confirm_does_not_advertise_cidrs_that_will_not_be_applied():
    fn = extract_fn("confirm")
    i = fn.index("K3s pod CIDR")
    assert '"$ROLE" != "appliance"' in fn[i - 300:i]


def test_back_navigation_is_not_a_per_step_case_any_more():
    """The routing that produced the bounce is gone.

    The old machine named each step's Back target by hand, so it had to
    know which neighbours were inert — and got it wrong the moment a
    partial preseed made a screen inert at runtime rather than by role.
    The executable test of the replacement lives in
    test_install_phase3_screens.py::test_the_wizard_loop_*.
    """
    assert 'local -a STEPS=(' in CODE
    assert 'dir="back"' in CODE
    # Three-way: 0 forward, 1 Back, 2 drew nothing.
    assert '2) if [ "$dir" = "back" ]; then' in CODE

# ── A class, not an item ──────────────────────────────────────────────


def test_no_backticks_inside_an_unquoted_heredoc():
    """`cat > f <<EOF` expands its body; `<<'EOF'` does not.

    So a backtick in what looks like a comment inside an unquoted heredoc
    is COMMAND SUBSTITUTION. Item 12 added a prose reference to
    ``spatium-state`` in the STATE-config heredoc, and spatium-state is a
    real command on the appliance — bash would have run it at install
    time and spliced its output into the YAML the boot-time renderer
    parses. shellcheck reports it as SC2006, which reads like a style
    note and is not one here.
    """
    import re

    lines = SRC.splitlines()
    offenders, inside, term = [], False, None
    for n, line in enumerate(lines, 1):
        if inside:
            if line.strip() == term:
                inside = False
            elif "`" in line:
                offenders.append(f"L{n}: {line.strip()[:70]}")
            continue
        m = re.search(r"<<-?(['\"]?)([A-Za-z_]+)\1", line)
        # A quoted delimiter disables expansion, so backticks are inert.
        if m and not m.group(1):
            inside, term = True, m.group(2)
    assert not offenders, "\n".join(offenders)
