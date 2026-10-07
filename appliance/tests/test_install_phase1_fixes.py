"""Structural guards for the #995 Phase 1 installer fixes.

``do_install`` partitions a real disk as root and rsyncs the live rootfs,
so it is not unit-testable host-side — the rest of this suite deliberately
exercises only ``--check-preseed`` and pure helpers. What CAN be pinned is
the shape of the code, and for these five items the shape IS the bug:
each one was a swallowed failure, a stale string or a hardcoded constant,
and each regresses by someone re-adding exactly the token removed here.

The executable halves live next door — ``test_install_dm_scope.py``
(item 10) and ``test_install_field_validators.py`` (items 3 + 4).

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_install_phase1_fixes.py -v
"""

from __future__ import annotations

import re

from _installer_source import CODE, SRC, extract_fn as _fn


# ── Item 1 — the install logs survive the reboot ──────────────────────


def test_installer_logs_are_copied_to_the_target():
    fn = _fn("_save_install_logs")
    assert "/var/log/spatiumddi/install" in fn
    # All three of the diagnostics on_failure prints, or the set that
    # survives is not the set an operator is told to read.
    assert "$INSTALL_LOG" in fn
    assert "$TRACE_LOG" in fn
    assert "spatium-install-launch.log" in fn


def test_installer_logs_are_readable_by_the_api_uid():
    """0755/0644, matching every sibling in that directory.

    The first cut used 0700/0600, which is defensible in isolation and
    silently breaks the collector half of the same change: the api reads
    these through a read-only bind mount as uid 1000, with no fsGroup and
    no userns remap, so root-only modes make iterdir() raise
    PermissionError and the bundle ship an error note instead of the logs
    — on every appliance, forever. firstboot chmods the parent 0755 and
    logrotate creates the siblings 0644 for exactly this reason.
    """
    fn = _fn("_save_install_logs")
    assert "chmod 0755" in fn
    assert "chmod 0644" in fn
    assert "0700" not in fn and "0600" not in fn


def test_saving_logs_reports_what_actually_happened():
    """An unconditional success line is the last thing written to the log
    that is then not copied — so on a read-only /var it ends with a claim
    the WARNs above it disprove."""
    fn = _fn("_save_install_logs")
    assert "saved=$((saved + 1))" in fn
    assert 'if [ "$saved" -gt 0 ]; then' in fn


def test_logs_are_also_saved_on_the_failure_path():
    """The three fatal aborts this change introduced all sit UPSTREAM of
    the 94% success-path call, so without this the failures that most
    need a durable record are the ones that leave none — and the
    operator's natural next move re-runs the installer, whose startup
    truncates both logs."""
    fn = _fn("on_failure")
    assert "_save_install_logs" in fn
    # Guarded: the trap also fires from the wizard prompts, long before
    # anything is mounted.
    assert '[ -d "$MOUNT/var/log" ]' in fn


def test_saving_logs_cannot_abort_a_successful_install():
    """Runs under ``set -e`` after everything else has succeeded. A
    failure to save a log must not be the thing that fails the install."""
    fn = _fn("_save_install_logs")
    assert fn.rstrip().endswith("return 0\n}"), fn[-200:]


def test_logs_are_saved_before_the_target_is_unmounted():
    """Ordering is the property: the copy writes to $MOUNT/var, so it has
    to happen while /var is still mounted."""
    save = CODE.index("        _save_install_logs")
    unmount = CODE.index('echo "95"; echo "Unmounting')
    assert save < unmount, "the log copy must precede the unmount block"


def test_devnull_fallback_logs_are_not_copied():
    """INSTALL_LOG / TRACE_LOG fall back to /dev/null when /var/log is not
    writable (the #581 host-portable path). Copying that makes an empty
    file that reads as "the installer logged nothing"."""
    assert '[ "$src" = "/dev/null" ] && continue' in _fn("_save_install_logs")


# ── Item 2 — the UEFI grub-install failure is no longer swallowed ─────


def _grub_block() -> str:
    start = CODE.index("grub-install --target=i386-pc")
    end = CODE.index("Cloning root_A", start)
    return CODE[start:end]


def test_neither_grub_install_is_unconditionally_ignored():
    """Anchored on the grub-install invocations themselves.

    A blanket "no `|| true` in this block" was the first shape of this
    test and it is too broad: the boot-leg marker write is deliberately
    best-effort, and a failure to record a warning must not abort an
    install that otherwise succeeded.
    """
    blk = _grub_block()
    # Join backslash continuations first: the grub-install calls span
    # several physical lines, so a swallowed ``|| true`` would land on a
    # continuation that does not itself contain the word "grub-install".
    # That gap is exactly why the blanket "no swallow anywhere in this
    # block" assertion existed — but blanket also flags unrelated
    # best-effort lines (#999 added a `umount ... || true` for the mirror
    # member's ESP), so the rule is applied per INVOCATION instead: same
    # coverage, no false positive.
    logical = blk.replace("\\\n", " ")
    for line in logical.splitlines():
        if "grub-install" in line or "--bootloader-id" in line:
            assert "|| true" not in line, line


def test_both_firmware_modes_have_a_fatal_branch():
    blk = _grub_block()
    assert 'FIRMWARE_MODE" = "bios"' in blk
    assert 'FIRMWARE_MODE" = "uefi"' in blk
    # One abort per branch — the mode that did NOT boot this ISO stays
    # best-effort, because --removable and the ef02 partition mean either
    # install can legitimately fail on the other kind of machine.
    assert blk.count("exit 1") == 2, blk


def test_firmware_mode_comes_from_the_kernel_not_a_guess():
    assert "[ -d /sys/firmware/efi ]" in CODE


def test_firmware_mode_is_shown_before_the_wipe():
    assert "Booted:" in _fn("confirm")


# ── Item 4 — the useradd failure is no longer swallowed ───────────────


def test_useradd_is_fatal():
    i = CODE.index("useradd -m -G sudo")
    window = CODE[i - 200:i + 800]
    assert "|| true" not in window, (
        "PermitRootLogin is off, so a swallowed useradd leaves a box with "
        "no way in at all"
    )
    assert "exit 1" in window


# ── Items 5 / 6 / 7 — the screens say what is true ────────────────────


def _done_block() -> str:
    start = SRC.index("    local done_addr=")
    return SRC[start:SRC.index('Press OK to reboot."', start)]


def test_done_screen_advertises_https():
    blk = _done_block()
    assert "https://" in blk
    assert "http://<appliance IP>" not in blk, "the frontend 301s to https"


def test_done_screen_does_not_claim_images_are_pulled():
    """Baked into the rootfs since #170 Wave A4. An operator told they are
    being pulled goes hunting for a network fault that does not exist."""
    blk = _done_block()
    assert "pulls" not in blk
    assert "Nothing is downloaded." in blk


def test_done_screen_is_role_aware():
    blk = _done_block()
    assert 'if [ "$ROLE" = "appliance" ]' in blk
    assert "no web UI" in blk
    assert "CONTROL_PLANE_URL" in blk


def test_done_screen_offers_the_live_address_in_dhcp_mode():
    assert "ip -4 -br addr" in _done_block()


def test_both_operator_data_screens_are_sized_to_their_content():
    """An 80x24 serial console is a first-class install path here
    (spatium-console@ttyS0), newt clips rather than scrolls, and the
    longest line on each of these screens is operator-supplied — a
    control-plane URL, a /dev/disk/by-id target path. A hardcoded height
    is wrong exactly when the content is unusual."""
    # Confirm's review is a --yesno again since the menu split (#995
    # item 28's fix): the summary needs the full height, and the field
    # picker is a separate short screen that needs almost none.
    for screen in ('--msgbox "$done_body"', '--yesno "$s"'):
        i = SRC.index(screen)
        assert "_whiptail_height" in SRC[i:i + 120], screen


def test_the_height_helper_counts_wrapped_rows_and_clamps():
    fn = _fn("_whiptail_height")
    # fold, not `wc -l` on the raw body: whiptail re-wraps at ~width-4.
    assert "fold -s -w" in fn
    assert "stty size" in fn
    assert "term - 1" in fn


def test_the_done_msgbox_cannot_abort_a_successful_install():
    """whiptail returns 255 on ESC and `set -e` is still on, so without
    `|| true` an operator who dismisses the final screen with ESC aborts
    an install that already succeeded and never reaches the reboot."""
    i = SRC.index('--msgbox "$done_body"')
    assert "|| true" in SRC[i:i + 140]


def test_the_other_boot_leg_failing_is_surfaced_not_just_logged():
    """Confirm has by then already told the operator that leg was being
    installed too. A log line nobody reads does not retract it."""
    assert 'BOOT_LEG_WARNING=""' in SRC
    blk = _grub_block()
    # A FILE, because the whole install runs inside `{ … } | whiptail
    # --gauge` and the left side of a pipeline is a subshell — a variable
    # set there is discarded before the Done screen reads it. shellcheck
    # reports that as SC2030/SC2031, and did, about the first version.
    assert blk.count("$BOOT_LEG_MISSING_FILE") == 2
    assert "BOOT_LEG_WARNING=" not in blk, (
        "a variable assignment here is lost with the pipeline's subshell"
    )
    assert "BOOT_LEG_WARNING" in _done_block()
    # Cleared before the pipeline, or a previous attempt's marker makes
    # this run report a bootloader failure that did not happen.
    assert 'rm -f "$BOOT_LEG_MISSING_FILE"' in CODE


def test_an_unreleased_device_mapper_map_refuses_before_the_wipe():
    """`wipefs -af` FORCES — measured, it returns 0 on a disk held open by
    a live map, as does `sgdisk -Z`; only `blockdev --rereadpt` fails, and
    that is `|| true`. So nothing downstream catches an unreleased map:
    the GPT is destroyed, the kernel keeps the stale table, and mkfs
    writes at the old offsets. The refusal has to be explicit."""
    fn = _fn("_assert_target_released")
    assert "_dm_maps_on_target" in fn
    assert "exit 1" in fn
    gate = CODE.index("_assert_target_released")
    wipe = CODE.index('wipefs -af "$TARGET_DISK"')
    assert gate < wipe, "the release gate must run before the wipe"


def test_the_admin_account_is_checked_before_the_wipe_too():
    """useradd is fatal now, at ~63% — after the disk is wiped. The
    reserved-account list is a hand-written approximation that misses
    `_apt`; the live rootfs IS the target rootfs, so its own passwd
    database answers exactly, and keeps answering as packages change."""
    fn = _fn("_assert_admin_user_available")
    assert "getent passwd" in fn
    assert "preseed_halt" in fn, "an unattended run must halt loudly"
    call = CODE.index("    _assert_admin_user_available")
    wipe = CODE.index('wipefs -af "$TARGET_DISK"')
    assert call < wipe


def test_every_prefilled_inputbox_guards_against_a_leading_dash():
    """whiptail uses popt, so a default beginning with `-` is parsed as an
    option: it exits 1 without drawing anything, and the state machine
    reads that as Back. Since the value re-prefilled is the REJECTED one,
    the validate-and-retry loops turn that into an inescapable bounce."""
    bad = [
        ln.strip() for ln in SRC.splitlines()
        if "3>&1 1>&2 2>&3" in ln
        # The default is the LAST positional, immediately before the fd
        # shuffle. Anchoring on that rather than on "a $VAR after a number"
        # matters since the menus began computing their width: `20
        # "$_DISK_MENU_W" 10 ...` matched the looser pattern and reported
        # a pre-filled default on a dialog that has none.
        and re.search(r'\d+ +"\$[A-Za-z_][A-Za-z0-9_]*" +3>&1', ln)
        and " -- " not in ln
    ]
    assert not bad, bad


def test_one_resolver_for_the_preseed_parser():
    """Three spellings would let the linter and the wizard find the repo's
    parser while a real preseed load found the installed one."""
    assert CODE.count('parser="$(dirname "$0")/spatium-preseed-parse"') == 1
    assert "python3 /usr/local/bin/spatium-preseed-parse" not in CODE


def test_confirm_no_longer_promises_dns_and_dhcp_at_install():
    """Contradicted ask_role two screens earlier: since #272 both are off
    at install and enabled per node from the Fleet UI."""
    fn = _fn("confirm")
    assert "api + db + DNS + DHCP" not in fn
    assert "DNS + DHCP stay OFF" in fn


def test_the_retired_application_role_name_is_gone():
    """#170 Wave B retired it; ask_role says "Additional node"."""
    assert "Application install" not in SRC
    assert "Application appliance" not in SRC


def test_welcome_lists_every_question_the_wizard_asks():
    fn = _fn("welcome")
    assert "First node / Additional node" in fn
    assert "CIDR" in fn
    assert "pairing code" in fn


# ── Item 8 — the backtitle is the version you booted ──────────────────


def test_backtitle_is_not_hardcoded():
    assert "SpatiumDDI Appliance Installer 0.1.0" not in SRC
    assert 'BACKTITLE="SpatiumDDI Appliance Installer ${_INSTALLER_VERSION' in SRC


def test_the_version_is_parsed_in_exactly_one_place():
    """do_install reads the same value back out of the rsynced copy to
    label the grub menuentries; two awk blocks could disagree about which
    build this is."""
    # One awk parse of the stamp (#1182 generalised it to any key, so the
    # clock check's BUILD_TIME goes through the same reader).
    assert CODE.count("awk -F= -v key=") == 1, "one awk parse, not several"
    assert CODE.count("_release_field() {") == 1
    assert CODE.count("_appliance_version_from() {") == 1
    # Nobody reads the release file except through the helper.
    #
    # Continuations are joined first: do_install passes the path on the
    # line AFTER the call, and a per-line scan reports that argument as an
    # unmediated read of the file.
    joined = CODE.replace("\\\n", " ")
    direct = [
        ln.strip()
        for ln in joined.splitlines()
        if "spatiumddi/appliance-release" in ln
        and "_appliance_version_from" not in ln
        and "_release_field" not in ln
        and "date -r" not in ln  # the mtime fallback, which wants the path itself
    ]
    assert not direct, direct
