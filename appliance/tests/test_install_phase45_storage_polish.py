"""#995 Phases 4 + 5 — storage hazards, reinstall, and polish (23-30).

Phase 4's headline items (a RAID1 install, a multipath install) need
mdadm / multipath-tools in the image and initramfs work that is NOT here
— see APPLIANCE.md. What IS here is the half that removes the trap: the
picker used to offer each PATH of a SAN LUN as a separate disk and let
you install to one of them, which is worse than unsupported because it
looks like it worked.

  23  refuse an md member          27  live rsync progress
  24  collapse multipath paths     28  Confirm is a menu of fields
  25  reinstall keeping /var       29  export the answers as a preseed
  26  stable disk identity         30  post-install verification

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_install_phase45_storage_polish.py -v
"""

from __future__ import annotations

import re

from _installer_source import CODE, extract_fn

# ── Items 23 + 24 — the trap ──────────────────────────────────────────


def test_a_multipath_path_is_refused_not_merely_unlisted():
    """Installing to one path of a LUN gives the installed system no
    failover, and nothing afterwards says so."""
    fn = extract_fn("_disk_hazard")
    assert "mpath" in fn
    assert "no failover" in fn


def test_an_md_member_is_refused():
    fn = extract_fn("_disk_hazard")
    assert "holders/md" in fn


def test_the_hazard_check_runs_before_the_size_check():
    """A multipath path is not made acceptable by being big enough."""
    fn = extract_fn("pick_disk")
    assert fn.index("_disk_hazard \"$TARGET_DISK\"") < fn.index("DISK_BYTES=$(blockdev")


def test_hazardous_disks_are_marked_not_hidden():
    """A hidden disk reads as a missing disk; a marked one explains
    itself — and the operator can see that the installer noticed."""
    fn = extract_fn("pick_disk")
    assert "[UNSUPPORTED]" in fn


def test_the_paths_of_one_lun_are_collapsed():
    """Otherwise the same LUN is offered three or four times."""
    fn = extract_fn("pick_disk")
    assert "seen_wwn" in fn
    assert "_disk_wwn" in fn


# ── Items 25 + 26 — reinstall and identity ────────────────────────────


def test_reinstall_keeping_var_is_offered_only_on_a_reusable_layout():
    """A partial or foreign layout must take the full wipe, not a guess
    about which partition is which."""
    fn = extract_fn("pick_disk")
    assert "_layout_is_reusable" in fn
    assert "_existing_install_version" in fn


def test_the_layout_check_goes_by_identity_not_partition_number():
    """All five parts of the layout are found by identity, so a disk
    carrying them at other indices is still reusable.

    ``assert "LABEL" in fn`` was the original form, and by #1045 the only
    uppercase ``LABEL`` left in the function was in its own comments — so
    the guard passed on prose while the code it describes had changed
    underneath it. It now asserts on the calls, and on there being no
    partition NUMBER, which is the property the name claims.
    """
    fn = extract_fn("_layout_is_reusable")
    code = "\n".join(ln.split("#", 1)[0] for ln in fn.splitlines())
    for part in ("ESP", "state", "var"):
        assert part in code, part
    # ESP / state / var by filesystem label; the two OS slots by GPT name,
    # which a slot upgrade cannot overwrite (#1045).
    assert "_labelled_device_on" in code
    for slot in ("root_a", "root_b"):
        assert slot in code, slot
    assert "_slot_device_on" in code
    assert not re.search(r"\$\{?dev\}?[0-9]|partition_node", code), (
        "the check must not reach for a partition number"
    )


def test_keeping_var_skips_the_partition_table_and_the_two_filesystems():
    """Repartitioning would destroy the very thing the operator asked to
    keep, and STATE carries the machine identity."""
    i = CODE.index("Reusing the existing partition table")
    guard = CODE.rindex('if [ "$KEEP_VAR" = "yes" ]; then', 0, i)
    # wipefs/sgdisk are inside the else, i.e. after the guard.
    assert CODE.index('wipefs -af "$TARGET_DISK"') > guard
    # state + var are guarded; the two OS slots are not.
    fmt = CODE[CODE.index('mkfs.fat -F32 -n ESP'):CODE.index('echo "15"')]
    # Walk the guard depth line by line: state and var must be inside a
    # KEEP_VAR guard, the two OS slots outside it (they are replaced
    # either way).
    # A STACK, not a counter. The counter form only incremented on a
    # KEEP_VAR ``if`` while decrementing on every ``fi``, so any other
    # conditional in the region (#999 added the mirror's second ESP
    # mkfs) drove the depth negative and reported every label at the
    # wrong level — the test failing for a reason unrelated to what it
    # is pinning.
    stack: list[bool] = []
    seen = {}
    for line in fmt.splitlines():
        t = line.strip()
        if t.startswith("if ") or t.startswith("elif "):
            if t.startswith("elif "):
                if stack:
                    stack[-1] = 'KEEP_VAR" != "yes"' in t
            else:
                stack.append('KEEP_VAR" != "yes"' in t)
            continue
        if t == "fi":
            if stack:
                stack.pop()
            continue
        for label in ("state", "var", "root_a", "root_b"):
            if t.startswith(f"mkfs.ext4 -F -L {label} "):
                seen[label] = 1 if any(stack) else 0
    assert seen == {"state": 1, "root_a": 0, "root_b": 0, "var": 1}, seen


def test_the_stable_disk_name_is_resolved_recorded_and_shown():
    """sdX is assigned in discovery order and #581 already notes it can
    move between the picker and the wipe."""
    fn = extract_fn("_disk_by_id")
    assert "wwn-" in fn, "prefer the name that survives a controller change"
    assert "usb-" in fn, "skip the least stable link"
    assert "-part[0-9]" in fn, "a partition link is not the disk"
    assert "TARGET_DISK_BY_ID=$(_disk_by_id" in CODE
    assert 'target_disk_by_id: "$TARGET_DISK_BY_ID"' in CODE
    assert "$TARGET_DISK_BY_ID" in extract_fn("confirm")


def test_confirm_says_reinstall_when_var_is_kept():
    """"will be ERASED" is false, and it is the sentence the operator is
    reading when they decide."""
    fn = extract_fn("confirm")
    assert "REINSTALL" in fn
    assert "/var and STATE are KEPT" in fn


# ── Item 27 — the progress bar ────────────────────────────────────────


def test_rsync_feeds_the_gauge():
    assert "--info=progress2" in CODE
    # The rsync lives in _copy_live_root (#2256); do_install pipes it into
    # the gauge loop, so read the block that follows that call.
    i = CODE.index("        _copy_live_root \\")
    blk = CODE[i:i + 1400]
    # A bash read loop, NOT awk. Debian ships mawk, which buffers its
    # input on a non-newline RS and block-buffers its output to a pipe —
    # measured, every gauge block arrived in one burst at rsync's EOF and
    # the bar stayed frozen at 20%, which is the symptom item 27 exists
    # to remove.
    assert "awk" not in blk, "mawk buffers this into uselessness"
    assert "read -r -d $'\\r'" in blk
    # \r, not \n: --info=progress2 rewrites one line...
    assert '|| [ -n "$_line" ]' in blk, "...so a final unterminated record is not dropped"
    # Only on a change, or the gauge protocol is flooded.
    assert '[ "$_g" = "$_last" ] && continue' in blk


# ── Item 28 — Confirm is a menu ───────────────────────────────────────


def test_confirm_offers_a_row_per_field_with_install_last_in_intent():
    fn = extract_fn("confirm")
    assert "--menu" in fn
    for step in ("pick_disk", "ask_hostname", "ask_network", "ask_timezone",
                 "ask_ntp", "ask_keyboard", "ask_role", "ask_ssh_keys"):
        assert f'"{step}"' in fn, step
    # Never the accidental default: --default-item is the install row, but
    # the row itself is spelled so a misfire is obvious.
    assert "*** INSTALL" in fn


def test_a_jump_goes_forward_from_the_chosen_screen():
    """Executable coverage lives in test_install_phase3_screens.py; this
    pins that the loop honours the variable at all."""
    assert "CONFIRM_JUMP" in extract_fn("confirm")
    blk = CODE[CODE.index('if [ -n "$CONFIRM_JUMP" ]; then'):]
    blk = blk[:blk.index("esac")]
    # An unknown step must fail visibly, not leave `i` unassigned and
    # redraw confirm with the selection silently discarded.
    assert 'log "BUG: confirm menu named an unknown step' in blk
    assert "RETURN_TO_CONFIRM" in blk


# ── Item 29 — export the answers ──────────────────────────────────────


def test_the_exported_preseed_carries_no_secrets():
    """It is world-readable on STATE and is meant to be copied off the
    box."""
    i = CODE.index('cat > "$STATE_MNT/spatium-preseed.yaml"')
    blk = CODE[i:CODE.index('chmod 0644 "$STATE_MNT/spatium-preseed.yaml"')]
    for secret in ("ADMIN_PASSWORD", "BOOTSTRAP_PAIRING_CODE", "pairing_code"):
        assert secret not in blk, secret
    assert "admin_password" not in blk.replace("# admin_password", "")


def test_the_export_prefers_the_stable_disk_name():
    i = CODE.index('cat > "$STATE_MNT/spatium-preseed.yaml"')
    blk = CODE[i:i + 1400]
    assert "/dev/disk/by-id/" in blk


def test_the_export_does_not_emit_v6_keys_the_parser_refuses():
    """The parser rejects ip6/prefix6/gateway6 under mode: dhcp, so an
    ungated export produces a file that cannot be linted — which is the
    entire point of exporting it."""
    i = CODE.index('cat > "$STATE_MNT/spatium-preseed.yaml"')
    blk = CODE[i:i + 1800]
    j = blk.index("NET6EOF")
    assert '[ "$NET_MODE" = "static" ]' in blk[:j]


# ── Item 30 — post-install verification ───────────────────────────────


def test_the_install_is_verified_before_it_is_called_done():
    # Scoped to the verify block. Against whole-file CODE four of these
    # six tokens occur elsewhere, so deleting the checks they stand for
    # left this test green — coverage that was fictional for two thirds
    # of item 30.
    blk = CODE[CODE.index("        _verify() {"):CODE.index("Saving installer logs to the target")]
    assert "verify_fail" in blk
    for check in ("EFI/BOOT/$_EFI_REMOVABLE", "grub.cfg", "grub-script-check",
                  "saved_entry=slot_a", "spatium-config.yaml", "root_B"):
        assert check in blk, check
    # #1026 — the ESP-bootloader check is parameterised now, because the
    # removable-media filename is per-architecture (UEFI §3.5.1.1). This
    # test used to pin the x86 literal ``BOOTX64.EFI``, which reported a
    # correct arm64 install as POST-INSTALL CHECKS FAILED on the one
    # screen whose job is to say whether the reboot is safe.
    #
    # Pinning the variable alone would let it be defined as the empty
    # string, so both spellings are asserted too: the check is only
    # meaningful if it resolves to a real filename on both.
    assert '_EFI_REMOVABLE="BOOTAA64.EFI"' in CODE
    assert '_EFI_REMOVABLE="BOOTX64.EFI"' in CODE


def test_verification_failures_survive_the_gauge_subshell():
    """The whole install runs inside `{ … } | whiptail --gauge`, so a
    variable set there is discarded before the Done screen reads it — the
    same trap shellcheck caught on BOOT_LEG_MISSING_FILE."""
    assert "VERIFY_FAIL_FILE=/run/" in CODE
    assert '[ -s "$VERIFY_FAIL_FILE" ]' in CODE


def test_verification_warns_rather_than_aborts():
    """The install IS complete. An operator who sees "the ESP has no
    bootloader" before rebooting is far better off than one who reboots
    into a grub prompt."""
    i = CODE.index("Verifying the installed system")
    blk = CODE[i:CODE.index("Saving installer logs to the target")]
    assert "exit 1" not in blk
    assert "POST-INSTALL CHECKS FAILED" in CODE


def test_the_verify_helper_takes_arguments_not_a_string_to_eval():
    """eval on a quoted expression is both a footgun and the reason
    shellcheck cannot see inside it."""
    i = CODE.index("        _verify() {")
    blk = CODE[i:CODE.index("Saving installer logs to the target")]
    assert "eval" not in blk
    assert 'if ! "$@" >/dev/null 2>&1; then' in blk
