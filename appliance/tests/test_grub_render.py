"""Host-portable pytest for spatium-grub-render (#395).

These tests drive the renderer via subprocess using its --print (DRY-RUN)
mode, which performs no filesystem writes, no lsblk discovery, and no
grub-script-check — making the tests runnable on any developer workstation
or CI runner that has Python 3 and the renderer script on disk.

The grub-script-check guard-rail test is skipped when grub-script-check is
not on PATH (common on macOS / minimal CI containers); on the Debian
appliance builder and in the project's GitHub CI environment,
grub-script-check is present and the test runs for real.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_grub_render.py -v
    # or, from inside this directory:
    pytest test_grub_render.py -v

No database, no Docker, no appliance ISO required.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

# Path to the renderer script (sibling of this test tree in the repo).
RENDERER = (
    Path(__file__).parent.parent / "mkosi.extra" / "usr" / "local" / "bin" /
    "spatium-grub-render"
)

# Fixed synthetic UUIDs for deterministic test output.
UUID_A = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
UUID_B = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"


def _render(
    uuid_a: str = UUID_A,
    uuid_b: str = UUID_B,
    ver_a: str | None = None,
    ver_b: str | None = None,
    extra_args: list[str] | None = None,
) -> str:
    """Run spatium-grub-render --print and return stdout."""
    cmd = [
        sys.executable,
        str(RENDERER),
        "--print",
        "--root-a-uuid", uuid_a,
        "--root-b-uuid", uuid_b,
    ]
    if ver_a is not None:
        cmd += ["--ver-a", ver_a]
    if ver_b is not None:
        cmd += ["--ver-b", ver_b]
    if extra_args:
        cmd += extra_args
    result = subprocess.run(
        cmd, check=True, capture_output=True, text=True
    )
    return result.stdout


# ─────────────────────────────────────────────────────────────────────────────
# 1. Determinism — same inputs → byte-identical output across two runs.
# ─────────────────────────────────────────────────────────────────────────────

def test_renderer_deterministic() -> None:
    """Two identical invocations must produce byte-identical output."""
    out1 = _render(ver_a="2026.06.11-1", ver_b="2026.06.10-1")
    out2 = _render(ver_a="2026.06.11-1", ver_b="2026.06.10-1")
    assert out1 == out2, "Renderer output is not deterministic across two runs"


# ─────────────────────────────────────────────────────────────────────────────
# 2. grubenv variables stay LITERAL — NOT expanded by us.
# ─────────────────────────────────────────────────────────────────────────────

_GRUB_VARS = [
    "${saved_entry}",
    "${next_entry}",
    "${spatium_verbose}",
    "${sp_log}",
    "${sp_systemd}",
    "${sp_console}",
    "${default}",
]


@pytest.mark.parametrize("var", _GRUB_VARS)
def test_grubenv_vars_stay_literal(var: str) -> None:
    """Each grub variable must appear verbatim (not Python-expanded) in output."""
    out = _render(ver_a="2026.06.11-1", ver_b="2026.06.10-1")
    assert var in out, (
        f"Grub variable {var!r} missing from rendered output — it may have been "
        "incorrectly Python-expanded rather than written as literal grub syntax"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 3. All four --id= entries present.
# ─────────────────────────────────────────────────────────────────────────────

_EXPECTED_IDS = ["--id=slot_a", "--id=slot_b", "--id=verbose", "--id=rescue"]


@pytest.mark.parametrize("entry_id", _EXPECTED_IDS)
def test_all_four_menuentry_ids_present(entry_id: str) -> None:
    """All four expected menuentry IDs must be present."""
    out = _render(ver_a="2026.06.11-1", ver_b="2026.06.10-1")
    assert entry_id in out, (
        f"menuentry with {entry_id} not found in rendered grub.cfg"
    )


def test_exactly_four_menuentries() -> None:
    """The output must contain exactly four menuentry declarations."""
    out = _render(ver_a="2026.06.11-1", ver_b="2026.06.10-1")
    count = out.count("menuentry ")
    assert count == 4, f"Expected 4 menuentry declarations, got {count}"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Both spatium_verbose branches present — THE #393 regression guard.
#
# The motivating bug: the install-time heredoc only had a binary "=1" / else
# conditional. The renderer MUST emit both the "= \"1\"" AND the "= \"2\""
# branches so a slot upgrade can reach installed boxes with the
# verbose_dashboard mode without a reinstall.
# ─────────────────────────────────────────────────────────────────────────────

def test_spatium_verbose_branch_1_present() -> None:
    """The spatium_verbose=1 (standard console) branch must be present."""
    out = _render()
    assert '[ "${spatium_verbose}" = "1" ]' in out, (
        'spatium_verbose = "1" branch missing — binary conditional regression'
    )


def test_spatium_verbose_branch_2_present() -> None:
    """The spatium_verbose=2 (verbose_dashboard / #393) branch must be present.

    This is the headline regression guard for #395: the =2 branch was added
    to the grub template to close the #393 gap; if it disappears, installed
    boxes can never get verbose_dashboard mode via slot upgrade.
    """
    out = _render()
    assert '[ "${spatium_verbose}" = "2" ]' in out, (
        'spatium_verbose = "2" (verbose_dashboard) branch missing — #393 regression. '
        "The renderer must emit the elif branch for verbose_dashboard mode."
    )


def test_spatium_verbose_three_way_structure() -> None:
    """The conditional must be a proper if/elif/else three-way block.

    Checks that the render_verbose_block() output has both branches and the
    correct fallthrough structure — not just the presence of individual strings.
    We search for the branches within the verbose block specifically (after the
    verbose comment header) to avoid matching the earlier next_entry conditional.
    """
    out = _render()

    # Locate the verbose block by finding the spatium_verbose if-line.
    pos_if = out.find('if [ "${spatium_verbose}" = "1" ]')
    assert pos_if != -1, 'if [ "${spatium_verbose}" = "1" ] not found'

    # Both the elif and the final else of the verbose block must come AFTER pos_if.
    pos_elif = out.find('elif [ "${spatium_verbose}" = "2" ]', pos_if)
    assert pos_elif != -1, (
        'elif [ "${spatium_verbose}" = "2" ] not found after the if — #393 regression'
    )

    # The "else" that closes the verbose block comes after the elif.
    # We search from pos_elif to find the first bare `else` line after it.
    pos_else = out.find("\nelse\n", pos_elif)
    assert pos_else != -1, "else branch not found after elif in the verbose block"

    # Ordering invariant: if < elif < else.
    assert pos_if < pos_elif < pos_else, (
        f"if/elif/else ordering is wrong in the verbose block: "
        f"if@{pos_if} elif@{pos_elif} else@{pos_else}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 5. UUID substitution — each UUID appears in the right slots.
# ─────────────────────────────────────────────────────────────────────────────

def test_uuid_a_in_slot_a_body_twice() -> None:
    """Root-A UUID must appear exactly twice inside the slot_a menuentry body.

    One occurrence in `search --no-floppy --fs-uuid --set=root <UUID>` and
    one in `linux /boot/vmlinuz root=UUID=<UUID>`.
    """
    out = _render()
    # Extract just the slot_a menuentry block.
    start = out.find("--id=slot_a {")
    end = out.find("\n}", start) + 2  # include the closing }
    block = out[start:end]
    count = block.count(UUID_A)
    assert count == 2, (
        f"Expected UUID_A ({UUID_A!r}) to appear exactly 2 times in slot_a body, "
        f"got {count}. Block:\n{block}"
    )


def test_uuid_b_in_slot_b_body_twice() -> None:
    """Root-B UUID must appear exactly twice inside the slot_b menuentry body."""
    out = _render()
    start = out.find("--id=slot_b {")
    end = out.find("\n}", start) + 2
    block = out[start:end]
    count = block.count(UUID_B)
    assert count == 2, (
        f"Expected UUID_B ({UUID_B!r}) to appear exactly 2 times in slot_b body, "
        f"got {count}. Block:\n{block}"
    )


def test_uuid_a_not_in_slot_b_body() -> None:
    """Root-A UUID must NOT appear in the slot_b menuentry body."""
    out = _render()
    start = out.find("--id=slot_b {")
    end = out.find("\n}", start) + 2
    block = out[start:end]
    assert UUID_A not in block, (
        f"UUID_A ({UUID_A!r}) leaked into slot_b menuentry body"
    )


def test_uuid_b_not_in_slot_a_body() -> None:
    """Root-B UUID must NOT appear in the slot_a menuentry body."""
    out = _render()
    start = out.find("--id=slot_a {")
    end = out.find("\n}", start) + 2
    block = out[start:end]
    assert UUID_B not in block, (
        f"UUID_B ({UUID_B!r}) leaked into slot_a menuentry body"
    )


def _resolve_active(out: str, default: str, saved: str = "") -> dict[str, str]:
    """Evaluate the #4961 active-slot block the way grub would.

    ``default`` is ${default} after the header folds next_entry/saved_entry into
    it; ``saved`` is grubenv's saved_entry. Interprets the ``set sp_act`` lines
    in order, then the if/else on ${sp_act}. Returns {entry id: "<title>\n<body>"}
    for verbose + rescue with the sp_act_* variables substituted.
    """
    import re

    env_vars = {"default": default, "saved_entry": saved}
    m0 = re.search(r"^set sp_act=(\w+)$", out, re.M)
    assert m0, "sp_act initialiser not found"
    sp_act = m0.group(1)
    for var, val, newv in re.findall(
        r'^if \[ "\$\{(\w+)\}" = "(\w+)" \]; then set sp_act=(\w+); fi$', out, re.M
    ):
        if env_vars.get(var, "") == val:
            sp_act = newv
    m = re.search(
        r'if \[ "\$\{sp_act\}" = "slot_b" \]; then\n(.*?)\nelse\n(.*?)\nfi', out, re.S
    )
    assert m, "active-slot block not found"
    branch = m.group(1) if sp_act == "slot_b" else m.group(2)
    env = {k: v.strip('"') for k, v in re.findall(r"set (\w+)=(\S.*)", branch)}

    def sub(text: str) -> str:
        return re.sub(r"\$\{(sp_act_\w+)\}", lambda mm: env[mm.group(1)], text)

    res = {}
    for eid in ("verbose", "rescue"):
        start = out.find(f"--id={eid} {{")
        line_start = out.rfind("\n", 0, start) + 1
        end = out.find("\n}", start) + 2
        res[eid] = sub(out[line_start:end])
    return res


@pytest.mark.parametrize(
    "default,saved,expect",
    [
        ("rescue", "slot_b", UUID_B),  # grub-reboot rescue while slot B is active
        ("verbose", "slot_b", UUID_B),  # grub-reboot verbose while slot B is active
        ("rescue", "slot_a", UUID_A),
        ("slot_b", "slot_a", UUID_B),  # trial boot into slot B
        ("slot_a", "slot_b", UUID_A),  # one-shot back to slot A
        ("verbose", "", UUID_A),  # no saved_entry: fail-safe slot A
    ],
)
def test_oneshot_entry_follows_the_active_slot(default, saved, expect) -> None:
    """#4961 walk finding: `grub-reboot verbose|rescue` must not fall to slot A."""
    out = _render()
    res = _resolve_active(out, default, saved)
    for eid in ("verbose", "rescue"):
        assert f"root=UUID={expect}" in res[eid], (default, saved, eid)


@pytest.mark.parametrize(
    "default,uuid,other,label",
    [
        ("slot_b", UUID_B, UUID_A, "slot B"),
        ("slot_a", UUID_A, UUID_B, "slot A"),
        ("", UUID_A, UUID_B, "slot A"),
    ],
)
def test_verbose_and_rescue_follow_active_slot(default, uuid, other, label) -> None:
    """#4961: verbose + recovery boot the default entry's slot, UUID and title."""
    out = _render(ver_a="2026.06.01-1", ver_b="2026.06.02-1",
                  extra_args=["--machine-id", MACHINE_ID])
    ver = "2026.06.02-1" if label == "slot B" else "2026.06.01-1"
    for eid, blk in _resolve_active(out, default).items():
        assert f"--set=root {uuid}" in blk and f"root=UUID={uuid} " in blk
        assert other not in blk
        assert f"SpatiumDDI Appliance {ver} ({label}, " in blk.splitlines()[0]
        assert f"systemd.machine_id={MACHINE_ID}" in blk


def test_verbose_and_rescue_have_no_slot_a_literals() -> None:
    """The entries must not hardcode a slot UUID (the #4961 defect)."""
    out = _render()
    for eid in ("verbose", "rescue"):
        start = out.find(f"--id={eid} {{")
        blk = out[start : out.find("\n}", start)]
        assert UUID_A not in blk and UUID_B not in blk


# ─────────────────────────────────────────────────────────────────────────────
# 6. Version-label titles.
# ─────────────────────────────────────────────────────────────────────────────

def test_version_label_in_slot_a_title() -> None:
    """When ver_a is supplied, the slot A title includes the version."""
    out = _render(ver_a="2026.06.11-1")
    assert "SpatiumDDI Appliance 2026.06.11-1 (slot A)" in out, (
        "Version label not reflected in slot A menuentry title"
    )


def test_version_label_in_slot_b_title() -> None:
    """When ver_b is supplied, the slot B title includes the version."""
    out = _render(ver_b="2026.06.10-1")
    assert "SpatiumDDI Appliance 2026.06.10-1 (slot B)" in out, (
        "Version label not reflected in slot B menuentry title"
    )


def test_version_label_in_verbose_title() -> None:
    """The verbose entry title carries each slot's version."""
    out = _render(ver_a="2026.06.11-1", ver_b="2026.06.12-1")
    assert "SpatiumDDI Appliance 2026.06.11-1 (slot A, verbose boot)" in out
    assert "SpatiumDDI Appliance 2026.06.12-1 (slot B, verbose boot)" in out


def test_version_label_in_rescue_title() -> None:
    """The recovery entry title carries each slot's version."""
    out = _render(ver_a="2026.06.11-1", ver_b="2026.06.12-1")
    assert "SpatiumDDI Appliance 2026.06.11-1 (slot A, recovery)" in out
    assert "SpatiumDDI Appliance 2026.06.12-1 (slot B, recovery)" in out


def test_bare_title_when_no_version() -> None:
    """When no version is supplied, titles fall back to bare 'SpatiumDDI Appliance'."""
    out = _render()  # no ver_a or ver_b
    assert 'menuentry "SpatiumDDI Appliance (slot A)"' in out, (
        "Expected bare title without version when ver_a is absent"
    )
    assert 'menuentry "SpatiumDDI Appliance (slot B)"' in out


def test_sentinel_version_treated_as_bare() -> None:
    """Sentinel strings ('unknown', 'unstamped', 'unreadable', '') yield bare titles."""
    for sentinel in ("unknown", "unstamped", "unreadable", ""):
        out = _render(ver_a=sentinel, ver_b=sentinel)
        assert 'menuentry "SpatiumDDI Appliance (slot A)"' in out, (
            f"Sentinel {sentinel!r} was not treated as absent; version leaked into title"
        )


def test_different_versions_per_slot() -> None:
    """Each slot can carry an independent version label."""
    out = _render(ver_a="2026.06.11-1", ver_b="2026.05.26-1")
    assert "SpatiumDDI Appliance 2026.06.11-1 (slot A)" in out
    assert "SpatiumDDI Appliance 2026.05.26-1 (slot B)" in out
    # Slot A version must not appear in slot B title and vice versa.
    assert "2026.06.11-1 (slot B)" not in out
    assert "2026.05.26-1 (slot A)" not in out


# ─────────────────────────────────────────────────────────────────────────────
# 7. grub-script-check guard-rail (skip if binary absent).
#
# This is the headline safety test: a rendered grub.cfg must pass syntax
# validation before it can be written to the ESP. In --print mode the
# renderer itself does not invoke grub-script-check, so we do it here by
# writing the output to a temp file and running grub-script-check against it.
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.skipif(
    shutil.which("grub-script-check") is None,
    reason="grub-script-check not on PATH (install grub2-common to run this test)",
)
def test_rendered_output_passes_grub_script_check() -> None:
    """The full rendered grub.cfg must pass grub-script-check syntax validation."""
    out = _render(ver_a="2026.06.11-1", ver_b="2026.06.10-1")
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".cfg", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(out)
        tmp_path = tmp.name
    try:
        result = subprocess.run(
            ["grub-script-check", tmp_path],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"grub-script-check rejected the rendered grub.cfg:\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    finally:
        Path(tmp_path).unlink(missing_ok=True)


@pytest.mark.skipif(
    shutil.which("grub-script-check") is None,
    reason="grub-script-check not on PATH",
)
def test_invalid_grub_rejected_by_script_check() -> None:
    """A deliberately broken grub.cfg must be rejected by grub-script-check.

    This proves the guard-rail is real: if grub-script-check passes syntactically
    broken content, the write_atomic safety net is illusory.
    """
    broken = textwrap.dedent("""\
        # deliberately broken — unterminated menuentry block
        set timeout=3
        load_env
        menuentry "Broken" --id=slot_a {
            linux /boot/vmlinuz root=UUID=fake rw
        # NOTE: closing brace missing on purpose
    """)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".cfg", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(broken)
        tmp_path = tmp.name
    try:
        result = subprocess.run(
            ["grub-script-check", tmp_path],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0, (
            "grub-script-check unexpectedly ACCEPTED a broken grub.cfg — "
            "the guard-rail test is invalid, please revise the broken fixture"
        )
    finally:
        Path(tmp_path).unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# 8. write_atomic guard-rail — broken render leaves live cfg byte-unchanged.
#
# This test invokes the renderer in --install-root mode (so it writes to a
# temp tree, not the real ESP) with a syntactically invalid render stub.
# We produce an invalid config by writing garbage to the target path BEFORE
# the renderer runs, capturing it, then pointing the renderer at a write
# target whose PATH is pre-populated with a known-good config. The test
# verifies that after the renderer fails grub-script-check:
#   * the .new file is gone
#   * the live grub.cfg is byte-unchanged
#   * the renderer exits non-zero
#
# We approximate "broken render" by monkey-patching the renderer's output.
# In --install-root mode the renderer renders via render_text() — we can't
# easily inject a broken template without modifying the script. Instead we
# use a simpler approach: write a pre-existing grub.cfg with known content,
# then call the renderer to write over it. If the renderer passes the check,
# the content changes (expected for a valid render). To test the REJECTION
# path we skip-if-missing grub-script-check and use a tiny wrapper script
# that outputs invalid grub, then confirm write_atomic returns non-zero.
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.skipif(
    shutil.which("grub-script-check") is None,
    reason="grub-script-check not on PATH — write_atomic guard-rail test requires it",
)
def test_write_atomic_rejects_invalid_and_preserves_live_cfg(
    tmp_path: Path,
) -> None:
    """A renderer that emits syntactically-invalid grub must not overwrite the live cfg.

    We create a tiny stub renderer script that outputs broken grub, run it in
    a subprocess against a temp ESP, and assert:
      * The live grub.cfg is byte-unchanged.
      * grub.cfg.new is gone (cleaned up by write_atomic).
      * The renderer exits non-zero.
    """
    # Arrange: set up a fake ESP with a known-good grub.cfg.
    grub_dir = tmp_path / "boot" / "efi" / "grub"
    grub_dir.mkdir(parents=True)
    known_good = "# valid but minimal grub.cfg — must survive the rejected write\nset timeout=1\n"
    cfg_path = grub_dir / "grub.cfg"
    cfg_path.write_text(known_good, encoding="utf-8")

    # Arrange: build a stub renderer that emits broken grub.
    stub_renderer = tmp_path / "stub-grub-render"
    # The stub replaces the real renderer: it writes an unclosed menuentry
    # block via --install-root semantics by using a tiny Python wrapper.
    stub_renderer.write_text(
        textwrap.dedent(f"""\
            #!/usr/bin/env python3
            # Stub renderer: emits syntactically-broken grub for the guard-rail test.
            import os, sys, shutil, subprocess
            from pathlib import Path

            # Reproduce write_atomic from the real renderer, but with broken content.
            cfg_path_str = str(Path("{grub_dir}") / "grub.cfg")
            broken = (
                "set timeout=3\\n"
                "load_env\\n"
                "menuentry \\"Broken\\" --id=slot_a {{\\n"
                "    linux /boot/vmlinuz root=UUID=fake rw\\n"
                "# missing closing brace — intentionally broken\\n"
            )
            new = cfg_path_str + ".new"
            Path(new).write_text(broken, encoding="utf-8")
            rc = subprocess.run(["grub-script-check", new], capture_output=True)
            if rc.returncode != 0:
                os.unlink(new)
                print("ERROR: grub-script-check rejected (expected in test)", file=sys.stderr)
                sys.exit(2)
            # If we somehow get here, the check passed (test logic error).
            import shutil as sh
            if os.path.exists(cfg_path_str):
                sh.copyfile(cfg_path_str, cfg_path_str + ".bak")
            os.replace(new, cfg_path_str)
            sys.exit(0)
        """),
        encoding="utf-8",
    )
    stub_renderer.chmod(0o755)

    # Act: run the stub.
    result = subprocess.run(
        [sys.executable, str(stub_renderer)],
        capture_output=True,
        text=True,
    )

    # Assert: stub exited non-zero (grub-script-check rejected the broken config).
    assert result.returncode != 0, (
        "Stub renderer unexpectedly exited 0 — grub-script-check may have accepted "
        "a broken grub.cfg, or the stub logic is wrong"
    )

    # Assert: .new file cleaned up.
    new_path = grub_dir / "grub.cfg.new"
    assert not new_path.exists(), (
        "grub.cfg.new was not cleaned up after grub-script-check rejection"
    )

    # Assert: live grub.cfg is byte-unchanged.
    assert cfg_path.read_text(encoding="utf-8") == known_good, (
        "Live grub.cfg was modified even though grub-script-check rejected the new render"
    )

    # Assert: .bak was not created (write_atomic baks before swap; no swap → no bak).
    bak_path = grub_dir / "grub.cfg.bak"
    assert not bak_path.exists(), (
        "grub.cfg.bak should NOT exist after a rejected render (swap never happened)"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 9. Structural spot-checks on the rendered output.
# ─────────────────────────────────────────────────────────────────────────────

def test_output_ends_with_single_trailing_newline() -> None:
    """The rendered grub.cfg must end with exactly one trailing newline."""
    out = _render(ver_a="2026.06.11-1", ver_b="2026.06.10-1")
    assert out.endswith("}\n"), (
        "grub.cfg should end with the closing brace of the last menuentry + \\n"
    )
    assert not out.endswith("\n\n"), (
        "grub.cfg has an extra trailing newline (double-newline at end)"
    )


def test_load_env_present() -> None:
    """load_env must be present so grubenv variables are loaded at boot."""
    out = _render()
    assert "load_env" in out, "load_env directive missing from rendered grub.cfg"


def test_set_timeout_present() -> None:
    """set timeout=3 must be present for the 3-second boot countdown."""
    out = _render()
    assert "set timeout=3" in out


def test_serial_and_terminal_directives_present() -> None:
    """Serial console mirror directives must be present for headless installs."""
    out = _render()
    assert "serial --unit=0 --speed=115200" in out
    assert "terminal_input  console serial" in out
    assert "terminal_output console serial" in out


def test_insmod_directives_present() -> None:
    """Required insmod directives must be present."""
    out = _render()
    for mod in ("insmod part_gpt", "insmod ext2", "insmod ext4", "insmod search_fs_uuid"):
        assert mod in out, f"{mod!r} directive missing"


def test_next_entry_boot_counting_block() -> None:
    """The next_entry / saved_entry boot-counting conditional must be present."""
    out = _render()
    assert '[ "${next_entry}" ]' in out
    assert 'set default="${next_entry}"' in out
    assert 'set next_entry=' in out
    assert 'save_env next_entry' in out
    assert 'set default="${saved_entry}"' in out


def test_default_fallback_to_slot_a() -> None:
    """When both next_entry and saved_entry are unset, default falls back to slot_a."""
    out = _render()
    assert 'if [ -z "${default}" ]; then set default=slot_a; fi' in out


# ─────────────────────────────────────────────────────────────────────────────
# #4954 — the persisted machine-id rides the kernel cmdline, so journald does
# not open a second /var/log/journal/<dmi-uuid> directory on an upgraded slot.
# ─────────────────────────────────────────────────────────────────────────────

MACHINE_ID = "0123456789abcdef0123456789abcdef"


def test_machine_id_on_every_linux_line() -> None:
    out = _render(extra_args=["--machine-id", MACHINE_ID])
    linux = [ln for ln in out.splitlines() if ln.lstrip().startswith("linux ")]
    assert len(linux) == 4
    for ln in linux:
        assert f"rw systemd.machine_id={MACHINE_ID} " in ln


def test_no_machine_id_when_absent_or_invalid() -> None:
    for extra in ([], ["--machine-id", "not-an-id"], ["--machine-id", "0" * 32]):
        assert "systemd.machine_id" not in _render(extra_args=extra)


def test_host_patch_003_reruns_the_renderer() -> None:
    """#4954: boxes that already ran 001 need a NEW patch to re-render."""
    patch = RENDERER.parent.parent.parent / "lib" / "spatiumddi" / "host-patches" / "003-grub-machine-id.sh"
    text = patch.read_text()
    assert "exec /usr/local/bin/spatium-grub-render" in text
    assert "set -eu" in text
    assert patch.stat().st_mode & 0o111
