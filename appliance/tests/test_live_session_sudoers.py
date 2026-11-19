"""The live ISO's session sudoers rule no longer reaches an installed system.

The ISO boots ``boot=live components``, so Debian live-config runs every
component under /lib/live/config. Its ``0040-sudo`` component writes
``/etc/sudoers.d/live`` (``user ALL=(ALL) NOPASSWD: ALL``) on every live
boot, and ``spatium-install`` copied the live root — that file included —
onto the target and then into ``/usr/lib/etc.image``, the /etc overlay
lower of both slots.

Four layers, each tested here:

* ``mkosi.postinst`` removes live-config's account components
  (``0030-user-setup``, ``0030-live-debconfig_passwd``, ``0040-sudo``), so
  the live session never writes the rule;
* the installer's live-root rsync excludes the rule and live-config's
  markers, and ``do_install`` removes them from the target before the
  /etc baseline snapshot;
* ``spatium-etc-reconcile`` removes the rule from installs that already
  carry it — only when the file holds exactly that one line;
* ``user`` and ``debian`` are refused as the admin username by both the
  shared validator and the installer's pre-flight.

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_live_session_sudoers.py -v
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from _installer_source import BIN, PARSER, extract_fn

APPLIANCE = Path(__file__).parent.parent
POSTINST = APPLIANCE / "mkosi.postinst"
EXTRA = APPLIANCE / "mkosi.extra"
RECONCILE = BIN / "spatium-etc-reconcile"
BASH = shutil.which("bash")
RSYNC = shutil.which("rsync")

LIVE_LINE = "user ALL=(ALL) NOPASSWD: ALL"
COMPONENTS = ("0030-user-setup", "0030-live-debconfig_passwd", "0040-sudo")


def _code(text: str) -> str:
    return "\n".join(ln.split("#", 1)[0] for ln in text.splitlines())


# ── mkosi.postinst: the live session never writes the rule ─────────────


def _run_postinst_block(buildroot: Path) -> subprocess.CompletedProcess:
    """Run only the live-config block of mkosi.postinst against a stub root.

    The whole hook creates units, chmods files and edits configs a stub
    root does not have, so the block is sliced out by its ``for`` loop.
    """
    src = POSTINST.read_text(encoding="utf-8")
    m = re.search(r"^for live_cfg_dir in .*?^done$", src, re.MULTILINE | re.DOTALL)
    assert m, "mkosi.postinst no longer removes live-config's account components"
    script = f'set -eu\nBUILDROOT="{buildroot}"\n{m.group(0)}\n'
    return subprocess.run(["sh", "-c", script], capture_output=True, text=True)


def test_postinst_removes_the_live_config_account_components(tmp_path):
    cfg = tmp_path / "usr" / "lib" / "live" / "config"
    cfg.mkdir(parents=True)
    for name in (*COMPONENTS, "0020-hostname", "0170-openssh-server"):
        (cfg / name).write_text("#!/bin/sh\n")
    # usrmerge: /lib -> usr/lib, as on trixie.
    (tmp_path / "lib").symlink_to("usr/lib")

    p = _run_postinst_block(tmp_path)
    assert p.returncode == 0, p.stderr
    left = sorted(f.name for f in cfg.iterdir())
    assert left == ["0020-hostname", "0170-openssh-server"], left


def test_postinst_block_is_a_noop_without_live_config(tmp_path):
    """An image without live-config must still build."""
    p = _run_postinst_block(tmp_path)
    assert p.returncode == 0, p.stderr


def test_the_boot_line_or_postinst_keeps_the_sudo_component_off():
    """Either the boot line restricts live-config's components, or the
    image does not carry the account components at all. Today it is the
    second; the guard accepts either so the mechanism can move."""
    wrap = (APPLIANCE / "scripts" / "wrap-iso.sh").read_text(encoding="utf-8")
    boot_restricts = re.search(r"live-config\.components=|components=[a-z]", wrap)
    postinst = _code(POSTINST.read_text(encoding="utf-8"))
    removes_all = all(name in postinst for name in COMPONENTS) and "rm -f" in postinst
    assert boot_restricts or removes_all


# ── shipped tree: nothing grants passwordless sudo ─────────────────────


def test_no_shipped_file_grants_passwordless_sudo():
    offenders = []
    for path in EXTRA.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if "NOPASSWD" in line.split("#", 1)[0]:
                offenders.append(f"{path.relative_to(APPLIANCE)}:{n}")
    # The cleanup step names the line it removes; that is a match
    # pattern, not a grant.
    offenders = [
        o
        for o in offenders
        if not o.startswith("mkosi.extra/usr/local/bin/spatium-etc-reconcile:")
    ]
    assert not offenders, offenders


def test_the_image_ships_no_sudoers_d_file_but_the_readme():
    d = EXTRA / "etc" / "sudoers.d"
    if not d.exists():
        return
    extra = sorted(p.name for p in d.iterdir() if p.name != "README")
    assert not extra, extra


# ── installer: the rule never reaches the target ──────────────────────


@pytest.mark.skipif(BASH is None or RSYNC is None, reason="bash + rsync required")
def test_live_root_copy_leaves_the_session_rule_behind(tmp_path):
    """Real rsync, the shipped excludes, a fake live root."""
    src = tmp_path / "live"
    (src / "etc" / "sudoers.d").mkdir(parents=True)
    (src / "etc" / "sudoers.d" / "live").write_text(LIVE_LINE + "\n")
    (src / "etc" / "sudoers.d" / "README").write_text("readme\n")
    (src / "var" / "lib" / "live" / "config").mkdir(parents=True)
    (src / "var" / "lib" / "live" / "config" / "sudo").write_text("")
    (src / "var" / "lib" / "other").mkdir(parents=True)
    (src / "var" / "lib" / "other" / "keep").write_text("x")
    dest = tmp_path / "target"
    dest.mkdir()
    log = tmp_path / "install.log"
    # -aAXH asks for ACLs / xattrs / ownership; an unprivileged runner
    # cannot set ownership, so rsync is wrapped to drop -AX and add
    # --no-owner --no-group without touching the exclude list.
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "rsync").write_text(
        "#!/bin/sh\n"
        'first="$1"; shift\n'
        f'exec {RSYNC} -rlptH --no-owner --no-group "$@"\n'
    )
    (bindir / "rsync").chmod(0o755)
    script = textwrap.dedent(f"""
        set -e -o pipefail
        export PATH="{bindir}:$PATH"
        INSTALL_LOG="{log}"
        MOUNT="{dest}"
        LIVE_ROOT_SRC="{src}/"
        log() {{ echo "$*" >> "$INSTALL_LOG"; }}
        {extract_fn("_copy_live_root")}
        _copy_live_root > /dev/null
        """)
    p = subprocess.run([BASH, "-c", script], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr + (log.read_text() if log.exists() else "")
    assert (dest / "etc" / "sudoers.d" / "README").is_file()
    assert not (dest / "etc" / "sudoers.d" / "live").exists()
    assert not (dest / "var" / "lib" / "live" / "config").exists()
    assert (dest / "var" / "lib" / "other" / "keep").is_file()


def test_do_install_removes_the_rule_before_the_etc_baseline_snapshot():
    body = _code(extract_fn("do_install"))
    rm = body.find('rm -f "$MOUNT/etc/sudoers.d/live"')
    markers = body.find('rm -rf "$MOUNT/var/lib/live/config"')
    snap = body.find('cp -a "$MOUNT/etc/." "$MOUNT/usr/lib/etc.image/"')
    assert rm != -1, "do_install no longer removes /etc/sudoers.d/live"
    assert markers != -1, "do_install no longer removes live-config's markers"
    assert snap != -1, "the /etc baseline snapshot moved; re-check the order"
    assert rm < snap and markers < snap


# ── spatium-etc-reconcile: existing installs ───────────────────────────


def _reconcile():
    loader = importlib.machinery.SourceFileLoader(
        "spatium_etc_reconcile", str(RECONCILE)
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _layout(tmp_path: Path, content: str | None, markers: bool = True):
    etc = tmp_path / "etc"
    (etc / "sudoers.d").mkdir(parents=True)
    if content is not None:
        (etc / "sudoers.d" / "live").write_text(content)
    state = tmp_path / "var" / "lib" / "live" / "config"
    if markers:
        state.mkdir(parents=True)
        (state / "sudo").write_text("")
        (state / "hostname").write_text("")
    return etc, state


@pytest.mark.parametrize("content", [LIVE_LINE + "\n", LIVE_LINE])
def test_reconcile_removes_the_exact_live_rule(tmp_path, content):
    mod = _reconcile()
    etc, state = _layout(tmp_path, content)
    removed = mod.remove_live_session_sudoers(etc, state)
    assert not (etc / "sudoers.d" / "live").exists()
    assert not state.exists()
    assert str(etc / "sudoers.d" / "live") in removed
    assert str(state) in removed


@pytest.mark.parametrize(
    "content",
    [
        "netops ALL=(ALL) NOPASSWD: ALL\n",
        LIVE_LINE + "\nnetops ALL=(ALL) ALL\n",
        "# operator\n" + LIVE_LINE + "\n",
        "",
    ],
)
def test_reconcile_keeps_a_file_with_other_content(tmp_path, content):
    mod = _reconcile()
    etc, state = _layout(tmp_path, content, markers=False)
    removed = mod.remove_live_session_sudoers(etc, state)
    assert (etc / "sudoers.d" / "live").read_text() == content
    assert removed == []


def test_reconcile_missing_file_is_a_noop(tmp_path):
    mod = _reconcile()
    etc, state = _layout(tmp_path, None, markers=False)
    assert mod.remove_live_session_sudoers(etc, state) == []


def test_reconcile_main_logs_what_it_removed(tmp_path, monkeypatch, caplog):
    mod = _reconcile()
    etc, state = _layout(tmp_path, LIVE_LINE + "\n")
    lower = tmp_path / "lower"
    upper = tmp_path / "upper"
    lower.mkdir()
    upper.mkdir()
    monkeypatch.setattr(mod, "LOWER", lower)
    monkeypatch.setattr(mod, "UPPER", upper)
    monkeypatch.setattr(mod, "ETC", etc)
    monkeypatch.setattr(mod, "LIVE_CONFIG_STATE", state)
    # main() calls basicConfig; let caplog see the records anyway.
    caplog.set_level("INFO")
    assert mod.main([]) == 0
    assert not (etc / "sudoers.d" / "live").exists()
    msgs = " ".join(r.getMessage() for r in caplog.records)
    assert "removed live-session leftover" in msgs
    assert str(etc / "sudoers.d" / "live") in msgs


# ── admin username: reserved by the live installer ─────────────────────


def _check(value: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(PARSER), "--check-field", "admin_user", value],
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize("name", ["user", "debian"])
def test_validator_reserves_live_installer_names(name):
    r = _check(name)
    assert r.returncode == 2, r.stdout + r.stderr
    assert "reserved by the live installer" in r.stdout


@pytest.mark.parametrize("name", ["users", "netops", "debian1"])
def test_validator_still_accepts_neighbouring_names(name):
    r = _check(name)
    assert r.returncode == 0, r.stdout + r.stderr


def _preflight(tmp_path: Path, name: str) -> subprocess.CompletedProcess:
    log = tmp_path / "install.log"
    script = textwrap.dedent(f"""
        INSTALL_LOG="{log}"
        ADMIN_USER="{name}"
        FULLY_UNATTENDED=1
        BACKTITLE=t
        log() {{ echo "$*" >> "$INSTALL_LOG"; }}
        getent() {{ return 2; }}
        preseed_halt() {{ echo "HALT: $*"; exit 7; }}
        {extract_fn("_assert_admin_user_available")}
        _assert_admin_user_available
        echo PASSED
        """)
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True)


@pytest.mark.skipif(BASH is None, reason="bash required")
@pytest.mark.parametrize("name", ["user", "debian"])
def test_preflight_reserves_live_installer_names(tmp_path, name):
    p = _preflight(tmp_path, name)
    assert p.returncode == 7, p.stdout + p.stderr
    assert "reserved by the live installer" in p.stdout


@pytest.mark.skipif(BASH is None, reason="bash required")
def test_preflight_accepts_an_ordinary_name(tmp_path):
    p = _preflight(tmp_path, "netops")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "PASSED" in p.stdout


def test_both_validators_reserve_the_same_names():
    parser = PARSER.read_text(encoding="utf-8")
    m = re.search(r"_LIVE_INSTALLER_USERS = \{([^}]*)\}", parser)
    assert m
    names = set(re.findall(r'"([^"]+)"', m.group(1)))
    fn = _code(extract_fn("_assert_admin_user_available"))
    in_bash = set(re.findall(r'"\$ADMIN_USER" = "([^"]+)"', fn))
    assert names == in_bash == {"user", "debian"}


# ── both slots: the whiteout in the shared upper (before etc.mount) ────
#
# Installers before this change put the rule in /usr/lib/etc.image of
# BOTH slots. A slot upgrade replaces one slot's lower and leaves the
# other's, so the merged-view removal above cannot reach the slot that is
# not running, and a rollback brings the rule back. The pre-mount step
# writes an overlay whiteout into the upper both slots share.

_FAKE_WHITEOUT = "<overlay whiteout>\n"


def _fake_whiteouts(monkeypatch, mod):
    """An unprivileged runner cannot mknod a character device, so stand
    a marker file in for the whiteout. The real mknod is exercised by
    test_real_whiteout_device when the runner can create one."""

    def make(path):
        Path(path).write_text(_FAKE_WHITEOUT)

    def is_wo(path):
        p = Path(path)
        return p.is_file() and p.read_text() == _FAKE_WHITEOUT

    monkeypatch.setattr(mod, "_make_whiteout", make)
    monkeypatch.setattr(mod, "_is_whiteout", is_wo)
    return is_wo


def _merged_has(rel: str, lower: Path, upper: Path, is_wo) -> str | None:
    """What an overlay of ``upper`` over ``lower`` shows at ``rel``."""
    u = upper / rel
    if os.path.lexists(u):
        return None if is_wo(u) else u.read_text()
    lo = lower / rel
    return lo.read_text() if lo.is_file() else None


def _slot_lower(root: Path, with_rule: bool) -> Path:
    lower = root / "usr" / "lib" / "etc.image"
    (lower / "sudoers.d").mkdir(parents=True)
    (lower / "sudoers.d" / "README").write_text("readme\n")
    if with_rule:
        (lower / "sudoers.d" / "live").write_text(LIVE_LINE + "\n")
    return lower


def test_rollback_after_upgrade_does_not_bring_the_rule_back(tmp_path, monkeypatch):
    """Upgrade then rollback: the old slot's lower still holds the rule."""
    mod = _reconcile()
    is_wo = _fake_whiteouts(monkeypatch, mod)
    old_lower = _slot_lower(tmp_path / "root_A", with_rule=True)
    new_lower = _slot_lower(tmp_path / "root_B", with_rule=False)
    upper = tmp_path / "persist" / "etc"
    upper.mkdir(parents=True)
    rel = "sudoers.d/live"

    # Before the upgrade: the old slot shows the rule.
    assert _merged_has(rel, old_lower, upper, is_wo) == LIVE_LINE + "\n"

    # First boot of the new slot: pre-mount step against ITS lower.
    assert mod.before_mount(upper, new_lower, tmp_path / "etc-not-mounted") == 0
    assert _merged_has(rel, new_lower, upper, is_wo) is None

    # Rollback: the old slot mounts the same upper over its own lower.
    assert _merged_has(rel, old_lower, upper, is_wo) is None
    # README still merges through from either lower.
    assert (upper / "sudoers.d").is_dir()
    assert _merged_has("sudoers.d/README", old_lower, upper, is_wo) == "readme\n"


def test_premount_is_idempotent_and_logs(tmp_path, monkeypatch, caplog):
    mod = _reconcile()
    _fake_whiteouts(monkeypatch, mod)
    lower = _slot_lower(tmp_path / "root", with_rule=False)
    upper = tmp_path / "upper"
    upper.mkdir()
    caplog.set_level("INFO")
    mod.before_mount(upper, lower, tmp_path / "etc")
    assert "created an overlay whiteout" in caplog.text
    first = (upper / "sudoers.d" / "live").read_text()
    caplog.clear()
    mod.before_mount(upper, lower, tmp_path / "etc")
    assert caplog.text == ""
    assert (upper / "sudoers.d" / "live").read_text() == first


def test_premount_new_upper_dir_copies_the_lower_dir_mode(tmp_path, monkeypatch):
    mod = _reconcile()
    _fake_whiteouts(monkeypatch, mod)
    lower = _slot_lower(tmp_path / "root", with_rule=False)
    os.chmod(lower / "sudoers.d", 0o750)
    upper = tmp_path / "upper"
    upper.mkdir()
    mod.before_mount(upper, lower, tmp_path / "etc")
    assert (upper / "sudoers.d").stat().st_mode & 0o777 == 0o750


@pytest.mark.parametrize(
    "content",
    ["netops ALL=(ALL) ALL\n", LIVE_LINE + "\nnetops ALL=(ALL) ALL\n", ""],
)
def test_premount_keeps_an_operator_file_in_the_upper(tmp_path, monkeypatch, content):
    """Case 5: the operator's own file lives in the upper and survives,
    over either slot's lower."""
    mod = _reconcile()
    is_wo = _fake_whiteouts(monkeypatch, mod)
    old_lower = _slot_lower(tmp_path / "root_A", with_rule=True)
    new_lower = _slot_lower(tmp_path / "root_B", with_rule=False)
    upper = tmp_path / "upper"
    (upper / "sudoers.d").mkdir(parents=True)
    (upper / "sudoers.d" / "live").write_text(content)
    mod.before_mount(upper, new_lower, tmp_path / "etc")
    assert (upper / "sudoers.d" / "live").read_text() == content
    for lower in (old_lower, new_lower):
        assert _merged_has("sudoers.d/live", lower, upper, is_wo) == content


def test_premount_replaces_an_upper_copy_of_the_rule(tmp_path, monkeypatch):
    mod = _reconcile()
    is_wo = _fake_whiteouts(monkeypatch, mod)
    lower = _slot_lower(tmp_path / "root", with_rule=True)
    upper = tmp_path / "upper"
    (upper / "sudoers.d").mkdir(parents=True)
    (upper / "sudoers.d" / "live").write_text(LIVE_LINE + "\n")
    mod.before_mount(upper, lower, tmp_path / "etc")
    assert is_wo(upper / "sudoers.d" / "live")


def test_premount_leaves_a_symlinked_sudoers_d_alone(tmp_path, monkeypatch):
    mod = _reconcile()
    _fake_whiteouts(monkeypatch, mod)
    lower = _slot_lower(tmp_path / "root", with_rule=True)
    upper = tmp_path / "upper"
    upper.mkdir()
    (upper / "sudoers.d").symlink_to(tmp_path)
    mod.before_mount(upper, lower, tmp_path / "etc")
    assert not (tmp_path / "live").exists()


def test_premount_refuses_a_mounted_etc(tmp_path, monkeypatch):
    """Changing an upper under a live overlay mount is undefined."""
    mod = _reconcile()
    _fake_whiteouts(monkeypatch, mod)
    lower = _slot_lower(tmp_path / "root", with_rule=True)
    upper = tmp_path / "upper"
    upper.mkdir()
    monkeypatch.setattr(mod.os.path, "ismount", lambda p: True)
    mod.before_mount(upper, lower, tmp_path / "etc")
    assert not (upper / "sudoers.d").exists()


def test_main_dispatches_before_mount(tmp_path, monkeypatch):
    mod = _reconcile()
    _fake_whiteouts(monkeypatch, mod)
    lower = _slot_lower(tmp_path / "root", with_rule=True)
    upper = tmp_path / "upper"
    upper.mkdir()
    monkeypatch.setattr(mod, "LOWER", lower)
    monkeypatch.setattr(mod, "UPPER", upper)
    monkeypatch.setattr(mod, "ETC", tmp_path / "etc")
    assert mod.main(["--before-mount"]) == 0
    assert (upper / "sudoers.d" / "live").exists()
    assert mod.main(["--bogus"]) == 2


def test_real_whiteout_device(tmp_path):
    """The real _make_whiteout / _is_whiteout pair, where mknod is allowed."""
    mod = _reconcile()
    path = tmp_path / "live"
    try:
        mod._make_whiteout(path)
    except PermissionError:
        pytest.skip("this runner cannot create character devices")
    assert mod._is_whiteout(path)
    assert not mod._is_whiteout(tmp_path)


def test_premount_unit_runs_between_var_and_etc_mount():
    unit = (
        EXTRA / "etc" / "systemd" / "system" / "spatium-etc-premount.service"
    ).read_text()
    assert "DefaultDependencies=no" in unit
    assert re.search(r"^After=.*\bvar\.mount\b", unit, re.M)
    assert re.search(r"^Before=.*\betc\.mount\b", unit, re.M)
    assert "ConditionPathIsMountPoint=!/etc" in unit
    assert "spatium-etc-reconcile --before-mount" in unit
    post = _code(POSTINST.read_text(encoding="utf-8"))
    assert "local-fs.target.wants/spatium-etc-premount.service" in post
    assert (
        'chmod 0644 "$BUILDROOT/etc/systemd/system/spatium-etc-premount.service"'
        in post
    )


def test_rollback_on_a_real_overlay(tmp_path):
    """Case 4 end to end on a real overlayfs, where the runner may mount.

    Skipped unprivileged (CI); run in a privileged container to see the
    kernel honour the whiteout over the OLD slot's lower.
    """
    mod = _reconcile()
    upper = tmp_path / "upper"
    work = tmp_path / "work"
    merged = tmp_path / "merged"
    for d in (upper, work, merged):
        d.mkdir()
    old_lower = _slot_lower(tmp_path / "root_A", with_rule=True)
    new_lower = _slot_lower(tmp_path / "root_B", with_rule=False)
    try:
        mod._make_whiteout(tmp_path / "probe")
    except PermissionError:
        pytest.skip("this runner cannot create character devices")
    os.unlink(tmp_path / "probe")

    mod.before_mount(upper, new_lower, merged)  # first boot of the new slot
    opts = f"lowerdir={old_lower},upperdir={upper},workdir={work}"
    r = subprocess.run(
        ["mount", "-t", "overlay", "overlay", "-o", opts, str(merged)],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        pytest.skip(f"cannot mount overlayfs here: {r.stderr.strip()}")
    try:  # the rollback: the old slot's lower under the shared upper
        assert not os.path.lexists(merged / "sudoers.d" / "live")
        assert (merged / "sudoers.d" / "README").read_text() == "readme\n"
    finally:
        subprocess.run(["umount", str(merged)], check=False)
