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
    assert mod.main() == 0
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
