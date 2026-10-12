"""Every appliance gets its own SSH host keys (GHSA-vvh9-6gfw-wphp).

Before this, the openssh-server postinst generated host keys inside the
mkosi build container, the installer copied those image-baked keys into
STATE, and ``spatium-etc-render`` restored them on every boot. So every
appliance installed from one release presented the same host keys, and
the private halves shipped in the public ISO.

Three halves, each executed rather than grepped where that is possible:

* the image ships no host keys (``mkosi.finalize`` run against a fake
  BUILDROOT);
* the installer's STATE block no longer seeds STATE from the image, and
  still never touches keys STATE already holds (#995 item 25);
* ``spatium-etc-render``'s SSH section, run against a stubbed STATE dir,
  generates when STATE is empty, rotates a build-container key exactly
  once, and leaves a unique key (or an operator's own) alone.

    python3 -m pytest appliance/tests/test_ssh_host_keys_unique.py -v
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from _installer_source import BIN, CODE, SRC

APPLIANCE = Path(__file__).resolve().parents[1]
FINALIZE = APPLIANCE / "mkosi.finalize"
ETC_RENDER = BIN / "spatium-etc-render"
UNIT_DIR = APPLIANCE / "mkosi.extra" / "etc" / "systemd" / "system"
POSTINST = APPLIANCE / "mkosi.postinst"

#: The comment the openssh postinst stamps on a key generated in the
#: build container: ``root@`` + docker's default hostname, the 12-hex
#: short container id. Taken from the advisory's own sample.
BUILD_COMMENT = "root@0395775719fb"

needs_keygen = pytest.mark.skipif(
    shutil.which("ssh-keygen") is None, reason="ssh-keygen not installed"
)


def _keygen(path: Path, comment: str, kind: str = "ed25519") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["ssh-keygen", "-q", "-t", kind, "-N", "", "-C", comment, "-f", str(path)],
        check=True,
    )


def _pub(path: Path) -> str:
    return path.with_name(path.name + ".pub").read_text(encoding="utf-8")


# ── the image ─────────────────────────────────────────────────────────


def test_finalize_strips_host_keys_from_the_image(tmp_path: Path) -> None:
    root = tmp_path / "buildroot"
    ssh = root / "etc" / "ssh"
    ssh.mkdir(parents=True)
    for name in (
        "ssh_host_ed25519_key",
        "ssh_host_ed25519_key.pub",
        "ssh_host_rsa_key",
        "ssh_host_rsa_key.pub",
        "ssh_host_ecdsa_key",
        "ssh_host_ecdsa_key.pub",
    ):
        (ssh / name).write_text("baked\n", encoding="utf-8")
    (ssh / "sshd_config").write_text("PermitRootLogin no\n", encoding="utf-8")
    (root / "var" / "log").mkdir(parents=True)

    proc = subprocess.run(
        ["sh", str(FINALIZE)],
        env={**os.environ, "BUILDROOT": str(root)},
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert sorted(p.name for p in ssh.glob("ssh_host_*")) == []
    # Only the keys — the daemon's config is not collateral.
    assert (ssh / "sshd_config").exists()


# ── the installer ─────────────────────────────────────────────────────


def _installer_state_block() -> str:
    start = SRC.index('STATE_MNT="$MOUNT/var/lib/spatium-state"')
    end = SRC.index('cat > "$STATE_MNT/spatium-config.yaml"', start)
    return SRC[start:end]


def test_installer_does_not_copy_image_keys_into_state(tmp_path: Path) -> None:
    """Executed: the image keys must not reach STATE, and a key STATE
    already holds from a previous install must survive (#995 item 25)."""
    mount = tmp_path / "mnt"
    image_ssh = mount / "usr/lib/etc.image/ssh"
    image_ssh.mkdir(parents=True)
    for name in ("ssh_host_ed25519_key", "ssh_host_ed25519_key.pub",
                 "ssh_host_rsa_key", "ssh_host_rsa_key.pub"):
        (image_ssh / name).write_text("image\n", encoding="utf-8")
    state_ssh = mount / "var/lib/spatium-state/ssh"
    state_ssh.mkdir(parents=True)
    (state_ssh / "ssh_host_ed25519_key").write_text("kept\n", encoding="utf-8")

    script = (
        "set -eu\n"
        f'MOUNT="{mount}"\nINSTALL_LOG="{tmp_path}/install.log"\n'
        + _installer_state_block()
    )
    proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr

    assert sorted(p.name for p in state_ssh.iterdir()) == ["ssh_host_ed25519_key"]
    assert (state_ssh / "ssh_host_ed25519_key").read_text() == "kept\n"
    # Nothing key-shaped is left in the overlay lower to shadow STATE.
    assert sorted(p.name for p in image_ssh.glob("ssh_host_*")) == []


def test_installer_creates_state_ssh_dir_on_a_fresh_disk(tmp_path: Path) -> None:
    mount = tmp_path / "mnt"
    (mount / "usr/lib/etc.image/ssh").mkdir(parents=True)
    script = (
        "set -eu\n"
        f'MOUNT="{mount}"\nINSTALL_LOG="{tmp_path}/install.log"\n'
        + _installer_state_block()
    )
    subprocess.run(["bash", "-c", script], check=True)
    state_ssh = mount / "var/lib/spatium-state/ssh"
    assert state_ssh.is_dir()
    assert list(state_ssh.iterdir()) == []


def test_installer_rsync_keeps_live_session_keys_off_the_target() -> None:
    """The live ISO generates throwaway keys at boot; the rootfs rsync must
    not carry them onto the installed disk."""
    assert '--exclude="/etc/ssh/ssh_host_*"' in CODE


# ── first boot ────────────────────────────────────────────────────────


def _ssh_section() -> str:
    src = ETC_RENDER.read_text(encoding="utf-8")
    start = src.index("# ── SSH host keys")
    end = src.index("# ── role-config")
    return src[start:end]


def _run_ssh_section(tmp_path: Path, hostname_val: str = "ddi1") -> str:
    """Run the shipped SSH section with STATE and /etc/ssh rebased.

    ``SSH_DIR`` is the only path the section writes outside STATE, so
    rebasing that one variable is the whole of the rewrite.
    """
    section = _ssh_section()
    assert re.search(r"^SSH_DIR=/etc/ssh$", section, re.M), (
        "the SSH section must route /etc/ssh through SSH_DIR"
    )
    section = re.sub(
        r"^SSH_DIR=/etc/ssh$", f"SSH_DIR={tmp_path}/etc/ssh", section, flags=re.M
    )
    script = (
        "set -eu\n"
        f"STATE_DIR={tmp_path}/state\n"
        f"HOSTNAME_VAL={hostname_val}\n" + section
    )
    proc = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout


@needs_keygen
def test_first_boot_generates_keys_when_state_is_empty(tmp_path: Path) -> None:
    (tmp_path / "state").mkdir()
    _run_ssh_section(tmp_path)

    state = tmp_path / "state/ssh"
    etc = tmp_path / "etc/ssh"
    assert (state / "ssh_host_ed25519_key").exists()
    assert (etc / "ssh_host_ed25519_key").exists()
    assert _pub(state / "ssh_host_ed25519_key") == _pub(etc / "ssh_host_ed25519_key")
    assert (state / ".build-keys-checked").exists()
    assert oct((etc / "ssh_host_ed25519_key").stat().st_mode & 0o777) == "0o600"


@needs_keygen
def test_a_build_container_key_in_state_is_rotated(tmp_path: Path) -> None:
    state = tmp_path / "state/ssh"
    _keygen(state / "ssh_host_ed25519_key", BUILD_COMMENT)
    _keygen(state / "ssh_host_rsa_key", BUILD_COMMENT, kind="rsa")
    # The overlay upper still holds the copy restored on earlier boots —
    # it must not survive either.
    etc = tmp_path / "etc/ssh"
    etc.mkdir(parents=True)
    for p in state.iterdir():
        shutil.copy2(p, etc / p.name)
    baked = _pub(state / "ssh_host_ed25519_key")

    out = _run_ssh_section(tmp_path)

    assert "rotat" in out.lower()
    for d in (state, etc):
        assert _pub(d / "ssh_host_ed25519_key") != baked
        for pub in d.glob("ssh_host_*_key.pub"):
            assert BUILD_COMMENT not in pub.read_text(encoding="utf-8")
    assert _pub(state / "ssh_host_ed25519_key") == _pub(etc / "ssh_host_ed25519_key")
    assert (state / ".build-keys-checked").exists()


@needs_keygen
def test_rotation_happens_once_not_on_every_boot(tmp_path: Path) -> None:
    state = tmp_path / "state/ssh"
    _keygen(state / "ssh_host_ed25519_key", BUILD_COMMENT)
    _run_ssh_section(tmp_path)
    first = _pub(state / "ssh_host_ed25519_key")

    _run_ssh_section(tmp_path)
    _run_ssh_section(tmp_path)
    assert _pub(state / "ssh_host_ed25519_key") == first


@needs_keygen
def test_a_twelve_hex_hostname_does_not_rotate_its_own_key(tmp_path: Path) -> None:
    """A node genuinely NAMED like a container id must not rotate the
    key it generated for itself, marker or no marker."""
    state = tmp_path / "state/ssh"
    _keygen(state / "ssh_host_ed25519_key", "root@deadbeefcafe")
    before = _pub(state / "ssh_host_ed25519_key")
    _run_ssh_section(tmp_path, hostname_val="deadbeefcafe")
    assert _pub(state / "ssh_host_ed25519_key") == before


@needs_keygen
@pytest.mark.parametrize("comment", ["root@ddi1", "ops@laptop", "root@ddi-0395775719fb"])
def test_a_unique_or_operator_key_is_left_alone(tmp_path: Path, comment: str) -> None:
    state = tmp_path / "state/ssh"
    _keygen(state / "ssh_host_ed25519_key", comment)
    before = _pub(state / "ssh_host_ed25519_key")

    _run_ssh_section(tmp_path)

    assert _pub(state / "ssh_host_ed25519_key") == before
    assert _pub(tmp_path / "etc/ssh/ssh_host_ed25519_key") == before
    assert (state / ".build-keys-checked").exists()


# ── sshd never starts keyless ─────────────────────────────────────────


def test_a_keygen_unit_orders_before_sshd_and_is_enabled() -> None:
    """With no keys in the image, every path that reaches sshd without
    etc-render (the live ISO, an /etc overlay that failed to mount) needs
    something to generate them first, or sshd refuses to start."""
    unit = (UNIT_DIR / "spatium-ssh-hostkeys.service").read_text(encoding="utf-8")
    assert re.search(r"^Before=.*\bssh\.service\b", unit, re.M)
    assert re.search(r"^After=.*\bspatium-etc-render\.service\b", unit, re.M)
    assert "ssh-keygen -A" in unit
    postinst = "\n".join(
        ln.split("#", 1)[0] for ln in POSTINST.read_text(encoding="utf-8").splitlines()
    )
    assert "spatium-ssh-hostkeys.service" in postinst
