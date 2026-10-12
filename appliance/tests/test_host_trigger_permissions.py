"""Local-account-to-root via file modes on the appliance (GHSA-h2j9-qrg7-grfw).

Three modes combined so that any local account — a compromised ``snmpd``
or ``lldpd`` is the realistic one — could become root:

1. ``/etc/rancher/k3s/k3s.yaml`` (cluster-admin) was 0644;
2. ``/var/lib/spatiumddi/release-state``, where every root host runner
   picks up its trigger file, was 1777, and no runner asked who wrote the
   trigger (the #786 slot-upgrade sidecars were 0666 on top);
3. ``/etc/spatiumddi/.env`` (database password, SECRET_KEY, agent PSKs)
   was 0644.

Each permission change only holds if the reader that needs the old access
gets it another way, so most tests here pin a PAIR: the new mode and the
reader's new path to it (the supervisor's pinned uid + ``spatium-host``
membership, the api pod's supplementalGroups, the entrypoint reading .env
as root before su-exec).

``spatiumddi-trigger-guard`` is EXECUTED against real files with right and
wrong owners. Ownership is simulated through its allowed-uid list rather
than by chown, so these tests need no root.

WHAT NEEDS A BOOTED APPLIANCE (not provable here): that systemd honours
the ``ExecCondition=`` skip without marking the unit failed, that
systemd-tmpfiles re-modes the existing directory at sysinit, that k3s
applies the drop-in's group, and that the pods actually carry gid 2770.

HOW TO RUN:
    python3 -m pytest appliance/tests/test_host_trigger_permissions.py -v
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
EXTRA = REPO / "appliance" / "mkosi.extra"
BIN = EXTRA / "usr" / "local" / "bin"
UNITS = EXTRA / "etc" / "systemd" / "system"
K3S_DIR = EXTRA / "etc" / "rancher" / "k3s"
POSTINST = REPO / "appliance" / "mkosi.postinst"
GUARD = BIN / "spatiumddi-trigger-guard"
FIRSTBOOT = BIN / "spatiumddi-firstboot"
SUPERVISOR_DOCKERFILE = (
    REPO / "agent" / "supervisor" / "images" / "supervisor" / "Dockerfile"
)
SUPERVISOR_ENTRYPOINT = (
    REPO / "agent" / "supervisor" / "images" / "supervisor" / "entrypoint.sh"
)
API_TEMPLATE = REPO / "charts" / "spatiumddi" / "templates" / "api.yaml"
CHART_VALUES = REPO / "charts" / "spatiumddi" / "values.yaml"

HOST_GID = 2770
SUPERVISOR_UID = 100
API_UID = 1000

needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# 1. the cluster-admin kubeconfig
# --------------------------------------------------------------------------


def _effective_k3s_config() -> dict:
    """config.yaml then config.yaml.d/*.yaml in lexical order, last wins —
    the order k3s merges them in for scalar keys."""
    merged: dict = dict(yaml.safe_load(_read(K3S_DIR / "config.yaml")) or {})
    dropins = K3S_DIR / "config.yaml.d"
    for f in sorted(dropins.glob("*.yaml")) if dropins.is_dir() else []:
        merged.update(yaml.safe_load(_read(f)) or {})
    return merged


def test_kubeconfig_is_not_world_readable() -> None:
    cfg = _effective_k3s_config()
    mode = int(str(cfg.get("write-kubeconfig-mode", "0600")), 8)
    assert (
        mode & 0o007 == 0
    ), f"k3s.yaml would be written {oct(mode)} — readable by every account"
    assert mode == 0o640
    # Group = the gid the supervisor (read_kubeconfig) and the admin carry.
    assert str(cfg.get("write-kubeconfig-group")) == str(HOST_GID)


def test_kubeconfig_mode_is_a_dropin_not_only_config_yaml() -> None:
    # config.yaml can live in the /etc overlay upper on an existing install
    # (spatium-cluster-join seds it), where a new image never replaces it —
    # so only a drop-in reaches those boxes.
    dropin = K3S_DIR / "config.yaml.d" / "spatium-kubeconfig.yaml"
    body = yaml.safe_load(_read(dropin))
    assert body["write-kubeconfig-mode"] == "0640"
    assert "0644" not in re.sub(r"(?m)^#.*$", "", _read(K3S_DIR / "config.yaml"))


def test_firstboot_heals_a_hidden_dropin_and_remodes_the_kubeconfig() -> None:
    text = _read(FIRSTBOOT)
    assert (
        "/usr/lib/etc.image/rancher/k3s/config.yaml.d/spatium-kubeconfig.yaml" in text
    )
    assert re.search(r"chmod 0640 /etc/rancher/k3s/k3s\.yaml", text)
    # Re-modded again once k3s is ready, i.e. after k3s has written it.
    ready_block = text[text.index('if [ "$ready" = 1 ]; then') :]
    assert ready_block.lstrip().splitlines()[1].strip() == "tighten_kubeconfig"


# --------------------------------------------------------------------------
# 2. the trigger directory + sidecars
# --------------------------------------------------------------------------


def test_firstboot_never_makes_release_state_world_writable() -> None:
    text = _read(FIRSTBOOT)
    code = re.sub(r"(?m)^\s*#.*$", "", text)
    assert "chmod 1777" not in code
    assert "0666" not in code
    assert re.search(r"^SPATIUM_HOST_GID=2770$", text, re.M)
    assert 'chgrp "$SPATIUM_HOST_GID" /var/lib/spatiumddi/release-state' in code
    assert "chmod 1770 /var/lib/spatiumddi/release-state" in code


def test_tmpfiles_tightens_release_state_on_every_boot() -> None:
    # tmpfiles runs at sysinit, before k3s — the path that repairs an
    # appliance installed with 1777 before either writer exists.
    text = _read(POSTINST)
    m = re.search(r"spatium-release-state\.conf\" <<'EOF'\n(.*?)\nEOF", text, re.S)
    assert m, "postinst does not ship spatium-release-state.conf"
    lines = [
        ln.split() for ln in m.group(1).splitlines() if ln and not ln.startswith("#")
    ]
    assert [
        "d",
        "/var/lib/spatiumddi/release-state",
        "1770",
        "root",
        str(HOST_GID),
        "-",
        "-",
    ] in lines
    for sidecar in ("slot-upgrade-pending.state", "slot-upgrade.progress"):
        assert [
            "z",
            f"/var/lib/spatiumddi/release-state/{sidecar}",
            "0660",
            "root",
            str(HOST_GID),
            "-",
            "-",
        ] in lines


@needs_bash
def test_slot_upgrade_sidecars_are_published_0660_not_0666(tmp_path: Path) -> None:
    stub = tmp_path / "spatium-upgrade-slot"
    stub.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
    stub.chmod(0o755)
    (tmp_path / "slot-upgrade-pending").write_text("https://example/img.raw.xz\n")
    env = {
        **os.environ,
        "SPATIUM_SLOT_TRIGGER": str(tmp_path / "slot-upgrade-pending"),
        "SPATIUM_SLOT_PROGRESS": str(tmp_path / "slot-upgrade.progress"),
        "SPATIUM_SLOT_LOG_DIR": str(tmp_path / "log"),
        "SPATIUM_UPGRADE_SLOT_BIN": str(stub),
        "SPATIUM_SLOT_TICK_SECONDS": "1",
        # A gid this (non-root) test process may chgrp to.
        "SPATIUM_HOST_GID": str(os.getgid()),
    }
    subprocess.run(
        ["bash", str(BIN / "spatiumddi-slot-upgrade")],
        env=env,
        capture_output=True,
        timeout=60,
    )
    for name in ("slot-upgrade-pending.state", "slot-upgrade.progress"):
        st = (tmp_path / name).stat()
        assert (
            stat.S_IMODE(st.st_mode) == 0o660
        ), f"{name} is {oct(stat.S_IMODE(st.st_mode))}"
        assert st.st_gid == os.getgid()


def test_slot_upgrade_runner_defaults_to_the_host_gid() -> None:
    assert re.search(
        r'^SIDECAR_GID="\$\{SPATIUM_HOST_GID:-2770\}"$',
        _read(BIN / "spatiumddi-slot-upgrade"),
        re.M,
    )


# --------------------------------------------------------------------------
# 3. the guard in front of every runner
# --------------------------------------------------------------------------


def _path_units() -> list[tuple[Path, str]]:
    out = []
    for p in sorted(UNITS.glob("*.path")):
        m = re.search(
            r"^Path(?:Changed|ExistsGlob|Exists|Modified)=(\S+)", _read(p), re.M
        )
        assert m, p
        out.append((p, m.group(1)))
    return out


def test_every_release_state_runner_is_guarded() -> None:
    units = [(p, w) for p, w in _path_units() if "/release-state/" in w]
    assert len(units) >= 20, "the .path unit inventory shrank unexpectedly"
    for path_unit, watched in units:
        service = path_unit.with_suffix(".service")
        conds = re.findall(r"^ExecCondition=(.*)$", _read(service), re.M)
        assert conds == [
            f"/usr/local/bin/spatiumddi-trigger-guard {watched}"
        ], f"{service.name} does not guard the trigger its .path watches ({watched})"


def test_guard_is_executable_in_the_image() -> None:
    assert 'chmod 0755 "$BUILDROOT/usr/local/bin/spatiumddi-trigger-guard"' in _read(
        POSTINST
    )


def test_guard_default_allowlist_is_root_supervisor_api() -> None:
    m = re.search(
        r'^ALLOWED_UIDS="\$\{SPATIUM_TRIGGER_ALLOWED_UIDS:-([0-9 ]+)\}"$',
        _read(GUARD),
        re.M,
    )
    assert m
    assert m.group(1).split() == ["0", str(SUPERVISOR_UID), str(API_UID)]


def _guard(
    tmp_path: Path, *specs: str, allowed: str, root: Path | None = None
) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "SPATIUM_TRIGGER_ALLOWED_UIDS": allowed,
        "SPATIUM_TRIGGER_ROOT": str(root or tmp_path),
        "SPATIUM_TRIGGER_GUARD_LOG": str(tmp_path / "guard.log"),
    }
    return subprocess.run(
        ["bash", str(GUARD), *specs],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _owner(p: Path) -> str:
    """The uid that owns ``p``, as the guard sees it. Under root (a dev
    container) the file is handed to an unprivileged uid first, because the
    guard exempts uid 0 from the world-writable-directory check and these
    tests are about the non-root writers."""
    if os.getuid() == 0:
        os.chown(p, 4242, 4242, follow_symlinks=False)
    return str(os.lstat(p).st_uid)


def _other_uid(owner: str) -> str:
    return str(int(owner) + 12345)


@pytest.fixture
def trig_dir(tmp_path: Path) -> Path:
    d = tmp_path / "release-state"
    d.mkdir()
    d.chmod(0o1770)
    return d


@needs_bash
def test_guard_accepts_a_trigger_from_an_allowed_owner(
    tmp_path: Path, trig_dir: Path
) -> None:
    trig = trig_dir / "ssh-config-pending"
    trig.write_text("payload\n")
    r = _guard(tmp_path, str(trig), allowed=_owner(trig), root=trig_dir)
    assert r.returncode == 0, r.stderr
    assert trig.read_text() == "payload\n"


@needs_bash
def test_guard_rejects_and_quarantines_a_foreign_trigger(
    tmp_path: Path, trig_dir: Path
) -> None:
    trig = trig_dir / "ssh-config-pending"
    trig.write_text("attacker authorized_keys\n")
    r = _guard(tmp_path, str(trig), allowed=_other_uid(_owner(trig)), root=trig_dir)
    # 1 = ExecCondition "skip"; never 255, which would mark the unit failed.
    assert r.returncode == 1
    assert not trig.exists(), "a rejected trigger left in place re-fires the unit"
    rejected = list(trig_dir.glob("ssh-config-pending.rejected.*"))
    assert len(rejected) == 1
    assert "REJECTED" in (tmp_path / "guard.log").read_text()


@needs_bash
def test_guard_skips_when_the_trigger_is_absent(tmp_path: Path, trig_dir: Path) -> None:
    # The quarantine rename re-fires a PathChanged unit once; that run must
    # skip rather than proceed (spatiumddi-reboot.service has no runner of
    # its own that would notice the missing file).
    r = _guard(tmp_path, str(trig_dir / "reboot-pending"), allowed="0", root=trig_dir)
    assert r.returncode == 1


@needs_bash
def test_guard_rejects_a_symlinked_trigger(tmp_path: Path, trig_dir: Path) -> None:
    target = tmp_path / "elsewhere"
    target.write_text("x\n")
    link = trig_dir / "apt-config-pending"
    link.symlink_to(target)
    r = _guard(tmp_path, str(link), allowed=f"0 {_owner(link)}", root=trig_dir)
    assert r.returncode == 1
    assert not link.is_symlink() and not link.exists()
    assert target.exists(), "the guard must never touch a symlink's target"


@needs_bash
def test_guard_distrusts_owner_in_a_world_writable_directory(tmp_path: Path) -> None:
    # On the legacy 1777 directory an owner uid proves nothing: host uid 100
    # is some system daemon, not the supervisor.
    legacy = tmp_path / "release-state"
    legacy.mkdir()
    legacy.chmod(0o1777)
    trig = legacy / "slot-upgrade-pending"
    trig.write_text("https://evil/img.raw.xz\n")
    r = _guard(tmp_path, str(trig), allowed=_owner(trig), root=legacy)
    assert r.returncode == 1
    assert not trig.exists()
    assert "world-writable" in (tmp_path / "guard.log").read_text()


@needs_bash
def test_guard_glob_quarantines_bad_requests_and_keeps_good_ones(
    tmp_path: Path, trig_dir: Path
) -> None:
    pcap = trig_dir / "pcap"
    pcap.mkdir()
    good = pcap / "a.request"
    good.write_text("capture_id=a\n")
    bad = pcap / "b.request"
    bad.symlink_to(good)
    r = _guard(tmp_path, str(pcap / "*.request"), allowed=_owner(good), root=trig_dir)
    assert r.returncode == 0
    assert good.exists()
    assert not bad.is_symlink()
    # The quarantined name must not match the glob, or PathExistsGlob loops.
    assert sorted(p.name for p in pcap.glob("*.request")) == ["a.request"]


@needs_bash
def test_guard_glob_with_only_bad_requests_skips(
    tmp_path: Path, trig_dir: Path
) -> None:
    storage = trig_dir / "storage"
    storage.mkdir()
    req = storage / "r1.request.json"
    req.write_text("{}")
    r = _guard(
        tmp_path,
        str(storage / "*.request.json"),
        allowed=_other_uid(_owner(req)),
        root=trig_dir,
    )
    assert r.returncode == 1
    assert list(storage.glob("*.request.json")) == []


@needs_bash
def test_guard_with_no_arguments_refuses(tmp_path: Path) -> None:
    assert _guard(tmp_path, allowed="0").returncode == 1


# --------------------------------------------------------------------------
# the writers keep their access: pinned supervisor ids + gid, api gid
# --------------------------------------------------------------------------


def test_supervisor_ids_are_pinned_and_it_carries_the_host_gid() -> None:
    text = _read(SUPERVISOR_DOCKERFILE)
    assert "addgroup -S -g 101 spatium" in text
    assert f"adduser -S -u {SUPERVISOR_UID} -G spatium spatium" in text
    assert f"addgroup -S -g {HOST_GID} spatium-host" in text
    assert "addgroup spatium spatium-host" in text
    # initgroups() is what carries 2770 into the process: a ``:group``
    # suffix on su-exec would drop it.
    assert re.search(
        r"^exec su-exec spatium /usr/local/bin/spatium-supervisor$",
        _read(SUPERVISOR_ENTRYPOINT),
        re.M,
    )


def test_api_pod_carries_the_host_gid_when_host_mounts_are_on() -> None:
    values = yaml.safe_load(_read(CHART_VALUES))
    assert values["api"]["applianceHostMounts"]["hostGroupGid"] == HOST_GID
    tpl = _read(API_TEMPLATE)
    assert re.search(
        r"\{\{- if \.Values\.api\.applianceHostMounts\.enabled \}\}\s*\n(?:\s*#.*\n)*\s*supplementalGroups:\s*\n"
        r"\s*- \{\{ \.Values\.api\.applianceHostMounts\.hostGroupGid \}\}",
        tpl,
    )


# --------------------------------------------------------------------------
# 4. /etc/spatiumddi/.env
# --------------------------------------------------------------------------


def test_firstboot_writes_env_0600_and_repairs_it_every_boot() -> None:
    text = _read(FIRSTBOOT)
    code = re.sub(r"(?m)^\s*#.*$", "", text)
    assert not re.search(r'chmod 0?644 "\$ENV_FILE"', code)
    # created 0600 before the secrets are written into it ...
    gen = code.index('install -m 0600 /dev/null "$ENV_FILE"')
    assert gen < code.index('cat > "$ENV_FILE" <<EOF')
    # ... and re-moded OUTSIDE the generate-once branch, so an existing
    # install's 0644 file is repaired.
    every_boot = code.index('chmod 0600 "$ENV_FILE"')
    assert every_boot > code.index("APPLIANCE_HOST_IPS=${APPLIANCE_HOST_IPS_VAL}")


def test_spatium_pair_keeps_env_0600() -> None:
    code = re.sub(r"(?m)^\s*#.*$", "", _read(BIN / "spatium-pair"))
    assert not re.search(r'chmod 0?644 "\$ENV_TMP"', code)
    assert 'install -m 0600 /dev/null "$ENV_TMP"' in code
    assert 'chmod 0600 "$ENV_TMP"' in code


def test_supervisor_reads_env_as_root_before_dropping_privileges() -> None:
    # The only non-root reader the 0644 used to serve: the entrypoint reads
    # it while still root, then su-execs.
    text = _read(SUPERVISOR_ENTRYPOINT)
    assert text.index('done < "$HOST_ENV"') < text.index("exec su-exec spatium")
