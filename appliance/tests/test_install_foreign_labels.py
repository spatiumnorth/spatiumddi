"""#4547 — another attached disk carrying the var / state / ESP labels.

The installed system mounts by filesystem label, so a second disk with the
same labels can win. The pre-wipe guard scans the non-target disks, and
refuses (or, after an explicit confirmation, blanks the labels). Run
against stubbed lsblk / e2label / fatlabel / whiptail; no block device is
touched.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from _installer_source import INSTALLER, SRC, extract_fn

FNS = "\n".join(
    extract_fn(n)
    for n in ("_foreign_labelled_partitions", "_clear_fs_label", "_assert_no_foreign_labels")
)

# disk -> [(partition, label, fstype)]
LAYOUT = {
    "/dev/sda": [("/dev/sda2", "ESP", "vfat"), ("/dev/sda3", "state", "ext4"),
                 ("/dev/sda6", "var", "ext4")],
    "/dev/sdb": [("/dev/sdb2", "ESP", "vfat"), ("/dev/sdb6", "var", "ext4")],
    "/dev/sdc": [("/dev/sdc1", "data", "ext4")],
}


def _rig(tmp: Path, layout, *, wh_menu="clear", wh_typed="CLEAR", fail_clear=False,
         unattended="0", allow=""):
    bind = tmp / "bin"
    bind.mkdir()
    st = tmp / "labels"
    st.write_text("".join(f"{p} {l} {f}\n" for rows in layout.values() for p, l, f in rows))
    disks = "\n".join(f"{d} disk" for d in layout)
    (bind / "lsblk").write_text(
        f"""#!/bin/bash
args="$*"
case "$args" in
  "-dnrpo NAME,TYPE") cat <<'D'
{disks}
D
  ;;
  "-nrpo NAME,LABEL "*) d="${{@: -1}}"
     while read -r p l f; do case "$p" in "$d"*) echo "$p $l";; esac; done < {st} ;;
  "-nro FSTYPE "*) d="${{@: -1}}"; while read -r p l f; do [ "$p" = "$d" ] && echo "$f"; done < {st} ;;
  "-nro LABEL "*) d="${{@: -1}}"; while read -r p l f; do [ "$p" = "$d" ] && echo "$l"; done < {st} ;;
esac
"""
    )
    clr = "exit 1" if fail_clear else (
        f'sed -i "s|^$1 [^ ]* |$1 NONE |" {st}'
    )
    for tool in ("e2label", "fatlabel"):
        (bind / tool).write_text(f"#!/bin/bash\n{clr}\n")
    (bind / "udevadm").write_text("#!/bin/bash\nexit 0\n")
    (bind / "whiptail").write_text(
        f"""#!/bin/bash
case "$*" in
  *--menu*) echo {wh_menu} >&2 ;;
  *--inputbox*) echo '{wh_typed}' >&2 ;;
esac
exit 0
"""
    )
    for f in bind.iterdir():
        f.chmod(0o755)
    script = tmp / "run.sh"
    script.write_text(
        f"""set -u
export PATH={bind}:$PATH
INSTALL_LOG={tmp}/log; BACKTITLE=t; FULLY_UNATTENDED={unattended}
PRESEED_CLEAR_FOREIGN_LABELS={allow!r}
log() {{ echo "$*" >> "$INSTALL_LOG"; }}
on_cancel() {{ echo "CANCELLED: $*"; exit 10; }}
preseed_halt() {{ echo "HALT: $1"; exit 11; }}
set +x
{FNS}
"$@"
"""
    )
    return script, st


def _run(script, *args):
    return subprocess.run(["bash", str(script), *args], capture_output=True, text=True)


def test_detects_second_disk_labels(tmp_path):
    script, _ = _rig(tmp_path, LAYOUT)
    r = _run(script, "_foreign_labelled_partitions", "/dev/sda")
    assert r.stdout.splitlines() == ["/dev/sdb2 ESP /dev/sdb", "/dev/sdb6 var /dev/sdb"]


def test_target_and_mirror_are_excluded(tmp_path):
    script, _ = _rig(tmp_path, LAYOUT)
    r = _run(script, "_foreign_labelled_partitions", "/dev/sda", "/dev/sdb")
    assert r.stdout == ""


def test_clean_system_passes(tmp_path):
    script, _ = _rig(tmp_path, {k: v for k, v in LAYOUT.items() if k != "/dev/sdb"})
    assert _run(script, "_assert_no_foreign_labels", "/dev/sda").returncode == 0


def test_interactive_stop_cancels_and_changes_nothing(tmp_path):
    script, st = _rig(tmp_path, LAYOUT, wh_menu="stop")
    before = st.read_text()
    r = _run(script, "_assert_no_foreign_labels", "/dev/sda")
    assert r.returncode == 10 and "CANCELLED" in r.stdout
    assert st.read_text() == before


def test_interactive_wrong_confirmation_changes_nothing(tmp_path):
    script, st = _rig(tmp_path, LAYOUT, wh_typed="clear")
    before = st.read_text()
    r = _run(script, "_assert_no_foreign_labels", "/dev/sda")
    assert r.returncode == 10
    assert st.read_text() == before


def test_interactive_typed_confirmation_clears_only_other_disk(tmp_path):
    script, st = _rig(tmp_path, LAYOUT)
    r = _run(script, "_assert_no_foreign_labels", "/dev/sda")
    assert r.returncode == 0, r.stdout
    text = st.read_text()
    assert "/dev/sdb2 NONE" in text and "/dev/sdb6 NONE" in text
    assert "/dev/sda6 var" in text and "/dev/sda3 state" in text


def test_unattended_refuses_without_key(tmp_path):
    script, st = _rig(tmp_path, LAYOUT, unattended="1")
    before = st.read_text()
    r = _run(script, "_assert_no_foreign_labels", "/dev/sda")
    assert r.returncode == 11 and "/dev/sdb6" in r.stdout
    assert st.read_text() == before


def test_unattended_with_key_clears(tmp_path):
    script, st = _rig(tmp_path, LAYOUT, unattended="1", allow="1")
    r = _run(script, "_assert_no_foreign_labels", "/dev/sda")
    assert r.returncode == 0, r.stdout
    assert "/dev/sdb6 NONE" in st.read_text()


def test_clear_failure_refuses(tmp_path):
    script, _ = _rig(tmp_path, LAYOUT, fail_clear=True)
    r = _run(script, "_assert_no_foreign_labels", "/dev/sda")
    assert r.returncode == 10 and "could not clear" in r.stdout


def test_wired_into_do_install_and_preseed_key():
    body = extract_fn("do_install")
    assert '_assert_no_foreign_labels "$TARGET_DISK" "${TARGET_DISK2:-}"' in body
    assert body.index("_assert_no_foreign_labels") > body.index("_assert_safe_wipe_target")
    from _installer_source import PARSER

    assert "PRESEED_CLEAR_FOREIGN_LABELS" in PARSER.read_text()


def test_fstab_still_label_based_for_new_installs():
    # UUID mounting is deliberately deferred (#4547): pin the fstab so a
    # change to it is a conscious one that also revisits the slot upgrade,
    # mirror and etc-render paths that resolve the same labels.
    assert "LABEL=var    /var" in SRC and "LABEL=ESP    /boot/efi" in SRC
    assert os.path.exists(INSTALLER)
