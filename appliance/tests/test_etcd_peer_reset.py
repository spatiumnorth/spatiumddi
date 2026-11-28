"""A kept single-node etcd whose address changed is reset, never an HA one (#4591).

``spatium-etcd-peer-reset`` (k3s.service ExecStartPre) reads k3s's own refusal
from the journal and runs ``k3s server --cluster-reset`` once when the member
list holds exactly this node. Run against stub k3s / journalctl binaries.

    python3 -m pytest appliance/tests/test_etcd_peer_reset.py -v
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

EXTRA = Path(__file__).resolve().parents[1] / "mkosi.extra"
SCRIPT = EXTRA / "usr" / "local" / "bin" / "spatium-etcd-peer-reset"

REFUSAL = (
    "Failed to test etcd connection: this server is not a member of the etcd cluster. "
    "Found [{found}], expect: n1-abc=https://10.0.0.9:2380"
)


def _run(
    tmp_path: Path,
    found: str | None,
    *,
    join: bool = False,
    config: bool = True,
    record: str | None = None,
    node_ip: str = "10.0.0.9",
    quote: bool = False,
):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    (tmp_path / "journal").write_text(
        REFUSAL.format(found=found) + ('"' if quote else "") + "\n" if found else ""
    )
    jc = bindir / "journalctl"
    jc.write_text(f'#!/bin/sh\necho "$@" >"{tmp_path}/jc.args"\ncat "{tmp_path}/journal"\n')
    k3s = bindir / "k3s"
    k3s.write_text(f'#!/bin/sh\necho "$@" >>"{tmp_path}/k3s.calls"\n')
    for f in (jc, k3s):
        f.chmod(0o755)
    cfg = tmp_path / "etcd-config"
    if config:
        cfg.write_text("name: n1-abc\n")
    dropin = tmp_path / "spatium-cluster.yaml"
    if join:
        dropin.write_text("server: https://10.0.0.1:6443\n")
    env = {
        **os.environ,
        "SPATIUM_K3S_BIN": str(k3s),
        "SPATIUM_JOURNALCTL": str(jc),
        "SPATIUM_K3S_JOIN_DROPIN": str(dropin),
        "SPATIUM_ETCD_CONFIG_FILE": str(cfg),
        "SPATIUM_ETCD_PEER_RESET_STAMP": str(tmp_path / "stamp"),
        "SPATIUM_ETCD_PEER_RESET_LOG": str(tmp_path / "log"),
        "SPATIUM_CONSOLE": str(tmp_path / "console"),
        "SPATIUM_NODE_IP": node_ip,
        "SPATIUM_ETCD_PEER_ADDR_RECORD": str(tmp_path / "addr-record"),
        "SPATIUM_ETCD_PEER_MISMATCH": str(tmp_path / "mismatch"),
    }
    if record is not None:
        (tmp_path / "addr-record").write_text(record + "\n")
    proc = subprocess.run(["sh", str(SCRIPT)], env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    calls = tmp_path / "k3s.calls"
    return proc, (calls.read_text().split() if calls.exists() else [])


def test_single_member_at_old_address_is_reset(tmp_path: Path) -> None:
    _, calls = _run(tmp_path, "n1-abc=https://10.0.0.5:2380")
    assert calls == ["server", "--cluster-reset"]
    assert (tmp_path / "stamp").read_text().strip().isdigit()
    assert "cluster-reset" in (tmp_path / "console").read_text()


def test_stamped_reset_is_not_repeated_for_old_lines(tmp_path: Path) -> None:
    # journalctl is stubbed to ignore --since, so prove the stamp is passed.
    _run(tmp_path, "n1-abc=https://10.0.0.5:2380")
    assert (tmp_path / "stamp").exists()
    text = SCRIPT.read_text()
    assert '--since "@$since"' in text


def test_journal_is_bounded_to_this_boot_and_a_recent_window(tmp_path: Path) -> None:
    # A stale refusal (earlier boot, or before the node became an HA seed) must
    # not trigger a reset: journalctl is asked for -b and a --since that is never
    # older than the window, even with no stamp.
    import time

    _run(tmp_path, "n1-abc=https://10.0.0.5:2380")
    args = (tmp_path / "jc.args").read_text().split()
    assert "-b" in args
    since = int(args[args.index("--since") + 1].lstrip("@"))
    assert since >= time.time() - 700


def test_multi_member_is_left_alone(tmp_path: Path) -> None:
    proc, calls = _run(tmp_path, "n1-abc=https://10.0.0.5:2380 n2-def=https://10.0.0.6:2380")
    assert calls == []
    assert "NOT resetting" in proc.stderr
    assert not (tmp_path / "stamp").exists()


def test_no_refusal_does_nothing(tmp_path: Path) -> None:
    _, calls = _run(tmp_path, None)
    assert calls == []


def test_joined_member_is_left_alone(tmp_path: Path) -> None:
    _, calls = _run(tmp_path, "n1-abc=https://10.0.0.5:2380", join=True)
    assert calls == []


def test_other_nodes_member_is_left_alone(tmp_path: Path) -> None:
    _, calls = _run(tmp_path, "zzz=https://10.0.0.5:2380")
    assert calls == []


def test_no_kept_datastore_does_nothing(tmp_path: Path) -> None:
    _, calls = _run(tmp_path, "n1-abc=https://10.0.0.5:2380", config=False)
    assert calls == []


def test_unit_runs_it_before_k3s() -> None:
    unit = (EXTRA / "etc" / "systemd" / "system" / "k3s.service").read_text()
    assert "ExecStartPre=-/usr/local/bin/spatium-etcd-peer-reset" in unit


def test_reason_line_has_no_stray_quote(tmp_path: Path) -> None:
    # k3s's journal line ends the expect: value with a double quote.
    _run(tmp_path, 'n1-abc=https://10.0.0.5:2380', quote=True)
    text = (tmp_path / "log").read_text()
    assert "now https://10.0.0.9:2380 (kept" in text
    assert '"' not in text


def test_multi_member_names_the_reason_for_the_console(tmp_path: Path) -> None:
    _run(tmp_path, "n1-abc=https://10.0.0.5:2380 n2-def=https://10.0.0.6:2380")
    reason = (tmp_path / "mismatch").read_text()
    assert "cannot rejoin under a new address" in reason
    assert "remove the member" in reason


def test_recorded_address_change_in_ha_is_named_without_a_refusal(tmp_path: Path) -> None:
    # An HA member never logs k3s's refusal: the recorded address is the signal.
    proc, calls = _run(tmp_path, None, record="10.0.0.5 3", node_ip="10.0.0.9")
    assert calls == []
    reason = (tmp_path / "mismatch").read_text()
    assert "10.0.0.5 -> 10.0.0.9" in reason
    assert "3-member" in reason
    assert "cannot rejoin" in (tmp_path / "console").read_text()


def test_recorded_single_node_or_same_address_is_silent_and_clears_the_flag(
    tmp_path: Path,
) -> None:
    (tmp_path / "mismatch").write_text("stale\n")
    _run(tmp_path, None, record="10.0.0.5 1", node_ip="10.0.0.9")
    assert not (tmp_path / "mismatch").exists()
    _run(tmp_path, None, record="10.0.0.9 3", node_ip="10.0.0.9")
    assert not (tmp_path / "mismatch").exists()


def test_firstboot_waits_for_a_pending_peer_reset() -> None:
    text = (EXTRA / "usr" / "local" / "bin" / "spatiumddi-firstboot").read_text()
    assert "etcd_peer_reset_pending()" in text
    assert text.index('if [ "$ready" != 1 ] && etcd_peer_reset_pending') < text.index(
        'echo "WARN: k3s /readyz did not respond within 5 minutes."'
    )
    assert "record_etcd_peer_addr" in text


def _unit_timeout_s() -> int:
    import re

    unit = (EXTRA / "etc" / "systemd" / "system" / "spatiumddi-firstboot.service").read_text()
    m = re.search(r"^TimeoutStartSec=(\d+)min$", unit, re.M)
    assert m, "TimeoutStartSec must be whole minutes"
    return int(m.group(1)) * 60


def test_unit_timeout_outlasts_the_reset_wait() -> None:
    """#4592 — systemd killed firstboot at 10 min, before the reset (which needs
    k3s's first start to give up, ~15 min after boot) could matter."""
    import re

    text = (EXTRA / "usr" / "local" / "bin" / "spatiumddi-firstboot").read_text()
    ready = int(re.search(r"for _ in \$\(seq 1 (\d+)\); do\n    if /usr/local/bin/k3s kubectl get --raw=/readyz", text).group(1)) * 5
    pend = int(re.search(r"seq 1 (\d+)\); do\n        if /usr/local/bin/k3s kubectl get --raw=/readyz", text).group(1)) * 5
    # the waits, plus the post-ready steps (slot-image window) and 5 min of margin
    assert _unit_timeout_s() >= ready + pend + 600 + 300


def test_reset_wait_re_anchors_the_image_check_window() -> None:
    text = (EXTRA / "usr" / "local" / "bin" / "spatiumddi-firstboot").read_text()
    wait = text.split('if [ "$ready" != 1 ] && etcd_peer_reset_pending', 1)[1].split('if [ "$ready" = 1 ]; then', 1)[0]
    assert "FIRSTBOOT_T0=$(uptime_s" in wait


def test_console_verdict_names_the_mismatch(tmp_path: Path) -> None:
    import ast

    console = EXTRA / "usr" / "local" / "bin" / "spatium-console"
    src = console.read_text()
    assert "etcd_peer_mismatch_reason()" in src.split("def overall_verdict", 1)[1].split(
        "def render_header", 1
    )[0]
    tree = ast.parse(src)
    body = [
        n
        for n in tree.body
        if (isinstance(n, ast.FunctionDef) and n.name == "etcd_peer_mismatch_reason")
        or (
            isinstance(n, ast.Assign)
            and any(getattr(t, "id", "") == "_ETCD_PEER_MISMATCH" for t in n.targets)
        )
    ]
    ns: dict = {"Path": Path}
    exec(compile(ast.Module(body=body, type_ignores=[]), "c", "exec"), ns)  # noqa: S102
    flag = tmp_path / "flag"
    ns["_ETCD_PEER_MISMATCH"] = flag
    assert ns["etcd_peer_mismatch_reason"]() == ""
    flag.write_text("address changed\n")
    assert ns["etcd_peer_mismatch_reason"]() == "address changed"


def _record_fn() -> str:
    text = (EXTRA / "usr" / "local" / "bin" / "spatiumddi-firstboot").read_text()
    start = text.index("record_etcd_peer_addr() {")
    return text[start : text.index("\n}\n", start) + 3]


def test_record_never_ends_firstboot_before_the_node_registers(tmp_path: Path) -> None:
    """#4592: on a fresh install the Node is not registered yet when /readyz
    answers; ``grep -c`` then exits 1, and under ``set -eu`` the assignment
    ended firstboot. The function must return, and the script must go on."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in {
        "k3s": "#!/bin/sh\nexit 0\n",  # no nodes yet
        "ip": "#!/bin/sh\necho '2: eth0    inet 10.0.0.9/24 brd 10.0.0.255 scope global eth0'\n",
        "sleep": "#!/bin/sh\nexit 0\n",
    }.items():
        p = bin_dir / name
        p.write_text(body)
        p.chmod(0o755)
    fn = _record_fn().replace("/usr/local/bin/k3s", str(bin_dir / "k3s"))
    script = f"set -eu\n{fn}\nrecord_etcd_peer_addr\necho AFTER\n"
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin"}
    proc = subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "AFTER" in proc.stdout


def test_record_is_called_last_and_guarded() -> None:
    text = (EXTRA / "usr" / "local" / "bin" / "spatiumddi-firstboot").read_text()
    ready = text.split('if [ "$ready" = 1 ]; then', 1)[1].split("\nfi\n", 1)[0]
    assert "record_etcd_peer_addr || true" in ready
    assert ready.index("record_etcd_peer_addr || true") > ready.index("commit_slot_if_healthy")
    assert ready.count("record_etcd_peer_addr") == 1
