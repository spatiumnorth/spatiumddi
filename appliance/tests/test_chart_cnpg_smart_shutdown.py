"""#2878: every CNPG Cluster bounds its smart shutdown.

One Postgres instance has no replica to switch over to, so a spec change that
rolls it restarts it in place. Demoting both members of a three-node cluster
is such a change: the Postgres limit follows the control-plane size (#2156),
and the demote moves it. CloudNativePG's instance manager then runs a smart
shutdown, which refuses every new connection, for up to
``smartShutdownTimeout``. The services' pooled sessions never end on their
own, so it always runs that long, and the chart left CNPG's 180 s: the api's
new pods reached no database, and every request through the appliance's
nginx answered 502 for well over three minutes after the demote.

The chart now renders ``smartShutdownTimeout`` at every instance count (a
Cluster already carries it when a demote leaves it one instance), and
``.github/scripts/chart-cnpg-recovery.py`` refuses a render without a bounded
one. The script runs in the Charts job (helm renders, no pytest), so its rule
is pinned here with negative controls: a guard that fails open ships the
defect green.

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_chart_cnpg_smart_shutdown.py -v
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent.parent
SCRIPT = ROOT / ".github" / "scripts" / "chart-cnpg-recovery.py"
UMBRELLA = ROOT / "charts" / "spatiumddi"
NO_VALUE = object()


def _cluster(instances: int, smart: object = NO_VALUE) -> str:
    method = "\n  primaryUpdateMethod: switchover" if instances > 1 else ""
    line = "" if smart is NO_VALUE else f"\n  smartShutdownTimeout: {smart}"
    return textwrap.dedent(
        """\
        apiVersion: postgresql.cnpg.io/v1
        kind: Cluster
        metadata:
          name: x-spatiumddi-postgresql
        spec:
          instances: {instances}{method}{line}
          storage:
            size: 8Gi
          postgresql:
            parameters:
              max_slot_wal_keep_size: 3GB
              wal_keep_size: 2GB
        """
    ).format(instances=instances, method=method, line=line)


def _run(manifest: str, tmp_path: Path) -> subprocess.CompletedProcess:
    path = tmp_path / "render.yaml"
    path.write_text(manifest, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--require-cluster", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_bounded_smart_shutdown_passes_at_every_instance_count(tmp_path: Path) -> None:
    for instances in (1, 3):
        for smart in (0, 15, 30):
            res = _run(_cluster(instances, smart), tmp_path)
            assert res.returncode == 0, (instances, smart, res.stderr)


def test_cnpgs_default_left_unset_fails(tmp_path: Path) -> None:
    # The instance count does not excuse it: a demote leaves one instance, and
    # the bound must already be on the Cluster when that happens.
    for instances in (1, 3):
        res = _run(_cluster(instances), tmp_path)
        assert res.returncode == 1, instances
        assert "#2878" in res.stderr and "unset" in res.stderr


def test_a_long_or_malformed_smart_shutdown_fails(tmp_path: Path) -> None:
    for smart in (31, 180, -1, '"15"', "15.5", "true"):
        res = _run(_cluster(1, smart), tmp_path)
        assert res.returncode == 1, (smart, res.stderr)
        assert "#2878" in res.stderr, smart


def test_the_other_rules_still_run_beside_it(tmp_path: Path) -> None:
    # Each rule reports on its own: an unbounded smart shutdown does not hide
    # the #2317 WAL cap or the #2831 primary update.
    bad = _cluster(3).replace("max_slot_wal_keep_size: 3GB", "max_slot_wal_keep_size: -1")
    bad = bad.replace("primaryUpdateMethod: switchover", "primaryUpdateMethod: restart")
    res = _run(bad, tmp_path)
    assert res.returncode == 1
    for issue in ("#2878", "#2831", "#2317"):
        assert issue in res.stderr, issue


def test_the_chart_renders_a_bounded_smart_shutdown_at_every_instance_count() -> None:
    values = yaml.safe_load((UMBRELLA / "values.yaml").read_text(encoding="utf-8"))
    smart = values["postgresql"]["cnpg"]["smartShutdownTimeout"]
    assert isinstance(smart, int) and 0 <= smart <= 30
    template = (UMBRELLA / "templates" / "cnpg-cluster.yaml").read_text(encoding="utf-8")
    line = "smartShutdownTimeout: {{ .Values.postgresql.cnpg.smartShutdownTimeout }}"
    assert line in template
    # Outside the instance-count condition: the field must not depend on it.
    gate = template.index("if gt (int .Values.postgresql.cnpg.instances) 1")
    end = template.index("{{- end }}", gate)
    assert not gate < template.index(line) < end
