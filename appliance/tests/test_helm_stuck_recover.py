"""spatiumddi-helm-stuck-recover — the JSON handoff must survive a big cluster.

The runner shells out for the HelmChart CRs and hands the JSON to an inline
python3 for the Failed-condition walk. It used to hand it over as ONE
environment variable. A single environment string is capped at
MAX_ARG_STRLEN (128 KiB on Linux), and spatium-control's ``valuesContent``
alone crosses that once a control plane has been promoted (~250 KB of
rendered values on the sizing campaign's 3-node clusters, 2026-09-02) — so
the timer failed with ``Argument list too long`` on every tick, on exactly
the clusters that wedge. The JSON now rides in a temp file.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_helm_stuck_recover.py -v

No k3s, no appliance required — the python body is extracted from the real
script and run against a fixture with a stub kubectl.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCRIPT = (
    Path(__file__).parent.parent
    / "mkosi.extra"
    / "usr"
    / "local"
    / "bin"
    / "spatiumddi-helm-stuck-recover"
)
UNIT = (
    Path(__file__).parent.parent
    / "mkosi.extra"
    / "etc"
    / "systemd"
    / "system"
    / "spatiumddi-helm-stuck-recover.service"
)

# Well over MAX_ARG_STRLEN (131072): what a promoted cluster's HelmChart list
# actually weighs, padded into valuesContent the way helm renders it.
_BIG = 300 * 1024


def _python_body() -> str:
    """The heredoc between ``python3 - <<PY`` and the closing ``PY``, with the
    shell's one interpolation (``${STUCK_THRESHOLD_SECONDS}``) resolved."""
    text = SCRIPT.read_text()
    m = re.search(r"python3 - <<PY\n(.*?)\nPY\n", text, re.S)
    assert m, "python heredoc not found in the runner"
    threshold = re.search(r"^STUCK_THRESHOLD_SECONDS=(\d+)", text, re.M)
    assert threshold, "STUCK_THRESHOLD_SECONDS not found"
    return m.group(1).replace("${STUCK_THRESHOLD_SECONDS}", threshold.group(1))


def _charts(*, failed_age_s: int, pad: int) -> dict:
    """One wedged HelmChart (Failed for ``failed_age_s``) beside a healthy one,
    with ``valuesContent`` padded to ``pad`` bytes like a promoted cluster's."""
    import datetime as dt

    then = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=failed_age_s)
    stamp = then.strftime("%Y-%m-%dT%H:%M:%SZ")
    values = "api:\n  replicas: 3\n" + "".join(
        f"  pad{i}: {'x' * 60}\n" for i in range(pad // 70)
    )
    return {
        "items": [
            {
                "metadata": {"namespace": "kube-system", "name": "spatium-control"},
                "spec": {"targetNamespace": "spatium", "valuesContent": values},
                "status": {
                    "conditions": [
                        {"type": "Failed", "status": "True", "lastTransitionTime": stamp}
                    ]
                },
            },
            {
                "metadata": {"namespace": "kube-system", "name": "spatium-bootstrap"},
                "spec": {"targetNamespace": "spatium", "valuesContent": values},
                "status": {"conditions": [{"type": "Failed", "status": "False"}]},
            },
        ]
    }


def _run(tmp_path: Path, charts: dict) -> tuple[subprocess.CompletedProcess, list[str]]:
    """Run the extracted body with a stub ``k3s`` that logs every kubectl call
    and answers the release-secret listing with one orphan secret."""
    stub = tmp_path / "k3s"
    calls = tmp_path / "calls.log"
    stub.write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> "{calls}"\n'
        'case "$*" in\n'
        '  *"get secrets"*) echo "sh.helm.release.v1.spatium-control.v1 other-secret";;\n'
        "esac\n"
    )
    stub.chmod(0o755)
    body = _python_body().replace("/usr/local/bin/k3s", str(stub))
    charts_file = tmp_path / "charts.json"
    charts_file.write_text(json.dumps(charts))
    proc = subprocess.run(
        [sys.executable, "-c", body],
        env={**os.environ, "CHARTS_FILE": str(charts_file)},
        capture_output=True,
        text=True,
        check=False,
    )
    lines = calls.read_text().splitlines() if calls.exists() else []
    return proc, lines


def test_the_json_rides_in_a_file_not_the_environment() -> None:
    text = SCRIPT.read_text()
    assert "CHARTS_FILE=" in text and 'os.environ["CHARTS_FILE"]' in text
    assert 'CHARTS_JSON="$charts_json" python3' not in text
    assert "mktemp" in text and "trap 'rm -f" in text


def test_a_promoted_clusters_chart_list_is_walked_and_the_wedge_cleared(tmp_path: Path) -> None:
    charts = _charts(failed_age_s=1200, pad=_BIG)
    assert len(json.dumps(charts)) > 131072  # the E2BIG regime
    proc, calls = _run(tmp_path, charts)
    assert proc.returncode == 0, proc.stderr
    assert "CLEARING wedged HelmChart kube-system/spatium-control" in proc.stdout
    assert any("delete job helm-install-spatium-control" in c for c in calls)
    assert any("delete secret sh.helm.release.v1.spatium-control.v1" in c for c in calls)
    assert not any("other-secret" in c and "delete" in c for c in calls)
    # The healthy chart is left alone.
    assert "spatium-bootstrap" not in proc.stdout


def test_a_fresh_failure_is_left_alone_under_the_threshold(tmp_path: Path) -> None:
    proc, calls = _run(tmp_path, _charts(failed_age_s=60, pad=1024))
    assert proc.returncode == 0, proc.stderr
    assert "under threshold, leaving alone" in proc.stdout
    assert not any("delete" in c for c in calls)


def test_the_unit_orders_after_k3s_but_never_requires_or_starts_it() -> None:
    """Requires= took a running recovery tick down with every k3s restart —
    the moment the recovery is needed. Wants= started k3s from a tick that
    landed while the cluster join runner held it stopped (#1723). The runner
    already bails when the API is not ready, so After= is the whole ordering
    it needs."""
    unit = UNIT.read_text()
    assert not re.search(r"^(Wants|Requires|BindsTo)=.*\bk3s\.service\b", unit, re.MULTILINE)
    assert re.search(r"^After=.*\bk3s\.service\b", unit, re.MULTILINE)
