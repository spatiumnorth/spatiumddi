"""The #1103 MetalLB install-ordering guards actually fail when they should.

``.github/scripts/chart-webhooks-fail-open.py`` is the gate that stops the
MetalLB validating webhooks drifting back to ``failurePolicy: Fail``. Like the
other chart gates it fails OPEN by construction — a bug that makes it skip a
webhook reports "ok" — so every passing case here is paired with a negative
control that must FAIL.

The second half pins the BGPPeer to its CRD's storage version. A conversion
webhook has no failure policy, so a BGPPeer written at a non-storage version
is refused while the controller is starting no matter what the gate above
checks — the same #1103 loop, reached by enabling MetalLB and BGP together.

Lives in ``appliance/tests`` for the reason ``test_chart_pod_posture.py``
gives: the hermetic pytest job with PyYAML that runs on every PR.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_chart_webhooks_fail_open.py -v
"""

from __future__ import annotations

import re
import subprocess
import sys
import textwrap
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO / ".github" / "scripts" / "chart-webhooks-fail-open.py"
BGP_TEMPLATE = REPO / "charts" / "spatiumddi-metallb" / "templates" / "metallb-bgp.yaml"
METALLB_CRDS = (
    REPO
    / "appliance"
    / "mkosi.extra"
    / "usr"
    / "local"
    / "share"
    / "spatiumddi"
    / "metallb-crds.yaml"
)


def _webhook(policy: str | None) -> str:
    line = f"\n    failurePolicy: {policy}" if policy is not None else ""
    return f"""
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: metallb-webhook-configuration
webhooks:
  - name: ipaddresspoolvalidationwebhook.metallb.io{line}
    sideEffects: None
"""


NOT_A_WEBHOOK = """
apiVersion: v1
kind: ConfigMap
metadata:
  name: x
"""


def _run(manifest: str, tmp_path: Path, *flags: str) -> subprocess.CompletedProcess:
    f = tmp_path / "render.yaml"
    f.write_text(textwrap.dedent(manifest))
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(f), *flags],
        capture_output=True,
        text=True,
        check=False,
    )


def test_script_exists() -> None:
    assert SCRIPT.is_file(), f"{SCRIPT} missing — the Charts job calls it by path"


def test_ignore_passes(tmp_path: Path) -> None:
    r = _run(_webhook("Ignore"), tmp_path, "--require")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "1 webhook(s) fail open" in r.stdout


def test_fail_is_refused(tmp_path: Path) -> None:
    r = _run(_webhook("Fail"), tmp_path, "--require")
    assert r.returncode == 1
    assert "ipaddresspoolvalidationwebhook.metallb.io" in r.stdout


def test_absent_policy_is_refused(tmp_path: Path) -> None:
    # The apiserver defaults an absent failurePolicy to Fail.
    r = _run(_webhook(None), tmp_path, "--require")
    assert r.returncode == 1


def test_no_webhook_fails_only_with_require(tmp_path: Path) -> None:
    assert _run(NOT_A_WEBHOOK, tmp_path).returncode == 0
    assert _run(NOT_A_WEBHOOK, tmp_path, "--require").returncode == 1


def test_unknown_flag_is_refused(tmp_path: Path) -> None:
    # A typo'd --require must not turn "no webhook rendered" into a pass.
    r = _run(NOT_A_WEBHOOK, tmp_path, "--requre")
    assert r.returncode == 2
    assert "--requre" in r.stderr


def _storage_version(crd_name: str) -> str:
    for doc in yaml.safe_load_all(METALLB_CRDS.read_text(encoding="utf-8")):
        if doc and doc.get("metadata", {}).get("name") == crd_name:
            stored = [v["name"] for v in doc["spec"]["versions"] if v.get("storage")]
            assert len(stored) == 1, stored
            return stored[0]
    raise AssertionError(f"{crd_name} not in {METALLB_CRDS}")


def test_bgppeer_is_written_at_its_storage_version() -> None:
    storage = _storage_version("bgppeers.metallb.io")
    text = BGP_TEMPLATE.read_text(encoding="utf-8")
    m = re.search(r"^apiVersion:\s*(\S+)\s*\nkind:\s*BGPPeer\s*$", text, re.MULTILINE)
    assert m, "no BGPPeer in the BGP template"
    assert m.group(1) == f"metallb.io/{storage}", (
        f"BGPPeer rendered as {m.group(1)} but the CRD stores {storage}: the "
        "create then needs the conversion webhook, which cannot fail open (#1103)"
    )
