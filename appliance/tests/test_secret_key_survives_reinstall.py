"""SECRET_KEY must survive a helm uninstall/reinstall (#1042).

`app/core/crypto.py` derives the at-rest Fernet key from SECRET_KEY whenever
no explicit CREDENTIAL_ENCRYPTION_KEY is set — which is every appliance. So
the chart-owned Secret carrying `secret-key` is the root of everything
`encrypt_str` ever wrote: the appliance CA private key, appliance certs,
integration credentials, OIDC/SAML secrets — plus every JWT.

A k3s HelmChart defaults to `failurePolicy: reinstall`, documented as "a
clean uninstall and reinstall of the chart". On three ddi-pg slot-upgrade
walks helm-controller took that path, the unannotated Secret was deleted, the
reinstall's `lookup` found nothing, `randAlphaNum 64` minted a new key, and
cluster member approval started answering 500 with
`ValueError: encrypted value could not be decrypted` — while the control
plane still reported healthy. The Postgres and Redis secrets survived the
same event purely because they carry `helm.sh/resource-policy: keep`.

Two independent guards, because each closes the hole for a different
deployment shape: the annotation protects anyone whose chart owns the Secret
(plain Kubernetes / Helm), and on the appliance `failurePolicy: retry` stops
helm-controller taking the destructive path at all (#1299): `helm uninstall`
keeps only what the release's LAST stored revision annotates, and after a slot
rollback to a release older than #1044 that revision is the old chart's, which
has no `keep` (test_firstboot_failure_policy.py pins the HelmChartConfig half).

    python3 -m pytest appliance/tests/test_secret_key_survives_reinstall.py -v
"""

from __future__ import annotations

import base64
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
FIRSTBOOT = REPO / "appliance" / "mkosi.extra" / "usr" / "local" / "bin" / "spatiumddi-firstboot"
CHART_TEMPLATES = REPO / "charts" / "spatiumddi" / "templates"

pytestmark = pytest.mark.skipif(
    not FIRSTBOOT.exists(), reason="appliance tree not present in this checkout"
)


# ── the chart half ───────────────────────────────────────────────────────────


def _generated_credential_secrets() -> list[Path]:
    """Secret templates that MINT a credential when none exists.

    Those are exactly the ones a delete-and-recreate silently rotates. Found
    by their generator rather than by name, so a fourth one cannot be added
    without either carrying the annotation or failing this test.
    """
    found = []
    for path in sorted(CHART_TEMPLATES.glob("*.yaml")):
        body = path.read_text(encoding="utf-8")
        if "kind: Secret" in body and re.search(r"\brandAlphaNum\b", body):
            found.append(path)
    return found


#: The annotation as a real YAML entry, with the value that matters. Matching
#: the key name anywhere in the file passed with the whole `annotations:` block
#: deleted, because this template's own header prose explains the annotation —
#: proven, and exactly the vacuous-guard shape these tests exist to prevent.
_KEEP_ENTRY = re.compile(r'^\s*"?helm\.sh/resource-policy"?\s*:\s*keep\s*$', re.M)

#: Helm's `{{/* … */}}` comments, stripped before matching so prose about the
#: annotation can never satisfy the assertion.
_HELM_COMMENT = re.compile(r"\{\{-?/\*.*?\*/-?\}\}", re.S)


def _body_without_comments(path: Path) -> str:
    body = _HELM_COMMENT.sub("", path.read_text(encoding="utf-8"))
    return "\n".join(
        ln for ln in body.splitlines() if not ln.lstrip().startswith("#")
    )


def test_generated_credential_secrets_are_kept_across_uninstall() -> None:
    missing = [
        p.name
        for p in _generated_credential_secrets()
        if not _KEEP_ENTRY.search(_body_without_comments(p))
    ]
    assert not missing, (
        "these templates mint a credential but do not carry "
        f"`helm.sh/resource-policy: keep` as a real annotation: {missing}"
    )


def test_the_app_secret_is_one_of_them() -> None:
    """Negative control on the finder itself.

    If `secret.yaml` ever stops being detected — renamed generator, moved
    file — the test above would pass by looking at nothing, which is the
    failure mode this whole change exists to stop.
    """
    names = [p.name for p in _generated_credential_secrets()]
    assert "secret.yaml" in names, f"SECRET_KEY's template is not being checked: {names}"


# ── the appliance half ───────────────────────────────────────────────────────


def _render_control_helmchart() -> dict:
    """Execute firstboot's own renderer and parse the manifest it emits."""
    src = FIRSTBOOT.read_text(encoding="utf-8")
    fn = re.search(r"^_render_control_helmchart\(\) \{.*?^\}$", src, re.S | re.M)
    assert fn, "firstboot no longer defines _render_control_helmchart"
    script = f"""
        set -euo pipefail
        {fn.group(0)}
        SPATIUMDDI_VERSION=0.0.0-test
        DNS_AGENT_KEY_VAL=x
        DHCP_AGENT_KEY_VAL=x
        LG_AGENT_KEY_VAL=x
        APPLIANCE_HOSTNAME_VAL=test
        APPLIANCE_HOST_IPS_VAL=10.0.0.1
        INITIAL_NTP_SERVERS_VAL=""
        CHART_TGZ=/nonexistent
        _render_control_helmchart "Y2hhcnQ="
    """
    out = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, check=True
    ).stdout
    return yaml.safe_load(out)


def test_the_control_helmchart_does_not_set_abort() -> None:
    """`abort` was considered and REJECTED (#1042) — this pins that decision.

    spatiumddi-helm-stuck-recover only acts on a HelmChart carrying a `Failed`
    condition, and only after a 600 s latch on a 5 min tick, so a release left
    `pending-upgrade` by the slot reboot may never qualify: `abort` there risks an
    indefinite outage with no API and no UI.
    """
    manifest = _render_control_helmchart()
    assert manifest["spec"].get("failurePolicy") != "abort", (
        "failurePolicy: abort defers recovery to a timer that may never fire "
        "for a pending-upgrade release — see this test's docstring"
    )


def test_the_control_helmchart_retries_instead_of_reinstalling() -> None:
    """`retry`, not the CRD default `reinstall` (#1299).

    #1042 kept `reinstall` and relied on `keep` to carry the Secret through its
    uninstall half. `helm uninstall` decides what to keep from the LAST stored
    revision's manifest, never from the live object, so after a slot rollback to a
    release older than #1044 (2026.09.04-1) the next reinstall deleted the Secret
    and minted a new SECRET_KEY. `retry` (helm-controller v0.17.7, k3s v1.36.4+k3s1)
    upgrades a failed release again and never deletes any of it, and unlike `abort`
    it does not wait for an operator. A HelmChartConfig's policy overrides this
    one; test_firstboot_failure_policy.py pins that half.
    """
    manifest = _render_control_helmchart()
    assert manifest["spec"].get("failurePolicy") == "retry"


def test_values_content_still_parses() -> None:
    """Cheap structural check on the manifest the appliance actually applies."""
    values = yaml.safe_load(_render_control_helmchart()["spec"]["valuesContent"])
    assert isinstance(values, dict) and values, "firstboot rendered no values"


# ── the render check must never echo a secret value ─────────────────────────

RENDER_CHECK = REPO / ".github" / "scripts" / "chart-credential-secrets-kept.py"


@pytest.mark.skipif(not RENDER_CHECK.exists(), reason="render check not in this checkout")
def test_the_render_check_never_prints_a_secret_value(tmp_path: Path) -> None:
    """CodeQL flags this script, and the flag is a false positive — pinned here.

    `py/clear-text-logging-sensitive-data` taints the WHOLE parsed document
    because it is a `Secret`, so every value derived from it is suspect —
    including `metadata.name`, which is in any `kubectl get secrets` listing.
    Removing the key names from the message did not clear it and could not.

    Rather than dismiss on reasoning alone, this plants a canary in the Secret
    and asserts it cannot reach the output on the FAILURE path — the only path
    that prints anything per-Secret. If a future edit starts echoing the data
    section, this fails even though CodeQL's verdict never changed.
    """
    doc = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "release-spatiumddi-app"},  # deliberately no annotations
        "stringData": {"secret-key": "SUPERSECRETCANARY12345"},
    }
    render = tmp_path / "render.yaml"
    render.write_text(yaml.safe_dump(doc), encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, str(RENDER_CHECK), str(render)], capture_output=True, text=True
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, f"the failure path was not exercised:\n{out}"
    assert "release-spatiumddi-app" in out, "the Secret's name is the whole diagnostic"
    assert "SUPERSECRETCANARY12345" not in out, f"the secret VALUE leaked:\n{out}"
    assert (
        base64.b64encode(b"SUPERSECRETCANARY12345").decode() not in out
    ), f"the secret value leaked base64-encoded:\n{out}"
