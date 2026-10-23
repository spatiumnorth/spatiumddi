"""firstboot puts the appliance env on the worker and beat, not only the api (#1826).

``APPLIANCE_MODE`` used to sit under ``api.env``, so the Celery worker (which
runs alert evaluation and the rolling-upgrade orchestrator) and beat ran with
it unset. Every ``settings.appliance_mode`` gate then read as off in the one
process that evaluates ``node_pressure`` and ``cluster_dns_degraded``, with
no error anywhere. The chart's ``sharedEnv`` is appended to api, worker and
beat; this pins that firstboot uses it.

The firstboot function is executed and its output parsed, not pattern-matched:
a key that is written but never interpolated would pass a regex.

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_firstboot_shared_env.py -v
"""

from __future__ import annotations

import re
import subprocess

import yaml
from _installer_source import BIN

FIRSTBOOT = (BIN / "spatiumddi-firstboot").read_text(encoding="utf-8")

# APPLIANCE_MODE is the live fix: the worker's appliance_mode gates. The other
# three are the cluster-wide seed identity and the settings row's NTP seed;
# no worker code path reads them today, but the three processes share one
# ``settings`` and a task that ever creates the platform_settings row lazily
# must seed it from the operator's Time-source answer, not the default pool.
SHARED = {
    "APPLIANCE_MODE",
    "APPLIANCE_HOSTNAME",
    "APPLIANCE_HOST_IPS",
    "INITIAL_NTP_SERVERS",
}


def _values() -> dict:
    fn = re.search(r"^_render_control_helmchart\(\) \{.*?^\}$", FIRSTBOOT, re.DOTALL | re.MULTILINE)
    assert fn, "firstboot no longer defines _render_control_helmchart"
    script = f"""
        set -euo pipefail
        {fn.group(0)}
        SPATIUMDDI_VERSION=0.0.0-test
        APP_KEY_SECRET=spatium-control-app-keys
        CHART_APP_SECRET=spatium-control-spatiumddi-app
        DNS_AGENT_KEY_VAL=x
        DHCP_AGENT_KEY_VAL=x
        LG_AGENT_KEY_VAL=x
        APPLIANCE_HOSTNAME_VAL=test
        APPLIANCE_HOST_IPS_VAL=10.0.0.1
        INITIAL_NTP_SERVERS_VAL=""
        CHART_TGZ=/nonexistent
        _render_control_helmchart "Y2hhcnQ="
    """
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True).stdout
    manifest = yaml.safe_load(out)
    return yaml.safe_load(manifest["spec"]["valuesContent"])


def _names(entries: list[dict]) -> list[str]:
    return [e["name"] for e in entries or []]


def test_appliance_env_is_in_shared_env() -> None:
    shared = _names(_values().get("sharedEnv"))
    assert SHARED <= set(shared), f"sharedEnv is missing {sorted(SHARED - set(shared))}"
    assert shared.count("APPLIANCE_MODE") == 1


def test_appliance_mode_is_true() -> None:
    entries = {e["name"]: e["value"] for e in _values()["sharedEnv"]}
    assert entries["APPLIANCE_MODE"] == "true"


def test_no_shared_variable_is_left_on_the_api_alone() -> None:
    """A copy under api.env is the bug coming back: the api has it, the worker
    does not, and a duplicate name on the api container is order-dependent."""
    api_env = _names(_values()["api"].get("env"))
    assert not (SHARED & set(api_env)), sorted(SHARED & set(api_env))


def test_appliance_version_is_a_value_of_its_own_not_a_shared_env_entry() -> None:
    """#2176: a cluster Rolling Upgrade holds the version with ``image.tag`` in
    the control chart's HelmChartConfig until every node runs the target. A
    HelmChartConfig replaces a list whole, so as a ``sharedEnv`` entry the
    version could not be held, and the seed's re-render on its new slot rolled
    the api, worker and beat mid-run. The chart appends ``applianceVersion`` to
    the same env as APPLIANCE_VERSION (charts-render-check.sh renders it)."""
    vals = _values()
    assert "APPLIANCE_VERSION" not in _names(vals.get("sharedEnv"))
    assert "APPLIANCE_VERSION" not in _names(vals["api"].get("env"))
    assert "applianceVersion" in vals
    assert isinstance(vals["applianceVersion"], str)


def test_appliance_version_is_stamped_from_the_slot_release_file(tmp_path) -> None:
    """#2004: the pods got no APPLIANCE_VERSION. Executes firstboot's real
    version-stamping block against a fake release file, then the real render,
    so an upgrade (new file contents) is seen to change the rendered value."""
    blk = re.search(
        r"^APPLIANCE_VERSION_VAL=\"\"\nif \[ -f /etc/spatiumddi/appliance-release \].*?^fi$",
        FIRSTBOOT,
        re.DOTALL | re.MULTILINE,
    )
    assert blk, "firstboot no longer derives APPLIANCE_VERSION_VAL every boot"
    fn = re.search(r"^_render_control_helmchart\(\) \{.*?^\}$", FIRSTBOOT, re.DOTALL | re.MULTILINE)
    assert fn

    def render(release: str | None, inherited: str = "") -> dict:
        rel = tmp_path / "appliance-release"
        rel.unlink(missing_ok=True)
        if release is not None:
            rel.write_text(f"APPLIANCE_VERSION={release}\n" if release else "OTHER=1\n")
        block = blk.group(0).replace("/etc/spatiumddi/appliance-release", str(rel))
        script = f"""
            set -euo pipefail
            APPLIANCE_VERSION={inherited!r}
            {fn.group(0)}
            {block}
            SPATIUMDDI_VERSION=0.0.0-test
            APP_KEY_SECRET=a; CHART_APP_SECRET=b
            DNS_AGENT_KEY_VAL=x; DHCP_AGENT_KEY_VAL=x; LG_AGENT_KEY_VAL=x
            APPLIANCE_HOSTNAME_VAL=test; APPLIANCE_HOST_IPS_VAL=10.0.0.1
            INITIAL_NTP_SERVERS_VAL=""; CHART_TGZ=/nonexistent
            _render_control_helmchart "Y2hhcnQ="
        """
        out = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, check=True
        ).stdout
        vals = yaml.safe_load(yaml.safe_load(out)["spec"]["valuesContent"])
        return vals["applianceVersion"]

    assert render("2026.10.16-1") == "2026.10.16-1"
    assert render("1.0.0") == "1.0.0"  # upgrade / rollback
    assert render(None) == ""  # unknown, not a made-up value
    # A release file without the key reads as unknown even though the .env
    # reconcile earlier in firstboot left APPLIANCE_VERSION set in the shell.
    assert render("", inherited="0.1.0") == ""
