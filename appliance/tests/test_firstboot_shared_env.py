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

# Read by code that runs in the worker (appliance_mode gates, cert SAN
# bootstrap helpers, the settings row's NTP seed).
SHARED = {"APPLIANCE_MODE", "APPLIANCE_HOSTNAME", "APPLIANCE_HOST_IPS", "INITIAL_NTP_SERVERS"}


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
