"""firstboot's control-plane sizing matches the supervisor's (#1003 item 4).

firstboot used to render the chart with the values-file defaults (api 512Mi)
and the supervisor's first heartbeat re-rendered it sized to the node — so
every install paid for a second helm-install Job, a second migrate Job and an
api + worker rollout, three minutes into a box that was already up.

firstboot now computes the same numbers up front. That means the formula
exists twice, in bash and in Python, which is a drift risk — so this test
runs BOTH and requires them to agree. Same pattern as
``test_role_chart_values.py``, which pins the same script's role-chart values
to the Python (#992).

#1115 added the Postgres terms — the platform reserve, the CloudNativePG
instance limit and shared_buffers — and for the database the first render
matters more than for the api: a resources change on a formed cluster is a
CNPG rolling restart, so firstboot's copy is what keeps a fresh install from
rolling its database three minutes after it came up.

The bash is executed, not pattern-matched: integer division in shell truncates
where Python's ``int(x * 0.5)`` may not, and the clamps are written as
different expressions in the two languages. Only running them finds that.
"""

from __future__ import annotations

import re
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

from spatium_supervisor import k8s_api


def _firstboot() -> Path:
    """Locate spatiumddi-firstboot by walking up to the repo root.

    Deliberately RAISES rather than skipping when it cannot be found. A
    cross-repo-boundary test that quietly skips is one that reports a clean
    pass while checking nothing — and this is the only thing standing between
    the two copies of the sizing formula.
    """
    rel = "appliance/mkosi.extra/usr/local/bin/spatiumddi-firstboot"
    for parent in Path(__file__).resolve().parents:
        candidate = parent / rel
        if candidate.is_file():
            return candidate
    raise AssertionError(
        f"could not find {rel} above {__file__} — this test pins firstboot's "
        f"sizing arithmetic to k8s_api.control_plane_resources and cannot "
        f"run without both"
    )


FIRSTBOOT = _firstboot()

# Real appliance sizes plus the clamp boundaries on both sides.
_SIZES = [
    1024,      # tiny — below every floor
    2048,      # budget 0 after the #1115 reserve
    3072,      # budget 1024: every share below its floor
    3943,      # the 4 GiB Proxmox VM in the #1003 report
    5931,      # the QA fleet's standard appliance (the #1115 base rig)
    6144,
    8192,
    12288,     # _WORKER_SMALL_NODE_MIB exactly (concurrency boundary)
    12289,     # one MiB over it
    16384,
    32768,
    65536,     # api clamp ceiling
    262144,    # far past every ceiling
]


def _bash_sizing(mem_mib: int) -> dict[str, int]:
    """Run firstboot's own arithmetic — INCLUDING its call arguments.

    The first version of this extracted the generic ``_clamp_mib`` helper and
    then supplied ``1 2 1024 8192`` / ``1 4 1024 4096`` / ``12288`` from the
    test. Those literals ARE the copy of the formula, so the guard covered
    everything except the numbers that can drift: a review changed firstboot's
    api fraction to 1/3 and all 13 sizing tests plus all 507 appliance tests
    stayed green.

    Now the invocation lines are extracted with anchored regexes and each
    match is asserted, so a retuned constant either moves the test with it or
    fails the extraction outright. #1115's reserve, Postgres clamp and
    shared_buffers divisor are extracted the same way.
    """
    src = FIRSTBOOT.read_text(encoding="utf-8")
    clamp = re.search(r"^[ \t]*_clamp_mib\(\) \{.*?^[ \t]*\}", src, re.S | re.MULTILINE)
    assert clamp, "firstboot no longer defines _clamp_mib"

    reserve = re.search(r"BUDGET_MIB=\$\(\( MEM_TOTAL_MIB - (\d+) \)\)", src)
    assert reserve, "could not find firstboot's platform reserve"
    api = re.search(
        r'API_MEM_MIB=\$\(_clamp_mib "\$BUDGET_MIB" (\d+) (\d+) (\d+) (\d+)\)', src
    )
    assert api, "could not find firstboot's API_MEM_MIB invocation"
    wrk = re.search(
        r'WORKER_MEM_MIB=\$\(_clamp_mib "\$BUDGET_MIB" (\d+) (\d+) (\d+) (\d+)\)', src
    )
    assert wrk, "could not find firstboot's WORKER_MEM_MIB invocation"
    pg = re.search(
        r'POSTGRES_MEM_MIB=\$\(_clamp_mib "\$BUDGET_MIB" (\d+) (\d+) (\d+) (\d+)\)', src
    )
    assert pg, "could not find firstboot's POSTGRES_MEM_MIB invocation"
    sb = re.search(r"POSTGRES_SHARED_BUFFERS_MB=\$\(\( POSTGRES_MEM_MIB / (\d+) \)\)", src)
    assert sb, "could not find firstboot's shared_buffers divisor"
    req = re.search(
        r'if \[ "\$POSTGRES_MEM_REQUEST_MIB" -lt (\d+) \]; '
        r"then POSTGRES_MEM_REQUEST_MIB=(\d+); fi",
        src,
    )
    assert req, "could not find firstboot's Postgres request floor"
    thr = re.search(r'\[ "\$MEM_TOTAL_MIB" -le (\d+) \]; then WORKER_CONCURRENCY=(\d+); else WORKER_CONCURRENCY=(\d+)', src)
    assert thr, "could not find firstboot's concurrency threshold"

    script = f"""
        set -euo pipefail
        {textwrap.dedent(clamp.group(0))}
        MEM_TOTAL_MIB={mem_mib}
        BUDGET_MIB=$(( MEM_TOTAL_MIB - {reserve.group(1)} ))
        if [ "$BUDGET_MIB" -lt 0 ]; then BUDGET_MIB=0; fi
        API_MEM_MIB=$(_clamp_mib "$BUDGET_MIB" {api.group(1)} {api.group(2)} {api.group(3)} {api.group(4)})
        WORKER_MEM_MIB=$(_clamp_mib "$BUDGET_MIB" {wrk.group(1)} {wrk.group(2)} {wrk.group(3)} {wrk.group(4)})
        POSTGRES_MEM_MIB=$(_clamp_mib "$BUDGET_MIB" {pg.group(1)} {pg.group(2)} {pg.group(3)} {pg.group(4)})
        POSTGRES_SHARED_BUFFERS_MB=$(( POSTGRES_MEM_MIB / {sb.group(1)} ))
        POSTGRES_MEM_REQUEST_MIB=$POSTGRES_SHARED_BUFFERS_MB
        if [ "$POSTGRES_MEM_REQUEST_MIB" -lt {req.group(1)} ]; then POSTGRES_MEM_REQUEST_MIB={req.group(2)}; fi
        if [ "$MEM_TOTAL_MIB" -le {thr.group(1)} ]; then C={thr.group(2)}; else C={thr.group(3)}; fi
        echo "$API_MEM_MIB $WORKER_MEM_MIB $POSTGRES_MEM_MIB $POSTGRES_SHARED_BUFFERS_MB $C $POSTGRES_MEM_REQUEST_MIB"
    """
    out = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, check=True
    ).stdout.split()
    return {
        "api": int(out[0]),
        "worker": int(out[1]),
        "postgres": int(out[2]),
        "shared_buffers": int(out[3]),
        "concurrency": int(out[4]),
        "postgres_request": int(out[5]),
    }


@pytest.mark.parametrize("mem_mib", _SIZES)
def test_bash_and_python_agree(mem_mib: int) -> None:
    py = k8s_api.control_plane_resources(mem_mib)
    sh = _bash_sizing(mem_mib)
    assert py["api"]["resources"]["limits"]["memory"] == f"{sh['api']}Mi"
    assert py["worker"]["resources"]["limits"]["memory"] == f"{sh['worker']}Mi"
    assert py["worker"]["concurrency"] == sh["concurrency"]
    assert py["postgresql"]["resources"]["limits"]["memory"] == f"{sh['postgres']}Mi"
    assert (
        py["postgresql"]["cnpg"]["parameters"]["shared_buffers"]
        == f"{sh['shared_buffers']}MB"
    )
    assert (
        py["postgresql"]["resources"]["requests"]["memory"]
        == f"{sh['postgres_request']}Mi"
    )


def _render_control_values_at(mem_mib: int) -> dict:
    """firstboot's ``_render_control_helmchart`` with MemTotal pinned.

    ``test_helmchartconfig_noop`` renders the function against the runner's
    real /proc/meminfo (None on a developer mac, so both sides render nothing).
    This pins the awk read to a number so the rendered VALUES — not only the
    arithmetic — can be compared with the supervisor's at sizes that matter.
    Only that one line is substituted; the rest is the shipped function.
    """
    src = FIRSTBOOT.read_text(encoding="utf-8")
    fn = re.search(r"^_render_control_helmchart\(\) \{.*?^\}$", src, re.DOTALL | re.MULTILINE)
    assert fn, "firstboot no longer defines _render_control_helmchart"
    awk = "awk '/^MemTotal:/ {print int($2/1024); exit}' /proc/meminfo 2>/dev/null || true"
    assert awk in fn.group(0), "firstboot's MemTotal read moved"
    body = fn.group(0).replace(awk, f"echo {mem_mib}")
    script = f"""
        set -euo pipefail
        {body}
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
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    manifest = yaml.safe_load(out.stdout)
    return yaml.safe_load(manifest["spec"]["valuesContent"])


@pytest.mark.parametrize("mem_mib", [3943, 5931, 8192, 12288, 65536])
def test_the_first_render_carries_the_supervisors_postgres_sizing(mem_mib: int) -> None:
    """The sequencing contract of #1115: the Cluster is CREATED with its size.

    A supervisor-only fix always lands after the chart's first render (the
    heartbeat needs the api up, which needs the chart applied — observed on
    nightly-2026.09.16: HelmChart 18:01:42Z, Cluster 18:01:46Z, the first
    override pass 18:04:39Z), and a resources change on a formed CNPG
    cluster is a rolling restart. So firstboot must render exactly the
    ``postgresql`` values the supervisor would write, or every fresh install
    rolls its database minutes after it came up.
    """
    values = _render_control_values_at(mem_mib)
    py = k8s_api.control_plane_resources(mem_mib)
    assert values["postgresql"]["resources"] == py["postgresql"]["resources"]
    assert (
        values["postgresql"]["cnpg"]["parameters"]
        == py["postgresql"]["cnpg"]["parameters"]
    )
    # ...beside what the block already carried.
    assert values["postgresql"]["kind"] == "cnpg"
    assert values["postgresql"]["cnpg"]["instances"] == 1
    assert values["postgresql"]["cnpg"]["podAntiAffinityType"] == "required"
    assert values["api"]["resources"] == py["api"]["resources"]
    assert values["worker"]["resources"] == py["worker"]["resources"]
    assert values["worker"]["concurrency"] == py["worker"]["concurrency"]
    # The guard the first heartbeat runs (#1005) then finds nothing to write.
    assert k8s_api._deep_merge(values, py) == values


def test_an_unreadable_memtotal_renders_no_postgres_fragment_and_stays_valid() -> None:
    src = FIRSTBOOT.read_text(encoding="utf-8")
    fn = re.search(r"^_render_control_helmchart\(\) \{.*?^\}$", src, re.DOTALL | re.MULTILINE)
    assert fn
    awk = "awk '/^MemTotal:/ {print int($2/1024); exit}' /proc/meminfo 2>/dev/null || true"
    body = fn.group(0).replace(awk, "true")
    script = f"""
        set -euo pipefail
        {body}
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
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    values = yaml.safe_load(yaml.safe_load(out.stdout)["spec"]["valuesContent"])
    assert values["postgresql"] == {
        "kind": "cnpg",
        "cnpg": {"instances": 1, "podAntiAffinityType": "required"},
    }
    assert "resources" not in values["api"] and "resources" not in values["worker"]


def test_firstboot_emits_nothing_when_memtotal_is_unreadable() -> None:
    """A blank fragment leaves the chart's defaults, not `memory: Mi`."""
    src = FIRSTBOOT.read_text(encoding="utf-8")
    assert 'API_SIZING_YAML=""' in src
    assert 'if [ -n "$API_MEM_MIB" ]; then' in src


def test_the_fragments_are_actually_rendered() -> None:
    """Computed but never interpolated is the failure this is prone to."""
    src = FIRSTBOOT.read_text(encoding="utf-8")
    assert "${API_SIZING_YAML}" in src
    assert "${WORKER_SIZING_YAML}" in src
    assert "${POSTGRES_SIZING_YAML}" in src
    assert "${POSTGRES_PARAMETERS_YAML}" in src
    assert 'POSTGRES_SIZING_YAML=""' in src
    assert 'POSTGRES_PARAMETERS_YAML=""' in src


def test_python_still_returns_empty_for_unknown_size() -> None:
    """The contract firstboot's empty-fragment branch mirrors."""
    assert k8s_api.control_plane_resources(None) == {}
    assert k8s_api.control_plane_resources(0) == {}
