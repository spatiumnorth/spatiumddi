"""The charts let DNS and Postgres come back at size (#2240, #2132).

* DNS: the agent renders and ``named-checkzone``s every zone before named
  listens. At 20,009 zones that took 16-20 minutes, and the tcp :53 liveness
  probe (30 s delay, 3 x 30 s) killed the container after ~2 minutes, in a
  loop. Each DNS role now carries a startupProbe with a 30-minute budget,
  rendered ahead of that liveness probe.
* Postgres: a former primary rejoining after a partition needs WAL back to
  where it diverged, for ``pg_rewind`` and for streaming. With CloudNativePG's
  512MB default retention it looped for ever (#2132), so the Cluster carries
  a larger ``wal_keep_size``.

HOW TO RUN: python3 -m pytest appliance/tests/test_chart_recover_at_size.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent.parent
APPLIANCE = REPO / "charts" / "spatiumddi-appliance"
UMBRELLA = REPO / "charts" / "spatiumddi"

# role values key -> template file; all three share the tcp :53 liveness probe.
DNS_ROLES = {
    "dnsBind9": "dns-bind9.yaml",
    "dnsPowerdns": "dns-powerdns.yaml",
    "dnsTechnitium": "dns-technitium.yaml",
}
# #2240 measured 16-20 minutes before named listened; 30 minutes is the budget.
MIN_STARTUP_SECONDS = 30 * 60
# CloudNativePG's own default, which #2132 outran.
CNPG_DEFAULT_WAL_KEEP_MB = 512


def _values(chart: Path) -> dict:
    return yaml.safe_load((chart / "values.yaml").read_text(encoding="utf-8"))


def _mb(q: str) -> float:
    m = re.fullmatch(r"(\d+)\s*(kB|MB|GB|TB)", q)
    assert m, f"unparsed Postgres size {q!r}"
    return int(m.group(1)) * {"kB": 1 / 1024, "MB": 1, "GB": 1024, "TB": 1024 * 1024}[m.group(2)]


@pytest.mark.parametrize("role", sorted(DNS_ROLES))
def test_dns_role_startup_probe_budget(role: str) -> None:
    probe = _values(APPLIANCE)[role]["startupProbe"]
    assert probe["enabled"] is True, f"{role}.startupProbe is off by default"
    budget = probe["periodSeconds"] * probe["failureThreshold"]
    assert budget >= MIN_STARTUP_SECONDS, (
        f"{role}.startupProbe allows {budget} s before a restart; a 20,009-zone "
        f"load took 16-20 min (#2240), the budget is {MIN_STARTUP_SECONDS} s"
    )
    assert probe["timeoutSeconds"] >= 1


@pytest.mark.parametrize("role", sorted(DNS_ROLES))
def test_dns_template_renders_its_own_startup_probe_before_liveness(role: str) -> None:
    text = (APPLIANCE / "templates" / DNS_ROLES[role]).read_text(encoding="utf-8")
    call = f'include "spatiumddi-appliance.dnsStartupProbe" .Values.{role}.startupProbe'
    assert call in text, f"{DNS_ROLES[role]} does not render {role}.startupProbe"
    assert text.index(call) < text.index("livenessProbe:")
    for other in set(DNS_ROLES) - {role}:
        assert f".Values.{other}.startupProbe" not in text, (
            f"{DNS_ROLES[role]} reads {other}'s startupProbe"
        )


def test_dns_startup_probe_helper_probes_port_53() -> None:
    helpers = (APPLIANCE / "templates" / "_helpers.tpl").read_text(encoding="utf-8")
    body = helpers.split('define "spatiumddi-appliance.dnsStartupProbe"', 1)[1]
    body = body.split("{{- define", 1)[0]
    assert ".enabled" in body, "the helper ignores startupProbe.enabled"
    for line in (
        "startupProbe:",
        "tcpSocket:",
        "port: 53",
        "periodSeconds:",
        "failureThreshold:",
        "timeoutSeconds:",
    ):
        assert line in body, f"dnsStartupProbe helper is missing {line!r}"


def test_cnpg_keeps_wal_for_a_former_primary() -> None:
    params = _values(UMBRELLA)["postgresql"]["cnpg"]["parameters"]
    assert "wal_keep_size" in params, "postgresql.cnpg.parameters lost wal_keep_size (#2132)"
    assert _mb(params["wal_keep_size"]) > CNPG_DEFAULT_WAL_KEEP_MB
    # The Cluster renders the whole parameters map, so the default reaches the
    # CR beside whatever the supervisor's HelmChartConfig sets (shared_buffers).
    cluster = (UMBRELLA / "templates" / "cnpg-cluster.yaml").read_text(encoding="utf-8")
    assert "toYaml .Values.postgresql.cnpg.parameters" in cluster


def test_size_parser_negative_control() -> None:
    # The 512MB default must not pass the check above; a parser that read every
    # size as large would pass it vacuously.
    assert not _mb("512MB") > CNPG_DEFAULT_WAL_KEEP_MB
    assert _mb("2GB") == 2048
