"""BIND9 agent RRL + amplification rendering (issue #146).

Exercises the pure ``_render_rate_limit_block`` helper against the
``options`` dict shape ``app.services.dns.agent_config`` ships, asserting
the ``rate-limit { … }`` stanza + amplification directives appear only
when opted in (so existing groups render byte-identical named.conf).
"""

from __future__ import annotations

from spatium_dns_agent.drivers.bind9 import _render_rate_limit_block


def test_default_is_noop() -> None:
    assert _render_rate_limit_block({}) == ""
    assert _render_rate_limit_block({"rrl_enabled": False, "minimal_responses": False}) == ""


def test_rrl_full_block() -> None:
    out = _render_rate_limit_block(
        {
            "rrl_enabled": True,
            "rrl_responses_per_second": 20,
            "rrl_window": 10,
            "rrl_slip": 3,
            "rrl_qps_scale": 250,
            "rrl_exempt_clients": ["10.0.0.0/8", "  ", "192.168.0.0/16"],
            "rrl_log_only": True,
        }
    )
    assert "rate-limit {" in out
    assert "responses-per-second 20;" in out
    assert "window 10;" in out
    assert "slip 3;" in out
    assert "qps-scale 250;" in out
    # blank exempt entry dropped; valid ones joined
    assert "exempt-clients { 10.0.0.0/8; 192.168.0.0/16; };" in out
    assert "log-only yes;" in out


def test_rrl_optional_fields_omitted() -> None:
    out = _render_rate_limit_block(
        {
            "rrl_enabled": True,
            "rrl_responses_per_second": 15,
            "rrl_window": 15,
            "rrl_slip": 2,
        }
    )
    assert "rate-limit {" in out
    assert "qps-scale" not in out
    assert "exempt-clients" not in out
    assert "log-only" not in out


def test_amplification_without_rrl() -> None:
    out = _render_rate_limit_block(
        {
            "minimal_responses": True,
            "tcp_clients": 200,
            "clients_per_query": 12,
            "max_clients_per_query": 120,
        }
    )
    assert "minimal-responses yes;" in out
    assert "tcp-clients 200;" in out
    assert "clients-per-query 12;" in out
    assert "max-clients-per-query 120;" in out
    # no RRL stanza when rrl_enabled is absent/false
    assert "rate-limit {" not in out


def test_partial_amplification_omits_unset() -> None:
    out = _render_rate_limit_block({"tcp_clients": 150})
    assert "tcp-clients 150;" in out
    assert "minimal-responses" not in out
    assert "clients-per-query" not in out


# ── dnsdist front (#146 Phase 2) ──────────────────────────────────────


def test_dnsdist_disabled_is_empty() -> None:
    from spatium_dns_agent.drivers.powerdns import render_dnsdist_conf

    assert render_dnsdist_conf({}) == ""
    assert render_dnsdist_conf({"dnsdist_enabled": False, "dnsdist_max_qps_per_client": 50}) == ""


def test_dnsdist_rules_only_no_base() -> None:
    from spatium_dns_agent.drivers.powerdns import render_dnsdist_conf

    # Rules-only: the base (setLocal/newServer) is composed by the front
    # container's entrypoint, NOT rendered here.
    out = render_dnsdist_conf({"dnsdist_enabled": True})
    assert "setLocal" not in out
    assert "newServer" not in out
    # Enabled-but-no-rules → just the header, no actions yet.
    assert "MaxQPSIPRule" not in out
    assert "setQueryRate" not in out


def test_dnsdist_qps_cap_action() -> None:
    from spatium_dns_agent.drivers.powerdns import render_dnsdist_conf

    trunc = render_dnsdist_conf({"dnsdist_enabled": True, "dnsdist_max_qps_per_client": 50})
    assert "addAction(MaxQPSIPRule(50), TCAction())" in trunc
    drop = render_dnsdist_conf(
        {"dnsdist_enabled": True, "dnsdist_max_qps_per_client": 50, "dnsdist_action": "drop"}
    )
    assert "addAction(MaxQPSIPRule(50), DropAction())" in drop


def test_dnsdist_dynblock() -> None:
    from spatium_dns_agent.drivers.powerdns import render_dnsdist_conf

    out = render_dnsdist_conf(
        {"dnsdist_enabled": True, "dnsdist_dynblock_qps": 200, "dnsdist_dynblock_seconds": 120}
    )
    assert "dynBlockRulesGroup()" in out
    assert 'dbr:setQueryRate(200, 10, "exceeded query rate", 120)' in out
    assert "function maintenance() dbr:apply() end" in out


def test_rrl_extra_knobs_render_when_set() -> None:
    """#3577 — nxdomains / errors / prefix-length etc. land in rate-limit {}."""
    out = _render_rate_limit_block(
        {
            "rrl_enabled": True,
            "rrl_nxdomains_per_second": 5,
            "rrl_errors_per_second": 6,
            "rrl_referrals_per_second": 7,
            "rrl_nodata_per_second": 8,
            "rrl_all_per_second": 9,
            "rrl_ipv4_prefix_length": 24,
            "rrl_ipv6_prefix_length": 56,
            "rrl_max_table_size": 20000,
        }
    )
    for line in (
        "nxdomains-per-second 5;",
        "errors-per-second 6;",
        "referrals-per-second 7;",
        "nodata-per-second 8;",
        "all-per-second 9;",
        "ipv4-prefix-length 24;",
        "ipv6-prefix-length 56;",
        "max-table-size 20000;",
    ):
        assert line in out
    # inside the stanza, before its closing brace
    assert out.index("nxdomains-per-second") < out.rindex("};")


def test_rrl_extra_knobs_unset_render_nothing() -> None:
    out = _render_rate_limit_block({"rrl_enabled": True, "rrl_nxdomains_per_second": None})
    assert "per-second" in out  # responses-per-second only
    assert "nxdomains" not in out and "prefix-length" not in out
