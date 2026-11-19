"""Query-log severity / print-* reach the agent's named.conf (#2265).

``query_log_severity`` and ``query_log_print_*`` were editable in the
Options UI and shipped, but the agent rendered a hard-coded channel, so
choosing them did nothing. Assertions are on the RENDERED logging block.
Channel and file stay fixed: the QueryLogShipper tails the file channel.
"""

from __future__ import annotations

from spatium_dns_agent.drivers.bind9 import _render_logging_block

_DEFAULT_CHANNEL = """\
logging {
    channel queries_channel {
        file "/var/log/named/queries.log" versions 5 size 50m;
        severity info;
        print-category yes;
        print-severity yes;
        print-time yes;
    };
    category queries { queries_channel; };
    category query-errors { queries_channel; };
"""


def _block(**opts: object) -> str:
    return _render_logging_block({"query_log_enabled": True, **opts})


def test_defaults_and_absent_keys_render_the_historical_channel() -> None:
    # Byte-identical for an existing group, so its etag does not shift.
    assert _block().startswith(_DEFAULT_CHANNEL)
    assert _block(
        query_log_channel="file",
        query_log_file="/var/log/named/queries.log",
        query_log_severity="info",
        query_log_print_category=True,
        query_log_print_severity=True,
        query_log_print_time=True,
    ).startswith(_DEFAULT_CHANNEL)


def test_severity_and_print_flags_are_rendered() -> None:
    out = _block(
        query_log_severity="debug 3",
        query_log_print_category=False,
        query_log_print_severity=False,
    )
    assert "        severity debug 3;\n" in out
    assert "        print-category no;\n" in out
    assert "        print-severity no;\n" in out
    assert "print-time yes;" in out


def test_channel_file_and_quiet_severity_cannot_starve_the_shipper() -> None:
    out = _block(
        query_log_channel="syslog",
        query_log_file="/srv/elsewhere.log",
        query_log_severity="warning",
        query_log_print_time=False,
    )
    assert 'file "/var/log/named/queries.log" versions 5 size 50m;' in out
    assert "syslog" not in out and "elsewhere" not in out
    assert "severity info;" in out
    assert "print-time yes;" in out
