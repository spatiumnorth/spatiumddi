"""Agent renders the query-log channel from a bundle shaped like the control plane's (#4594)."""

from __future__ import annotations

from pathlib import Path

from spatium_dns_agent.drivers.bind9 import Bind9Driver


def test_channel_settings_from_bundle_options(tmp_path: Path) -> None:
    Bind9Driver(state_dir=tmp_path).render(
        {
            "server": {"name": "s1", "driver": "bind9"},
            "options": {
                "query_log_enabled": True,
                "query_log_severity": "dynamic",
                "query_log_print_category": False,
                "query_log_print_severity": False,
            },
            "acls": [],
            "views": [],
            "zones": [],
            "blocklists": [],
            "tsig_keys": [],
            "pending_ops": [],
        }
    )
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    assert "severity dynamic;" in conf
    assert "print-category no;" in conf
    assert "print-severity no;" in conf
