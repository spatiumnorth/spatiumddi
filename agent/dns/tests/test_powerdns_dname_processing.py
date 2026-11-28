"""#4571 — pdns serves DNAME substitution only with ``dname-processing=yes``."""

from pathlib import Path

from spatium_dns_agent.drivers.powerdns import PowerDNSDriver


def test_render_conf_enables_dname_processing(tmp_path: Path) -> None:
    conf = PowerDNSDriver(state_dir=tmp_path)._render_conf(api_key="k", log_level=4)
    assert "dname-processing=yes" in conf.splitlines()
