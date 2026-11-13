"""Windows Path B pull keeps the aging-timestamp verdict (#2251)."""

from app.drivers.dns.windows import _parse_records, _ps_list_records


def test_script_asks_for_the_timestamp() -> None:
    assert "$r.Timestamp" in _ps_list_records("corp.test.")


def test_parse_keeps_dynamic_verdict() -> None:
    raw = (
        '[{"HostName":"pc1","Type":"A","TTL":1200,"Dynamic":true,"Value":"10.0.0.5"},'
        '{"HostName":"web","Type":"A","TTL":3600,"Dynamic":false,"Value":"10.0.0.6"},'
        '{"HostName":"old","Type":"A","TTL":3600,"Value":"10.0.0.7"}]'
    )
    got = {r.name: r.dynamic for r in _parse_records(raw)}
    assert got == {"pc1": True, "web": False, "old": None}
