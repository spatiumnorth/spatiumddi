"""#4822 / #4823 — Windows DNS (no WinRM) dials the server's DNS port and
bounds the TCP connect.
"""

from __future__ import annotations

import socket
from types import SimpleNamespace
from typing import Any

import pytest

from app.drivers.dns.base import RecordChange, RecordData
from app.drivers.dns.windows import WindowsDNSDriver


def _server(**kw: Any) -> SimpleNamespace:
    base = dict(id="s1", host="192.0.2.10", port=1053, api_port=None, credentials_encrypted=None)
    base.update(kw)
    return SimpleNamespace(**base)


@pytest.fixture
def xfr_seen(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    import dns.query
    import dns.zone

    seen: dict[str, Any] = {"calls": 0}

    class _Z:
        def items(self) -> list[Any]:
            return []

    def fake_xfr(where: str, origin: Any, **kw: Any) -> object:
        seen["calls"] += 1
        seen["port"] = kw.get("port")
        return object()

    monkeypatch.setattr(dns.query, "xfr", fake_xfr)
    monkeypatch.setattr(dns.zone, "from_xfr", lambda _g: _Z())
    return seen


@pytest.mark.asyncio
async def test_pull_uses_dns_port_not_api_port(
    xfr_seen: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    dialled: list[tuple[Any, ...]] = []

    def fake_conn(addr: Any, timeout: Any = None) -> Any:
        dialled.append((addr, timeout))
        return SimpleNamespace(close=lambda: None)

    monkeypatch.setattr(socket, "create_connection", fake_conn)
    await WindowsDNSDriver().pull_zone_records(_server(api_port=953), "example.com.")
    assert xfr_seen["port"] == 1053
    assert dialled[0][0] == ("192.0.2.10", 1053)


@pytest.mark.asyncio
async def test_unreachable_server_fails_fast_without_transfer(
    xfr_seen: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    seen_timeout: list[Any] = []

    def dead(addr: Any, timeout: Any = None) -> Any:
        seen_timeout.append(timeout)
        raise TimeoutError("timed out")

    monkeypatch.setattr(socket, "create_connection", dead)
    with pytest.raises(RuntimeError, match="failed"):
        await WindowsDNSDriver().pull_zone_records(_server(), "example.com.")
    assert seen_timeout and seen_timeout[0] is not None and seen_timeout[0] <= 10
    assert xfr_seen["calls"] == 0


@pytest.mark.asyncio
async def test_rfc2136_update_uses_dns_port(monkeypatch: pytest.MonkeyPatch) -> None:
    import dns.query

    seen: dict[str, Any] = {}

    def fake_tcp(msg: Any, where: str, **kw: Any) -> object:
        seen["port"] = kw.get("port")
        import dns.message

        # A server's NOERROR reply: the update path reads its rcode (#4939).
        return dns.message.make_response(msg)

    monkeypatch.setattr(dns.query, "tcp", fake_tcp)
    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="192.0.2.1", ttl=60),
        target_serial=1,
    )
    await WindowsDNSDriver().apply_record_change(_server(api_port=953), change)
    assert seen["port"] == 1053
