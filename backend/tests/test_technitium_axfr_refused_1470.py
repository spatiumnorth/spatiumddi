"""A TCP connection refusal is not a refused zone transfer (#1470).

``TechnitiumDriver.pull_zone_records`` matched ``"REFUSED"`` anywhere in the
error text, so a server that could not even be connected to — on an appliance
behind the DNS VIP nothing listens on the node address — was reported as
having "refused the zone transfer despite signing it with the group key",
sending the operator to the TSIG configuration of every Technitium server.
"""

from __future__ import annotations

import socket
from types import SimpleNamespace

import dns.query
import dns.rcode
import dns.xfr
import pytest

from app.drivers.dns.base import TsigKey
from app.drivers.dns.technitium import TechnitiumDriver

_KEY = TsigKey(name="spatium-iwg", secret="c2VjcmV0c2VjcmV0c2VjcmV0", algorithm="hmac-sha256")


def _closed_port() -> int:
    """A loopback port with nothing listening on it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.mark.asyncio
async def test_connection_refused_is_reported_as_unreachable() -> None:
    server = SimpleNamespace(host="127.0.0.1", port=_closed_port(), id="s1")

    with pytest.raises(RuntimeError) as err:
        await TechnitiumDriver().pull_zone_records(server, "example.test.", tsig=_KEY)

    message = str(err.value)
    assert "could not be reached" in message
    assert "despite signing" not in message
    assert "refused the zone transfer" not in message


@pytest.mark.asyncio
async def test_a_dns_refused_still_names_the_tsig_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _refused(*_a: object, **_kw: object) -> object:
        raise dns.xfr.TransferError(dns.rcode.REFUSED)

    monkeypatch.setattr(dns.query, "xfr", _refused)
    server = SimpleNamespace(host="127.0.0.1", port=53, id="s1")

    with pytest.raises(RuntimeError, match="refused the zone transfer .* despite signing"):
        await TechnitiumDriver().pull_zone_records(server, "example.test.", tsig=_KEY)
