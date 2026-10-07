"""PeeringDB URL fields are scheme-checked at ingest (#1361).

``website`` keeps only http(s); ``looking_glass`` also keeps telnet and
ssh, the schemes PeeringDB itself accepts for it. Anything else is stored
as None. ``_fetch`` is stubbed, so no network.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services.bgp import peeringdb


def _stub_row(monkeypatch: pytest.MonkeyPatch, **fields: Any) -> None:
    async def fake_fetch(path: str, params: dict[str, Any], cache_key: str) -> Any:
        return {"data": [{"name": "Example", **fields}]}

    monkeypatch.setattr(peeringdb, "_fetch", fake_fetch)


@pytest.mark.parametrize(
    "value",
    [
        "https://www.example.net/",
        "http://www.example.net",
        "HTTPS://WWW.EXAMPLE.NET/",
    ],
)
async def test_website_keeps_http_and_https(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    _stub_row(monkeypatch, website=value)
    out = await peeringdb.fetch_asn_network(64500)
    assert out["website"] == value


@pytest.mark.parametrize(
    "value",
    [
        "javascript:alert(1)",
        "JAVASCRIPT:alert(1)",
        " javascript:alert(1)",
        "data:text/html,<b>x</b>",
        "vbscript:msgbox(1)",
        "telnet://lg.example.net",
        "ssh://lg.example.net",
        "www.example.net",
        "https://",
        "https://@",
        "https://:443",
        "ht\ttps://www.example.net/",
        "https://www.exa\nmple.net/",
        "\x01https://www.example.net/",
        "",
        "   ",
        None,
        42,
    ],
)
async def test_website_drops_other_values(monkeypatch: pytest.MonkeyPatch, value: Any) -> None:
    _stub_row(monkeypatch, website=value)
    out = await peeringdb.fetch_asn_network(64500)
    assert out["website"] is None


@pytest.mark.parametrize(
    "value",
    [
        "https://lg.example.net/",
        "http://lg.example.net",
        "telnet://route-views.routeviews.org",
        "ssh://lg.example.net",
        "TELNET://lg.example.net",
    ],
)
async def test_looking_glass_keeps_allowed_schemes(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    _stub_row(monkeypatch, looking_glass=value)
    out = await peeringdb.fetch_asn_network(64500)
    assert out["looking_glass"] == value


@pytest.mark.parametrize(
    "value",
    [
        "javascript:alert(1)",
        "JavaScript:alert(1)",
        "data:text/html,<b>x</b>",
        "vbscript:msgbox(1)",
        "ftp://lg.example.net",
        "ssh://user@",
        "telnet://:23",
        "lg.example.net",
        "",
        None,
    ],
)
async def test_looking_glass_drops_other_values(
    monkeypatch: pytest.MonkeyPatch, value: Any
) -> None:
    _stub_row(monkeypatch, looking_glass=value)
    out = await peeringdb.fetch_asn_network(64500)
    assert out["looking_glass"] is None


async def test_surrounding_whitespace_is_trimmed(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_row(monkeypatch, website="  https://www.example.net/ \n")
    out = await peeringdb.fetch_asn_network(64500)
    assert out["website"] == "https://www.example.net/"
