"""The Technitium admin password never reaches the agent's log
(GHSA-x4gw-9gqx-vr4m).

``createToken`` used to be a GET with the password in the query string, and
httpx logs every request line, full URL included, at INFO. The call is now a
POST with a form body, and every agent keeps the httpx loggers at WARNING.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import httpx
import pytest

from spatium_dns_agent.drivers import technitium
from spatium_dns_agent.drivers.technitium import TechnitiumDriver
from spatium_dns_agent.log import configure_logging


def test_create_token_sends_the_password_in_a_form_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    password = d.admin_bootstrap_password()
    seen: list[dict[str, Any]] = []

    def _post(url: str, **kw: Any) -> httpx.Response:
        seen.append({"url": url, **kw})
        return httpx.Response(
            200,
            json={"status": "ok", "token": "minted"},
            request=httpx.Request("POST", url),
        )

    def _get(*_a: Any, **_kw: Any) -> httpx.Response:
        raise AssertionError("createToken must not be a GET (the URL is logged)")

    monkeypatch.setattr(technitium.httpx, "post", _post)
    monkeypatch.setattr(technitium.httpx, "get", _get)

    assert d._create_api_token() == "minted"
    assert len(seen) == 1
    assert password not in seen[0]["url"]
    assert "params" not in seen[0]
    assert seen[0]["data"]["pass"] == password


def test_agent_logging_keeps_httpx_request_lines_out() -> None:
    configure_logging("INFO")
    for name in ("httpx", "httpcore"):
        # The level set on the logger itself, not the effective one: under
        # pytest the root already has handlers, so basicConfig leaves it at
        # WARNING and an effective-level check would pass without the fix.
        assert logging.getLogger(name).level >= logging.WARNING, name
