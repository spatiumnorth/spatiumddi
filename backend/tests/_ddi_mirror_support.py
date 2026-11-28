"""Recorded-WAPI fixtures and a mock transport for the commercial-DDI mirror
tests (#4729). No live Infoblox: responses are JSON captured in the shape NIOS
returns, served by an ``httpx.MockTransport`` keyed on the WAPI object path."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

_DIR = Path(__file__).parent / "fixtures" / "ddi_mirror" / "infoblox"

_OBJECT_FILES = {
    "grid": "grid",
    "view": "view",
    "networkcontainer": "networkcontainer",
    "range": "range",
    "fixedaddress": "fixedaddress",
    "zone_auth": "zone_auth",
    "record:host": "record_host",
    "record:a": "record_a",
    "record:ptr": "record_ptr",
}


def fixture(name: str) -> Any:
    return json.loads((_DIR / f"{name}.json").read_text())


class FakeWapi:
    """Serves the fixtures; records every request so tests can assert on them."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        # object name -> (status, body) overriding the fixture
        self.overrides: dict[str, tuple[int, Any]] = {}
        self.require_auth = ("admin", "secret")

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        auth = request.headers.get("authorization", "")
        import base64

        want = base64.b64encode(f"{self.require_auth[0]}:{self.require_auth[1]}".encode()).decode()
        if auth != f"Basic {want}":
            return httpx.Response(
                401, json={"Error": "AdmConProtoError", "text": "Authorization Required"}
            )
        prefix = "/wapi/"
        path = request.url.path
        assert path.startswith(prefix), path
        obj = path[len(prefix) :].split("/", 1)[1]
        if obj in self.overrides:
            status, body = self.overrides[obj]
            return httpx.Response(status, json=body)
        params = request.url.params
        if obj == "network":
            body = fixture(
                "network_page2" if params.get("_page_id") == "page-2" else "network_page1"
            )
            return httpx.Response(200, json=body)
        if obj not in _OBJECT_FILES:
            return httpx.Response(
                400, json={"Error": "AdmConProtoError", "text": f"Unknown object type {obj}"}
            )
        body = fixture(_OBJECT_FILES[obj])
        if obj == "grid":
            return httpx.Response(200, json=body["result"])
        return httpx.Response(200, json=body)

    def objects_requested(self) -> list[str]:
        return [r.url.path.split("/", 3)[3] for r in self.requests]
