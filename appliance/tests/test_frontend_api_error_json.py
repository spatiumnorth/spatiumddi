"""A JSON route answers JSON when the api is unreachable (#1083).

Both nginx configs map 502/504 to ``@starting``, the "SpatiumDDI is
initialising" HTML page. That is right for the SPA shell and wrong for every
``/api/`` route: a client polling ``GET /api/v1/appliance/cluster/health``
while the api Service has no ready endpoint -- a CNPG failover empties it,
because ``/health/ready`` needs the database -- got an HTML body on a JSON
route, and a POST that tripped the 60 s ``proxy_read_timeout`` got nginx's
``405 Not Allowed`` because ``error_page`` redirected it to a static file
(#1080). The ``/api/`` locations now send their 502/504 to
``@api_unavailable``, which ``return``s a JSON body with the upstream status
preserved and a ``Retry-After``.

There are TWO hand-maintained copies of this config (the image's template
and the appliance's TLS ConfigMap); these read both.

    python3 -m pytest appliance/tests/test_frontend_api_error_json.py -v
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
IMAGE_TEMPLATE = REPO / "frontend" / "default.conf.template"
APPLIANCE_TEMPLATE = REPO / "charts" / "spatiumddi" / "templates" / "frontend-tls-config.yaml"

CONFIGS = pytest.mark.parametrize(
    "path", [IMAGE_TEMPLATE, APPLIANCE_TEMPLATE], ids=["image-template", "appliance-tls-configmap"]
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _locations(text: str) -> dict[str, str]:
    """``location <spec> { ... }`` blocks, brace-matched (an ``if`` nests)."""
    out: dict[str, str] = {}
    for m in re.finditer(r"^\s*location\s+(\S+(?:\s+\S+)?)\s*\{", text, re.M):
        spec = m.group(1).strip()
        depth, i = 1, m.end()
        while depth and i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        out[spec] = text[m.end() : i - 1]
    return out


def _api_locations(locs: dict[str, str]) -> dict[str, str]:
    """Prefix locations under ``/api/`` and regex locations anchored there (the
    storage action's exact-path block, #1080)."""
    return {
        spec: body
        for spec, body in locs.items()
        if spec.startswith("/api/") or re.match(r"~\*?\s*\^/api/", spec)
    }


@CONFIGS
def test_every_api_location_sends_502_504_to_the_json_page(path: Path) -> None:
    api = _api_locations(_locations(_text(path)))
    assert api, f"{path.name}: no /api/ locations found"
    for spec, body in api.items():
        assert re.search(r"error_page\s+502\s+504\s+@api_unavailable;", body), (
            f"{path.name}: location {spec} still inherits the server-level "
            "error_page -> @starting, so a JSON client gets the initialising HTML"
        )


@CONFIGS
def test_json_error_page_returns_json_with_the_upstream_status(path: Path) -> None:
    locs = _locations(_text(path))
    assert "@api_unavailable" in locs, f"{path.name}: no location @api_unavailable"
    body = locs["@api_unavailable"]
    assert "default_type application/json;" in body
    assert "try_files" not in body, "a static file would 405 every non-GET (#1080)"
    returns = re.findall(r"return\s+(50[24])\s+'(\{.*?\})';", body)
    assert sorted(code for code, _ in returns) == ["502", "504"], (
        f"{path.name}: expected one JSON return per upstream status, got {returns}"
    )
    for _code, payload in returns:
        parsed = json.loads(payload)
        assert isinstance(parsed.get("detail"), str) and parsed["detail"], payload
    assert re.search(r"add_header\s+Retry-After\s+\d+\s+always;", body), "clients need a retry hint"
    assert "X-Upstream-Status $upstream_status" in body


@CONFIGS
def test_the_spa_shell_keeps_the_initialising_page(path: Path) -> None:
    """The HTML gate is still the right answer for a browser at ``/``."""
    text = _text(path)
    assert re.search(r"^\s*error_page\s+502\s+504\s+@starting;", text, re.M), (
        f"{path.name}: the server-level error_page -> @starting must stay for the SPA"
    )
    locs = _locations(text)
    assert "@starting" in locs and "try_files /_starting.html" in locs["@starting"]


def test_both_copies_carry_the_same_json_bodies() -> None:
    bodies = []
    for path in (IMAGE_TEMPLATE, APPLIANCE_TEMPLATE):
        body = _locations(_text(path))["@api_unavailable"]
        bodies.append(sorted(re.findall(r"return\s+50[24]\s+'(\{.*?\})';", body)))
    assert bodies[0] == bodies[1], "the two hand-maintained copies drifted"
