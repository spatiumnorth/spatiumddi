"""/api/docs and /api/redoc load only what the api serves itself (#1157).

FastAPI's default pages load Swagger UI and ReDoc from cdn.jsdelivr.net
(ReDoc also Google Fonts), and Swagger starts from an inline ``<script>``.
Through the web tier, whose Content-Security-Policy allows scripts and
stylesheets from the page's own origin only (#400,
``frontend/default.conf.template``), both pages rendered blank. On an
air-gapped install they cannot reach the CDN at all.

These pin the property that makes the pages work under that policy: no
inline script, and nothing requested from another origin. Every asset they
reference must come from ``app/static/api-docs/`` with a script or stylesheet
MIME type, which the web tier's ``X-Content-Type-Options: nosniff`` requires.
The vendored bundles must also still be the published bytes their README
records.
"""

from __future__ import annotations

import hashlib
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
from httpx import AsyncClient

from app.api.docs import STATIC_DIR, STATIC_PATH
from app.main import app

PAGES = ("/api/docs", "/api/redoc")


class _Page(HTMLParser):
    """The scripts, inline scripts, stylesheets and icons a page asks for."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[dict[str, str]] = []
        self.inline_scripts: list[str] = []
        self.links: list[dict[str, str]] = []
        self._inline: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: v or "" for k, v in attrs}
        if tag == "script":
            if a.get("src"):
                self.scripts.append(a)
            else:
                self._inline = []
        elif tag == "link":
            self.links.append(a)

    def handle_data(self, data: str) -> None:
        if self._inline is not None:
            self._inline.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._inline is not None:
            if "".join(self._inline).strip():
                self.inline_scripts.append("".join(self._inline))
            self._inline = None


async def _page(client: AsyncClient, path: str) -> tuple[str, _Page]:
    r = await client.get(path)
    assert r.status_code == 200, (path, r.status_code, r.text[:200])
    assert r.headers["content-type"].startswith("text/html"), r.headers["content-type"]
    parsed = _Page()
    parsed.feed(r.text)
    return r.text, parsed


def _refs(page: _Page) -> list[str]:
    return [s["src"] for s in page.scripts] + [
        link["href"] for link in page.links if link.get("href")
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", PAGES)
async def test_docs_page_has_no_inline_script(client: AsyncClient, path: str) -> None:
    """``script-src 'self'`` refuses an inline script; Swagger's initializer
    is a file (swagger-ui-init.js) instead."""
    _, page = await _page(client, path)
    assert page.inline_scripts == [], f"{path} carries an inline script: {page.inline_scripts}"
    assert page.scripts, f"{path} loads no script at all"


@pytest.mark.asyncio
@pytest.mark.parametrize("path", PAGES)
async def test_docs_page_asks_nothing_of_another_origin(client: AsyncClient, path: str) -> None:
    """Every script, stylesheet and icon is a path on the page's own origin:
    the web tier's CSP allows nothing else, and an air-gapped install can
    reach nothing else. That includes Google Fonts and FastAPI's favicon."""
    body, page = await _page(client, path)
    for ref in _refs(page):
        assert ref.startswith("/") and not ref.startswith("//"), f"{path} asks for {ref!r}"
    assert not re.search(r"(?:src|href)=[\"']?(?:https?:)?//", body), f"{path}: {body}"


@pytest.mark.asyncio
@pytest.mark.parametrize("path", PAGES)
async def test_every_asset_a_docs_page_asks_for_is_served(client: AsyncClient, path: str) -> None:
    """The vendored bundles answer from the api itself, with the MIME type a
    browser needs to run a script or apply a stylesheet under ``nosniff``."""
    _, page = await _page(client, path)
    wanted = {
        ".js": ("text/javascript", "application/javascript"),
        ".css": ("text/css",),
    }
    served = 0
    for ref in _refs(page):
        if not ref.startswith(STATIC_PATH + "/"):
            continue  # the console's own favicon, which the web tier serves
        r = await client.get(ref)
        assert r.status_code == 200, (ref, r.status_code)
        kind = Path(ref).suffix
        assert r.headers["content-type"].split(";")[0] in wanted[kind], (ref, r.headers)
        served += 1
    assert served >= 1, f"{path} references none of the vendored assets"


@pytest.mark.asyncio
async def test_swagger_ui_is_pointed_at_the_spec(client: AsyncClient) -> None:
    """The initializer takes the spec URL from its script tag; it must be the
    app's own openapi_url, and that document must be served."""
    _, page = await _page(client, "/api/docs")
    init = [s for s in page.scripts if s["src"].endswith("/swagger-ui-init.js")]
    assert len(init) == 1, page.scripts
    assert init[0].get("data-openapi-url") == app.openapi_url == "/api/openapi.json"
    spec = await client.get(init[0]["data-openapi-url"])
    assert spec.status_code == 200
    assert spec.json()["openapi"].startswith("3.")


@pytest.mark.asyncio
async def test_fastapi_cdn_pages_are_not_registered_too(client: AsyncClient) -> None:
    """``docs_url`` / ``redoc_url`` stay off: FastAPI would otherwise also
    register its own CDN pages (and the OAuth2 redirect page, which carries
    an inline script and serves no flow here — the API authenticates with a
    bearer token)."""
    assert app.docs_url is None and app.redoc_url is None
    r = await client.get("/docs/oauth2-redirect")
    assert r.status_code == 404


def test_vendored_bundles_are_the_published_bytes() -> None:
    """``app/static/api-docs/`` holds npm's bytes, unmodified; its README
    records their SHA-256. A hand edit, or a bump that forgot to update the
    README, fails here."""
    readme = (STATIC_DIR / "README.md").read_text(encoding="utf-8")
    recorded = re.findall(r"^([0-9a-f]{64})  (\S+)$", readme, re.M)
    assert {name for _, name in recorded} == {
        "swagger-ui/swagger-ui-bundle.js",
        "swagger-ui/swagger-ui.css",
        "redoc/redoc.standalone.js",
    }
    for digest, name in recorded:
        assert hashlib.sha256((STATIC_DIR / name).read_bytes()).hexdigest() == digest, name
