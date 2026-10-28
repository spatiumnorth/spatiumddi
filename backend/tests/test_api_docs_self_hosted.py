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
import uuid
from html.parser import HTMLParser
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.docs import DOCS_SPEC_URL, OPENAPI_URL, STATIC_DIR, STATIC_PATH
from app.core.security import hash_password
from app.main import app
from app.models.auth import User

from ._signed_in import signed_in_headers

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
@pytest.mark.parametrize(
    ("path", "init_js"), [("/api/docs", "swagger-ui-init.js"), ("/api/redoc", "redoc-init.js")]
)
async def test_docs_page_is_pointed_at_the_spec(
    client: AsyncClient, db_session: AsyncSession, path: str, init_js: str
) -> None:
    """The initializer takes the spec URL from its script tag; it must be
    the docs pages' spec route, and that document must be served — to a
    signed-in caller (#2935), which here means the refresh cookie a login
    sets, since these pages never hold a Bearer. The helper that fetches it
    loads before the initializer."""
    _, page = await _page(client, path)
    srcs = [s["src"] for s in page.scripts]
    init = [s for s in page.scripts if s["src"].endswith("/" + init_js)]
    assert len(init) == 1, page.scripts
    auth = [i for i, src in enumerate(srcs) if src.endswith("/api-docs-auth.js")]
    assert auth and auth[0] < srcs.index(init[0]["src"]), srcs
    assert init[0].get("data-openapi-url") == DOCS_SPEC_URL == "/api/v1/auth/openapi.json"
    assert init[0].get("data-login-url") == "/login"
    # Under the refresh cookie's path, or the browser would not send it.
    assert DOCS_SPEC_URL.startswith("/api/v1/auth/")
    user = User(
        username=f"docs-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="Docs reader",
        hashed_password=hash_password("Sup3r-secret!"),
        auth_source="local",
        is_active=True,
        is_superadmin=False,
    )
    db_session.add(user)
    await db_session.commit()
    login = await client.post(
        "/api/v1/auth/login", json={"username": user.username, "password": "Sup3r-secret!"}
    )
    assert login.status_code == 200, login.text
    spec = await client.get(init[0]["data-openapi-url"])
    assert spec.status_code == 200
    assert spec.json()["openapi"].startswith("3.")
    # The Bearer route serves the same document to an API client.
    bearer = await client.get(OPENAPI_URL, headers=await signed_in_headers(db_session))
    assert bearer.status_code == 200
    assert bearer.json() == spec.json()


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
