"""The interactive API docs, served with their own assets (#1157).

FastAPI's default ``/docs`` and ``/redoc`` pages load Swagger UI and ReDoc
from cdn.jsdelivr.net (ReDoc also Google Fonts), and Swagger starts from an
inline ``<script>``. The web tier's Content-Security-Policy (#400,
``frontend/default.conf.template``) allows scripts and stylesheets from the
page's own origin only, so through the web port, which the console's "API
docs" links use, both pages rendered blank. On an air-gapped install they
cannot reach the CDN on any port.

So the api serves both bundles itself from ``app/static/api-docs/``, which
holds byte-for-byte copies of the npm packages (see its README). Swagger UI's
initializer is a static file there, not an inline script. Neither page asks
for anything outside its own origin, whether it is loaded through the web
tier or from the api port.

ReDoc still needs two things at runtime that the console's policy refuses:
a ``blob:`` worker for its search index, and its "API docs by Redocly" logo
on cdn.redoc.ly. The web tier grants those on ``/api/redoc`` only.

Signed-in only (#2935). The OpenAPI document names every route and carries
``info.version``, which tells an anonymous scanner the exact release and so
which advisories apply. ``/api/openapi.json`` is therefore served here
behind ``CurrentUser`` rather than by FastAPI (which serves it to anyone).
The two HTML pages stay public shells: they carry nothing but the product
title, and they cannot authenticate on their own, because the console keeps
its access token in memory only (#484). So ``api-docs-auth.js`` asks
``/api/v1/auth/refresh`` for a token, which the browser's HttpOnly refresh
cookie answers for a signed-in user — the same silent refresh a second
console tab performs on load — and fetches the spec with it. Without a
session the page says so and links to the sign-in page. The release asset
``openapi.json`` (#903) is generated from ``app.openapi()`` directly and is
unaffected; it stays the contract for client generators.
"""

from __future__ import annotations

from html import escape
from pathlib import Path

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.deps import CurrentUser

#: URL prefix of the vendored assets. The web tier routes it to the api with
#: a ``^~`` location in both nginx configs. Without that, the static-asset
#: regex location answers every ``.js`` / ``.css`` path from the SPA's own disk.
STATIC_PATH = "/api/docs/static"
STATIC_DIR = Path(__file__).resolve().parent.parent / "static" / "api-docs"

#: Where the OpenAPI document is served, signed in only (#2935). The app is
#: created with ``openapi_url=None`` so FastAPI does not also serve it to
#: anyone at this path.
OPENAPI_URL = "/api/openapi.json"

#: The console's silent-refresh endpoint, which the pages use to get a token.
REFRESH_URL = "/api/v1/auth/refresh"

# FastAPI's get_swagger_ui_html() page, minus its inline initializer: the
# options now live in swagger-ui-init.js, which reads the spec URL from its
# own data attribute. The favicon is the console's (the web tier serves it);
# FastAPI's default is an image on fastapi.tiangolo.com.
_SWAGGER_UI_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link type="text/css" rel="stylesheet" href="{static}/swagger-ui/swagger-ui.css">
<link rel="icon" href="/favicon.svg">
<title>{title}</title>
</head>
<body>
<div id="swagger-ui"></div>
<script src="{static}/swagger-ui/swagger-ui-bundle.js"></script>
<script src="{static}/api-docs-auth.js"></script>
<script src="{static}/swagger-ui-init.js" data-openapi-url="{openapi_url}" data-refresh-url="{refresh_url}" data-login-url="{login_url}"></script>
</body>
</html>
"""

# FastAPI's get_redoc_html() page, minus its Google Fonts link and inline
# style, starting ReDoc from redoc-init.js instead of a ``spec-url``
# attribute: ReDoc fetches a ``spec-url`` itself, with no way to add the
# Bearer the document now needs (#2935).
_REDOC_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="/favicon.svg">
<title>{title}</title>
</head>
<body>
<div id="redoc-container"></div>
<script src="{static}/redoc/redoc.standalone.js"></script>
<script src="{static}/api-docs-auth.js"></script>
<script src="{static}/redoc-init.js" data-openapi-url="{openapi_url}" data-refresh-url="{refresh_url}" data-login-url="{login_url}"></script>
</body>
</html>
"""

router = APIRouter(include_in_schema=False)


def _prefix(request: Request) -> str:
    # FastAPI's own docs routes honour a proxy's root_path the same way.
    return str(request.scope.get("root_path", "")).rstrip("/")


def _page(request: Request, template: str, title: str) -> HTMLResponse:
    root = _prefix(request)
    return HTMLResponse(
        template.format(
            static=escape(root + STATIC_PATH),
            title=escape(f"{request.app.title} - {title}"),
            openapi_url=escape(root + OPENAPI_URL),
            refresh_url=escape(root + REFRESH_URL),
            login_url=escape(root + "/login"),
        )
    )


@router.get("/api/docs")
async def swagger_ui(request: Request) -> HTMLResponse:
    return _page(request, _SWAGGER_UI_HTML, "Swagger UI")


@router.get("/api/redoc")
async def redoc(request: Request) -> HTMLResponse:
    return _page(request, _REDOC_HTML, "ReDoc")


@router.get(OPENAPI_URL)
async def openapi_document(request: Request, _: CurrentUser) -> JSONResponse:
    """The OpenAPI document, for a signed-in caller or an API token (#2935).

    The same document FastAPI would serve (``app.openapi()``, including the
    generator fixes ``create_app`` wraps it with), just not to anyone.
    """
    return JSONResponse(request.app.openapi())


def install_api_docs(app: FastAPI) -> None:
    """Serve ``/api/docs``, ``/api/redoc`` and ``/api/openapi.json``.

    Create the app with ``docs_url=None, redoc_url=None, openapi_url=None``
    so FastAPI's CDN pages and its anonymous spec route are not registered
    as well. A mount cannot ride ``include_router``,
    so this function mounts the asset directory on the app itself.
    """
    app.include_router(router)
    app.mount(STATIC_PATH, StaticFiles(directory=STATIC_DIR), name="api-docs-static")
