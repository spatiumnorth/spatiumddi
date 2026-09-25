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
"""

from __future__ import annotations

from html import escape
from pathlib import Path

from fastapi import APIRouter, FastAPI, Request
from fastapi.openapi.docs import get_redoc_html
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

#: URL prefix of the vendored assets. The web tier routes it to the api with
#: a ``^~`` location in both nginx configs. Without that, the static-asset
#: regex location answers every ``.js`` / ``.css`` path from the SPA's own disk.
STATIC_PATH = "/api/docs/static"
STATIC_DIR = Path(__file__).resolve().parent.parent / "static" / "api-docs"

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
<script src="{static}/swagger-ui-init.js" data-openapi-url="{openapi_url}"></script>
</body>
</html>
"""

router = APIRouter(include_in_schema=False)


def _prefix(request: Request) -> str:
    # FastAPI's own docs routes honour a proxy's root_path the same way.
    return str(request.scope.get("root_path", "")).rstrip("/")


@router.get("/api/docs")
async def swagger_ui(request: Request) -> HTMLResponse:
    root = _prefix(request)
    return HTMLResponse(
        _SWAGGER_UI_HTML.format(
            static=escape(root + STATIC_PATH),
            title=escape(f"{request.app.title} - Swagger UI"),
            openapi_url=escape(root + request.app.openapi_url),
        )
    )


@router.get("/api/redoc")
async def redoc(request: Request) -> HTMLResponse:
    root = _prefix(request)
    return get_redoc_html(
        openapi_url=root + request.app.openapi_url,
        title=f"{request.app.title} - ReDoc",
        redoc_js_url=f"{root}{STATIC_PATH}/redoc/redoc.standalone.js",
        redoc_favicon_url="/favicon.svg",
        with_google_fonts=False,
    )


def install_api_docs(app: FastAPI) -> None:
    """Serve ``/api/docs`` and ``/api/redoc`` with the vendored assets.

    Create the app with ``docs_url=None, redoc_url=None`` so FastAPI's CDN
    pages are not registered as well. A mount cannot ride ``include_router``,
    so this function mounts the asset directory on the app itself.
    """
    app.include_router(router)
    app.mount(STATIC_PATH, StaticFiles(directory=STATIC_DIR), name="api-docs-static")
