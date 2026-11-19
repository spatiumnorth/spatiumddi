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
title, and they cannot present a Bearer, because the console keeps its access
token in memory only (#484). What a docs tab DOES share with the console is
the HttpOnly refresh cookie, path-scoped to ``/api/v1/auth``. So the pages
fetch the document from ``/api/v1/auth/openapi.json``, which accepts that
cookie as the credential and **reads it without rotating it**.

Not ``POST /auth/refresh``, deliberately. A refresh rotates: it revokes the
session the console's in-memory access token is bound to, so opening the docs
would make the console's next request 401 and refresh in turn (which then
revokes the token the docs tab was just given), and a console refresh racing
the docs tab's — both presenting the same cookie — loses and is bounced to
``/login``. A read that rotates nothing has neither effect. Swagger UI's "Try
it out" therefore carries no token until the operator uses Authorize, which is
how it behaved before this change. Without a live session the page says so
and links to the sign-in page. The release asset ``openapi.json`` (#903) is
generated from ``app.openapi()`` directly and is unaffected; it stays the
contract for client generators.
"""

from __future__ import annotations

from html import escape
from pathlib import Path

from fastapi import APIRouter, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.deps import DB, CurrentUser
from app.api.v1.auth.router import REFRESH_COOKIE, live_refresh_session
from app.models.auth import User

#: URL prefix of the vendored assets. The web tier routes it to the api with
#: a ``^~`` location in both nginx configs. Without that, the static-asset
#: regex location answers every ``.js`` / ``.css`` path from the SPA's own disk.
STATIC_PATH = "/api/docs/static"
STATIC_DIR = Path(__file__).resolve().parent.parent / "static" / "api-docs"

#: Where the OpenAPI document is served, signed in only (#2935). The app is
#: created with ``openapi_url=None`` so FastAPI does not also serve it to
#: anyone at this path.
OPENAPI_URL = "/api/openapi.json"

#: Where the docs pages fetch the document: under the refresh cookie's path
#: (``/api/v1/auth``), so the browser sends that cookie, which this route reads
#: without rotating (#2935).
DOCS_SPEC_URL = "/api/v1/auth/openapi.json"

#: Never cached: the document is per-session now, and a browser cache would
#: hand it to whoever uses the machine after sign-out.
_NO_STORE = {"Cache-Control": "no-store"}

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
<script src="{static}/swagger-ui-init.js" data-openapi-url="{openapi_url}" data-login-url="{login_url}"></script>
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
<script src="{static}/redoc-init.js" data-openapi-url="{openapi_url}" data-login-url="{login_url}"></script>
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
            openapi_url=escape(root + DOCS_SPEC_URL),
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
    return JSONResponse(request.app.openapi(), headers=_NO_STORE)


@router.get(DOCS_SPEC_URL)
async def openapi_document_for_docs_pages(request: Request, db: DB) -> JSONResponse:
    """The OpenAPI document for ``/api/docs`` and ``/api/redoc`` (#2935).

    Authenticated by the HttpOnly refresh cookie, which the browser sends
    because this path sits under the cookie's ``/api/v1/auth`` path, and read
    WITHOUT rotating it (see the module docstring for why that matters). The
    session must be live by the same rule ``/auth/refresh`` applies
    (``live_refresh_session``), and the account active and not under a
    must-change-password gate, which every other signed-in read enforces.
    Nothing is written: not a rotation, and not ``last_seen_at``, since
    reading the docs is not the console being used. The cookie is
    ``SameSite=Strict``, so another site cannot make the browser send it, and
    a GET that only returns a document the same-origin policy keeps from
    other origins is not a CSRF target.
    """
    raw = request.cookies.get(REFRESH_COOKIE)
    session = await live_refresh_session(db, raw) if raw else None
    user = await db.get(User, session.user_id) if session is not None else None
    if user is None or not user.is_active or user.password_change_required:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sign in to view the API documentation",
        )
    return JSONResponse(request.app.openapi(), headers=_NO_STORE)


def install_api_docs(app: FastAPI) -> None:
    """Serve ``/api/docs``, ``/api/redoc`` and the OpenAPI document routes.

    Create the app with ``docs_url=None, redoc_url=None, openapi_url=None``
    so FastAPI's CDN pages and its anonymous spec route are not registered
    as well. A mount cannot ride ``include_router``,
    so this function mounts the asset directory on the app itself.
    """
    app.include_router(router)
    app.mount(STATIC_PATH, StaticFiles(directory=STATIC_DIR), name="api-docs-static")
