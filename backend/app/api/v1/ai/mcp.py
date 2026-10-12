"""MCP (Model Context Protocol) HTTP endpoint (issue #90 Wave 2).

JSON-RPC 2.0 over HTTP, mirroring the MCP spec's "Streamable HTTP"
transport. Wave 2 implements the minimum viable surface — operators
can connect Claude Desktop / Cursor / any MCP-speaking client and
call SpatiumDDI's read-only tools.

Methods supported:
    initialize        — protocol handshake
    notifications/initialized  — client-pushed init complete
    tools/list        — list available tools
    tools/call        — invoke a tool with arguments
    ping              — health check

Methods deliberately NOT supported in Wave 2 (return method-not-found):
    resources/*, prompts/*, sampling/*, completion/*

Auth:
    The same auth surface as every other ``/api/v1/*`` route — session
    JWT for browser clients, API tokens for external MCP clients.
    External clients use a token with the ``read`` scope (Wave 2 tools
    are all read-only). The scope helper in ``app/services/api_token_scopes``
    has been extended to allow POST to ``/api/v1/mcp/*`` under ``read``
    so this works without a dedicated MCP scope. Phase 3 adds an
    ``mcp:write`` scope when write tools land.

    Authentication is not authorization (GHSA-4wrc-78rq-vgcg): the
    advertised and callable set is the same effective set the in-app chat
    uses (Tool Catalog × ``default_enabled`` × enabled feature modules),
    narrowed to the tools the caller's own permissions allow, and
    ``ToolRegistry.call`` re-checks each tool's declared permission.
"""

from __future__ import annotations

import time
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel

from app.api.deps import DB, CurrentUser
from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services import feature_modules as fm_svc
from app.services.ai.tools import (
    REGISTRY,
    Tool,
    ToolArgumentError,
    ToolDisabled,
    ToolNotFound,
    ToolPermissionDenied,
    effective_tool_names,
)

logger = structlog.get_logger(__name__)
router = APIRouter()


# Server identity returned in ``initialize``. Bump ``version`` when the
# tool surface changes shape in a non-additive way.
_SERVER_INFO = {
    "name": "spatiumddi",
    "version": "1.0.0",
}

# Protocol version we speak. Matches the MCP spec rev we built against;
# clients negotiate down if they speak an older version.
_PROTOCOL_VERSION = "2025-06-18"


class JSONRPCRequest(BaseModel):
    """One JSON-RPC 2.0 request frame. ``id`` is None for notifications."""

    model_config = {"extra": "allow"}

    jsonrpc: str = "2.0"
    id: int | str | None = None
    method: str
    params: dict[str, Any] | None = None


def _ok(req_id: int | str | None, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _err(req_id: int | str | None, code: int, message: str, data: Any = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        payload["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": payload}


async def _mcp_tool_names(db: Any) -> set[str]:
    """The tools the MCP transport may dispatch — genuinely read-only only.

    SECURITY (GHSA-4wrc-78rq-vgcg): the same effective set the in-app chat
    resolves — the operator's Tool Catalog over each tool's
    ``default_enabled``, minus tools whose feature module is off — so a
    tool the operator disabled (or never enabled) is not reachable here
    either. Previously MCP exposed every non-write tool.

    SECURITY (#400, M1): ``effective_tool_names`` keys off the ``writes``
    flag, but every ``propose_*`` tool is registered ``writes=False`` (the
    propose call itself only previews + persists a proposal row; the
    mutation runs later through the C2-gated /apply endpoint). We therefore
    additionally drop ``propose_*`` tools so the MCP surface never
    previews/stages a write either. ``tools/list`` (advertised set) and
    ``tools/call`` (dispatch gate) both consume this single source of truth
    so they can never drift apart.
    """
    platform_settings = await db.get(PlatformSettings, 1)
    platform_enabled = platform_settings.ai_tools_enabled if platform_settings is not None else None
    effective = effective_tool_names(
        platform_enabled=platform_enabled,
        provider_enabled=None,
        enabled_modules=await fm_svc.get_enabled_modules(db),
    )
    return {n for n in effective if not n.startswith("propose_")}


async def _mcp_tools(db: Any, user: User) -> list[Tool]:
    """The tools ``tools/list`` advertises to ``user``: the effective set,
    narrowed to the ones the caller's permissions allow."""
    names = await _mcp_tool_names(db)
    return REGISTRY.callable_by(user, [t for t in REGISTRY.read_only() if t.name in names])


# Standard JSON-RPC error codes
_PARSE_ERROR = -32700
_INVALID_REQUEST = -32600
_METHOD_NOT_FOUND = -32601
_INVALID_PARAMS = -32602
_INTERNAL_ERROR = -32603


@router.get("")
async def mcp_get(current_user: CurrentUser, db: DB) -> dict[str, Any]:
    """A bare GET on ``/mcp`` returns server info — useful for browser
    sanity-checks and for Streamable-HTTP clients that probe for
    server identity without going through ``initialize``. Auth is
    required to keep server info from leaking to anonymous probes.
    """
    return {
        "server": _SERVER_INFO,
        "protocol_version": _PROTOCOL_VERSION,
        "available_tools": len(await _mcp_tools(db, current_user)),
        "transport": "streamable_http",
    }


@router.post("")
async def mcp_post(
    request: Request, current_user: CurrentUser, db: DB
) -> dict[str, Any] | list[dict[str, Any]]:
    """Handle one JSON-RPC request (or batch). Returns a single
    response object for single requests, a list for batches. Notifications
    (``id`` omitted) get no response — we still emit an empty object so
    HTTP clients always have a body to parse.
    """
    try:
        raw = await request.json()
    except Exception:
        # Don't echo the parser exception back — JSONDecodeError
        # messages are usually safe but CodeQL py/stack-trace-exposure
        # tracks any ``{exc}`` to the response, and the constant
        # message tells the client everything they need to know
        # (alerts #23 / #24).
        logger.exception("mcp_bad_json_body")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body is not valid JSON.",
        ) from None

    if isinstance(raw, list):
        return [await _dispatch_one(item, db, current_user) for item in raw]
    return await _dispatch_one(raw, db, current_user)


async def _dispatch_one(raw: Any, db: Any, user: Any) -> dict[str, Any]:
    try:
        req = JSONRPCRequest.model_validate(raw)
    except Exception:
        # Pydantic validation messages contain field paths that are
        # safe to surface, but CodeQL py/stack-trace-exposure flags
        # any ``{exc}`` flowing into a response. Send a constant
        # message and rely on the request id being absent to signal
        # which frame failed (the spec allows id=null on parse errs).
        logger.exception("mcp_invalid_jsonrpc_frame")
        return _err(None, _INVALID_REQUEST, "Invalid JSON-RPC frame.")

    method = req.method
    params = req.params or {}
    started = time.monotonic()

    try:
        if method == "initialize":
            client_info = params.get("clientInfo", {})
            logger.info(
                "mcp_initialize",
                client_name=client_info.get("name"),
                client_version=client_info.get("version"),
                protocol_version=params.get("protocolVersion"),
            )
            return _ok(
                req.id,
                {
                    "protocolVersion": _PROTOCOL_VERSION,
                    "serverInfo": _SERVER_INFO,
                    "capabilities": {
                        # Wave 2 only ships ``tools``. ``resources`` /
                        # ``prompts`` / ``sampling`` advertise as absent
                        # so capable clients don't try to call them.
                        "tools": {},
                    },
                },
            )

        if method in ("notifications/initialized", "ping"):
            # Notifications don't get a response per JSON-RPC 2.0,
            # but we return an empty result to keep our HTTP shape
            # uniform — clients ignore the result for notifications.
            return _ok(req.id, {})

        if method == "tools/list":
            return _ok(
                req.id,
                {"tools": [t.to_mcp_tool() for t in await _mcp_tools(db, user)]},
            )

        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments") or {}
            if not isinstance(name, str):
                return _err(
                    req.id,
                    _INVALID_PARAMS,
                    "tools/call requires string `name`",
                )
            # SECURITY (#400, M1 + GHSA-4wrc-78rq-vgcg): tools/call must
            # refuse anything outside the advertised set. Passing
            # effective={MCP tool names} makes the registry raise
            # ToolDisabled for write / propose / catalog-disabled /
            # module-disabled tools, and the registry itself enforces each
            # tool's declared permission against the caller.
            try:
                result = await REGISTRY.call(
                    name, arguments, db=db, user=user, effective=await _mcp_tool_names(db)
                )
            except ToolNotFound as exc:
                return _err(
                    req.id,
                    _METHOD_NOT_FOUND,
                    f"tool not found: {exc.name!r}",
                )
            except ToolDisabled as exc:
                # A registered tool the MCP surface doesn't expose (write /
                # propose). Report it as method-not-found so we don't leak
                # the existence of tools outside the advertised set.
                return _err(
                    req.id,
                    _METHOD_NOT_FOUND,
                    f"tool not found: {exc.name!r}",
                )
            except ToolPermissionDenied as exc:
                # An MCP tool-execution failure, reported in-band the way the
                # spec asks (``isError``) — the REST analogue is a 403.
                logger.info("mcp_tool_denied", tool=name, user_id=str(user.id))
                return _ok(
                    req.id,
                    {"content": [{"type": "text", "text": str(exc)}], "isError": True},
                )
            except ToolArgumentError as exc:
                return _err(
                    req.id,
                    _INVALID_PARAMS,
                    f"invalid arguments for tool {exc.name!r}: {exc.detail}",
                )
            elapsed_ms = int((time.monotonic() - started) * 1000)
            logger.info(
                "mcp_tool_call",
                tool=name,
                user_id=str(user.id),
                latency_ms=elapsed_ms,
            )
            # MCP wraps tool results in a ``content`` array of typed
            # blocks. JSON results go in a single text block — most
            # clients then re-parse the JSON before showing it.
            import json

            return _ok(
                req.id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, default=str),
                        }
                    ],
                    "isError": False,
                },
            )

        # Spec-mandated method-not-found for anything else.
        return _err(
            req.id,
            _METHOD_NOT_FOUND,
            f"method not implemented: {method}",
        )
    except Exception:  # noqa: BLE001
        # Full exception (incl. stack) is logged server-side. The
        # JSON-RPC client gets a constant message — exception strings
        # can carry SQL fragments, file paths, etc. that CodeQL
        # py/stack-trace-exposure correctly flags.
        logger.exception("mcp_internal_error", method=method)
        return _err(req.id, _INTERNAL_ERROR, "Internal error.")
