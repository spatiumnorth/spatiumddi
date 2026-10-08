"""Tool registry primitives (issue #90 — Operator Copilot Wave 2).

A tool is a Python async function the LLM may invoke. Each tool
declares its arguments via a Pydantic model — that gives us
auto-generated JSON Schema (which both the OpenAI Chat Completions
``tools`` parameter and the MCP ``tools/list`` response consume) for
free.

Tools are registered on import (see ``tools/__init__.py``) via the
``@register_tool`` decorator. The :class:`ToolRegistry` is the
canonical interface used by both the in-app chat orchestrator
(Wave 3, in-process) and the MCP HTTP endpoint (Wave 2, external
clients) — keeping a single source of truth for "what can the
operator copilot do?".

All Wave 2 tools are read-only. Write tools (Phase 3) will gate on
a ``writes: bool`` flag plus the existing ``requires_confirmation``
preview / commit pattern.

Every tool also carries a mandatory ``permission`` declaration
(GHSA-4wrc-78rq-vgcg), enforced centrally by :meth:`ToolRegistry.call`
for every caller — the in-app chat AND the MCP endpoint. Before it a
tool ran with no authorization, so any signed-in account (or a
resource-scoped API token) could read data its role does not grant.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User

# Each tool's executor: takes the user's DB session, the requesting
# user (for permission scoping if needed), and a parsed Pydantic args
# instance. ``args`` is typed ``Any`` rather than ``BaseModel`` so each
# tool can declare its concrete subclass in its function signature
# without tripping mypy's invariance — the registry validates against
# the declared model on dispatch, so the contract is preserved.
ToolExecutor = Callable[[AsyncSession, User, Any], Awaitable[Any]]

# ── Permission declarations ─────────────────────────────────────────
#
# A tool's ``permission`` is one of:
#
# * ``(action, resource_type)`` — the caller needs ``action`` on
#   ``resource_type`` (unscoped, via ``user_has_permission``, which also
#   applies an API token's coarse resource-grant check). ``resource_type``
#   may be a tuple, meaning "any of these" — mirroring the
#   ``require_any_resource_permission`` gates on the aggregate REST
#   routers. Pick the pair the equivalent REST route requires, so the
#   copilot never grants more than REST does. Tools that list rows
#   additionally narrow them per row (an API token bound to one zone /
#   subnet sees only that instance), the way the REST list routes do.
# * ``SUPERADMIN`` — superadmin-only, matching a ``SuperAdmin`` REST
#   surface.
# * ``AUTHENTICATED`` — any signed-in caller; for tools whose REST
#   equivalent requires nothing beyond sign-in (``GET /settings``,
#   ``/alerts``, ``/search`` …) or which return static metadata.
# * ``SELF`` — any signed-in caller; the tool only reads or acts on the
#   caller's own rows (saved views, own chat session, own requests).
SUPERADMIN = "superadmin"
AUTHENTICATED = "authenticated"
SELF = "self"
_NAMED_PERMISSIONS = frozenset({SUPERADMIN, AUTHENTICATED, SELF})

ToolPermission = str | tuple[str, str | tuple[str, ...]]


def validate_tool_permission(name: str, permission: object) -> None:
    """Raise ``ValueError`` unless ``permission`` is a well-formed
    declaration. Called on registration so a tool cannot ship without one."""
    if isinstance(permission, str):
        if permission in _NAMED_PERMISSIONS:
            return
    elif isinstance(permission, tuple) and len(permission) == 2:
        action, rtypes = permission
        types = rtypes if isinstance(rtypes, tuple) else (rtypes,)
        if (
            isinstance(action, str)
            and action
            and types
            and all(isinstance(t, str) and t and t != "*" for t in types)
        ):
            return
    raise ValueError(
        f"Tool {name!r} has no valid permission declaration ({permission!r}); "
        "declare (action, resource_type), SUPERADMIN, AUTHENTICATED or SELF."
    )


def tool_permission_allows(user: User, permission: ToolPermission) -> bool:
    """Whether ``user`` (with any API-token narrowing already stashed on
    it by the auth dependency) may call a tool declaring ``permission``."""
    # Imported here: app.core.permissions imports the auth deps, which
    # must not load on the tool-registry import path.
    from app.core.permissions import (  # noqa: PLC0415
        is_effective_superadmin,
        user_has_permission,
    )

    if permission == SUPERADMIN:
        return is_effective_superadmin(user)
    if permission in (AUTHENTICATED, SELF):
        return bool(getattr(user, "is_active", False))
    if isinstance(permission, str):
        return False  # unknown named permission — fail closed
    action, rtypes = permission
    types = rtypes if isinstance(rtypes, tuple) else (rtypes,)
    return any(user_has_permission(user, action, rt) for rt in types)


def describe_tool_permission(permission: ToolPermission) -> str:
    if isinstance(permission, str):
        return permission
    action, rtypes = permission
    types = rtypes if isinstance(rtypes, tuple) else (rtypes,)
    return f"{action!r} on " + (repr(types[0]) if len(types) == 1 else f"one of {list(types)}")


@dataclass(frozen=True)
class Tool:
    """A registered tool. Carries everything needed to:

    - Translate to OpenAI's ``tools`` parameter shape
    - Translate to MCP's ``tools/list`` response shape
    - Validate inbound arguments (via the Pydantic model)
    - Dispatch to the executor
    """

    name: str
    description: str
    args_model: type[BaseModel]
    executor: ToolExecutor
    # ``writes`` is False for every Wave 2 tool. Phase 3 introduces
    # write tools that flip this true, gated behind a per-conversation
    # toggle and the preview / commit pattern.
    writes: bool = False
    # Free-form category used by the admin "available tools" page to
    # group tools — "ipam", "dns", "dhcp", "network", "ops".
    category: str = "ops"
    # ``default_enabled`` controls whether the tool appears in the
    # effective set for a fresh install. Niche tools (TLS chain
    # check, public WHOIS lookups, propose-* writes) ship as False so
    # operators opt in via Settings → AI → Tool Catalog. The default
    # can always be overridden per-platform via
    # ``PlatformSettings.ai_tools_enabled`` and per-provider via
    # ``AIProvider.enabled_tools``.
    default_enabled: bool = True
    # Optional feature-module id (see
    # ``app.services.feature_modules.MODULES``). When set and the
    # operator has disabled that module, the tool is stripped from
    # the registry's effective set regardless of its
    # ``default_enabled`` / per-platform / per-provider state. None
    # means "always available" (the cross-cutting tools — IPAM/DNS/DHCP
    # core lookups, ops helpers).
    module: str | None = None
    # Mandatory authorization declaration — see ``ToolPermission`` above.
    # Defaults to None only so the dataclass field order works; the
    # registry refuses to register a tool without a valid one.
    permission: ToolPermission | None = None

    def parameters_schema(self) -> dict[str, Any]:
        """JSON Schema for the args. Both OpenAI and MCP consume this
        verbatim. Pydantic emits ``$defs`` for nested models — we
        leave them in place; the model handles them.
        """
        return self.args_model.model_json_schema()

    def to_openai_tool(self) -> dict[str, Any]:
        """OpenAI Chat Completions ``tools`` entry."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters_schema(),
            },
        }

    def to_mcp_tool(self) -> dict[str, Any]:
        """MCP ``tools/list`` entry. The protocol uses ``inputSchema``
        rather than ``parameters``.
        """
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.parameters_schema(),
        }


class ToolRegistry:
    """Process-wide tool registry. Tools register themselves on
    import via :func:`register_tool` (see ``tools/__init__.py``).
    """

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        validate_tool_permission(tool.name, tool.permission)
        if tool.name in self._tools:
            raise ValueError(f"Tool {tool.name!r} is already registered.")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def all(self) -> list[Tool]:
        return sorted(self._tools.values(), key=lambda t: t.name)

    def read_only(self) -> list[Tool]:
        """The subset safe to expose to read-only contexts (Wave 2)."""
        return [t for t in self.all() if not t.writes]

    def callable_by(self, user: User, tools: list[Tool]) -> list[Tool]:
        """The subset of ``tools`` ``user`` is authorized to call — what
        ``tools/list`` and the chat tool schema advertise."""
        return [
            t
            for t in tools
            if t.permission is not None and tool_permission_allows(user, t.permission)
        ]

    async def call(
        self,
        name: str,
        raw_args: dict[str, Any],
        *,
        db: AsyncSession,
        user: User,
        effective: set[str] | None = None,
    ) -> Any:
        """Validate ``raw_args`` against the tool's Pydantic model and
        dispatch. Raises :class:`ToolNotFound` /
        :class:`ToolArgumentError` / :class:`ToolDisabled` /
        :class:`ToolPermissionDenied` on the obvious failure modes.

        ``effective`` is the operator's resolved tool set
        (Tool Catalog × per-provider allowlist). When supplied, the
        registry refuses to dispatch tools outside the set so a
        hallucinating LLM can't call something the operator
        explicitly disabled. Pass None only where the caller has
        already resolved the effective set itself.

        The tool's ``permission`` is enforced here for EVERY caller,
        regardless of ``effective`` (GHSA-4wrc-78rq-vgcg).
        """
        tool = self.get(name)
        if tool is None:
            raise ToolNotFound(name)
        if effective is not None and name not in effective:
            raise ToolDisabled(name, scope="platform")
        if tool.permission is None or not tool_permission_allows(user, tool.permission):
            raise ToolPermissionDenied(name, tool.permission)
        try:
            args = tool.args_model.model_validate(raw_args or {})
        except Exception as exc:
            raise ToolArgumentError(name, str(exc)) from exc
        return await tool.executor(db, user, args)


# Module-level singleton. Tool modules call ``register_tool(...)`` on
# import to populate it.
REGISTRY = ToolRegistry()


class ToolNotFound(KeyError):
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


class ToolPermissionDenied(PermissionError):
    """The caller lacks the permission the tool declares."""

    def __init__(self, name: str, permission: ToolPermission | None) -> None:
        self.name = name
        self.permission = permission
        need = describe_tool_permission(permission) if permission is not None else "unknown"
        super().__init__(f"Permission denied for tool {name!r}: need {need}")


class ToolArgumentError(ValueError):
    def __init__(self, name: str, detail: str) -> None:
        super().__init__(detail)
        self.name = name
        self.detail = detail


def register_tool(
    *,
    name: str,
    description: str,
    args_model: type[BaseModel],
    writes: bool = False,
    category: str = "ops",
    default_enabled: bool = True,
    module: str | None = None,
    permission: ToolPermission,
) -> Callable[[ToolExecutor], ToolExecutor]:
    """Decorator. Use on each tool's executor function.

    ``permission`` is mandatory — see ``ToolPermission``.

    Example::

        class ListSpacesArgs(BaseModel):
            search: str | None = None

        @register_tool(
            name="list_ip_spaces",
            description="...",
            args_model=ListSpacesArgs,
            category="ipam",
            permission=("read", "ip_space"),
        )
        async def list_ip_spaces(
            db: AsyncSession, user: User, args: ListSpacesArgs
        ) -> list[dict[str, Any]]:
            ...
    """

    def decorator(fn: ToolExecutor) -> ToolExecutor:
        REGISTRY.register(
            Tool(
                name=name,
                description=description,
                args_model=args_model,
                executor=fn,
                writes=writes,
                category=category,
                default_enabled=default_enabled,
                module=module,
                permission=permission,
            )
        )
        return fn

    return decorator


# ── Tool resolution ────────────────────────────────────────────────


class ToolDisabled(KeyError):
    """Raised when a tool is registered but disabled in the operator's
    Tool Catalog or per-provider allowlist. The chat orchestrator
    surfaces the failure as a tool-result message so the LLM can
    explain to the user how to enable it."""

    def __init__(self, name: str, scope: str) -> None:
        super().__init__(name)
        self.name = name
        # ``scope`` is "platform" (operator-level disable) or
        # "provider" (per-provider allowlist). Drives the message the
        # user sees.
        self.scope = scope


def _platform_enabled_set(platform_enabled: list[str] | None) -> set[str] | None:
    """Resolve ``PlatformSettings.ai_tools_enabled`` against the
    registry defaults. Returns the explicit set when the setting is
    non-NULL, else None meaning "use registry defaults"."""
    if platform_enabled is None:
        return None
    return set(platform_enabled)


def effective_tool_names(
    *,
    platform_enabled: list[str] | None,
    provider_enabled: list[str] | None,
    enabled_modules: set[str] | None = None,
) -> set[str]:
    """Resolve which tools are enabled for *this* request.

    Layering, narrow-down semantics:

    1. Start with the registry's ``default_enabled=True`` set.
    2. If ``platform_enabled`` is non-NULL, replace step 1 with that
       explicit list (operator's Tool Catalog override).
    3. If ``provider_enabled`` is non-NULL, intersect with it
       (per-provider narrowing for small-context models).
    4. If ``enabled_modules`` is non-NULL, drop every tool whose
       ``module`` id is a *known* catalog module that isn't in that
       set. ``module=None`` is always kept, and an *unknown* module id
       fails OPEN (tool kept) — mirroring
       ``feature_modules.is_module_enabled``'s "unknown ⇒ True"
       defensiveness, so a mistyped / renamed module id can never
       silently strip a tool from the copilot surface (issue #479).
       For a known module this is still a hard kill-switch — disabling
       ``network.customer`` removes the customer find/count tools
       regardless of any catalog or provider override.

    NULL at any layer means "no override at this layer" — the
    behaviour falls through to the wider layer.
    """
    platform = _platform_enabled_set(platform_enabled)
    if platform is None:
        eligible = {t.name for t in REGISTRY.all() if t.default_enabled and not t.writes}
    else:
        # Operator-explicit list. Filter to tools that actually exist
        # so a renamed / removed tool doesn't break chat — same
        # forward-compat we already do for provider allowlists.
        registered = {t.name for t in REGISTRY.all() if not t.writes}
        eligible = platform & registered
    if provider_enabled is not None:
        eligible &= set(provider_enabled)
    if enabled_modules is not None:
        # Gate only on KNOWN catalog modules. ``module=None`` and any
        # unknown/mistyped module id fail open (tool kept) — see the
        # docstring; ``is_known`` is imported at call time to avoid an
        # import cycle with feature_modules (issue #479).
        from app.services.feature_modules import is_known

        modules_by_tool = {t.name: t.module for t in REGISTRY.all()}

        def _module_allows(mod: str | None) -> bool:
            if mod is None or not is_known(mod):
                return True
            return mod in enabled_modules

        eligible = {n for n in eligible if _module_allows(modules_by_tool.get(n))}
    return eligible
