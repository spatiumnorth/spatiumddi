"""The tools a Copilot Watch run may call (issue #4405).

Watch has its own allowlist, much shorter than the chat's: enough to
drill into what the evidence pack points at, and nothing else. Four
layers decide what a run is offered, each only ever narrowing:

1. the allowlist: ``ai_watch_config.enabled_tools``, or
   :data:`DEFAULT_WATCH_TOOLS` when that is NULL;
2. :func:`tool_refusal` — a structural floor no setting can lift: no
   write tool, no ``propose_*`` tool, nothing that sends traffic outward
   or spends a network-tool budget, nothing superadmin-only, nothing that
   waits for a person;
3. the platform Tool Catalog, the provider's own allowlist and the
   feature modules, exactly as the chat applies them;
4. what the Watch identity's roles let it call.

The registry enforces the last one again at dispatch.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai import AIProvider
from app.models.ai_watch import AIWatchConfig
from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services import feature_modules as fm_svc
from app.services.ai.tools import REGISTRY, Tool, effective_tool_names
from app.services.ai.tools.base import SELF, SUPERADMIN

DEFAULT_WATCH_TOOLS: tuple[str, ...] = (
    # What the detectors found.
    "list_alerts",
    "list_alert_rules",
    "current_state",
    "find_conformity_results",
    "get_conformity_summary",
    "find_agents_with_config_failures",
    "find_agents_with_spool_backlog",
    # What changed just before.
    "get_audit_history",
    "audit_walk",
    # The objects the evidence names.
    "list_subnets",
    "get_subnet_summary",
    "get_subnet_utilization_trend",
    "list_dns_server_groups",
    "find_dns_servers",
    "list_dns_zones",
    "list_dhcp_servers",
    "list_dhcp_scopes",
    "find_dhcp_pool_occupancy",
    "find_dhcp_server_stats",
    "get_dhcp_lease_rate",
    "get_dns_query_rate",
)

# Tools that stop and wait for a person to answer.
_INTERACTIVE_TOOLS: frozenset[str] = frozenset({"ask_yes_no"})


def tool_refusal(tool: Tool) -> str | None:
    """Why ``tool`` can never be offered to Watch, or None when it can."""
    if tool.writes:
        return "it changes state"
    if tool.name.startswith("propose_"):
        return "it stages a change; Copilot Watch only observes and advises"
    if tool.outbound or tool.rate_limit is not None:
        return "it sends traffic outward"
    if tool.permission in (SUPERADMIN, SELF):
        return "it is superadmin-only or acts on the caller's own rows"
    if tool.name in _INTERACTIVE_TOOLS:
        return "it waits for a person to answer"
    return None


def allowable_tools() -> list[Tool]:
    """Every registered tool the settings page may offer for the allowlist."""
    return [t for t in REGISTRY.all() if tool_refusal(t) is None]


def validate_allowlist(names: list[str]) -> list[str]:
    """Return the problems with a proposed allowlist; empty when it is fine."""
    problems: list[str] = []
    for name in names:
        tool = REGISTRY.get(name)
        if tool is None:
            problems.append(f"{name}: no such tool")
            continue
        why = tool_refusal(tool)
        if why is not None:
            problems.append(f"{name}: {why}")
    return problems


async def tools_for_run(
    db: AsyncSession,
    *,
    config: AIWatchConfig,
    principal: User,
    provider: AIProvider | None,
) -> list[Tool]:
    """The tools this run is offered, after all four layers."""
    wanted = set(config.enabled_tools if config.enabled_tools is not None else DEFAULT_WATCH_TOOLS)
    platform_settings = await db.get(PlatformSettings, 1)
    effective = effective_tool_names(
        platform_enabled=(
            platform_settings.ai_tools_enabled if platform_settings is not None else None
        ),
        provider_enabled=provider.enabled_tools if provider is not None else None,
        enabled_modules=await fm_svc.get_enabled_modules(db),
    )
    candidates = [
        t
        for t in REGISTRY.read_only()
        if t.name in wanted and t.name in effective and tool_refusal(t) is None
    ]
    return REGISTRY.callable_by(principal, candidates)


__all__ = [
    "DEFAULT_WATCH_TOOLS",
    "allowable_tools",
    "tool_refusal",
    "tools_for_run",
    "validate_allowlist",
]
