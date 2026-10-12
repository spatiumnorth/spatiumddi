"""Top-N report read tools for the Operator Copilot (issue #47).

Surfaces the four Top-N reports as read-only MCP tools so operators can
ask "which subnets are most full?", "who owns the most IPs?", "what's
been changed most this week?", or "which clients are hammering DNS?"
without leaving the chat drawer.

Each tool reuses the exact aggregation helper the REST endpoint uses
(``app.api.v1.reports.router.compute_*``) so the chat answer and the
Reports page can never drift. All four are read-only and gated by the
``reports.top_n`` feature module — disabling the module in Settings →
Features strips them from the AI surface in lock-step with the sidebar
entry, matching the router-level ``require_module`` gate.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.reports.router import (
    TOP_N,
    compute_top_dns_clients,
    compute_top_modified_resources,
    compute_top_owners,
    compute_top_subnets,
)
from app.core.permissions import user_has_permission
from app.models.auth import User
from app.services.ai.tools.base import register_tool

_MODULE = "reports.top_n"
_CATEGORY = "reports"


def _limit_field() -> Any:
    return Field(
        default=TOP_N,
        ge=1,
        le=TOP_N,
        description=f"How many ranked rows to return (max {TOP_N}).",
    )


# ── find_top_subnets_by_utilization ────────────────────────────────────


class FindTopSubnetsArgs(BaseModel):
    limit: int = _limit_field()


@register_tool(
    name="find_top_subnets_by_utilization",
    permission=("read", "subnet"),
    module=_MODULE,
    description=(
        "Return the most-utilized subnets, ranked by utilization "
        "percentage (highest first). Each row carries id, name, "
        "network (CIDR), utilization_percent, allocated_ips, and "
        "total_ips. Use for 'which subnets are nearly full?' or "
        "'top subnets by usage'."
    ),
    args_model=FindTopSubnetsArgs,
    category=_CATEGORY,
    writes=False,
    default_enabled=True,
)
async def find_top_subnets_by_utilization(
    db: AsyncSession, user: User, args: FindTopSubnetsArgs  # noqa: ARG001 — read-only
) -> list[dict[str, Any]]:
    rows = await compute_top_subnets(db, limit=args.limit)
    return [r.model_dump() for r in rows]


# ── find_top_owners_by_ip_count ────────────────────────────────────────


class FindTopOwnersArgs(BaseModel):
    limit: int = _limit_field()


@register_tool(
    name="find_top_owners_by_ip_count",
    permission=("read", "customer"),
    module=_MODULE,
    description=(
        "Return the customers owning the most IP addresses, ranked by "
        "IP count (highest first). Ownership is resolved via the owning "
        "subnet's customer link; IPs whose subnet has no customer fall "
        "into a single 'Unowned' bucket (customer_id null). Each row "
        "carries customer_id, customer_name, and ip_count. Use for "
        "'who owns the most IPs?' or 'top customers by address usage'."
    ),
    args_model=FindTopOwnersArgs,
    category=_CATEGORY,
    writes=False,
    default_enabled=True,
)
async def find_top_owners_by_ip_count(
    db: AsyncSession, user: User, args: FindTopOwnersArgs
) -> list[dict[str, Any]] | dict[str, str]:
    # The payload is the customer roster (customer_id + customer_name).
    # ``compute_top_owners`` performs no permission check of its own, so
    # gate here on ``read:customer`` — the same resource type the
    # canonical customers surface and the REST endpoint require. A caller
    # with only ``read:ip_address`` must not read customer names through
    # this side door.
    if not user_has_permission(user, "read", "customer"):
        return {
            "error": (
                "This report returns the customer roster (the top IP "
                "owners) and requires 'read' permission on 'customer'. "
                "Ask your platform admin to grant it."
            )
        }
    rows = await compute_top_owners(db, limit=args.limit)
    return [r.model_dump() for r in rows]


# ── find_top_modified_resources ────────────────────────────────────────


class FindTopModifiedResourcesArgs(BaseModel):
    limit: int = _limit_field()


@register_tool(
    name="find_top_modified_resources",
    permission=("read", "audit_log"),
    module=_MODULE,
    description=(
        "Return the most-frequently-modified resources over the trailing "
        "7 days, ranked by mutation count (create / update / delete). "
        "Each row carries resource_type, resource_id, resource_display, "
        "and change_count. Use for 'what changed the most this week?' or "
        "'which resources are churning?'."
    ),
    args_model=FindTopModifiedResourcesArgs,
    category=_CATEGORY,
    writes=False,
    default_enabled=True,
)
async def find_top_modified_resources(
    db: AsyncSession, user: User, args: FindTopModifiedResourcesArgs  # noqa: ARG001 — read-only
) -> list[dict[str, Any]]:
    rows = await compute_top_modified_resources(db, limit=args.limit)
    return [r.model_dump() for r in rows]


# ── find_top_dns_clients ───────────────────────────────────────────────


class FindTopDNSClientsArgs(BaseModel):
    limit: int = _limit_field()


@register_tool(
    name="find_top_dns_clients",
    permission=("read", ("server", "dns_group")),
    module=_MODULE,
    description=(
        "Return the noisiest DNS clients by query volume over the DNS "
        "query-log retention window (24 h). Each row carries client_ip "
        "and query_count. Returns an empty list when no query logs have "
        "been shipped. Use for 'which clients are querying DNS the "
        "most?' or 'top DNS talkers'."
    ),
    args_model=FindTopDNSClientsArgs,
    category=_CATEGORY,
    writes=False,
    default_enabled=True,
)
async def find_top_dns_clients(
    db: AsyncSession, user: User, args: FindTopDNSClientsArgs  # noqa: ARG001 — read-only
) -> list[dict[str, Any]]:
    rows = await compute_top_dns_clients(db, limit=args.limit)
    return [r.model_dump() for r in rows]
