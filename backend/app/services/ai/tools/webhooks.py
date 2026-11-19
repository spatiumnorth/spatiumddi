"""Operator Copilot read tools for the webhook surface (#105 era).

Surfaces the ``EventSubscription`` registry + the ``EventOutbox``
delivery log so the Copilot can answer "which webhooks do we have
configured?", "is the SIEM webhook delivering successfully?", "what
events can I subscribe to?".

Secrets are NEVER returned — the HMAC signing key on each
``EventSubscription.secret_encrypted`` is folded into a boolean
``secret_set`` marker, matching the redaction pattern the REST
list endpoint uses.

Issue #280 — catch-up to MCP coverage parity. The matching
``propose_create_webhook`` / ``propose_update_webhook`` /
``propose_test_webhook`` write tools are deferred to a follow-up —
each needs an ``Operation`` class with preview + apply, which is
substantial wiring.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import is_effective_superadmin
from app.models.auth import User
from app.models.event_subscription import EventOutbox, EventSubscription
from app.services.ai.tools.base import register_tool


def _superadmin_gate(user: User) -> dict[str, Any] | None:
    """Webhook config surfaces URLs + delivery history that the REST
    endpoint gates to superadmin-only (operators may treat webhook
    URLs as semi-private — e.g. SIEM ingestion URLs with embedded
    auth tokens). Mirror the gate at the MCP layer so a non-
    superadmin's chat session can't read it either.
    """
    if not is_effective_superadmin(user):
        return {
            "error": (
                "Webhook config is restricted to superadmin users. "
                "Ask your platform admin to run the query."
            )
        }
    return None


class ListWebhooksArgs(BaseModel):
    enabled: bool | None = Field(
        default=None,
        description="True = only enabled, False = only disabled, omitted = both.",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="list_webhooks",
    permission="superadmin",
    description=(
        "List configured webhook subscriptions. Each entry carries "
        "name / url / enabled flag / subscribed event_types / "
        "secret_set boolean (NEVER the secret itself) / "
        "timeout_seconds / max_attempts. Operator uses this to "
        "answer 'what webhooks do we have?' or 'is the SIEM webhook "
        "still wired up?'. Read-only; no secrets surfaced."
    ),
    args_model=ListWebhooksArgs,
    category="webhooks",
)
async def list_webhooks(
    db: AsyncSession, user: User, args: ListWebhooksArgs
) -> list[dict[str, Any]] | dict[str, Any]:
    gate = _superadmin_gate(user)
    if gate is not None:
        return gate
    stmt = select(EventSubscription)
    if args.enabled is not None:
        stmt = stmt.where(EventSubscription.enabled.is_(args.enabled))
    stmt = stmt.order_by(EventSubscription.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(s.id),
            "name": s.name,
            "description": s.description,
            "url": s.url,
            "enabled": s.enabled,
            # Boolean marker — never the cleartext HMAC secret.
            "secret_set": bool(s.secret_encrypted),
            "event_types": s.event_types,
            "timeout_seconds": s.timeout_seconds,
            "max_attempts": s.max_attempts,
        }
        for s in rows
    ]


class GetWebhookEventTypesArgs(BaseModel):
    """No arguments — the catalog is platform-wide."""

    pass


@register_tool(
    name="get_webhook_event_types",
    permission="superadmin",
    description=(
        "Return the full typed-event vocabulary the platform emits "
        "(``space.created``, ``dns.zone.updated``, "
        "``appliance.permanently_deleted``, …). Generated from the "
        "resource_namespace × verb cross-product the publisher uses + "
        "any special-case event names (system.backup_completed, etc.). "
        "Use this so the LLM can validate ``event_types`` references "
        "before proposing a webhook subscription. Read-only."
    ),
    args_model=GetWebhookEventTypesArgs,
    category="webhooks",
)
async def get_webhook_event_types(
    db: AsyncSession, user: User, args: GetWebhookEventTypesArgs
) -> dict[str, list[str]]:
    # Lazy import — the publisher module pulls in the bulk of the
    # event-publisher graph, and we don't want that on import-time
    # registration.
    from app.services.event_publisher import (  # noqa: PLC0415
        _RESOURCE_NAMESPACE,
        _SPECIAL_EVENT_MAP,
        _VERB_MAP,
    )

    types: set[str] = set()
    for namespace in set(_RESOURCE_NAMESPACE.values()):
        for verb in _VERB_MAP.values():
            types.add(f"{namespace}.{verb}")
    types.update(_SPECIAL_EVENT_MAP.values())
    return {"event_types": sorted(types)}


class FindWebhookDeliveriesArgs(BaseModel):
    subscription_id: uuid.UUID | None = Field(
        default=None,
        description="Filter to one subscription's deliveries.",
    )
    state: str | None = Field(
        default=None,
        description="Filter by state: ``pending`` / ``in_flight`` / ``delivered`` / ``failed`` / ``dead``.",
    )
    event_type: str | None = Field(
        default=None,
        description="Filter to one event type (e.g. ``dns.zone.created``).",
    )
    limit: int = Field(default=50, ge=1, le=200)


@register_tool(
    name="find_webhook_deliveries",
    permission="superadmin",
    description=(
        "List recent webhook deliveries from the EventOutbox — the "
        "pending / in-flight / delivered / failed / dead history. "
        "Operator uses this to debug 'why hasn't the SIEM webhook "
        "received the last 3 deletes?' or to confirm a delivery "
        "landed. Includes attempts, last_error, last_status_code, "
        "delivered_at. Most recent first. Read-only."
    ),
    args_model=FindWebhookDeliveriesArgs,
    category="webhooks",
)
async def find_webhook_deliveries(
    db: AsyncSession, user: User, args: FindWebhookDeliveriesArgs
) -> list[dict[str, Any]] | dict[str, Any]:
    gate = _superadmin_gate(user)
    if gate is not None:
        return gate
    stmt = select(EventOutbox)
    if args.subscription_id:
        stmt = stmt.where(EventOutbox.subscription_id == args.subscription_id)
    if args.state:
        stmt = stmt.where(EventOutbox.state == args.state)
    if args.event_type:
        stmt = stmt.where(EventOutbox.event_type == args.event_type)
    stmt = stmt.order_by(EventOutbox.created_at.desc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(o.id),
            "subscription_id": str(o.subscription_id),
            "event_type": o.event_type,
            "state": o.state,
            "attempts": o.attempts,
            "last_error": o.last_error,
            "last_status_code": o.last_status_code,
            "next_attempt_at": (o.next_attempt_at.isoformat() if o.next_attempt_at else None),
            "delivered_at": o.delivered_at.isoformat() if o.delivered_at else None,
            "created_at": o.created_at.isoformat() if o.created_at else None,
            # Don't echo the full payload — could be large + may
            # contain operator-set custom fields. Operators wanting
            # the payload can hit the REST endpoint directly.
        }
        for o in rows
    ]
