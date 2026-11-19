"""Which LLM providers a Copilot Watch run may use (issue #4405).

The chat sends install data to a provider because a person asked a
question and is looking at the answer. Watch sends it with nobody
watching, so it does not inherit the chat's provider list: by default it
uses only providers the operator has marked on-prem
(``ai_provider.is_on_prem``). Anything else needs the separate
``allow_hosted_provider`` switch on the Watch settings.

The same rule bounds failover. A run never falls back to a provider it
would not have been allowed to start on.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai import AIProvider
from app.models.ai_watch import AIWatchConfig

# Provider kinds that are a hosted service by definition and so can never
# be marked on-prem. ``openai_compat`` is the one kind that can point at a
# host the operator runs (Ollama, vLLM, LM Studio, llama.cpp ...).
HOSTED_ONLY_KINDS: frozenset[str] = frozenset({"anthropic", "google", "azure_openai"})


def can_be_on_prem(kind: str) -> bool:
    return kind not in HOSTED_ONLY_KINDS


def provider_eligible(provider: AIProvider, config: AIWatchConfig) -> bool:
    if not provider.is_enabled:
        return False
    return bool(provider.is_on_prem) or bool(config.allow_hosted_provider)


async def resolve_provider_chain(
    db: AsyncSession, config: AIWatchConfig
) -> tuple[list[AIProvider], str | None]:
    """The providers a run may use, the one to start on first.

    Returns ``(chain, None)``, or ``([], reason)`` when no provider may be
    used: ``no_provider`` (none is enabled, or the pinned one is missing
    or disabled) or ``hosted_not_allowed`` (enabled providers exist, but
    none is on-prem and hosted use is off).
    """
    rows = list(
        (
            await db.execute(
                select(AIProvider)
                .where(AIProvider.is_enabled.is_(True))
                .order_by(AIProvider.priority.asc(), AIProvider.name.asc())
            )
        )
        .scalars()
        .all()
    )
    if not rows:
        return [], "no_provider"
    eligible = [p for p in rows if provider_eligible(p, config)]

    if config.provider_id is not None:
        pinned = next((p for p in rows if p.id == config.provider_id), None)
        if pinned is None:
            return [], "no_provider"
        if not provider_eligible(pinned, config):
            return [], "hosted_not_allowed"
        return [pinned, *[p for p in eligible if p.id != pinned.id]], None

    if not eligible:
        return [], "hosted_not_allowed"
    return eligible, None


__all__ = ["HOSTED_ONLY_KINDS", "can_be_on_prem", "provider_eligible", "resolve_provider_chain"]
