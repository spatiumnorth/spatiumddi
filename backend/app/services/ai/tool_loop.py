"""The model / tool-call loop, without a chat session (issue #4405).

``ChatOrchestrator.stream_turn`` used to hold the whole loop inline, bound
to an ``AIChatSession`` and an SSE stream. Copilot Watch needs the same
loop from a Celery task with no session and nobody listening, so the three
parts that are not about chat live here:

* :func:`stream_model_round` — one request to the model, with failover
  across a provider chain. It yields content deltas as they arrive, so the
  chat can still stream them, and ends with a ``result`` or an ``error``.
* :func:`dispatch_tool_call` — the duplicate-call guard, the registry
  dispatch and the mapping of every refusal to a tool result the model can
  read.
* :func:`run_headless` — both of the above over an in-memory message
  list, with a round cap and a token cap, for callers with no session.

The chat orchestrator persists messages and translates events to SSE
around the first two; behaviour there is unchanged.
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass, field
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.llm import get_driver
from app.drivers.llm.base import ChatMessage, ChatRequest, ToolCall, ToolDefinition
from app.models.ai import AIProvider
from app.models.auth import User
from app.services.ai.tools import (
    REGISTRY,
    ToolArgumentError,
    ToolDisabled,
    ToolNotFound,
    ToolPermissionDenied,
    is_rate_limit_refusal,
)

logger = structlog.get_logger(__name__)


def is_transient_failure(exc: BaseException) -> bool:
    """Decide whether a driver error is worth retrying on a fallback
    provider. Transient = network hiccup, server-side 5xx, rate limit.
    Configuration errors (auth, schema) are NOT retried — they need
    operator action and surface untouched.

    The match is on the SDK exception class name rather than ``isinstance``
    so we can recognise both OpenAI- and Anthropic-flavoured errors
    without import-time coupling between drivers.
    """
    name = type(exc).__name__
    transient_class_names = {
        # OpenAI + Anthropic share these names.
        "APIConnectionError",
        "APITimeoutError",
        "APIConnectionTimeoutError",
        "APIResponseValidationError",
        "InternalServerError",
        "ServiceUnavailableError",
        "RateLimitError",
        # Generic asyncio / httpx
        "TimeoutError",
        "ReadTimeout",
        "ConnectError",
        "ConnectTimeout",
    }
    if name in transient_class_names:
        return True
    # APIStatusError covers any non-2xx — only treat 5xx + 429 as transient.
    status_code = getattr(exc, "status_code", None)
    if isinstance(status_code, int) and (status_code >= 500 or status_code == 429):
        return True
    return False


# ── One model round ───────────────────────────────────────────────────


@dataclass(frozen=True)
class RoundResult:
    """What one completed request to the model produced."""

    content: str
    tool_calls: list[ToolCall]
    finish_reason: str | None
    prompt_tokens: int | None
    completion_tokens: int | None
    elapsed_ms: int
    # The provider and model that actually answered: the first in the
    # chain, or a fallback.
    provider: AIProvider
    model: str


@dataclass(frozen=True)
class RoundEvent:
    """One item from :func:`stream_model_round`.

    ``kind`` is ``content`` (``delta``), ``failover`` (``info``), and then
    exactly one of ``result`` (``result``) or ``error`` (``message``).
    """

    kind: str
    delta: str = ""
    info: dict[str, Any] = field(default_factory=dict)
    result: RoundResult | None = None
    message: str = ""


async def stream_model_round(
    *,
    messages: Sequence[ChatMessage],
    tools: Sequence[ToolDefinition],
    chain: Sequence[AIProvider],
    model: str,
    log_event_prefix: str = "ai_chat",
    log_context: dict[str, Any] | None = None,
) -> AsyncIterator[RoundEvent]:
    """Send ``messages`` to ``chain[0]`` and stream the reply.

    On a transient failure before anything was received, the next provider
    in ``chain`` is tried with its own ``default_model`` (the first one's
    model name probably does not exist there). A configuration error, or a
    failure after part of a reply arrived, ends the round with ``error``:
    retrying then could produce a duplicated or contradictory reply.
    """
    ctx = log_context or {}
    attempt_idx = 0
    chunks_received = False
    content = ""
    tool_calls: list[ToolCall] = []
    finish_reason: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    started = time.monotonic()
    current_provider = chain[0]
    current_model = model

    while True:
        # Fresh request bound to whatever provider/model we're
        # currently attempting (might be a fallback).
        request = ChatRequest(
            messages=messages,
            model=current_model,
            tools=tools,
            temperature=float(current_provider.options.get("temperature", 0.3)),
            max_tokens=int(current_provider.options.get("max_tokens", 2048)),
        )
        driver = get_driver(current_provider)
        try:
            async for chunk in driver.chat(request):
                if chunk.content_delta:
                    content += chunk.content_delta
                    chunks_received = True
                    yield RoundEvent("content", delta=chunk.content_delta)
                if chunk.tool_call_delta is not None:
                    tool_calls.append(chunk.tool_call_delta)
                    chunks_received = True
                # Usage may arrive on the finish_reason chunk
                # (OpenAI native) OR a trailing usage-only chunk
                # (Ollama with stream_options.include_usage).
                # Capture whichever shows up.
                if chunk.prompt_tokens is not None:
                    prompt_tokens = chunk.prompt_tokens
                if chunk.completion_tokens is not None:
                    completion_tokens = chunk.completion_tokens
                if chunk.finish_reason:
                    finish_reason = chunk.finish_reason
            break
        except Exception as exc:  # noqa: BLE001
            if not is_transient_failure(exc) or chunks_received:
                # Either a configuration error (auth, schema)
                # or we've already received partial output —
                # don't risk a duplicated/contradictory reply.
                logger.exception(
                    f"{log_event_prefix}_driver_error",
                    provider=current_provider.name,
                    **ctx,
                )
                yield RoundEvent("error", message=f"{type(exc).__name__}: {exc}")
                return
            attempt_idx += 1
            if attempt_idx >= len(chain):
                # Out of fallbacks. Surface the last error.
                logger.exception(
                    f"{log_event_prefix}_failover_exhausted",
                    tried=[p.name for p in chain],
                    **ctx,
                )
                yield RoundEvent(
                    "error",
                    message=(
                        f"all {len(chain)} provider(s) "
                        f"failed; last error: {type(exc).__name__}: {exc}"
                    ),
                )
                return
            next_provider = chain[attempt_idx]
            next_model = next_provider.default_model or current_model
            logger.warning(
                f"{log_event_prefix}_failover",
                from_provider=current_provider.name,
                to_provider=next_provider.name,
                to_model=next_model,
                reason=f"{type(exc).__name__}: {exc}",
                **ctx,
            )
            yield RoundEvent(
                "failover",
                info={
                    "kind": "failover",
                    "from_provider": current_provider.name,
                    "to_provider": next_provider.name,
                    "to_model": next_model,
                    "reason": f"{type(exc).__name__}",
                },
            )
            current_provider = next_provider
            current_model = next_model
            # Reset attempt-local state and retry the round.
            content = ""
            tool_calls = []
            finish_reason = None
            prompt_tokens = None
            completion_tokens = None
            started = time.monotonic()

    yield RoundEvent(
        "result",
        result=RoundResult(
            content=content,
            tool_calls=tool_calls,
            finish_reason=finish_reason,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            provider=current_provider,
            model=current_model,
        ),
    )


# ── One tool call ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class ToolOutcome:
    """The result of one tool call, as the text fed back to the model."""

    result_text: str
    is_error: bool
    # True when the call repeated one already served this turn and the
    # tool was not run again.
    duplicate: bool = False


def parse_tool_arguments(tc: ToolCall) -> Any:
    """The call's arguments as the model wrote them; ``{}`` when they are
    not JSON. A JSON value that is not an object is returned as it is, and
    the registry refuses it as invalid arguments."""
    try:
        return json.loads(tc.arguments_json or "{}")
    except json.JSONDecodeError:
        return {}


async def dispatch_tool_call(
    tc: ToolCall,
    *,
    db: AsyncSession,
    user: User,
    effective: set[str],
    seen_calls: set[tuple[str, str]],
    log_event_prefix: str = "ai_chat",
    log_context: dict[str, Any] | None = None,
) -> ToolOutcome:
    """Run ``tc`` as ``user`` and return what the model should read.

    Never raises: every refusal (unknown tool, disabled, permission,
    bad arguments, the tool's own exception) becomes an error result the
    model can act on. ``seen_calls`` is the caller's per-turn set of
    ``(name, canonical args)``; a repeat is answered with a stop-the-loop
    hint instead of running the tool again. Some smaller open-weight
    models loop on a successful call (qwen2.5:7b has called
    ``list_subnets`` five times in a row with the same arguments).
    """
    raw_args = parse_tool_arguments(tc)

    # Dedup: same name + same canonical args we've already
    # served this turn. Don't re-run the tool — feed back
    # a stop-the-loop hint so the model summarises instead.
    args_canonical = json.dumps(raw_args, sort_keys=True, default=str)
    call_key = (tc.name, args_canonical)
    if call_key in seen_calls:
        return ToolOutcome(
            result_text=json.dumps(
                {
                    "warning": (
                        f"You already called {tc.name} with these arguments "
                        "earlier in this turn — the result is already in your "
                        "conversation history. Do NOT call this tool again. "
                        "Read the previous result and write the answer to the "
                        "operator now."
                    ),
                }
            ),
            is_error=False,
            duplicate=True,
        )
    seen_calls.add(call_key)

    try:
        result = await REGISTRY.call(
            tc.name,
            raw_args,
            db=db,
            user=user,
            effective=effective,
        )
        return ToolOutcome(
            result_text=json.dumps(result, default=str),
            is_error=is_rate_limit_refusal(result),
        )
    except ToolNotFound:
        # Smaller open-weight models (gemma, llama-3-8b, etc.)
        # sometimes hallucinate a generic-sounding name like
        # ``list_all_resources``. Echo the real tool names
        # back so the model can self-correct on the next
        # iteration rather than giving up and emitting a
        # generic greeting.
        result_text = json.dumps(
            {
                "error": f"tool not found: {tc.name}",
                "available_tools": sorted(effective),
                "hint": (
                    "You may only call tools listed in available_tools. "
                    "Pick the closest match and try again."
                ),
            }
        )
    except ToolDisabled as exc:
        # The operator has disabled this tool in
        # Settings → AI → Tool Catalog (or in the
        # provider's allowlist). The model picked it
        # anyway — surface a clear message so it can
        # explain to the user how to enable it.
        result_text = json.dumps(
            {
                "error": f"tool {exc.name!r} is disabled by the operator",
                "hint": (
                    "This tool exists but is not enabled in the operator's "
                    "Tool Catalog. Tell the user the feature is disabled and "
                    "to ask their administrator to enable "
                    f"'{exc.name}' under Administration → AI Tool Catalog. "
                    "Do not retry this tool call."
                ),
            }
        )
    except ToolPermissionDenied as exc:
        result_text = json.dumps(
            {
                "error": str(exc),
                "hint": (
                    "The signed-in user's role does not grant this. "
                    "Tell them; do not retry this tool call."
                ),
            }
        )
    except ToolArgumentError as exc:
        result_text = json.dumps({"error": f"invalid args: {exc.detail}"})
    except Exception as exc:  # noqa: BLE001
        logger.exception(
            f"{log_event_prefix}_tool_error",
            tool=tc.name,
            **(log_context or {}),
        )
        result_text = json.dumps({"error": f"{type(exc).__name__}: {exc}"})
    return ToolOutcome(result_text=result_text, is_error=True)


# ── The headless loop ─────────────────────────────────────────────────


@dataclass
class HeadlessResult:
    """Outcome of :func:`run_headless`."""

    # ``ok`` — the model gave a final answer. ``error`` — a driver error.
    # ``round_cap`` / ``token_cap`` — a limit ended the loop first.
    status: str
    content: str = ""
    error: str | None = None
    # Every message of the run after the ones passed in, in order, plus
    # the tool calls made. Stored by the caller as the run's transcript.
    transcript: list[dict[str, Any]] = field(default_factory=list)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    rounds: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    # Token counts per model that answered, for cost accounting: a
    # failover mid-run bills two rate sheets.
    usage_by_model: dict[str, tuple[int, int]] = field(default_factory=dict)
    provider: AIProvider | None = None
    model: str = ""

    @property
    def tokens_total(self) -> int:
        return self.tokens_in + self.tokens_out


async def run_headless(
    *,
    db: AsyncSession,
    user: User,
    messages: list[ChatMessage],
    tools: Sequence[ToolDefinition],
    chain: Sequence[AIProvider],
    model: str,
    max_rounds: int,
    max_tokens: int | None = None,
    max_tool_calls_per_round: int = 8,
    final_round_nudge: str | None = None,
    log_event_prefix: str = "ai_headless",
    log_context: dict[str, Any] | None = None,
) -> HeadlessResult:
    """Run the model / tool loop to a final answer with nobody listening.

    ``messages`` is extended in place. ``user`` is the identity every tool
    runs as; the registry enforces its permissions at dispatch.
    ``final_round_nudge`` is sent as a user message before the last round
    allowed, once tools have been used, to tell a model that would keep
    calling tools to answer instead. (The tools stay in the request: a
    provider may refuse a conversation holding tool results with no tools
    declared.) A model that asks for a tool on the last round anyway ends
    the run with ``round_cap``. ``max_tokens`` caps prompt + completion
    tokens summed over the run: the loop stops with ``token_cap`` before
    starting a round once the total has reached it.
    """
    effective = {t.name for t in tools}
    seen_calls: set[tuple[str, str]] = set()
    out = HeadlessResult(status="round_cap")

    for round_idx in range(max_rounds):
        if max_tokens is not None and out.tokens_total >= max_tokens:
            out.status = "token_cap"
            return out
        last_round = round_idx == max_rounds - 1
        if last_round and round_idx > 0 and final_round_nudge:
            messages.append(ChatMessage(role="user", content=final_round_nudge))
            out.transcript.append({"role": "user", "content": final_round_nudge})
        result: RoundResult | None = None
        async for ev in stream_model_round(
            # A copy: the request must not change under a driver (or a
            # recorded request) as this loop appends to ``messages``.
            messages=list(messages),
            tools=tools,
            chain=chain,
            model=model,
            log_event_prefix=log_event_prefix,
            log_context=log_context,
        ):
            if ev.kind == "error":
                out.status = "error"
                out.error = ev.message
                return out
            if ev.kind == "failover":
                out.transcript.append({"role": "info", **ev.info})
            if ev.kind == "result":
                result = ev.result
        if result is None:  # pragma: no cover - the generator always ends in result/error
            out.status = "error"
            out.error = "the model round ended without a result"
            return out

        out.rounds += 1
        tin = result.prompt_tokens or 0
        tout = result.completion_tokens or 0
        out.tokens_in += tin
        out.tokens_out += tout
        prev = out.usage_by_model.get(result.model, (0, 0))
        out.usage_by_model[result.model] = (prev[0] + tin, prev[1] + tout)
        out.provider = result.provider
        out.model = result.model

        calls = result.tool_calls[:max_tool_calls_per_round]
        messages.append(
            ChatMessage(role="assistant", content=result.content, tool_calls=tuple(calls))
        )
        out.transcript.append(
            {
                "role": "assistant",
                "content": result.content,
                "tool_calls": [
                    {"id": tc.id, "name": tc.name, "arguments": tc.arguments_json} for tc in calls
                ],
                "tokens_in": result.prompt_tokens,
                "tokens_out": result.completion_tokens,
                "model": result.model,
            }
        )

        if result.finish_reason != "tool_calls" and not calls:
            out.status = "ok"
            out.content = result.content
            return out
        if last_round:
            # Out of rounds: the calls it asked for are not run.
            break

        for tc in calls:
            outcome = await dispatch_tool_call(
                tc,
                db=db,
                user=user,
                effective=effective,
                seen_calls=seen_calls,
                log_event_prefix=log_event_prefix,
                log_context=log_context,
            )
            messages.append(
                ChatMessage(
                    role="tool",
                    content=outcome.result_text,
                    tool_call_id=tc.id,
                    name=tc.name,
                )
            )
            out.transcript.append(
                {
                    "role": "tool",
                    "name": tc.name,
                    "tool_call_id": tc.id,
                    "content": outcome.result_text,
                    "is_error": outcome.is_error,
                }
            )
            out.tool_calls.append(
                {
                    "name": tc.name,
                    "arguments": tc.arguments_json,
                    "is_error": outcome.is_error,
                    "duplicate": outcome.duplicate,
                }
            )

    return out


__all__ = [
    "HeadlessResult",
    "RoundEvent",
    "RoundResult",
    "ToolOutcome",
    "dispatch_tool_call",
    "is_transient_failure",
    "parse_tool_arguments",
    "run_headless",
    "stream_model_round",
]
