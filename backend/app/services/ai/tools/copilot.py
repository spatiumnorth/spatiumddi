"""Operator Copilot self-tools (issue #120).

Tools the copilot uses to coordinate with the operator inside the
chat surface itself, rather than to look anything up. Today's only
member is ``ask_yes_no`` — the model invokes it when it needs a
binary answer (continue/cancel, include/exclude, yes/no) and the
chat drawer renders Yes/No buttons in place of free-text reply.

The tool returns a structured payload the orchestrator and the
frontend both pattern-match on:

* The orchestrator (chat.py round loop) detects ``kind ==
  "yes_no_question"`` in the tool_result and short-circuits — no
  further LLM round runs; the conversation pauses until the
  operator clicks a button (which sends a fresh user turn).
* The frontend (CopilotDrawer.MessageBubble) detects the same
  ``kind`` and renders a YesNoCard with two buttons; click feeds
  the answer back as a regular user message.

Default-enabled, ``module="ai.copilot"`` so deployments that have
the AI module disabled don't see it. Per-provider tool allowlists
can still narrow the set on a kiosk-style provider.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.services.ai.tools.base import register_tool


class AskYesNoArgs(BaseModel):
    question: str = Field(
        ...,
        min_length=1,
        max_length=300,
        description=(
            "One sentence the operator will see above the Yes/No buttons. "
            "Phrase it as a true binary — 'Continue with the deletion?' / "
            "'Include disabled rules?'. If the question is open-ended, "
            "ask in plain prose instead of calling this tool."
        ),
    )
    context: str | None = Field(
        default=None,
        max_length=600,
        description=(
            "Optional 1–3 sentence context block rendered under the "
            "question. Use to remind the operator what they'd be "
            "agreeing to."
        ),
    )
    yes_label: str = Field(
        default="Yes",
        max_length=20,
        description="Short button label for the affirmative answer.",
    )
    no_label: str = Field(
        default="No",
        max_length=20,
        description="Short button label for the negative answer.",
    )


@register_tool(
    name="ask_yes_no",
    permission="authenticated",
    description=(
        "Ask the operator a yes-or-no question and pause the "
        "conversation until they click a button. Use for true "
        "binaries: 'Continue with the deletion?', 'Include disabled "
        "scopes?', 'Run this against all subnets?'. Do NOT use for "
        "open-ended questions ('What hostname?') — ask those in "
        "plain prose. Returns immediately; the chat will resume on a "
        "fresh user turn carrying the operator's answer ('Yes' or "
        "'No'). After calling this, STOP — do not continue "
        "generating, do not call other tools, just wait. Cap: one "
        "``ask_yes_no`` call per turn."
    ),
    args_model=AskYesNoArgs,
    category="ops",
    module="ai.copilot",
)
async def ask_yes_no(
    db: AsyncSession,
    user: User,
    args: AskYesNoArgs,
) -> dict[str, Any]:
    """Returns a `kind: "yes_no_question"` payload that both the
    orchestrator and the frontend pattern-match on. No DB row
    needed — the question + answer flow rides on the existing
    chat-message persistence (the tool_result row carries the
    question; the operator's button click triggers a fresh user
    message carrying the answer).
    """
    return {
        "kind": "yes_no_question",
        "question": args.question,
        "context": args.context,
        "yes_label": args.yes_label,
        "no_label": args.no_label,
        # Hint the model echoes if it's tempted to keep generating
        # — most providers respect tool-result instructions, smaller
        # local models sometimes ignore them and the orchestrator's
        # short-circuit catches that case anyway.
        "instruction": (
            "Pause here. The operator will click Yes or No and the "
            "next user message will carry their answer. Do not "
            "generate any further response right now."
        ),
    }
