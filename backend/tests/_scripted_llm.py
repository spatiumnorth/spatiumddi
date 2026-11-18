"""A scripted stand-in for an LLM driver (issue #4405).

``ScriptedLLM`` replays a fixed list of steps, one per request the code
under test makes, and records every request it was sent. Install it with
:func:`install`, which replaces ``get_driver`` where the model / tool loop
resolves it, so no provider SDK or network is involved.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from app.drivers.llm.base import ChatChunk, ChatRequest, ToolCall


class APIConnectionError(Exception):
    """Named like the SDK error the loop treats as transient."""


class AuthenticationError(Exception):
    """A configuration error: never retried on another provider."""


@dataclass
class Step:
    """One scripted reply: text, tool calls, or an exception to raise."""

    content: str = ""
    tool_calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    raises: Exception | None = None
    prompt_tokens: int | None = 10
    completion_tokens: int | None = 5
    # Raise after the content was streamed, instead of before anything.
    raise_after_content: bool = False


def say(content: str, **kw: Any) -> Step:
    return Step(content=content, **kw)


def call(name: str, args: dict[str, Any] | None = None, **kw: Any) -> Step:
    return Step(tool_calls=[(name, args or {})], **kw)


class ScriptedLLM:
    def __init__(self, steps: list[Step]) -> None:
        self.steps = list(steps)
        self.requests: list[tuple[str, ChatRequest]] = []

    def driver_for(self, provider: Any) -> _Driver:
        return _Driver(self, provider)


class _Driver:
    def __init__(self, llm: ScriptedLLM, provider: Any) -> None:
        self.llm = llm
        self.provider = provider

    async def chat(self, request: ChatRequest) -> AsyncIterator[ChatChunk]:
        self.llm.requests.append((self.provider.name, request))
        if not self.llm.steps:
            raise AssertionError("the scripted LLM was asked for more replies than scripted")
        step = self.llm.steps.pop(0)
        if step.raises is not None and not step.raise_after_content:
            raise step.raises
        if step.content:
            yield ChatChunk(content_delta=step.content)
        if step.raises is not None:
            raise step.raises
        for i, (name, args) in enumerate(step.tool_calls):
            yield ChatChunk(
                tool_call_delta=ToolCall(
                    id=f"call_{len(self.llm.requests)}_{i}",
                    name=name,
                    arguments_json=json.dumps(args),
                )
            )
        yield ChatChunk(
            finish_reason="tool_calls" if step.tool_calls else "stop",
            prompt_tokens=step.prompt_tokens,
            completion_tokens=step.completion_tokens,
        )


def install(monkeypatch: pytest.MonkeyPatch, steps: list[Step]) -> ScriptedLLM:
    llm = ScriptedLLM(steps)
    monkeypatch.setattr("app.services.ai.tool_loop.get_driver", llm.driver_for)
    return llm
