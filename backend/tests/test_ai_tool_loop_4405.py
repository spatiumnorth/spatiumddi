"""The model / tool loop shared by the chat and Copilot Watch (#4405).

``ChatOrchestrator.stream_turn`` held the loop inline until #4405 moved the
model round and the tool dispatch into ``app.services.ai.tool_loop``. The
first half of this file pins the chat's behaviour across that move (the
events it streams, the messages it stores, failover, the duplicate-call
guard, the round cap); the second half covers ``run_headless``, the loop
with no chat session that Copilot Watch runs.
"""

from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.drivers.llm.base import ChatMessage, ToolDefinition
from app.models.ai import AIChatMessage, AIProvider
from app.models.auth import Group, Role, User
from app.models.ipam import IPSpace
from app.services.ai.chat import MAX_TOOL_ROUNDS, ChatOrchestrator, StreamEvent
from app.services.ai.tool_loop import run_headless
from app.services.ai.tools import REGISTRY
from tests._scripted_llm import APIConnectionError, AuthenticationError, call, install, say


async def _user(
    db: AsyncSession, *, superadmin: bool = False, permissions: list[dict] | None = None
) -> User:
    u = User(
        username=f"loop-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Loop",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
        is_active=True,
    )
    u.groups = []
    if permissions:
        role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
        group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
        group.roles = [role]
        u.groups = [group]
        db.add_all([role, group])
    db.add(u)
    await db.commit()
    return u


async def _provider(db: AsyncSession, name: str, *, priority: int = 100) -> AIProvider:
    p = AIProvider(
        name=name,
        kind="openai_compat",
        base_url="http://llm.example.test/v1",
        default_model=f"{name}-model",
        is_enabled=True,
        priority=priority,
        options={},
    )
    db.add(p)
    await db.commit()
    return p


async def _turn(
    db: AsyncSession, user: User, provider: AIProvider, text: str = "how many spaces?"
) -> tuple[list[StreamEvent], uuid.UUID]:
    chat = ChatOrchestrator(db, user)
    session = await chat.get_or_create_session(
        session_id=None, provider=provider, model=provider.default_model
    )
    await db.commit()
    events = [ev async for ev in chat.stream_turn(session=session, user_text=text)]
    return events, session.id


async def _messages(db: AsyncSession, session_id: uuid.UUID) -> list[AIChatMessage]:
    stmt = (
        select(AIChatMessage)
        .where(AIChatMessage.session_id == session_id)
        .order_by(AIChatMessage.created_at.asc())
    )
    return list((await db.execute(stmt)).scalars().all())


# ── Chat: behaviour held across the extraction ────────────────────────


async def test_chat_turn_runs_a_tool_then_answers(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = await _user(db_session, superadmin=True)
    provider = await _provider(db_session, "primary")
    db_session.add(IPSpace(name="loop-space", description=""))
    await db_session.commit()
    llm = install(monkeypatch, [call("list_ip_spaces"), say("One space: loop-space.")])

    events, session_id = await _turn(db_session, user, provider)

    assert [e.kind for e in events] == ["session", "tool_call", "tool_result", "content", "done"]
    tool_result = events[2].data
    assert tool_result["name"] == "list_ip_spaces"
    assert tool_result["is_error"] is False
    assert "loop-space" in tool_result["preview"]
    assert events[3].data == {"delta": "One space: loop-space."}
    assert events[4].data["finish_reason"] == "stop"
    assert events[4].data["tokens_in"] == 10

    rows = await _messages(db_session, session_id)
    assert [m.role for m in rows] == ["system", "user", "assistant", "tool", "assistant"]
    assert rows[2].tool_calls and rows[2].tool_calls[0]["name"] == "list_ip_spaces"
    assert rows[2].tokens_in == 10 and rows[2].tokens_out == 5
    assert rows[3].tool_call_id == rows[2].tool_calls[0]["id"]
    assert rows[4].content == "One space: loop-space."

    # The second request carried the tool result back to the model.
    second = llm.requests[1][1]
    assert [m.role for m in second.messages][-2:] == ["assistant", "tool"]
    assert "list_ip_spaces" in {t.name for t in second.tools}


async def test_chat_repeat_of_a_tool_call_is_not_run_again(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = await _user(db_session, superadmin=True)
    provider = await _provider(db_session, "primary")
    install(monkeypatch, [call("list_ip_spaces"), call("list_ip_spaces"), say("done")])

    events, session_id = await _turn(db_session, user, provider)

    results = [e.data for e in events if e.kind == "tool_result"]
    assert len(results) == 2
    assert "already called list_ip_spaces" in results[1]["preview"]
    assert results[1]["is_error"] is False
    tools = [m for m in await _messages(db_session, session_id) if m.role == "tool"]
    assert "Do NOT call this tool again" in tools[1].content


async def test_chat_unknown_and_refused_tools_become_error_results(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No grant on alerts or subnets: the tool exists but is not in this
    # user's schema, so the registry refuses it as disabled.
    user = await _user(db_session, permissions=[{"action": "read", "resource_type": "ip_space"}])
    provider = await _provider(db_session, "primary")
    install(
        monkeypatch,
        [
            call("list_all_resources"),
            call("list_subnets"),
            call("list_ip_spaces", {"limit": "not-a-number"}),
            say("I could not look that up."),
        ],
    )

    events, session_id = await _turn(db_session, user, provider)

    results = [e.data for e in events if e.kind == "tool_result"]
    assert [r["is_error"] for r in results] == [True, True, True]
    assert "tool not found: list_all_resources" in results[0]["preview"]
    stored = [m for m in await _messages(db_session, session_id) if m.role == "tool"]
    # The real names are echoed back so the model can correct itself.
    assert "list_ip_spaces" in json.loads(stored[0].content)["available_tools"]
    assert "disabled by the operator" in results[1]["preview"]
    assert "invalid args" in results[2]["preview"]
    assert events[-1].kind == "done"


async def test_chat_fails_over_on_a_transient_error_and_not_on_a_config_error(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = await _user(db_session, superadmin=True)
    primary = await _provider(db_session, "primary", priority=10)
    await _provider(db_session, "backup", priority=20)

    llm = install(monkeypatch, [say("", raises=APIConnectionError("down")), say("from backup")])
    events, session_id = await _turn(db_session, user, primary)
    assert [e.kind for e in events] == ["session", "info", "content", "done"]
    assert events[1].data["from_provider"] == "primary"
    assert events[1].data["to_provider"] == "backup"
    assert events[1].data["to_model"] == "backup-model"
    assert [name for name, _ in llm.requests] == ["primary", "backup"]
    assert llm.requests[1][1].model == "backup-model"
    assert (await _messages(db_session, session_id))[-1].content == "from backup"

    llm = install(monkeypatch, [say("", raises=AuthenticationError("bad key"))])
    events, _ = await _turn(db_session, user, primary)
    assert [e.kind for e in events] == ["session", "error"]
    assert "AuthenticationError: bad key" in events[1].data["message"]
    assert [name for name, _ in llm.requests] == ["primary"]


async def test_chat_does_not_fail_over_after_part_of_a_reply_arrived(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = await _user(db_session, superadmin=True)
    primary = await _provider(db_session, "primary", priority=10)
    await _provider(db_session, "backup", priority=20)
    llm = install(
        monkeypatch,
        [say("half an ans", raises=APIConnectionError("cut"), raise_after_content=True)],
    )

    events, _ = await _turn(db_session, user, primary)

    assert [e.kind for e in events] == ["session", "content", "error"]
    assert len(llm.requests) == 1


async def test_chat_reports_exhausted_failover(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = await _user(db_session, superadmin=True)
    primary = await _provider(db_session, "primary", priority=10)
    await _provider(db_session, "backup", priority=20)
    install(
        monkeypatch,
        [say("", raises=APIConnectionError("a")), say("", raises=APIConnectionError("b"))],
    )

    events, _ = await _turn(db_session, user, primary)

    assert events[-1].kind == "error"
    assert "all 2 provider(s) failed" in events[-1].data["message"]


async def test_chat_stops_at_the_round_cap(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = await _user(db_session, superadmin=True)
    provider = await _provider(db_session, "primary")
    steps = [call("list_ip_spaces", {"limit": i + 1}) for i in range(MAX_TOOL_ROUNDS)]
    llm = install(monkeypatch, steps)

    events, _ = await _turn(db_session, user, provider)

    assert events[-1].kind == "error"
    assert "MAX_TOOL_ROUNDS" in events[-1].data["message"]
    assert len(llm.requests) == MAX_TOOL_ROUNDS


# ── The headless loop ─────────────────────────────────────────────────


def _defs(*names: str) -> list[ToolDefinition]:
    out = []
    for n in names:
        t = REGISTRY.get(n)
        assert t is not None
        out.append(
            ToolDefinition(name=t.name, description=t.description, parameters=t.parameters_schema())
        )
    return out


def _start() -> list[ChatMessage]:
    return [
        ChatMessage(role="system", content="You review a DDI install."),
        ChatMessage(role="user", content="Evidence: none."),
    ]


async def test_headless_runs_tools_as_the_given_user_and_returns_the_answer(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = await _user(db_session, permissions=[{"action": "read", "resource_type": "ip_space"}])
    provider = await _provider(db_session, "local")
    db_session.add(IPSpace(name="headless-space", description=""))
    await db_session.commit()
    llm = install(
        monkeypatch,
        [call("list_ip_spaces", prompt_tokens=100, completion_tokens=20), say('{"findings": []}')],
    )
    messages = _start()

    out = await run_headless(
        db=db_session,
        user=user,
        messages=messages,
        tools=_defs("list_ip_spaces"),
        chain=[provider],
        model="local-model",
        max_rounds=4,
    )

    assert out.status == "ok"
    assert out.content == '{"findings": []}'
    assert out.rounds == 2
    assert (out.tokens_in, out.tokens_out) == (110, 25)
    assert out.usage_by_model == {"local-model": (110, 25)}
    assert out.provider is provider and out.model == "local-model"
    assert [m["role"] for m in out.transcript] == ["assistant", "tool", "assistant"]
    assert "headless-space" in out.transcript[1]["content"]
    assert out.tool_calls == [
        {"name": "list_ip_spaces", "arguments": "{}", "is_error": False, "duplicate": False}
    ]
    # The caller's list was extended in place and sent back to the model.
    assert [m.role for m in messages] == ["system", "user", "assistant", "tool", "assistant"]
    assert len(llm.requests[1][1].messages) == 4


async def test_headless_refuses_a_tool_outside_the_set_it_was_given(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A superadmin identity, to show the refusal comes from the tool set
    # the loop was handed and not from the caller's permissions.
    user = await _user(db_session, superadmin=True)
    provider = await _provider(db_session, "local")
    install(monkeypatch, [call("list_subnets"), say("{}")])

    out = await run_headless(
        db=db_session,
        user=user,
        messages=_start(),
        tools=_defs("list_ip_spaces"),
        chain=[provider],
        model="m",
        max_rounds=3,
    )

    assert out.status == "ok"
    assert out.tool_calls[0]["is_error"] is True
    assert "disabled by the operator" in out.transcript[1]["content"]


async def test_headless_enforces_the_identitys_permissions_at_dispatch(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = await _user(db_session, permissions=[{"action": "read", "resource_type": "ip_space"}])
    provider = await _provider(db_session, "local")
    install(monkeypatch, [call("list_subnets"), say("{}")])

    out = await run_headless(
        db=db_session,
        user=user,
        messages=_start(),
        tools=_defs("list_ip_spaces", "list_subnets"),  # offered, but not granted
        chain=[provider],
        model="m",
        max_rounds=3,
    )

    assert out.tool_calls[0]["is_error"] is True
    assert "Permission denied for tool 'list_subnets'" in out.transcript[1]["content"]


async def test_headless_nudges_before_the_last_round_and_stops_at_the_cap(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = await _user(db_session, superadmin=True)
    provider = await _provider(db_session, "local")
    llm = install(
        monkeypatch,
        [
            call("list_ip_spaces", {"limit": 1}),
            call("list_ip_spaces", {"limit": 2}),
            call("list_ip_spaces", {"limit": 3}),
        ],
    )

    out = await run_headless(
        db=db_session,
        user=user,
        messages=_start(),
        tools=_defs("list_ip_spaces"),
        chain=[provider],
        model="m",
        max_rounds=3,
        final_round_nudge="Answer now.",
    )

    assert out.status == "round_cap"
    assert out.rounds == 3
    assert len(out.tool_calls) == 2  # the third round's call was not run
    last_request = llm.requests[2][1]
    assert last_request.messages[-1].role == "user"
    assert last_request.messages[-1].content == "Answer now."
    assert last_request.tools  # still declared: the history holds tool results


async def test_headless_stops_at_the_token_cap_before_another_round(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = await _user(db_session, superadmin=True)
    provider = await _provider(db_session, "local")
    llm = install(
        monkeypatch,
        [call("list_ip_spaces", prompt_tokens=900, completion_tokens=200), say("never sent")],
    )

    out = await run_headless(
        db=db_session,
        user=user,
        messages=_start(),
        tools=_defs("list_ip_spaces"),
        chain=[provider],
        model="m",
        max_rounds=5,
        max_tokens=1000,
    )

    assert out.status == "token_cap"
    assert out.tokens_total == 1100
    assert len(llm.requests) == 1


async def test_headless_reports_a_driver_error_and_keeps_to_its_chain(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = await _user(db_session, superadmin=True)
    local = await _provider(db_session, "local", priority=10)
    # Enabled and higher priority, but not in the chain the caller built:
    # a headless caller decides which providers may be used at all.
    await _provider(db_session, "hosted", priority=1)
    llm = install(monkeypatch, [say("", raises=APIConnectionError("down"))])

    out = await run_headless(
        db=db_session,
        user=user,
        messages=_start(),
        tools=[],
        chain=[local],
        model="m",
        max_rounds=2,
    )

    assert out.status == "error"
    assert out.error and "all 1 provider(s) failed" in out.error
    assert [name for name, _ in llm.requests] == ["local"]


async def test_headless_caps_tool_calls_per_round(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests._scripted_llm import Step

    user = await _user(db_session, superadmin=True)
    provider = await _provider(db_session, "local")
    many = Step(tool_calls=[("list_ip_spaces", {"limit": i + 1}) for i in range(5)])
    install(monkeypatch, [many, say("{}")])

    out = await run_headless(
        db=db_session,
        user=user,
        messages=_start(),
        tools=_defs("list_ip_spaces"),
        chain=[provider],
        model="m",
        max_rounds=3,
        max_tool_calls_per_round=2,
    )

    assert out.status == "ok"
    assert len(out.tool_calls) == 2
    assert json.loads(out.transcript[0]["tool_calls"][1]["arguments"]) == {"limit": 2}
    assert len(out.transcript[0]["tool_calls"]) == 2
