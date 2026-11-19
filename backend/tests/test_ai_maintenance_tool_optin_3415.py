"""An operator can switch on the Copilot's maintenance-mode tool, and a catalog
save names what it cannot keep (#3415).

``set_maintenance_mode`` shipped ``default_enabled=False`` for the operator to
opt in from Settings → AI → Tool Catalog, but it was registered ``writes=True``,
and the catalog's save, the effective tool set and the chat keep only tools that
do not write. The save dropped it and still answered 200, so its toggle snapped
back off and the page could not say why. It is now
``propose_set_maintenance_mode``: the call stages an ``AIOperationProposal`` and
the operator's Apply is the write, like every other Copilot write. A save that
asks to enable a name it cannot keep is refused with a 422 that names it.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import Iterator

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ai import mcp as mcp_mod
from app.core import maintenance_mode
from app.core.security import create_access_token, hash_password
from app.models.ai import AIOperationProposal
from app.models.audit import AuditLog
from app.models.auth import User
from app.services.ai import operations
from app.services.ai.chat import ChatOrchestrator
from app.services.ai.tools import REGISTRY

PROPOSE = "propose_set_maintenance_mode"


@pytest.fixture(autouse=True)
def _reset_cache() -> Iterator[None]:
    maintenance_mode.invalidate_cache()
    yield
    maintenance_mode.invalidate_cache()


async def _user(db: AsyncSession, *, superadmin: bool = True) -> tuple[User, dict[str, str]]:
    u = User(
        username=f"mm-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="Root" if superadmin else "Plain",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    u.groups = []  # mark loaded: is_effective_superadmin walks .groups (#351)
    db.add(u)
    await db.commit()
    return u, {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


def _defaults() -> set[str]:
    return {t.name for t in REGISTRY.all() if t.default_enabled and not t.writes}


async def _save(client: AsyncClient, headers: dict[str, str], *names: str):
    return await client.put(
        "/api/v1/ai/tools/catalog",
        json={"enabled": sorted(_defaults() | set(names))},
        headers=headers,
    )


async def _enable(client: AsyncClient, headers: dict[str, str], *names: str) -> dict:
    r = await _save(client, headers, *names)
    assert r.status_code == 200, r.text
    return r.json()


async def _state(db: AsyncSession) -> tuple[bool, str, object]:
    # The API shares this session (the ``client`` fixture), so an Apply's
    # commit is visible here; only the middleware's cache needs dropping.
    maintenance_mode.invalidate_cache()
    return await maintenance_mode.get_maintenance_state(db)


async def _stage(db: AsyncSession, user: User, args: dict) -> dict:
    """Call the tool the way the chat does: gated by the tool list it sends
    the model (``ChatOrchestrator.stream_turn``)."""
    effective = {t.name for t in await ChatOrchestrator(db, user)._tools_for_request()}
    return await REGISTRY.call(PROPOSE, args, db=db, user=user, effective=effective)


async def _audit(db: AsyncSession, action: str) -> list[AuditLog]:
    stmt = select(AuditLog).where(AuditLog.action == action)
    return list((await db.execute(stmt)).scalars().all())


async def test_catalog_save_keeps_the_enabled_maintenance_tool(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tool = REGISTRY.get(PROPOSE)
    assert tool is not None, f"{PROPOSE} is not registered"
    assert tool.default_enabled is False
    _, h = await _user(db_session)

    body = await _enable(client, h, PROPOSE)

    assert PROPOSE in body["platform_override"]
    (entry,) = [t for t in body["tools"] if t["name"] == PROPOSE]
    assert entry["enabled"] is True
    # Read back, as the Tool Catalog page does after the save.
    again = (await client.get("/api/v1/ai/tools", headers=h)).json()
    (entry,) = [t for t in again["tools"] if t["name"] == PROPOSE]
    assert entry["enabled"] is True


async def test_enabled_maintenance_tool_reaches_the_chat(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, h = await _user(db_session)
    chat = ChatOrchestrator(db_session, user)
    assert PROPOSE not in {t.name for t in await chat._tools_for_request()}  # default off

    await _enable(client, h, PROPOSE)

    assert PROPOSE in {t.name for t in await chat._tools_for_request()}


async def test_mcp_never_offers_the_maintenance_tool(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _user(db_session)
    await _enable(client, h, PROPOSE)

    names = await mcp_mod._mcp_tool_names(db_session, token_scopes=[])
    assert PROPOSE not in names
    assert "set_maintenance_mode" not in names


async def test_the_call_only_stages_a_proposal_and_apply_is_the_write(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, h = await _user(db_session)
    await _enable(client, h, PROPOSE)

    result = await _stage(db_session, user, {"enabled": True, "message": "ai window"})

    assert result.get("kind") == "proposal", result
    proposal_id = uuid.UUID(result["proposal_id"])
    proposal = await db_session.get(AIOperationProposal, proposal_id)
    assert proposal is not None
    assert proposal.operation == "set_maintenance_mode"
    assert proposal.applied_at is None
    # Nothing written until the operator applies it.
    assert (await _state(db_session))[0] is False
    assert await _audit(db_session, "maintenance_mode.enabled") == []

    r = await client.post(f"/api/v1/ai/proposals/{proposal_id}/apply", headers=h, json={})

    assert r.status_code == 200 and r.json()["ok"] is True, r.text
    enabled, message, started_at = await _state(db_session)
    assert (enabled, message) == (True, "ai window")
    assert started_at is not None
    (row,) = await _audit(db_session, "maintenance_mode.enabled")
    assert row.resource_id == "maintenance"
    assert row.new_value["via"] == "ai_proposal"

    # And off again the same way; the window's start is cleared.
    result = await _stage(db_session, user, {"enabled": False})
    assert result.get("kind") == "proposal", result
    r = await client.post(f"/api/v1/ai/proposals/{result['proposal_id']}/apply", headers=h, json={})
    assert r.status_code == 200 and r.json()["ok"] is True, r.text
    enabled, _, started_at = await _state(db_session)
    assert enabled is False and started_at is None
    assert len(await _audit(db_session, "maintenance_mode.disabled")) == 1


async def test_a_non_superadmin_can_neither_reach_nor_apply_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tool = REGISTRY.get(PROPOSE)
    assert tool is not None, f"{PROPOSE} is not registered"
    plain, plain_h = await _user(db_session, superadmin=False)
    _, h = await _user(db_session)
    await _enable(client, h, PROPOSE)

    # Not in the tool list a plain user's chat sends the model.
    assert REGISTRY.callable_by(plain, [tool]) == []
    # A proposal row in their name is refused at apply, before anything runs.
    row = AIOperationProposal(
        session_id=None,
        user_id=plain.id,
        operation="set_maintenance_mode",
        args={"enabled": True},
        preview_text="p",
        expires_at=operations.expires_at_default(),
    )
    db_session.add(row)
    await db_session.commit()

    r = await client.post(f"/api/v1/ai/proposals/{row.id}/apply", headers=plain_h, json={})

    assert r.status_code == 403, r.text
    assert (await _state(db_session))[0] is False
    assert await _audit(db_session, "maintenance_mode.enabled") == []


@pytest.mark.parametrize("name", ["no_such_tool_3415", "set_maintenance_mode"])
async def test_catalog_save_refuses_a_name_it_does_not_know(
    client: AsyncClient, db_session: AsyncSession, name: str
) -> None:
    _, h = await _user(db_session)
    before = (await client.get("/api/v1/ai/tools", headers=h)).json()["platform_override"]

    r = await _save(client, h, name)

    assert r.status_code == 422, f"{r.status_code} {r.text}"
    assert name in r.json()["detail"]
    # Nothing stored, nothing audited.
    after = (await client.get("/api/v1/ai/tools", headers=h)).json()["platform_override"]
    assert after == before
    stmt = select(AuditLog).where(AuditLog.resource_id == "ai_tools_catalog")
    assert (await db_session.execute(stmt)).scalars().all() == []


async def test_catalog_save_refuses_a_tool_that_writes(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tool registered ``writes=True`` is never offered to the model, so the
    save says so instead of dropping it. A stand-in, so the test does not
    depend on which shipped tools write."""
    base = REGISTRY.get("maintenance_status")
    assert base is not None
    stand_in = dataclasses.replace(base, name="zz_writes_stand_in_3415", writes=True)
    monkeypatch.setitem(REGISTRY._tools, stand_in.name, stand_in)
    _, h = await _user(db_session)

    r = await _save(client, h, stand_in.name)

    assert r.status_code == 422, f"{r.status_code} {r.text}"
    assert stand_in.name in r.json()["detail"]
    assert "writes" in r.json()["detail"]
