"""A server row deleted while its agent's request is in flight (#1936).

``DELETE /dns/groups/{g}/servers/{id}`` (and the DHCP twin) wakes the server's
channel and then deletes the row. The agent's open long-poll wakes and
refreshes a row that no longer exists, and SQLAlchemy raises
``InvalidRequestError: Could not refresh instance`` -- an unhandled 500.

The agent's auth dependency already answers 404 for a token whose server row is
not there, and 404 is what makes an agent discard its JWT and re-bootstrap from
its PSK (CLAUDE.md, "Agent bootstrap + reconnection"). The agent drops only the
token: its cached config and its daemon keep running (non-negotiable #5). A row
that vanishes mid-request is the same fact, so it gets the same answer.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from sqlalchemy import inspect, select
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.ext.asyncio import AsyncSession


async def refresh_agent_server(db: AsyncSession, server: Any) -> None:
    """``db.refresh(server)``, with a vanished row answered as 404.

    Whether the row is gone is decided by looking for it, not by matching the
    exception's message: ``refresh`` raises ``InvalidRequestError`` for a
    missing row (``ObjectDeletedError`` is a subclass), but that class also
    covers our own mistakes, and its wording is not a contract. So the error is
    re-raised unless a fresh ``SELECT`` confirms the row is not there.
    """
    try:
        await db.refresh(server)
    except InvalidRequestError as exc:
        identity = inspect(server).identity
        if identity is None:
            raise
        model = type(server)
        still_there = await db.scalar(select(model.id).where(model.id == identity[0]))
        if still_there is not None:
            raise
        raise HTTPException(status_code=404, detail="Server not found") from exc
