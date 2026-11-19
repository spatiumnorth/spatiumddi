"""Per-entity SAVEPOINT for the one-shot importers (#2816).

An importer that writes entity by entity must not answer a failed entity with
``db.rollback()``: that expires every loaded object, the signed-in user among
them, and the next access (the next entity's audit row, the route's log line)
is lazy IO outside the greenlet, a 500 after the earlier entities committed.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession


@asynccontextmanager
async def entity_savepoint(db: AsyncSession) -> AsyncIterator[None]:
    """One entity's write as a real SAVEPOINT.

    A failure undoes only this entity; ``db.rollback()`` would expire every
    loaded object, the signed-in user included (#2816). The committers end
    with ``db.commit()``, which closes the savepoint with the transaction;
    a path that wrote nothing (skip) ends it here.
    """
    sp = await db.begin_nested()
    try:
        yield
    except BaseException:
        # A failed flush has already rolled the savepoint back and left it
        # deactivated, which ``is_active`` reports as False; ``rollback()`` on
        # it is what releases the session, and is a no-op once it is closed.
        # Never ``db.rollback()`` here: that expires every loaded object.
        await sp.rollback()
        raise
    if sp.is_active:
        await sp.commit()
