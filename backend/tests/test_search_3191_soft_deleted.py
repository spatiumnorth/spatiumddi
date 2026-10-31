"""Global search must not return soft-deleted rows (#3191)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

import app.models  # noqa: F401  (registers every mapper)
from app.core.security import create_access_token, hash_password
from app.db import _get_soft_delete_models
from app.models.auth import User
from app.models.base import Base, SoftDeleteMixin
from app.models.circuit import Circuit
from app.models.ownership import Provider
from app.services.search.providers import PROVIDERS
from app.services.search.schemas import shape_of

pytestmark = pytest.mark.asyncio


class _Result:
    def all(self) -> list[Any]:
        return []

    def scalars(self) -> _Result:
        return self

    def first(self) -> None:
        return None


class _RecordingSession:
    """Stands in for AsyncSession: records every statement a provider sends."""

    def __init__(self) -> None:
        self.statements: list[Any] = []

    async def execute(self, stmt: Any, *a: Any, **kw: Any) -> _Result:
        self.statements.append(stmt)
        return _Result()


def _soft_delete_mappers() -> list[type]:
    return [
        m.class_
        for m in Base.registry.mappers
        if issubclass(m.class_, SoftDeleteMixin) and hasattr(m.class_, "__tablename__")
    ]


async def test_every_provider_filters_soft_deletable_models() -> None:
    """Structural guard over the provider registry.

    A soft-deletable model is safe in a search query only when the global
    ORM filter in ``app.db`` covers it, or the statement carries its own
    ``deleted_at IS NULL``. Anything else leaks a deleted row into search.
    """
    covered = set(_get_soft_delete_models())
    uncovered = [m for m in _soft_delete_mappers() if m not in covered]
    assert Circuit in uncovered  # the premise: circuits rely on a manual clause
    offenders: list[str] = []
    for provider in PROVIDERS:
        for q in ("x", "10.0.0.1", "10.0.0.0/24", "aa:bb:cc:dd:ee:ff"):
            db = _RecordingSession()
            try:
                await provider.fn(db, shape_of(q), 5)  # type: ignore[arg-type]
            except Exception:  # noqa: BLE001 - a provider that cannot run on the stub is skipped
                continue
            for stmt in db.statements:
                sql = str(stmt.compile())
                for model in uncovered:
                    table = model.__tablename__
                    reads = f"FROM {table}" in sql or f"JOIN {table}" in sql
                    if reads and f"{table}.deleted_at IS NULL" not in sql:
                        offenders.append(f"{provider.type} -> {table}")
    assert not offenders, sorted(set(offenders))


async def test_search_hides_a_deleted_circuit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"a-{tag}",
        email=f"{tag}@t.io",
        display_name="a",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    prov = Provider(name=f"prov-{tag}", kind="carrier")
    db_session.add_all([user, prov])
    await db_session.flush()
    ckt = Circuit(name=f"wan-{tag}", ckt_id=f"CKT-{tag}", provider_id=prov.id)
    db_session.add(ckt)
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}

    for q in (f"wan-{tag}", f"CKT-{tag}"):
        r = await client.get("/api/v1/search", params={"q": q, "types": "circuit"}, headers=hdr)
        assert r.status_code == 200, r.text
        assert [x["id"] for x in r.json()["results"]] == [str(ckt.id)], q

    ckt.deleted_at = datetime.now(UTC)
    await db_session.commit()

    for q in (f"wan-{tag}", f"CKT-{tag}"):
        r = await client.get("/api/v1/search", params={"q": q, "types": "circuit"}, headers=hdr)
        assert r.status_code == 200, r.text
        assert r.json()["results"] == [], q
