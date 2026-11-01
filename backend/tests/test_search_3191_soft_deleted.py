"""Global search must not return soft-deleted rows (#3191)."""

from __future__ import annotations

import importlib
import re
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select, true
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.core.security import create_access_token, hash_password
from app.db import _get_soft_delete_models
from app.models.auth import User
from app.models.base import Base, SoftDeleteMixin
from app.models.circuit import Circuit
from app.models.ownership import Provider, Site
from app.services.search.providers import PROVIDERS
from app.services.search.schemas import shape_of

# Import for side effect: registers every mapper. importlib keeps it from
# binding an unused ``app`` name in this module.
importlib.import_module("app.models")

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


def _uncovered_models() -> list[type]:
    """Soft-deletable models the global ORM filter in ``app.db`` does not
    cover: every read of one of these must carry its own clause."""
    covered = set(_get_soft_delete_models())
    return [m for m in _soft_delete_mappers() if m not in covered]


def _unfiltered_reads(sql: str, tables: list[str]) -> list[str]:
    """Tables in ``tables`` that ``sql`` reads (FROM or JOIN, aliased or not)
    without a ``<table or alias>.deleted_at IS NULL`` clause anywhere."""
    leaks: list[str] = []
    for table in tables:
        for m in re.finditer(rf"(?:FROM|JOIN) {table}\b(?: AS (\w+))?", sql):
            name = m.group(1) or table
            if f"{name}.deleted_at IS NULL" not in sql:
                leaks.append(table)
    return leaks


async def test_unfiltered_read_detector_flags_a_bare_read() -> None:
    """Negative control for the guard below: for every uncovered model, a
    bare read, an aliased read and a join are flagged, a filtered one is
    not. Empty (and so trivially green) once every soft-deletable model is
    in the global filter set."""
    for model in _uncovered_models():
        table = model.__tablename__
        alias = aliased(model)
        flagged = [
            select(model),
            select(alias),
            select(Provider).join(model, true()),
        ]
        for stmt in flagged:
            assert _unfiltered_reads(str(stmt.compile()), [table]) == [table], (table, str(stmt))
        clean = select(model).where(model.deleted_at.is_(None))
        assert _unfiltered_reads(str(clean.compile()), [table]) == [], table


async def test_every_provider_filters_soft_deletable_models() -> None:
    """Structural guard over the provider registry.

    A soft-deletable model is safe in a search query only when the global
    ORM filter in ``app.db`` covers it, or the statement carries its own
    ``deleted_at IS NULL``. Anything else leaks a deleted row into search.
    Every provider must run against the recording stub: one that cannot
    is a failure here, not a silent skip, so the guard never goes vacuous.
    """
    tables = [m.__tablename__ for m in _uncovered_models()]
    offenders: list[str] = []
    for provider in PROVIDERS:
        sent = 0
        for q in ("x", "10.0.0.1", "10.0.0.0/24", "aa:bb:cc:dd:ee:ff"):
            db = _RecordingSession()
            await provider.fn(db, shape_of(q), 5)  # type: ignore[arg-type]
            sent += len(db.statements)
            for stmt in db.statements:
                for table in _unfiltered_reads(str(stmt.compile()), tables):
                    offenders.append(f"{provider.type} -> {table}")
        assert sent, f"provider {provider.type} sent no statement to the stub"
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


async def test_overlay_paths_ignore_a_deleted_circuit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The overlay site's preferred-circuit check and the simulation's name
    lookup read Circuit by id, so they need the live-only clause too."""
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"o-{tag}",
        email=f"o{tag}@t.io",
        display_name="o",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    prov = Provider(name=f"oprov-{tag}", kind="carrier")
    s1, s2 = Site(name=f"s1-{tag}"), Site(name=f"s2-{tag}")
    db_session.add_all([user, prov, s1, s2])
    await db_session.flush()
    ckt = Circuit(name=f"ockt-{tag}", provider_id=prov.id)
    db_session.add(ckt)
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}

    r = await client.post("/api/v1/overlays", json={"name": f"ovl-{tag}"}, headers=hdr)
    assert r.status_code == 201, r.text
    ovl = r.json()["id"]
    r = await client.post(
        f"/api/v1/overlays/{ovl}/sites",
        json={"site_id": str(s1.id), "preferred_circuits": [str(ckt.id)]},
        headers=hdr,
    )
    assert r.status_code == 201, r.text

    async def _primary_name() -> str | None:
        r = await client.post(f"/api/v1/overlays/{ovl}/simulate", json={}, headers=hdr)
        assert r.status_code == 200, r.text
        (site,) = r.json()["site_resolutions"]
        return site["primary_circuit_name"]

    assert await _primary_name() == ckt.name  # positive control

    r = await client.delete(f"/api/v1/circuits/{ckt.id}", headers=hdr)
    assert r.status_code == 204, r.text

    assert await _primary_name() is None
    r = await client.post(
        f"/api/v1/overlays/{ovl}/sites",
        json={"site_id": str(s2.id), "preferred_circuits": [str(ckt.id)]},
        headers=hdr,
    )
    assert r.status_code == 422, r.text
    assert str(ckt.id) in r.json()["detail"]
