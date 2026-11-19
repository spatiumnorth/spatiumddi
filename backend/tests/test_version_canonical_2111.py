"""One spelling of a nightly's version (#2111) and the stale agent note (#2112)."""

from __future__ import annotations

import importlib.util
import uuid
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.versions import canonical_version, nightly_build_date, parse_release
from app.models.dns import DNSServer, DNSServerGroup

from ._signed_in import signed_in_headers

STAMP = "0.0.0-nightly-20261012+abc1234"


def test_bare_nightly_tag_takes_the_build_stamp() -> None:
    assert canonical_version("nightly-20261012", STAMP) == STAMP


def test_bare_nightly_tag_without_a_stamp_is_still_the_semver_form() -> None:
    out = canonical_version("nightly-20261012", None)
    assert out == "0.0.0-nightly-20261012"
    assert nightly_build_date(out) is not None


def test_a_stamp_from_another_night_is_not_borrowed() -> None:
    assert canonical_version("nightly-20261013", STAMP) == "0.0.0-nightly-20261013"


@pytest.mark.parametrize("v", ["2026.09.04-1", "1.0.0", "dev", "", STAMP, "nightly-2026.10.12"])
def test_everything_else_is_unchanged(v: str) -> None:
    assert canonical_version(v, STAMP) == v
    assert parse_release(v) == parse_release(canonical_version(v, STAMP))


@pytest.mark.asyncio
async def test_version_endpoint_reports_the_agents_spelling(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "version", "nightly-20261012")
    monkeypatch.setattr(settings, "app_version", STAMP)
    # The version is for signed-in callers only (#2935).
    resp = await client.get("/api/v1/version", headers=await signed_in_headers(db_session))
    assert resp.status_code == 200
    assert resp.json()["version"] == STAMP


@pytest.mark.asyncio
async def test_version_endpoint_leaves_a_release_alone(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "version", "2026.09.04-1")
    monkeypatch.setattr(settings, "app_version", "")
    resp = await client.get("/api/v1/version", headers=await signed_in_headers(db_session))
    assert resp.json()["version"] == "2026.09.04-1"


def _migration_sql():
    path = (
        Path(__file__).parent.parent / "alembic/versions/d3a7f19c52e8_clear_stale_dns_agent_note.py"
    )
    spec = importlib.util.spec_from_file_location("mig_2112", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.CLEAR_STALE_NOTE_SQL


@pytest.mark.asyncio
async def test_migration_clears_only_the_stale_literal(db_session: AsyncSession) -> None:
    g = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(g)
    await db_session.flush()
    notes = {
        "stale": "agent v2026.04.14.1",
        "operator": "rack 4, ask Dana",
        "real": "agent v2026.10.02-1",
        "mixed": "agent v2026.04.14.1 (moved)",
    }
    ids = {}
    for k, n in notes.items():
        s = DNSServer(group_id=g.id, name=k, driver="bind9", host=k, port=53, notes=n)
        db_session.add(s)
        await db_session.flush()
        ids[k] = s.id
    await db_session.execute(_migration_sql())
    db_session.expire_all()
    for k, n in notes.items():
        row = (
            await db_session.execute(select(DNSServer).where(DNSServer.id == ids[k]))
        ).scalar_one()
        assert row.notes == ("" if k == "stale" else n), k
