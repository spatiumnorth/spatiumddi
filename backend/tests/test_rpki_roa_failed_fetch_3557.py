"""A failed ROA fetch must never wipe stored ROAs (spatiumddi#3557).

RIPE retired the validator URL the ``ripe`` source pointed at and it began
answering 404. The fetch layer returned "no ROAs" for any failure, so the
reconcile deleted every stored ROA of the AS and reported success.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.asn import ASN, ASNRpkiRoa
from app.models.auth import User
from app.services import rpki_roa
from app.tasks.rpki_roa_refresh import _refresh_one_asn

pytestmark = pytest.mark.asyncio


class _Mirror:
    def __init__(self, doc: dict | None, *, fail: str | None = None):
        self.body = json.dumps(doc).encode() if doc is not None else b""
        self.fail = fail

    async def __call__(self, url: str) -> AsyncIterator[bytes]:
        if self.fail == "transport":
            raise httpx.ConnectError("mirror down")
        if self.fail == "status":
            raise ValueError("http 404")
        yield self.body


@pytest.fixture(autouse=True)
def _fresh_cache():
    rpki_roa._clear_cache_for_test()
    yield
    rpki_roa._clear_cache_for_test()


async def _asn_with_roa(db: AsyncSession, number: int = 64496) -> ASN:
    asn = ASN(number=number, name=f"AS{number}", kind="public", registry="arin")
    db.add(asn)
    await db.flush()
    db.add(
        ASNRpkiRoa(
            asn_id=asn.id,
            prefix="192.0.2.0/24",
            max_length=24,
            trust_anchor="arin",
            state="valid",
        )
    )
    await db.flush()
    return asn


async def _roa_count(db: AsyncSession, asn: ASN) -> int:
    rows = (await db.execute(select(ASNRpkiRoa).where(ASNRpkiRoa.asn_id == asn.id))).scalars()
    return len(rows.all())


@pytest.mark.parametrize("fail", ["status", "transport"])
async def test_failed_fetch_keeps_stored_roas_and_raises(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, fail: str
) -> None:
    asn = await _asn_with_roa(db_session)
    monkeypatch.setattr(rpki_roa, "_stream_dump", _Mirror(None, fail=fail))
    with pytest.raises(rpki_roa.RoaFetchError):
        await _refresh_one_asn(db_session, asn, "ripe", 4, datetime.now(UTC))
    await db_session.flush()
    assert await _roa_count(db_session, asn) == 1


async def test_successful_empty_answer_deletes(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    asn = await _asn_with_roa(db_session)
    doc = {"roas": [{"asn": "AS64999", "prefix": "198.51.100.0/24", "maxLength": 24, "ta": "ripe"}]}
    monkeypatch.setattr(rpki_roa, "_stream_dump", _Mirror(doc))
    summary = await _refresh_one_asn(db_session, asn, "ripe", 4, datetime.now(UTC))
    await db_session.flush()
    assert summary["removed"] == 1
    assert await _roa_count(db_session, asn) == 0


async def test_sweep_reports_failure_and_keeps_roas(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from contextlib import asynccontextmanager

    import app.tasks.rpki_roa_refresh as task_mod

    asn = await _asn_with_roa(db_session)
    await db_session.commit()

    @asynccontextmanager
    async def _ts():
        yield db_session

    monkeypatch.setattr(task_mod, "task_session", _ts)
    monkeypatch.setattr(rpki_roa, "_stream_dump", _Mirror(None, fail="status"))
    result = await task_mod._run_refresh()
    assert result["status"] == "failed"
    assert "404" in result["error"]
    assert result["errors"] >= 1
    assert result["removed"] == 0
    assert await _roa_count(db_session, asn) == 1


async def test_refresh_route_answers_502_and_keeps_roas(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(user)
    asn = await _asn_with_roa(db_session)
    await db_session.commit()
    h = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    monkeypatch.setattr(rpki_roa, "_stream_dump", _Mirror(None, fail="status"))
    r = await client.post(f"/api/v1/asns/{asn.id}/refresh-rpki", headers=h)
    assert r.status_code == 502, r.text
    assert "404" in r.json()["detail"]
    assert await _roa_count(db_session, asn) == 1
