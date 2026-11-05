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

import app.tasks.rpki_roa_refresh as task_mod
from app.core.security import create_access_token, hash_password
from app.models.asn import ASN, ASNRpkiRoa
from app.models.audit import AuditLog
from app.models.auth import User
from app.services import rpki_roa

pytestmark = pytest.mark.asyncio

# The shipped floor, read before the autouse fixture lowers it per test.
_SHIPPED_FLOOR = rpki_roa._MIN_INDEX_ENTRIES


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
def _fresh_cache(monkeypatch: pytest.MonkeyPatch):
    # Fixture documents are a few ROAs; the floor tests below raise it.
    monkeypatch.setattr(rpki_roa, "_MIN_INDEX_ENTRIES", 0)
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
        await task_mod._refresh_one_asn(db_session, asn, "ripe", 4, datetime.now(UTC))
    await db_session.flush()
    assert await _roa_count(db_session, asn) == 1


async def test_successful_empty_answer_deletes(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    asn = await _asn_with_roa(db_session)
    doc = {"roas": [{"asn": "AS64999", "prefix": "198.51.100.0/24", "maxLength": 24, "ta": "ripe"}]}
    monkeypatch.setattr(rpki_roa, "_stream_dump", _Mirror(doc))
    summary = await task_mod._refresh_one_asn(db_session, asn, "ripe", 4, datetime.now(UTC))
    await db_session.flush()
    assert summary["removed"] == 1
    assert await _roa_count(db_session, asn) == 0


async def test_sweep_reports_failure_and_keeps_roas(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from contextlib import asynccontextmanager

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
    audit = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "rpki-roa-refresh")))
        .scalars()
        .all()
    )
    assert [a.result for a in audit] == ["error"]
    assert "404" in audit[0].new_value["error"]


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


def _doc(n: int, asn: int = 64999) -> dict:
    return {
        "roas": [
            {"asn": f"AS{asn}", "prefix": f"10.{i // 256}.{i % 256}.0/24", "maxLength": 24}
            for i in range(n)
        ]
    }


@pytest.mark.parametrize("doc", [{"roas": []}, _doc(3)], ids=["empty", "short"])
async def test_a_200_far_smaller_than_a_full_index_keeps_stored_roas(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, doc: dict
) -> None:
    """An upstream outage that still answers 200 (an empty or cut-down
    export) must not read as "nobody has ROAs any more"."""
    monkeypatch.setattr(rpki_roa, "_MIN_INDEX_ENTRIES", 10)
    asn = await _asn_with_roa(db_session)
    monkeypatch.setattr(rpki_roa, "_stream_dump", _Mirror(doc))
    with pytest.raises(rpki_roa.RoaFetchError, match="fewer than the 10"):
        await task_mod._refresh_one_asn(db_session, asn, "cloudflare", 4, datetime.now(UTC))
    await db_session.flush()
    assert await _roa_count(db_session, asn) == 1


async def test_a_full_size_index_without_the_asn_still_deletes(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rpki_roa, "_MIN_INDEX_ENTRIES", 10)
    asn = await _asn_with_roa(db_session)
    monkeypatch.setattr(rpki_roa, "_stream_dump", _Mirror(_doc(10)))
    summary = await task_mod._refresh_one_asn(db_session, asn, "cloudflare", 4, datetime.now(UTC))
    assert summary["removed"] == 1


async def test_the_floor_sits_well_under_a_real_index() -> None:
    # Both sources carried ~1.03M ROAs on 2026-11-05; the floor must leave
    # room for churn and still catch a cut-down export.
    assert 10_000 <= _SHIPPED_FLOOR <= 200_000


@pytest.mark.parametrize(
    ("source", "valid_to", "known"),
    [
        ("ripe", None, 0),  # RIPE's export: no lifetime
        ("cloudflare", datetime(2030, 1, 1, tzinfo=UTC), 0),  # a cache expiry, not a lifetime
        ("ripe", datetime(2030, 1, 1, tzinfo=UTC), 1),  # a real notAfter
    ],
    ids=["ripe-no-window", "cloudflare-cache-expiry", "ripe-notafter"],
)
async def test_dashboard_says_whether_roa_expiry_is_measured(
    client: AsyncClient,
    db_session: AsyncSession,
    source: str,
    valid_to: datetime | None,
    known: int,
) -> None:
    from app.models.settings import PlatformSettings

    ps = await db_session.get(PlatformSettings, 1)
    if ps is None:
        ps = PlatformSettings(id=1)
        db_session.add(ps)
    ps.rpki_roa_source = source
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(user)
    asn = await _asn_with_roa(db_session)
    roa = (
        await db_session.execute(select(ASNRpkiRoa).where(ASNRpkiRoa.asn_id == asn.id))
    ).scalar_one()
    roa.valid_to = valid_to
    await db_session.commit()
    h = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    r = await client.get("/api/v1/dashboards/network/summary", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["rpki_total_count"] == 1
    assert body["rpki_expiry_known_count"] == known
