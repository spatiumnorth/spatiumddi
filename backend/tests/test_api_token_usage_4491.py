"""API token usage: Redis counting, batch flush, list/usage fields, idle filter (#4491)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import generate_api_token, hash_password
from app.models.auth import APIToken, APITokenUsageDaily, User
from app.services import api_token_usage
from app.services.ai.tools.api_tokens import FindApiTokensArgs, find_api_tokens
from app.tasks import api_token_usage as task


class _Pipe:
    def __init__(self, r: FakeRedis) -> None:
        self.r = r
        self.ops: list[tuple] = []

    def hincrby(self, k, f, n):  # type: ignore[no-untyped-def]
        self.ops.append(("incr", k, f, n))

    def expire(self, k, s):  # type: ignore[no-untyped-def]
        pass

    def hset(self, k, f, v):  # type: ignore[no-untyped-def]
        self.ops.append(("set", k, f, v))

    async def execute(self) -> None:
        for op, k, f, v in self.ops:
            d = self.r.h.setdefault(k, {})
            d[f] = int(d.get(f, 0)) + v if op == "incr" else v


class FakeRedis:
    def __init__(self) -> None:
        self.h: dict[str, dict[str, int | str]] = {}

    def pipeline(self, transaction: bool = False) -> _Pipe:
        return _Pipe(self)

    async def scan_iter(self, match: str):  # type: ignore[no-untyped-def]
        for k in list(self.h):
            if k.startswith(match.rstrip("*")):
                yield k

    async def hgetall(self, k):  # type: ignore[no-untyped-def]
        return dict(self.h.get(k, {}))

    async def hincrby(self, k, f, n):  # type: ignore[no-untyped-def]
        d = self.h.setdefault(k, {})
        d[f] = int(d.get(f, 0)) + n

    async def hdel(self, k, f):  # type: ignore[no-untyped-def]
        self.h.get(k, {}).pop(f, None)


@pytest.fixture
def fake_redis(monkeypatch: pytest.MonkeyPatch) -> FakeRedis:
    r = FakeRedis()
    monkeypatch.setattr(api_token_usage, "_client", r)
    return r


async def _token(db: AsyncSession, last_used: datetime | None, created_days_ago: int = 0):
    owner = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="o",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(owner)
    await db.flush()
    raw, _p, h = generate_api_token()
    t = APIToken(
        name=f"t-{uuid.uuid4().hex[:6]}",
        token_hash=h,
        prefix=raw[:10],
        scope="user",
        scopes=[],
        user_id=owner.id,
        created_by_user_id=owner.id,
        is_active=True,
        last_used_at=last_used,
    )
    db.add(t)
    await db.commit()
    if created_days_ago:
        t.created_at = datetime.now(UTC) - timedelta(days=created_days_ago)
        await db.commit()
    return t, raw, owner


@pytest.mark.asyncio
async def test_call_is_counted_in_redis_not_db(
    client: AsyncClient, db_session: AsyncSession, fake_redis: FakeRedis
) -> None:
    t, raw, _ = await _token(db_session, None)
    for _ in range(3):
        r = await client.get("/api/v1/ipam/spaces", headers={"Authorization": f"Bearer {raw}"})
        assert r.status_code == 200
    key = api_token_usage.calls_key(datetime.now(UTC).date())
    assert fake_redis.h[key][str(t.id)] == 3
    assert fake_redis.h[api_token_usage.LAST_IP_KEY][str(t.id)]
    rows = (await db_session.execute(select(APITokenUsageDaily))).scalars().all()
    assert rows == []


@pytest.mark.asyncio
async def test_flush_folds_counts_and_ip_and_prunes(
    db_session: AsyncSession, fake_redis: FakeRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    t, _raw, _ = await _token(db_session, None)
    tid = t.id
    await api_token_usage.record_call(tid, "203.0.113.7")
    await api_token_usage.record_call(tid, "203.0.113.8")
    old = (datetime.now(UTC) - timedelta(days=120)).date()
    db_session.add(APITokenUsageDaily(token_id=tid, day=old, calls=5))
    await db_session.commit()

    out = await task._flush()
    assert out["calls_folded"] == 2 and out["rows_pruned"] == 1
    # A second run adds nothing: the folded counts were subtracted.
    assert (await task._flush())["calls_folded"] == 0

    db_session.expire_all()
    rows = (await db_session.execute(select(APITokenUsageDaily))).scalars().all()
    assert [(r.day, r.calls) for r in rows] == [(datetime.now(UTC).date(), 2)]
    assert (await db_session.get(APIToken, tid)).last_client_ip == "203.0.113.8"


@pytest.mark.asyncio
async def test_list_usage_and_idle_filter(
    client: AsyncClient, db_session: AsyncSession, fake_redis: FakeRedis
) -> None:
    fresh, raw, owner = await _token(db_session, datetime.now(UTC))
    stale, _r2, _ = await _token(db_session, datetime.now(UTC) - timedelta(days=100))
    never, _r3, _ = await _token(db_session, None, created_days_ago=100)
    new_never, _r4, _ = await _token(db_session, None)
    db_session.add(APITokenUsageDaily(token_id=fresh.id, day=datetime.now(UTC).date(), calls=7))
    fresh.last_client_ip = "198.51.100.4"
    await db_session.commit()
    h = {"Authorization": f"Bearer {raw}"}

    rows = (await client.get("/api/v1/api-tokens", headers=h)).json()
    by_id = {r["id"]: r for r in rows}
    assert by_id[str(fresh.id)]["calls_30d"] >= 7
    assert by_id[str(fresh.id)]["last_client_ip"] == "198.51.100.4"

    idle = (await client.get("/api/v1/api-tokens?idle_days=90", headers=h)).json()
    assert {r["id"] for r in idle} == {str(stale.id), str(never.id)}

    u = (await client.get(f"/api/v1/api-tokens/{fresh.id}/usage?days=7", headers=h)).json()
    assert len(u["days"]) == 7 and u["days"][-1]["calls"] >= 7 and u["total"] >= 7

    tool = await find_api_tokens(db_session, owner, FindApiTokensArgs(idle_days=90))
    assert {t["id"] for t in tool["api_tokens"]} == {str(stale.id), str(never.id)}
    assert all("token_hash" not in t for t in tool["api_tokens"])


@pytest.mark.asyncio
async def test_usage_is_owner_only(
    client: AsyncClient, db_session: AsyncSession, fake_redis: FakeRedis
) -> None:
    mine, raw_mine, owner_mine = await _token(db_session, datetime.now(UTC))
    theirs, _r, owner_theirs = await _token(db_session, datetime.now(UTC))
    owner_mine.is_superadmin = False
    owner_theirs.is_superadmin = False
    await db_session.commit()
    h = {"Authorization": f"Bearer {raw_mine}"}

    assert (await client.get(f"/api/v1/api-tokens/{mine.id}/usage", headers=h)).status_code == 200
    # Another user's token answers 404, not 403, so its existence does not leak.
    assert (await client.get(f"/api/v1/api-tokens/{theirs.id}/usage", headers=h)).status_code == 404
