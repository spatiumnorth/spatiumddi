"""Schema-at-head readiness check (#299 phase 1 / #565).

The comparison core lives in ``app.core.schema_check`` (extracted in
#565 so the Celery worker/beat share it); ``app.api.health.
_check_schema_ready`` is a thin ``("ok"|"error", detail)`` wrapper over
``schema_at_head`` folded into ``/health/ready``.

Covers:

* ``alembic_version`` at the bundled head → readiness check says ``ok``.
* ``alembic_version`` table missing → check says ``error`` with the
  asyncpg ``relation does not exist`` short form, readiness response
  is 503 with the schema-specific detail.
* ``alembic_version`` row missing → "alembic_version row missing"
  detail, 503.
* ``version_num`` behind the bundled head → "schema at X, image
  expects Y" detail, 503.
* ``version_num`` a revision this image does not know, i.e. a NEWER
  release migrated the database (#2777): ``ahead``; readiness keeps a
  process that has already been ready at its own head in service
  (the mixed-version window of a rolling upgrade) and refuses it on a
  process that never was; behind and unstamped stay 503 either way; a
  mismatch is logged once per change.

The cached ``_EXPECTED_HEAD`` module global is reset around each test
so a previous test's view of the head doesn't bleed into the next.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from structlog.testing import capture_logs

from app.api import health as health_module
from app.core import schema_check as schema_module
from app.db import AsyncSessionLocal

# A revision no release has: what a NEWER release's migration leaves in
# ``alembic_version`` as far as this image can tell (#2777).
NEWER = "f00dfeed2777"


def _parent_of_head() -> str:
    """The revision just before the bundled head: a schema BEHIND this image."""
    from alembic.config import Config  # noqa: PLC0415
    from alembic.script import ScriptDirectory  # noqa: PLC0415

    ini = schema_module._locate_alembic_ini()
    assert ini is not None
    script = ScriptDirectory.from_config(Config(str(ini)))
    head = script.get_revision(script.get_current_head())
    assert head is not None
    parent = head.down_revision
    if isinstance(parent, tuple):  # a merge revision: each parent is behind it
        parent = parent[0]
    assert isinstance(parent, str), "the bundled head has no parent revision"
    return parent


async def _stamp(revision: str) -> None:
    async with AsyncSessionLocal() as s:
        await s.execute(
            text("UPDATE alembic_version SET version_num = :rev"),
            {"rev": revision},
        )
        await s.commit()


@pytest.fixture(autouse=True)
def _reset_head_cache() -> None:
    """Clear the module-level head cache before every test.

    ``expected_alembic_head`` caches the result of
    ``ScriptDirectory.get_current_head()`` to avoid re-walking the
    versions directory on every probe; the cache survives across
    tests in the same worker without this fixture.
    """
    schema_module._head_cache.head = None
    schema_module._head_cache.error = None


@pytest.fixture(autouse=True)
async def _seed_alembic_version() -> AsyncIterator[None]:
    """Ensure ``alembic_version`` exists + is stamped at the bundled
    head before each test.

    The conftest fast-path uses ``Base.metadata.create_all`` to build
    the test schema (much faster than ``alembic upgrade head`` per
    worker), so the ``alembic_version`` table doesn't naturally
    exist in the per-worker test DB. Without this fixture the new
    schema-aware readiness check would report "schema not initialised"
    against tests whose intent is actually about the schema being AT
    head — that's what production looks like. We seed the table and
    let individual tests mutate it (DELETE row, UPDATE to fake
    revision, etc.) to exercise the failure modes.
    """
    expected, _ = schema_module.expected_alembic_head()
    async with AsyncSessionLocal() as s:
        await s.execute(
            text(
                "CREATE TABLE IF NOT EXISTS alembic_version ("
                "version_num VARCHAR(32) NOT NULL PRIMARY KEY)"
            )
        )
        await s.execute(text("DELETE FROM alembic_version"))
        await s.execute(
            text("INSERT INTO alembic_version (version_num) VALUES (:head)"),
            {"head": expected},
        )
        await s.commit()
    yield
    # Clean up so concurrent tests in other files don't trip on the
    # leftover table (the conftest's TRUNCATE truncates registered
    # tables only — alembic_version isn't in Base.metadata).
    async with AsyncSessionLocal() as s:
        await s.execute(text("DROP TABLE IF EXISTS alembic_version"))
        await s.commit()


@pytest.mark.asyncio
async def test_schema_check_ok_when_at_head() -> None:
    """The check_schema_ready helper returns ok when version_num
    matches the bundled head."""
    expected, err = schema_module.expected_alembic_head()
    assert err is None
    assert expected is not None  # alembic.ini + versions/ are bundled

    # The conftest's per-worker DB is migrated to head, so the live
    # query should return the same revision the script directory
    # reports.
    verdict, detail = await health_module._check_schema_ready()
    assert verdict == "ok", detail
    assert expected in detail


@pytest.mark.asyncio
async def test_schema_check_reports_mismatch() -> None:
    """When alembic_version says a revision behind the head, the check
    returns error + names both versions."""
    expected, _ = schema_module.expected_alembic_head()
    assert expected is not None

    # Mutate alembic_version to the head's parent and assert the helper
    # surfaces both sides of the diff. A real older revision, not a
    # made-up one: since #2777 a revision the image does not know means
    # a NEWER schema, which the tests further down cover.
    old_revision = _parent_of_head()
    await _stamp(old_revision)
    try:
        verdict, detail = await health_module._check_schema_ready()
        assert verdict == "error"
        assert old_revision in detail
        assert expected in detail
    finally:
        # Restore so subsequent tests see a clean schema head.
        async with AsyncSessionLocal() as s:
            await s.execute(
                text("UPDATE alembic_version SET version_num = :head"),
                {"head": expected},
            )
            await s.commit()


@pytest.mark.asyncio
async def test_schema_check_reports_missing_row() -> None:
    """alembic_version table exists but is empty — common right after
    a migrate failure or a botched ``alembic stamp``. The helper
    reports the missing row explicitly so operators see the cause."""
    expected, _ = schema_module.expected_alembic_head()
    assert expected is not None

    async with AsyncSessionLocal() as s:
        await s.execute(text("DELETE FROM alembic_version"))
        await s.commit()
    try:
        verdict, detail = await health_module._check_schema_ready()
        assert verdict == "error"
        assert "alembic_version row missing" in detail
    finally:
        async with AsyncSessionLocal() as s:
            await s.execute(
                text("INSERT INTO alembic_version (version_num) VALUES (:head)"),
                {"head": expected},
            )
            await s.commit()


@pytest.mark.asyncio
async def test_schema_check_reports_missing_table() -> None:
    """alembic_version table doesn't exist — migrate Job hasn't run
    yet, which is the cold-boot 502 window from issue #299. We
    simulate by patching ``AsyncSessionLocal`` to a session whose
    SELECT raises an UndefinedTable-shape ProgrammingError (the
    SQLAlchemy wrapper around asyncpg's UndefinedTableError)."""

    class _FakeSession:
        async def __aenter__(self) -> _FakeSession:
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def execute(self, *_args: object, **_kwargs: object) -> None:
            # Mirror the SQLAlchemy → asyncpg shape: ProgrammingError
            # carrying ``relation … does not exist`` as the .orig
            # exception's message. The helper's substring match on
            # "does not exist" is what triggers the "schema not
            # initialised" path; other ProgrammingError shapes fall
            # through to the generic "schema check failed" path
            # (covered separately below).
            raise ProgrammingError(
                "SELECT version_num FROM alembic_version",
                {},
                Exception('relation "alembic_version" does not exist'),
            )

    @asynccontextmanager
    async def _fake_session_factory() -> AsyncIterator[_FakeSession]:
        yield _FakeSession()

    _result = await schema_module.schema_at_head(session_factory=_fake_session_factory)
    verdict, detail = ("ok" if _result.ok else "error"), _result.detail
    assert verdict == "error"
    assert "schema not initialised" in detail
    assert "alembic_version" in detail


@pytest.mark.asyncio
async def test_schema_check_reports_other_programming_error() -> None:
    """ProgrammingError that ISN'T a missing-table case (permission
    denied, syntax error, etc.) gets the generic "schema check
    failed" detail — review polish to stop misdirecting operators
    down the migrate path when the real cause is something else."""

    class _FakeSession:
        async def __aenter__(self) -> _FakeSession:
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def execute(self, *_args: object, **_kwargs: object) -> None:
            raise ProgrammingError(
                "SELECT version_num FROM alembic_version",
                {},
                Exception("permission denied for table alembic_version"),
            )

    @asynccontextmanager
    async def _fake_session_factory() -> AsyncIterator[_FakeSession]:
        yield _FakeSession()

    _result = await schema_module.schema_at_head(session_factory=_fake_session_factory)
    verdict, detail = ("ok" if _result.ok else "error"), _result.detail
    assert verdict == "error"
    # NOT "schema not initialised" — operator needs to see "permission
    # denied" or similar, not be sent down the migrate path.
    assert "schema not initialised" not in detail
    assert "schema check failed" in detail
    assert "permission denied" in detail


@pytest.mark.asyncio
async def test_schema_check_reports_generic_exception() -> None:
    """Non-ProgrammingError exception (asyncio timeout, connection
    blip, …) — also reported as "schema check failed", separate from
    the cold-boot path."""

    class _FakeSession:
        async def __aenter__(self) -> _FakeSession:
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def execute(self, *_args: object, **_kwargs: object) -> None:
            raise TimeoutError("query timed out after 30s")

    @asynccontextmanager
    async def _fake_session_factory() -> AsyncIterator[_FakeSession]:
        yield _FakeSession()

    _result = await schema_module.schema_at_head(session_factory=_fake_session_factory)
    verdict, detail = ("ok" if _result.ok else "error"), _result.detail
    assert verdict == "error"
    assert "schema check failed" in detail
    assert "timed out" in detail


@pytest.mark.asyncio
async def test_readiness_endpoint_503_on_schema_mismatch(client: AsyncClient) -> None:
    """End-to-end: the readiness endpoint folds the schema check into
    its rollup. Postgres is up + Redis is up but schema is behind →
    503 with the schema-specific detail in the ``checks`` block."""
    expected, _ = schema_module.expected_alembic_head()
    assert expected is not None

    pre_migrate = _parent_of_head()
    await _stamp(pre_migrate)
    try:
        response = await client.get("/health/ready")
        assert response.status_code == 503
        body = response.json()
        assert body["status"] == "degraded"
        # DB connect still ok — only the schema check fails.
        assert body["checks"]["database"] == "ok"
        assert pre_migrate in body["checks"]["schema"]
        assert expected in body["checks"]["schema"]
    finally:
        async with AsyncSessionLocal() as s:
            await s.execute(
                text("UPDATE alembic_version SET version_num = :head"),
                {"head": expected},
            )
            await s.commit()


@pytest.mark.asyncio
async def test_readiness_endpoint_200_at_head(client: AsyncClient) -> None:
    """Sanity: when everything's clean (Postgres up, schema at head,
    Redis up), readiness returns 200 with every check ok."""
    response = await client.get("/health/ready")
    body = response.json()
    # Redis may be unavailable in some test environments — only assert
    # the schema check passes (which is what #299 phase 1 changed).
    if body["checks"].get("database") == "ok":
        assert body["checks"].get("schema", "").startswith("ok")


# ── #2777 — a NEWER schema under a pod already in service ───────────
#
# On a rolling upgrade the new release's migration commits while the
# previous release's api pods still serve. Each of them then finds
# ``alembic_version`` at a revision its image does not know. Answering
# 503 for that took every old pod out of the Service before the first
# new pod was ready (~80 s of 502 on a three-node roll).


class _RedisUp:
    async def ping(self) -> bool:
        return True

    async def aclose(self) -> None:
        return None


class _RedisDown:
    async def ping(self) -> bool:
        raise ConnectionError("redis is down")

    async def aclose(self) -> None:
        return None


@pytest.fixture
def redis_up(monkeypatch: pytest.MonkeyPatch) -> None:
    """Readiness's Redis check answers, so its verdict turns on the schema."""
    from app.core import redis_client  # noqa: PLC0415

    monkeypatch.setattr(redis_client, "make_async_redis", lambda *_a, **_k: _RedisUp())


@pytest.fixture
def fresh_api_process() -> None:
    """This process has not been ready at its own head yet: a new pod, a
    restarted container, or an older release rolled back onto a newer
    database. (conftest resets it before every test too; this says so.)"""
    health_module.reset_schema_readiness()


@pytest.mark.asyncio
async def test_schema_check_marks_an_unknown_revision_ahead() -> None:
    """A revision this image's migrations do not contain was written by a
    newer release: ``ahead``, still not ``ok``, the detail unchanged."""
    expected, _ = schema_module.expected_alembic_head()
    await _stamp(NEWER)

    result = await schema_module.schema_at_head()

    assert result.ok is False
    assert result.ahead is True
    assert result.actual == NEWER
    assert result.detail == f"schema at {NEWER}, image expects {expected}"


@pytest.mark.asyncio
async def test_schema_check_marks_a_known_older_revision_behind() -> None:
    """A revision the image knows that is not its head is BEHIND it: with
    one head, every other revision in the tree is an ancestor of it."""
    expected, _ = schema_module.expected_alembic_head()
    parent = _parent_of_head()
    await _stamp(parent)

    result = await schema_module.schema_at_head()

    assert result.ok is False
    assert result.ahead is False
    assert result.detail == f"schema at {parent}, image expects {expected}"


@pytest.mark.asyncio
async def test_ready_pod_keeps_serving_when_a_newer_release_migrates(
    client: AsyncClient, redis_up: None
) -> None:
    """The issue's contract: a pod already ready at its own head stays
    ready when a newer release's migration moves the schema past it."""
    expected, _ = schema_module.expected_alembic_head()
    response = await client.get("/health/ready")
    assert response.status_code == 200, response.json()

    await _stamp(NEWER)
    response = await client.get("/health/ready")

    body = response.json()
    assert response.status_code == 200, body
    assert body["status"] == "ok"
    assert body["checks"]["schema"].startswith("ok: ")
    assert NEWER in body["checks"]["schema"]
    assert expected in body["checks"]["schema"]


@pytest.mark.asyncio
async def test_a_test_starts_as_a_fresh_api_process(client: AsyncClient, redis_up: None) -> None:
    """No test inherits an earlier test's readiness history: conftest's
    ``_reset_global_caches`` resets it around every test. This test follows
    one that leaves the process ready at its head, so without the reset it
    would find that latch on the same worker and answer 200."""
    expected, _ = schema_module.expected_alembic_head()
    await _stamp(NEWER)

    response = await client.get("/health/ready")

    assert response.status_code == 503, response.json()
    assert response.json()["checks"]["schema"] == (
        f"error: schema at {NEWER}, image expects {expected}"
    )


@pytest.mark.asyncio
async def test_fresh_process_on_a_newer_schema_stays_unready(
    client: AsyncClient, redis_up: None, fresh_api_process: None
) -> None:
    """A process that was never ready at its own head must not enter
    service on a schema it does not know (#1227's guard): 503, every time."""
    expected, _ = schema_module.expected_alembic_head()
    await _stamp(NEWER)

    for _ in range(2):
        response = await client.get("/health/ready")
        assert response.status_code == 503
        assert response.json()["checks"]["schema"] == (
            f"error: schema at {NEWER}, image expects {expected}"
        )


@pytest.mark.asyncio
async def test_a_probe_that_fails_on_redis_does_not_latch(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only a probe that answers 200 with the schema at head means the pod
    has been Ready at its own head. One that found the schema at head but
    failed on Redis answered 503, so a newer schema afterwards is refused."""
    from app.core import redis_client  # noqa: PLC0415

    expected, _ = schema_module.expected_alembic_head()
    monkeypatch.setattr(redis_client, "make_async_redis", lambda *_a, **_k: _RedisDown())
    response = await client.get("/health/ready")
    body = response.json()
    assert response.status_code == 503, body
    assert body["checks"]["schema"] == "ok"
    assert body["checks"]["redis"].startswith("error: ")

    monkeypatch.setattr(redis_client, "make_async_redis", lambda *_a, **_k: _RedisUp())
    await _stamp(NEWER)
    response = await client.get("/health/ready")

    assert response.status_code == 503, response.json()
    assert response.json()["checks"]["schema"] == (
        f"error: schema at {NEWER}, image expects {expected}"
    )


@pytest.mark.asyncio
async def test_ready_pod_still_refuses_a_schema_behind_its_head(
    client: AsyncClient, redis_up: None
) -> None:
    """#299 holds after the pod has been ready: behind is 503."""
    expected, _ = schema_module.expected_alembic_head()
    assert (await client.get("/health/ready")).status_code == 200
    parent = _parent_of_head()
    await _stamp(parent)

    response = await client.get("/health/ready")

    assert response.status_code == 503
    assert response.json()["checks"]["schema"] == (
        f"error: schema at {parent}, image expects {expected}"
    )


@pytest.mark.asyncio
async def test_ready_pod_still_refuses_an_unstamped_schema(
    client: AsyncClient, redis_up: None
) -> None:
    """An emptied ``alembic_version`` is 503 after the pod has been ready."""
    assert (await client.get("/health/ready")).status_code == 200
    async with AsyncSessionLocal() as s:
        await s.execute(text("DELETE FROM alembic_version"))
        await s.commit()

    response = await client.get("/health/ready")

    assert response.status_code == 503
    assert "alembic_version row missing" in response.json()["checks"]["schema"]


@pytest.mark.asyncio
async def test_schema_mismatch_is_logged_once_per_change(
    client: AsyncClient, redis_up: None
) -> None:
    """A mismatch logs a warning once per change, never once per probe,
    and the way back to head logs once at info."""
    expected, _ = schema_module.expected_alembic_head()
    parent = _parent_of_head()
    response = await client.get("/health/ready")  # in service at head
    assert response.status_code == 200, response.json()

    with capture_logs() as logs:
        for revision in (NEWER, parent, expected):
            await _stamp(revision)
            await health_module._check_schema_ready()
            await health_module._check_schema_ready()

    mismatches = [e for e in logs if e["event"] == "readiness_schema_mismatch"]
    assert [(e["log_level"], e["actual"], e["ahead"], e["serving"]) for e in mismatches] == [
        ("warning", NEWER, True, True),
        ("warning", parent, False, False),
    ]
    back = [e for e in logs if e["event"] == "readiness_schema_at_head"]
    assert [(e["log_level"], e["expected"]) for e in back] == [("info", expected)]
