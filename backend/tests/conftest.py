"""Pytest fixtures for integration tests.

Tests run against a real PostgreSQL instance (not mocks) to catch
ORM/query issues early. Set TEST_DATABASE_URL in the environment or
docker-compose.test.yml.

Parallel execution via ``pytest -n auto`` (pytest-xdist) is supported:
each xdist worker carves its own throwaway database off the same Postgres
instance — ``spatiumddi_test_gw0``, ``spatiumddi_test_gw1``, … — so the
session-scoped ``DROP SCHEMA`` + per-test ``TRUNCATE`` can't step on
another worker's data. The non-xdist case (``pytest`` with no ``-n``)
falls through to the unsuffixed base database name, matching pre-xdist
behaviour exactly.
"""

import os
from collections.abc import AsyncGenerator, Iterator
from urllib.parse import urlsplit, urlunsplit

# IMPORTANT: the per-worker DATABASE_URL override below MUST run before any
# ``app.*`` import — ``app.config.settings`` reads ``DATABASE_URL`` from the
# environment at module-load time, and ``app.db.task_session()`` (used by
# Celery-task tests like the lease-cleanup + reservation-sweep + soft-delete
# purge sweeps) builds throwaway engines against ``settings.database_url``.
# Without this override, those tasks would query the base ``spatiumddi_test``
# database while the test fixtures wrote into ``spatiumddi_test_gw<N>``, and
# the sweeps would find an empty table and the tests would fail.


def _worker_id() -> str:
    """Return the pytest-xdist worker id, or '' when running single-process.

    xdist exposes ``PYTEST_XDIST_WORKER`` per worker process (``gw0``,
    ``gw1``, …); the controller process never sees it. Empty string means
    fall back to the base database name so plain ``pytest`` keeps working.
    """
    return os.getenv("PYTEST_XDIST_WORKER", "")


def _per_worker_url(base_url: str, worker: str) -> str:
    """Append the worker suffix to the database name segment of ``base_url``.

    ``postgresql+asyncpg://u:p@host/spatiumddi_test`` →
    ``postgresql+asyncpg://u:p@host/spatiumddi_test_gw0``.
    """
    if not worker:
        return base_url
    split = urlsplit(base_url)
    new_path = f"{split.path}_{worker}"
    return urlunsplit(split._replace(path=new_path))


def _maintenance_url(base_url: str) -> str:
    """URL for the ``postgres`` maintenance DB — used to CREATE / DROP per-worker DBs.

    ``CREATE DATABASE`` can't run inside the target database, so we
    connect to ``postgres`` (the default maintenance DB present on every
    PG cluster) to issue it.
    """
    split = urlsplit(base_url)
    # asyncpg doesn't understand the SQLAlchemy '+asyncpg' driver suffix —
    # strip it for the raw connection.
    scheme = split.scheme.replace("postgresql+asyncpg", "postgresql")
    return urlunsplit(split._replace(scheme=scheme, path="/postgres"))


def _extract_dbname(url: str) -> str:
    return urlsplit(url).path.lstrip("/")


_BASE_TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://spatiumddi:changeme@localhost:5432/spatiumddi_test",
)
_WORKER = _worker_id()
_TEST_DATABASE_URL = _per_worker_url(_BASE_TEST_DATABASE_URL, _WORKER)

# Force the app's own ``DATABASE_URL`` to point at the per-worker test DB
# *before* the first ``app.*`` import below, so module-level engines (and
# Celery ``task_session`` engines built later) land in the right database.
# In single-process mode this is a no-op rewrite to the same URL CI already
# set; in xdist mode it swaps to the worker-suffixed name.
os.environ["DATABASE_URL"] = _TEST_DATABASE_URL

import asyncpg  # noqa: E402  — must follow the DATABASE_URL override above
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool  # noqa: E402

from app.db import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models.base import Base  # noqa: E402

# NullPool: open a fresh asyncpg connection on every checkout and drop it on
# release. The default QueuePool keeps connections bound to the loop they
# were opened on, which collides with pytest-asyncio's per-test loops and
# produces "another operation in progress" / "attached to a different loop"
# errors. This is the cheap, safe fix; tests are I/O-bound on Postgres
# anyway so pool reuse buys nothing here.
_test_engine = create_async_engine(_TEST_DATABASE_URL, echo=False, poolclass=NullPool)
_TestSessionLocal = async_sessionmaker(_test_engine, class_=AsyncSession, expire_on_commit=False)


async def _ensure_worker_database() -> None:
    """Create the per-worker test database if it doesn't already exist.

    No-op when not running under xdist (worker id empty) — the base DB
    is provisioned by CI / docker-compose for the single-process case.
    Idempotent: subsequent test runs reuse the existing per-worker DB
    and the session-scoped schema fixture wipes it clean.
    """
    if not _WORKER:
        return
    dbname = _extract_dbname(_TEST_DATABASE_URL)
    conn = await asyncpg.connect(_maintenance_url(_BASE_TEST_DATABASE_URL))
    try:
        exists = await conn.fetchval("SELECT 1 FROM pg_database WHERE datname = $1", dbname)
        if not exists:
            # asyncpg can't parameterise identifiers; the worker id pattern
            # is r"gw\d+" so injection isn't reachable here.
            await conn.execute(f'CREATE DATABASE "{dbname}"')
    finally:
        await conn.close()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def create_test_schema() -> AsyncGenerator[None, None]:
    await _ensure_worker_database()
    # Tear down any prior schema with CASCADE so circular FKs don't block the
    # drop (dns_record ↔ ip_address has a cycle that Base.metadata.drop_all
    # can't untangle). Easiest is to nuke the public schema wholesale.
    async with _test_engine.begin() as conn:
        await conn.execute(text("DROP SCHEMA public CASCADE"))
        await conn.execute(text("CREATE SCHEMA public"))
        await conn.run_sync(Base.metadata.create_all)
    yield
    # No session-teardown drop. The setup above already wipes any prior
    # schema, so a teardown ``DROP SCHEMA … CASCADE`` is purely cosmetic —
    # and as the schema grew it became a liability: all xdist workers finish
    # ~together, so their simultaneous CASCADE drops (one AccessExclusiveLock
    # per table/index/FK/sequence) exhausted the shared lock table on the CI
    # Postgres ("out of shared memory / increase max_locks_per_transaction").
    # CI DBs are ephemeral; local runs are cleaned by the next run's setup.


@pytest_asyncio.fixture(autouse=True)
async def _reset_global_caches() -> AsyncGenerator[None, None]:
    """Reset the process-global short-TTL caches around every test.

    System maintenance mode (``app.core.maintenance_mode``), feature-
    module enablement (``app.services.feature_modules``), the effective
    TLD registry and the cluster-DNS probe verdict are all cached at
    module level, keyed on a monotonic clock — NOT on the per-test DB. So
    a test that flips maintenance mode on, or a feature module off, leaks
    that state into later tests on the same xdist worker for up to the
    cache TTL, regardless of the per-test TRUNCATE. That surfaced as flaky
    503 / 404s once the suite was sharded across workers (#435): e.g. a
    leaked maintenance-on cache 503'd an unrelated multicast POST whose
    flush-but-not-committed superadmin the middleware's bypass session
    couldn't see. Individual suites used to opt in to a local reset
    fixture; doing it globally fixes the whole class.
    """
    from app.core import maintenance_mode
    from app.services import feature_modules
    from app.services.appliance import cluster_health
    from app.services.dns import tld_registry

    maintenance_mode.invalidate_cache()
    feature_modules.invalidate_cache()
    # #986 — the effective TLD registry is cached the same way, so a test
    # that stores a snapshot would keep classifying later tests' zones
    # against it after the per-test TRUNCATE removed the row.
    tld_registry.invalidate_effective_cache()
    # #985 — the CoreDNS resolve probe is memoized so the 2 s dashboard
    # stream does not hammer cluster DNS. Keyed on a monotonic clock, so a
    # stubbed verdict outlives the per-test TRUNCATE and would answer for
    # unrelated tests.
    cluster_health.invalidate_probe_cache()
    yield
    maintenance_mode.invalidate_cache()
    feature_modules.invalidate_cache()
    tld_registry.invalidate_effective_cache()
    cluster_health.invalidate_probe_cache()


@pytest.fixture(autouse=True)
def _no_bundle_render_enqueue() -> Iterator[None]:
    """#1111 — DNS writes mark agent bundles dirty and, after commit, publish
    a render request to the Celery broker. The suite has no broker, so the
    publish would fail (harmlessly, but on a thread, per DNS write). Tests of
    the enqueue path monkeypatch the publisher itself."""
    from app.config import settings as _settings

    before = _settings.dns_agent_bundle_enqueue_renders
    _settings.dns_agent_bundle_enqueue_renders = False
    try:
        yield
    finally:
        _settings.dns_agent_bundle_enqueue_renders = before


@pytest.fixture(autouse=True)
def _all_feature_modules_enabled() -> Iterator[None]:
    """Treat every catalog module as default-ENABLED for the suite.

    Which modules ship on is a product decision, revised in #1069 from 37
    of 53 to 14. The test suite must not encode it: a test DB is built by
    ``create_all`` and so carries no ``feature_module`` rows at all, which
    means every module-gated router would answer 404 for whichever set
    happened to be off that release — and the next revision would be
    another sweep through two dozen test files adding enable fixtures.

    So the catalog's DEFAULTS are patched, not the table. A DB row still
    wins over the default, so the tests that deliberately exercise the
    gate keep working unchanged, in both directions:

        db.add(FeatureModule(id="governance.approvals", enabled=False))

    is still a disabled module here. A test that wants a module off must
    say so with a row like that rather than leaning on the shipped
    default — leaning on it is what made the default invisible.

    The shipped values themselves are pinned by
    ``test_feature_module_defaults.py``, which reads the catalog source
    rather than importing it, so this patch cannot mask a wrong default.

    Deliberately does NOT take the ``monkeypatch`` fixture, though that is
    the obvious way to write it. ``monkeypatch`` is function-scoped and
    SHARED with the test, so requesting it from an autouse fixture hoists
    its creation ahead of the DB fixtures — and finalizers run in reverse,
    so it would then undo the test's own patches AFTER the session and
    connection tear down. Tests that stub ``socket.getaddrinfo`` or
    ``asyncpg.connect`` (``test_dns_axfr_helper``, ``test_fix_l5_ssrf``,
    ``test_rewrap_partial_abort``) would then error in teardown, on a
    stub that is theirs and an ordering they never asked to change.
    """
    import dataclasses

    from app.services import feature_modules as fm

    original_modules = fm.MODULES
    original_by_id = fm.MODULES_BY_ID
    patched = tuple(dataclasses.replace(m, default_enabled=True) for m in original_modules)
    fm.MODULES = patched
    # MODULES_BY_ID is derived at import, so patching only MODULES would leave
    # the two disagreeing about default_enabled: the list endpoint reads
    # MODULES, the toggle endpoint reads MODULES_BY_ID.
    fm.MODULES_BY_ID = {m.id: m for m in patched}
    try:
        yield
    finally:
        fm.MODULES = original_modules
        fm.MODULES_BY_ID = original_by_id


@pytest_asyncio.fixture(autouse=True)
async def _isolate_db() -> AsyncGenerator[None, None]:
    """Truncate every table after each test so state doesn't leak.

    ``db_session`` alone isn't enough: HTTP tests go through FastAPI
    handlers that commit via the dependency-overridden session, so
    rolling back the fixture's session doesn't undo the inserts. A
    TRUNCATE … CASCADE on all mapped tables keeps the schema intact
    (much cheaper than drop_all + create_all) and is loop-safe because
    NullPool gives us a fresh connection.
    """
    yield
    tables = ", ".join(f'"{t.name}"' for t in reversed(Base.metadata.sorted_tables))
    if not tables:
        return
    async with _test_engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async with _TestSessionLocal() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """HTTP test client with DB dependency overridden to the test session."""

    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()
