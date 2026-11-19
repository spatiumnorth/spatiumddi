import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import structlog
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session, with_loader_criteria

from app.config import settings

_db_logger = structlog.get_logger(__name__)


def _json_serializer(value: Any) -> str:
    """SQLAlchemy JSON/JSONB column serializer.

    Stdlib ``json.dumps`` rejects ``uuid.UUID``, ``datetime``, ``Decimal``,
    ``ipaddress.IP*Network``, and a few other perfectly-serializable-as-text
    types. We stringify any of them via ``default=str`` so audit-log writes
    and other ``JSONB`` columns that capture ``pydantic.model_dump()``
    output don't 500 when the caller forgets to coerce. Loses some type
    round-tripping on read, but the DB-side representation is JSON text
    anyway — callers that need types back go through the ORM attribute
    which re-parses strings as needed.
    """
    return json.dumps(value, default=str)


engine = create_async_engine(
    settings.database_url,
    pool_size=settings.database_pool_size,
    max_overflow=settings.database_max_overflow,
    echo=settings.debug,
    json_serializer=_json_serializer,
    # Probe each pooled connection with a ``SELECT 1`` before
    # checkout. The cost is one tiny extra round-trip per request
    # — negligible against a localhost socket — and the benefit is
    # automatic recovery when something kills the underlying
    # connection out from under the pool. Concretely:
    #   * A backup restore (issue #117) calls
    #     ``engine.dispose()`` + ``pg_terminate_backend`` to kick
    #     stragglers; without pre-ping, agents' in-flight long-poll
    #     requests would crash with
    #     ``cannot call PreparedStatement.fetch(): the underlying
    #     connection is closed`` on the next checkout.
    #   * A postgres restart, a network blip, or a long idle period
    #     (some firewalls drop NAT entries after 30 min) would
    #     produce the same symptom without pre-ping; with it, the
    #     pool quietly recycles and the request succeeds.
    pool_pre_ping=True,
    # #590 — pre-ping only helps when a dead connection FAILS FAST
    # (postgres restarted on a live host → RST). A node death is a
    # BLACK HOLE: the peer vanishes mid-connection, nothing answers,
    # and the ping's SELECT 1 waits out the OS TCP retransmission
    # timeout — minutes — while holding the checkout. Every pooled
    # connection that pointed at the dead node poisons requests in
    # turn, /health/ready's database check included, so the api sat
    # NotReady cluster-wide long after CNPG had already promoted a
    # new primary (observed live 2026-07-12: the survivor's readiness
    # still timing out 3+ min into a kill_leader drill while the
    # postgres -rw endpoint was healthy the whole time).
    #
    #   * command_timeout bounds EVERY command on the wire, the
    #     pre-ping included: a black-holed connection now raises in
    #     30 s instead of minutes, SQLAlchemy invalidates it, and the
    #     retry connects fresh — which lands on the NEW primary via
    #     the Service. Ceiling chosen well above any legitimate
    #     single statement in the app path (route handlers are many
    #     small queries; bulk work is chunked; alembic runs on its
    #     own engine and is unaffected).
    #   * timeout bounds the fresh CONNECT during failover, so a
    #     half-open target costs 5 s, not the OS default.
    connect_args={
        "timeout": 5,
        "command_timeout": 30,
    },
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ── Readiness-probe engine (#2944) ─────────────────────────────────────────
#
# /health/ready used to check a connection out of the request pool above. Under
# load (about 90 concurrent bulk writes) that pool is exhausted, the probe's
# checkout queued behind request traffic, blew its 4 s bound and took a busy but
# healthy pod out of the Service. The probe now has ONE connection of its own
# that no request can take, so it waits only on the database. A database that is
# really down still fails it: the connect or the SELECT raises or times out.
#
# ``pool_timeout`` is under the endpoint's 4 s bound so two overlapping probes
# answer "busy" rather than hang. The connection is created lazily for the
# running event loop (an asyncpg connection is bound to its loop) and rebuilt if
# the loop or process changes, as ``services.dispatch_db`` does.

PROBE_POOL_TIMEOUT_S = 3


class _ProbeEngineState:
    engine: Any = None
    loop: Any = None
    pid: int | None = None


_probe_state = _ProbeEngineState()


def probe_engine() -> Any:
    """The readiness probe's private one-connection engine."""
    import asyncio  # noqa: PLC0415
    import os  # noqa: PLC0415

    loop = asyncio.get_running_loop()
    if _probe_state.engine is not None and (
        _probe_state.loop is not loop or _probe_state.pid != os.getpid()
    ):
        _probe_state.engine.sync_engine.dispose(close=False)
        _probe_state.engine = None
    if _probe_state.engine is None:
        _probe_state.engine = create_async_engine(
            settings.database_url,
            pool_size=1,
            max_overflow=0,
            pool_timeout=PROBE_POOL_TIMEOUT_S,
            pool_pre_ping=True,
            echo=False,
            connect_args={"timeout": 5, "command_timeout": 30},
        )
        _probe_state.loop, _probe_state.pid = loop, os.getpid()
    return _probe_state.engine


def ProbeSessionLocal() -> AsyncSession:  # noqa: N802 - sessionmaker-shaped factory
    """A session on the readiness probe's own engine."""
    return AsyncSession(probe_engine(), expire_on_commit=False)


async def dispose_probe_engine() -> None:
    """Close the probe connection. Awaited from the api lifespan shutdown."""
    engine, _probe_state.engine = _probe_state.engine, None
    if engine is not None:
        await engine.dispose()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    # The close is where a failover surfaces AFTER the response has started:
    # its rollback meets ``InterfaceError: cannot call Transaction.rollback():
    # the underlying connection is closed`` or a ``TimeoutError``. Raised from
    # a dependency's cleanup at that point it became "Caught handled
    # exception, but response already started" (#3017), a 500 line for a
    # request that had already answered. Only dependency-down failures are
    # swallowed (and logged); a real bug in the close still propagates, and a
    # route's own exception is never replaced by a swallowed close failure.
    session = AsyncSessionLocal()
    try:
        yield session
    finally:
        try:
            # ``__aexit__`` rather than a bare ``close()``: it runs the close
            # to completion even if this task is cancelled meanwhile (a
            # client gone mid-request), which ``async with`` did here before
            # and a bare ``await session.close()`` would not, abandoning the
            # connection's return to the pool halfway.
            await session.__aexit__(None, None, None)
        except Exception as exc:  # noqa: BLE001 — classified, else re-raised
            from app.core.dependency_down import is_only_dependency_down  # noqa: PLC0415

            if not is_only_dependency_down(exc):
                raise
            _db_logger.warning(
                "db_session_cleanup_dependency_down",
                error_class=type(exc).__name__,
                error=str(exc)[:200],
            )


# ── Per-task DB session for Celery ────────────────────────────────────────
#
# Celery's ``asyncio.run(...)`` pattern spins up a fresh event loop per
# task invocation. The shared ``engine`` / ``AsyncSessionLocal`` above
# bind their asyncpg connections to whichever loop first checked them
# out — re-using them from a later task surfaces as
# ``RuntimeError: Future attached to a different loop``.
#
# Tasks should call this helper instead of importing ``AsyncSessionLocal``
# directly. It builds a throwaway engine + session factory scoped to the
# current call so the connection lifecycle matches the loop lifecycle.
# Cost is one extra TCP handshake per task — acceptable for our task
# cadence (seconds, not milliseconds).


def task_connect_args(command_timeout: float | None = None) -> dict[str, float]:
    """asyncpg ``connect_args`` for every Celery-side engine (#1719).

    ``task_session()`` uses it, and so must every ``create_async_engine`` on
    ``settings.database_url`` in ``app/tasks`` and ``app/services``
    (``tests/test_task_session_timeouts.py`` fails any that omits it).
    """
    return {
        "timeout": settings.task_db_connect_timeout,
        "command_timeout": (
            command_timeout if command_timeout is not None else settings.task_db_command_timeout
        ),
    }


@asynccontextmanager
async def task_sessionmaker(
    *, command_timeout: float | None = None
) -> AsyncGenerator[async_sessionmaker[AsyncSession], None]:
    """Per-Celery-task session factory, for task code that opens several
    sessions in turn (a poll loop) and must not reach for the shared
    ``AsyncSessionLocal``. One throwaway engine bound to the current loop,
    disposed at exit — so N sessions cost one engine, not N (#1687).

    ``command_timeout`` overrides the per-statement bound
    (``settings.task_db_command_timeout``); tasks whose single statements are
    legitimately slow pass ``settings.task_db_long_command_timeout`` (#1719).
    """

    # A task needs exactly one connection; bound the pool to 1 (no
    # overflow) so a burst of N concurrent scheduled tasks opens N
    # connections, not N×(pool_size+max_overflow). The engine is disposed
    # in the finally below, releasing that connection at task end (#15).
    task_engine = create_async_engine(
        settings.database_url,
        future=True,
        json_serializer=_json_serializer,
        pool_size=1,
        max_overflow=0,
        # A long task outlives its connection: the rolling upgrade holds one
        # session across the CNPG switchover it waits for, and the next query
        # after it met "connection is closed" (#1445). Pinging on checkout
        # replaces a dead connection between transactions, as the module
        # engine above already does.
        pool_pre_ping=True,
        # #1719 — the same black-hole bound the module engine carries (#590).
        # Without it a task holding a connection to a primary whose node died
        # sat in epoll_wait for ~15 min (the kernel's TCP retransmit timeout)
        # while its worker completed nothing and the liveness probe passed.
        # The pre-ping is a command too, so this bounds it as well.
        connect_args=task_connect_args(command_timeout),
    )
    try:
        yield async_sessionmaker(task_engine, class_=AsyncSession, expire_on_commit=False)
    finally:
        await task_engine.dispose()


@asynccontextmanager
async def task_session(
    *, command_timeout: float | None = None
) -> AsyncGenerator[AsyncSession, None]:
    """Per-Celery-task DB session — fresh engine, fresh loop binding.

    ``command_timeout`` is passed to :func:`task_sessionmaker`.
    """
    async with task_sessionmaker(command_timeout=command_timeout) as factory:
        async with factory() as session:
            yield session


# ── Global soft-delete filter ──────────────────────────────────────────────
#
# A ``do_orm_execute`` event listener injects ``Model.deleted_at IS NULL``
# into every SELECT touching one of the in-scope models. Callers that
# legitimately need to see soft-deleted rows (Trash list, Restore endpoint,
# the nightly purge sweep, audit / diagnostic tooling) opt in with
# ``execution_options(include_deleted=True)``.
#
# Implementation note: ``with_loader_criteria(include_aliases=True)`` makes
# the criterion apply to every ORM entity the statement names — its columns,
# ``select_from()``, ``.join()`` targets (in the ON clause, so outer joins
# keep their meaning), ``aliased()`` copies, and the same in every ORM
# subquery nested anywhere in it. A table a SELECT reaches only through its
# WHERE clause (``exists().where(Subnet.id == …)``) is not an entity the ORM
# filters, so the hook adds ``deleted_at IS NULL`` to that SELECT's WHERE
# itself (#3492). The hook is mounted on the global ``Session`` class, which
# is where SQLAlchemy fires ORM events from under the AsyncSession wrapper.
#
# NOT covered — write the predicate by hand or don't do this: a Core
# ``Table`` or ``Table.alias()`` used as a JOIN target, ``text()`` /
# ``literal_column()`` SQL, and raw ``connection.execute`` (no ORM event).


def _soft_delete_models() -> tuple[type, ...]:
    """Resolve in-scope models lazily so circular imports don't bite.

    Importing the model modules at module-load time would create a cycle
    (``app.db`` ↔ ``app.models.*`` ↔ ``app.models.audit_forward`` …).
    The hook fires per-execute so the cost of one-time import-and-cache
    is trivial.
    """

    from app.models.dhcp import DHCPPool, DHCPScope, DHCPStaticAssignment
    from app.models.dns import DNSRecord, DNSZone
    from app.models.ipam import IPBlock, IPSpace, Subnet

    return (
        IPSpace,
        IPBlock,
        Subnet,
        DNSZone,
        DNSRecord,
        DHCPScope,
        # Cascade children of DHCPScope (#617). Registering them here is what
        # closes the read leaks: a bare ``select(DHCPStaticAssignment)`` — the
        # statics list route, the group-wide MAC conflict check, the
        # ``find_dhcp_statics`` MCP tool — is now filtered on the primary
        # entity, so a trashed scope's reservations stop answering queries and
        # stop 409-ing new ones against a scope the operator cannot see.
        DHCPPool,
        DHCPStaticAssignment,
    )


_CACHED_SOFT_DELETE_MODELS: tuple[type, ...] | None = None


def _get_soft_delete_models() -> tuple[type, ...]:
    global _CACHED_SOFT_DELETE_MODELS
    if _CACHED_SOFT_DELETE_MODELS is None:
        _CACHED_SOFT_DELETE_MODELS = _soft_delete_models()
    return _CACHED_SOFT_DELETE_MODELS


def _referenced_soft_delete_models(statement: Any, models: tuple[type, ...]) -> set[type]:
    """Which of ``models`` the statement mentions ANYWHERE — one walk.

    One pass over the whole statement tree (:func:`_walk_statement`): the
    outer entity and columns, every ``Join`` (left and right),
    FROM-subqueries (#1933), and every subquery inside WHERE / HAVING /
    ORDER BY / the column list — ``exists()``, ``select().exists()``,
    ``x.in_(select(…))``, ``.subquery()`` / ``.cte()``, scalar subqueries,
    nested to any depth. A soft-deletable model reached only through a join
    or a subquery used to be invisible here, so it got no filter and a
    trashed subnet's / zone's / scope's rows came back through the join
    (#3492).

    A model counts as referenced when an element in the tree carries its
    mapper as ``parententity`` (ORM entities and columns, ``aliased()``
    included) or when its table appears as a ``Table``.

    Cost: this used to call ``statement.get_final_froms()``, which resolves
    and compiles the FROM graph — ~1.9 ms in the #879 profile, once per
    model before that, ~15 ms on every ORM SELECT. The tree walk compiles
    nothing: measured for #3492, a plain ``select(Subnet.id)`` went from
    0.23 to 0.05 ms through the whole hook, a two-join list page from 8.8
    to 0.18 ms, while seeing strictly more of the statement.
    """
    return _scan_statement(statement, models)[0]


def _scan_statement(statement: Any, models: tuple[type, ...]) -> tuple[set[type], list[Any]]:
    """``(referenced models, every Select in the tree)`` from one walk.

    On any failure the answer is the conservative one — every model, no
    selects — rather than risk leaking soft-deleted rows.
    """
    try:
        classes, table_names, selects = _walk_statement(statement)
    except Exception:  # pragma: no cover — defensive, never block a query
        return set(models), []
    referenced = {
        m for m in models if m in classes or getattr(m, "__tablename__", None) in table_names
    }
    return referenced, selects


def _walk_statement(statement: Any) -> tuple[set[Any], set[str], list[Any]]:
    """The single tree walk behind the soft-delete filter.

    Returns the mapped classes and table names found anywhere in the
    statement, plus every ``Select`` in it (the statement itself included),
    which :func:`_implicit_soft_delete_froms` needs and which would
    otherwise cost a second walk.
    """
    from sqlalchemy.sql.schema import Table
    from sqlalchemy.sql.selectable import Select

    classes: set[Any] = set()
    table_names: set[str] = set()
    selects: list[Any] = []
    # ``sqlalchemy.sql.visitors.iterate``, plus one thing it cannot do:
    # prune. A nested SELECT carrying ``include_deleted=True`` (see
    # :func:`exists_including_deleted`) is not descended into, so nothing
    # inside it is filtered unless the same model is also named elsewhere.
    stack = [statement]
    while stack:
        el = stack.pop()
        if isinstance(el, Select):
            if el is not statement and el._execution_options.get("include_deleted"):
                continue
            selects.append(el)
        elif isinstance(el, Table):
            table_names.add(el.name)
        ann = getattr(el, "_annotations", None)
        if ann:
            entity = ann.get("parententity")
            if entity is not None:
                classes.add(getattr(entity, "class_", None))
        stack.extend(el.get_children())
    return classes, table_names, selects


def exists_including_deleted(*criteria: Any) -> Any:
    """``exists().where(*criteria)`` that counts soft-deleted rows too.

    For a reference check that must see the Trash: "is anything still
    pointing at this row?" before hard-deleting it. A trashed child still
    holds its foreign key, so ignoring it either fails the delete (a
    ``RESTRICT`` FK) or silently destroys the Trash entry with it (a
    ``CASCADE`` one). The SELECT names no entity — its FROMs come from
    ``criteria`` alone — so the ORM's loader criteria never reach it either,
    whatever else the enclosing statement names.
    """
    from sqlalchemy import exists, literal_column, select

    return exists(
        select(literal_column("1")).where(*criteria).execution_options(include_deleted=True)
    )


def _implicit_soft_delete_froms(select: Any, table_names: frozenset[str]) -> list[Any]:
    """Soft-deletable FROMs of ``select`` that ``with_loader_criteria`` misses.

    The loader criteria the hook adds are applied by the ORM to the
    entities a SELECT *names*: its columns, ``select_from()`` and
    ``.join()`` targets — including ``aliased()`` ones, and including those
    of ORM selects nested anywhere in the statement. They are NOT applied
    to a table the SELECT only reaches through its WHERE clause, which is
    exactly what ``exists().where(Subnet.id == …)`` and
    ``select(func.count()).where(Subnet.block_id == …)`` do: the FROM is
    inferred from the criteria, and nothing filters it (#3492). Those are
    returned here so the hook can add ``deleted_at IS NULL`` to that
    SELECT's own WHERE.

    Anything joined (``.join()`` targets, members of a ``Join`` passed to
    ``select_from``) is left alone: a WHERE predicate on the inner side of
    an outer join would turn it into an inner join. Joined ORM entities are
    covered by the loader criteria; a joined *Core* table or
    ``Table.alias()`` is not covered at all (see the hook's docstring).
    """
    from sqlalchemy.sql.schema import Table
    from sqlalchemy.sql.selectable import Alias, Join

    def is_soft(f: Any) -> bool:
        if isinstance(f, Table):
            return f.name in table_names
        if isinstance(f, Alias):
            inner = f.element
            return isinstance(inner, Table) and inner.name in table_names
        return False

    covered: set[Any] = set()
    joined: set[Any] = set()

    def note_join(j: Any) -> None:
        for side in (j.left, j.right):
            if isinstance(side, Join):
                note_join(side)
            else:
                joined.add(side._deannotate())

    def note_explicit(f: Any) -> None:
        if f._annotations.get("parententity") is not None:
            covered.add(f._deannotate())

    for col in select._raw_columns:
        # The ORM filters exactly one entity per column: its
        # ``plugin_subject`` — ``Subnet`` for ``Subnet.id``, for
        # ``func.count(Subnet.id)`` and for ``select(Subnet)`` alike. A
        # second table the same expression touches
        # (``func.count(Subnet.id) + func.count(IPBlock.id)``), or a bare
        # Core column, gets no loader criteria.
        subject = col._propagate_attrs.get("plugin_subject")
        subject_from = getattr(subject, "selectable", None)
        if subject_from is not None:
            subject_from = subject_from._deannotate()
            for f in col._from_objects:
                if f._deannotate() is subject_from:
                    covered.add(subject_from)
    for f in select._from_obj:
        if isinstance(f, Join):
            note_join(f)
        else:
            note_explicit(f)
    for target, *_ in select._setup_joins:
        for f in getattr(target, "_from_objects", None) or [target]:
            joined.add(f._deannotate())

    out: list[Any] = []
    seen: set[Any] = set()
    candidates = [f for col in select._raw_columns for f in col._from_objects]
    candidates += [f for crit in select._where_criteria for f in crit._from_objects]
    candidates += [f for f in select._from_obj if not isinstance(f, Join)]
    for f in candidates:
        key = f._deannotate()
        if key in seen or key in covered or key in joined or not is_soft(key):
            continue
        seen.add(key)
        out.append(key)
    return out


def _filter_implicit_froms(statement: Any, selects: list[Any], soft_tables: set[str]) -> Any:
    """Add ``<from>.deleted_at IS NULL`` to every SELECT in ``statement``
    that reaches a soft-deletable table only through its WHERE clause.

    Returns ``statement`` untouched (no clone) in the common case where no
    SELECT needs it. Otherwise rebuilds the tree once with
    ``replacement_traverse``, rewriting innermost SELECTs first so a
    filtered subquery nested inside another filtered one keeps its filter.
    """
    from sqlalchemy.sql import visitors

    soft_names = frozenset(soft_tables)
    needs: dict[int, list[Any]] = {}
    for sel in selects:
        froms = _implicit_soft_delete_froms(sel, soft_names)
        if froms:
            needs[id(sel)] = froms
    if not needs:
        return statement

    done: dict[int, Any] = {}

    def rewrite(el: Any) -> Any:
        key = id(el)
        if key in done:
            return done[key]

        def replace(element: Any, **_kw: Any) -> Any:
            if element is not el and id(element) in needs:
                return rewrite(element)
            return None

        new = visitors.replacement_traverse(el, {}, replace)
        if key in needs:
            new = new.where(*[f.c.deleted_at.is_(None) for f in needs[key]])
        done[key] = new
        return new

    return rewrite(statement)


@event.listens_for(Session, "before_flush")
def _audit_chain_hash(session: Session, _flush_context: Any, _instances: Any) -> None:
    """Hash every newly-added ``AuditLog`` row before it hits the DB
    (issue #73). Lives on the global ``Session`` listener so it fires
    for sync sessions, sync-bound flushes inside the AsyncSession, and
    Celery task sessions alike.

    Lazy import so ``app.db`` doesn't pull every model at module load.
    """
    from app.services.audit_chain import compute_audit_hashes

    compute_audit_hashes(session)


@event.listens_for(Session, "do_orm_execute")
def _filter_soft_deleted(execute_state: Any) -> None:
    """Inject ``deleted_at IS NULL`` into every SELECT against in-scope models.

    Skips:
      * non-SELECT statements (UPDATE / DELETE / INSERT have their own
        WHERE clause already)
      * statements that opt out via ``include_deleted=True``
      * models that aren't referenced in the statement at all

    "Referenced" means anywhere in the tree — joins and subqueries in
    WHERE / HAVING / ORDER BY / the column list included (#3492) — so a
    caller that deliberately reads trashed rows through a join or a
    subquery must pass ``include_deleted=True`` like any other.

    Implementation note: ``propagate_to_loaders=False`` keeps the criterion
    off relationship loads. Without it, a SELECT against ``DHCPScope`` (which
    eager-joins ``pools`` / ``statics``) would require ``.unique()`` on
    every result — a sprawling regression. We accept that relationship
    loads can surface soft-deleted descendants; the cascade soft-delete
    pattern compensates by stamping parents + children atomically, so a
    "live" parent can't point at a soft-deleted child via the relationship
    in normal flow.
    """

    if not execute_state.is_select:
        return
    if execute_state.execution_options.get("include_deleted", False):
        return
    execute_state.statement = _apply_soft_delete_filter(execute_state.statement)


def _apply_soft_delete_filter(statement: Any) -> Any:
    """The statement with ``deleted_at IS NULL`` applied to every in-scope
    model it references; ``statement`` itself when it references none."""
    all_models = _get_soft_delete_models()
    referenced, selects = _scan_statement(statement, all_models)
    if not referenced:
        return statement
    if selects:
        soft_tables = {m.__tablename__ for m in referenced if hasattr(m, "__tablename__")}
        try:
            statement = _filter_implicit_froms(statement, selects, soft_tables)
        except Exception:  # pragma: no cover — defensive, never block a query
            # The loader criteria below still apply; only the WHERE-only
            # FROMs go unfiltered. Loud, because that is a leak.
            _db_logger.warning("soft_delete_implicit_from_rewrite_failed", exc_info=True)
    # Iterate the canonical tuple, not the set, so the options are applied
    # in a deterministic order — a set's iteration order would vary the
    # statement's cache key between processes for no reason.
    for model in all_models:
        if model not in referenced:
            continue
        # NOTE: no late-binding-closure bug here. ``model`` (the outer
        # loop var) is NOT captured by the lambda — it's passed to
        # ``with_loader_criteria`` as the entity to scope to, and
        # SQLAlchemy invokes the lambda with THAT entity as ``cls`` at
        # query-build time. So each criterion correctly targets its own
        # model. Do NOT "fix" this by referencing ``model`` inside the
        # lambda — that WOULD introduce the classic late-binding bug
        # (every criterion would see the last loop value).
        statement = statement.options(
            with_loader_criteria(
                model,
                lambda cls: cls.deleted_at.is_(None),
                include_aliases=True,
                propagate_to_loaders=False,
            )
        )
    return statement
