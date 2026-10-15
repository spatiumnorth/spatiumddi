"""Factory-reset orchestration (issue #116).

Validates every guardrail, runs the per-section wipe, writes the
audit anchor, fires the typed event for fan-out.

Guardrails enforced here (caller — the API endpoint — applies the
permission gate + password verification + confirm-phrase check
before reaching this layer):

* **Mutex** — refuse if any backup target is mid-run, or another
  factory-reset is in flight (Redis lock, 10 min TTL).
* **Cooldown** — refuse if a prior factory_reset_performed audit
  row landed within the last 6 hours.
* **Audit anchor** — single ``factory_reset_performed`` row written
  AFTER the destructive SQL on a fresh session so it survives a
  truncate of ``audit_log`` itself.

The destructive SQL runs against a short-lived asyncpg connection
rather than the SQLAlchemy session — TRUNCATE takes an ACCESS
EXCLUSIVE lock that fights the async session's pooled connections.

It never uses ``TRUNCATE … CASCADE`` (#1835): that empties every table
with a foreign key into the truncated one whatever the key's ``ON
DELETE`` rule, so a Tools reset emptied every IP address, DNS record
and DHCP static. See :mod:`app.services.factory_reset.fk_graph`. The
whole reset runs in ONE transaction, so a refusal part-way (a
``RESTRICT`` key from a table the reset does not cover) rolls every
section back rather than leaving half an install wiped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import asyncpg
import structlog
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.factory_reset.fk_graph import (
    FK_EDGES_SQL,
    FKEdge,
    blocking_count_queries,
    delete_order,
    dependent_count_queries,
    edges_from_rows,
    truncatable,
)
from app.services.factory_reset.sections import (
    AUTH_RBAC_CASCADE_DEPENDENTS,
    FACTORY_SECTIONS_BY_KEY,
    FactorySection,
    expand_everything,
)

logger = structlog.get_logger(__name__)

COOLDOWN_HOURS = 6
RESET_LOCK_KEY = "spatium:factory_reset:in_progress"
RESET_LOCK_TTL_SECONDS = 600


class FactoryResetError(Exception):
    """Generic failure for factory-reset orchestration."""


class FactoryResetMutexError(FactoryResetError):
    """Raised when another long-running operation prevents the reset
    from starting (HTTP 409). The message names the blocker so
    operators know what to wait on.
    """


class FactoryResetBlockedError(FactoryResetError):
    """Raised when a table the reset does not cover still holds a
    ``RESTRICT`` / ``NO ACTION`` foreign key into one it would wipe
    (HTTP 409). Nothing has been deleted when this is raised.
    """


class FactoryResetCooldownError(FactoryResetError):
    """Raised when a prior reset completed within the cooldown
    window (HTTP 409 / 429). The next-allowed timestamp is
    surfaced in the message.
    """


@dataclass
class SectionPreview:
    section_key: str
    label: str
    kind: str
    table_counts: dict[str, int] = field(default_factory=dict)
    affected_rows: int = 0
    notes: list[str] = field(default_factory=list)


@dataclass
class FactoryResetOutcome:
    sections: list[str]
    deleted_rows_total: int
    per_section: list[SectionPreview]
    audit_anchor_id: str | None
    duration_ms: int


# ── Helpers ─────────────────────────────────────────────────────────


def _resolve_targets(section_keys: list[str]) -> list[FactorySection]:
    """Translate operator-supplied keys to actual sections,
    expanding ``all`` to every concrete section in order.
    """
    out: list[FactorySection] = []
    seen: set[str] = set()
    for key in section_keys:
        section = FACTORY_SECTIONS_BY_KEY.get(key)
        if section is None:
            raise FactoryResetError(f"unknown section key: {key!r}")
        if section.kind == "everything":
            for sub in expand_everything():
                if sub.key not in seen:
                    seen.add(sub.key)
                    out.append(sub)
        elif key not in seen:
            seen.add(key)
            out.append(section)
    return out


def _pg_dsn(db_url: str) -> str:
    return db_url.replace("postgresql+asyncpg://", "postgresql://", 1)


async def _ensure_no_backup_in_flight(db: AsyncSession) -> None:
    """Refuse if any backup target's last_run_status is
    ``in_progress``. The backup-runner sets this as a per-target
    mutex; we treat it as a global signal here.
    """
    from app.models.backup import BackupTarget  # noqa: PLC0415

    busy = await db.execute(
        select(BackupTarget.name).where(BackupTarget.last_run_status == "in_progress")
    )
    name = busy.scalar()
    if name is not None:
        raise FactoryResetMutexError(
            f"backup target {name!r} is currently running — wait for it to finish "
            "(or abort it) before resetting"
        )


async def _ensure_cooldown_clear(db: AsyncSession) -> None:
    """Refuse if a factory_reset_performed audit row landed within
    the last :data:`COOLDOWN_HOURS` hours.
    """
    res = await db.execute(
        text("SELECT MAX(timestamp) FROM audit_log WHERE action = 'factory_reset_performed'")
    )
    last = res.scalar()
    if last is None:
        return
    threshold = datetime.now(UTC) - timedelta(hours=COOLDOWN_HOURS)
    if last >= threshold:
        next_ok = last + timedelta(hours=COOLDOWN_HOURS)
        raise FactoryResetCooldownError(
            f"a factory reset ran at {last.isoformat()}; "
            f"the next reset is allowed after {next_ok.isoformat()} "
            f"({COOLDOWN_HOURS}h cooldown)"
        )


async def _acquire_lock_or_raise() -> Any:
    """Set a Redis flag with a TTL. Raises
    :class:`FactoryResetMutexError` when the flag is already held.
    Returns the redis client so the caller can release it.
    """
    from app.config import settings  # noqa: PLC0415
    from app.core.redis_client import make_async_redis  # noqa: PLC0415

    client = make_async_redis(settings.redis_url, socket_connect_timeout=2)
    acquired = await client.set(RESET_LOCK_KEY, "1", nx=True, ex=RESET_LOCK_TTL_SECONDS)
    if not acquired:
        await client.aclose()
        raise FactoryResetMutexError(
            "another factory reset is currently running — wait for it to "
            "complete before starting a new one"
        )
    return client


async def _release_lock(client: Any) -> None:
    try:
        await client.delete(RESET_LOCK_KEY)
    except Exception:  # noqa: BLE001
        # Lock will expire on its own via TTL.
        pass
    finally:
        try:
            await client.aclose()
        except Exception:  # noqa: BLE001
            pass


# ── Preview ──────────────────────────────────────────────────────────


async def preview_factory_reset(
    db: AsyncSession,
    *,
    section_keys: list[str],
    calling_user_id: UUID,
) -> list[SectionPreview]:
    """Compute a per-section preview of what the reset would
    delete. Read-only — does not mutate state.
    """
    targets = _resolve_targets(section_keys)
    previews: list[SectionPreview] = []
    for section in targets:
        preview = SectionPreview(section_key=section.key, label=section.label, kind=section.kind)
        if section.kind == "truncate":
            for table in section.tables:
                count = await _table_count(db, table)
                preview.table_counts[table] = count
                preview.affected_rows += count
            await _add_cascade_preview(db, section, preview)
        elif section.kind == "auth_rbac":
            counts = await _auth_rbac_counts(db, calling_user_id)
            preview.table_counts = counts
            preview.affected_rows = sum(counts.values())
            preview.notes.append("calling superadmin + built-in roles preserved")
            if AUTH_RBAC_CASCADE_DEPENDENTS:
                preview.notes.append(
                    "rows owned by a deleted user go with it: "
                    + ", ".join(AUTH_RBAC_CASCADE_DEPENDENTS)
                )
        elif section.kind == "settings_reset":
            preview.affected_rows = 1
            preview.notes.append("platform_settings row reverted to model defaults")
        previews.append(preview)
    blockers = await _preview_blockers(db, targets)
    if blockers and previews:
        previews[0].notes.append("REFUSED until cleared: " + "; ".join(blockers))
    return previews


async def _load_edges_sa(db: AsyncSession) -> list[FKEdge]:
    res = await db.execute(text(FK_EDGES_SQL))
    return edges_from_rows(res.mappings().all())


async def _present_tables_sa(db: AsyncSession) -> set[str]:
    res = await db.execute(text("SELECT tablename FROM pg_tables WHERE schemaname='public'"))
    return {r[0] for r in res.all()}


def _dependent_count_sql(
    section: FactorySection, edges: list[FKEdge], present: set[str]
) -> dict[str, str]:
    """Per dependent table, the SQL counting exactly the rows a wipe of
    ``section.tables`` removes through CASCADE keys (see
    :func:`.fk_graph.dependent_count_queries`)."""
    own = [t for t in section.tables if t in present]
    return {dep: sql for dep, sql in dependent_count_queries(edges, own).items() if dep in present}


async def _dependent_counts_sa(
    db: AsyncSession, section: FactorySection, edges: list[FKEdge], present: set[str]
) -> dict[str, int]:
    out: dict[str, int] = {}
    for dep, sql in _dependent_count_sql(section, edges, present).items():
        try:
            out[dep] = int((await db.execute(text(sql))).scalar() or 0)
        except Exception as exc:  # noqa: BLE001
            logger.info("factory_reset_dependent_count_failed", table=dep, error=str(exc))
            await db.rollback()
    return out


async def _add_cascade_preview(
    db: AsyncSession, section: FactorySection, preview: SectionPreview
) -> None:
    edges = await _load_edges_sa(db)
    present = await _present_tables_sa(db)
    counts = await _dependent_counts_sa(db, section, edges, present)
    nonzero = {t: n for t, n in counts.items() if n}
    if nonzero:
        total = sum(nonzero.values())
        preview.affected_rows += total
        for t, n in nonzero.items():
            preview.table_counts[f"{t} (cascade)"] = n
        preview.notes.append(
            f"includes {total} row(s) in other tables that cannot exist "
            "without these (foreign keys with ON DELETE CASCADE)"
        )


async def _preview_blockers(db: AsyncSession, targets: list[FactorySection]) -> list[str]:
    """Human-readable list of references that would make the reset
    fail: rows outside the wipe holding a ``RESTRICT`` / ``NO ACTION``
    key to a row it removes. Empty when nothing blocks it."""
    wiped = [t for s in targets if s.kind == "truncate" for t in s.tables]
    if not wiped:
        return []
    edges = await _load_edges_sa(db)
    present = await _present_tables_sa(db)
    out: list[str] = []
    for e, sql in blocking_count_queries(edges, [t for t in wiped if t in present]):
        if e.child not in present:
            continue
        try:
            n = int((await db.execute(text(sql))).scalar() or 0)
        except Exception as exc:  # noqa: BLE001
            logger.info("factory_reset_blocker_count_failed", table=e.child, error=str(exc))
            await db.rollback()
            continue
        if n:
            owner = next(
                (s.label for s in FACTORY_SECTIONS_BY_KEY.values() if e.child in s.tables), None
            )
            hint = f" (reset {owner} with it, or first)" if owner else ""
            out.append(f"{n} {e.child} row(s) still reference {e.parent}{hint}")
    return out


async def _table_count(db: AsyncSession, table: str) -> int:
    try:
        res = await db.execute(text(f'SELECT COUNT(*) FROM "{table}"'))
        return int(res.scalar() or 0)
    except Exception as exc:  # noqa: BLE001
        # Optional integration / feature module not present.
        logger.info("factory_reset_table_missing", table=table, error=str(exc))
        await db.rollback()
        return 0


async def _auth_rbac_counts(db: AsyncSession, calling_user_id: UUID) -> dict[str, int]:
    """Count rows the auth_rbac section will delete, excluding the
    preserved set (calling user + all other superadmins + built-in
    roles).
    """
    counts: dict[str, int] = {}
    counts["user"] = int(
        (
            await db.execute(
                text('SELECT COUNT(*) FROM "user" ' "WHERE is_superadmin = false AND id <> :uid"),
                {"uid": str(calling_user_id)},
            )
        ).scalar()
        or 0
    )
    counts["group"] = int((await db.execute(text('SELECT COUNT(*) FROM "group"'))).scalar() or 0)
    counts["role"] = int(
        (await db.execute(text("SELECT COUNT(*) FROM role WHERE is_builtin = false"))).scalar() or 0
    )
    counts["api_token"] = int(
        (await db.execute(text("SELECT COUNT(*) FROM api_token"))).scalar() or 0
    )
    counts["auth_provider"] = int(
        (await db.execute(text("SELECT COUNT(*) FROM auth_provider"))).scalar() or 0
    )
    counts["auth_group_mapping"] = int(
        (await db.execute(text("SELECT COUNT(*) FROM auth_group_mapping"))).scalar() or 0
    )
    return counts


# ── Execute ──────────────────────────────────────────────────────────


async def apply_factory_reset(
    db: AsyncSession,
    *,
    section_keys: list[str],
    calling_user_id: UUID,
    calling_user_display: str,
    db_url: str,
) -> FactoryResetOutcome:
    """Run every guardrail, dispatch each section's wipe, write
    the audit anchor.

    Caller is responsible for the permission gate + password
    re-verification + per-section confirm-phrase check; this layer
    handles the destructive side.
    """
    targets = _resolve_targets(section_keys)
    started = datetime.now(UTC)

    # Pre-flight guardrails.
    await _ensure_no_backup_in_flight(db)
    await _ensure_cooldown_clear(db)

    # Refuse BEFORE anything is deleted when a table the reset does not
    # cover holds a RESTRICT key into one it would wipe.
    blockers = await _preview_blockers(db, targets)
    if blockers:
        raise FactoryResetBlockedError(
            "cannot reset: " + "; ".join(blockers) + " — reset or remove those first"
        )

    # Snapshot pre-wipe counts for the audit row.
    previews = await preview_factory_reset(
        db, section_keys=section_keys, calling_user_id=calling_user_id
    )

    # Acquire the in-flight lock + dispose the SQLAlchemy session
    # before TRUNCATE so the connection pool doesn't fight the
    # destructive subprocess.
    lock_client = await _acquire_lock_or_raise()

    deleted_total = 0
    audit_anchor_id: str | None = None
    try:
        # Close + dispose session before TRUNCATE — TRUNCATE takes
        # an ACCESS EXCLUSIVE lock and concurrent SQLAlchemy reads
        # will deadlock against it.
        await db.close()
        from app.db import engine as global_engine  # noqa: PLC0415

        await global_engine.dispose()

        dsn = _pg_dsn(db_url)
        conn = await asyncpg.connect(dsn=dsn)
        try:
            # ONE transaction: a failure part-way rolls every section
            # back instead of leaving half an install wiped.
            async with conn.transaction():
                deleted_total = await _execute_sections(
                    conn, targets, calling_user_id=calling_user_id
                )
        except asyncpg.ForeignKeyViolationError as exc:
            raise FactoryResetBlockedError(
                f"cannot reset: {exc} — nothing was deleted; reset the referencing data first"
            ) from exc
        finally:
            await conn.close()

        # Audit anchor — fresh session because the old one was
        # disposed. The anchor row carries all the diagnostic info
        # operators / auditors need.
        audit_anchor_id = await _write_audit_anchor(
            calling_user_id=calling_user_id,
            calling_user_display=calling_user_display,
            sections=[s.key for s in targets],
            previews=previews,
            duration_ms=int((datetime.now(UTC) - started).total_seconds() * 1000),
        )
    finally:
        await _release_lock(lock_client)

    duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
    logger.info(
        "factory_reset_applied",
        sections=[s.key for s in targets],
        deleted_rows_total=deleted_total,
        actor_id=str(calling_user_id),
        duration_ms=duration_ms,
    )
    return FactoryResetOutcome(
        sections=[s.key for s in targets],
        deleted_rows_total=deleted_total,
        per_section=previews,
        audit_anchor_id=audit_anchor_id,
        duration_ms=duration_ms,
    )


async def _execute_sections(
    conn: asyncpg.Connection,
    targets: list[FactorySection],
    *,
    calling_user_id: UUID,
) -> int:
    """Run every target inside the caller's transaction. Returns the
    approximate deleted-row count (own rows + cascade dependents).

    All ``truncate`` sections are planned TOGETHER: ``Everything`` runs
    IPAM before Integrations, but an integration's ``ip_space`` key is
    ``RESTRICT``, so the order has to come from the foreign keys, not
    from the section list.
    """
    deleted = 0
    truncate_sections = [s for s in targets if s.kind == "truncate"]
    if truncate_sections:
        deleted += await _execute_truncate_sections(conn, truncate_sections)
    for section in targets:
        if section.kind == "auth_rbac":
            deleted += await _execute_auth_rbac(conn, calling_user_id=calling_user_id)
        elif section.kind == "settings_reset":
            deleted += await _execute_settings_reset(conn)
        elif section.kind != "truncate":
            raise FactoryResetError(f"unhandled section kind: {section.kind!r}")
    return deleted


async def _execute_truncate_sections(
    conn: asyncpg.Connection, sections: list[FactorySection]
) -> int:
    """Wipe the tables of every section in ``sections`` without
    ``CASCADE`` (#1835):

    * tables nothing outside the wipe references are ``TRUNCATE``d
      (fast on the big log tables) — a plain TRUNCATE refuses rather
      than reach into a referencing table;
    * the rest are ``DELETE``d children-first, so ``ON DELETE SET
      NULL`` keys (``ip_address.last_profile_scan_id``,
      ``dns_record.ip_address_id`` …) null and the referencing row
      survives.

    Tables absent from this install (optional modules) are skipped.
    """
    edges = edges_from_rows(await conn.fetch(FK_EDGES_SQL))
    rows = await conn.fetch("SELECT tablename FROM pg_tables WHERE schemaname='public'")
    present = {r["tablename"] for r in rows}

    # Pre-count for the operator-facing total (own rows + the rows
    # CASCADE keys will take with them).
    # Each count runs in its own SAVEPOINT: a failed statement would
    # otherwise abort the whole reset transaction and every DELETE
    # after it would fail with "current transaction is aborted".
    async def _count(sql: str) -> int:
        try:
            async with conn.transaction():
                return int(await conn.fetchval(sql) or 0)
        except asyncpg.PostgresError as exc:
            logger.info("factory_reset_count_failed", sql=sql, error=str(exc))
            return 0

    deleted = 0
    for section in sections:
        for t in section.tables:
            if t in present:
                deleted += await _count(f'SELECT COUNT(*) FROM "{t}"')
        for sql in _dependent_count_sql(section, edges, present).values():
            deleted += await _count(sql)

    wanted = [t for s in sections for t in s.tables if t in present]
    wanted = list(dict.fromkeys(wanted))
    if not wanted:
        return 0
    can_truncate = truncatable(edges, wanted)
    to_truncate = [t for t in wanted if t in can_truncate]
    to_delete = delete_order(edges, [t for t in wanted if t not in can_truncate])

    if to_truncate:
        quoted = ", ".join(f'"{t}"' for t in to_truncate)
        # Deliberately NOT CASCADE: nothing outside this list may be
        # touched (``truncatable`` guarantees nothing references it).
        await conn.execute(f"TRUNCATE TABLE {quoted} RESTART IDENTITY")
    for t in to_delete:
        await conn.execute(f'DELETE FROM "{t}"')
    logger.info(
        "factory_reset_sections_wiped",
        sections=[s.key for s in sections],
        truncated=to_truncate,
        deleted_from=to_delete,
        rows=deleted,
    )
    return deleted


async def _execute_auth_rbac(conn: asyncpg.Connection, *, calling_user_id: UUID) -> int:
    """Wipe non-admin users / custom groups / non-builtin roles /
    api_tokens / auth_providers. Preserves:

    * The calling superadmin (their User row, group + role
      memberships).
    * Every other superadmin (so multi-admin installs don't
      orphan operators).
    * Built-in roles (``is_builtin=True``).
    """
    deleted = 0
    # Order matters — clear association rows before the parent rows.
    queries = (
        ("user_session", "DELETE FROM user_session"),
        ("api_token", "DELETE FROM api_token"),
        ("auth_group_mapping", "DELETE FROM auth_group_mapping"),
        ("auth_provider", "DELETE FROM auth_provider"),
        # Wipe groups + their associations. Preserve no groups —
        # the issue says "all custom groups" and there are no
        # built-in groups in the seeded set.
        ("group_role", "DELETE FROM group_role"),
        ("user_group", "DELETE FROM user_group"),
        ("group", 'DELETE FROM "group"'),
        # Roles — keep the platform built-ins.
        ("role", "DELETE FROM role WHERE is_builtin = false"),
        # Users — keep all superadmins (the calling user + any
        # others). is_superadmin=True is the explicit gate.
        (
            "user",
            'DELETE FROM "user" WHERE is_superadmin = false AND id <> $1',
        ),
    )
    for label, sql in queries:
        if "$1" in sql:
            res = await conn.execute(sql, calling_user_id)
        else:
            res = await conn.execute(sql)
        # asyncpg returns command tag like "DELETE 7"
        try:
            n = int(res.split()[-1])
        except (ValueError, IndexError):
            n = 0
        deleted += n
        logger.info("factory_reset_auth_rbac", table=label, rows=n)
    return deleted


async def _execute_settings_reset(conn: asyncpg.Connection) -> int:
    """Wipe + recreate the singleton ``platform_settings`` row.
    DELETE + INSERT (rather than UPDATE every column to default)
    so future-added columns automatically pick up their model
    defaults via the INSERT path.
    """
    # platform_settings has a single row by convention. DELETE all,
    # then let the next API request re-create it via the standard
    # ``get_or_create_platform_settings`` path (which inserts a
    # fresh row with model defaults). Other tables don't FK to
    # platform_settings.id, so a brief gap is fine.
    await conn.execute("DELETE FROM platform_settings")
    return 1


async def _write_audit_anchor(
    *,
    calling_user_id: UUID,
    calling_user_display: str,
    sections: list[str],
    previews: list[SectionPreview],
    duration_ms: int,
) -> str | None:
    """Insert the synthetic ``factory_reset_performed`` audit row
    via a fresh ``AsyncSessionLocal``. Writing through the
    SQLAlchemy session is what fires the event-publisher hook
    (``system.factory_reset`` typed event); writing via raw
    asyncpg would land the row but skip the fan-out.

    This is the row that survives a wipe of the audit-log
    section itself — it's inserted post-truncate.
    """
    new_value = {
        "sections": sections,
        "actor": {
            "user_id": str(calling_user_id),
            "display_name": calling_user_display,
        },
        "duration_ms": duration_ms,
        "per_section": [
            {
                "key": p.section_key,
                "label": p.label,
                "kind": p.kind,
                "affected_rows": p.affected_rows,
                "tables": p.table_counts,
                "notes": p.notes,
            }
            for p in previews
        ],
    }
    try:
        from app.db import AsyncSessionLocal  # noqa: PLC0415
        from app.models.audit import AuditLog  # noqa: PLC0415

        async with AsyncSessionLocal() as fresh:
            row = AuditLog(
                action="factory_reset_performed",
                resource_type="platform",
                resource_id="factory_reset",
                resource_display=",".join(sections),
                user_id=calling_user_id,
                user_display_name=calling_user_display,
                result="success",
                new_value=new_value,
            )
            fresh.add(row)
            await fresh.commit()
            return str(row.id)
    except Exception as exc:  # noqa: BLE001
        # Audit anchor failure is non-fatal — the data is wiped,
        # we just lose the structured trail.
        logger.error("factory_reset_audit_anchor_failed", error=str(exc))
        return None


def verify_user_password(user: Any, plaintext: str) -> bool:
    """Re-verify the calling user's password against the stored
    bcrypt hash. Wrapper here so the API layer doesn't have to know
    bcrypt internals.
    """
    if not getattr(user, "hashed_password", None):
        return False
    from app.core.security import verify_password  # noqa: PLC0415

    return verify_password(plaintext, user.hashed_password)


__all__ = [
    "COOLDOWN_HOURS",
    "FactoryResetBlockedError",
    "FactoryResetCooldownError",
    "FactoryResetError",
    "FactoryResetMutexError",
    "FactoryResetOutcome",
    "SectionPreview",
    "apply_factory_reset",
    "preview_factory_reset",
    "verify_user_password",
]
