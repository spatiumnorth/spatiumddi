"""Test-time guard: no zone row written after the audit-chain lock (#3503).

A record create holds its zone's ``dns_zone`` row from its serial-bump flush on
and takes the audit-chain advisory lock at its commit. Any transaction that
takes the chain lock first and writes that row afterwards deadlocks against it
(#3389, #3503). ``compute_audit_hashes`` locks the zone rows a flush is about
to write before it takes the chain lock, so a flush carrying both is safe; what
it cannot see is a zone row written by a LATER flush of a transaction that
already holds the lock (an audit row flushed, or ``lock_audit_chain`` called,
before the serial bump). This records every such write, and ``conftest`` fails
the test that made it, so a new path cannot reintroduce the deadlock unseen.

Per session, in ``session.info``: whether the transaction holds the chain lock,
and which zone rows it already holds (inserted, or written by an earlier flush:
writing those again later waits for nobody). Both are cleared when the root
transaction ends, which is when Postgres releases the locks.
"""

from __future__ import annotations

import os
import traceback
from typing import Any

import greenlet
from sqlalchemy import Select, event
from sqlalchemy.orm import Session, SessionTransaction
from sqlalchemy.sql.elements import TextClause

import app
from app.models.audit import AuditLog
from app.services.audit_chain import _AUDIT_CHAIN_LOCK_KEY

#: The backend checkout, wherever it is: ``/app`` in the dev container, the
#: runner's workspace in CI. Frames outside ``app/`` and ``tests/`` are library
#: code. (A hardcoded ``/app/`` matched nothing in CI, so KNOWN_UNFIXED never
#: matched there either.)
_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(app.__file__)))
_OWN_DIRS = (os.path.join(_BACKEND, "app") + os.sep, os.path.join(_BACKEND, "tests") + os.sep)

_LOCKED = "_audit_lock_guard_locked"
_HELD = "_audit_lock_guard_held"
_BY = "_audit_lock_guard_by"

#: ``app.services.audit_chain.LOCKED_BEFORE_AUDIT_TABLES``, restated so the
#: guard still runs against a tree without it (proving a test fails unfixed).
LOCKED_BEFORE_AUDIT_TABLES = frozenset({"dns_zone"})

#: Entry points known to take the chain lock before a zone row, NOT fixed here,
#: each with why. A violation under one of these is not recorded. Keep it short:
#: every entry is a deadlock waiting for its interleaving.
KNOWN_UNFIXED: dict[str, str] = {
    # The approval is audited (``mark_approved``) before the approved
    # operation's ``apply()`` runs in the same transaction, so any operation
    # that writes a zone (create_ip_address with DNS, ...) takes the chain lock
    # first. Reordering moves the approval's audit row after the change it
    # approves, a governance decision for its own issue.
    "approve_change_request": "approval audited before apply() (#3503 follow-up)",
}

#: One entry per offending flush, read and cleared by the conftest fixture.
violations: list[str] = []


def _table_name(obj: Any) -> str | None:
    table = getattr(type(obj), "__table__", None)
    return None if table is None else table.name


def _caller_frames() -> list[traceback.FrameSummary]:
    """The app frames that led to this flush. Under ``AsyncSession`` the flush
    runs in a greenlet whose own stack starts at the spawn, so the awaiting
    callers are on the parent greenlet's (suspended) stack."""
    frame = None
    current = greenlet.getcurrent()
    if current.parent is not None:
        frame = current.parent.gr_frame
    return [
        f
        for f in traceback.extract_stack(frame)
        if f.filename.startswith(_OWN_DIRS)
        and not f.filename.endswith("_audit_lock_order_guard.py")
    ]


def _app_stack(frames: list[traceback.FrameSummary]) -> str:
    names = [f"{f.filename[len(_BACKEND) + 1 :]}:{f.lineno} {f.name}" for f in frames]
    return " <- ".join(reversed(names[-8:]))


def _before_flush(session: Session, _ctx: Any, _instances: Any) -> None:
    # Installed with ``insert=True``, so this runs before compute_audit_hashes
    # takes the lock for THIS flush: only a lock from an earlier flush counts.
    if session.info.get(_LOCKED):
        held = session.info.get(_HELD, set())
        written = sorted(
            f"{_table_name(obj)}:{obj.id}"
            for obj in (*session.dirty, *session.deleted)
            if _table_name(obj) in LOCKED_BEFORE_AUDIT_TABLES
            and (_table_name(obj), obj.id) not in held
            and (obj in session.deleted or session.is_modified(obj, include_collections=False))
        )
        frames = _caller_frames() if written else []
        if written and not any(f.name in KNOWN_UNFIXED for f in frames):
            violations.append(
                f"{', '.join(written)} written after this transaction took the "
                f"audit-chain lock (for {session.info.get(_BY)}); at {_app_stack(frames)}"
            )
    audits = [obj for obj in session.new if isinstance(obj, AuditLog)]
    if audits and not session.info.get(_LOCKED):
        session.info[_LOCKED] = True
        session.info[_BY] = f"audit row {audits[0].resource_type}/{audits[0].action}"


def _after_flush(session: Session, _ctx: Any) -> None:
    # ``session.new`` / ``dirty`` / ``deleted`` still hold the pre-flush state
    # here: every row in them is now locked until the transaction ends.
    for obj in (*session.new, *session.dirty, *session.deleted):
        name = _table_name(obj)
        if name not in LOCKED_BEFORE_AUDIT_TABLES:
            continue
        if obj in session.dirty and not session.is_modified(obj, include_collections=False):
            continue  # no UPDATE was issued, so no row lock was taken
        session.info.setdefault(_HELD, set()).add((name, obj.id))


def _locked_select_table(stmt: Any) -> str | None:
    """The table of a ``SELECT <table>.id ... FOR [NO KEY] UPDATE`` on one of
    :data:`LOCKED_BEFORE_AUDIT_TABLES`, or None. That is how a writer takes a
    zone row ahead of the chain lock without writing it yet."""
    if not isinstance(stmt, Select) or stmt._for_update_arg is None:
        return None
    cols = list(stmt.selected_columns)
    if len(cols) != 1 or getattr(cols[0], "key", None) != "id":
        return None
    table = getattr(cols[0], "table", None)
    name = getattr(table, "name", None)
    return name if name in LOCKED_BEFORE_AUDIT_TABLES else None


def _do_orm_execute(state: Any) -> Any:
    stmt = state.statement
    locked_table = _locked_select_table(stmt)
    if locked_table is not None:
        # Every row it returns is now this transaction's until it ends.
        frozen = state.invoke_statement().freeze()
        held = state.session.info.setdefault(_HELD, set())
        held.update((locked_table, row[0]) for row in frozen().all())
        return frozen()
    # ``lock_audit_chain`` takes the lock outside a flush.
    if (
        isinstance(stmt, TextClause)
        and "pg_advisory_xact_lock" in stmt.text
        and (state.parameters or {}).get("k") == _AUDIT_CHAIN_LOCK_KEY
        and not state.session.info.get(_LOCKED)
    ):
        state.session.info[_LOCKED] = True
        state.session.info[_BY] = "lock_audit_chain"
    # None tells SQLAlchemy to run the statement normally.
    return None


def _after_transaction_end(session: Session, transaction: SessionTransaction) -> None:
    if transaction.parent is None:
        session.info.pop(_LOCKED, None)
        session.info.pop(_HELD, None)
        session.info.pop(_BY, None)


def install() -> None:
    if event.contains(Session, "before_flush", _before_flush):
        return
    event.listen(Session, "before_flush", _before_flush, insert=True)
    event.listen(Session, "after_flush", _after_flush)
    event.listen(Session, "do_orm_execute", _do_orm_execute)
    event.listen(Session, "after_transaction_end", _after_transaction_end)
