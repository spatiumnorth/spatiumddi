"""Read side of the E911 resolution trail (#3598).

``e911_resolution_log`` records every location lookup (#972, #3514). Nothing
read it but SQL, which is how an after-action review of "what was this phone
told" had to be done. This module is the one query the REST list, the CSV
export and the copilot tool share, so the three cannot disagree about what a
filter means.

The trail says who looked up which device's location, so it has its own
permission (``e911_resolution_log``) and **every read of it writes an audit
row** (:func:`audit_trail_read`). Individual lookups and the counter rows
development builds wrote between #3514 and #3633 come out in one list, in time
order, told apart by ``kind``.
"""

from __future__ import annotations

import csv
import io
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.auth import APIToken, User
from app.models.e911 import E911ResolutionLog, EmergencyResponseLocation
from app.services.e911.exports import _csv_safe
from app.services.search.ranking import escape_like

#: ``audit_log.resource_type`` of a trail read. Deliberately not the ``e911``
#: string ERL / binding edits use: "who read the location history" is the
#: question an auditor asks on its own, and it should not need a changed_fields
#: filter to separate it from ERL edits.
AUDIT_RESOURCE = "e911_resolution_log"

#: Rows one CSV export may carry. A trail at the busiest end of retention is
#: millions of rows; past this the operator narrows the window.
EXPORT_ROW_CAP = 50_000

CSV_COLUMNS: tuple[str, ...] = (
    "queried_at",
    "kind",
    "identity_kind",
    "identity_value",
    "actor_kind",
    "actor",
    "source_ip",
    "erl_name",
    "rule_matched",
    "confidence",
    "degraded_reason",
    "evidence_age_seconds",
    "lookups_not_individually_logged",
)


@dataclass(frozen=True)
class TrailFilters:
    #: Substring of the identity asked about (IP / MAC / ``chassis/port``).
    identity: str | None = None
    identity_kind: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    #: The caller: a user id or an API token id.
    actor_id: uuid.UUID | None = None
    actor_kind: str | None = None
    #: Outcome of the resolution: ``observed`` / ``degraded`` / ``none``.
    confidence: str | None = None
    erl_id: uuid.UUID | None = None
    #: ``lookup`` (one row per lookup) or ``counter`` (an aggregated row).
    kind: str | None = None

    def as_audit(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in self.__dict__.items():
            if value is not None:
                out[key] = value.isoformat() if isinstance(value, datetime) else str(value)
        return out


@dataclass
class TrailRow:
    row: E911ResolutionLog
    actor_label: str | None
    erl_name: str | None

    @property
    def kind(self) -> str:
        return "counter" if self.row.suppressed_count is not None else "lookup"


def _apply(stmt: Select[Any], f: TrailFilters) -> Select[Any]:
    log = E911ResolutionLog
    if f.identity:
        stmt = stmt.where(log.identity_value.ilike(f"%{escape_like(f.identity)}%", escape="\\"))
    if f.identity_kind:
        stmt = stmt.where(log.identity_kind == f.identity_kind)
    if f.since is not None:
        stmt = stmt.where(log.queried_at >= f.since)
    if f.until is not None:
        stmt = stmt.where(log.queried_at < f.until)
    if f.actor_id is not None:
        stmt = stmt.where(log.actor_id == f.actor_id)
    if f.actor_kind:
        stmt = stmt.where(log.actor_kind == f.actor_kind)
    if f.confidence:
        stmt = stmt.where(log.confidence == f.confidence)
    if f.erl_id is not None:
        stmt = stmt.where(log.erl_id == f.erl_id)
    if f.kind == "counter":
        stmt = stmt.where(log.suppressed_count.is_not(None))
    elif f.kind == "lookup":
        stmt = stmt.where(log.suppressed_count.is_(None))
    return stmt


async def list_trail(
    db: AsyncSession, f: TrailFilters, *, limit: int, offset: int
) -> tuple[list[TrailRow], int]:
    """One page of the trail, newest first, plus the total matching ``f``."""
    log = E911ResolutionLog
    total = (await db.execute(_apply(select(func.count()).select_from(log), f))).scalar_one()
    rows = list(
        (
            await db.execute(
                _apply(select(log), f)
                .order_by(log.queried_at.desc(), log.id.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return await _decorate(db, rows), int(total)


async def _decorate(db: AsyncSession, rows: list[E911ResolutionLog]) -> list[TrailRow]:
    """Attach the actor's name and the ERL's name, in three queries total.

    The log keeps ids only (an ERL or a user may be gone by the time the trail
    is read); a missing one reads as ``None`` rather than failing the page.
    """
    actors_user = {r.actor_id for r in rows if r.actor_kind == "user" and r.actor_id}
    actors_tok = {r.actor_id for r in rows if r.actor_kind == "api_token" and r.actor_id}
    erls = {r.erl_id for r in rows if r.erl_id}
    users: dict[uuid.UUID, str] = {}
    tokens: dict[uuid.UUID, str] = {}
    erl_names: dict[uuid.UUID, str] = {}
    if actors_user:
        users = {
            i: n
            for i, n in (
                await db.execute(select(User.id, User.username).where(User.id.in_(actors_user)))
            ).all()
        }
    if actors_tok:
        tokens = {
            i: n
            for i, n in (
                await db.execute(
                    select(APIToken.id, APIToken.name).where(APIToken.id.in_(actors_tok))
                )
            ).all()
        }
    if erls:
        erl_names = {
            i: n
            for i, n in (
                await db.execute(
                    select(EmergencyResponseLocation.id, EmergencyResponseLocation.name).where(
                        EmergencyResponseLocation.id.in_(erls)
                    )
                )
            ).all()
        }
    out: list[TrailRow] = []
    for r in rows:
        label: str | None = None
        if r.actor_id:
            label = (users if r.actor_kind == "user" else tokens).get(r.actor_id)
        elif r.actor_kind == "device_self":
            label = "device (self-query)"
        out.append(TrailRow(r, label, erl_names.get(r.erl_id) if r.erl_id else None))
    return out


def audit_trail_read(
    db: AsyncSession,
    user: User | None,
    *,
    action: str,
    filters: TrailFilters,
    returned: int,
) -> None:
    """Add the audit row for a read of the trail; the caller commits.

    ``action`` is ``read`` for a page and ``export`` for the CSV. The filters
    are recorded because *what was looked for* is the sensitive part: a
    review of the reviewers wants to see that someone searched one phone's
    history, not merely that the page was opened.
    """
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            user_display_name=user.display_name if user else "system",
            auth_source=user.auth_source if user else "system",
            action=action,
            resource_type=AUDIT_RESOURCE,
            resource_id="resolution-log",
            resource_display=f"{returned} trail row(s)",
            new_value={"filters": filters.as_audit(), "returned": returned},
            result="success",
        )
    )


def render_trail_csv(rows: list[TrailRow]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(CSV_COLUMNS), lineterminator="\r\n")
    writer.writeheader()
    for t in rows:
        r = t.row
        writer.writerow(
            {
                "queried_at": r.queried_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "kind": t.kind,
                "identity_kind": _csv_safe(r.identity_kind),
                "identity_value": _csv_safe(r.identity_value),
                "actor_kind": _csv_safe(r.actor_kind),
                "actor": _csv_safe(t.actor_label or r.actor_id),
                "source_ip": _csv_safe(r.source_ip),
                "erl_name": _csv_safe(t.erl_name),
                "rule_matched": _csv_safe(r.rule_matched),
                "confidence": _csv_safe(r.confidence),
                "degraded_reason": _csv_safe(r.degraded_reason),
                "evidence_age_seconds": _csv_safe(r.evidence_age_seconds),
                "lookups_not_individually_logged": _csv_safe(r.suppressed_count),
            }
        )
    return buf.getvalue()


__all__ = [
    "AUDIT_RESOURCE",
    "CSV_COLUMNS",
    "EXPORT_ROW_CAP",
    "TrailFilters",
    "TrailRow",
    "audit_trail_read",
    "list_trail",
    "render_trail_csv",
]
