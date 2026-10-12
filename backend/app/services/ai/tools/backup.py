"""Backup + factory-reset read tools for the Operator Copilot
(issues #117 + #116 + #702).

Six read-only tools, all superadmin-only because the surface
exposes destination configs (even with secrets redacted, the
target name + kind + path/bucket/host is sensitive metadata):

* ``list_backup_targets`` — every configured target with last-run
  state, schedule, retention. The first thing an operator asks
  via copilot: "did all my backups succeed last night?" / "which
  targets are scheduled?".
* ``list_backup_archives_at_target`` — what's actually stored at
  a specific target right now. Calls the driver's
  ``list_archives`` so the answer matches the Backup admin
  page's "Archives" drawer exactly.
* ``find_backup_audit_history`` — timeline of backup-created /
  backup-target-run / backup-restored / factory-reset-performed
  audit rows with their per-row counters / sizes / errors.
  Useful for "when did backup last fail?" or "show me last
  week's reset history".
* ``find_restore_drills`` — restore-verification drill history
  (#702): did the archive actually survive a test restore, and
  which checks failed if not.
* ``get_restore_drill_readiness`` — the rollup that answers "can
  I restore this install right now, and how do I know?" per
  target, without reading the whole history.
* ``get_backup_health`` — per target: is the schedule actually
  producing backups? Failed / stale / stuck, decided by the same
  function as the ``backup_failed`` / ``backup_stale`` alerts (#1262).

Deliberately NO ``propose_*`` write tools. The factory-reset and
restore paths are password-gated + confirm-phrase-gated by design;
inserting an LLM intermediary into "should I restore?" adds
friction without value, and ``propose_create_backup_target``
involves pasting destination credentials, which doesn't fit a
chat-driven flow. Operators reach for the Backup admin page when
they're about to mutate state.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, Field
from sqlalchemy import desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import is_effective_superadmin
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.backup import BackupTarget, RestoreDrill
from app.services.ai.tools.base import register_tool


def _superadmin_gate(user: User) -> dict[str, Any] | None:
    """Returns an error dict the caller bubbles up if not
    superadmin; ``None`` when the call is allowed. Mirrors the
    pattern from ``tools/admin.py`` for the RBAC tools.
    """
    if not is_effective_superadmin(user):
        return {
            "error": (
                "Backup tools expose destination metadata + audit "
                "history and are restricted to superadmin users. "
                "Ask your platform admin to run the query."
            )
        }
    return None


def _try_uuid(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(value)
    except (ValueError, AttributeError):
        return None


def _known_kinds() -> list[str]:
    """The destination kinds this build registers, sorted.

    Read from the same registry the API's ``GET /backup/targets/kinds``
    reflects on, so the copilot and the UI picker cannot disagree about
    what exists.

    Imports the *package*, not ``.base``: the registry lives in ``base``
    but is populated by the package's ``__init__`` as an import side
    effect. Reaching straight for ``base`` would read an empty dict
    whenever this module happens to be imported first — which yields an
    empty enumeration in the description rather than an error.
    """
    from app.services.backup.targets import DESTINATIONS  # noqa: PLC0415

    return sorted(DESTINATIONS)


# ── list_backup_targets ───────────────────────────────────────────────


class ListBackupTargetsArgs(BaseModel):
    enabled_only: bool = Field(
        default=False,
        description="When True, exclude disabled targets from the result.",
    )
    kind: str | None = Field(
        default=None,
        description=(
            # Enumerated from the driver registry rather than typed out.
            # This string is what the model reads to decide which values
            # are legal, so a hand-maintained list does not merely go
            # stale — it makes a registered destination unaskable-about
            # (``nfs`` in #971 was the case that surfaced it).
            "Filter by destination kind: "
            + " / ".join(_known_kinds())
            + "."
        ),
    )
    last_run_status: Literal["never", "in_progress", "success", "failed"] | None = Field(
        default=None,
        description=(
            "Filter by the most recent run's status. 'failed' is the "
            "useful one — 'show me targets where last night's run "
            "failed'."
        ),
    )


@register_tool(
    name="list_backup_targets",
    permission="superadmin",
    description=(
        "List all configured backup targets (superadmin only). "
        "Each row carries id / name / kind / enabled / "
        "schedule_cron / retention / last_run_status / last_run_at "
        "/ last_run_filename / last_run_bytes / last_run_error / "
        "next_run_at. Use for 'did all my backups succeed last "
        "night?', 'which targets are scheduled?', or 'list failed "
        "backup runs'. Destination credentials are NOT returned; "
        "the ``config`` blob is omitted."
    ),
    args_model=ListBackupTargetsArgs,
    category="admin",
)
async def list_backup_targets(
    db: AsyncSession, user: User, args: ListBackupTargetsArgs
) -> list[dict[str, Any]]:
    gate = _superadmin_gate(user)
    if gate:
        return [gate]
    stmt = select(BackupTarget).order_by(BackupTarget.name.asc())
    if args.enabled_only:
        stmt = stmt.where(BackupTarget.enabled.is_(True))
    if args.kind:
        stmt = stmt.where(BackupTarget.kind == args.kind)
    if args.last_run_status:
        stmt = stmt.where(BackupTarget.last_run_status == args.last_run_status)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(t.id),
            "name": t.name,
            "kind": t.kind,
            "enabled": t.enabled,
            "schedule_cron": t.schedule_cron,
            "retention_keep_last_n": t.retention_keep_last_n,
            "retention_keep_days": t.retention_keep_days,
            "last_run_status": t.last_run_status,
            "last_run_at": (t.last_run_at.isoformat() if t.last_run_at else None),
            "last_run_filename": t.last_run_filename,
            "last_run_bytes": t.last_run_bytes,
            "last_run_duration_ms": t.last_run_duration_ms,
            "last_run_error": t.last_run_error,
            "next_run_at": t.next_run_at.isoformat() if t.next_run_at else None,
            "passphrase_set": bool(t.passphrase_encrypted),
            # #989 — the flag changes four visible behaviours (prune
            # skipped, archive delete 409, pull-mode download 409, drills
            # report cannot_drill). Without it the copilot reads
            # "retention: null, last run: success" and describes a healthy
            # target with no retention, unable to say why its recovery
            # readiness is UNVERIFIED.
            "write_only": t.write_only,
        }
        for t in rows
    ]


# ── list_backup_archives_at_target ────────────────────────────────────


class ListBackupArchivesArgs(BaseModel):
    target: str = Field(
        ...,
        description="Target id (UUID) or name. Names are matched exactly.",
    )
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="list_backup_archives_at_target",
    permission="superadmin",
    description=(
        "List archives currently stored at a specific backup target "
        "(superadmin only). Calls the driver's ``list_archives`` so "
        "the result matches what the Backup admin page's Archives "
        "drawer shows. Returns filename / size_bytes / created_at "
        "newest-first. Use for 'what's on my S3 bucket?' or 'how "
        "many archives are at the corp-vault target?'. Errors from "
        "the destination (auth failed, bucket not found, etc.) are "
        "returned in the response rather than raised."
    ),
    args_model=ListBackupArchivesArgs,
    category="admin",
)
async def list_backup_archives_at_target(
    db: AsyncSession, user: User, args: ListBackupArchivesArgs
) -> dict[str, Any]:
    gate = _superadmin_gate(user)
    if gate:
        return gate
    # Resolve target by id-or-name. Operators using the LLM are more
    # likely to type the name; the id path stays available for
    # programmatic callers.
    stmt = select(BackupTarget)
    target_id = _try_uuid(args.target)
    if target_id is not None:
        stmt = stmt.where(BackupTarget.id == target_id)
    else:
        stmt = stmt.where(BackupTarget.name == args.target)
    target = (await db.execute(stmt)).scalar_one_or_none()
    if target is None:
        return {"error": f"backup target {args.target!r} not found (by id or name)"}

    # Lazy imports to keep the module's top-level cheap on startup.
    from app.services.backup.targets import (  # noqa: PLC0415
        BackupDestinationError,
        SecretFieldError,
        decrypt_config_secrets,
        get_destination,
    )

    try:
        driver = get_destination(target.kind)
        plain_config = decrypt_config_secrets(driver, target.config)
        archives = await driver.list_archives(config=plain_config)
    except SecretFieldError as exc:
        return {
            "error": (
                f"target {target.name!r} has a secret field that can't be "
                f"decrypted with this install's SECRET_KEY: {exc}. The "
                f"target needs to be rotated before it can be used."
            )
        }
    except BackupDestinationError as exc:
        return {
            "error": (
                f"destination at target {target.name!r} ({target.kind}) "
                f"returned an error: {exc}"
            )
        }
    return {
        "target": {
            "id": str(target.id),
            "name": target.name,
            "kind": target.kind,
        },
        "count": len(archives),
        "archives": [
            {
                "filename": a.filename,
                "size_bytes": a.size_bytes,
                "created_at": a.created_at.isoformat(),
            }
            for a in archives[: args.limit]
        ],
    }


# ── find_backup_audit_history ─────────────────────────────────────────


class FindBackupAuditHistoryArgs(BaseModel):
    since_hours: float | None = Field(
        default=24 * 7,
        description=(
            "Only include audit rows newer than N hours ago. Default "
            "= 7 days. None = no lower bound."
        ),
        ge=0.0,
    )
    actions: list[str] | None = Field(
        default=None,
        description=(
            "Filter by audit action. Useful values: backup_created, "
            "backup_target_run_success, backup_target_run_failed, "
            "backup_restored, factory_reset_performed. Default = all "
            "five backup + factory-reset action types."
        ),
    )
    limit: int = Field(default=100, ge=1, le=1000)


_DEFAULT_BACKUP_ACTIONS = (
    "backup_created",
    "backup_target_run_success",
    "backup_target_run_failed",
    "backup_restored",
    "factory_reset_performed",
)


@register_tool(
    name="find_backup_audit_history",
    permission="superadmin",
    description=(
        "Return the recent backup + factory-reset audit history "
        "(superadmin only). Each row carries timestamp / action / "
        "actor / resource_display / result / error_detail / "
        "new_value (operator-readable counters per audit type). Use "
        "for 'when did backup last fail?', 'show me last week's "
        "reset history', or 'who restored on Tuesday?'. Default "
        "window is the last 7 days; cap is 1000 rows."
    ),
    args_model=FindBackupAuditHistoryArgs,
    category="admin",
)
async def find_backup_audit_history(
    db: AsyncSession, user: User, args: FindBackupAuditHistoryArgs
) -> list[dict[str, Any]]:
    gate = _superadmin_gate(user)
    if gate:
        return [gate]
    actions = args.actions or list(_DEFAULT_BACKUP_ACTIONS)
    stmt = select(AuditLog).where(or_(*[AuditLog.action == a for a in actions]))
    if args.since_hours is not None:
        stmt = stmt.where(
            AuditLog.timestamp >= datetime.now(UTC) - timedelta(hours=args.since_hours)
        )
    stmt = stmt.order_by(desc(AuditLog.timestamp)).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(r.id),
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "action": r.action,
            "actor": r.user_display_name,
            "resource_type": r.resource_type,
            "resource_display": r.resource_display,
            "result": r.result,
            "error_detail": r.error_detail,
            "new_value": r.new_value,
        }
        for r in rows
    ]


# ── find_restore_drills ───────────────────────────────────────────────


class FindRestoreDrillsArgs(BaseModel):
    target: str | None = Field(
        default=None,
        description="Restrict to one target — id (UUID) or exact name.",
    )
    state: Literal["running", "passed", "failed", "error", "cannot_drill"] | None = Field(
        default=None,
        description=(
            "Filter by verdict. 'failed' means the archive did not "
            "survive a test restore (a real finding). 'error' means the "
            "drill could not run at all and says nothing about the "
            "archive."
        ),
    )
    failed_only: bool = Field(
        default=False,
        description="Shorthand for state='failed'. Ignored when state is set.",
    )
    since_hours: int | None = Field(
        default=None, ge=1, le=24 * 365, description="Only drills started within this window."
    )
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="find_restore_drills",
    permission="superadmin",
    description=(
        "Return restore-verification drill history (superadmin only). "
        "A drill replays a backup target's newest archive into a "
        "throwaway database and asserts against the result, proving "
        "the archive is actually restorable. Each row carries target / "
        "state / filename / duration / the per-check assertion verdicts "
        "and any error. Use for 'did my backups pass verification?', "
        "'which archive failed its drill?', or 'show me the failed "
        "checks on the corp-vault drill'. Note 'failed' (the archive is "
        "bad) and 'error' (the drill could not run) mean different "
        "things and should not be conflated."
    ),
    args_model=FindRestoreDrillsArgs,
    category="admin",
)
async def find_restore_drills(
    db: AsyncSession, user: User, args: FindRestoreDrillsArgs
) -> list[dict[str, Any]]:
    gate = _superadmin_gate(user)
    if gate:
        return [gate]
    stmt = select(RestoreDrill, BackupTarget.name).join(
        BackupTarget, BackupTarget.id == RestoreDrill.target_id
    )
    if args.target:
        as_uuid = _try_uuid(args.target)
        stmt = stmt.where(
            RestoreDrill.target_id == as_uuid
            if as_uuid is not None
            else BackupTarget.name == args.target
        )
    state = args.state or ("failed" if args.failed_only else None)
    if state:
        stmt = stmt.where(RestoreDrill.state == state)
    if args.since_hours is not None:
        stmt = stmt.where(
            RestoreDrill.started_at >= datetime.now(UTC) - timedelta(hours=args.since_hours)
        )
    stmt = stmt.order_by(desc(RestoreDrill.started_at)).limit(args.limit)
    rows = (await db.execute(stmt)).all()
    return [
        {
            "id": str(d.id),
            "target_id": str(d.target_id),
            "target_name": name,
            "state": d.state,
            "triggered_by": d.triggered_by,
            "filename": d.filename,
            "archive_bytes": d.archive_bytes,
            "assertions": d.assertions or [],
            "error": d.error,
            "started_at": d.started_at.isoformat() if d.started_at else None,
            "finished_at": d.finished_at.isoformat() if d.finished_at else None,
            "duration_ms": d.duration_ms,
        }
        for d, name in rows
    ]


# ── get_restore_drill_readiness ───────────────────────────────────────


class RestoreDrillReadinessArgs(BaseModel):
    pass


@register_tool(
    name="get_restore_drill_readiness",
    permission="superadmin",
    description=(
        "One-shot recovery-readiness rollup across every backup target "
        "(superadmin only). Per target: whether drills are scheduled, "
        "the latest verdict, when it last passed, and how stale that "
        "proof is. Answers the question an operator actually cares "
        "about — 'can I currently restore this install, and how do I "
        "know?' — without reading the whole drill history. Targets "
        "that proof is. A target that has never passed a drill is "
        "reported as unverified rather than healthy — an untested "
        "backup is an unknown, not a pass — while a target whose most "
        "recent drill merely errored (destination unreachable) keeps "
        "its previous verdict, because an error disproves nothing."
    ),
    args_model=RestoreDrillReadinessArgs,
    category="admin",
)
async def get_restore_drill_readiness(
    db: AsyncSession, user: User, args: RestoreDrillReadinessArgs
) -> dict[str, Any]:
    gate = _superadmin_gate(user)
    if gate:
        return gate
    # Shared with the REST readiness endpoint and the admin UI so all
    # three give the same answer to the same question.
    from app.services.backup.drill import compute_drill_readiness  # noqa: PLC0415

    out = await compute_drill_readiness(db)
    verified = sum(1 for r in out if r["verified"])
    return {
        "targets": out,
        "total_targets": len(out),
        "verified_targets": verified,
        "unverified_targets": len(out) - verified,
    }


# ── get_backup_health ─────────────────────────────────────────────────


class BackupHealthArgs(BaseModel):
    problems_only: bool = Field(
        default=False,
        description="When True, return only targets that are failed, stale or stuck.",
    )


@register_tool(
    name="get_backup_health",
    permission="superadmin",
    description=(
        "Per backup target: is its schedule actually producing backups? "
        "(superadmin only). Each row carries state (ok / failed / stale / "
        "stuck / running / awaiting_first_run / manual_only / disabled), "
        "last_run_status, last_run_at, last_success_at, next_run_at and "
        "stale_after (when it goes stale without a success). Decided by "
        "the same function as the backup_failed and backup_stale alerts, "
        "so the answer matches what they fire on. 'stuck' means a run has "
        "been in progress so long its process is presumed dead. Use for "
        "'are my backups healthy?', 'when did the corp-vault target last "
        "succeed?' or 'why is the backup_stale alert firing?'. No "
        "destination config or credentials are returned."
    ),
    args_model=BackupHealthArgs,
    category="admin",
)
async def get_backup_health(db: AsyncSession, user: User, args: BackupHealthArgs) -> dict[str, Any]:
    gate = _superadmin_gate(user)
    if gate:
        return gate
    from app.models.alerts import AlertRule  # noqa: PLC0415
    from app.services.alerts import RULE_TYPE_BACKUP_STALE  # noqa: PLC0415
    from app.services.backup.health import (  # noqa: PLC0415
        STALE_AFTER_RUNS_DEFAULT,
        evaluate_backup_health,
    )

    # Use the stale threshold the alert rule is configured with, so the
    # tool and the alert agree on what "stale" means on this install.
    rule = await db.scalar(
        select(AlertRule).where(AlertRule.rule_type == RULE_TYPE_BACKUP_STALE).limit(1)
    )
    runs = (rule.threshold_percent if rule is not None else None) or STALE_AFTER_RUNS_DEFAULT
    rows = await evaluate_backup_health(db, now=datetime.now(UTC), stale_after_runs=runs)
    targets = [h.as_dict() for h in rows]
    if args.problems_only:
        targets = [t for t in targets if t["state"] in ("failed", "stale", "stuck")]
    return {
        "stale_after_runs": runs,
        "targets": targets,
        "failed": sum(1 for h in rows if h.failed),
        "stale": sum(1 for h in rows if h.stale),
    }
