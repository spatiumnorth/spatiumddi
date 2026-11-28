"""Per-target reconcile for the commercial-DDI mirror (#4729).

Pulls every kind from the provider into ``ddi_mirror_object``, keyed on
``(target, kind, source_ref)`` so repeated pulls update rather than duplicate.
Strictly read-only toward the source, and writes nothing outside the mirror
store: live IPAM / DNS / DHCP rows are never touched.

Failure handling is per kind. An auth failure (401 / 403) aborts the run —
every remaining call would fail the same way. Any other failure on one kind is
recorded in the report and the run continues; that kind's rows are left as they
were (never swept on the strength of a pull that did not complete), and the run
finishes with a warning instead of an error.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_str
from app.models.audit import AuditLog
from app.models.ddi_mirror import DDIMirrorObject, DDIMirrorTarget
from app.services.ddi_mirror.base import (
    DDIProviderError,
    ProviderConfig,
    SourceObject,
)
from app.services.ddi_mirror.registry import get_provider_class

logger = structlog.get_logger(__name__)

# Keep the persisted report small: examples only, the counts are exact.
_MAX_UNMAPPED_EXAMPLES = 25


@dataclass
class KindReport:
    fetched: int = 0
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    deleted: int = 0
    unmapped: int = 0
    complete: bool = True
    error: str | None = None


@dataclass
class MirrorSummary:
    ok: bool = False
    error: str | None = None
    warning: str | None = None
    version: str | None = None
    object_count: int = 0
    kinds: dict[str, KindReport] = field(default_factory=dict)
    unmapped_examples: list[str] = field(default_factory=list)

    def report(self) -> dict[str, Any]:
        """The JSON persisted as ``DDIMirrorTarget.last_report``."""
        return {
            "kinds": {k: asdict(v) for k, v in self.kinds.items()},
            "unmapped_examples": self.unmapped_examples,
            "unmapped_total": sum(v.unmapped for v in self.kinds.values()),
        }


def _config(target: DDIMirrorTarget, password: str, transport: Any = None) -> ProviderConfig:
    return ProviderConfig(
        base_url=target.base_url,
        api_version=target.api_version,
        username=target.username,
        password=password,
        verify_tls=target.verify_tls,
        ca_bundle_pem=target.ca_bundle_pem or "",
        network_view=target.network_view,
        dns_view=target.dns_view,
        page_size=target.page_size,
        transport=transport,
    )


def _same(row: DDIMirrorObject, o: SourceObject) -> bool:
    return (
        row.name == o.name
        and row.view == o.view
        and row.value == o.value
        and row.comment == o.comment
        and row.data == o.data
    )


async def _apply_kind(
    db: AsyncSession,
    target_id: Any,
    kind: str,
    objects: list[SourceObject],
    complete: bool,
    rep: KindReport,
) -> None:
    existing = {
        r.source_ref: r
        for r in (
            await db.execute(
                select(DDIMirrorObject).where(
                    DDIMirrorObject.target_id == target_id, DDIMirrorObject.kind == kind
                )
            )
        )
        .scalars()
        .all()
    }
    seen: set[str] = set()
    for o in objects:
        seen.add(o.source_ref)
        row = existing.get(o.source_ref)
        if row is None:
            db.add(
                DDIMirrorObject(
                    target_id=target_id,
                    kind=kind,
                    source_ref=o.source_ref,
                    name=o.name,
                    view=o.view,
                    value=o.value,
                    comment=o.comment,
                    data=o.data,
                )
            )
            rep.created += 1
        elif _same(row, o):
            rep.unchanged += 1
        else:
            row.name, row.view, row.value = o.name, o.view, o.value
            row.comment, row.data = o.comment, o.data
            rep.updated += 1
    if complete:
        for ref, row in existing.items():
            if ref not in seen:
                await db.delete(row)
                rep.deleted += 1
    await db.flush()


async def reconcile_target(
    db: AsyncSession, target: DDIMirrorTarget, *, transport: Any = None
) -> MirrorSummary:
    summary = MirrorSummary()
    target_id, target_name = target.id, target.name

    password = ""
    if target.password_encrypted:
        try:
            password = decrypt_str(target.password_encrypted)
        except ValueError as exc:
            summary.error = f"password decrypt failed: {exc}"
    if not password and summary.error is None:
        summary.error = "no password configured"
    if summary.error is None:
        try:
            provider_cls = get_provider_class(target.vendor)
        except ValueError as exc:
            summary.error = str(exc)
    if summary.error is not None:
        await _fail(db, target, summary)
        return summary

    try:
        async with provider_cls(_config(target, password, transport)) as provider:
            info = await provider.probe()
            summary.version = info.version
            for kind in provider.kinds:
                rep = summary.kinds.setdefault(kind, KindReport())
                try:
                    fetched = await provider.fetch(kind)
                except DDIProviderError as exc:
                    if exc.is_auth:
                        raise
                    rep.error = str(exc)
                    continue
                rep.fetched = len(fetched.objects)
                rep.unmapped = len(fetched.unmapped)
                rep.complete = fetched.complete
                room = _MAX_UNMAPPED_EXAMPLES - len(summary.unmapped_examples)
                summary.unmapped_examples += [f"{kind}: {m}" for m in fetched.unmapped[:room]]
                await _apply_kind(db, target_id, kind, fetched.objects, fetched.complete, rep)
    except DDIProviderError as exc:
        summary.error = str(exc)
        await db.rollback()
        target = await db.get(DDIMirrorTarget, target_id, populate_existing=True)  # type: ignore[assignment]
        if target is not None:
            await _fail(db, target, summary)
        return summary

    problems = [f"{k}: {r.error}" for k, r in summary.kinds.items() if r.error]
    problems += [
        f"{k}: stopped at the object cap" for k, r in summary.kinds.items() if not r.complete
    ]
    summary.warning = "; ".join(problems)[:1000] or None
    summary.object_count = sum(r.fetched for r in summary.kinds.values())

    target.last_synced_at = datetime.now(UTC)
    target.last_sync_error = None
    target.last_sync_warning = summary.warning
    target.source_version = summary.version
    target.object_count = summary.object_count
    target.last_report = summary.report()
    db.add(
        AuditLog(
            user_display_name="system",
            auth_source="system",
            action="ddi_mirror.reconcile",
            resource_type="ddi_mirror_target",
            resource_id=str(target_id),
            resource_display=target_name,
            new_value={
                "objects": summary.object_count,
                "created": sum(r.created for r in summary.kinds.values()),
                "updated": sum(r.updated for r in summary.kinds.values()),
                "deleted": sum(r.deleted for r in summary.kinds.values()),
                "warning": summary.warning,
            },
        )
    )
    await db.commit()
    summary.ok = True
    logger.info(
        "ddi_mirror_reconcile_ok",
        target=str(target_id),
        vendor=target.vendor,
        objects=summary.object_count,
    )
    return summary


async def _fail(db: AsyncSession, target: DDIMirrorTarget, summary: MirrorSummary) -> None:
    """Record a failed run on the target and in the error audit the dashboards read."""
    target.last_synced_at = datetime.now(UTC)
    target.last_sync_error = summary.error
    db.add(
        AuditLog(
            user_display_name="system",
            auth_source="system",
            action="ddi_mirror.reconcile",
            resource_type="ddi_mirror_target",
            resource_id=str(target.id),
            resource_display=target.name,
            result="error",
            error_detail=summary.error,
        )
    )
    await db.commit()
    logger.warning("ddi_mirror_reconcile_failed", target=str(target.id), error=summary.error)


__all__ = ["KindReport", "MirrorSummary", "reconcile_target"]
