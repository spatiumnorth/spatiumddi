"""Findings: what the model may return, and what becomes of it (#4405).

The model's reply is untrusted text. Before any of it is stored:

1. it has to parse as JSON and match :class:`FindingDraft`;
2. every evidence reference is checked against the database
   (``evidence.verify_refs``); references that do not hold are removed,
   and a finding left with none is dropped and counted;
3. the fingerprint (kind + the sorted subjects of its evidence) is
   compared with the live findings: a match is updated, not filed again;
4. a muted fingerprint is not filed at all.

:func:`close_cleared` is the other half of the lifecycle. It needs no
model: a live finding closes when every detector that supported it has
stopped reporting.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field, ValidationError, field_validator
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_watch import (
    FINDING_ACTIVE_STATES,
    FINDING_CONFIDENCES,
    FINDING_KINDS,
    FINDING_OPEN,
    FINDING_RESOLVED,
    FINDING_SEVERITIES,
    AIFinding,
    AIFindingMute,
    AIWatchRun,
)
from app.models.audit import AuditLog
from app.models.auth import User
from app.services.ai.watch import evidence as ev
from app.services.ai.watch.principal import AUDIT_VIA

# How many findings one run may file or update. A reply with more is cut
# here; the point of Watch is a few findings, not a second alert list.
MAX_FINDINGS_PER_RUN = 20
MAX_RECOMMENDATIONS = 8
_TITLE_CAP = 255
_EXPLANATION_CAP = 4000
_RECOMMENDATION_CAP = 500

# A finding resting only on audit rows has nothing that can clear, so it
# closes once no run has reported it for this long.
AUDIT_ONLY_TTL = timedelta(hours=24)


class FindingDraft(BaseModel):
    """One finding as the model returns it."""

    model_config = {"extra": "ignore"}

    # Set by the model when it is updating a finding it was shown.
    finding_id: str | None = None
    kind: str = "other"
    severity: str
    title: str = Field(min_length=1)
    explanation: str = ""
    evidence: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    confidence: str = "medium"

    @field_validator("kind", mode="before")
    @classmethod
    def _kind(cls, v: Any) -> str:
        v = str(v or "").strip().lower()
        return v if v in FINDING_KINDS else "other"

    @field_validator("confidence", mode="before")
    @classmethod
    def _confidence(cls, v: Any) -> str:
        v = str(v or "").strip().lower()
        return v if v in FINDING_CONFIDENCES else "medium"

    @field_validator("severity", mode="before")
    @classmethod
    def _severity(cls, v: Any) -> str:
        v = str(v or "").strip().lower()
        if v not in FINDING_SEVERITIES:
            raise ValueError(f"severity must be one of {list(FINDING_SEVERITIES)}")
        return v

    @field_validator("title", mode="before")
    @classmethod
    def _title(cls, v: Any) -> str:
        return str(v or "").strip()[:_TITLE_CAP]

    @field_validator("explanation", mode="before")
    @classmethod
    def _explanation(cls, v: Any) -> str:
        return str(v or "").strip()[:_EXPLANATION_CAP]

    @field_validator("evidence", "recommendations", mode="before")
    @classmethod
    def _str_list(cls, v: Any) -> list[str]:
        if not isinstance(v, list):
            return []
        return [str(x).strip() for x in v if isinstance(x, str | int) and str(x).strip()]

    @field_validator("recommendations")
    @classmethod
    def _recommendations(cls, v: list[str]) -> list[str]:
        return [r[:_RECOMMENDATION_CAP] for r in v[:MAX_RECOMMENDATIONS]]


class OutputError(ValueError):
    """The model's reply is not the JSON document it was asked for."""


_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def _load_json(text: str) -> Any:
    text = text.strip()
    candidates = [text]
    candidates.extend(m.group(1).strip() for m in _FENCE.finditer(text))
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        candidates.append(text[start : end + 1])
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    raise OutputError("the reply is not JSON")


def parse_output(text: str) -> tuple[list[FindingDraft], int]:
    """Parse a model reply into drafts.

    Returns ``(drafts, invalid)`` where ``invalid`` counts entries of the
    ``findings`` list that did not match the schema (no title, an unknown
    severity ...). Raises :class:`OutputError` when the reply as a whole
    is unusable: not JSON, or no ``findings`` list.
    """
    data = _load_json(text)
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise OutputError('the reply has no "findings" list')
    drafts: list[FindingDraft] = []
    invalid = 0
    for raw in data["findings"]:
        try:
            drafts.append(FindingDraft.model_validate(raw))
        except ValidationError:
            invalid += 1
    return drafts, invalid


def fingerprint(kind: str, items: list[ev.EvidenceItem]) -> str:
    """Stable identity of a finding: its kind and what it is about.

    Built from the subjects of the detector evidence, not from event ids,
    so an alert that resolves and fires again, or a conformity check
    re-evaluated on the next pass, leaves it unchanged. A finding with
    only audit evidence falls back to the audit rows' subjects.
    """
    subjects = {i.subject for i in items if i.type in ev.DETECTOR_TYPES}
    if not subjects:
        subjects = {i.subject for i in items}
    payload = "v1|" + kind + "|" + "|".join(sorted(subjects))
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass
class ApplyResult:
    opened: int = 0
    updated: int = 0
    dropped: int = 0
    muted: int = 0
    touched: list[uuid.UUID] = field(default_factory=list)
    # ``[{title, reason, refs}]`` for the run transcript.
    notes: list[dict[str, Any]] = field(default_factory=list)


async def _active_mutes(db: AsyncSession, now: datetime) -> set[str]:
    rows = await db.execute(
        select(AIFindingMute.fingerprint).where(
            or_(AIFindingMute.until.is_(None), AIFindingMute.until > now)
        )
    )
    return {fp for (fp,) in rows.all()}


def _audit(principal: User, action: str, finding: AIFinding, new_value: dict[str, Any]) -> AuditLog:
    return AuditLog(
        user_id=principal.id,
        user_display_name=principal.display_name,
        auth_source=principal.auth_source,
        action=action,
        resource_type="ai_finding",
        resource_id=str(finding.id),
        resource_display=finding.title,
        new_value={**new_value, "via": AUDIT_VIA},
    )


async def apply_drafts(
    db: AsyncSession,
    *,
    principal: User,
    run: AIWatchRun,
    drafts: list[FindingDraft],
    model: str,
    now: datetime,
) -> ApplyResult:
    """Validate ``drafts`` against the database and file what survives.

    Flushes; the caller commits.
    """
    out = ApplyResult()
    muted = await _active_mutes(db, now)
    active = {
        f.id: f
        for f in (
            await db.execute(select(AIFinding).where(AIFinding.state.in_(FINDING_ACTIVE_STATES)))
        )
        .scalars()
        .all()
    }
    by_fingerprint = {f.fingerprint: f for f in active.values()}

    for draft in drafts[:MAX_FINDINGS_PER_RUN]:
        items, bad = await ev.verify_refs(db, principal, draft.evidence)
        if not items:
            out.dropped += 1
            out.notes.append(
                {"title": draft.title, "reason": "no evidence that exists", "refs": bad}
            )
            continue

        target: AIFinding | None = None
        if draft.finding_id:
            try:
                target = active.get(uuid.UUID(draft.finding_id))
            except ValueError:
                target = None
        fp = target.fingerprint if target is not None else fingerprint(draft.kind, items)
        if target is None:
            target = by_fingerprint.get(fp)

        if target is None and fp in muted:
            out.muted += 1
            out.notes.append({"title": draft.title, "reason": "muted", "refs": []})
            continue

        stored = [i.stored() for i in items]
        if target is not None:
            if target.id in out.touched:
                # A second draft about a finding already handled this run.
                continue
            target.severity = draft.severity
            target.title = draft.title
            target.explanation = draft.explanation
            target.evidence = stored
            target.recommendations = draft.recommendations
            target.confidence = draft.confidence
            target.last_seen_at = now
            target.run_id = run.id
            target.model = model
            out.updated += 1
            out.touched.append(target.id)
            continue

        finding = AIFinding(
            fingerprint=fp,
            kind=draft.kind,
            severity=draft.severity,
            title=draft.title,
            explanation=draft.explanation,
            evidence=stored,
            recommendations=draft.recommendations,
            confidence=draft.confidence,
            state=FINDING_OPEN,
            first_seen_at=now,
            last_seen_at=now,
            run_id=run.id,
            model=model,
        )
        db.add(finding)
        await db.flush()
        db.add(
            _audit(
                principal,
                "create",
                finding,
                {
                    "kind": finding.kind,
                    "severity": finding.severity,
                    "evidence": [i.ref for i in items],
                    "run_id": str(run.id),
                },
            )
        )
        active[finding.id] = finding
        by_fingerprint[fp] = finding
        out.opened += 1
        out.touched.append(finding.id)

    await db.flush()
    return out


async def close_cleared(db: AsyncSession, *, principal: User | None, now: datetime) -> int:
    """Resolve live findings whose evidence has cleared. Returns how many.

    A finding closes when none of its detector evidence still reports a
    problem. One that rests only on audit rows closes when no run has
    reported it for :data:`AUDIT_ONLY_TTL`. Each close is audited.
    """
    rows = (
        (await db.execute(select(AIFinding).where(AIFinding.state.in_(FINDING_ACTIVE_STATES))))
        .scalars()
        .all()
    )
    closed = 0
    for finding in rows:
        refreshed = await ev.refresh(db, list(finding.evidence or []))
        detectors = [e for e in refreshed if e.get("type") in ev.DETECTOR_TYPES]
        if detectors:
            done = all(e.get("cleared") for e in detectors)
            why = "evidence cleared"
        else:
            done = finding.last_seen_at <= now - AUDIT_ONLY_TTL
            why = "not reported again"
        if refreshed != list(finding.evidence or []):
            finding.evidence = refreshed
        if not done:
            continue
        previous = finding.state
        finding.state = FINDING_RESOLVED
        finding.resolved_at = now
        finding.state_changed_at = now
        finding.state_changed_by_user_id = None
        db.add(
            AuditLog(
                user_id=principal.id if principal is not None else None,
                user_display_name=principal.display_name if principal is not None else "<system>",
                auth_source=principal.auth_source if principal is not None else "system",
                action="resolve",
                resource_type="ai_finding",
                resource_id=str(finding.id),
                resource_display=finding.title,
                old_value={"state": previous},
                new_value={"state": FINDING_RESOLVED, "reason": why, "via": AUDIT_VIA},
            )
        )
        closed += 1
    if closed:
        await db.flush()
    return closed


__all__ = [
    "AUDIT_ONLY_TTL",
    "ApplyResult",
    "FindingDraft",
    "MAX_FINDINGS_PER_RUN",
    "OutputError",
    "apply_drafts",
    "close_cleared",
    "fingerprint",
    "parse_output",
]
