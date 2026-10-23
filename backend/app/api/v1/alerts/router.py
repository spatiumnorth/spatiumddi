"""Alerts CRUD router.

Two surfaces:

* ``/alerts/rules`` — CRUD for AlertRule definitions.
* ``/alerts/events`` — read-only event history (open + resolved).
  Evaluator-driven; operators don't create events directly.

Permissions: CRUD on rules requires superadmin (alert rules can fan
notifications to SIEMs, so gating the knob tight). Reading events +
the evaluator's "force evaluate now" action is open to any
authenticated user — matches the existing "logs surface" pattern.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import delete, select, update

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.core.update_nulls import resolve_update_changes
from app.models.alerts import AlertEvent, AlertRule
from app.models.audit import AuditLog
from app.services import alerts as alert_service
from app.services.alert_rule_catalogue import RuleTypeSpec, build_catalogue

router = APIRouter()


# ── Schemas ────────────────────────────────────────────────────────────────


_SEVERITIES = frozenset({"info", "warning", "critical"})
_SERVER_TYPES = frozenset({"dns", "dhcp", "any"})


class AlertRuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str = Field("", max_length=1000)
    enabled: bool = True
    rule_type: str
    threshold_percent: int | None = None
    threshold_days: int | None = None
    # ``dhcp_pool_exhaustion`` absolute free-address floor (issue #339).
    min_free_addresses: int | None = None
    server_type: str | None = None
    # ``compliance_change`` params — see issue #105.
    classification: str | None = None
    change_scope: str | None = None
    severity: str = "warning"
    notify_syslog: bool = True
    notify_webhook: bool = True
    notify_smtp: bool = False

    @field_validator("rule_type")
    @classmethod
    def _v_type(cls, v: str) -> str:
        if v not in alert_service.RULE_TYPES:
            raise ValueError(
                f"rule_type must be one of: {', '.join(sorted(alert_service.RULE_TYPES))}"
            )
        return v

    @field_validator("severity")
    @classmethod
    def _v_sev(cls, v: str) -> str:
        if v not in _SEVERITIES:
            raise ValueError(f"severity must be one of: {', '.join(sorted(_SEVERITIES))}")
        return v

    @field_validator("server_type")
    @classmethod
    def _v_srv(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in _SERVER_TYPES:
            raise ValueError(f"server_type must be one of: {', '.join(sorted(_SERVER_TYPES))}")
        return v

    @field_validator("threshold_percent")
    @classmethod
    def _v_thr(cls, v: int | None) -> int | None:
        if v is None:
            return None
        if not (0 <= v <= 100):
            raise ValueError("threshold_percent must be 0..100")
        return v

    @field_validator("threshold_days")
    @classmethod
    def _v_thr_days(cls, v: int | None) -> int | None:
        if v is None:
            return None
        # Floor at 1 — anything ≤0 turns the rule into a trivial
        # "fires forever" predicate. Ceiling at 3650 (10 y) is just
        # a sanity bound; long-lived domains rarely care about
        # multi-year alerts.
        if not (1 <= v <= 3650):
            raise ValueError("threshold_days must be 1..3650")
        return v

    @field_validator("min_free_addresses")
    @classmethod
    def _v_min_free(cls, v: int | None) -> int | None:
        if v is None:
            return None
        if v < 1:
            raise ValueError("min_free_addresses must be ≥ 1")
        return v

    @field_validator("classification")
    @classmethod
    def _v_classification(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in alert_service.COMPLIANCE_CLASSIFICATIONS:
            raise ValueError(
                "classification must be one of: "
                f"{', '.join(sorted(alert_service.COMPLIANCE_CLASSIFICATIONS))}"
            )
        return v

    @field_validator("change_scope")
    @classmethod
    def _v_change_scope(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in alert_service.COMPLIANCE_CHANGE_SCOPES:
            raise ValueError(
                "change_scope must be one of: "
                f"{', '.join(sorted(alert_service.COMPLIANCE_CHANGE_SCOPES))}"
            )
        return v

    @model_validator(mode="after")
    def _v_compliance_requires_classification(self) -> AlertRuleCreate:
        # #1580 — a compliance_change rule without a classification
        # can never fire; the evaluator just warned every tick.
        if self.rule_type == alert_service.RULE_TYPE_COMPLIANCE_CHANGE and not self.classification:
            raise ValueError("classification is required for compliance_change rules")
        return self


# Update-body fields by column nullability (#1987). Keep in step with
# ``AlertRule`` — a NOT NULL column missing from the first set is a 500.
_RULE_NON_NULLABLE_FIELDS = (
    "name",
    "description",
    "enabled",
    "severity",
    "notify_syslog",
    "notify_webhook",
    "notify_smtp",
)
_RULE_CLEARABLE_FIELDS = (
    "threshold_percent",
    "threshold_days",
    "min_free_addresses",
    "server_type",
    "classification",
    "change_scope",
)


class AlertRuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    threshold_percent: int | None = None
    threshold_days: int | None = None
    min_free_addresses: int | None = None
    server_type: str | None = None
    classification: str | None = None
    change_scope: str | None = None
    severity: str | None = None
    notify_syslog: bool | None = None
    notify_webhook: bool | None = None
    notify_smtp: bool | None = None

    @field_validator("severity")
    @classmethod
    def _v_sev(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in _SEVERITIES:
            raise ValueError(f"severity must be one of: {', '.join(sorted(_SEVERITIES))}")
        return v

    @field_validator("server_type")
    @classmethod
    def _v_srv(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in _SERVER_TYPES:
            raise ValueError(f"server_type must be one of: {', '.join(sorted(_SERVER_TYPES))}")
        return v

    @field_validator("threshold_percent")
    @classmethod
    def _v_thr(cls, v: int | None) -> int | None:
        if v is None:
            return None
        if not (0 <= v <= 100):
            raise ValueError("threshold_percent must be 0..100")
        return v

    @field_validator("threshold_days")
    @classmethod
    def _v_thr_days(cls, v: int | None) -> int | None:
        if v is None:
            return None
        if not (1 <= v <= 3650):
            raise ValueError("threshold_days must be 1..3650")
        return v

    @field_validator("min_free_addresses")
    @classmethod
    def _v_min_free(cls, v: int | None) -> int | None:
        if v is None:
            return None
        if v < 1:
            raise ValueError("min_free_addresses must be ≥ 1")
        return v

    @field_validator("classification")
    @classmethod
    def _v_classification(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in alert_service.COMPLIANCE_CLASSIFICATIONS:
            raise ValueError(
                "classification must be one of: "
                f"{', '.join(sorted(alert_service.COMPLIANCE_CLASSIFICATIONS))}"
            )
        return v

    @field_validator("change_scope")
    @classmethod
    def _v_change_scope(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in alert_service.COMPLIANCE_CHANGE_SCOPES:
            raise ValueError(
                "change_scope must be one of: "
                f"{', '.join(sorted(alert_service.COMPLIANCE_CHANGE_SCOPES))}"
            )
        return v


class AlertRuleResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    enabled: bool
    rule_type: str
    threshold_percent: int | None
    threshold_days: int | None
    min_free_addresses: int | None
    server_type: str | None
    classification: str | None
    change_scope: str | None
    last_scanned_audit_at: datetime | None
    severity: str
    notify_syslog: bool
    notify_webhook: bool
    notify_smtp: bool
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}


class AlertEventResponse(BaseModel):
    id: uuid.UUID
    rule_id: uuid.UUID
    subject_type: str
    subject_id: str
    subject_display: str
    severity: str
    message: str
    fired_at: datetime
    resolved_at: datetime | None
    delivered_syslog: bool
    delivered_webhook: bool
    delivered_smtp: bool
    last_observed_value: dict[str, Any] | None

    model_config = {"from_attributes": True}


class EvaluateResponse(BaseModel):
    opened: int
    resolved: int
    delivered_syslog: int
    delivered_webhook: int
    delivered_smtp: int


# ── Rules ──────────────────────────────────────────────────────────────────


@router.get("/rules", response_model=list[AlertRuleResponse])
async def list_rules(db: DB, current_user: CurrentUser) -> list[AlertRule]:
    res = await db.execute(select(AlertRule).order_by(AlertRule.name))
    return list(res.scalars().all())


@router.get("/rule-types", response_model=list[RuleTypeSpec])
async def list_rule_types(db: DB, current_user: CurrentUser) -> list[RuleTypeSpec]:
    """Every rule type, its label, and the parameters its evaluator reads (#1997).

    Same access as listing rules: any authenticated user. The editor renders
    from this instead of a hand-kept list that had drifted to 23 of ~64.

    A type whose feature module is off is left out (#2130): the evaluator
    never runs it (``_RULE_TYPE_MODULE``), so offering it would let an
    operator create a rule that can never fire. Rules already stored keep
    working and stay listed by ``GET /rules``.
    """
    from app.services import feature_modules

    enabled = await feature_modules.get_enabled_modules(db)
    return [
        spec
        for spec in build_catalogue()
        if (mod := alert_service.rule_type_module(spec.rule_type)) is None or mod in enabled
    ]


@router.post("/rules", response_model=AlertRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(body: AlertRuleCreate, db: DB, current_user: SuperAdmin) -> AlertRule:
    rule = AlertRule(**body.model_dump())
    db.add(rule)
    await db.flush()  # column-default id must exist before the audit row reads it (#2006)
    db.add(
        AuditLog(
            action="create",
            resource_type="alert_rule",
            resource_id=str(rule.id),
            resource_display=body.name,
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
            new_value={
                "name": body.name,
                "rule_type": body.rule_type,
                "enabled": body.enabled,
            },
        )
    )
    await db.commit()
    await db.refresh(rule)
    return rule


@router.get("/rules/{rule_id}", response_model=AlertRuleResponse)
async def get_rule(rule_id: uuid.UUID, db: DB, current_user: CurrentUser) -> AlertRule:
    rule = await db.get(AlertRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.patch("/rules/{rule_id}", response_model=AlertRuleResponse)
async def update_rule(
    rule_id: uuid.UUID, body: AlertRuleUpdate, db: DB, current_user: SuperAdmin
) -> AlertRule:
    rule = await db.get(AlertRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    # #1580 — reject an update that leaves a compliance_change rule
    # without a classification (e.g. explicitly clearing it); such a
    # rule can never fire. rule_type isn't updatable, so check the
    # stored type against the merged classification.
    effective_classification = (
        body.classification if "classification" in body.model_fields_set else rule.classification
    )
    if rule.rule_type == alert_service.RULE_TYPE_COMPLIANCE_CHANGE and not effective_classification:
        raise HTTPException(
            status_code=422,
            detail="classification is required for compliance_change rules",
        )
    # #1987 — an explicit null for a NOT NULL column is a 422 naming the
    # field, not the 500 Postgres' 23502 became. The nullable columns
    # (thresholds, server_type, classification, change_scope) stay
    # clearable, as they were.
    changes = resolve_update_changes(
        body,
        clearable=_RULE_CLEARABLE_FIELDS,
        non_nullable=_RULE_NON_NULLABLE_FIELDS,
    )
    changed: dict[str, Any] = {}
    for field, value in changes.items():
        old = getattr(rule, field)
        if old != value:
            changed[field] = {"old": old, "new": value}
            setattr(rule, field, value)
    # #1988 — disabling a rule closes what it still has open. The
    # evaluator only visits enabled rules, so nothing would ever resolve
    # these: a dashboard counting an alert whose condition may be long
    # gone. Recorded in the same audit row as the disable. Keyed on the
    # request (``enabled: false`` sent), not on the column flipping, so a
    # rule disabled before this fix — whose events are stuck open — can
    # be cleared by sending the disable again. Resolution is silent, as
    # the evaluator's own resolve is: no delivery fires for a close.
    if changes.get("enabled") is False:
        closed = await db.execute(
            update(AlertEvent)
            .where(AlertEvent.rule_id == rule.id, AlertEvent.resolved_at.is_(None))
            .values(resolved_at=datetime.now(UTC))
        )
        closed_count = closed.rowcount or 0
        if closed_count:
            changed["resolved_open_events"] = {"old": closed_count, "new": 0}
    if changed:
        db.add(
            AuditLog(
                action="update",
                resource_type="alert_rule",
                resource_id=str(rule.id),
                resource_display=rule.name,
                user_id=current_user.id,
                user_display_name=current_user.username,
                result="success",
                changed_fields=list(changed.keys()),
                new_value=changed,
            )
        )
    await db.commit()
    await db.refresh(rule)
    return rule


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: uuid.UUID, db: DB, current_user: SuperAdmin) -> None:
    rule = await db.get(AlertRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    name = rule.name
    db.add(
        AuditLog(
            action="delete",
            resource_type="alert_rule",
            resource_id=str(rule.id),
            resource_display=name,
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
        )
    )
    await db.execute(delete(AlertRule).where(AlertRule.id == rule_id))
    await db.commit()


# ── Events ─────────────────────────────────────────────────────────────────


@router.get("/events", response_model=list[AlertEventResponse])
async def list_events(
    db: DB,
    current_user: CurrentUser,
    open_only: bool = Query(False, description="Only return events with resolved_at IS NULL"),
    rule_id: uuid.UUID | None = Query(None),
    # Per-resource filters (#917). Events have always carried the subject they
    # fired about; without these a "alerts for this subnet" panel had to pull
    # up to 1000 events and filter client-side, which silently truncates on a
    # noisy install — the one where the panel matters most.
    subject_type: str | None = Query(
        None,
        max_length=64,
        description="Exact subject type, e.g. 'subnet', 'dns_server', 'dhcp_pool'.",
    ),
    subject_id: str | None = Query(
        None,
        max_length=255,
        description="Exact subject id. Usually paired with subject_type.",
    ),
    severity: str | None = Query(None, max_length=32, description="Exact severity match."),
    limit: int = Query(200, ge=1, le=1000),
) -> list[AlertEvent]:
    q = select(AlertEvent).order_by(AlertEvent.fired_at.desc()).limit(limit)
    if open_only:
        q = q.where(AlertEvent.resolved_at.is_(None))
    if rule_id:
        q = q.where(AlertEvent.rule_id == rule_id)
    if subject_type:
        q = q.where(AlertEvent.subject_type == subject_type)
    if subject_id:
        q = q.where(AlertEvent.subject_id == subject_id)
    if severity:
        q = q.where(AlertEvent.severity == severity)
    res = await db.execute(q)
    return list(res.scalars().all())


@router.post("/events/{event_id}/resolve", response_model=AlertEventResponse)
async def resolve_event(event_id: uuid.UUID, db: DB, current_user: SuperAdmin) -> AlertEvent:
    """Manually mark an event resolved. Useful to silence a known-good
    alert while the underlying metric is still above threshold.

    Superadmin only, like the rule writes: for transition-once rules a
    resolve dismisses the signal for good. Audited.
    """
    event = await db.get(AlertEvent, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    if event.resolved_at is None:
        event.resolved_at = datetime.now(UTC)
        # Reassign, not mutate: JSONB isn't change-tracked in place. The
        # evaluator keeps a manually resolved event resolved while its
        # subject still matches (#2498).
        event.last_observed_value = {
            **(event.last_observed_value or {}),
            "resolved_by": alert_service.MANUAL_RESOLVED_BY,
        }
        db.add(
            AuditLog(
                action="resolve",
                resource_type="alert_event",
                resource_id=str(event.id),
                resource_display=event.subject_display,
                user_id=current_user.id,
                user_display_name=current_user.username,
                result="success",
                new_value={"rule_id": str(event.rule_id), "subject_type": event.subject_type},
            )
        )
    await db.commit()
    await db.refresh(event)
    return event


# ── Force-evaluate ─────────────────────────────────────────────────────────


@router.post("/evaluate", response_model=EvaluateResponse)
async def evaluate_now(db: DB, current_user: SuperAdmin) -> EvaluateResponse:
    """Run the evaluator pass immediately.

    Handy for "did that rule I just created fire?" workflows — skips
    waiting for the 60 s Celery tick. Same semantics as the scheduled
    run, just synchronous. Superadmin only: a pass delivers to the
    configured syslog / webhook / SMTP targets.
    """
    result = await alert_service.evaluate_all(db)
    return EvaluateResponse(**result)
