"""Conformity policy + result + summary CRUD (issue #106).

Three groups of routes:

* ``/conformity/policies`` — CRUD on ``ConformityPolicy``.
  Read = ``read`` on ``conformity``. Write / delete = ``admin`` on
  ``conformity``. Built-in policies (``is_builtin=True``) accept
  ``enabled`` / ``eval_interval_hours`` / ``severity`` /
  ``fail_alert_rule_id`` updates but reject changes to identity
  fields (``name``, ``framework``, ``check_kind``, etc.) — operators
  who want a different shape clone the row first.
* ``/conformity/results`` — read-only history. Filterable by policy /
  resource / status / since.
* ``/conformity/summary`` — per-framework rollup for the Platform
  Insights dashboard card.
* ``/conformity/checks`` — the catalog of available check_kinds, so
  the policy editor UI can render args dynamically.
* ``/conformity/policies/{id}/evaluate`` — on-demand re-evaluation.
* ``/conformity/export.pdf`` — auditor-facing PDF.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, desc, func, select

from app.api.deps import DB, CurrentUser
from app.core.content_disposition import content_disposition
from app.core.permissions import user_has_permission
from app.core.responses import PdfResponse
from app.models.audit import AuditLog
from app.models.conformity import ConformityPolicy, ConformityResult
from app.services import alerts as alert_service
from app.services.conformity import evaluate_policy
from app.services.conformity.checks import (
    CHECK_CATALOG,
    CHECK_REGISTRY,
)
from app.services.conformity.current import (
    current_status_counts,
    retire_pass_if_rescoped,
)
from app.services.conformity.engine import (
    RESOLUTION_POLICY_DELETED,
    RESOLUTION_POLICY_DISABLED,
    resolve_policy_alerts,
)
from app.services.conformity.pdf import generate_conformity_pdf

router = APIRouter()


CONFORMITY_RESOURCE = "conformity"

_TARGET_KINDS = frozenset(
    {"platform", "subnet", "ip_address", "dns_zone", "dhcp_scope", "multicast_group"}
)
_SEVERITIES = frozenset({"info", "warning", "critical"})
_STATUSES = frozenset({"pass", "fail", "warn", "not_applicable"})

# Fields a built-in policy permits the operator to override.
# Identity / shape fields are intentionally excluded — the seed file
# is the source of truth for those.
_BUILTIN_MUTABLE_FIELDS = frozenset(
    {"enabled", "eval_interval_hours", "severity", "fail_alert_rule_id", "description"}
)

# ── Schemas ─────────────────────────────────────────────────────────


class PolicyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str = Field("", max_length=2000)
    framework: str = Field("custom", max_length=40)
    reference: str | None = Field(None, max_length=80)
    severity: str = "warning"
    target_kind: str
    target_filter: dict[str, Any] = Field(default_factory=dict)
    check_kind: str
    check_args: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    eval_interval_hours: int = 24
    fail_alert_rule_id: uuid.UUID | None = None

    @field_validator("severity")
    @classmethod
    def _v_sev(cls, v: str) -> str:
        if v not in _SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(_SEVERITIES)}")
        return v

    @field_validator("target_kind")
    @classmethod
    def _v_target_kind(cls, v: str) -> str:
        if v not in _TARGET_KINDS:
            raise ValueError(f"target_kind must be one of {sorted(_TARGET_KINDS)}")
        return v

    @field_validator("check_kind")
    @classmethod
    def _v_check_kind(cls, v: str) -> str:
        if v not in CHECK_REGISTRY:
            raise ValueError(f"check_kind must be one of {sorted(CHECK_REGISTRY)}")
        return v

    @field_validator("eval_interval_hours")
    @classmethod
    def _v_interval(cls, v: int) -> int:
        if v < 0 or v > 24 * 365:
            raise ValueError("eval_interval_hours must be 0..8760 (1 year)")
        return v


class PolicyUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    framework: str | None = None
    reference: str | None = None
    severity: str | None = None
    target_kind: str | None = None
    target_filter: dict[str, Any] | None = None
    check_kind: str | None = None
    check_args: dict[str, Any] | None = None
    enabled: bool | None = None
    eval_interval_hours: int | None = None
    fail_alert_rule_id: uuid.UUID | None = None

    @field_validator("severity")
    @classmethod
    def _v_sev(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in _SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(_SEVERITIES)}")
        return v

    @field_validator("target_kind")
    @classmethod
    def _v_target_kind(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in _TARGET_KINDS:
            raise ValueError(f"target_kind must be one of {sorted(_TARGET_KINDS)}")
        return v

    @field_validator("check_kind")
    @classmethod
    def _v_check_kind(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in CHECK_REGISTRY:
            raise ValueError(f"check_kind must be one of {sorted(CHECK_REGISTRY)}")
        return v


class PolicyResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    framework: str
    reference: str | None
    severity: str
    target_kind: str
    target_filter: dict[str, Any]
    check_kind: str
    check_args: dict[str, Any]
    is_builtin: bool
    enabled: bool
    eval_interval_hours: int
    last_evaluated_at: datetime | None
    fail_alert_rule_id: uuid.UUID | None
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}


class ResultResponse(BaseModel):
    id: uuid.UUID
    policy_id: uuid.UUID
    resource_kind: str
    resource_id: str
    resource_display: str
    evaluated_at: datetime
    status: str
    detail: str
    diagnostic: dict[str, Any] | None

    model_config = {"from_attributes": True}


class FrameworkRollup(BaseModel):
    framework: str
    policies_total: int
    policies_enabled: int
    pass_count: int
    warn_count: int
    fail_count: int
    not_applicable_count: int


class SummaryResponse(BaseModel):
    overall_pass: int
    overall_warn: int
    overall_fail: int
    overall_not_applicable: int
    last_evaluated_at: datetime | None
    frameworks: list[FrameworkRollup]


class EvaluateNowResponse(BaseModel):
    passed: int
    failed: int
    warned: int
    not_applicable: int
    total: int


class CheckCatalogEntry(BaseModel):
    name: str
    label: str
    supports: list[str]
    args: list[dict[str, Any]]


# ── Permission helpers ──────────────────────────────────────────────


def _require_read(current_user: object) -> None:
    if not user_has_permission(current_user, "read", CONFORMITY_RESOURCE):  # type: ignore[arg-type]
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied: need 'read' on '{CONFORMITY_RESOURCE}'",
        )


def _require_admin(current_user: object) -> None:
    if not user_has_permission(current_user, "admin", CONFORMITY_RESOURCE):  # type: ignore[arg-type]
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied: need 'admin' on '{CONFORMITY_RESOURCE}'",
        )


# ── Policy CRUD ─────────────────────────────────────────────────────


@router.get("/policies", response_model=list[PolicyResponse])
async def list_policies(
    db: DB,
    current_user: CurrentUser,
    framework: str | None = Query(None),
    enabled_only: bool = Query(False),
) -> list[ConformityPolicy]:
    _require_read(current_user)
    q = select(ConformityPolicy).order_by(ConformityPolicy.framework, ConformityPolicy.name)
    if framework:
        q = q.where(ConformityPolicy.framework == framework)
    if enabled_only:
        q = q.where(ConformityPolicy.enabled.is_(True))
    return list((await db.execute(q)).scalars().all())


@router.get("/checks", response_model=list[CheckCatalogEntry])
async def list_check_kinds(current_user: CurrentUser) -> list[dict[str, Any]]:
    """Available ``check_kind`` catalog. Used by the policy editor
    UI to render type-aware ``check_args`` form fields.

    Read-only on ``conformity`` is enough — the catalog itself doesn't
    expose any operator-specific data.
    """
    _require_read(current_user)
    return CHECK_CATALOG


@router.get("/policies/{policy_id}", response_model=PolicyResponse)
async def get_policy(policy_id: uuid.UUID, db: DB, current_user: CurrentUser) -> ConformityPolicy:
    _require_read(current_user)
    p = await db.get(ConformityPolicy, policy_id)
    if p is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return p


@router.post(
    "/policies",
    response_model=PolicyResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_policy(body: PolicyCreate, db: DB, current_user: CurrentUser) -> ConformityPolicy:
    _require_admin(current_user)
    p = ConformityPolicy(**body.model_dump(), is_builtin=False)
    db.add(p)
    await db.flush()  # column-default id must exist before the audit row reads it (#2006)
    db.add(
        AuditLog(
            action="create",
            resource_type="conformity_policy",
            resource_id=str(p.id),
            resource_display=body.name,
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
            new_value={
                "name": body.name,
                "framework": body.framework,
                "check_kind": body.check_kind,
                "target_kind": body.target_kind,
            },
        )
    )
    await db.commit()
    await db.refresh(p)
    return p


@router.patch("/policies/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: uuid.UUID,
    body: PolicyUpdate,
    db: DB,
    current_user: CurrentUser,
) -> ConformityPolicy:
    _require_admin(current_user)
    p = await db.get(ConformityPolicy, policy_id)
    if p is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    payload = body.model_dump(exclude_unset=True)
    if p.is_builtin:
        offending = sorted(set(payload) - _BUILTIN_MUTABLE_FIELDS)
        if offending:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Built-in policies only accept updates to "
                    f"{sorted(_BUILTIN_MUTABLE_FIELDS)}; rejected: {offending}. "
                    "Clone the policy first to change identity fields."
                ),
            )
    changed: dict[str, Any] = {}
    for key, value in payload.items():
        old = getattr(p, key)
        if old != value:
            changed[key] = {"old": str(old)[:200], "new": str(value)[:200]}
            setattr(p, key, value)
    if "enabled" in changed and not p.enabled:
        # #2277 — a disabled policy is never evaluated again; its open
        # alerts would otherwise stay red forever.
        await resolve_policy_alerts(db, p.id, reason=RESOLUTION_POLICY_DISABLED)
    # #2278 — a re-scoped policy's last pass answers a different question.
    retire_pass_if_rescoped(p, changed)
    if changed:
        db.add(
            AuditLog(
                action="update",
                resource_type="conformity_policy",
                resource_id=str(p.id),
                resource_display=p.name,
                user_id=current_user.id,
                user_display_name=current_user.username,
                result="success",
                changed_fields=list(changed),
                new_value=changed,
            )
        )
    await db.commit()
    await db.refresh(p)
    return p


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(policy_id: uuid.UUID, db: DB, current_user: CurrentUser) -> None:
    _require_admin(current_user)
    p = await db.get(ConformityPolicy, policy_id)
    if p is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    if p.is_builtin:
        raise HTTPException(
            status_code=400,
            detail=(
                "Built-in policies cannot be deleted. Disable instead "
                "(PATCH enabled=false) or clone before editing."
            ),
        )
    name = p.name
    db.add(
        AuditLog(
            action="delete",
            resource_type="conformity_policy",
            resource_id=str(p.id),
            resource_display=name,
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
        )
    )
    await resolve_policy_alerts(db, policy_id, reason=RESOLUTION_POLICY_DELETED)
    await db.execute(delete(ConformityPolicy).where(ConformityPolicy.id == policy_id))
    await db.commit()


# ── On-demand evaluate ──────────────────────────────────────────────


@router.post(
    "/policies/{policy_id}/evaluate",
    response_model=EvaluateNowResponse,
)
async def evaluate_policy_now(
    policy_id: uuid.UUID, db: DB, current_user: CurrentUser
) -> EvaluateNowResponse:
    _require_admin(current_user)
    p = await db.get(ConformityPolicy, policy_id)
    if p is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    # #2261 — commit the results and any alert event before paging anyone.
    with alert_service.defer_deliveries() as pending:
        summary = await evaluate_policy(db, p)
    await db.commit()
    await alert_service.deliver_deferred(db, pending)
    return EvaluateNowResponse(
        passed=summary["passed"],
        failed=summary["failed"],
        warned=summary["warned"],
        not_applicable=summary["not_applicable"],
        total=summary["total"],
    )


# ── Results ─────────────────────────────────────────────────────────


@router.get("/results", response_model=list[ResultResponse])
async def list_results(
    db: DB,
    current_user: CurrentUser,
    policy_id: uuid.UUID | None = Query(None),
    resource_kind: str | None = Query(None),
    resource_id: str | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    since: datetime | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
) -> list[ConformityResult]:
    _require_read(current_user)
    q = select(ConformityResult).order_by(desc(ConformityResult.evaluated_at)).limit(limit)
    if policy_id:
        q = q.where(ConformityResult.policy_id == policy_id)
    if resource_kind:
        q = q.where(ConformityResult.resource_kind == resource_kind)
    if resource_id:
        q = q.where(ConformityResult.resource_id == resource_id)
    if status_filter:
        if status_filter not in _STATUSES:
            raise HTTPException(
                status_code=400,
                detail=f"status must be one of {sorted(_STATUSES)}",
            )
        q = q.where(ConformityResult.status == status_filter)
    if since:
        q = q.where(ConformityResult.evaluated_at >= since)
    return list((await db.execute(q)).scalars().all())


# ── Summary (Platform Insights card) ────────────────────────────────


@router.get("/summary", response_model=SummaryResponse)
async def summary(db: DB, current_user: CurrentUser) -> SummaryResponse:
    """Per-framework rollup of the CURRENT results.

    Current means the most recent pass of each ENABLED policy
    (``services.conformity.current``, #2278): a target deleted or
    reclassified out of scope since is not in that pass, and a disabled
    policy contributes no results — only to ``policies_total``. The
    counting runs in SQL, so this reads policies × current targets
    rather than the whole append-only history. Powers the Platform
    Insights conformity card and the dashboard pivot table.
    """
    _require_read(current_user)

    policies = list((await db.execute(select(ConformityPolicy))).scalars().all())
    framework_buckets: dict[str, FrameworkRollup] = {
        p.framework: FrameworkRollup(
            framework=p.framework,
            policies_total=0,
            policies_enabled=0,
            pass_count=0,
            warn_count=0,
            fail_count=0,
            not_applicable_count=0,
        )
        for p in policies
    }
    for p in policies:
        b = framework_buckets[p.framework]
        b.policies_total += 1
        if p.enabled:
            b.policies_enabled += 1

    overall = {"pass": 0, "warn": 0, "fail": 0, "not_applicable": 0}
    for fw, by_status in (await current_status_counts(db)).items():
        b = framework_buckets[fw]
        for st, n in by_status.items():
            if st == "pass":
                b.pass_count += n
                overall["pass"] += n
            elif st == "warn":
                b.warn_count += n
                overall["warn"] += n
            elif st == "fail":
                b.fail_count += n
                overall["fail"] += n
            else:
                b.not_applicable_count += n
                overall["not_applicable"] += n

    last_evaluated = (
        await db.execute(
            select(func.max(ConformityPolicy.last_evaluated_at)).where(
                ConformityPolicy.enabled.is_(True)
            )
        )
    ).scalar()

    return SummaryResponse(
        overall_pass=overall["pass"],
        overall_warn=overall["warn"],
        overall_fail=overall["fail"],
        overall_not_applicable=overall["not_applicable"],
        last_evaluated_at=last_evaluated,
        frameworks=sorted(framework_buckets.values(), key=lambda b: b.framework),
    )


# ── PDF export ──────────────────────────────────────────────────────


@router.get(
    "/export.pdf",
    # Declared media type, not just the wire header: FastAPI documents a bare
    # `-> Response` as application/json, so the (correctly sent)
    # application/pdf was undocumented and schema-conformance clients flagged
    # every response (schemathesis UndefinedContentType, 13/13 runs).
    # ``response_class`` rather than a ``responses={200: {"content": ...}}``
    # entry (#921): that entry MERGES with the inferred application/json, so
    # the route still declared a JSON body it never produces.
    response_class=PdfResponse,
    responses={200: {"description": "PDF conformity report"}},
)
async def export_pdf(
    db: DB,
    current_user: CurrentUser,
    framework: str | None = Query(None),
) -> Response:
    """Generate the auditor-facing PDF synchronously.

    Read on ``conformity`` is sufficient — the dashboard already
    exposes the same content. PDF generation is gated to
    authenticated users so the document never leaks publicly. The
    operator-supplied ``framework`` filter narrows to one section
    when an auditor only needs PCI evidence.
    """
    _require_read(current_user)
    # ``reportlab`` itself is sync; the service runs its render pass in
    # ``asyncio.to_thread`` — on the single-worker uvicorn loop an inline
    # render stalled every concurrent request and the kubelet's probes.
    pdf_bytes = await generate_conformity_pdf(db, framework=framework)
    fname = "spatiumddi-conformity"
    if framework:
        # Bounded so an arbitrarily long ``framework`` can't grow the
        # response header without limit; the header builder below is what
        # makes the *content* safe.
        fname += f"-{framework.lower().replace(' ', '-').replace('/', '-')[:60]}"
    fname += f"-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}.pdf"
    # Content-Disposition is a latin-1 header carrying an operator-supplied
    # value, which is three separate bugs an f-string does not survive — see
    # ``app.core.content_disposition``. Notably an ASCII-strip is NOT enough:
    # CR/LF are ASCII, and reach uvicorn's writer as an invalid header value
    # (connection dropped, no response at all).
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": content_disposition(fname)},
    )
