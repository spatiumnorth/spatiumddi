"""Admin REST surface for the feature-module catalog.

Two endpoints:

* ``GET  /admin/feature-modules`` — list every catalog entry alongside
  its current enabled state. Available to any authenticated user (the
  Sidebar + Cmd-K palette query this on every page so we don't gate it
  behind superadmin — viewers need to know which sections are visible
  to them too).

* ``PATCH /admin/feature-modules/{id}`` — flip the enabled state.
  Superadmin only. Writes an audit row and busts the local cache.

The response shape is intentionally flat — frontend code reads it as
``Record<string, boolean>`` for fast ``enabled[id]`` lookups, alongside
catalog metadata (label / group / description) for the Settings page.
"""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import UUID

import structlog
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.stepup import refuse_if_stepup_blocked
from app.core.auth_throttle import login_rate_limited, record_stepup_password_failure
from app.core.demo_mode import DEMO_RESTRICTED_MODULES, is_demo_mode
from app.core.permissions import is_effective_superadmin
from app.core.request_meta import get_trusted_client_ip
from app.models.audit import AuditLog
from app.models.dhcp import DHCPScope, DHCPServer
from app.models.dns import DNSServer, DNSZone
from app.models.feature_module import FeatureModule
from app.models.settings import PlatformSettings
from app.services import feature_modules as fm_svc
from app.services.account_lockout import LockoutPolicy, is_locked, register_failure
from app.services.ai.operations import get_operation
from app.services.ai.operations_control import (
    MODULE_ID as APPROVALS_MODULE_ID,
)
from app.services.ai.operations_control import (
    ControlKind,
    ModifyApprovalControlArgs,
    is_controls_protected,
    maybe_gate_control,
)
from app.services.reauth import ReauthOutcome, reverify_operator

logger = structlog.get_logger(__name__)
router = APIRouter()

# Typed confirmation phrase the break-glass caller must echo exactly — mirrors
# factory-reset's exact-match phrase guard. Wrong phrase → 422.
BREAK_GLASS_PHRASE = "BREAK GLASS"

# Audit action strings. The SUCCESS path keeps the HIGH-severity
# ``approvals.break_glass`` action so SIEM rules keying on it stay clean — a
# real break-glass is rare and alarming. Post-auth VALIDATION failures (wrong
# phrase / bad password / stale change) use a distinct lower-severity action so
# they don't pollute the high-sev success signal with noise an attacker could
# generate at will. (NN #4 — every attempt that passes the superadmin gate is
# still durably audited, just under the right action.)
_BREAK_GLASS_ACTION_SUCCESS = "approvals.break_glass"
_BREAK_GLASS_ACTION_DENIED = "approvals.break_glass_denied"


# #1068 — a core subsystem may not be switched off while it still owns
# live state. ``require_module`` answers 404, so disabling ``core.dhcp``
# on an install with running Kea servers would not decommission anything:
# it would hide every scope, pool and lease behind a not-found surface
# while the agents kept serving from their cached config, with no way to
# reach the rows from the UI. Refusing is the same fail-closed stance the
# #934 / #935 moves take, and the way back out is explicit — delete the
# servers and zones first.
#
# The agent routers are deliberately NOT gated (see router.py), so the
# fleet would keep running either way; that is what makes the stranded
# state invisible rather than obviously broken.
# Scopes and zones are soft-delete models, so the global ``deleted_at IS
# NULL`` filter in ``app/db.py`` applies here and a deleted row correctly
# does not hold the toggle hostage.
_CORE_SUBSYSTEM_STATE: dict[str, tuple[tuple[str, Any], ...]] = {
    "core.dhcp": (("DHCP server", DHCPServer), ("DHCP scope", DHCPScope)),
    "core.dns": (("DNS server", DNSServer), ("DNS zone", DNSZone)),
}


async def _refuse_disable_while_populated(db: DB, module_id: str) -> None:
    """422 when turning off a core subsystem that still has rows."""
    checks = _CORE_SUBSYSTEM_STATE.get(module_id)
    if not checks:
        return
    counts: list[str] = []
    for label, model in checks:
        n = (await db.execute(select(func.count(model.id)))).scalar_one()
        if n:
            counts.append(f"{n} {label}{'s' if n != 1 else ''}")
    if counts:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Cannot disable this feature while it still has "
                f"{' and '.join(counts)}. Delete them first — disabling would "
                f"hide them behind a 404 without stopping the agents that "
                f"serve them."
            ),
        )


class FeatureModuleEntry(BaseModel):
    """Catalog entry + current state. ``label`` / ``group`` /
    ``description`` come from the in-process catalog so the UI doesn't
    need to know about it separately. ``default_enabled`` lets the
    Settings page show a "default" badge for transparency."""

    id: str
    label: str
    group: str
    description: str
    default_enabled: bool
    enabled: bool
    # #1068 — ids this module is meaningless without. ``enabled`` above is
    # this module's OWN state, so a child under a disabled parent reports
    # enabled=True while resolving off everywhere else; the page reads
    # ``requires`` to show that as "Requires DNS" rather than as a toggle
    # that appears to do nothing.
    requires: list[str] = []


class FeatureModuleToggleBody(BaseModel):
    enabled: bool
    # #62: when enabling ``governance.approvals``, the operator may also turn
    # on the self-governance lock in the same call. Only honoured for that
    # module on the enable path; ignored everywhere else (enabling never
    # CLEARS the lock — that's a gated weakening move).
    protect_controls: bool | None = None


@router.get("/feature-modules", response_model=list[FeatureModuleEntry])
async def list_feature_modules(db: DB, current_user: CurrentUser) -> list[FeatureModuleEntry]:
    rows = (await db.execute(select(FeatureModule))).scalars().all()
    overrides: dict[str, bool] = {row.id: row.enabled for row in rows}

    return [
        FeatureModuleEntry(
            id=spec.id,
            label=spec.label,
            group=spec.group,
            description=spec.description,
            default_enabled=spec.default_enabled,
            enabled=overrides.get(spec.id, spec.default_enabled),
            requires=list(spec.requires),
        )
        for spec in fm_svc.MODULES
    ]


@router.patch("/feature-modules/{module_id}")
async def toggle_feature_module(
    module_id: str,
    body: FeatureModuleToggleBody,
    db: DB,
    current_user: SuperAdmin,
    request: Request,
):  # noqa: ANN201 — returns FeatureModuleEntry OR a 202 JSONResponse (gated)
    if not fm_svc.is_known(module_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown feature module: {module_id}",
        )

    # Demo-mode lockdown — re-enable attempts on the curated
    # abusable surface (nmap, AI, integrations) get 403'd. Disabling
    # is always allowed (operator can voluntarily turn off more).
    if is_demo_mode() and body.enabled and module_id in DEMO_RESTRICTED_MODULES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Feature '{module_id}' cannot be enabled while this "
                "instance is running in demo mode."
            ),
        )

    spec = fm_svc.MODULES_BY_ID[module_id]

    # #1068 — refuse to switch a core subsystem off while it still owns
    # rows. Runs before anything is written or audited, so a refused
    # toggle leaves no trace beyond the 422.
    if not body.enabled:
        await _refuse_disable_while_populated(db, module_id)

    # #62 self-governance lock: disabling ``governance.approvals`` is a
    # WEAKENING change. When the lock is on (and the caller isn't going
    # through break-glass), this returns a 202 + a pending change_request a
    # SECOND superadmin must approve, INSTEAD of disabling inline. When the
    # lock is off ``maybe_gate_control`` returns None immediately (before any
    # extra query) so the inline path below is byte-identical to today.
    if module_id == APPROVALS_MODULE_ID and body.enabled is False:
        from fastapi.responses import JSONResponse  # noqa: PLC0415

        pending = await maybe_gate_control(
            db,
            current_user,
            request,
            kind="disable_module",
            resource_type="feature_module",
            resource_id=module_id,
            resource_display="Approval workflows",
        )
        if pending is not None:
            return JSONResponse(
                status_code=status.HTTP_202_ACCEPTED,
                content=pending.as_dict(),
            )

    row = await fm_svc.set_module_enabled(db, module_id, body.enabled, user_id=current_user.id)
    # Mirror the toggle into the matching ``PlatformSettings`` column
    # for integrations. The Celery beat reconcilers gate on those
    # columns directly; keeping both sides in lock-step lets the
    # reconciler stop / start without touching every task. Non-
    # integration ids skip this branch.
    settings_col = fm_svc.INTEGRATION_SETTINGS_MIRROR.get(module_id)
    if settings_col is not None:
        ps = await db.get(PlatformSettings, 1)
        if ps is not None:
            setattr(ps, settings_col, body.enabled)
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="update",
            resource_type="feature_module",
            resource_id=module_id,
            resource_display=spec.label,
            result="success",
            new_value={"enabled": body.enabled},
        )
    )

    # #62 set-at-enable-time: turning ON ``governance.approvals`` with
    # ``protect_controls=true`` also flips the self-protection lock on. This
    # is a STRENGTHENING move → stays single-person inline + audited.
    # ``protect_controls`` is never honoured to CLEAR the lock here (that's a
    # gated weakening move via break-glass / approval).
    if module_id == APPROVALS_MODULE_ID and body.enabled and body.protect_controls:
        # Get-or-create the settings row before mutating — on a fresh install
        # there is no ``PlatformSettings(1)`` yet, and skipping the write while
        # still reporting the lock ON would leave the lock reading OFF (so every
        # weakening op runs ungated). Mirrors the firewall.py pattern. Only the
        # audit row lands AFTER the flag is actually staged.
        ps = await db.get(PlatformSettings, 1)
        if ps is None:
            ps = PlatformSettings(id=1)
            db.add(ps)
            await db.flush()
        if not ps.approvals_protect_controls:
            ps.approvals_protect_controls = True
            db.add(
                AuditLog(
                    user_id=current_user.id,
                    user_display_name=current_user.display_name,
                    auth_source=current_user.auth_source,
                    action="update",
                    resource_type="platform_settings",
                    resource_id="approvals_protect_controls",
                    resource_display="Approval self-protection lock",
                    result="success",
                    new_value={"approvals_protect_controls": True},
                )
            )

    await db.commit()
    fm_svc.invalidate_cache()

    return FeatureModuleEntry(
        id=spec.id,
        label=spec.label,
        group=spec.group,
        description=spec.description,
        default_enabled=spec.default_enabled,
        enabled=row.enabled,
        requires=list(spec.requires),
    )


# ── Self-protection lock toggle (#62) ───────────────────────────────────


class ApprovalsLockBody(BaseModel):
    enabled: bool


@router.get("/feature-modules/approvals-lock")
async def get_approvals_lock(db: DB, current_user: SuperAdmin) -> dict:
    """Current self-governance lock state (superadmin)."""
    return {"approvals_protect_controls": await is_controls_protected(db)}


@router.post("/feature-modules/approvals-lock")
async def set_approvals_lock(
    body: ApprovalsLockBody,
    db: DB,
    current_user: SuperAdmin,
    request: Request,
):  # noqa: ANN201 — {state} OR a 202 JSONResponse (gated when turning OFF)
    """Turn the self-governance lock on / off (superadmin, #62).

    Turning it ON is a STRENGTHENING move → inline + audited, single-person.
    Turning it OFF is a WEAKENING move → when the lock is currently on it
    routes through ``maybe_gate_control`` (a second superadmin must approve)
    so you can't quietly self-unlock; the break-glass endpoint is the
    immediate escape hatch.
    """
    currently = await is_controls_protected(db)

    if body.enabled:
        # Strengthen — inline.
        if not currently:
            # Get-or-create the settings row before mutating. On a fresh
            # install no ``PlatformSettings(1)`` exists yet; skipping the write
            # while reporting the lock ON would leave it reading OFF and every
            # weakening op ungated. Mirrors firewall.py; audit lands only AFTER
            # the flag is actually staged.
            ps = await db.get(PlatformSettings, 1)
            if ps is None:
                ps = PlatformSettings(id=1)
                db.add(ps)
                await db.flush()
            ps.approvals_protect_controls = True
            db.add(
                AuditLog(
                    user_id=current_user.id,
                    user_display_name=current_user.display_name,
                    auth_source=current_user.auth_source,
                    action="update",
                    resource_type="platform_settings",
                    resource_id="approvals_protect_controls",
                    resource_display="Approval self-protection lock",
                    result="success",
                    new_value={"approvals_protect_controls": True},
                )
            )
            await db.commit()
        return {"approvals_protect_controls": True}

    # Weaken (turn off) — gate when currently on.
    pending = await maybe_gate_control(
        db,
        current_user,
        request,
        kind="unlock",
        resource_type="platform_settings",
        resource_id="approvals_protect_controls",
        resource_display="Approval self-protection lock",
    )
    if pending is not None:
        from fastapi.responses import JSONResponse  # noqa: PLC0415

        return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content=pending.as_dict())

    # Lock already off (maybe_gate_control short-circuited) → idempotent no-op.
    return {"approvals_protect_controls": False}


# ── Break-glass: force a protected control change immediately (#62) ──────


class BreakGlassBody(BaseModel):
    """Force a weakening control change immediately, bypassing the
    two-person gate. The mandatory anti-lockout escape hatch."""

    kind: ControlKind
    policy_id: UUID | None = None
    # Re-confirmation — local users supply ``password``; external-auth
    # users (no local password) supply ``totp_code`` (see services/reauth.py).
    password: str | None = None
    totp_code: str | None = None
    # Typed confirmation phrase — must equal BREAK_GLASS_PHRASE exactly.
    confirm_phrase: str = Field(min_length=1)


def _break_glass_audit(
    db: DB,
    *,
    user,  # type: ignore[no-untyped-def]
    kind: str,
    result: str,
    new_value: dict | None = None,
    action: str = _BREAK_GLASS_ACTION_SUCCESS,
) -> None:
    """Break-glass audit row.

    There is no ``severity`` column (NN #4 trail is the signal); the distinct
    ``action="approvals.break_glass"`` + the ``governance.break_glass`` typed
    event (event_publisher special map) convey the high-severity intent so
    operators can wire a dedicated alert / SIEM rule on it. Post-auth validation
    failures pass ``action=_BREAK_GLASS_ACTION_DENIED`` so they stay
    distinguishable from genuine successes for SIEM rules.
    """
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=getattr(user, "auth_source", "local") or "local",
            action=action,
            resource_type="approval_control",
            resource_id=kind,
            resource_display=f"Break-glass: {kind}",
            result=result,
            new_value=new_value,
        )
    )


@router.post("/feature-modules/break-glass", status_code=status.HTTP_200_OK)
async def break_glass(
    body: BreakGlassBody,
    db: DB,
    current_user: SuperAdmin,
    request: Request,
) -> dict:
    """Force a protected control change IMMEDIATELY (anti-lockout, #62).

    Superadmin-only. Requires BOTH a typed confirmation phrase AND password /
    TOTP re-confirmation, then executes the weakening control change under the
    calling superadmin — bypassing the two-person gate. This must never be
    gateable itself, or a fully-locked platform with no second superadmin could
    be permanently wedged. Writes a HIGH-severity audit row + fires the
    ``governance.break_glass`` event.

    The reauth surface is rate-limited (#4): per-IP via the shared login budget
    AND per-account via the lockout machinery, so a captured-session attacker
    can't brute-force the TOTP (relevant for external-auth superadmins with no
    local password) or spam the high-sev audit log. The HIGH-severity SUCCESS
    audit is committed in ITS OWN transaction BEFORE apply() runs (#3), so a
    break-glass that passed phrase+reauth is durably recorded even if apply()
    raises (e.g. policy deleted concurrently) and rolls the session back.
    """
    # 0. Per-IP rate limit (#4) — same Redis budget /auth/login uses, fails open.
    #    Bounds TOTP-spray + high-sev audit noise from one source even before
    #    we touch the per-account counter.
    if await login_rate_limited(get_trusted_client_ip(request)):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many break-glass attempts. Try again shortly.",
        )

    # 1. Superadmin gate (SuperAdmin dep already enforces, but audit the shape).
    if not is_effective_superadmin(current_user):  # pragma: no cover — dep enforces
        _break_glass_audit(
            db,
            user=current_user,
            kind=body.kind,
            result="forbidden",
            new_value={"reason": "non_superadmin"},
            action=_BREAK_GLASS_ACTION_DENIED,
        )
        await db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only superadmins can break the glass")

    # 1b. Per-account lockout short-circuit (#4) — runs BEFORE the credential
    #     check so a locked account can't keep guessing. Same machinery as
    #     /auth/login's per-account lockout (#71).
    if is_locked(current_user):
        _break_glass_audit(
            db,
            user=current_user,
            kind=body.kind,
            result="forbidden",
            new_value={"reason": "account_locked"},
            action=_BREAK_GLASS_ACTION_DENIED,
        )
        await db.commit()
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Account is temporarily locked due to repeated failed re-confirmation attempts.",
        )

    # 2. Typed confirmation phrase — exact match (mirrors factory-reset).
    if body.confirm_phrase != BREAK_GLASS_PHRASE:
        _break_glass_audit(
            db,
            user=current_user,
            kind=body.kind,
            result="forbidden",
            new_value={"reason": "bad_phrase"},
            action=_BREAK_GLASS_ACTION_DENIED,
        )
        await db.commit()
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Confirmation phrase must be exactly {BREAK_GLASS_PHRASE!r}",
        )

    # 3. Password / TOTP re-confirmation (#408 pattern). The shared budget gate
    # first (#1413): this endpoint keeps its own break-glass audit row and
    # lockout counter, so it uses the gate rather than require_operator_stepup,
    # but a wrong answer spends the same per-account step-up budget.
    try:
        await refuse_if_stepup_blocked(current_user)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            _break_glass_audit(
                db,
                user=current_user,
                kind=body.kind,
                result="forbidden",
                new_value={"reason": "stepup_blocked"},
                action=_BREAK_GLASS_ACTION_DENIED,
            )
            await db.commit()
        raise
    outcome = reverify_operator(current_user, password=body.password, totp_code=body.totp_code)
    if outcome is not ReauthOutcome.OK:
        reason = "mfa_required" if outcome is ReauthOutcome.MFA_REQUIRED else "bad_credential"
        # #4: bump the per-account lockout counter on a genuine BAD CREDENTIAL
        # (not on MFA_REQUIRED, which is a "you haven't enrolled" config issue,
        # not a guess). Mirrors /auth/login's register_failure on bad_password.
        if outcome is ReauthOutcome.BAD_CREDENTIAL:
            settings_row = await db.get(PlatformSettings, 1)
            register_failure(current_user, LockoutPolicy.from_row(settings_row))
            if body.password or body.totp_code:
                await record_stepup_password_failure(current_user.id)
        _break_glass_audit(
            db,
            user=current_user,
            kind=body.kind,
            result="forbidden",
            new_value={"reason": reason},
            action=_BREAK_GLASS_ACTION_DENIED,
        )
        await db.commit()
        # Friction-sleep so a bad-credential attempt doesn't leak via timing.
        await asyncio.sleep(0.5)
        if outcome is ReauthOutcome.MFA_REQUIRED:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Re-confirmation requires MFA. Your account has no local "
                "password — enrol TOTP under Settings → Security, then retry.",
            )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Password or TOTP code is incorrect")

    # 4. Execute the control change IMMEDIATELY under the caller, bypassing the
    #    gate (apply() never re-enters maybe_gate_control).
    op = get_operation("modify_approval_control")
    assert op is not None  # registered at import
    args = ModifyApprovalControlArgs(kind=body.kind, policy_id=body.policy_id)

    # Stale-state guard — refuse a moot change with a clear reason. Runs BEFORE
    # the success audit so a preview-moot break-glass records the lower-severity
    # ``denied`` row, not a success.
    preview = await op.preview(db, current_user, args)
    if not preview.ok:
        _break_glass_audit(
            db,
            user=current_user,
            kind=body.kind,
            result="error",
            new_value={"reason": "stale", "detail": preview.detail},
            action=_BREAK_GLASS_ACTION_DENIED,
        )
        await db.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, preview.detail)

    # Idempotent — the desired end-state is already reached (#5). The
    # break-glass was authenticated, so record a SUCCESS row (the operator
    # forced the change; it just turned out to be a no-op) and return cleanly
    # without re-running apply().
    if preview.idempotent:
        _break_glass_audit(
            db,
            user=current_user,
            kind=body.kind,
            result="success",
            new_value={
                "kind": body.kind,
                "policy_id": str(body.policy_id) if body.policy_id else None,
                "idempotent": True,
                "detail": preview.detail,
            },
        )
        await db.commit()
        logger.warning(
            "approvals.break_glass",
            user=current_user.username,
            kind=body.kind,
            policy_id=str(body.policy_id) if body.policy_id else None,
            idempotent=True,
        )
        return {"forced": True, "kind": body.kind, "result": {"idempotent": True}}

    # #3: durably record the authenticated break-glass in ITS OWN transaction
    # BEFORE apply() runs. apply() commits its own mutation; if it raises (e.g.
    # the policy was deleted concurrently → ValueError) the session rolls back
    # — committing the success audit FIRST guarantees a row exists for every
    # break-glass that passed phrase + reauth, closing the non-repudiation gap.
    _break_glass_audit(
        db,
        user=current_user,
        kind=body.kind,
        result="success",
        new_value={"kind": body.kind, "policy_id": str(body.policy_id) if body.policy_id else None},
    )
    await db.commit()
    logger.warning(
        "approvals.break_glass",
        user=current_user.username,
        kind=body.kind,
        policy_id=str(body.policy_id) if body.policy_id else None,
    )
    # apply() runs the mutation + its own audit row + commit. The success audit
    # above is already durable, so an apply() failure can't erase it.
    result = await op.apply(db, current_user, args)
    return {"forced": True, "kind": body.kind, "result": result}
