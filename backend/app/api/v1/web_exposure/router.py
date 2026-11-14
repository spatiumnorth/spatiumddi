"""Web exposure detection REST surface (#3651).

Gated behind the default-off ``security.web_exposure`` module at the router
include. Reads follow the Security-dashboard privilege split (#400): the
verdict and its counts for any signed-in caller, the per-network breakdown for
callers who may read the audit log or users, exact addresses for superadmins.
Everything that changes configuration or enforcement is superadmin-only and
audited (non-negotiable #4).

No outbound connection of any kind is made here or anywhere in the feature.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.v1.appliance.firewall import WebUIAccessResponse
from app.config import settings
from app.core.demo_mode import forbid_in_demo_mode
from app.core.permissions import is_effective_superadmin, user_has_permission
from app.core.request_meta import get_trusted_client_ip
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.web_exposure import config as cfg_mod
from app.services.web_exposure import mitigations, store
from app.services.web_exposure.classify import (
    INTERNAL_RANGES,
    bucket_of,
    classify,
    parse_networks,
)
from app.services.web_exposure.config import WebExposureConfig, config_from_row
from app.services.web_exposure.verdict import Verdict, build_verdict, deployment_shape

router = APIRouter()

PRIVATE_RANGES = INTERNAL_RANGES


async def _row(db: DB) -> PlatformSettings:
    row = await db.get(PlatformSettings, 1)
    if row is None:
        row = PlatformSettings(id=1)
        db.add(row)
        await db.flush()
    return row


def _audit(
    user: User,
    *,
    action: str,
    display: str,
    old: dict[str, Any] | None = None,
    new: dict[str, Any] | None = None,
    changed: list[str] | None = None,
) -> AuditLog:
    return AuditLog(
        user_id=user.id,
        user_display_name=user.display_name,
        auth_source=user.auth_source,
        action=action,
        resource_type="web_exposure",
        resource_id="1",
        resource_display=display,
        result="success",
        changed_fields=changed,
        old_value=old,
        new_value=new,
    )


class BucketRowOut(BaseModel):
    bucket: str
    requests: int
    signals: dict[str, int]
    first_seen: str | None
    last_seen: str | None
    endpoints: list[str]
    addresses: list[str] | None
    login_page: int
    other_api: int
    login_failures: int


class VerdictOut(BaseModel):
    verdict: Verdict
    severity: Literal["info", "warning", "critical"] | None
    window_hours: int
    threshold: int
    distinct_external_buckets: int
    since: str | None
    totals: dict[str, int]
    distinct_usernames: int
    attack_evidence: bool
    intentional: bool
    attribution_warning: bool
    deployment_shape: str
    fix_hint: str
    summary: str
    buckets: list[BucketRowOut]


class WebExposureContext(BaseModel):
    caller_ip: str | None
    caller_class: str
    caller_bucket: str | None
    deployment_shape: str
    appliance: bool
    break_glass_active: bool
    superadmins_without_totp: list[str]
    #: Active bans; None when Redis is unreachable.
    bans: list[dict[str, Any]] | None
    bans_available: bool
    private_ranges: list[str]


class WebExposureConfigResponse(WebExposureContext):
    config: WebExposureConfig


class WebExposureConfigSaved(WebExposureConfigResponse):
    warnings: list[str]


class BansResponse(BaseModel):
    available: bool
    bans: list[dict[str, Any]]


class BansClearedResponse(BaseModel):
    cleared: int


# ── Verdict ─────────────────────────────────────────────────────────


@router.get("/verdict", response_model=VerdictOut)
async def get_verdict(db: DB, current_user: CurrentUser) -> dict[str, Any]:
    """The verdict with its evidence. Counts for everyone signed in; the
    per-network rows for callers who may read the audit log or users; exact
    addresses only for superadmins."""
    row = await db.get(PlatformSettings, 1)
    cfg = config_from_row(row.web_exposure if row else None)
    superadmin = is_effective_superadmin(current_user)
    privileged = (
        superadmin
        or user_has_permission(current_user, "read", "audit_log")
        or user_has_permission(current_user, "read", "user")
    )
    result = build_verdict(
        await store.read_window(cfg.window_hours), cfg, include_addresses=superadmin
    )
    out = result.as_dict()
    if not privileged:
        out["buckets"] = []
    return out


# ── Configuration ───────────────────────────────────────────────────


class TrustedNetworkRequest(BaseModel):
    cidr: str = Field(min_length=3, max_length=64)


async def _context(request: Request, db: DB, cfg: WebExposureConfig) -> dict[str, Any]:
    caller = get_trusted_client_ip(request)
    caller_class = classify(caller, parse_networks(cfg.trusted_networks))
    unenrolled = (
        (
            await db.execute(
                select(User.username).where(
                    User.is_active.is_(True),
                    User.auth_source == "local",
                    User.is_superadmin.is_(True),
                    User.totp_enabled.is_(False),
                )
            )
        )
        .scalars()
        .all()
    )
    bans = await mitigations.list_bans()
    return {
        "caller_ip": caller,
        "caller_class": caller_class,
        "caller_bucket": bucket_of(caller) if caller else None,
        "deployment_shape": deployment_shape(),
        "appliance": bool(settings.appliance_mode),
        "break_glass_active": cfg_mod.mitigations_break_glass(),
        "superadmins_without_totp": sorted(unenrolled),
        "bans": bans,
        "bans_available": bans is not None,
        "private_ranges": list(PRIVATE_RANGES),
    }


@router.get("/config", response_model=WebExposureConfigResponse)
async def get_config(request: Request, db: DB, current_user: SuperAdmin) -> dict[str, Any]:
    row = await db.get(PlatformSettings, 1)
    cfg = config_from_row(row.web_exposure if row else None)
    return {"config": cfg.model_dump(), **await _context(request, db, cfg)}


@router.put("/config", response_model=WebExposureConfigSaved)
async def put_config(
    body: WebExposureConfig, request: Request, db: DB, current_user: SuperAdmin
) -> dict[str, Any]:
    """Replace the configuration. Tier 2 has a pre-flight: it is refused unless
    the enabling superadmin's own address is trusted / internal or their own
    account has TOTP, and the 422 names every local superadmin without TOTP,
    since those are who the change strands. There is no
    acknowledgement path: 'enrol from inside' presumes an inside exists."""
    forbid_in_demo_mode("Web exposure settings are disabled in demo mode")
    row = await _row(db)
    old = config_from_row(row.web_exposure)
    ctx = await _context(request, db, body)

    if body.require_mfa_external and not old.require_mfa_external:
        caller_inside = ctx["caller_class"] in ("trusted", "internal")
        if not (caller_inside or current_user.totp_enabled):
            stranded = ", ".join(ctx["superadmins_without_totp"]) or "none"
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    "Refusing to require a second factor from outside: your current "
                    f"address ({ctx['caller_ip'] or 'unknown'}) is not internal or trusted "
                    "and your own account has no TOTP enrolled, so you could lock "
                    "yourself out. Enrol TOTP on your account, or enable this from an "
                    "internal network. Local superadmins without TOTP, who would be "
                    f"stranded from outside until they enrol from inside: {stranded}."
                ),
            )

    new = body.model_dump()
    before = old.model_dump()
    changed = sorted(k for k in new if new[k] != before.get(k))
    row.web_exposure = new
    if changed:
        db.add(
            _audit(
                current_user,
                action="update",
                display="Web exposure settings",
                old={k: before[k] for k in changed},
                new={k: new[k] for k in changed},
                changed=changed,
            )
        )
    await db.commit()
    cfg_mod.invalidate_cache()
    warnings: list[str] = []
    if (body.external_throttle_enabled or body.ban_enabled) and ctx["caller_class"] == "external":
        warnings.append(
            "Your current address is external: the throttle / ban would apply to your own "
            "next sign-in from here. Add your network to the trusted list if it is yours."
        )
    return {"config": body.model_dump(), "warnings": warnings, **await _context(request, db, body)}


@router.post("/trusted-networks", response_model=WebExposureConfigResponse)
async def add_trusted_network(
    body: TrustedNetworkRequest, request: Request, db: DB, current_user: SuperAdmin
) -> dict[str, Any]:
    """ "This is ours": add one network (typically a source bucket from the
    evidence table) to the trusted list."""
    forbid_in_demo_mode("Web exposure settings are disabled in demo mode")
    try:
        canon = str(ipaddress.ip_network(body.cidr.strip(), strict=False))
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"invalid CIDR: {exc}") from exc
    row = await _row(db)
    cfg = config_from_row(row.web_exposure)
    if canon not in cfg.trusted_networks:
        old_list = list(cfg.trusted_networks)
        cfg = WebExposureConfig.model_validate(
            {**cfg.model_dump(), "trusted_networks": [*old_list, canon]}
        )
        row.web_exposure = cfg.model_dump()
        db.add(
            _audit(
                current_user,
                action="update",
                display="Web exposure trusted networks",
                old={"trusted_networks": old_list},
                new={"trusted_networks": cfg.trusted_networks},
                changed=["trusted_networks"],
            )
        )
        await db.commit()
        cfg_mod.invalidate_cache()
    return {"config": cfg.model_dump(), **await _context(request, db, cfg)}


# ── Bans (tier 1b) ──────────────────────────────────────────────────


@router.get("/bans", response_model=BansResponse)
async def list_bans(db: DB, current_user: SuperAdmin) -> dict[str, Any]:
    bans = await mitigations.list_bans()
    return {"available": bans is not None, "bans": bans or []}


@router.delete("/bans", response_model=BansClearedResponse)
async def clear_bans(db: DB, current_user: SuperAdmin, bucket: str | None = None) -> dict[str, Any]:
    """Clear one ban (``?bucket=203.0.113.0/24``) or all of them."""
    if bucket is not None:
        try:
            ipaddress.ip_network(bucket, strict=False)
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid bucket") from exc
    try:
        cleared = await mitigations.clear_bans(bucket)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Redis unreachable") from exc
    db.add(
        _audit(
            current_user,
            action="web_exposure.ban_cleared",
            display=f"ban {bucket}" if bucket else "all bans",
            new={"bucket": bucket, "cleared": cleared},
        )
    )
    await db.commit()
    return {"cleared": cleared}


# ── Tier 3a: appliance Web UI source restriction ────────────────────


class ApplyAllowListRequest(BaseModel):
    #: Same acknowledgements the Web UI access endpoint takes (#1013).
    override_lockout: bool = False
    acknowledge_console_only: bool = False


@router.post("/apply-web-ui-allow-list", response_model=WebUIAccessResponse)
async def apply_web_ui_allow_list(
    body: ApplyAllowListRequest, request: Request, db: DB, current_user: SuperAdmin
) -> WebUIAccessResponse:
    """Tier 3a, appliance only: write the trusted networks plus private space
    (CGNAT and ULA included) into ``web_ui_allowed_cidrs`` via the existing
    Web UI access endpoint, so its lock-out guards (your own address must be
    covered, the console-only pre-flight) apply unchanged. A bridge to a
    control that already exists, not a new mechanism."""
    forbid_in_demo_mode("Web exposure settings are disabled in demo mode")
    if not settings.appliance_mode:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "The Web UI source restriction is an appliance control. On Docker Compose or "
            "Kubernetes restrict the published port / load balancer source ranges instead "
            "(docs/deployment/REVERSE_PROXY.md).",
        )
    row = await db.get(PlatformSettings, 1)
    cfg = config_from_row(row.web_exposure if row else None)
    cidrs = [*PRIVATE_RANGES, *cfg.trusted_networks]

    from app.api.v1.appliance.firewall import (  # noqa: PLC0415
        SetWebUIAccessRequest,
        set_web_ui_access,
    )

    res = await set_web_ui_access(
        SetWebUIAccessRequest(
            allowed_cidrs=cidrs,
            override_lockout=body.override_lockout,
            acknowledge_console_only=body.acknowledge_console_only,
        ),
        request,
        db,
        current_user,
    )
    db.add(
        _audit(
            current_user,
            action="web_exposure.apply_web_ui_allow_list",
            display="Web UI allow-list from trusted networks",
            new={"allowed_cidrs": res.allowed_cidrs},
        )
    )
    await db.commit()
    return res
