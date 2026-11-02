"""Security dashboard tab summary (issue #109).

Aggregates four security-relevant signals into one rollup:

* **MFA coverage** — % of *local-auth* users with TOTP enrolled.
  External-auth users (LDAP / OIDC / SAML) authenticate against
  the upstream provider and don't carry SpatiumDDI-side TOTP, so
  including them in the denominator would understate coverage.
* **API tokens nearing expiry** — count + detail of tokens whose
  ``expires_at`` is within the threshold window. NULL ``expires_at``
  means never-expires (intentional for service tokens) and is
  excluded from the count.
* **Failed-login bursts** — audit rows with ``action="login"`` and
  ``result="failure"`` (what every sign-in path writes for a rejected
  attempt: bad password, unknown user, locked or disabled account, bad
  MFA code, external-provider rejection; ``"error"`` rows are provider
  outages, not guesses) in the trailing 24 h, grouped by source IP +
  username so brute-force runs surface as a single row.
* **Recent permission changes** — audit rows touching ``role`` /
  ``group`` / ``user`` resources within the trailing 7 d. The
  panel surfaces who changed what so an audit walk doesn't need a
  filter dance.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import desc, func, select

from app.api.deps import DB, CurrentUser
from app.core.permissions import is_effective_superadmin, user_has_permission
from app.models.audit import AuditLog
from app.models.auth import APIToken, User

router = APIRouter()


# ── Schemas ─────────────────────────────────────────────────────────


class MFAUserRow(BaseModel):
    id: str
    username: str
    display_name: str
    last_login_at: datetime | None
    auth_source: str


class APITokenRow(BaseModel):
    id: str
    name: str
    user_id: str | None
    user_display: str | None
    expires_at: datetime | None
    days_remaining: int | None
    scopes: list[str]


class FailedLoginRow(BaseModel):
    user_display_name: str
    source_ip: str | None
    failure_count: int
    latest_at: datetime


class PermissionChangeRow(BaseModel):
    id: str
    timestamp: datetime
    actor: str
    action: str
    resource_type: str
    resource_id: str
    resource_display: str
    changed_fields: list[str] | None


class SecurityDashboardSummary(BaseModel):
    generated_at: datetime

    # True when the four per-row lists below were stripped for this caller
    # (#400 M2): an empty list then means "not shown to you", never "none".
    detail_withheld: bool = False

    # MFA
    mfa_total_local_users: int
    mfa_enrolled_count: int
    mfa_coverage_pct: float
    mfa_unenrolled: list[MFAUserRow]

    # API tokens
    api_tokens_total: int
    api_tokens_expiring_count: int
    api_tokens_expiring: list[APITokenRow]

    # Failed logins
    failed_login_window_hours: int
    failed_login_total: int
    failed_login_top_sources: list[FailedLoginRow]

    # Permission changes
    permission_change_window_days: int
    permission_change_count: int
    permission_changes: list[PermissionChangeRow]


# Per-panel knobs. Tuned to "informative without noise" — operators
# who want a different threshold edit the rule on the alert side
# (#71, #72, #73) rather than this dashboard.
_API_TOKEN_EXPIRY_THRESHOLD_DAYS = 30
_FAILED_LOGIN_WINDOW_HOURS = 24
_PERMISSION_CHANGE_WINDOW_DAYS = 7
_DETAIL_LIMIT = 20

# Resource_type values that count as "permission changes" for the
# audit-driven panel. Mirrors the strings emitted by each router's
# audit-log call.
_PERMISSION_RESOURCE_TYPES: frozenset[str] = frozenset(
    {
        "user",
        "group",
        "role",
        "api_token",
        "auth_provider",
        "auth_provider_secret",
        "auth_group_mapping",
    }
)


# ── Route ───────────────────────────────────────────────────────────


@router.get("/security/summary", response_model=SecurityDashboardSummary)
async def security_summary(db: DB, current_user: CurrentUser) -> SecurityDashboardSummary:
    """Single-shot rollup for the Security dashboard tab.

    SECURITY (#400 / M2): this rollup surfaces user/MFA/token/login
    telemetry (per-user last-login times, failed-login source IPs,
    permission-change actor history) that must not be exposed to any
    authenticated caller. Privileged callers — an effective superadmin
    or anyone holding ``read`` on ``audit_log`` *or* ``user`` — get the
    full per-row detail. Everyone else still gets the aggregate
    headline counts (so the dashboard tile renders) but the per-user
    PII-bearing detail lists are stripped. This keeps the legitimate
    operator flow intact while closing the unauthenticated-PII leak.
    """
    privileged = (
        is_effective_superadmin(current_user)
        or user_has_permission(current_user, "read", "audit_log")
        or user_has_permission(current_user, "read", "user")
    )
    now = datetime.now(UTC)

    # ── MFA coverage (local-auth users only) ────────────────────
    local_users = list(
        (
            await db.execute(
                select(User).where(User.is_active.is_(True)).where(User.auth_source == "local")
            )
        )
        .scalars()
        .all()
    )
    enrolled = [u for u in local_users if u.totp_enabled]
    unenrolled = [u for u in local_users if not u.totp_enabled]
    mfa_total = len(local_users)
    mfa_enrolled = len(enrolled)
    mfa_pct = (mfa_enrolled / mfa_total * 100.0) if mfa_total else 0.0
    mfa_unenrolled_rows = [
        MFAUserRow(
            id=str(u.id),
            username=u.username,
            display_name=u.display_name or u.username,
            last_login_at=u.last_login_at,
            auth_source=u.auth_source,
        )
        for u in sorted(
            unenrolled,
            key=lambda u: (u.last_login_at or datetime.min.replace(tzinfo=UTC)),
            reverse=True,
        )[:_DETAIL_LIMIT]
    ]

    # ── API tokens nearing expiry ───────────────────────────────
    tokens_total = (await db.execute(select(func.count()).select_from(APIToken))).scalar_one()
    expiry_cutoff = now + timedelta(days=_API_TOKEN_EXPIRY_THRESHOLD_DAYS)
    expiring_tokens = list(
        (
            await db.execute(
                select(APIToken)
                .where(APIToken.is_active.is_(True))
                .where(APIToken.expires_at.is_not(None))
                .where(APIToken.expires_at > now)
                .where(APIToken.expires_at <= expiry_cutoff)
                .order_by(APIToken.expires_at.asc())
            )
        )
        .scalars()
        .all()
    )
    user_ids = {t.user_id for t in expiring_tokens if t.user_id}
    user_lookup: dict[str, str] = {}
    if user_ids:
        user_rows = (await db.execute(select(User).where(User.id.in_(user_ids)))).scalars().all()
        user_lookup = {str(u.id): (u.display_name or u.username) for u in user_rows}
    expiring_rows = []
    for t in expiring_tokens[:_DETAIL_LIMIT]:
        days_remaining: int | None = None
        if t.expires_at is not None:
            delta = t.expires_at - now
            days_remaining = max(0, delta.days)
        expiring_rows.append(
            APITokenRow(
                id=str(t.id),
                name=t.name,
                user_id=str(t.user_id) if t.user_id else None,
                user_display=(user_lookup.get(str(t.user_id)) if t.user_id else None),
                expires_at=t.expires_at,
                days_remaining=days_remaining,
                scopes=t.scopes if isinstance(t.scopes, list) else [],
            )
        )

    # ── Failed-login bursts (24 h, grouped by IP + user) ─────────
    failed_window_start = now - timedelta(hours=_FAILED_LOGIN_WINDOW_HOURS)
    failed_rows = list(
        (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.action == "login")
                .where(AuditLog.result == "failure")
                .where(AuditLog.timestamp >= failed_window_start)
            )
        )
        .scalars()
        .all()
    )
    by_source: dict[tuple[str, str | None], list[AuditLog]] = defaultdict(list)
    for r in failed_rows:
        by_source[(r.user_display_name or "(unknown)", r.source_ip)].append(r)
    grouped: list[FailedLoginRow] = []
    for (user, ip), rows in by_source.items():
        latest = max(r.timestamp for r in rows)
        grouped.append(
            FailedLoginRow(
                user_display_name=user,
                source_ip=ip,
                failure_count=len(rows),
                latest_at=latest,
            )
        )
    grouped.sort(key=lambda g: g.failure_count, reverse=True)

    # ── Permission audit (7 d) ──────────────────────────────────
    perm_window_start = now - timedelta(days=_PERMISSION_CHANGE_WINDOW_DAYS)
    perm_rows = list(
        (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.timestamp >= perm_window_start)
                .where(AuditLog.action.in_({"create", "update", "delete"}))
                .where(AuditLog.resource_type.in_(_PERMISSION_RESOURCE_TYPES))
                .order_by(desc(AuditLog.timestamp))
            )
        )
        .scalars()
        .all()
    )
    perm_change_rows = [
        PermissionChangeRow(
            id=str(r.id),
            timestamp=r.timestamp,
            actor=r.user_display_name,
            action=r.action,
            resource_type=r.resource_type,
            resource_id=r.resource_id,
            resource_display=r.resource_display or "",
            changed_fields=(list(r.changed_fields) if isinstance(r.changed_fields, list) else None),
        )
        for r in perm_rows[:_DETAIL_LIMIT]
    ]

    # SECURITY (#400 / M2): aggregate counts are safe for any
    # authenticated viewer, but the per-row detail lists carry PII
    # (usernames, last-login timestamps, failed-login source IPs,
    # permission-change actors). Withhold those from non-privileged
    # callers — the tile still renders from the headline counts.
    return SecurityDashboardSummary(
        generated_at=now,
        detail_withheld=not privileged,
        mfa_total_local_users=mfa_total,
        mfa_enrolled_count=mfa_enrolled,
        mfa_coverage_pct=round(mfa_pct, 1),
        mfa_unenrolled=mfa_unenrolled_rows if privileged else [],
        api_tokens_total=int(tokens_total),
        api_tokens_expiring_count=len(expiring_tokens),
        api_tokens_expiring=expiring_rows if privileged else [],
        failed_login_window_hours=_FAILED_LOGIN_WINDOW_HOURS,
        failed_login_total=len(failed_rows),
        failed_login_top_sources=grouped[:_DETAIL_LIMIT] if privileged else [],
        permission_change_window_days=_PERMISSION_CHANGE_WINDOW_DAYS,
        permission_change_count=len(perm_rows),
        permission_changes=perm_change_rows if privileged else [],
    )
