"""Operator Copilot tools for TLS certificate monitoring (issue #118).

Read tools (all default-enabled, ``module="security.tls_certs"`` so
disabling the feature module strips them — NN #14):

* ``find_tls_cert`` — list / look up monitored targets by host, domain,
  zone, IP, or expiring-within-N-days. Identity + lifecycle only.
* ``count_tls_certs_expiring`` — rollup of certs expiring within N days
  (≤7 / ≤14 / ≤30 / ≤90 buckets) + the soonest.
* ``get_cert_chain`` — the latest probe's parsed chain for one target.
* ``count_tls_targets_by_state`` — coarse health rollup by state bucket.

Write tool:

* ``propose_run_cert_probe`` — gated write (default-DISABLED: it touches
  the network). Delegates to the ``run_cert_probe`` Operation so the
  preview / apply contract matches the REST ``POST /tls-certs/{id}/probe``.

NEVER returns private keys (we never hold them) — PEM is only surfaced
via ``get_cert_chain`` and is public material.

Distinct tool names from the ACME-client tools (``find_certificates`` /
``count_certificates_expiring``) so the registry doesn't collide.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.tls_cert import TLSCertProbe, TLSCertTarget
from app.services.ai import operations
from app.services.ai.tools.base import register_tool

_MODULE = "security.tls_certs"


def _days_remaining(not_after: datetime | None, now: datetime) -> int | None:
    if not_after is None:
        return None
    na = not_after if not_after.tzinfo else not_after.replace(tzinfo=UTC)
    return int((na - now).total_seconds() // 86400)


def _target_to_dict(t: TLSCertTarget, now: datetime) -> dict[str, Any]:
    return {
        "id": str(t.id),
        "host": t.host,
        "port": t.port,
        "display_name": t.display_name,
        "state": t.state,
        "source": t.source,
        "enabled": t.enabled,
        "subject_cn": t.subject_cn,
        "issuer_cn": t.issuer_cn,
        "sans": list(t.sans_json or []),
        "not_after": t.not_after.isoformat() if t.not_after else None,
        "days_remaining": _days_remaining(t.not_after, now),
        "chain_valid": t.chain_valid,
        "self_signed": t.self_signed,
        "fingerprint_sha256": t.fingerprint_sha256,
        "last_checked_at": t.last_checked_at.isoformat() if t.last_checked_at else None,
        "last_error": t.last_error,
    }


# ── find_tls_cert ──────────────────────────────────────────────────


class FindTLSCertArgs(BaseModel):
    host: str | None = Field(default=None, description="Substring match on host / display_name.")
    domain_id: str | None = Field(default=None, description="Filter to a tracked Domain (UUID).")
    dns_zone_id: str | None = Field(default=None, description="Filter to a DNS zone (UUID).")
    state: str | None = Field(
        default=None,
        description="Filter by state: ok / expiring / expired / mismatch / unreachable / unknown.",
    )
    expiring_within_days: int | None = Field(
        default=None, ge=1, le=3650, description="Only certs whose not_after is within N days."
    )
    limit: int = Field(default=50, ge=1, le=200)


@register_tool(
    name="find_tls_cert",
    permission=("read", "tls_cert"),
    description=(
        "List monitored TLS certificate targets. Each row carries host, "
        "state (ok / expiring / expired / mismatch / unreachable), subject "
        "+ issuer CN, SANs, not_after + days_remaining, chain validity, and "
        "fingerprint. Filter by host substring, domain_id, dns_zone_id, "
        "state, or expiring_within_days. Use to answer 'which services have "
        "a cert expiring this month?' or 'is auth.example.com's chain "
        "valid?'. Read-only; never returns private keys."
    ),
    args_model=FindTLSCertArgs,
    category="security",
    default_enabled=True,
    module=_MODULE,
)
async def find_tls_cert(db: AsyncSession, user: User, args: FindTLSCertArgs) -> dict[str, Any]:
    now = datetime.now(UTC)
    stmt = select(TLSCertTarget)
    if args.host:
        needle = f"%{args.host.strip()}%"
        stmt = stmt.where(
            or_(TLSCertTarget.host.ilike(needle), TLSCertTarget.display_name.ilike(needle))
        )
    if args.domain_id:
        try:
            stmt = stmt.where(TLSCertTarget.domain_id == uuid.UUID(args.domain_id))
        except ValueError:
            return {"error": f"invalid domain_id {args.domain_id!r}"}
    if args.dns_zone_id:
        try:
            stmt = stmt.where(TLSCertTarget.dns_zone_id == uuid.UUID(args.dns_zone_id))
        except ValueError:
            return {"error": f"invalid dns_zone_id {args.dns_zone_id!r}"}
    if args.state:
        stmt = stmt.where(TLSCertTarget.state == args.state)
    if args.expiring_within_days is not None:
        cutoff = now + timedelta(days=args.expiring_within_days)
        stmt = stmt.where(TLSCertTarget.not_after.is_not(None), TLSCertTarget.not_after <= cutoff)
    stmt = stmt.order_by(TLSCertTarget.host.asc()).limit(args.limit)
    rows = list((await db.execute(stmt)).scalars().all())
    return {"targets": [_target_to_dict(t, now) for t in rows], "count": len(rows)}


# ── count_tls_certs_expiring ───────────────────────────────────────


class CountTLSCertsExpiringArgs(BaseModel):
    within_days: int = Field(default=30, ge=1, le=3650)
    enabled_only: bool = Field(default=True)


@register_tool(
    name="count_tls_certs_expiring",
    permission=("read", "tls_cert"),
    description=(
        "Count monitored TLS certs expiring within N days (default 30), "
        "bucketed ≤7 / ≤14 / ≤30 / ≤90 days, plus the soonest-expiring "
        "target. Use for 'how many certs lapse this month?'. Read-only."
    ),
    args_model=CountTLSCertsExpiringArgs,
    category="security",
    default_enabled=True,
    module=_MODULE,
)
async def count_tls_certs_expiring(
    db: AsyncSession, user: User, args: CountTLSCertsExpiringArgs
) -> dict[str, Any]:
    now = datetime.now(UTC)
    stmt = select(TLSCertTarget).where(TLSCertTarget.not_after.is_not(None))
    if args.enabled_only:
        stmt = stmt.where(TLSCertTarget.enabled.is_(True))
    rows = list((await db.execute(stmt)).scalars().all())

    buckets = {"<=7": 0, "<=14": 0, "<=30": 0, "<=90": 0}
    within = 0
    soonest: dict[str, Any] | None = None
    for t in rows:
        d = _days_remaining(t.not_after, now)
        if d is None:
            continue
        if d <= args.within_days:
            within += 1
        if d <= 7:
            buckets["<=7"] += 1
        if d <= 14:
            buckets["<=14"] += 1
        if d <= 30:
            buckets["<=30"] += 1
        if d <= 90:
            buckets["<=90"] += 1
        if soonest is None or d < soonest["days_remaining"]:
            soonest = {
                "id": str(t.id),
                "host": t.host,
                "days_remaining": d,
                "not_after": t.not_after.isoformat() if t.not_after else None,
            }
    return {
        "within_days": args.within_days,
        "count": within,
        "buckets": buckets,
        "soonest_expiring": soonest,
    }


# ── get_cert_chain ─────────────────────────────────────────────────


class GetCertChainArgs(BaseModel):
    target_id: str = Field(description="UUID of the tls_cert_target.")


@register_tool(
    name="get_cert_chain",
    permission=("read", "tls_cert"),
    description=(
        "Return the latest successful probe's parsed certificate for one "
        "target: subject / issuer CN, serial, validity window, SANs, key "
        "algorithm + size, signature algorithm, chain depth + validity, "
        "self-signed flag, and SHA-256 fingerprint. Public chain data — no "
        "private keys. Read-only."
    ),
    args_model=GetCertChainArgs,
    category="security",
    default_enabled=True,
    module=_MODULE,
)
async def get_cert_chain(db: AsyncSession, user: User, args: GetCertChainArgs) -> dict[str, Any]:
    try:
        tid = uuid.UUID(args.target_id)
    except ValueError:
        return {"error": f"invalid target_id {args.target_id!r}"}
    probe = await db.scalar(
        select(TLSCertProbe)
        .where(TLSCertProbe.target_id == tid, TLSCertProbe.ok.is_(True))
        .order_by(TLSCertProbe.probed_at.desc())
        .limit(1)
    )
    if probe is None:
        return {"error": "no successful probe yet for this target"}
    return {
        "target_id": str(tid),
        "probed_at": probe.probed_at.isoformat(),
        "subject_cn": probe.subject_cn,
        "issuer_cn": probe.issuer_cn,
        "serial": probe.serial,
        "not_before": probe.not_before.isoformat() if probe.not_before else None,
        "not_after": probe.not_after.isoformat() if probe.not_after else None,
        "sans": list(probe.sans_json or []),
        "key_algo": probe.key_algo,
        "key_size": probe.key_size,
        "sig_algo": probe.sig_algo,
        "chain_depth": probe.chain_depth,
        "chain_valid": probe.chain_valid,
        "chain_error": probe.chain_error,
        "self_signed": probe.self_signed,
        "fingerprint_sha256": probe.fingerprint_sha256,
    }


# ── count_tls_targets_by_state ─────────────────────────────────────


class CountTLSTargetsByStateArgs(BaseModel):
    enabled_only: bool = Field(default=True)


@register_tool(
    name="count_tls_targets_by_state",
    permission=("read", "tls_cert"),
    description=(
        "Coarse health rollup of monitored TLS endpoints grouped by state "
        "(ok / expiring / expired / mismatch / unreachable / unknown). Use "
        "for 'how healthy is the cert fleet?'. Read-only."
    ),
    args_model=CountTLSTargetsByStateArgs,
    category="security",
    default_enabled=True,
    module=_MODULE,
)
async def count_tls_targets_by_state(
    db: AsyncSession, user: User, args: CountTLSTargetsByStateArgs
) -> dict[str, Any]:
    stmt = select(TLSCertTarget.state, func.count()).group_by(TLSCertTarget.state)
    if args.enabled_only:
        stmt = stmt.where(TLSCertTarget.enabled.is_(True))
    rows = (await db.execute(stmt)).all()
    by_state = {state: count for state, count in rows}
    return {"by_state": by_state, "total": sum(by_state.values())}


# ── find_ct_log_entries (off-prem read, default-disabled) ──────────


class FindCTLogEntriesArgs(BaseModel):
    host: str = Field(description="Hostname / domain to query CT logs for.")
    limit: int = Field(default=25, ge=1, le=100)


@register_tool(
    name="find_ct_log_entries",
    permission=("read", "tls_cert"),
    description=(
        "Cross-reference a host/domain against public Certificate "
        "Transparency logs (crt.sh) — every CA-logged cert issued for the "
        "name, to spot issuance you didn't deploy. OFF-PREM: this queries "
        "crt.sh and leaks the hostname to it, so it's default-disabled; an "
        "operator opts in per provider. Read-only."
    ),
    args_model=FindCTLogEntriesArgs,
    category="security",
    default_enabled=False,
    module=_MODULE,
)
async def find_ct_log_entries(
    db: AsyncSession, user: User, args: FindCTLogEntriesArgs
) -> dict[str, Any]:
    from app.services.tls_cert.ct_log import lookup_ct  # noqa: PLC0415

    return await lookup_ct(args.host, limit=args.limit)


# ── propose_run_cert_probe (gated write, default-disabled) ─────────


@register_tool(
    name="propose_run_cert_probe",
    permission=("write", "tls_cert"),
    description=(
        "Prepare a proposal to probe a TLS cert target now. The operator "
        "must click Apply for the probe to run — it opens a real TLS "
        "connection. Returns kind='proposal'; surface the preview and wait "
        "for the operator's decision. Use when someone just rotated a cert "
        "and wants to confirm the new one is live."
    ),
    args_model=operations.RunCertProbeArgs,
    writes=False,  # the propose tool is read-only; apply is the write
    category="security",
    default_enabled=False,
    module=_MODULE,
)
async def propose_run_cert_probe(
    db: AsyncSession, user: User, args: operations.RunCertProbeArgs
) -> dict[str, Any]:
    from app.services.ai.tools.proposals import _persist_proposal, _proposal_result  # noqa: PLC0415

    op = operations.get_operation("run_cert_probe")
    if op is None:
        return {"error": "Operation 'run_cert_probe' is not registered"}
    preview = await op.preview(db, user, args)
    if not preview.ok:
        return {
            "kind": "proposal_rejected",
            "operation": "run_cert_probe",
            "detail": preview.detail,
        }
    proposal = await _persist_proposal(
        db,
        user=user,
        operation="run_cert_probe",
        args=args.model_dump(),
        preview_text=preview.preview_text,
    )
    return _proposal_result(proposal, preview_text=preview.preview_text)
