"""Operator Copilot tools for the appliance Web UI TLS certificate
surface (issue #438 Phase 1 — embedded ACME client).

Three tools land here:

* ``find_certificates`` — read-only list of every
  ``ApplianceCertificate`` row (uploaded / CSR-pending / Let's Encrypt
  / self-signed), with source, active flag, subject CN, SANs, issuer,
  fingerprint, and validity window. Use to answer "what cert is
  active?", "do we have a Let's Encrypt cert yet?", or "what's the
  expiry on the wildcard cert?". NEVER returns the private key — the
  ``key_encrypted`` column is omitted entirely.
* ``count_certificates_expiring`` — counts active-or-all certs whose
  ``valid_to`` falls within N days of now. The capacity / "is anything
  about to lapse?" rollup.
* ``get_acme_account`` — the ACME *client* account at the CA. Returns
  the directory URL / account URL / email / EAB key id, plus an
  ``eab_hmac_set`` boolean — NEVER the account key or the EAB HMAC
  secret. Default-disabled (off-prem CA context + auth material
  adjacency); operators opt in via the Tool Catalog.

Read-only. The matching ``propose_*`` issuance write (model proposes
"issue a cert for X via Let's Encrypt", operator clicks Apply) is
deferred — issuance is irreversible at the CA (the serial is logged)
and the friendly path is the Certificates tab's "Issue via Let's
Encrypt" flow. The Operation/preview seam can be filled in a later
wave without touching this module.

All three carry ``module="security.certificates"`` so disabling the
feature module strips them from the AI surface (NN #14).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import is_effective_superadmin
from app.models.appliance import ApplianceCertificate
from app.models.auth import User
from app.services.ai.tools.base import register_tool


def _cert_to_dict(row: ApplianceCertificate) -> dict[str, Any]:
    """Compact JSON shape — identity + lifecycle only. The
    Fernet-encrypted private key (``key_encrypted``) is NEVER included;
    nor is the raw cert PEM (large + not Copilot-useful — the
    fingerprint + identity columns are the operator-relevant facts)."""
    return {
        "id": str(row.id),
        "name": row.name,
        "source": row.source,
        "is_active": row.is_active,
        "subject_cn": row.subject_cn,
        "sans": list(row.sans_json or []),
        "issuer_cn": row.issuer_cn,
        "fingerprint_sha256": row.fingerprint_sha256,
        "valid_from": (row.valid_from.isoformat() if row.valid_from else None),
        "valid_to": (row.valid_to.isoformat() if row.valid_to else None),
        # ``cert_pem IS NULL`` is the canonical "CSR pending" sentinel.
        "csr_pending": row.cert_pem is None,
        "activated_at": (row.activated_at.isoformat() if row.activated_at else None),
        "created_at": row.created_at.isoformat(),
        "notes": row.notes,
    }


# ── find_certificates ──────────────────────────────────────────────


class FindCertificatesArgs(BaseModel):
    source: str | None = Field(
        default=None,
        description=(
            "Filter by certificate source: 'uploaded' / 'csr' / "
            "'letsencrypt' / 'self-signed'. Omit for all sources."
        ),
    )
    active_only: bool = Field(
        default=False,
        description="Return only the certificate nginx is actively serving.",
    )
    limit: int = Field(default=50, ge=1, le=200)


@register_tool(
    name="find_certificates",
    description=(
        "List the appliance Web UI TLS certificates. Each row carries "
        "the operator label (name), source (uploaded / csr / letsencrypt "
        "/ self-signed), whether it's the active cert nginx serves, the "
        "subject CN, SAN list, issuer CN, SHA-256 fingerprint, and the "
        "valid-from / valid-to window. Use to answer 'what cert is "
        "active?', 'do we have a Let's Encrypt cert yet?', or 'what's "
        "the expiry on the wildcard?'. Filter by source or active_only. "
        "Read-only — the private key is NEVER returned. Issuance goes "
        "through the Certificates tab's 'Issue via Let's Encrypt' flow."
    ),
    args_model=FindCertificatesArgs,
    category="admin",
    default_enabled=True,
    module="security.certificates",
)
async def find_certificates(
    db: AsyncSession, user: User, args: FindCertificatesArgs
) -> dict[str, Any]:
    stmt = select(ApplianceCertificate).order_by(
        ApplianceCertificate.is_active.desc(),
        ApplianceCertificate.created_at.desc(),
    )
    if args.source is not None:
        stmt = stmt.where(ApplianceCertificate.source == args.source)
    if args.active_only:
        stmt = stmt.where(ApplianceCertificate.is_active.is_(True))
    rows = list((await db.execute(stmt.limit(args.limit))).scalars().all())
    return {
        "certificates": [_cert_to_dict(r) for r in rows],
        "count": len(rows),
    }


# ── count_certificates_expiring ────────────────────────────────────


class CountCertificatesExpiringArgs(BaseModel):
    within_days: int = Field(
        default=30,
        ge=1,
        le=3650,
        description="Window in days from now to count certs expiring within.",
    )
    active_only: bool = Field(
        default=True,
        description=(
            "Count only the active (nginx-served) cert. Default True — "
            "the active cert is the one whose expiry actually matters. "
            "Set False to count every stored cert."
        ),
    )


@register_tool(
    name="count_certificates_expiring",
    description=(
        "Count appliance Web UI TLS certificates whose validity expires "
        "within N days of now (default 30). Counts only the active cert "
        "by default — the one whose lapse would break HTTPS — or every "
        "stored cert with active_only=False. Returns the count plus the "
        "soonest-expiring cert's name / valid_to / days_remaining. Use "
        "to answer 'is the cert about to expire?' or 'how long until we "
        "need to renew?'. Read-only."
    ),
    args_model=CountCertificatesExpiringArgs,
    category="admin",
    default_enabled=True,
    module="security.certificates",
)
async def count_certificates_expiring(
    db: AsyncSession, user: User, args: CountCertificatesExpiringArgs
) -> dict[str, Any]:
    now = datetime.now(UTC)
    cutoff = now + timedelta(days=args.within_days)
    stmt = select(ApplianceCertificate).where(
        ApplianceCertificate.valid_to.is_not(None),
        ApplianceCertificate.valid_to <= cutoff,
    )
    if args.active_only:
        stmt = stmt.where(ApplianceCertificate.is_active.is_(True))
    rows = list((await db.execute(stmt)).scalars().all())

    soonest: dict[str, Any] | None = None
    for r in rows:
        if r.valid_to is None:
            continue
        if soonest is None or r.valid_to < datetime.fromisoformat(soonest["valid_to"]):
            soonest = {
                "id": str(r.id),
                "name": r.name,
                "source": r.source,
                "valid_to": r.valid_to.isoformat(),
                "days_remaining": (r.valid_to - now).days,
            }
    return {
        "count": len(rows),
        "within_days": args.within_days,
        "active_only": args.active_only,
        "soonest_expiring": soonest,
    }


# ── get_acme_account ───────────────────────────────────────────────


class GetACMEAccountArgs(BaseModel):
    pass


@register_tool(
    name="get_acme_account",
    description=(
        "Read the embedded ACME client account configured for Let's "
        "Encrypt issuance (superadmin only). Returns the CA directory "
        "URL, the CA-assigned account URL (NULL until first issuance), "
        "the contact email, the EAB key id, and an ``eab_hmac_set`` "
        "boolean — the account key and EAB HMAC secret are NEVER "
        "returned. Use to answer 'is an ACME account configured?' or "
        "'which CA are we issuing against?'. Read-only; disabled by "
        "default (off-prem CA + auth-material adjacency) — opt in via "
        "Administration -> AI Tool Catalog."
    ),
    args_model=GetACMEAccountArgs,
    category="admin",
    # Default-disabled (NN #13): the surface sits next to ACME account
    # auth material (account key + EAB HMAC). We never return the
    # secrets, but the conservative default is opt-in + superadmin-gated.
    default_enabled=False,
    module="security.certificates",
)
async def get_acme_account(
    db: AsyncSession, user: User, args: GetACMEAccountArgs
) -> dict[str, Any]:
    if not is_effective_superadmin(user):
        return {
            "error": (
                "The ACME account surface is restricted to superadmin "
                "users. Ask your platform admin to run the query."
            )
        }
    # Lazy import — keeps the ACME client model out of the tool-registry
    # import path for installs that never touch ACME.
    from app.models.acme_client import ACMEClientAccount  # noqa: PLC0415

    row = (
        await db.execute(
            select(ACMEClientAccount).order_by(ACMEClientAccount.created_at.desc()).limit(1)
        )
    ).scalar_one_or_none()
    if row is None:
        return {"configured": False}
    return {
        "configured": True,
        "id": str(row.id),
        "directory_url": row.directory_url,
        "account_url": row.account_url,
        "email": row.email,
        "eab_kid": row.eab_kid,
        # Boolean only — the EAB HMAC + account key are never surfaced.
        "eab_hmac_set": row.eab_hmac_encrypted is not None,
        "created_at": row.created_at.isoformat(),
        "modified_at": row.modified_at.isoformat(),
    }


__all__ = [
    "find_certificates",
    "count_certificates_expiring",
    "get_acme_account",
]
