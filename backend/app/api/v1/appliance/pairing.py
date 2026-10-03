"""Pairing-code admin surface (#169 + #170 Wave A3 reshape).

The original #169 design coupled every pairing code to a
``deployment_kind`` (``dns`` / ``dhcp`` / ``both``) because the
consume endpoint had to hand back the matching long-PSK bootstrap
key. Wave A2's supervisor identity model removed the long PSK
entirely — supervisors prove identity via Ed25519 public-key
submission, not a shared secret — so codes are now kind-agnostic.

What this module owns:

* ``POST /api/v1/appliance/pairing-codes`` — mint a code. Required:
  ``persistent: bool``. Optional: ``expires_in_minutes`` (defaults:
  15 min for ephemeral, no expiry for persistent), ``max_claims``
  (only for persistent; NULL = unlimited), ``note``.
* ``GET /api/v1/appliance/pairing-codes`` — list every code with
  redacted shape (``code_last_two`` only) + claim count + derived
  ``state`` (pending / claimed / expired / revoked / disabled).
* ``DELETE /api/v1/appliance/pairing-codes/{id}`` — revoke (permanent;
  no-op on already-revoked rows).
* ``POST /api/v1/appliance/pairing-codes/{id}/enable`` — re-enable a
  paused persistent code. 404 for ephemeral codes.
* ``POST /api/v1/appliance/pairing-codes/{id}/disable`` — pause a
  persistent code; new claims rejected but already-claimed
  appliances unaffected.
* ``POST /api/v1/appliance/pairing-codes/{id}/reveal`` —
  password-gated re-reveal of a persistent code's cleartext value.
  Mirrors agent-bootstrap-keys reveal: superadmin only, local-auth
  only, audited. Ephemeral codes are NOT re-revealable (the cleartext
  is shown exactly once at create time).

What this module no longer owns:

* The consume endpoint (``POST /api/v1/appliance/pair``) is gone —
  all pairing now flows through ``POST /api/v1/appliance/supervisor/
  register`` (Wave A2), which writes ``pairing_claim`` rows
  directly. Existing dns / dhcp installers that used /pair stop
  working with Wave A3 control planes; per the alpha-stage caveat
  on #170 we don't carry compat shims.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.api.deps import DB, CurrentUser
from app.api.stepup import require_operator_stepup
from app.core.crypto import decrypt_str, encrypt_str
from app.core.permissions import is_effective_superadmin, require_permission
from app.models.appliance import PairingClaim, PairingCode
from app.models.audit import AuditLog
from app.models.auth import User

logger = structlog.get_logger(__name__)

router = APIRouter()


# ── Code generation ────────────────────────────────────────────────


_CODE_LENGTH = 8
_CODE_ALPHABET = "0123456789"
_EPHEMERAL_MIN_EXPIRY_MINUTES = 5
_EPHEMERAL_MAX_EXPIRY_MINUTES = 60
_EPHEMERAL_DEFAULT_EXPIRY_MINUTES = 15
# Persistent codes can carry an optional expiry — we cap it
# at 5 years so an admin can't accidentally mint a code that
# survives every operator currently working at the org.
_PERSISTENT_MAX_EXPIRY_MINUTES = 60 * 24 * 365 * 5


def _generate_code() -> str:
    return "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_LENGTH))


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("ascii")).hexdigest()


# ── Schemas ────────────────────────────────────────────────────────


CodeState = Literal["pending", "claimed", "expired", "revoked", "disabled"]


class PairingCodeCreate(BaseModel):
    persistent: bool = Field(
        default=False,
        description=(
            "False = single-use code with a short expiry (today's "
            "default). True = multi-claim code that can admit N "
            "appliances; default no expiry; admin can disable / "
            "re-reveal."
        ),
    )
    expires_in_minutes: int | None = Field(
        default=None,
        description=(
            f"Ephemeral codes: defaults to {_EPHEMERAL_DEFAULT_EXPIRY_MINUTES} "
            f"min, range {_EPHEMERAL_MIN_EXPIRY_MINUTES}-"
            f"{_EPHEMERAL_MAX_EXPIRY_MINUTES}. Persistent codes: NULL "
            "= no expiry (default); 0 also means no expiry; any "
            "positive integer up to 5 years caps the validity window."
        ),
    )
    max_claims: int | None = Field(
        default=None,
        ge=1,
        description=(
            "Optional ceiling on claims for persistent codes. NULL = "
            "unlimited. Ignored for ephemeral codes."
        ),
    )
    note: str | None = Field(default=None, max_length=255)


class PairingCodeCreated(BaseModel):
    """Carries the cleartext code — shown ONCE for ephemeral, also
    available via /reveal for persistent."""

    id: uuid.UUID
    code: str
    persistent: bool
    enabled: bool
    expires_at: datetime | None
    max_claims: int | None
    note: str | None
    created_at: datetime


class PairingCodeRow(BaseModel):
    id: uuid.UUID
    code_last_two: str
    persistent: bool
    enabled: bool
    state: CodeState
    expires_at: datetime | None
    max_claims: int | None
    claim_count: int
    revoked_at: datetime | None
    note: str | None
    created_at: datetime
    created_by_user_id: uuid.UUID | None


class PairingCodeList(BaseModel):
    codes: list[PairingCodeRow]


class PairingCodeRevealRequest(BaseModel):
    # #408 — local users supply ``password``; external-auth users (no
    # local password) supply ``totp_code``; a local user with MFA enrolled
    # may use either. The reauth helper decides; at least one is required.
    password: str | None = Field(default=None, description="Caller's current password.")
    totp_code: str | None = Field(default=None, description="Caller's current TOTP code.")


class PairingCodeRevealResponse(BaseModel):
    """Returns the original cleartext code stored Fernet-encrypted
    on the row at create time. No rotation happens — the same 8
    digits the operator saw originally are what's surfaced again.
    Only persistent codes carry an encrypted cleartext; ephemeral
    codes leave ``code_encrypted=NULL`` and reveal 422s on them.
    """

    id: uuid.UUID
    code: str


# ── Helpers ────────────────────────────────────────────────────────


def _require_superadmin(user: CurrentUser) -> None:
    if not is_effective_superadmin(user):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Pairing-code management is restricted to superadmins.",
        )


def _state_for(row: PairingCode, now: datetime, claim_count: int) -> CodeState:
    """Derive the operator-facing state.

    Precedence: revoked > disabled > expired > claimed > pending. The
    "claimed" terminal state only applies to ephemeral codes; for
    persistent codes any claim count is just informational and the
    state stays pending/disabled/etc.
    """
    if row.revoked_at is not None:
        return "revoked"
    if row.persistent and not row.enabled:
        return "disabled"
    if row.expires_at is not None and row.expires_at <= now:
        return "expired"
    if not row.persistent and claim_count > 0:
        return "claimed"
    return "pending"


async def _get_claim_count(db: DB, code_id: uuid.UUID) -> int:
    stmt = select(func.count()).where(PairingClaim.pairing_code_id == code_id)
    return int((await db.execute(stmt)).scalar_one())


# ── Create ─────────────────────────────────────────────────────────


@router.post(
    "/pairing-codes",
    response_model=PairingCodeCreated,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Mint a new pairing code (superadmin)",
)
async def create_pairing_code(
    body: PairingCodeCreate,
    current_user: CurrentUser,
    db: DB,
) -> PairingCodeCreated:
    _require_superadmin(current_user)

    now = datetime.now(UTC)
    expires_at: datetime | None
    if body.persistent:
        # Persistent code: NULL or 0 means no expiry. Positive value
        # caps validity; values above the 5-year ceiling rejected.
        minutes = body.expires_in_minutes
        if minutes is None or minutes == 0:
            expires_at = None
        elif minutes < 0:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "expires_in_minutes must be non-negative.",
            )
        elif minutes > _PERSISTENT_MAX_EXPIRY_MINUTES:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"expires_in_minutes capped at {_PERSISTENT_MAX_EXPIRY_MINUTES} "
                "(5 years) for persistent codes.",
            )
        else:
            expires_at = now + timedelta(minutes=minutes)
    else:
        # Ephemeral: range-validated; default 15 min.
        minutes = body.expires_in_minutes
        if minutes is None:
            minutes = _EPHEMERAL_DEFAULT_EXPIRY_MINUTES
        if not (_EPHEMERAL_MIN_EXPIRY_MINUTES <= minutes <= _EPHEMERAL_MAX_EXPIRY_MINUTES):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"Ephemeral codes: expires_in_minutes must be in "
                f"{_EPHEMERAL_MIN_EXPIRY_MINUTES}-{_EPHEMERAL_MAX_EXPIRY_MINUTES}.",
            )
        expires_at = now + timedelta(minutes=minutes)

        if body.max_claims is not None:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "max_claims is only valid for persistent codes.",
            )

    code = _generate_code()
    row_id = uuid.uuid4()
    # Persistent codes carry a Fernet-encrypted cleartext so the
    # operator can re-distribute them via /reveal later. Ephemeral
    # codes leave code_encrypted=NULL — the cleartext is shown once
    # on create and lost forever (#169 semantics preserved).
    code_encrypted = encrypt_str(code) if body.persistent else None
    row = PairingCode(
        id=row_id,
        code_hash=_hash_code(code),
        code_last_two=code[-2:],
        persistent=body.persistent,
        enabled=True,
        expires_at=expires_at,
        max_claims=body.max_claims if body.persistent else None,
        code_encrypted=code_encrypted,
        note=body.note,
        created_by_user_id=current_user.id,
    )
    db.add(row)
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.pairing_code_created",
            resource_type="pairing_code",
            resource_id=str(row_id),
            resource_display=("persistent pairing code" if body.persistent else "pairing code")
            + f" (••{code[-2:]})",
            result="success",
            new_value={
                "persistent": body.persistent,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "max_claims": row.max_claims,
                "note": body.note,
            },
        )
    )
    await db.commit()
    await db.refresh(row)
    logger.info(
        "pairing_code_created",
        id=str(row.id),
        persistent=body.persistent,
        expires_at=expires_at.isoformat() if expires_at else None,
        user=current_user.username,
    )
    return PairingCodeCreated(
        id=row.id,
        code=code,
        persistent=body.persistent,
        enabled=True,
        expires_at=expires_at,
        max_claims=row.max_claims,
        note=body.note,
        created_at=row.created_at,
    )


# ── List ───────────────────────────────────────────────────────────


@router.get(
    "/pairing-codes",
    response_model=PairingCodeList,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="List pairing codes (superadmin)",
)
async def list_pairing_codes(
    current_user: CurrentUser,
    db: DB,
    include_terminal: bool = Query(default=True),
) -> PairingCodeList:
    _require_superadmin(current_user)

    rows = (
        (await db.execute(select(PairingCode).order_by(PairingCode.created_at.desc())))
        .scalars()
        .all()
    )

    # Bulk claim-count query: one trip vs N. Returns a dict
    # {code_id: count}; missing keys default to 0.
    claim_counts: dict[uuid.UUID, int] = {}
    if rows:
        cstmt = (
            select(PairingClaim.pairing_code_id, func.count())
            .where(PairingClaim.pairing_code_id.in_([r.id for r in rows]))
            .group_by(PairingClaim.pairing_code_id)
        )
        for code_id, count in (await db.execute(cstmt)).all():
            claim_counts[code_id] = int(count)

    now = datetime.now(UTC)
    out: list[PairingCodeRow] = []
    for row in rows:
        count = claim_counts.get(row.id, 0)
        state = _state_for(row, now, count)
        if not include_terminal and state in ("claimed", "expired", "revoked"):
            continue
        out.append(
            PairingCodeRow(
                id=row.id,
                code_last_two=row.code_last_two,
                persistent=row.persistent,
                enabled=row.enabled,
                state=state,
                expires_at=row.expires_at,
                max_claims=row.max_claims,
                claim_count=count,
                revoked_at=row.revoked_at,
                note=row.note,
                created_at=row.created_at,
                created_by_user_id=row.created_by_user_id,
            )
        )
    return PairingCodeList(codes=out)


# ── Revoke ─────────────────────────────────────────────────────────


@router.delete(
    "/pairing-codes/{code_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Revoke a pairing code (superadmin)",
)
async def revoke_pairing_code(
    code_id: uuid.UUID,
    current_user: CurrentUser,
    db: DB,
) -> None:
    _require_superadmin(current_user)
    row = await db.get(PairingCode, code_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Pairing code not found.")
    if row.revoked_at is not None:
        return None
    now = datetime.now(UTC)
    row.revoked_at = now
    row.revoked_by_user_id = current_user.id
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.pairing_code_revoked",
            resource_type="pairing_code",
            resource_id=str(row.id),
            resource_display=("persistent pairing code" if row.persistent else "pairing code"),
            result="success",
        )
    )
    await db.commit()
    logger.info("pairing_code_revoked", id=str(row.id), user=current_user.username)
    return None


# ── Enable / Disable (persistent codes only) ───────────────────────


async def _toggle_persistent_code(
    code_id: uuid.UUID,
    *,
    enable: bool,
    current_user: User,
    db: DB,
) -> None:
    _require_superadmin(current_user)
    row = await db.get(PairingCode, code_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Pairing code not found.")
    if not row.persistent:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Enable / disable only applies to persistent codes.",
        )
    if row.revoked_at is not None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Cannot toggle a revoked code. Mint a new one.",
        )
    if row.enabled == enable:
        return  # idempotent
    row.enabled = enable
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action=(
                "appliance.pairing_code_enabled" if enable else "appliance.pairing_code_disabled"
            ),
            resource_type="pairing_code",
            resource_id=str(row.id),
            resource_display="persistent pairing code",
            result="success",
        )
    )
    await db.commit()
    logger.info(
        "pairing_code_enabled" if enable else "pairing_code_disabled",
        id=str(row.id),
        user=current_user.username,
    )


@router.post(
    "/pairing-codes/{code_id}/enable",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Re-enable a paused persistent pairing code (superadmin)",
)
async def enable_pairing_code(code_id: uuid.UUID, current_user: CurrentUser, db: DB) -> None:
    await _toggle_persistent_code(code_id, enable=True, current_user=current_user, db=db)


@router.post(
    "/pairing-codes/{code_id}/disable",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Pause a persistent pairing code (superadmin)",
)
async def disable_pairing_code(code_id: uuid.UUID, current_user: CurrentUser, db: DB) -> None:
    await _toggle_persistent_code(code_id, enable=False, current_user=current_user, db=db)


# ── Reveal (persistent codes only) ─────────────────────────────────


@router.post(
    "/pairing-codes/{code_id}/reveal",
    response_model=PairingCodeRevealResponse,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Reveal a persistent pairing code by re-minting it (superadmin)",
)
async def reveal_pairing_code(
    code_id: uuid.UUID,
    body: PairingCodeRevealRequest,
    current_user: CurrentUser,
    db: DB,
) -> PairingCodeRevealResponse:
    """Re-display a persistent code's original cleartext.

    Returns the same 8 digits the operator saw at create time —
    Fernet-decrypted from ``code_encrypted``. Ephemeral codes carry
    no encrypted cleartext (shown once on create); reveal 422s on
    them.

    Gated: superadmin + password-or-TOTP re-confirm (#408) + audited.
    Mirrors agent-bootstrap-keys reveal.
    """
    _require_superadmin(current_user)

    # #408 — local users re-confirm with password or TOTP; external-auth
    # users with TOTP (enrol under Settings → Security if not yet enrolled).
    # #1413 — through the shared step-up: a wrong answer spends the
    # per-account budget, and a refusal is now audited (it was not).
    await require_operator_stepup(
        db,
        current_user,
        password=body.password,
        totp_code=body.totp_code,
        action="pairing_code_reveal_denied",
        resource_type="pairing_code",
        resource_id=str(code_id),
        resource_display=str(code_id),
    )

    row = await db.get(PairingCode, code_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Pairing code not found.")
    if not row.persistent or row.code_encrypted is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Reveal only applies to persistent codes. Ephemeral codes "
            "are shown once on creation; mint a new one if lost.",
        )
    if row.revoked_at is not None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Cannot reveal a revoked code. Mint a new one.",
        )

    try:
        cleartext = decrypt_str(row.code_encrypted)
    except Exception as exc:  # InvalidToken or related Fernet errors
        # Decrypt failure should never happen under normal operation —
        # would mean the SECRET_KEY changed between create + reveal.
        # Log + 500 so the operator notices.
        logger.error(
            "pairing_code_reveal_decrypt_failed",
            id=str(row.id),
            error=str(exc),
        )
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Failed to decrypt stored code. SECRET_KEY may have changed.",
        ) from exc

    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.pairing_code_revealed",
            resource_type="pairing_code",
            resource_id=str(row.id),
            resource_display="persistent pairing code",
            result="success",
        )
    )
    await db.commit()
    logger.info("pairing_code_revealed", id=str(row.id), user=current_user.username)
    return PairingCodeRevealResponse(id=row.id, code=cleartext)
