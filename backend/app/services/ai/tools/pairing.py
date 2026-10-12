"""Operator Copilot read tool for the appliance pairing-code surface
(issues #169 + #170 Wave A3).

Surfaces the ``pairing_code`` table — active + recently-terminal
rows — so a superadmin can ask the Copilot "any active pairing
codes?" / "did dns-west-2 successfully pair?" / "list claimed codes
from the last hour" through chat instead of clicking into the
Appliance UI.

Restricted to superadmin because pairing codes are agent bootstrap
auth: even the redacted shape leaks "there are N pending codes
right now", which is signal an attacker could use to time a
brute-force window. The runtime gate inside the executor
(``user.is_superadmin``) is the only thing standing between a regular
operator's LLM session and that data — see ``admin._superadmin_gate``
for the canonical pattern; the LLM itself has no input on this.

No ``propose_create_pairing_code`` write tool by design. Issuing a
pairing code returns the cleartext code in the response, and we don't
want the operator's copilot transcript carrying a live bootstrap-auth
secret. The dedicated Appliance → Pairing UI flow is the friendly path.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field
from sqlalchemy import func as sa_func
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import is_effective_superadmin
from app.models.appliance import PairingClaim, PairingCode
from app.models.auth import User
from app.services.ai.tools.base import register_tool


def _superadmin_gate(user: User) -> dict[str, Any] | None:
    if not is_effective_superadmin(user):
        return {
            "error": (
                "Pairing codes contain agent bootstrap secrets, so this "
                "tool is restricted to superadmin users. Ask your "
                "platform admin to run the query."
            )
        }
    return None


PairingCodeState = Literal["pending", "claimed", "expired", "revoked", "disabled", "exhausted"]


def _state_for(row: PairingCode, claim_count: int, now: datetime) -> PairingCodeState:
    """Mirror of the API-side state derivation; see
    ``app.api.v1.appliance.pairing._state_for``.
    """
    if row.revoked_at is not None:
        return "revoked"
    if row.persistent and not row.enabled:
        return "disabled"
    if row.expires_at is not None and row.expires_at <= now:
        return "expired"
    if row.persistent and row.max_claims is not None and claim_count >= row.max_claims:
        return "exhausted"
    if not row.persistent and claim_count > 0:
        return "claimed"
    return "pending"


class FindPairingCodesArgs(BaseModel):
    persistent: bool | None = Field(
        default=None,
        description=(
            "Filter by code flavour: True = persistent (multi-claim), "
            "False = ephemeral (single-use). Omit for both flavours."
        ),
    )
    state: PairingCodeState | None = Field(
        default=None,
        description=(
            "Filter by code state. 'pending' / 'active' codes are still "
            "actively usable. Omit for all states."
        ),
    )
    limit: int = Field(default=25, ge=1, le=200)


@register_tool(
    name="find_pairing_codes",
    permission="superadmin",
    description=(
        "List appliance pairing codes (superadmin only). Each row "
        "carries the last two digits of the code, persistent flag, "
        "enabled flag, state (pending / claimed / expired / revoked / "
        "disabled / exhausted), max_claims (nullable), claim_count, "
        "expires_at (nullable for persistent), and note. Use to "
        "answer 'any active pairing codes?', 'how many supervisors "
        "have claimed the staging-fleet code?', or 'how many codes "
        "have expired today?'. Defaults to the 25 most recent rows "
        "across every state; filter with persistent + state."
    ),
    args_model=FindPairingCodesArgs,
    category="admin",
    # Default enabled (NN #13) — read-only, no secrets in response
    # (cleartext code never surfaced), no off-prem calls. Admins
    # discover it without opt-in. The superadmin gate is the real auth.
    default_enabled=True,
)
async def find_pairing_codes(
    db: AsyncSession, user: User, args: FindPairingCodesArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err

    stmt = select(PairingCode).order_by(PairingCode.created_at.desc())
    if args.persistent is not None:
        stmt = stmt.where(PairingCode.persistent == args.persistent)
    rows = list((await db.execute(stmt)).scalars().all())

    # Bulk claim-count query: one trip vs N.
    claim_counts: dict[str, int] = {}
    if rows:
        cstmt = (
            select(PairingClaim.pairing_code_id, sa_func.count())
            .where(PairingClaim.pairing_code_id.in_([r.id for r in rows]))
            .group_by(PairingClaim.pairing_code_id)
        )
        for code_id, count in (await db.execute(cstmt)).all():
            claim_counts[str(code_id)] = int(count)

    now = datetime.now(UTC)
    out: list[dict[str, Any]] = []
    for row in rows:
        count = claim_counts.get(str(row.id), 0)
        state = _state_for(row, count, now)
        if args.state is not None and state != args.state:
            continue
        out.append(
            {
                "id": str(row.id),
                "code_last_two": row.code_last_two,
                "persistent": row.persistent,
                "enabled": row.enabled,
                "state": state,
                "max_claims": row.max_claims,
                "claim_count": count,
                "note": row.note,
                "expires_at": row.expires_at.isoformat() if row.expires_at else None,
                "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
                "created_at": row.created_at.isoformat(),
            }
        )
        if len(out) >= args.limit:
            break

    return {
        "codes": out,
        "count": len(out),
        # Quick "is there a code an agent could be redeeming right now?"
        # rollup for the LLM's summarisation.
        "active_count": sum(1 for c in out if c["state"] in ("pending", "active")),
    }
