"""Service accounts (#2144): API principals for external systems.

Connecting Home Assistant, Ansible, a monitoring poller or CI used to mean
inventing a person: a ``homeassistant`` "user" with a password it never
needed, which could sign in to the UI, sat in the user list, and broke when
someone tidied up unused accounts. A service account is the non-interactive
version: no password, no sign-in, groups (and so roles) like anyone else, and
API tokens a superadmin mints for it.

**Data model.** A ``User`` row with ``auth_source = "service"``
(:data:`app.models.auth.SERVICE_ACCOUNT_AUTH_SOURCE`), not a table of its own.
Every permission check takes a ``User``, a token's ``user_id`` points at one,
and audit rows carry its id: a separate principal table would have meant a
second path through each of those. The ``auth_source`` value is also what
keeps it out of everything that means a person, because every one of those
paths already keys on ``local`` or on a provider type.

**Who manages them.** Superadmin only, on every route here, and a service
account is never an effective superadmin itself
(``app.core.permissions.is_effective_superadmin``), so no service-account
token can reach these routes, manage itself or mint itself another token.
Minting a token also takes the caller's step-up, as minting one's own does.
A token can only narrow its owner's RBAC, so the ceiling on what a service
account's token can do is the account's groups, which only a superadmin (or a
group admin within their own permissions, through ``/groups``) can change.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select

from app.api.deps import DB, SuperAdmin
from app.api.stepup import require_operator_stepup
from app.api.v1.api_tokens.router import (
    ApiTokenCreate,
    ApiTokenCreateResponse,
    ApiTokenResponse,
    mint_api_token,
    with_owner,
)
from app.core.permissions import refuse_and_audit
from app.models.audit import AuditLog
from app.models.auth import SERVICE_ACCOUNT_AUTH_SOURCE, APIToken, Group, User
from app.services.api_token_revocation import revoke_owner_tokens
from app.services.api_token_scopes import token_write
from app.services.service_accounts import TokenSummary, token_summaries
from app.services.superadmin_grant import load_model

router = APIRouter()

# A name a config file, a log line and a URL can all carry unquoted. It shares
# the user namespace (``user.username`` is unique), which is what keeps a
# person from ever signing in as one.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,149}$")


# ── Schemas ────────────────────────────────────────────────────────────────


class ServiceAccountGroup(BaseModel):
    id: uuid.UUID
    name: str


class ServiceAccountResponse(BaseModel):
    id: uuid.UUID
    username: str
    #: What the account is for ("Home Assistant on ha.lan").
    display_name: str
    is_active: bool
    groups: list[ServiceAccountGroup]
    #: Tokens that would authenticate now: active and unexpired.
    active_token_count: int
    #: When any of its tokens was last used, or None if never.
    last_used_at: datetime | None
    #: The soonest expiry among its active tokens, or None if none expires.
    next_token_expiry: datetime | None
    created_at: datetime


class ServiceAccountCreate(BaseModel):
    username: str = Field(..., min_length=1, max_length=150)
    display_name: str = Field("", max_length=255)
    group_ids: list[uuid.UUID] = Field(default_factory=list)

    @field_validator("username")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not _NAME_RE.match(v):
            raise ValueError(
                "Use letters, digits, '.', '_' or '-', starting with a letter or digit"
            )
        return v


class ServiceAccountUpdate(BaseModel):
    display_name: str | None = Field(None, max_length=255)
    is_active: bool | None = None
    #: Replaces the account's groups when given.
    group_ids: list[uuid.UUID] | None = None


# ── Helpers ────────────────────────────────────────────────────────────────


async def _load(db: DB, account_id: uuid.UUID) -> User:
    user = await db.get(User, account_id)
    if user is None or not user.is_service_account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Service account not found"
        )
    return user


async def _resolve_groups(
    db: DB, actor: User, request: Request, group_ids: list[uuid.UUID], display: str
) -> list[Group]:
    """The groups ``group_ids`` names, refusing a missing one (422) and one
    that would make the account a superadmin (422, audited).

    A service account is never an effective superadmin, so a ``*`` / ``*``
    group would grant it every RBAC route while the UI showed it as
    superadmin; refusing here says so at the point of the mistake. Give it a
    role with the permissions the external system needs instead.
    """
    if not group_ids:
        return []
    groups = list((await db.execute(select(Group).where(Group.id.in_(group_ids)))).scalars())
    if len(groups) != len(set(group_ids)):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="One or more group_ids do not exist",
        )
    model = await load_model(db)
    wildcard = sorted(g.name for g in groups if model.group_grants_superadmin(g.id))
    if wildcard:
        await refuse_and_audit(
            db,
            actor,
            request,
            action="update",
            resource_type="service_account",
            resource_id=display,
            resource_display=display,
            reason="superadmin_group",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "A service account cannot be a superadmin, and these groups grant "
                f"superadmin ('*' on '*'): {', '.join(wildcard)}. Give it a group "
                "whose roles carry only the permissions the external system needs."
            ),
        )
    return groups


async def _responses(db: DB, users: list[User]) -> list[ServiceAccountResponse]:
    stats = await token_summaries(db, [u.id for u in users])
    out = []
    for u in users:
        summary = stats.get(u.id, TokenSummary())
        out.append(
            ServiceAccountResponse(
                id=u.id,
                username=u.username,
                display_name=u.display_name,
                is_active=u.is_active,
                groups=sorted(
                    (ServiceAccountGroup(id=g.id, name=g.name) for g in u.groups),
                    key=lambda g: g.name.lower(),
                ),
                active_token_count=summary.active_count,
                last_used_at=summary.last_used_at,
                next_token_expiry=summary.next_expiry,
                created_at=u.created_at,
            )
        )
    return out


def _audit(actor: User, action: str, account: User, **values: object) -> AuditLog:
    return AuditLog(
        user_id=actor.id,
        user_display_name=actor.display_name,
        auth_source=actor.auth_source,
        action=action,
        resource_type="service_account",
        resource_id=str(account.id),
        resource_display=account.username,
        result="success",
        new_value=values or None,
    )


# ── Routes ─────────────────────────────────────────────────────────────────


@router.get("", response_model=list[ServiceAccountResponse])
async def list_service_accounts(db: DB, _: SuperAdmin) -> list[ServiceAccountResponse]:
    users = list(
        (
            await db.execute(
                select(User)
                .where(User.auth_source == SERVICE_ACCOUNT_AUTH_SOURCE)
                .order_by(User.username)
            )
        ).scalars()
    )
    return await _responses(db, users)


@router.post("", response_model=ServiceAccountResponse, status_code=status.HTTP_201_CREATED)
@token_write("Creates a service account, an API principal")
async def create_service_account(
    body: ServiceAccountCreate, request: Request, db: DB, current_user: SuperAdmin
) -> ServiceAccountResponse:
    taken = (
        await db.execute(select(User.id).where(User.username == body.username))
    ).scalar_one_or_none()
    if taken is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"The name '{body.username}' is already used by a user or service account",
        )
    groups = await _resolve_groups(db, current_user, request, body.group_ids, body.username)
    account = User(
        username=body.username,
        # The unique email index leaves "" out, so any number of accounts
        # without one can exist (#1290).
        email="",
        display_name=body.display_name.strip() or body.username,
        hashed_password=None,
        auth_source=SERVICE_ACCOUNT_AUTH_SOURCE,
        is_active=True,
        is_superadmin=False,
        force_password_change=False,
    )
    account.groups = groups
    db.add(account)
    await db.flush()
    db.add(
        _audit(
            current_user,
            "create",
            account,
            display_name=account.display_name,
            groups=sorted(g.name for g in groups),
        )
    )
    await db.commit()
    await db.refresh(account)
    return (await _responses(db, [account]))[0]


@router.get("/{account_id}", response_model=ServiceAccountResponse)
async def get_service_account(
    account_id: uuid.UUID, db: DB, _: SuperAdmin
) -> ServiceAccountResponse:
    return (await _responses(db, [await _load(db, account_id)]))[0]


@router.patch("/{account_id}", response_model=ServiceAccountResponse)
async def update_service_account(
    account_id: uuid.UUID,
    body: ServiceAccountUpdate,
    request: Request,
    db: DB,
    current_user: SuperAdmin,
) -> ServiceAccountResponse:
    """Rename, change groups, disable or re-enable.

    A change of ``is_active`` revokes every token the account holds, in both
    directions, exactly as disabling a user does (#3432): disabling is how an
    administrator contains a leaked credential, and a token that came back on
    re-enable would undo it. Re-enabling therefore starts with no tokens.
    """
    account = await _load(db, account_id)
    changes: dict[str, object] = {}
    if body.group_ids is not None:
        groups = await _resolve_groups(db, current_user, request, body.group_ids, account.username)
        before = sorted(g.name for g in account.groups)
        after = sorted(g.name for g in groups)
        if before != after:
            account.groups = groups
            changes["groups"] = after
    if body.display_name is not None:
        name = body.display_name.strip() or account.username
        if name != account.display_name:
            account.display_name = name
            changes["display_name"] = name
    if body.is_active is not None and body.is_active != account.is_active:
        changes["is_active"] = body.is_active
        changes["api_tokens_revoked"] = await revoke_owner_tokens(
            db,
            account.id,
            actor=current_user,
            reason="owner_enabled" if body.is_active else "owner_disabled",
        )
        account.is_active = body.is_active
    if changes:
        db.add(_audit(current_user, "update", account, **changes))
    await db.commit()
    await db.refresh(account)
    return (await _responses(db, [account]))[0]


@router.delete("/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_service_account(account_id: uuid.UUID, db: DB, current_user: SuperAdmin) -> None:
    """Delete the account and every token it holds. Its audit rows stay,
    naming it by id and name."""
    account = await _load(db, account_id)
    tokens = (
        await db.execute(select(func.count(APIToken.id)).where(APIToken.user_id == account.id))
    ).scalar_one()
    db.add(_audit(current_user, "delete", account, api_tokens_deleted=tokens))
    await db.delete(account)
    await db.commit()


@router.get("/{account_id}/tokens", response_model=list[ApiTokenResponse])
async def list_service_account_tokens(
    account_id: uuid.UUID, db: DB, _: SuperAdmin
) -> list[ApiTokenResponse]:
    """The account's tokens, newest first. Revoke or delete one through
    ``/api-tokens/{id}``, as for any token."""
    account = await _load(db, account_id)
    tokens = (
        await db.execute(
            select(APIToken)
            .where(APIToken.user_id == account.id)
            .order_by(APIToken.created_at.desc())
        )
    ).scalars()
    return [await with_owner(db, t) for t in tokens]


@router.post(
    "/{account_id}/tokens",
    response_model=ApiTokenCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
@token_write("Mints an API token, a long-lived credential for a service account")
async def create_service_account_token(
    account_id: uuid.UUID, body: ApiTokenCreate, db: DB, current_user: SuperAdmin
) -> dict:
    """Mint a token for the account; the raw token is in this response only.

    Takes the CALLER's step-up, as minting one's own token does (#1355): a
    token outlives the session that minted it. Scopes, resource grants and
    expiry narrow the account's RBAC exactly as for a person's token, and a
    resource grant the account itself does not hold is refused (422).
    """
    account = await _load(db, account_id)
    method = await require_operator_stepup(
        db,
        current_user,
        password=body.stepup_password,
        totp_code=body.stepup_totp_code,
        action="create",
        resource_type="api_token",
        resource_id="?",
        resource_display=f"{body.name} (service account {account.username})",
    )
    return await mint_api_token(
        db,
        body,
        owner=account,
        actor=current_user,
        stepup_method=method,
        audit_extra={"owner": account.username, "owner_id": str(account.id)},
    )
