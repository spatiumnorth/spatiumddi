"""Admin CRUD for external authentication providers (LDAP / OIDC / SAML) and
their external-group → internal-group mappings.

All routes require superadmin. Secrets are stored Fernet-encrypted via
``app.core.crypto`` and are never returned to the client: the response body
exposes a boolean ``has_secrets`` instead. A PUT that omits the ``secrets``
field leaves the stored ciphertext untouched; passing an empty dict clears it.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select, update
from sqlalchemy.orm import selectinload

from app.api.deps import DB, SuperAdmin
from app.api.stepup import require_operator_stepup
from app.core.auth.ldap import test_connection as ldap_test_connection
from app.core.auth.oidc import invalidate_caches as oidc_invalidate_caches
from app.core.auth.oidc import probe_discovery as oidc_probe_discovery
from app.core.auth.radius import test_connection as radius_test_connection
from app.core.auth.saml import probe_metadata as saml_probe_metadata
from app.core.auth.tacacs import test_connection as tacacs_test_connection
from app.core.crypto import decrypt_dict, encrypt_dict
from app.models.audit import AuditLog
from app.models.auth import Group, User, UserSession
from app.models.auth_provider import (
    PROVIDER_TYPES,
    AuthGroupMapping,
    AuthProvider,
)
from app.models.settings import PlatformSettings
from app.services.superadmin_grant import load_model

logger = structlog.get_logger(__name__)
router = APIRouter()


# ── Schemas ────────────────────────────────────────────────────────────────────


class ProviderCreate(BaseModel):
    model_config = {"extra": "ignore"}

    name: str
    type: str
    is_enabled: bool = False
    priority: int = 100
    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, Any] | None = None
    auto_create_users: bool = True
    auto_update_users: bool = True

    @field_validator("type")
    @classmethod
    def _type(cls, v: str) -> str:
        if v not in PROVIDER_TYPES:
            raise ValueError(f"type must be one of {PROVIDER_TYPES}")
        return v


class ProviderUpdate(BaseModel):
    model_config = {"extra": "ignore"}

    name: str | None = None
    is_enabled: bool | None = None
    priority: int | None = None
    config: dict[str, Any] | None = None
    # None → leave secrets untouched. {} → clear. Non-empty dict → replace.
    secrets: dict[str, Any] | None = None
    auto_create_users: bool | None = None
    auto_update_users: bool | None = None


class ProviderResponse(BaseModel):
    id: uuid.UUID
    name: str
    type: str
    is_enabled: bool
    priority: int
    config: dict[str, Any]
    has_secrets: bool
    auto_create_users: bool
    auto_update_users: bool
    mapping_count: int
    created_at: datetime
    modified_at: datetime


class MappingCreate(BaseModel):
    model_config = {"extra": "ignore"}

    external_group: str
    internal_group_id: uuid.UUID
    priority: int = 100
    # #1476 — needed only when the internal group grants superadmin.
    stepup_password: str | None = None
    stepup_totp_code: str | None = None


class MappingUpdate(BaseModel):
    model_config = {"extra": "ignore"}

    external_group: str | None = None
    internal_group_id: uuid.UUID | None = None
    priority: int | None = None
    stepup_password: str | None = None
    stepup_totp_code: str | None = None


class MappingResponse(BaseModel):
    id: uuid.UUID
    provider_id: uuid.UUID
    external_group: str
    internal_group_id: uuid.UUID
    internal_group_name: str
    priority: int
    created_at: datetime
    modified_at: datetime


# ── Helpers ────────────────────────────────────────────────────────────────────


def _to_response(p: AuthProvider, mapping_count: int) -> ProviderResponse:
    return ProviderResponse(
        id=p.id,
        name=p.name,
        type=p.type,
        is_enabled=p.is_enabled,
        priority=p.priority,
        config=p.config or {},
        has_secrets=p.secrets_encrypted is not None,
        auto_create_users=p.auto_create_users,
        auto_update_users=p.auto_update_users,
        mapping_count=mapping_count,
        created_at=p.created_at,
        modified_at=p.modified_at,
    )


async def _mapping_count(db: DB, provider_id: uuid.UUID) -> int:
    res = await db.execute(
        select(func.count())
        .select_from(AuthGroupMapping)
        .where(AuthGroupMapping.provider_id == provider_id)
    )
    return int(res.scalar_one())


def _mapping_to_response(m: AuthGroupMapping, group_name: str) -> MappingResponse:
    return MappingResponse(
        id=m.id,
        provider_id=m.provider_id,
        external_group=m.external_group,
        internal_group_id=m.internal_group_id,
        internal_group_name=group_name,
        priority=m.priority,
        created_at=m.created_at,
        modified_at=m.modified_at,
    )


async def _get_provider_or_404(db: DB, provider_id: uuid.UUID) -> AuthProvider:
    p = await db.get(AuthProvider, provider_id)
    if p is None:
        raise HTTPException(status_code=404, detail="Auth provider not found")
    return p


# ── Provider endpoints ────────────────────────────────────────────────────────


@router.get("", response_model=list[ProviderResponse])
async def list_providers(db: DB, _: SuperAdmin) -> list[ProviderResponse]:
    res = await db.execute(
        select(AuthProvider)
        .options(selectinload(AuthProvider.mappings))
        .order_by(AuthProvider.priority, AuthProvider.name)
    )
    providers = res.unique().scalars().all()
    return [_to_response(p, len(p.mappings)) for p in providers]


@router.post("", response_model=ProviderResponse, status_code=status.HTTP_201_CREATED)
async def create_provider(body: ProviderCreate, db: DB, user: SuperAdmin) -> ProviderResponse:
    existing = await db.execute(select(AuthProvider).where(AuthProvider.name == body.name))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="A provider with that name already exists")

    provider = AuthProvider(
        name=body.name.strip(),
        type=body.type,
        is_enabled=body.is_enabled,
        priority=body.priority,
        config=body.config or {},
        secrets_encrypted=encrypt_dict(body.secrets) if body.secrets else None,
        auto_create_users=body.auto_create_users,
        auto_update_users=body.auto_update_users,
    )
    db.add(provider)
    await db.flush()

    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="create",
            resource_type="auth_provider",
            resource_id=str(provider.id),
            resource_display=provider.name,
            new_value={
                "type": provider.type,
                "is_enabled": provider.is_enabled,
                "priority": provider.priority,
            },
            result="success",
        )
    )
    await db.commit()
    await db.refresh(provider)
    logger.info(
        "auth_provider_created", id=str(provider.id), name=provider.name, type=provider.type
    )
    return _to_response(provider, 0)


@router.get("/{provider_id}", response_model=ProviderResponse)
async def get_provider(provider_id: uuid.UUID, db: DB, _: SuperAdmin) -> ProviderResponse:
    p = await _get_provider_or_404(db, provider_id)
    return _to_response(p, await _mapping_count(db, provider_id))


@router.put("/{provider_id}", response_model=ProviderResponse)
async def update_provider(
    provider_id: uuid.UUID, body: ProviderUpdate, db: DB, user: SuperAdmin
) -> ProviderResponse:
    provider = await _get_provider_or_404(db, provider_id)

    changes: dict[str, Any] = {}
    if body.name is not None and body.name != provider.name:
        conflict = await db.execute(
            select(AuthProvider).where(
                AuthProvider.name == body.name, AuthProvider.id != provider_id
            )
        )
        if conflict.scalar_one_or_none() is not None:
            raise HTTPException(status_code=409, detail="A provider with that name already exists")
        provider.name = body.name.strip()
        changes["name"] = provider.name
    if body.is_enabled is not None:
        provider.is_enabled = body.is_enabled
        changes["is_enabled"] = body.is_enabled
    if body.priority is not None:
        provider.priority = body.priority
        changes["priority"] = body.priority
    if body.config is not None:
        provider.config = body.config
        changes["config"] = True  # content is potentially sensitive, audit only the fact it changed
    if body.secrets is not None:
        provider.secrets_encrypted = encrypt_dict(body.secrets) if body.secrets else None
        changes["secrets"] = True
    if body.auto_create_users is not None:
        provider.auto_create_users = body.auto_create_users
        changes["auto_create_users"] = body.auto_create_users
    if body.auto_update_users is not None:
        provider.auto_update_users = body.auto_update_users
        changes["auto_update_users"] = body.auto_update_users

    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="update",
            resource_type="auth_provider",
            resource_id=str(provider.id),
            resource_display=provider.name,
            changed_fields=list(changes.keys()),
            new_value={k: v for k, v in changes.items() if k not in {"config", "secrets"}},
            result="success",
        )
    )
    await db.commit()
    await db.refresh(provider)
    if provider.type == "oidc":
        oidc_invalidate_caches(str(provider.id))
    logger.info("auth_provider_updated", id=str(provider.id), fields=list(changes.keys()))
    return _to_response(provider, await _mapping_count(db, provider.id))


@router.delete("/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_provider(provider_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    provider = await _get_provider_or_404(db, provider_id)
    if user.auth_provider_id == provider.id:
        # The caller's own account would be unlinked, and refused at its next
        # sign-in until another administrator links it.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Your own account signs in through this provider. Deleting it "
                "would lock you out; have another administrator delete it."
            ),
        )
    # Its accounts lose their provider (the FK is SET NULL) and, with it,
    # their identifier (#1235). An external id means something only at the
    # provider that issued it, and a stale one would make the next provider
    # of this type issuing the same ``sub`` / DN / NameID look like the
    # account's owner to anything matching on ``(auth_source, external_id)``.
    # The accounts are refused at sign-in until an administrator links them
    # to a provider.
    orphaned = (
        await db.execute(
            update(User)
            .where(User.auth_provider_id == provider.id)
            .values(external_id=None)
            .execution_options(synchronize_session=False)
        )
    ).rowcount
    # And their sessions, as a link does: deleting the provider withdraws the
    # authority those sessions were issued on, so none outlives it until its
    # refresh token happens to expire.
    sessions_revoked = (
        await db.execute(
            update(UserSession)
            .where(
                UserSession.user_id.in_(
                    select(User.id).where(User.auth_provider_id == provider.id)
                ),
                UserSession.revoked.is_(False),
            )
            .values(revoked=True)
            .execution_options(synchronize_session=False)
        )
    ).rowcount
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="delete",
            resource_type="auth_provider",
            resource_id=str(provider.id),
            resource_display=provider.name,
            result="success",
            new_value={"accounts_unlinked": orphaned, "sessions_revoked": sessions_revoked},
        )
    )
    await db.delete(provider)
    await db.commit()
    if provider.type == "oidc":
        oidc_invalidate_caches(str(provider_id))
    logger.info("auth_provider_deleted", id=str(provider_id))


class TestConnectionRequest(BaseModel):
    model_config = {"extra": "ignore"}

    username: str | None = None
    password: str | None = None


class TestUnsavedRequest(BaseModel):
    """Dry-run form for the "Test connection" button BEFORE saving the
    provider, so admins can iterate on config + secrets without creating
    a broken row. Body mirrors ``ProviderCreate`` plus optional probe
    credentials for the LDAP "Test as user" path."""

    model_config = {"extra": "ignore"}

    type: str
    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, Any] = Field(default_factory=dict)
    username: str | None = None
    password: str | None = None

    @field_validator("type")
    @classmethod
    def _check_type(cls, v: str) -> str:
        if v not in PROVIDER_TYPES:
            raise ValueError(f"invalid provider type: {v!r}")
        return v


class TestConnectionResponse(BaseModel):
    ok: bool
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


async def _run_probe(
    provider: AuthProvider,
    body_username: str | None,
    body_password: str | None,
    db: DB,
) -> dict[str, Any]:
    """Dispatch a test probe for an in-memory or persisted provider. Returns
    the raw ``{ok, message, details}`` dict from the per-type probe."""
    if provider.type == "ldap":
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(ldap_test_connection, provider, body_username, body_password),
                timeout=20,
            )
        except TimeoutError:
            return {"ok": False, "message": "LDAP probe timed out", "details": {}}
    if provider.type == "oidc":
        try:
            return await asyncio.wait_for(oidc_probe_discovery(provider), timeout=15)
        except TimeoutError:
            return {"ok": False, "message": "OIDC discovery probe timed out", "details": {}}
    if provider.type == "saml":
        settings_row = await db.get(PlatformSettings, 1)
        base_url = (settings_row.app_base_url if settings_row else "").rstrip("/")
        try:
            return await asyncio.wait_for(
                saml_probe_metadata(provider, base_url or "http://localhost"),
                timeout=15,
            )
        except TimeoutError:
            return {"ok": False, "message": "SAML metadata probe timed out", "details": {}}
    if provider.type == "radius":
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(radius_test_connection, provider),
                timeout=20,
            )
        except TimeoutError:
            return {"ok": False, "message": "RADIUS probe timed out", "details": {}}
    if provider.type == "tacacs":
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(tacacs_test_connection, provider),
                timeout=20,
            )
        except TimeoutError:
            return {"ok": False, "message": "TACACS+ probe timed out", "details": {}}
    raise HTTPException(
        status_code=400,
        detail=(f"Testing is not yet implemented for provider type {provider.type!r}"),
    )


@router.post("/test", response_model=TestConnectionResponse)
async def test_unsaved_provider(
    body: TestUnsavedRequest,
    db: DB,
    user: SuperAdmin,
) -> TestConnectionResponse:
    """Dry-run "Test connection" against an unsaved provider config. Builds
    an in-memory ``AuthProvider`` from the request body — **nothing is
    persisted**, no audit row is written (caller has no resource id to bind
    to), and the encrypted-secrets blob is discarded after the probe runs.
    """
    transient = AuthProvider(
        name="__dry_run__",
        type=body.type,
        is_enabled=True,
        priority=0,
        config=body.config,
        secrets_encrypted=encrypt_dict(body.secrets) if body.secrets else None,
        auto_create_users=False,
        auto_update_users=False,
    )
    report = await _run_probe(transient, body.username, body.password, db)
    return TestConnectionResponse(
        ok=bool(report.get("ok", False)),
        message=str(report.get("message", "")),
        details=dict(report.get("details") or {}),
    )


@router.post("/{provider_id}/test", response_model=TestConnectionResponse)
async def test_provider(
    provider_id: uuid.UUID,
    body: TestConnectionRequest,
    db: DB,
    user: SuperAdmin,
) -> TestConnectionResponse:
    provider = await _get_provider_or_404(db, provider_id)
    report = await _run_probe(provider, body.username, body.password, db)

    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="test",
            resource_type="auth_provider",
            resource_id=str(provider.id),
            resource_display=provider.name,
            result="success" if report.get("ok") else "failure",
            new_value={
                "message": str(report.get("message", ""))[:500],
                "tested_user": bool(body.username),
            },
        )
    )
    await db.commit()

    return TestConnectionResponse(
        ok=bool(report.get("ok", False)),
        message=str(report.get("message", "")),
        details=dict(report.get("details") or {}),
    )


class RevealSecretsRequest(BaseModel):
    """The operator step-up (#408): a local user's password, or an external
    user's authenticator code."""

    password: str | None = None
    totp_code: str | None = None


# Decrypt + return a provider's secrets (the LDAP bind password, the OIDC /
# SAML / RADIUS / TACACS+ secrets). A POST carrying the operator step-up,
# like every other secret reveal (#1355): it was a GET with none, the one
# reveal a stolen session could read outright.
@router.post("/{provider_id}/secrets", response_model=dict[str, Any])
async def reveal_secrets(
    provider_id: uuid.UUID, body: RevealSecretsRequest, db: DB, user: SuperAdmin
) -> dict[str, Any]:
    provider = await _get_provider_or_404(db, provider_id)
    method = await require_operator_stepup(
        db,
        user,
        password=body.password,
        totp_code=body.totp_code,
        action="read",
        resource_type="auth_provider_secret",
        resource_id=str(provider.id),
        resource_display=provider.name,
    )
    if provider.secrets_encrypted is None:
        return {}
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="read",
            resource_type="auth_provider_secret",
            resource_id=str(provider.id),
            resource_display=provider.name,
            result="success",
            new_value={"stepup_method": method},
        )
    )
    await db.commit()
    try:
        return decrypt_dict(provider.secrets_encrypted)
    except ValueError:
        raise HTTPException(
            status_code=500,
            detail=(
                "Stored secret could not be decrypted — credential_encryption_key or "
                "secret_key may have changed since the secret was saved."
            ),
        )


# ── Mapping endpoints ─────────────────────────────────────────────────────────


async def _stepup_if_group_grants_superadmin(
    db: DB,
    user: User,
    group: Group,
    *,
    password: str | None,
    totp_code: str | None,
    action: str,
    resource_id: str,
    resource_display: str,
) -> str | None:
    """Step up when a mapping would route IdP accounts into a group that
    makes its members superadmins (#1476, the path #1412 left open).

    The mapping grants nothing at once: the next sign-in from any account in
    the external group becomes a superadmin. So a stolen session that also
    controls an IdP account would have a step-up-free way in. Who signs in
    is unknown here, so the check is on the target group, not on users.
    Returns the step-up method, or None when the group grants no superadmin.
    """
    if not (await load_model(db)).group_grants_superadmin(group.id):
        return None
    return await require_operator_stepup(
        db,
        user,
        password=password,
        totp_code=totp_code,
        action=action,
        resource_type="auth_group_mapping",
        resource_id=resource_id,
        resource_display=f"{resource_display} (into superadmin group {group.name})",
    )


async def _mapping_with_group_name(db: DB, mapping: AuthGroupMapping) -> MappingResponse:
    group = await db.get(Group, mapping.internal_group_id)
    return _mapping_to_response(mapping, group.name if group else "")


@router.get("/{provider_id}/mappings", response_model=list[MappingResponse])
async def list_mappings(provider_id: uuid.UUID, db: DB, _: SuperAdmin) -> list[MappingResponse]:
    await _get_provider_or_404(db, provider_id)
    res = await db.execute(
        select(AuthGroupMapping)
        .where(AuthGroupMapping.provider_id == provider_id)
        .order_by(AuthGroupMapping.priority, AuthGroupMapping.external_group)
    )
    mappings = res.unique().scalars().all()
    out = []
    for m in mappings:
        out.append(await _mapping_with_group_name(db, m))
    return out


@router.post(
    "/{provider_id}/mappings",
    response_model=MappingResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_mapping(
    provider_id: uuid.UUID, body: MappingCreate, db: DB, user: SuperAdmin
) -> MappingResponse:
    provider = await _get_provider_or_404(db, provider_id)

    group = await db.get(Group, body.internal_group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Internal group not found")

    dup = await db.execute(
        select(AuthGroupMapping).where(
            AuthGroupMapping.provider_id == provider_id,
            AuthGroupMapping.external_group == body.external_group,
        )
    )
    if dup.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=409, detail="A mapping for that external group already exists"
        )

    method = await _stepup_if_group_grants_superadmin(
        db,
        user,
        group,
        password=body.stepup_password,
        totp_code=body.stepup_totp_code,
        action="create",
        resource_id=str(provider_id),
        resource_display=f"{provider.name}: {body.external_group.strip()} → {group.name}",
    )

    mapping = AuthGroupMapping(
        provider_id=provider_id,
        external_group=body.external_group.strip(),
        internal_group_id=body.internal_group_id,
        priority=body.priority,
    )
    db.add(mapping)
    await db.flush()

    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="create",
            resource_type="auth_group_mapping",
            resource_id=str(mapping.id),
            resource_display=f"{provider.name}: {mapping.external_group} → {group.name}",
            new_value={
                "provider_id": str(provider_id),
                "external_group": mapping.external_group,
                "internal_group_id": str(mapping.internal_group_id),
                **({"grants_superadmin": True, "stepup_method": method} if method else {}),
            },
            result="success",
        )
    )
    await db.commit()
    await db.refresh(mapping)
    return _mapping_to_response(mapping, group.name)


@router.put("/{provider_id}/mappings/{mapping_id}", response_model=MappingResponse)
async def update_mapping(
    provider_id: uuid.UUID,
    mapping_id: uuid.UUID,
    body: MappingUpdate,
    db: DB,
    user: SuperAdmin,
) -> MappingResponse:
    mapping = await db.get(AuthGroupMapping, mapping_id)
    if mapping is None or mapping.provider_id != provider_id:
        raise HTTPException(status_code=404, detail="Mapping not found")

    target_id = body.internal_group_id or mapping.internal_group_id
    target = await db.get(Group, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Internal group not found")
    new_external = body.external_group.strip() if body.external_group is not None else None
    # Re-pointing the mapping, or renaming the external group of one that
    # points at a superadmin group, changes which IdP accounts land in it.
    # The priority does not: every matching mapping applies on sign-in.
    method: str | None = None
    if (
        body.internal_group_id is not None and body.internal_group_id != mapping.internal_group_id
    ) or (new_external is not None and new_external != mapping.external_group):
        method = await _stepup_if_group_grants_superadmin(
            db,
            user,
            target,
            password=body.stepup_password,
            totp_code=body.stepup_totp_code,
            action="update",
            resource_id=str(mapping.id),
            resource_display=f"{new_external or mapping.external_group} → {target.name}",
        )

    changes: dict[str, Any] = {}
    if new_external is not None:
        mapping.external_group = new_external
        changes["external_group"] = mapping.external_group
    if body.internal_group_id is not None:
        mapping.internal_group_id = body.internal_group_id
        changes["internal_group_id"] = str(body.internal_group_id)
    if body.priority is not None:
        mapping.priority = body.priority
        changes["priority"] = body.priority

    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="update",
            resource_type="auth_group_mapping",
            resource_id=str(mapping.id),
            resource_display=mapping.external_group,
            changed_fields=list(changes.keys()),
            new_value={
                **changes,
                **({"grants_superadmin": True, "stepup_method": method} if method else {}),
            },
            result="success",
        )
    )
    await db.commit()
    await db.refresh(mapping)
    return await _mapping_with_group_name(db, mapping)


@router.delete("/{provider_id}/mappings/{mapping_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_mapping(
    provider_id: uuid.UUID, mapping_id: uuid.UUID, db: DB, user: SuperAdmin
) -> None:
    mapping = await db.get(AuthGroupMapping, mapping_id)
    if mapping is None or mapping.provider_id != provider_id:
        raise HTTPException(status_code=404, detail="Mapping not found")
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="delete",
            resource_type="auth_group_mapping",
            resource_id=str(mapping.id),
            resource_display=mapping.external_group,
            result="success",
        )
    )
    await db.delete(mapping)
    await db.commit()
