"""TLS certificate monitoring CRUD + probe-now (issue #118).

Manage probe targets (auto-discovered ones + ad-hoc external hostnames),
read probe history + the captured chain, and fire a synchronous probe.

Permissions: every endpoint gates on the ``tls_cert`` resource_type
(admin via the seeded Network Editor builtin role; read via Viewer /
Auditor; superadmin always passes). The whole router is feature-gated
behind ``security.tls_certs`` at the include site (404 when off). Each
mutation writes an ``audit_log`` row before commit (non-negotiable #4).

SSRF: ``host`` is validated through ``assert_target_allowed`` (rejects
loopback / link-local / cloud-metadata IP literals); the probe service
additionally re-resolves the hostname at probe time and re-checks each
answer.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, computed_field, field_validator
from sqlalchemy import func, or_, select

from app.api.deps import DB, CurrentUser
from app.api.v1.ownership._audit import write_audit
from app.core.celery_dispatch import dispatch
from app.core.permissions import require_resource_permission
from app.models.settings import PlatformSettings
from app.models.tls_cert import (
    SOURCE_MANUAL,
    TLSCertProbe,
    TLSCertTarget,
)
from app.services.nettools.schemas import assert_target_allowed
from app.services.tls_cert.probe import parse_chain_pem, probe_one

router = APIRouter(
    tags=["tls-certs"],
    dependencies=[Depends(require_resource_permission("tls_cert"))],
)

_SINGLETON_ID = 1
TargetState = Literal["unknown", "ok", "expiring", "expired", "mismatch", "unreachable"]
TargetSource = Literal["manual", "discovered"]


def _norm_host(value: str) -> str:
    return assert_target_allowed(value.strip()).rstrip(".").lower()


# ── Schemas ─────────────────────────────────────────────────────────


class TLSCertTargetCreate(BaseModel):
    host: str = Field(..., min_length=1, max_length=255)
    port: int = Field(default=443, ge=1, le=65535)
    server_name: str | None = Field(default=None, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)
    interval_hours: int | None = Field(default=None, ge=1, le=168)
    enabled: bool = True

    @field_validator("host")
    @classmethod
    def _v_host(cls, v: str) -> str:
        return _norm_host(v)

    @field_validator("server_name")
    @classmethod
    def _v_sni(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        return v.strip().rstrip(".").lower()


class TLSCertTargetUpdate(BaseModel):
    host: str | None = Field(default=None, min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    server_name: str | None = Field(default=None, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)
    interval_hours: int | None = Field(default=None, ge=1, le=168)
    enabled: bool | None = None

    @field_validator("host")
    @classmethod
    def _v_host(cls, v: str | None) -> str | None:
        return _norm_host(v) if v is not None else None

    @field_validator("server_name")
    @classmethod
    def _v_sni(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        return v.strip().rstrip(".").lower()


class TLSCertTargetRead(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    host: str
    port: int
    server_name: str | None
    display_name: str | None
    enabled: bool
    source: str
    dns_record_id: uuid.UUID | None
    dns_zone_id: uuid.UUID | None
    domain_id: uuid.UUID | None
    ip_address_id: uuid.UUID | None
    interval_hours: int | None
    next_check_at: datetime | None
    last_checked_at: datetime | None
    state: str
    last_error: str | None
    consecutive_failures: int
    serial: str | None
    subject_cn: str | None
    issuer_cn: str | None
    not_before: datetime | None
    not_after: datetime | None
    sans_json: list[str]
    key_algo: str | None
    key_size: int | None
    sig_algo: str | None
    chain_depth: int | None
    chain_valid: bool | None
    chain_error: str | None
    self_signed: bool | None
    fingerprint_sha256: str | None
    created_at: datetime
    modified_at: datetime

    @computed_field  # type: ignore[prop-decorator]
    @property
    def days_remaining(self) -> int | None:
        if self.not_after is None:
            return None
        na = self.not_after if self.not_after.tzinfo else self.not_after.replace(tzinfo=UTC)
        return int((na - datetime.now(UTC)).total_seconds() // 86400)


class TLSCertTargetListResponse(BaseModel):
    items: list[TLSCertTargetRead]
    total: int
    limit: int
    offset: int


class TLSCertProbeRead(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    target_id: uuid.UUID
    probed_at: datetime
    ok: bool
    state: str
    error: str | None
    serial: str | None
    subject_cn: str | None
    issuer_cn: str | None
    not_before: datetime | None
    not_after: datetime | None
    sans_json: list[str]
    key_algo: str | None
    key_size: int | None
    sig_algo: str | None
    chain_depth: int | None
    chain_valid: bool | None
    chain_error: str | None
    self_signed: bool | None
    fingerprint_sha256: str | None


class TLSCertProbeListResponse(BaseModel):
    items: list[TLSCertProbeRead]
    total: int
    limit: int
    offset: int


# ── Helpers ─────────────────────────────────────────────────────────


async def _assert_unique(
    db: DB, host: str, port: int, sni: str | None, *, exclude: uuid.UUID | None = None
) -> None:
    stmt = select(TLSCertTarget).where(
        func.lower(TLSCertTarget.host) == host,
        TLSCertTarget.port == port,
    )
    stmt = stmt.where(
        TLSCertTarget.server_name == sni if sni is not None else TLSCertTarget.server_name.is_(None)
    )
    if exclude is not None:
        stmt = stmt.where(TLSCertTarget.id != exclude)
    if (await db.scalar(stmt)) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"a target for {host}:{port} (sni={sni or '-'}) already exists",
        )


async def _interval(db: DB) -> int:
    ps = await db.get(PlatformSettings, _SINGLETON_ID)
    hours = ps.tls_cert_check_interval_hours if ps is not None else 6
    return max(1, min(168, hours or 6))


# ── Endpoints ───────────────────────────────────────────────────────


@router.get("", response_model=TLSCertTargetListResponse)
async def list_targets(
    db: DB,
    _: CurrentUser,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    state: TargetState | None = Query(default=None),
    source: TargetSource | None = Query(default=None),
    enabled: bool | None = Query(default=None),
    dns_zone_id: uuid.UUID | None = Query(default=None),
    domain_id: uuid.UUID | None = Query(default=None),
    ip_address_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(
        default=None, description="Case-insensitive substring on host / display_name / subject_cn."
    ),
) -> TLSCertTargetListResponse:
    stmt = select(TLSCertTarget)
    if state is not None:
        stmt = stmt.where(TLSCertTarget.state == state)
    if source is not None:
        stmt = stmt.where(TLSCertTarget.source == source)
    if enabled is not None:
        stmt = stmt.where(TLSCertTarget.enabled.is_(enabled))
    if dns_zone_id is not None:
        stmt = stmt.where(TLSCertTarget.dns_zone_id == dns_zone_id)
    if domain_id is not None:
        stmt = stmt.where(TLSCertTarget.domain_id == domain_id)
    if ip_address_id is not None:
        stmt = stmt.where(TLSCertTarget.ip_address_id == ip_address_id)
    if search:
        needle = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                TLSCertTarget.host.ilike(needle),
                TLSCertTarget.display_name.ilike(needle),
                TLSCertTarget.subject_cn.ilike(needle),
            )
        )
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    stmt = stmt.order_by(TLSCertTarget.host.asc()).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    return TLSCertTargetListResponse(
        items=[TLSCertTargetRead.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("", response_model=TLSCertTargetRead, status_code=status.HTTP_201_CREATED)
async def create_target(body: TLSCertTargetCreate, db: DB, user: CurrentUser) -> TLSCertTargetRead:
    await _assert_unique(db, body.host, body.port, body.server_name)
    row = TLSCertTarget(
        host=body.host,
        port=body.port,
        server_name=body.server_name,
        display_name=body.display_name or body.host,
        interval_hours=body.interval_hours,
        enabled=body.enabled,
        source=SOURCE_MANUAL,
        next_check_at=None,
    )
    db.add(row)
    await db.flush()
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="tls_cert",
        resource_id=str(row.id),
        resource_display=row.display_name or row.host,
        new_value={"host": row.host, "port": row.port, "server_name": row.server_name},
    )
    await db.commit()
    await db.refresh(row)

    # Fire the first probe right away so the row populates within seconds
    # instead of waiting for the next sweep. Best-effort — a broker hiccup
    # must not fail the create.
    try:
        from app.tasks.tls_certs import probe_one_target_by_id  # noqa: PLC0415

        await dispatch(probe_one_target_by_id, str(row.id))
    except Exception:  # noqa: BLE001
        pass

    return TLSCertTargetRead.model_validate(row)


@router.get("/{target_id}", response_model=TLSCertTargetRead)
async def get_target(target_id: uuid.UUID, db: DB, _: CurrentUser) -> TLSCertTargetRead:
    row = await db.get(TLSCertTarget, target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="target not found")
    return TLSCertTargetRead.model_validate(row)


@router.put("/{target_id}", response_model=TLSCertTargetRead)
async def update_target(
    target_id: uuid.UUID, body: TLSCertTargetUpdate, db: DB, user: CurrentUser
) -> TLSCertTargetRead:
    row = await db.get(TLSCertTarget, target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="target not found")
    data = body.model_dump(exclude_unset=True)
    # Re-check uniqueness if any connect-tuple field changed.
    if {"host", "port", "server_name"} & data.keys():
        new_host = data.get("host", row.host)
        new_port = data.get("port", row.port)
        new_sni = data.get("server_name", row.server_name)
        await _assert_unique(db, new_host, new_port, new_sni, exclude=row.id)
    changed: list[str] = []
    for field, value in data.items():
        if getattr(row, field) != value:
            setattr(row, field, value)
            changed.append(field)
    if changed:
        write_audit(
            db,
            user=user,
            action="update",
            resource_type="tls_cert",
            resource_id=str(row.id),
            resource_display=row.display_name or row.host,
            changed_fields=changed,
        )
        await db.commit()
        await db.refresh(row)
    return TLSCertTargetRead.model_validate(row)


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(target_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    row = await db.get(TLSCertTarget, target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="target not found")
    label = row.display_name or row.host
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="tls_cert",
        resource_id=str(row.id),
        resource_display=label,
    )
    await db.delete(row)
    await db.commit()


@router.get("/{target_id}/probes", response_model=TLSCertProbeListResponse)
async def list_probes(
    target_id: uuid.UUID,
    db: DB,
    _: CurrentUser,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> TLSCertProbeListResponse:
    if (await db.get(TLSCertTarget, target_id)) is None:
        raise HTTPException(status_code=404, detail="target not found")
    base = select(TLSCertProbe).where(TLSCertProbe.target_id == target_id)
    total = await db.scalar(select(func.count()).select_from(base.subquery())) or 0
    rows = (
        (await db.execute(base.order_by(TLSCertProbe.probed_at.desc()).limit(limit).offset(offset)))
        .scalars()
        .all()
    )
    return TLSCertProbeListResponse(
        items=[TLSCertProbeRead.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


class CertChainEntry(BaseModel):
    """One parsed certificate from the captured bundle.

    Every field ``parse_chain_pem`` emits is declared, not just the obvious
    ones: leaving the rest to ``extra`` would keep them off the published
    schema, so a generated client would be missing exactly the fields the
    existing chain view already renders (``TLSChainCert`` in the frontend).
    Typing half a model is the failure this whole change is about.
    """

    model_config = {"extra": "allow"}

    #: 0-based depth in the presented bundle: leaf first, root last.
    position: int | None = None
    role: str | None = None
    subject_cn: str | None = None
    issuer_cn: str | None = None
    serial: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    key_algo: str | None = None
    key_size: int | None = None
    sig_algo: str | None = None
    is_ca: bool | None = None
    self_signed: bool | None = None
    fingerprint_sha256: str | None = None


class CertChainResponse(BaseModel):
    """The latest successful probe's captured chain. Public material only —
    no private key is ever stored or returned."""

    target_id: uuid.UUID
    probed_at: datetime
    subject_cn: str | None = None
    issuer_cn: str | None = None
    serial: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    sans: list[str] = []
    key_algo: str | None = None
    key_size: int | None = None
    sig_algo: str | None = None
    chain_depth: int | None = None
    #: ``None`` when validation was never attempted, which is not the same as
    #: a chain that failed to validate.
    chain_valid: bool | None = None
    chain_error: str | None = None
    self_signed: bool | None = None
    fingerprint_sha256: str | None = None
    leaf_pem: str | None = None
    chain_pem: str | None = None
    #: leaf → intermediate(s) → root, parsed from the captured bundle.
    chain: list[CertChainEntry] = []


@router.get("/{target_id}/chain", response_model=CertChainResponse)
async def get_chain(target_id: uuid.UUID, db: DB, _: CurrentUser) -> CertChainResponse:
    """Latest probe's captured PEM + parsed identity (powers the UI chain
    view + the get_cert_chain MCP tool). Public material only."""
    if (await db.get(TLSCertTarget, target_id)) is None:
        raise HTTPException(status_code=404, detail="target not found")
    probe = await db.scalar(
        select(TLSCertProbe)
        .where(TLSCertProbe.target_id == target_id, TLSCertProbe.ok.is_(True))
        .order_by(TLSCertProbe.probed_at.desc())
        .limit(1)
    )
    if probe is None:
        raise HTTPException(status_code=404, detail="no successful probe yet")
    return CertChainResponse.model_validate(
        {
            "target_id": str(target_id),
            "probed_at": probe.probed_at.isoformat(),
            "subject_cn": probe.subject_cn,
            "issuer_cn": probe.issuer_cn,
            "serial": probe.serial,
            "not_before": probe.not_before.isoformat() if probe.not_before else None,
            "not_after": probe.not_after.isoformat() if probe.not_after else None,
            "sans": probe.sans_json or [],
            "key_algo": probe.key_algo,
            "key_size": probe.key_size,
            "sig_algo": probe.sig_algo,
            "chain_depth": probe.chain_depth,
            "chain_valid": probe.chain_valid,
            "chain_error": probe.chain_error,
            "self_signed": probe.self_signed,
            "fingerprint_sha256": probe.fingerprint_sha256,
            "leaf_pem": probe.leaf_pem,
            "chain_pem": probe.chain_pem,
            # Per-cert breakdown (leaf → intermediate(s) → root) parsed from the
            # captured bundle, for the cert detail view.
            "chain": parse_chain_pem(probe.chain_pem or probe.leaf_pem),
        }
    )


@router.get("/{target_id}/ct-log")
async def ct_log(
    target_id: uuid.UUID,
    db: DB,
    _: CurrentUser,
    limit: int = Query(50, ge=1, le=100),
) -> dict[str, Any]:
    """Cross-reference this target's host against Certificate Transparency
    logs (crt.sh). OFF-PREM + explicit: this leaks the hostname to crt.sh,
    so it only runs on this on-demand request — never the scheduled probe."""
    row = await db.get(TLSCertTarget, target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="target not found")
    from app.services.tls_cert.ct_log import lookup_ct  # noqa: PLC0415

    return await lookup_ct(row.server_name or row.host, limit=limit)


@router.post("/{target_id}/probe", response_model=TLSCertTargetRead)
async def probe_now(target_id: uuid.UUID, db: DB, user: CurrentUser) -> TLSCertTargetRead:
    """Synchronous probe — runs now (≈8 s timeout), returns the fresh row."""
    row = await db.get(TLSCertTarget, target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="target not found")
    result = await probe_one(db, row, default_interval_hours=await _interval(db))
    write_audit(
        db,
        user=user,
        action="probe",
        resource_type="tls_cert",
        resource_id=str(row.id),
        resource_display=row.display_name or row.host,
        new_value={"state": result.state, "ok": result.ok, "error": result.error},
        result="success" if result.ok else "error",
    )
    await db.commit()
    await db.refresh(row)
    return TLSCertTargetRead.model_validate(row)
