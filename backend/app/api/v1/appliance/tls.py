"""Appliance Web UI certificate management — Phase 4b.1.

Mounted at ``/api/v1/appliance/tls``. Operators paste cert + private
key PEM, the server validates the pair, stores it (key Fernet-encrypted
at rest), and exposes activate / delete. Phase 4b.2 will materialize
the active row into ``/etc/nginx/certs/active.{pem,key}`` and reload
nginx; 4b.1 just persists, so the surface is testable in dev before
the appliance-side wiring lands.

All mutating routes require ``admin`` on ``appliance``; reads accept
``read``. The "Appliance Operator" built-in role grants admin;
superadmin bypasses both.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import or_, select

from app.api.deps import DB, CurrentUser
from app.config import settings
from app.core.crypto import encrypt_str
from app.core.permissions import require_permission
from app.models.appliance import (
    CERT_SOURCE_CSR,
    CERT_SOURCE_UPLOADED,
    ApplianceCertificate,
)
from app.models.audit import AuditLog
from app.services.appliance.deployment import deploy_and_reload
from app.services.appliance.tls import (
    KEY_TYPES,
    CSRSubject,
    TLSValidationError,
    generate_csr_and_key,
    parse_pem_certificate,
    validate_key_matches_cert,
)
from app.services.dns.cert_rotation import (
    wake_dns_groups_serving_cert,
    wake_for_cert_deletion,
)

logger = structlog.get_logger(__name__)

router = APIRouter()


# ── Response shapes ─────────────────────────────────────────────────


class CertificateSummary(BaseModel):
    """Cert metadata only — never includes cert_pem or the key.

    Used for list responses where we don't want to ship the full PEM
    for every row. The single-cert GET returns the cert PEM as a
    separate field (key still never leaves the server).

    For CSR-pending rows (Phase 4b.3), ``pending`` is true and the
    cert-derived fields (issuer_cn / fingerprint / validity dates)
    are null. The ``csr_pem`` field on this same summary lets the UI
    surface the "download CSR" affordance without a separate fetch.
    """

    id: uuid.UUID
    name: str
    source: str
    is_active: bool
    activated_at: datetime | None
    subject_cn: str
    issuer_cn: str | None
    sans: list[str]
    fingerprint_sha256: str | None
    valid_from: datetime | None
    valid_to: datetime | None
    notes: str | None
    created_at: datetime
    created_by_user_id: uuid.UUID | None
    # CSR-pending state: true when this row is waiting for the operator
    # to paste back a signed cert from their CA. While pending, the
    # cert-derived fields above are null and ``csr_pem`` is set.
    pending: bool
    csr_pem: str | None


class CertificateDetail(CertificateSummary):
    cert_pem: str | None


def _to_summary(row: ApplianceCertificate) -> CertificateSummary:
    return CertificateSummary(
        id=row.id,
        name=row.name,
        source=row.source,
        is_active=row.is_active,
        activated_at=row.activated_at,
        subject_cn=row.subject_cn,
        issuer_cn=row.issuer_cn,
        sans=row.sans_json,
        fingerprint_sha256=row.fingerprint_sha256,
        valid_from=row.valid_from,
        valid_to=row.valid_to,
        notes=row.notes,
        created_at=row.created_at,
        created_by_user_id=row.created_by_user_id,
        pending=row.cert_pem is None,
        csr_pem=row.csr_pem,
    )


# ── Request bodies ──────────────────────────────────────────────────


class CertificateUpload(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    cert_pem: str = Field(min_length=1)
    key_pem: str = Field(min_length=1)
    notes: str | None = Field(default=None, max_length=2000)
    # If true, the new cert becomes the active one (clears all other
    # rows' is_active flag). If false, it lands inactive — operator
    # has to hit /activate to flip it. Default true since the most
    # common path is "I uploaded a renewal, use it now".
    activate: bool = True


class CSRGenerate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    # Subject fields — common_name is required, the rest are optional.
    # Country must be the 2-letter ISO code (CA, US, GB, …) per the
    # x509 spec; "ZZ" is fine even if politically meaningless, but the
    # letters must be ASCII: pydantic's min/max_length counts CHARACTERS
    # while cryptography's CountryName counts encoded BYTES, so a
    # 2-character multibyte string passed validation and blew up the
    # x509.Name build as a 500 ("length must be >= 2 and <= 2, but it
    # was 6", live under fuzz).
    common_name: str = Field(min_length=1, max_length=255)
    organization: str | None = Field(default=None, max_length=120)
    organizational_unit: str | None = Field(default=None, max_length=120)
    country: str | None = Field(default=None, pattern="^[A-Za-z]{2}$")
    state: str | None = Field(default=None, max_length=120)
    locality: str | None = Field(default=None, max_length=120)
    email: str | None = Field(default=None, max_length=255)
    sans: list[str] = Field(default_factory=list, max_length=100)
    key_type: str = Field(default="rsa-2048")
    notes: str | None = Field(default=None, max_length=2000)


class CSRImport(BaseModel):
    cert_pem: str = Field(min_length=1)
    # Default true — most operators paste the signed cert specifically
    # so it becomes active. False keeps it inactive for staged renewals.
    activate: bool = True


# ── Endpoints ───────────────────────────────────────────────────────


@router.get(
    "",
    response_model=list[CertificateSummary],
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="List Web UI certificates",
)
async def list_certificates(db: DB) -> list[CertificateSummary]:
    result = await db.execute(
        select(ApplianceCertificate).order_by(
            ApplianceCertificate.is_active.desc(),
            ApplianceCertificate.created_at.desc(),
        )
    )
    return [_to_summary(row) for row in result.scalars().all()]


@router.get(
    "/{cert_id:uuid}",
    response_model=CertificateDetail,
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Get one certificate (with PEM, never key)",
)
async def get_certificate(cert_id: uuid.UUID, db: DB) -> CertificateDetail:
    row = await db.get(ApplianceCertificate, cert_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "certificate not found")
    summary = _to_summary(row)
    return CertificateDetail(**summary.model_dump(), cert_pem=row.cert_pem)


@router.post(
    "/upload",
    response_model=CertificateSummary,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Upload a PEM certificate + private key",
)
async def upload_certificate(
    body: CertificateUpload,
    db: DB,
    user: CurrentUser,
) -> CertificateSummary:
    """Parse, validate, store. 422 on any parse / mismatch failure.

    The key is Fernet-encrypted before persistence. The cert PEM is
    stored verbatim — public material, no need to encrypt.
    """
    try:
        info = parse_pem_certificate(body.cert_pem)
        validate_key_matches_cert(body.cert_pem, body.key_pem)
    except TLSValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))

    # Name uniqueness — separate check so we return a clean 409 rather
    # than letting the unique constraint surface as a generic 500.
    existing = await db.execute(
        select(ApplianceCertificate).where(ApplianceCertificate.name == body.name)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"a certificate named '{body.name}' already exists",
        )

    row = ApplianceCertificate(
        name=body.name,
        source=CERT_SOURCE_UPLOADED,
        cert_pem=body.cert_pem,
        key_encrypted=encrypt_str(body.key_pem),
        is_active=False,
        subject_cn=info.subject_cn,
        sans_json=info.sans,
        issuer_cn=info.issuer_cn,
        fingerprint_sha256=info.fingerprint_sha256,
        valid_from=info.valid_from,
        valid_to=info.valid_to,
        notes=body.notes,
        created_by_user_id=user.id,
    )
    db.add(row)
    await db.flush()

    if body.activate:
        await _activate_only(db, row)

    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="create",
            resource_type="appliance_certificate",
            resource_id=str(row.id),
            resource_display=row.name,
            new_value={
                "name": row.name,
                "source": row.source,
                "subject_cn": row.subject_cn,
                "fingerprint_sha256": row.fingerprint_sha256,
                "valid_to": row.valid_to.isoformat() if row.valid_to else None,
                "is_active": row.is_active,
            },
            result="success",
        )
    )
    await db.commit()
    await db.refresh(row)
    logger.info(
        "appliance_cert_uploaded",
        cert_id=str(row.id),
        name=row.name,
        subject_cn=row.subject_cn,
        is_active=row.is_active,
    )
    # Pass body.key_pem so the deployer doesn't have to re-decrypt
    # what we just encrypted milliseconds ago.
    _deploy_if_active(row, body.key_pem)
    return _to_summary(row)


@router.post(
    "/csr",
    response_model=CertificateSummary,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Generate a private key + CSR on the server, save them",
)
async def generate_csr(
    body: CSRGenerate,
    db: DB,
    user: CurrentUser,
) -> CertificateSummary:
    """Create a CSR-pending row.

    The private key never leaves the server: it's generated here,
    Fernet-encrypted, and persisted. The operator gets back the CSR
    PEM (via this response and via GET /tls/{id}) to hand to their
    CA. Once they have the signed cert they POST /tls/{id}/import-cert
    with the cert PEM; the server pairs it with the stored key and
    the row becomes a normal (no-longer-pending) certificate.

    422 if the key type isn't recognised, the common_name is empty,
    or any SAN entry fails to parse as DNS / IP.
    """
    if body.key_type not in KEY_TYPES:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"unsupported key_type — pick one of {', '.join(KEY_TYPES)}",
        )

    existing = await db.execute(
        select(ApplianceCertificate).where(ApplianceCertificate.name == body.name)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"a certificate named '{body.name}' already exists",
        )

    subject = CSRSubject(
        common_name=body.common_name.strip(),
        organization=body.organization,
        organizational_unit=body.organizational_unit,
        country=body.country.upper() if body.country else None,
        state=body.state,
        locality=body.locality,
        email=body.email,
    )

    try:
        csr_pem, key_pem = generate_csr_and_key(subject, body.sans, body.key_type)
    except TLSValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))

    row = ApplianceCertificate(
        name=body.name,
        source=CERT_SOURCE_CSR,
        cert_pem=None,  # populated on import-cert
        key_encrypted=encrypt_str(key_pem),
        is_active=False,
        subject_cn=subject.common_name,
        sans_json=list(body.sans),
        issuer_cn=None,
        fingerprint_sha256=None,
        valid_from=None,
        valid_to=None,
        notes=body.notes,
        created_by_user_id=user.id,
        csr_pem=csr_pem,
        csr_subject=subject.to_dict() | {"sans": list(body.sans), "key_type": body.key_type},
    )
    db.add(row)
    await db.flush()

    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="generate_csr",
            resource_type="appliance_certificate",
            resource_id=str(row.id),
            resource_display=row.name,
            new_value={
                "name": row.name,
                "subject_cn": subject.common_name,
                "sans": body.sans,
                "key_type": body.key_type,
            },
            result="success",
        )
    )
    await db.commit()
    await db.refresh(row)
    logger.info(
        "appliance_csr_generated",
        cert_id=str(row.id),
        name=row.name,
        subject_cn=subject.common_name,
        key_type=body.key_type,
    )
    return _to_summary(row)


@router.post(
    "/{cert_id:uuid}/import-cert",
    response_model=CertificateSummary,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Attach a CA-signed certificate to a CSR-pending row",
)
async def import_signed_cert(
    cert_id: uuid.UUID,
    body: CSRImport,
    db: DB,
    user: CurrentUser,
) -> CertificateSummary:
    """Finalize a CSR-pending row by pairing it with the signed cert.

    Decrypts the stored private key, validates that the supplied
    certificate's public key matches it, parses the cert for identity
    (issuer / fingerprint / validity), and flips the row out of
    pending state. Optionally activates.

    422 if the cert doesn't match the stored key, if the row isn't
    actually pending, or if the cert PEM fails to parse.
    """
    from app.core.crypto import decrypt_str

    row = await db.get(ApplianceCertificate, cert_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "certificate not found")
    if row.cert_pem is not None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "this row already has a certificate — upload a new row instead",
        )

    try:
        stored_key_pem = decrypt_str(row.key_encrypted)
        validate_key_matches_cert(body.cert_pem, stored_key_pem)
        info = parse_pem_certificate(body.cert_pem)
    except TLSValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))

    # The CA might have edited the subject / SANs (rare, but a few
    # public CAs normalise). Trust the cert as the canonical source
    # now that it's signed. Keep csr_pem on the row for audit history.
    row.cert_pem = body.cert_pem
    row.subject_cn = info.subject_cn
    row.sans_json = info.sans
    row.issuer_cn = info.issuer_cn
    row.fingerprint_sha256 = info.fingerprint_sha256
    row.valid_from = info.valid_from
    row.valid_to = info.valid_to

    if body.activate:
        await _activate_only(db, row)

    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="import_signed_cert",
            resource_type="appliance_certificate",
            resource_id=str(row.id),
            resource_display=row.name,
            new_value={
                "subject_cn": row.subject_cn,
                "issuer_cn": row.issuer_cn,
                "fingerprint_sha256": row.fingerprint_sha256,
                "valid_to": row.valid_to.isoformat() if row.valid_to else None,
                "is_active": row.is_active,
            },
            result="success",
        )
    )
    await db.commit()
    await db.refresh(row)
    logger.info(
        "appliance_csr_imported",
        cert_id=str(row.id),
        name=row.name,
        subject_cn=row.subject_cn,
        is_active=row.is_active,
    )
    # ``stored_key_pem`` is in scope from earlier in this function
    # — reuse it so we don't decrypt twice.
    _deploy_if_active(row, stored_key_pem)
    # #50 — this row may also back a DNS group's DoT/DoH listener; the
    # freshly-signed cert has to reach those agents too.
    await wake_dns_groups_serving_cert(db, row.id)
    return _to_summary(row)


@router.post(
    "/{cert_id:uuid}/activate",
    response_model=CertificateSummary,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Make this certificate the active one",
)
async def activate_certificate(
    cert_id: uuid.UUID,
    db: DB,
    user: CurrentUser,
) -> CertificateSummary:
    row = await db.get(ApplianceCertificate, cert_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "certificate not found")

    # CSR-pending rows have no cert yet — refuse the activation outright
    # rather than letting nginx try to serve a null cert_pem.
    if row.cert_pem is None or row.valid_to is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "this row is a CSR awaiting signature — paste the signed certificate first",
        )

    # Refuse to activate an expired cert — nginx would happily serve
    # it but every client would refuse the connection, and the
    # operator wouldn't see why until they tried to load the UI. A
    # 422 with a clear message is friendlier.
    if row.valid_to < datetime.now(tz=row.valid_to.tzinfo):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"certificate expired on {row.valid_to.isoformat()}; upload a renewal first",
        )

    await _activate_only(db, row)
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="activate_certificate",
            resource_type="appliance_certificate",
            resource_id=str(row.id),
            resource_display=row.name,
            result="success",
        )
    )
    await db.commit()
    await db.refresh(row)
    logger.info("appliance_cert_activated", cert_id=str(row.id), name=row.name)
    # Decrypt + write cert files + HUP nginx. No-op on non-appliance.
    _deploy_if_active(row, None)
    return _to_summary(row)


@router.delete(
    "/{cert_id:uuid}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Delete a certificate",
)
async def delete_certificate(
    cert_id: uuid.UUID,
    db: DB,
    user: CurrentUser,
) -> None:
    row = await db.get(ApplianceCertificate, cert_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "certificate not found")
    if row.is_active:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "this certificate is currently active — activate a different one first",
        )

    # #50 — the same store backs DNS DoT/DoH listeners, and the FK is
    # ON DELETE SET NULL, so without this guard deleting a cert silently
    # drops every encrypted-DNS client in those groups back to "connection
    # refused" with nothing warning the operator. Mirrors the is_active
    # check above: refuse, name what's using it, let them unlink first.
    serving = await _dns_groups_serving_cert(db, cert_id)
    if serving:
        names = ", ".join(serving)
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"this certificate serves DoT/DoH for DNS server group(s): {names}. "
            "Disable those listeners (or point them at another certificate) "
            "under DNS → Server Groups → Options → Encrypted transports first.",
        )

    # Wake BEFORE the delete: afterwards the FK is already NULL and the
    # owning groups can no longer be found. Nothing is actually serving this
    # cert (the guard above just proved it), so this only covers the
    # cert-linked-but-listeners-off case, where the bundle carries no
    # material and the wake is a cheap no-op.
    await wake_for_cert_deletion(db, cert_id)

    name = row.name
    await db.delete(row)
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="delete",
            resource_type="appliance_certificate",
            resource_id=str(cert_id),
            resource_display=name,
            result="success",
        )
    )
    await db.commit()
    logger.info("appliance_cert_deleted", cert_id=str(cert_id), name=name)


# ── Internal helpers ────────────────────────────────────────────────


async def _dns_groups_serving_cert(db: DB, cert_id: uuid.UUID) -> list[str]:
    """Names of DNS server groups with a LIVE DoT/DoH listener on this cert.

    Only groups with a listener actually enabled count — a group that merely
    points at the cert with both listeners off isn't serving anything, so
    deleting the cert costs it nothing.
    """
    from app.models.dns import DNSServerGroup, DNSServerOptions  # noqa: PLC0415

    rows = (
        (
            await db.execute(
                select(DNSServerGroup.name)
                .join(DNSServerOptions, DNSServerOptions.group_id == DNSServerGroup.id)
                .where(
                    DNSServerOptions.tls_certificate_id == cert_id,
                    or_(
                        DNSServerOptions.dot_enabled.is_(True),
                        DNSServerOptions.doh_enabled.is_(True),
                    ),
                )
                .order_by(DNSServerGroup.name)
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


def _deploy_if_active(row: ApplianceCertificate, key_pem: str | None) -> None:
    """Materialise an active cert onto disk + signal nginx to reload.

    Called from the three endpoints that flip is_active=True after
    the DB commit lands. ``key_pem`` is the decrypted private key —
    callers that have it in hand (upload / import) pass it through
    so we don't double-decrypt; activate-only calls pass None and we
    re-decrypt from ``row.key_encrypted``.

    Failure inside the deployer is logged but never raised — the DB
    is the source of truth ("this cert IS active"); the cert-on-disk
    is just the materialisation. A stuck nginx reload still leaves
    the API state correct, and Path A of ensure_self_signed_cert will
    re-deploy on next api boot.

    No-op when settings.appliance_mode is false.
    """
    if not row.is_active or not row.cert_pem:
        return
    if not settings.appliance_mode:
        return
    if key_pem is None:
        from app.core.crypto import decrypt_str  # noqa: PLC0415

        try:
            key_pem = decrypt_str(row.key_encrypted)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "appliance_cert_deploy_decrypt_failed",
                cert_id=str(row.id),
                error=str(exc),
            )
            return
    deploy_and_reload(row.cert_pem, key_pem, name=row.name)


async def _activate_only(db: DB, target: ApplianceCertificate) -> None:
    """Flip ``is_active=true`` on ``target``, false on everything else.

    Done in one transaction so we never have two active rows or zero
    active rows visible to a concurrent read. Caller commits.
    """

    from sqlalchemy import update

    # target.valid_to can be None for a CSR-pending row, but those are
    # rejected upstream by the activate endpoint — keep a safe fallback
    # anyway so the helper doesn't crash if a future caller drifts.
    tzinfo = target.valid_to.tzinfo if target.valid_to else UTC
    now = datetime.now(tz=tzinfo)
    await db.execute(
        update(ApplianceCertificate)
        .where(ApplianceCertificate.id != target.id)
        .values(is_active=False)
    )
    target.is_active = True
    target.activated_at = now
