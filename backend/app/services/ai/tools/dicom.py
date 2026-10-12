"""Operator-Copilot tools for the DICOM AE registry (#723).

Read-only tools over the AE Title namespace and the configured
association map. All gated on the ``network.dicom`` feature module so
they stay in lock-step with the feature surface.

No ``propose_*`` write tools. Every write here is plain CRUD an operator
performs in the UI, and shipping write proposals for a brand-new table
before anyone has used it would be speculative.

Nothing in this module returns patient data — the registry does not
store any. See ``app.models.dicom`` for the guardrail.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.models.auth import User
from app.models.dicom import DICOMApplicationEntity, DICOMPeer
from app.models.ipam import IPAddress
from app.services.ai.tools.base import register_tool
from app.services.dicom.titles import is_vendor_default

_MODULE = "network.dicom"


class FindDICOMAEsArgs(BaseModel):
    ae_title: str | None = Field(
        default=None,
        description="Exact AE Title (case-sensitive — peers match titles exactly).",
    )
    device_class: str | None = Field(
        default=None,
        description=(
            "modality / pacs / workstation / archive / router / worklist / printer / other."
        ),
    )
    subnet_id: UUID | None = Field(default=None, description="Restrict to one subnet.")
    unbound: bool | None = Field(
        default=None,
        description=(
            "True = only reservations (titles with no host, held so the name is "
            "not re-issued while peers still send to it)."
        ),
    )
    tls_enabled: bool | None = Field(
        default=None, description="Filter on whether the AE is recorded as using TLS."
    )
    q: str | None = Field(
        default=None,
        description="Case-insensitive substring on title, vendor, model, department or location.",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_dicom_aes",
    permission=("read", "dicom_ae"),
    description=(
        "List DICOM Application Entities with their AE Title, host, port, "
        "role and device class. Use this to answer 'which device holds AE "
        "Title X', 'what imaging gear is on this subnet', or 'which AE "
        "Titles are still vendor defaults'. AE Titles are unique "
        "institution-wide, so an exact title lookup returns at most one row."
    ),
    args_model=FindDICOMAEsArgs,
    category="network",
    module=_MODULE,
    # Read-only network inventory. No secrets, no patient data (the
    # registry stores none), no device access.
    default_enabled=True,
)
async def find_dicom_aes(
    db: AsyncSession, user: User, args: FindDICOMAEsArgs
) -> list[dict[str, Any]]:
    _ = user
    # OUTER join — an unbound reservation has no address row, and an
    # inner join would hide exactly the rows most at risk of being
    # silently re-issued.
    stmt = select(DICOMApplicationEntity, IPAddress).outerjoin(
        IPAddress, IPAddress.id == DICOMApplicationEntity.ip_address_id
    )
    if args.ae_title:
        stmt = stmt.where(DICOMApplicationEntity.ae_title == args.ae_title.strip())
    if args.device_class:
        stmt = stmt.where(DICOMApplicationEntity.device_class == args.device_class)
    if args.subnet_id is not None:
        stmt = stmt.where(DICOMApplicationEntity.subnet_id == args.subnet_id)
    if args.unbound is not None:
        stmt = stmt.where(
            DICOMApplicationEntity.ip_address_id.is_(None)
            if args.unbound
            else DICOMApplicationEntity.ip_address_id.is_not(None)
        )
    if args.tls_enabled is not None:
        stmt = stmt.where(DICOMApplicationEntity.tls_enabled.is_(args.tls_enabled))
    if args.q:
        needle = f"%{args.q}%"
        stmt = stmt.where(
            or_(
                DICOMApplicationEntity.ae_title.ilike(needle),
                DICOMApplicationEntity.vendor.ilike(needle),
                DICOMApplicationEntity.model_name.ilike(needle),
                DICOMApplicationEntity.department.ilike(needle),
                DICOMApplicationEntity.location.ilike(needle),
            )
        )
    stmt = stmt.order_by(DICOMApplicationEntity.ae_title).limit(args.limit)

    return [
        {
            "id": str(ae.id),
            "ae_title": ae.ae_title,
            "address": str(ip.address) if ip is not None else None,
            "hostname": ip.hostname if ip is not None else None,
            "port": ae.port,
            "tls_enabled": ae.tls_enabled,
            "role": ae.role,
            "device_class": ae.device_class,
            "vendor": ae.vendor,
            "model_name": ae.model_name,
            "department": ae.department,
            "location": ae.location,
            "subnet_id": str(ae.subnet_id) if ae.subnet_id else None,
            "is_reservation": ae.ip_address_id is None,
            "is_vendor_default": is_vendor_default(ae.ae_title),
            "seen_via": ae.seen_via,
        }
        for ae, ip in (await db.execute(stmt)).all()
    ]


class CountDICOMAEsArgs(BaseModel):
    subnet_id: UUID | None = Field(default=None, description="Restrict to one subnet.")


@register_tool(
    name="count_dicom_aes",
    permission=("read", "dicom_ae"),
    description=(
        "Count DICOM Application Entities with a breakdown of unbound "
        "reservations, plaintext (non-TLS) endpoints, and how many are "
        "still on a vendor default AE Title. Quick health rollup for an "
        "imaging estate."
    ),
    args_model=CountDICOMAEsArgs,
    category="network",
    module=_MODULE,
    default_enabled=True,
)
async def count_dicom_aes(db: AsyncSession, user: User, args: CountDICOMAEsArgs) -> dict[str, Any]:
    _ = user
    stmt = select(
        func.count(DICOMApplicationEntity.id),
        func.count(DICOMApplicationEntity.id).filter(
            DICOMApplicationEntity.ip_address_id.is_(None)
        ),
        func.count(DICOMApplicationEntity.id).filter(DICOMApplicationEntity.tls_enabled.is_(False)),
    )
    if args.subnet_id is not None:
        stmt = stmt.where(DICOMApplicationEntity.subnet_id == args.subnet_id)
    total, reservations, plaintext = (await db.execute(stmt)).one()

    # Vendor-default detection is a Python-side set membership, so the
    # titles come back and are counted here rather than in SQL. The
    # registry is hundreds of rows, not millions.
    title_stmt = select(DICOMApplicationEntity.ae_title)
    if args.subnet_id is not None:
        title_stmt = title_stmt.where(DICOMApplicationEntity.subnet_id == args.subnet_id)
    titles = (await db.execute(title_stmt)).scalars().all()

    return {
        "total": int(total),
        "reservations": int(reservations),
        "plaintext": int(plaintext),
        "vendor_default_titles": sum(1 for t in titles if is_vendor_default(t)),
    }


class FindDICOMPeersArgs(BaseModel):
    ae_title: str | None = Field(
        default=None,
        description=(
            "Restrict to edges touching this AE Title, in either direction. "
            "This is the 'what breaks if I renumber it' question."
        ),
    )
    limit: int = Field(default=200, ge=1, le=500)


@register_tool(
    name="find_dicom_peers",
    permission=("read", "dicom_ae"),
    description=(
        "List configured DICOM associations as directed AE→AE edges with "
        "the services each carries. Use this to answer 'what talks to this "
        "modality' or 'what would break if this host is renumbered'. These "
        "are relationships documented by the operator, not observed traffic."
    ),
    args_model=FindDICOMPeersArgs,
    category="network",
    module=_MODULE,
    default_enabled=True,
)
async def find_dicom_peers(
    db: AsyncSession, user: User, args: FindDICOMPeersArgs
) -> list[dict[str, Any]]:
    _ = user
    source = aliased(DICOMApplicationEntity, name="source_ae")
    target = aliased(DICOMApplicationEntity, name="target_ae")
    stmt = (
        select(DICOMPeer, source.ae_title, target.ae_title)
        .join(source, source.id == DICOMPeer.source_ae_id)
        .join(target, target.id == DICOMPeer.target_ae_id)
        .order_by(source.ae_title.asc(), target.ae_title.asc())
        .limit(args.limit)
    )
    if args.ae_title:
        needle = args.ae_title.strip()
        stmt = stmt.where(or_(source.ae_title == needle, target.ae_title == needle))

    return [
        {
            "id": str(peer.id),
            "source_ae_title": src,
            "target_ae_title": dst,
            "services": [str(s) for s in (peer.services or [])],
            "notes": peer.notes,
        }
        for peer, src, dst in (await db.execute(stmt)).all()
    ]
