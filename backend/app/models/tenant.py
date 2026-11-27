"""Tenant -- the multi-tenancy boundary on IP spaces (#4263, phase 1 of #695).

A tenant owns IP spaces; blocks, subnets and addresses belong to the tenant of
their space (ownership by container, not per row). Groups and API tokens may be
bound to a tenant, which makes their users *tenant users*: every IPAM read is
narrowed to the tenant's spaces by ``app.services.tenancy`` and every route
that has not declared itself tenant-aware is refused.

``customer_id`` optionally links the free-form ``Customer`` ownership label;
the tenant never reads it for enforcement.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Tenant(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "tenant"
    __table_args__ = (Index("uq_tenant_name_lower", text("lower(name)"), unique=True),)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    customer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("customer.id", ondelete="SET NULL"),
        nullable=True,
    )
