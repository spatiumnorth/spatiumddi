"""Logical ownership entities — Customer / Site / Provider (issue #91).

Three first-class rows that cross-cut IPAM / DNS / DHCP / Network so
operators can answer "who owns this?", "what's at NYC?", and "which
circuits does Cogent supply us?" without resorting to free-form tags.

Distinct from a CMDB: these are *logical* abstractions a network
operator reasons over (customer, site, provider) — not hardware
inventory (rack, U position, PDU). Everything explicitly excluded
from the data model lives in the issue's "Out of scope" list.

Cross-reference columns on existing tables (subnet / ip_block /
ip_space / vrf / dns_zone / asn / network_device / domain) are added
in the matching alembic migration with ``ON DELETE SET NULL`` so a
customer/site/provider deletion never cascades into core IPAM rows —
operators want to re-tag, not lose data.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, SoftDeleteMixin, TimestampMixin, UUIDPrimaryKeyMixin

# Customer status values. ``decommissioning`` flags rows that are
# winding down so the dashboard / list views can de-emphasise them
# without deleting the row (operators still want history).
CUSTOMER_STATUSES: frozenset[str] = frozenset({"active", "inactive", "decommissioning"})

# Site kind values. Free-form ``region`` lives alongside this — kind is
# the discrete shape, region is the operator's geo label.
SITE_KINDS: frozenset[str] = frozenset(
    {"datacenter", "branch", "pop", "colo", "cloud_region", "customer_premise"}
)

# Provider kind values. ``registrar`` is for domain registration
# providers (replaces today's freeform Domain.registrar text).
# ``sdwan_vendor`` is reserved for the SD-WAN overlay roadmap (#95).
PROVIDER_KINDS: frozenset[str] = frozenset(
    {"transit", "peering", "carrier", "cloud", "registrar", "sdwan_vendor"}
)


class Customer(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """A logical owner of network resources.

    Soft-deletable because operators commonly decommission customers
    but want to keep the audit-trail of which subnets / zones used to
    belong to them.

    ``account_number`` is operator-supplied — not enforced unique
    because some shops keep the same account number across separate
    Customer rows for cost allocation purposes.
    """

    __tablename__ = "customer"
    __table_args__ = (
        # Partial, so a soft-deleted customer stops holding its name (#2738);
        # same pattern as ix_ip_space_name (#491).
        Index(
            "uq_customer_name",
            "name",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_customer_status", "status"),
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    account_number: Mapped[str | None] = mapped_column(String(64), nullable=True)
    contact_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    contact_phone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    contact_address: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ``active`` | ``inactive`` | ``decommissioning``
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="active", server_default="active"
    )
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")

    tags: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default="{}")
    custom_fields: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )

    # Provenance for the NetBox one-shot importer (issue #36). ``netbox``
    # for customers (NetBox tenants) created by /ipam/import/netbox; NULL
    # for hand-created rows. ``imported_at`` is the wall-clock commit time.
    import_source: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Site(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A physical location resources are deployed at.

    Hierarchical: a campus Site may have building Sites under it,
    and floors below those. ``parent_site_id`` is ``ON DELETE SET
    NULL`` so deleting a parent doesn't cascade-delete its children
    (operators may want to keep the leaves and re-parent them
    manually).

    Deliberately NOT modelled here: lat / long, rack count, floor
    plans, U-positions, postal address fields. That's CMDB territory
    — see issue #91 "Out of scope". ``region`` is a free-form geo
    label (``us-east-1`` / ``EMEA`` / ``NYC metro``) so operators can
    self-organise without us prescribing a taxonomy.
    """

    __tablename__ = "site"
    __table_args__ = (
        # Operator code is unique per parent for sub-site disambiguation
        # (e.g. two campuses with floors named ``F1``). NULL parents
        # share one global namespace; ``NULLS NOT DISTINCT`` makes the
        # NULL parent_site_id values compare equal so two top-level sites
        # can't share a *code*. But ``code`` itself is optional, and that
        # same NULLS-NOT-DISTINCT flag also makes empty codes collide —
        # so a second code-less sibling (top-level or otherwise) would
        # 409 with "a sibling site with this code already exists" even
        # though it has no code at all. The partial ``WHERE code IS NOT
        # NULL`` predicate excludes code-less rows from the index, so any
        # number of siblings may have no code while real codes stay
        # unique per parent. (create/update normalise ``""`` → NULL so
        # an empty input field is treated as "no code", not a code of
        # "".) Requires PG 15+ for NULLS NOT DISTINCT.
        Index(
            "ix_site_parent_code_unique",
            "parent_site_id",
            "code",
            unique=True,
            postgresql_nulls_not_distinct=True,
            postgresql_where=text("code IS NOT NULL"),
        ),
        Index("ix_site_kind", "kind"),
        Index("ix_site_region", "region"),
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # Short operator-facing slug (``DC-EAST`` / ``NYC-01``); optional
    # but expected for any site that gets referenced from terminal
    # output / runbooks.
    code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # ``datacenter`` | ``branch`` | ``pop`` | ``colo`` | ``cloud_region`` | ``customer_premise``
    kind: Mapped[str] = mapped_column(
        String(32), nullable=False, default="datacenter", server_default="datacenter"
    )
    region: Mapped[str | None] = mapped_column(String(128), nullable=True)
    parent_site_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("site.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    tags: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default="{}")

    # Provenance for the NetBox one-shot importer (issue #36). ``netbox``
    # for sites (NetBox sites/regions) created by /ipam/import/netbox; NULL
    # for hand-created rows. ``imported_at`` is the wall-clock commit time.
    import_source: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Provider(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An external organisation we buy network capacity / services from.

    ``default_asn_id`` is the optional FK to an ASN — typically the
    provider's main BGP AS for peering. ``ON DELETE SET NULL`` so
    deleting an ASN row nulls this column rather than cascading the
    Provider delete.

    The ``registrar`` ``kind`` overlaps with the existing
    ``Domain.registrar`` text column. The migration adds
    ``Domain.registrar_provider_id`` as the FK successor; backfill
    of existing free-form values is explicitly deferred (issue #91
    "Deferred follow-ups") so domain rows keep their existing text
    until an operator picks a Provider through the new picker.
    """

    __tablename__ = "provider"
    __table_args__ = (
        UniqueConstraint("name", name="uq_provider_name"),
        Index("ix_provider_kind", "kind"),
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # ``transit`` | ``peering`` | ``carrier`` | ``cloud`` | ``registrar`` | ``sdwan_vendor``
    kind: Mapped[str] = mapped_column(
        String(32), nullable=False, default="transit", server_default="transit"
    )
    account_number: Mapped[str | None] = mapped_column(String(64), nullable=True)
    contact_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    contact_phone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")

    default_asn_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("asn.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    tags: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default="{}")


__all__ = [
    "Customer",
    "Site",
    "Provider",
    "CUSTOMER_STATUSES",
    "SITE_KINDS",
    "PROVIDER_KINDS",
]
