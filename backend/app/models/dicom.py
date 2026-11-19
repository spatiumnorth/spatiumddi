"""DICOM Application Entity registry — issue #723 (part of #543).

A DICOM Application Entity Title is a flat, **institution-wide-unique**,
16-byte identifier. Every imaging device, PACS node, workstation and
archive on a hospital network answers to one, and every peer that wants
to talk to it must have that exact string configured. Duplicates break
C-MOVE, Storage Commitment, Modality Worklist and MPPS in ways that are
famously hard to trace, and the failure mode is documented back to 1997.

DICOM PS3.15 Annex H defines ``dicomUniqueAETitlesRegistryRoot`` — an LDAP
registry object whose entire purpose is allocating unique AE Titles via a
compare-and-set against an enforced constraint. It is essentially
undeployed. In practice the namespace lives in a spreadsheet.

That is the BACnet device-instance argument (#541,
``uq_bacnet_device_instance``) with better provenance: the standard
itself says the value must be unique and specifies a registry for it, and
no incumbent system owns the namespace. So the ``UNIQUE(ae_title)``
constraint below is the point of this table, not an incidental index.

Two structural decisions worth stating outright:

* ``ip_address_id`` is **nullable** with ``ON DELETE SET NULL``, unlike
  BACnet's ``CASCADE``. An AE Title outlives the host it currently runs
  on: it is burned into peer configuration across the estate, so
  decommissioning an IP must demote the title to a *reservation*, not
  free a name that a dozen modalities still send to. Cascading would
  hand that name straight back to the next commissioning engineer.
* ``DICOMPeer`` is a directed AE→AE edge describing *configured*
  associations, not observed traffic. It is what makes "what breaks if I
  renumber this host" and an ePHI data-flow map answerable — the
  topology-rule analogue of BACnet's BBMD-per-subnet.

**No PHI, ever.** This registry stores network identity only: titles,
addresses, ports, roles, vendors. It records nothing about patients,
studies, or images. Storing patient-identifiable data would make
SpatiumDDI a HIPAA Business Associate, which is permanently out of
scope. There is deliberately no free-text field documented as safe for
clinical detail, and ``notes`` is documented in the API as
network-configuration notes.

Phase 1 (this) is registry + conformity with zero network I/O. The
C-ECHO verification probe — which would confirm an AE actually answers
at the recorded host:port — is deferred to its own issue. Unlike every
other deferred probe in the #543 family it is *not* blocked on the
agent↔subnet binding (C-ECHO is routable unicast TCP), but it must
respect the #722 do-not-probe flag, and a probe that reaches a modality
mid-study is exactly the hazard #722 exists for.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

# The AE Value Representation is 16 characters of printable ASCII — not
# an alphanumeric-only repertoire. Per PS3.5:
#
#   * maximum length 16 (ASCII, so characters == bytes);
#   * the default character repertoire (0x20-0x7E) excluding backslash
#     (0x5C); control characters and non-ASCII are refused;
#   * spaces are LEGAL but non-significant (they are padding), so
#     leading/trailing space is trimmed on the way in;
#   * an all-space value is explicitly forbidden.
#
# Getting this wrong in the strict direction is not harmless: a registry
# that rejects a title real devices use records a plan that fails at
# commissioning, which is the exact failure this table exists to prevent.
DICOM_AE_TITLE_MAX_BYTES: int = 16

# Vendor default AE Titles, lower-cased for comparison. Devices ship with
# these and an alarming number stay that way, which is what makes
# duplicates so common — two vendors' defaults collide across an estate
# long before anyone runs out of names. Advisory only; the check that
# reads this warns, it does not block.
DICOM_DEFAULT_AE_TITLES: frozenset[str] = frozenset(
    {
        "ae_title",
        "aetitle",
        "any-scp",
        "anyscp",
        "changeme",
        "conquestsrv1",
        "dcm4chee",
        "dcmqrscp",
        "default",
        "dicom",
        "horos",
        "orthanc",
        "osirix",
        "pacs",
        "storescp",
        "storescu",
        "test",
        "workstation",
    }
)

# What the AE does in an association. DICOM calls the initiator the
# Service Class User and the responder the Service Class Provider; most
# real devices are both (a modality pushes images as an SCU and answers
# echo/worklist as an SCP), so ``both`` is the common case rather than an
# escape hatch.
DICOM_AE_ROLES: frozenset[str] = frozenset({"scp", "scu", "both"})

# Coarse device classification. Deliberately shallow — this is for
# filtering a list and reading a data-flow map, not for modelling the
# DICOM conformance statement. ``modality`` covers CT / MR / US / CR and
# the rest; splitting it per-modality would multiply the vocabulary
# without changing any question an operator asks of IPAM.
DICOM_DEVICE_CLASSES: frozenset[str] = frozenset(
    {
        "modality",
        "pacs",
        "workstation",
        "archive",
        "router",
        "worklist",
        "printer",
        "other",
    }
)

# How a row got here. ``import`` is the CSV of an estate's existing AE
# table; ``echo`` is reserved for the deferred C-ECHO verification probe
# so adding it later needs no data migration.
DICOM_AE_SOURCES: frozenset[str] = frozenset({"manual", "import", "echo"})

# 104 and 11112 are both conventional. IANA registers **11112 as
# ``dicom``**; 104 carries the historical name ``acr-nema``, which is
# why it is listed second and why nothing here calls 104 "the DICOM
# port". 11112 is the modern default because 104 is privileged.
DICOM_DEFAULT_PORT: int = 11112
DICOM_LEGACY_PORT: int = 104


class DICOMApplicationEntity(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One DICOM Application Entity, optionally anchored to an IPAM address.

    ``UNIQUE(ae_title)`` is enforced in the database rather than only
    validated in the API because the failure it prevents — two devices
    answering to the same title — is precisely what makes a DICOM estate
    misbehave in ways that cost days to trace. The uniqueness is
    institution-wide by specification, so it is deliberately not scoped
    to a site, subnet or IPSpace.
    """

    __tablename__ = "dicom_ae"
    __table_args__ = (
        # THE constraint. See the class docstring and PS3.15 Annex H.
        UniqueConstraint("ae_title", name="uq_dicom_ae_title"),
        Index("ix_dicom_ae_ip_address_id", "ip_address_id"),
        Index("ix_dicom_ae_device_class", "device_class"),
        # The "which AEs are unbound reservations" list — rows whose host
        # was decommissioned out from under a title still in peer config.
        # Partial, because in a healthy estate almost every row IS bound.
        Index(
            "ix_dicom_ae_unbound",
            "ae_title",
            postgresql_where=text("ip_address_id IS NULL"),
        ),
        CheckConstraint(
            "port >= 1 AND port <= 65535",
            name="ck_dicom_ae_port",
        ),
        # Length is a specification constant, so it is enforced in the
        # database. The *repertoire* (no backslash, no control chars, not
        # all-space) is validated at the API layer, where a rejection can
        # explain which rule was broken.
        CheckConstraint(
            f"octet_length(ae_title) BETWEEN 1 AND {DICOM_AE_TITLE_MAX_BYTES}",
            name="ck_dicom_ae_title_length",
        ),
    )

    # Nullable + SET NULL: an AE Title outlives its host. See the module
    # docstring — this is the deliberate difference from BACnet's CASCADE.
    ip_address_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ip_address.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Denormalized from the address for per-subnet grouping, mirroring
    # ``BACnetDevice.subnet_id``. Kept in step by the service layer at
    # every point the anchor can move.
    subnet_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("subnet.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Stored as given (case is significant to peers — an AE configured as
    # ``CT_ONE`` will not match ``ct_one``), uniqueness is exact-match.
    ae_title: Mapped[str] = mapped_column(String(DICOM_AE_TITLE_MAX_BYTES), nullable=False)

    port: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=DICOM_DEFAULT_PORT,
        server_default=str(DICOM_DEFAULT_PORT),
    )
    # Plain DICOM carries ePHI in the clear. Recording the answer is what
    # makes the ``dicom_ae_no_tls`` check possible; we never test it on
    # the wire.
    tls_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    # One of ``DICOM_AE_ROLES``.
    role: Mapped[str] = mapped_column(
        String(8), nullable=False, default="both", server_default="both"
    )
    # One of ``DICOM_DEVICE_CLASSES``.
    device_class: Mapped[str] = mapped_column(
        String(16), nullable=False, default="other", server_default="other"
    )

    vendor: Mapped[str] = mapped_column(String(255), nullable=False, default="", server_default="")
    model_name: Mapped[str] = mapped_column(
        String(255), nullable=False, default="", server_default=""
    )
    department: Mapped[str] = mapped_column(
        String(255), nullable=False, default="", server_default=""
    )
    location: Mapped[str] = mapped_column(
        String(255), nullable=False, default="", server_default=""
    )

    # One of ``DICOM_AE_SOURCES``.
    seen_via: Mapped[str] = mapped_column(
        String(16), nullable=False, default="manual", server_default="manual"
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Network-configuration notes only. NOT a clinical field — see the
    # module docstring's PHI guardrail; the API description says so too,
    # because the surest way to end up storing PHI is an unlabelled
    # free-text box.
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")

    tags: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )
    custom_fields: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )


class DICOMPeer(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A configured, directed association from one AE to another.

    Direction is meaningful: "the CT pushes to the archive" and "the
    archive queries the CT" are different edges with different failure
    consequences, and collapsing them would lose exactly the information
    that makes a renumbering blast-radius answerable.

    These are *configured* relationships as documented by the operator or
    imported from the estate's AE table — not observed traffic. Nothing
    here is derived from the wire, and this table never grows an
    ``observed_at``: inferring associations from captured DICOM would
    mean parsing traffic that carries PHI.

    Both FKs cascade. An edge to or from a deleted AE describes an
    association that cannot exist, and keeping half an edge would put
    dangling rows into the data-flow map the table exists to produce.
    """

    __tablename__ = "dicom_peer"
    __table_args__ = (
        # One edge per ordered pair. Re-documenting the same association
        # is an update, not a second row.
        UniqueConstraint("source_ae_id", "target_ae_id", name="uq_dicom_peer_pair"),
        Index("ix_dicom_peer_source", "source_ae_id"),
        Index("ix_dicom_peer_target", "target_ae_id"),
        # A self-edge would describe an AE associating with itself, which
        # is not a thing on the wire and would render as a loop in the
        # topology view.
        CheckConstraint("source_ae_id <> target_ae_id", name="ck_dicom_peer_not_self"),
    )

    source_ae_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dicom_ae.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_ae_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dicom_ae.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Free-text list of the DICOM services this edge carries (C-STORE,
    # C-FIND, C-MOVE, MPPS, …). A JSONB list rather than a constrained
    # vocabulary because SOP class support is genuinely open-ended and an
    # operator documenting their estate should never be blocked on our
    # taxonomy being complete.
    services: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )

    notes: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")


__all__ = [
    "DICOM_AE_ROLES",
    "DICOM_AE_SOURCES",
    "DICOM_AE_TITLE_MAX_BYTES",
    "DICOM_DEFAULT_AE_TITLES",
    "DICOM_DEFAULT_PORT",
    "DICOM_DEVICE_CLASSES",
    "DICOM_LEGACY_PORT",
    "DICOMApplicationEntity",
    "DICOMPeer",
]
