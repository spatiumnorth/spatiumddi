"""E911 dispatchable location — issue #972 Phase 1 (LIS core).

RAY BAUM'S Act §506 (47 CFR §9.16(b)) requires every MLTS 911 call to
carry a **dispatchable location**: a validated civic address *plus*
"additional information such as room number, floor number, or similar
information necessary to adequately identify the location of the calling
party". Fixed devices since Jan 2021, non-fixed since Jan 2022. The duty
is on the **enterprise**, not the carrier.

SpatiumDDI already holds every raw input needed to answer "which room is
this device in, right now?" and nothing joins them — DHCP leases and
``IpMacHistory`` for IP↔MAC, ``NetworkFdbEntry`` for MAC↔switch-port,
``NetworkNeighbour`` for the phone's own LLDP announcement,
``Subnet.site_id`` / ``NetworkDevice.site_id`` for the building. That is
exactly the tracking Cisco Emergency Responder does with its own SNMP
pollers against the same switches; here it is a by-product of data
collected for IPAM, and every other consumer can read it too.

**We are not the 911 service provider.** No call routing, no ALI upload,
no ELIN provisioning, no PSAP interaction. This is a location *source*;
the operator's legal duty under §9.16 is theirs, and the docs say so
rather than implying "install this and you are compliant".

Three structural decisions worth stating outright:

* **The civic address lives here, not on ``Site``.** ``Site`` carries
  ``name`` / ``code`` / ``kind`` / ``region`` / ``parent_site_id`` and no
  address fields at all, so there was nothing to extend. An ERL is also
  finer-grained than a site by construction — a building has many
  dispatchable locations — so even a Site with an address could only ever
  supply the front door.

* **Every civic element is its own column**, not one JSONB blob or one
  free-text string. A string cannot be decomposed later, and PIDF-LO,
  HELD and every provider validation API want the elements separately.
  JSONB was the other candidate and is specifically wrong here: #917
  established that an unconstrained object publishes as
  ``{"type": "object"}`` with no properties, which a code generator
  cannot use — and the civic address is the one field every external
  consumer of this feature reads. ``CIVIC_ELEMENTS`` below is the single
  source of truth for the column set, its CAtype numbers and its PIDF-LO
  tag names, so the Phase 2 renderer and the CSV export cannot drift
  from the schema the way the two blocklist renderers did in #878.

* **Binding precedence is fixed in code, not operator-ordered.** There is
  no ``priority`` column: ``ERL_RULE_PRECEDENCE`` is a constant and
  most-specific always wins. An operator who could reorder these could
  put ``site_default`` above ``switch_port`` and send every ambulance to
  the front door while the UI showed a rule for the room. One ERL per
  target per kind is enforced by UNIQUE constraints for the same reason:
  a tie would otherwise be resolved by whichever row the planner
  happened to return.

``ip_address_id`` and ``network_interface_id`` are ``ON DELETE CASCADE``
on the binding only — deleting the *binding* never touches the ERL, and
deleting an ERL drops its bindings, which fails safe: the resolver then
degrades to the next-coarser rule instead of pointing at a location that
no longer exists.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Final

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, MACADDR, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

#: The RFC 4776 §3.4 / RFC 5139 §4 civic-address elements, as
#: ``(column, catype, pidf_tag, description)``.
#:
#: ONE list, three consumers: the column set below, the API schema, and
#: (Phase 2) the PIDF-LO ``<ca:civicAddress>`` renderer and the DHCP
#: option-99 encoder, which is a TLV stream keyed by exactly these CAtype
#: numbers. Keeping the numbers beside the columns is the point — option
#: 99 cannot be written from the column names alone, and a second copy of
#: this mapping is how #878's two renderers came to disagree.
#:
#: ``country`` has no CAtype: RFC 4776 carries it as its own fixed-length
#: field ahead of the TLVs, and PIDF-LO as its own element.
CIVIC_ELEMENTS: Final[tuple[tuple[str, int | None, str, str], ...]] = (
    ("country", None, "country", "ISO 3166-1 alpha-2 country code"),
    ("a1", 1, "A1", "National subdivision (state, province, region)"),
    ("a2", 2, "A2", "County, parish, gun, district"),
    ("a3", 3, "A3", "City, township, shi"),
    ("a4", 4, "A4", "City division, borough, city district, ward"),
    ("a5", 5, "A5", "Neighbourhood, block"),
    ("a6", 6, "A6", "Street name (legacy; prefer RD)"),
    ("prd", 16, "PRD", "Leading street direction (N, W, SW)"),
    ("pod", 17, "POD", "Trailing street suffix (SW)"),
    ("sts", 18, "STS", "Street suffix or type (Avenue, Street)"),
    ("hno", 19, "HNO", "House number, numeric part only"),
    ("hns", 20, "HNS", "House number suffix (A, 1/2)"),
    ("lmk", 21, "LMK", "Landmark or vanity address"),
    ("loc", 22, "LOC", "Additional location information"),
    ("nam", 23, "NAM", "Name of the occupant, business or public place"),
    ("pc", 24, "PC", "Postal/zip code"),
    ("bld", 25, "BLD", "Building (structure)"),
    ("unit", 26, "UNIT", "Unit (apartment, suite)"),
    ("flr", 27, "FLR", "Floor"),
    ("room", 28, "ROOM", "Room"),
    ("plc", 29, "PLC", "Place type (office, residence, classroom)"),
    ("pcn", 30, "PCN", "Postal community name"),
    ("pobox", 31, "POBOX", "Post office box"),
    ("addcode", 32, "ADDCODE", "Additional code"),
    ("seat", 33, "SEAT", "Seat, desk, cubicle, workstation"),
    ("rd", 34, "RD", "Primary road or street name"),
    ("rdsec", 35, "RDSEC", "Road section"),
    ("rdbr", 36, "RDBR", "Road branch"),
    ("rdsubbr", 37, "RDSUBBR", "Road sub-branch"),
    ("prm", 38, "PRM", "Road pre-modifier (Old)"),
    ("pom", 39, "POM", "Road post-modifier (Extended)"),
)

#: Just the column names, in declaration order.
CIVIC_COLUMNS: Final[tuple[str, ...]] = tuple(c for c, _n, _t, _d in CIVIC_ELEMENTS)

#: The elements that make an address *dispatchable* beyond the street
#: door — RAY BAUM'S "room number, floor number, or similar". An ERL
#: carrying none of these is a street address, which is what the
#: ``e911_erl_not_dispatchable`` conformity check exists to find.
DISPATCHABLE_DETAIL_COLUMNS: Final[tuple[str, ...]] = (
    "bld",
    "flr",
    "unit",
    "room",
    "seat",
    "loc",
)

#: Binding rule kinds, MOST SPECIFIC FIRST. This tuple *is* the
#: precedence — see the module docstring for why it is not a column.
#:
#: **This deviates from the ordering in #972, deliberately.** The issue
#: lists the manual pin at position 5, below ``subnet`` and ``vlan``. That
#: contradicts its own "most specific wins" principle and, worse, makes
#: the pin DEAD CODE: every device carrying a pin is also on some subnet,
#: so a subnet rule would win every time and a pin could never fire. The
#: pin exists precisely for the phone on an unmonitored port — if it
#: cannot beat the floor-level rule it has no purpose. It stays below
#: ``switch_port`` because a live port observation is measured truth where
#: a pin is an operator's standing assertion.
#:
#: ``mac`` above ``ip``: a MAC follows the handset, an IP can be handed to
#: a different device by the next lease.
#:
#: ``wireless_ap`` keeps position 2 even though nothing populates it yet —
#: the UniFi and Meraki mirrors do not carry the client→AP association, so
#: the rule has no data until that lands (#972 Deferred). Leaving the slot
#: means adding the data later is a reconciler change, not a renumbering
#: of everything below it.
ERL_RULE_PRECEDENCE: Final[tuple[str, ...]] = (
    "switch_port",
    "wireless_ap",
    "mac",
    "ip",
    "subnet",
    "vlan",
    "site_default",
)

#: Rule kind → the one column that must be non-NULL for it.
ERL_RULE_TARGET_COLUMN: Final[dict[str, str]] = {
    "switch_port": "network_interface_id",
    "wireless_ap": "bssid",
    "subnet": "subnet_id",
    "vlan": "vlan_ref_id",
    "mac": "mac_address",
    "ip": "ip_address_id",
    "site_default": "site_id",
}

#: How a resolution was reached, worst to best. ``degraded`` means the
#: resolver REFUSED a more precise answer because its evidence was stale
#: and fell back to a coarser rule — see ``services/e911/resolver.py``.
ERL_CONFIDENCE_LEVELS: Final[tuple[str, ...]] = ("none", "degraded", "observed")


class EmergencyResponseLocation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One dispatchable location — the NENA "ERL"."""

    __tablename__ = "emergency_response_location"
    __table_args__ = (
        UniqueConstraint("name", name="uq_erl_name"),
        CheckConstraint(
            "validation_state IN ('unvalidated', 'validated', 'rejected')",
            name="ck_erl_validation_state",
        ),
        # Latitude/longitude are meaningful only together. A half-point is
        # not a coarse location, it is a wrong one.
        CheckConstraint(
            "num_nonnulls(latitude, longitude) IN (0, 2)",
            name="ck_erl_point_is_complete",
        ),
        Index("ix_erl_site_id", "site_id"),
    )

    #: Operator-facing label, e.g. "Bldg A — Floor 3 East". Unique so a
    #: CSV re-import updates rather than duplicates.
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    #: SET NULL, not CASCADE: the ERL carries its own address, so it stays
    #: a valid dispatchable location after the Site row goes. Deleting a
    #: site must not delete the places inside it.
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("site.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ── RFC 5139 civic address ────────────────────────────────────────
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    a1: Mapped[str | None] = mapped_column(String(255), nullable=True)
    a2: Mapped[str | None] = mapped_column(String(255), nullable=True)
    a3: Mapped[str | None] = mapped_column(String(255), nullable=True)
    a4: Mapped[str | None] = mapped_column(String(255), nullable=True)
    a5: Mapped[str | None] = mapped_column(String(255), nullable=True)
    a6: Mapped[str | None] = mapped_column(String(255), nullable=True)
    prd: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pod: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sts: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hno: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hns: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lmk: Mapped[str | None] = mapped_column(String(255), nullable=True)
    loc: Mapped[str | None] = mapped_column(String(255), nullable=True)
    nam: Mapped[str | None] = mapped_column(String(255), nullable=True)
    pc: Mapped[str | None] = mapped_column(String(32), nullable=True)
    bld: Mapped[str | None] = mapped_column(String(255), nullable=True)
    unit: Mapped[str | None] = mapped_column(String(64), nullable=True)
    flr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    room: Mapped[str | None] = mapped_column(String(64), nullable=True)
    plc: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pcn: Mapped[str | None] = mapped_column(String(255), nullable=True)
    pobox: Mapped[str | None] = mapped_column(String(64), nullable=True)
    addcode: Mapped[str | None] = mapped_column(String(64), nullable=True)
    seat: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rd: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rdsec: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rdbr: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rdsubbr: Mapped[str | None] = mapped_column(String(255), nullable=True)
    prm: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pom: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # ── Optional geodetic point (RFC 6225 / PIDF-LO <gml:Point>) ──────
    #: Numeric, not Float: a coordinate is a decimal quantity an operator
    #: typed from a survey or a map, and binary float rounding would make
    #: the value read back differently from the one they entered.
    latitude: Mapped[Decimal | None] = mapped_column(Numeric(9, 6), nullable=True)
    longitude: Mapped[Decimal | None] = mapped_column(Numeric(9, 6), nullable=True)
    altitude: Mapped[Decimal | None] = mapped_column(Numeric(9, 2), nullable=True)
    altitude_unit: Mapped[str | None] = mapped_column(String(8), nullable=True)

    #: Emergency Location Identification Numbers — the DIDs a PSAP sees
    #: as caller-ID and can call back. A JSONB array rather than a table
    #: because Phase 1 neither allocates nor tracks per-ELIN call state;
    #: a real ELIN pool (which ELIN is lent to which call right now) is a
    #: 911-provider function and explicitly out of scope.
    elins: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )

    #: Address validation is the **provider's** verdict (RedSky, Intrado
    #: and Bandwidth all expose a validation call against the MSAG / NG911
    #: LVF). We store what they said and never assert it ourselves —
    #: marking an address valid on our own say-so is the one thing that
    #: would make this feature actively dangerous.
    validation_state: Mapped[str] = mapped_column(
        String(16), nullable=False, default="unvalidated", server_default="unvalidated"
    )
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    validation_source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    validation_detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")


class ERLBinding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One network identity → one ERL, at a fixed precedence level."""

    __tablename__ = "erl_binding"
    __table_args__ = (
        CheckConstraint(
            "rule_kind IN ('switch_port', 'wireless_ap', 'subnet', 'vlan', "
            "'mac', 'ip', 'site_default')",
            name="ck_erl_binding_rule_kind",
        ),
        # Exactly one target, and it must be the one this rule kind names.
        # The num_nonnulls half alone would let a `subnet` rule carry a
        # `mac_address`, which the resolver would never look at — a rule
        # that silently matches nothing is worse than a refused one.
        CheckConstraint(
            "num_nonnulls(network_interface_id, bssid, subnet_id, vlan_ref_id, "
            "mac_address, ip_address_id, site_id) = 1",
            name="ck_erl_binding_one_target",
        ),
        CheckConstraint(
            "(rule_kind = 'switch_port') = (network_interface_id IS NOT NULL) AND "
            "(rule_kind = 'wireless_ap') = (bssid IS NOT NULL) AND "
            "(rule_kind = 'subnet') = (subnet_id IS NOT NULL) AND "
            "(rule_kind = 'vlan') = (vlan_ref_id IS NOT NULL) AND "
            "(rule_kind = 'mac') = (mac_address IS NOT NULL) AND "
            "(rule_kind = 'ip') = (ip_address_id IS NOT NULL) AND "
            "(rule_kind = 'site_default') = (site_id IS NOT NULL)",
            name="ck_erl_binding_target_matches_kind",
        ),
        # One ERL per target per kind. A tie would otherwise be broken by
        # whichever row the planner returned first, which is not a
        # decision anybody made.
        UniqueConstraint("network_interface_id", name="uq_erl_binding_interface"),
        UniqueConstraint("bssid", name="uq_erl_binding_bssid"),
        UniqueConstraint("subnet_id", name="uq_erl_binding_subnet"),
        UniqueConstraint("vlan_ref_id", name="uq_erl_binding_vlan"),
        UniqueConstraint("mac_address", name="uq_erl_binding_mac"),
        UniqueConstraint("ip_address_id", name="uq_erl_binding_ip"),
        UniqueConstraint("site_id", name="uq_erl_binding_site"),
        Index("ix_erl_binding_erl_id", "erl_id"),
        Index("ix_erl_binding_rule_kind", "rule_kind"),
    )

    erl_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("emergency_response_location.id", ondelete="CASCADE"),
        nullable=False,
    )
    rule_kind: Mapped[str] = mapped_column(String(16), nullable=False)

    network_interface_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("network_interface.id", ondelete="CASCADE"),
        nullable=True,
    )
    #: Not an FK: no table mirrors wireless APs yet (#972 Deferred), so
    #: this is the BSSID as the controller reports it. Stored as text
    #: rather than MACADDR because some controllers report a BSSID with a
    #: radio/SSID suffix and refusing those would make the rule unusable
    #: the day the mirror lands.
    bssid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    subnet_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("subnet.id", ondelete="CASCADE"),
        nullable=True,
    )
    vlan_ref_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vlan.id", ondelete="CASCADE"),
        nullable=True,
    )
    mac_address: Mapped[str | None] = mapped_column(MACADDR, nullable=True)
    ip_address_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ip_address.id", ondelete="CASCADE"),
        nullable=True,
    )
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("site.id", ondelete="CASCADE"),
        nullable=True,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")


class E911ResolutionLog(UUIDPrimaryKeyMixin, Base):
    """Who asked about which identity, and what they were told.

    A location lookup tells the caller which desk a named person sits at,
    so the trail is not optional — and it is kept separately from
    ``audit_log`` because the interesting query here is "every lookup of
    THIS identity", which wants its own index rather than a JSONB scan of
    a general-purpose table.

    Deliberately records the identity asked about and the ERL returned,
    never a subject name: the ERL's own ``nam`` element is as close to a
    person as this feature gets, and duplicating it per lookup would turn
    an access log into a movement history.

    Every lookup that returns a location has a row of its own
    (``suppressed_count`` NULL). Past the per-minute budget a HELD lookup is
    refused (#3633) and writes nothing. The ``caller_key`` / ``window_start``
    / ``suppressed_count`` columns hold counter rows written by development
    builds before that (#3514; no release shipped them): "N lookups not
    individually logged". They are kept so those rows stay readable until
    the retention prune drops them.
    """

    __tablename__ = "e911_resolution_log"
    __table_args__ = (
        Index("ix_e911_res_log_queried_at", "queried_at"),
        Index("ix_e911_res_log_identity", "identity_kind", "identity_value"),
        Index("ix_e911_res_log_actor", "actor_kind", "actor_id"),
        # One counter row per caller per minute window (#3514); the upsert's
        # ON CONFLICT target. Partial, so individual lookups stay out of it.
        Index(
            "uq_e911_res_log_suppressed_window",
            "caller_key",
            "window_start",
            unique=True,
            postgresql_where=text("caller_key IS NOT NULL"),
        ),
        CheckConstraint(
            "(caller_key IS NULL AND window_start IS NULL AND suppressed_count IS NULL)"
            " OR (caller_key IS NOT NULL AND window_start IS NOT NULL"
            " AND suppressed_count >= 1)",
            name="ck_e911_res_log_suppressed_shape",
        ),
    )

    #: No ``index=True`` here: ``ix_e911_res_log_queried_at`` in
    #: ``__table_args__`` already covers this column, and declaring both
    #: makes Postgres build two identical indexes.
    queried_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    #: ``ip`` / ``mac`` / ``chassis_port``
    identity_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    identity_value: Mapped[str] = mapped_column(String(255), nullable=False)

    #: ``user`` / ``api_token`` / ``device_self``
    actor_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(INET, nullable=True)

    erl_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("emergency_response_location.id", ondelete="SET NULL"),
        nullable=True,
    )
    rule_matched: Mapped[str | None] = mapped_column(String(16), nullable=True)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    degraded_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Age in seconds of the evidence the answer rests on, so an
    #: after-action review can tell a fresh answer from a lucky one.
    evidence_age_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ── Counter rows (#3514, no longer written since #3633) ──────────
    # Builds of main between #3514 and #3633 COUNTED HELD lookups past the
    # per-caller budget in one row per caller per minute window instead of
    # logging each; on such a row the columns above describe the LAST lookup
    # counted, and these three are set. Nothing writes them now: past the
    # budget a lookup is refused. All three are NULL on every row written
    # since, and the retention prune ages the old ones out.
    #: The budget's caller key: the API token id, else the user id, else the
    #: source address.
    caller_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Start of the minute the counted lookups fell in.
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: How many lookups in that window were not individually logged.
    suppressed_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
