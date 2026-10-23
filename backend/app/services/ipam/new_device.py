"""New-device (arpwatch-style) detection — classification + ingest helpers.

Issue #459. The platform already logs every observed ``(ip, mac)`` pair into
``ip_mac_history`` (issue #369). This module adds the *classification* layer on
top of that store: deciding whether a freshly-observed MAC is something the
operator already trusts (``known``), has dismissed (``acknowledged``), or has
never seen before (``new``) — the last being what raises a ``new_mac_seen``
alert and a ``device.first_seen`` event.

Design notes:

* **One store, not two.** We extend ``ip_mac_history`` rather than build a
  parallel sighting table — see ``docs/features/IPAM.md`` §8.x. Every ingestion
  path (DHCP lease, SNMP ARP, ping/ARP sweep, L2 sniff) routes through
  :func:`app.services.ipam.discovery.record_mac_observation`, which calls
  :func:`classify_mac` on first sight.
* **Allowlist is MAC-keyed, sightings are (ip, mac)-keyed.** The allowlist
  (``mac_allowlist``) survives the cascade-delete of the IP a MAC was first
  seen on, and silences a trusted MAC wherever it appears. Acknowledgement, by
  contrast, dismisses one specific ``(ip, mac)`` sighting.
* **Randomised MACs are flagged, not hidden.** Modern phones rotate
  locally-administered MACs per network; :func:`is_locally_administered`
  stamps ``ip_mac_history.is_randomized`` so the default alert rule can skip
  them and avoid a reconnection storm, while they stay visible in the review
  queue.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import and_, delete, func, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.ipam import IPAddress, IpMacHistory, MACAllowlist, Subnet
from app.services.oui import _prefix_from_mac, normalize_mac_key

logger = structlog.get_logger(__name__)

# IPAddress.status values that mean "an operator deliberately associated this
# MAC with this IP" — i.e. part of the known fleet, never a surprise.
_KNOWN_FLEET_STATUSES: frozenset[str] = frozenset({"allocated", "reserved", "static_dhcp"})

# Classification values stored on ip_mac_history.classification.
CLASSIFICATION_NEW = "new"
CLASSIFICATION_ACKNOWLEDGED = "acknowledged"
CLASSIFICATION_KNOWN = "known"

# Well-known virtualisation / container OUIs seeded (disabled by default, the
# operator enables what applies) so a hypervisor or Docker host spinning up VMs
# doesn't read as a fleet of rogue devices. Lower-case, no separators.
BUILTIN_VIRT_OUIS: tuple[tuple[str, str], ...] = (
    ("005056", "VMware"),
    ("000c29", "VMware"),
    ("000569", "VMware"),
    ("001c14", "VMware"),
    ("00155d", "Microsoft Hyper-V"),
    ("00163e", "Xen"),
    ("0a0027", "VirtualBox"),
    ("080027", "VirtualBox"),
    ("525400", "QEMU/KVM"),
    ("0242ac", "Docker"),
)


@dataclass(slots=True)
class MacObservationResult:
    """Outcome of recording one MAC sighting."""

    mac_address: str
    classification: str
    is_new_row: bool  # True only on the first-ever sighting of this (ip, mac)
    is_randomized: bool

    @property
    def is_first_seen_new(self) -> bool:
        """A genuinely new device worth a ``device.first_seen`` event/alert."""
        return self.is_new_row and self.classification == CLASSIFICATION_NEW


def is_locally_administered(mac: str | None) -> bool:
    """True if the MAC's locally-administered (privacy-randomised) bit is set.

    The second-least-significant bit of the first octet (``0x02``) marks a
    locally-administered address — iOS / Android per-network randomised MACs,
    and most software-assigned virtual NIC MACs. Returns False for an
    unparseable MAC (treated as a real, globally-unique address).
    """
    key = normalize_mac_key(mac)
    if key is None:
        return False
    try:
        first_octet = int(key[:2], 16)
    except ValueError:
        return False
    return bool(first_octet & 0x02)


def oui_prefix_of(mac: str | None) -> str | None:
    """Return the 6-char lowercase OUI prefix of a MAC (or None)."""
    return _prefix_from_mac(mac)


async def classify_mac(
    db: AsyncSession, mac_address: str | None, *, space_id: uuid.UUID | None = None
) -> str:
    """Classify a MAC as ``known`` or ``new`` at observation time.

    ``acknowledged`` is never returned here — it is only ever set by an explicit
    operator dismissal of a specific ``(ip, mac)`` sighting. The two ``known``
    paths are:

    * the MAC (or its OUI prefix) is in ``mac_allowlist`` — operator trusts it
      everywhere;
    * the MAC already sits on an operator-allocated IP (``allocated`` /
      ``reserved`` / ``static_dhcp``) — it is part of the known fleet.
      That fleet is per IP space when ``space_id`` is given (#2577): spaces
      are independent networks, so a MAC allocated in one must not mask a
      first sighting in another. The allowlist stays platform-wide by
      design — it is the operator's "trust this MAC everywhere".

    Everything else is ``new``.
    """
    if not mac_address:
        return CLASSIFICATION_NEW

    prefix = oui_prefix_of(mac_address)
    allow_conds = [MACAllowlist.mac_address == mac_address]
    if prefix is not None:
        allow_conds.append(MACAllowlist.oui_prefix == prefix)
    allow_hit = (
        await db.execute(select(MACAllowlist.id).where(or_(*allow_conds)).limit(1))
    ).first()
    if allow_hit is not None:
        return CLASSIFICATION_KNOWN

    fleet_q = select(IPAddress.id).where(
        IPAddress.mac_address == mac_address,
        IPAddress.status.in_(_KNOWN_FLEET_STATUSES),
    )
    if space_id is not None:
        fleet_q = fleet_q.join(Subnet, Subnet.id == IPAddress.subnet_id).where(
            Subnet.space_id == space_id
        )
    fleet_hit = (await db.execute(fleet_q.limit(1))).first()
    if fleet_hit is not None:
        return CLASSIFICATION_KNOWN

    return CLASSIFICATION_NEW


# ── Counts (shared by the REST summary endpoint + the MCP count tool) ───────


async def new_device_counts(db: AsyncSession) -> dict[str, int]:
    """Return new-device counts by bucket in a single pass.

    Canonical keys: ``new`` (non-randomised) / ``new_randomized`` /
    ``new_last_24h`` / ``acknowledged`` / ``known`` / ``allowlist``. One
    aggregate query over ``ip_mac_history`` (FILTER) + one over the allowlist,
    so the dashboard summary and the Copilot count tool can't drift.
    """
    day_ago = datetime.now(UTC) - timedelta(hours=24)
    not_random = IpMacHistory.is_randomized.is_(False)
    is_new = IpMacHistory.classification == CLASSIFICATION_NEW
    row = (
        await db.execute(
            select(
                func.count().filter(and_(is_new, not_random)).label("new"),
                func.count()
                .filter(and_(is_new, IpMacHistory.is_randomized.is_(True)))
                .label("new_randomized"),
                func.count()
                .filter(and_(is_new, not_random, IpMacHistory.first_seen >= day_ago))
                .label("new_last_24h"),
                func.count()
                .filter(IpMacHistory.classification == CLASSIFICATION_ACKNOWLEDGED)
                .label("acknowledged"),
                func.count()
                .filter(IpMacHistory.classification == CLASSIFICATION_KNOWN)
                .label("known"),
            )
        )
    ).one()
    allowlist = (await db.execute(select(func.count()).select_from(MACAllowlist))).scalar_one()
    return {
        "new": int(row.new),
        "new_randomized": int(row.new_randomized),
        "new_last_24h": int(row.new_last_24h),
        "acknowledged": int(row.acknowledged),
        "known": int(row.known),
        "allowlist": int(allowlist),
    }


# ── Operator actions (shared by the REST router + MCP propose_* tools) ──────


async def baseline_import(db: AsyncSession) -> int:
    """Mark every currently-observed MAC as ``known`` (learning-mode baseline).

    Run once when arming the feature so day-one isn't a wall of alerts for the
    fleet that was already on the network. Flips every ``ip_mac_history`` row not
    already ``known`` → ``known``. Returns the number of rows reclassified. Does
    NOT commit — the caller owns the transaction (so it can audit in the same
    unit of work).
    """
    result = await db.execute(
        update(IpMacHistory)
        .where(IpMacHistory.classification != CLASSIFICATION_KNOWN)
        .values(classification=CLASSIFICATION_KNOWN)
    )
    return int(result.rowcount or 0)


async def acknowledge_sighting(
    db: AsyncSession, sighting_id: uuid.UUID, user: User | None
) -> IpMacHistory | None:
    """Dismiss one ``(ip, mac)`` sighting → ``acknowledged``. Returns the row, or
    None if it doesn't exist. Idempotent. Does NOT commit."""
    row = await db.get(IpMacHistory, sighting_id)
    if row is None:
        return None
    row.classification = CLASSIFICATION_ACKNOWLEDGED
    row.acknowledged_at = datetime.now(UTC)
    row.acknowledged_by_user_id = user.id if user else None
    return row


def normalize_oui_prefix(raw: str | None) -> str | None:
    """Return a 6-char lowercase hex OUI prefix from a partial MAC / prefix.

    Accepts ``00:50:56``, ``005056``, ``00-50-56``, ``0050.56xx`` → ``005056``.
    Returns None when fewer than 6 hex chars are present.
    """
    if not raw:
        return None
    cleaned = "".join(c for c in raw.lower() if c in "0123456789abcdef")
    return cleaned[:6] if len(cleaned) >= 6 else None


async def _reclassify_for_allowlist(
    db: AsyncSession, *, mac_address: str | None, oui_prefix: str | None
) -> int:
    """Reclassify existing non-``known`` sightings that the new allowlist entry
    now covers → ``known`` (so the review queue clears + open alerts resolve).
    Matches by exact MAC and/or OUI prefix. Returns the count touched.

    The OUI match formats the MACADDR column to its canonical lowercase text
    (``08:00:2b:…``), strips the colons, and compares the first 6 chars to the
    stored prefix — robust across however the MAC was originally written.
    """
    if not mac_address and not oui_prefix:
        return 0
    clauses = []
    params: dict[str, str] = {}
    if mac_address:
        clauses.append("mac_address = CAST(:mac AS macaddr)")
        params["mac"] = mac_address
    if oui_prefix:
        clauses.append("left(replace(mac_address::text, ':', ''), 6) = :prefix")
        params["prefix"] = oui_prefix
    result = await db.execute(
        text(
            "UPDATE ip_mac_history SET classification = 'known' "
            "WHERE classification <> 'known' AND (" + " OR ".join(clauses) + ")"
        ),
        params,
    )
    return int(result.rowcount or 0)


async def add_allowlist_entry(
    db: AsyncSession,
    *,
    mac_address: str | None = None,
    oui_prefix: str | None = None,
    note: str = "",
    user: User | None = None,
    is_builtin: bool = False,
) -> tuple[MACAllowlist, int]:
    """Create a ``mac_allowlist`` row and reclassify the sightings it now
    covers → ``known``. Returns ``(row, reclassified_count)``. Does NOT commit.

    Normalises ``oui_prefix`` to 6 lowercase hex chars. Raises ``ValueError`` if
    neither key is usable (mirrors the table's CHECK constraint)."""
    norm_prefix = normalize_oui_prefix(oui_prefix)
    if not mac_address and not norm_prefix:
        raise ValueError("an allowlist entry needs a MAC address or an OUI prefix")
    row = MACAllowlist(
        mac_address=mac_address,
        oui_prefix=norm_prefix,
        note=note,
        is_builtin=is_builtin,
        created_by_user_id=user.id if user else None,
    )
    db.add(row)
    reclassified = await _reclassify_for_allowlist(
        db, mac_address=mac_address, oui_prefix=norm_prefix
    )
    return row, reclassified


async def remove_allowlist_entry(db: AsyncSession, allowlist_id: uuid.UUID) -> bool:
    """Delete a ``mac_allowlist`` row. Returns False if it didn't exist. Does NOT
    commit. Existing ``known`` sightings keep their classification — removing
    trust doesn't retroactively re-flag; the next fresh sighting re-evaluates."""
    result = await db.execute(delete(MACAllowlist).where(MACAllowlist.id == allowlist_id))
    return bool(result.rowcount)
