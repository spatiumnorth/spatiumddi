"""Identity → dispatchable location (#972 Phase 1).

Given a phone's IP, MAC, or LLDP chassis+port, answer "which room is this
device in, right now?" by joining data SpatiumDDI already collects for
IPAM, then applying the operator's ERL bindings in a fixed precedence.

**The load-bearing safety property: a stale precise answer is worse than
a fresh coarse one.**

A phone unplugged from port 3/0/12 and re-patched on another floor stays
in the switch's FDB on the old port until the entry ages out, and stays in
*our copy* of the FDB until the next SNMP poll. Sending an ambulance to
the old floor is the failure this whole feature exists to prevent. So a
port-level answer whose evidence is older than the freshness window is
**refused**, not returned: the resolver falls back to the next-coarser
rule and reports ``confidence="degraded"`` with the reason. Every answer
carries ``observed_at`` and ``rule_matched``; there is deliberately no
code path that returns a bare address.

The freshness window defaults to the polling device's own
``poll_interval_seconds`` × 2 — one missed poll is tolerated, two is not —
because a fixed global number is either too tight for a 15-minute poller
or uselessly loose for a 60-second one.

Two independent staleness signals, and they are not redundant:

* **Age.** The evidence is older than the window.
* **Disagreement.** An LLDP neighbour on the same port reports a
  different chassis-id than the MAC the FDB puts there. LLDP is the
  device's own announcement, so when the two disagree the FDB row is the
  one to distrust — and this fires *immediately*, where age has to wait
  out the window. A phone swapped for a different phone on the same port
  is exactly the case age cannot catch quickly.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import cast, func, or_, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.asyncio import AsyncSession

# Imported rather than re-implemented: this would otherwise be the sixth MAC
# cleaner in the tree, and #878 is the standing lesson about two copies of one
# rule drifting apart. It lives in the service layer precisely because this
# module is imported by the DHCP config bundle, and ``app.core`` has an empty
# package ``__init__`` — which is what keeps it out of a cycle. See
# ``app/core/mac.py`` for the two earlier homes that were both wrong.
from app.core.mac import canonicalize_mac
from app.models.dhcp import DHCPLease, DHCPScope
from app.models.e911 import (
    ERL_RULE_PRECEDENCE,
    EmergencyResponseLocation,
    ERLBinding,
)
from app.models.ipam import IPAddress, IpMacHistory, Subnet
from app.models.network import (
    NetworkDevice,
    NetworkFdbEntry,
    NetworkInterface,
    NetworkNeighbour,
)

#: One missed poll is tolerated; two is not.
FRESHNESS_POLL_MULTIPLIER = 2

#: Used when the evidence came from a device with no poll interval
#: recorded, or from a DHCP lease (which has no poller behind it).
DEFAULT_FRESHNESS_SECONDS = 600

#: LLDP chassis-id subtype 4 is "MAC address" (IEEE 802.1AB-2005 §9.5.2.2).
#: Only that subtype can be compared against a MAC we hold; a
#: subtype-7 (locally assigned) chassis-id is an opaque string.
LLDP_CHASSIS_SUBTYPE_MAC = 4


def _valid_ip(raw: str | None) -> str | None:
    """Return ``raw`` only if Postgres will accept it as an INET.

    Unvalidated text reaching an INET comparison raises 22P02, and the
    blast radius is not one request: via the ``find_e911_location`` copilot
    tool the aborted transaction takes out every later tool call and
    message write in the chat turn. Refusing here keeps a typo a "no
    location" answer, which is the honest one.
    """
    if not raw:
        return None
    try:
        ipaddress.ip_address(raw.strip())
    except ValueError:
        return None
    return raw.strip()


@dataclass(frozen=True)
class Evidence:
    """One observation the answer rests on."""

    #: ``lldp`` / ``fdb`` / ``dhcp_lease`` / ``ip_mac_history`` / ``config``
    kind: str
    observed_at: datetime | None
    age_seconds: int | None
    #: Window this observation was judged against, for the audit trail.
    window_seconds: int | None
    stale: bool
    detail: str


@dataclass(frozen=True)
class Resolution:
    identity_kind: str
    identity_value: str
    erl: EmergencyResponseLocation | None = None
    rule_matched: str | None = None
    confidence: str = "none"
    degraded_reason: str | None = None
    observed_at: datetime | None = None
    evidence_age_seconds: int | None = None
    evidence: list[Evidence] = field(default_factory=list)

    @property
    def found(self) -> bool:
        return self.erl is not None


def _age_seconds(observed_at: datetime | None, now: datetime) -> int | None:
    if observed_at is None:
        return None
    seen = observed_at
    if seen.tzinfo is None:
        # Defensive: every column here is timezone-aware, but a naive
        # value subtracted from an aware one raises TypeError, and this
        # function runs on the path that answers a 911 location query.
        seen = seen.replace(tzinfo=UTC)
    return max(0, int((now - seen).total_seconds()))


async def _freshness_window(db: AsyncSession, interface_id: uuid.UUID) -> int:
    """The window for evidence from the device owning ``interface_id``."""
    interval = (
        await db.execute(
            select(NetworkDevice.poll_interval_seconds)
            .join(NetworkInterface, NetworkInterface.device_id == NetworkDevice.id)
            .where(NetworkInterface.id == interface_id)
        )
    ).scalar_one_or_none()
    if not interval or interval <= 0:
        return DEFAULT_FRESHNESS_SECONDS
    return int(interval) * FRESHNESS_POLL_MULTIPLIER


async def _mac_from_ip(
    db: AsyncSession, ip: str, now: datetime, *, subnet: Subnet | None
) -> tuple[str | None, Evidence | None]:
    """Resolve IP → MAC, preferring a live DHCP lease.

    The lease is the better source: it is the binding the DHCP server is
    currently honouring. ``IpMacHistory`` is the fallback for statically
    addressed phones, which never appear in a lease table at all.

    **Scoped to the subnet, and ambiguity fails closed.** DHCP leases are
    per-server and per-scope, so the same address legitimately exists in two
    overlapping networks — a 10.x RFC 1918 range reused behind two different
    sites is the ordinary case, not a pathological one. An unscoped "newest
    active lease for this IP" therefore attaches the caller to ANOTHER
    network's MAC, and from there to that MAC's switch port and that port's
    room: a confident, precise, completely wrong answer, which is the single
    failure mode this module exists to prevent.

    So when the subnet is known the query is constrained to scopes serving it.
    When it is not, and the address resolves to more than one distinct MAC,
    the resolver declines to guess: no MAC is returned, the port-level and
    pin rules are skipped, and the answer degrades to whatever the IP alone
    supports.
    """
    lease_q = (
        select(DHCPLease.mac_address, DHCPLease.last_seen_at)
        .where(DHCPLease.ip_address == ip, DHCPLease.state == "active")
        # A DHCPv6 lease identified by DUID alone carries no MAC to trace to
        # a switch port (#1141) — and counted here it would read as a second,
        # ambiguous MAC ("None") and make the resolver decline a good answer.
        .where(DHCPLease.mac_address.is_not(None))
        .order_by(DHCPLease.last_seen_at.desc())
    )
    if subnet is not None:
        # OUTER join, and the filter admits a lease with NO scope recorded.
        # An inner join looked right and silently discarded every lease whose
        # `scope_id` is NULL — which is legitimate and common: a lease pulled
        # from a server whose scopes SpatiumDDI does not manage has nothing to
        # point at. Dropping those would make the IP→MAC hop fail on exactly
        # the estates that adopted the DHCP mirror without the scope model,
        # and the feature would quietly stop working for them.
        #
        # Ambiguity is still refused below, so admitting the unscoped rows
        # costs no safety: two candidate MACs decline either way.
        lease_q = lease_q.outerjoin(DHCPScope, DHCPScope.id == DHCPLease.scope_id).where(
            or_(DHCPScope.subnet_id == subnet.id, DHCPLease.scope_id.is_(None))
        )

    leases = (await db.execute(lease_q.limit(10))).all()
    distinct_macs = {str(m) for m, _seen in leases}
    if len(distinct_macs) > 1:
        # Two networks, one address. Declining is the whole point.
        return None, Evidence(
            kind="dhcp_lease",
            observed_at=None,
            age_seconds=None,
            window_seconds=None,
            stale=True,
            detail=(
                f"{len(distinct_macs)} active leases for {ip} on different "
                "scopes — declining to guess which device it is"
            ),
        )
    if leases:
        mac, seen = leases[0]
        age = _age_seconds(seen, now)
        return str(mac), Evidence(
            kind="dhcp_lease",
            observed_at=seen,
            age_seconds=age,
            window_seconds=DEFAULT_FRESHNESS_SECONDS,
            # A lease that has expired out of `active` is already excluded
            # above; age here is reported, not gated, because the DHCP
            # server's own lifetime is the authority on a lease and
            # second-guessing it with our poll cadence would degrade answers
            # that are perfectly current.
            stale=False,
            detail=f"active DHCP lease for {ip}"
            + (f" in {subnet.network}" if subnet is not None else ""),
        )

    hist_q = (
        select(IpMacHistory.mac_address, IpMacHistory.last_seen)
        # ``IPAddress.address == ip``, never a cast to text: an INET compared
        # by SPELLING is the #877 failure — 2606:4700::1111 and its expanded
        # form are one host and two strings, so an IPv6 lookup would silently
        # answer "no location". It is also non-sargable, on the flagship
        # query of the feature.
        .join(IPAddress, IPAddress.id == IpMacHistory.ip_address_id)
        .where(IPAddress.address == ip)
        .order_by(IpMacHistory.last_seen.desc())
    )
    if subnet is not None:
        # Same scoping argument, and here it is unconditional: an IPAM address
        # row ALWAYS has a subnet (the column is NOT NULL), so there is no
        # legitimate unscoped case to admit.
        hist_q = hist_q.where(IPAddress.subnet_id == subnet.id)

    rows = (await db.execute(hist_q.limit(10))).all()
    hist_macs = {str(m) for m, _seen in rows}
    if len(hist_macs) > 1:
        return None, Evidence(
            kind="ip_mac_history",
            observed_at=None,
            age_seconds=None,
            window_seconds=None,
            stale=True,
            detail=(
                f"{len(hist_macs)} addresses matching {ip} in different "
                "subnets — declining to guess which device it is"
            ),
        )
    if rows:
        mac, seen = rows[0]
        age = _age_seconds(seen, now)
        # Gated, unlike the lease branch. A lease is a binding the DHCP
        # server is currently honouring; an IpMacHistory row is only the last
        # time anything was observed, and a years-old one driving a `mac` pin
        # to confidence="observed" is exactly the stale-precise-answer this
        # module exists to refuse.
        return str(mac), Evidence(
            kind="ip_mac_history",
            observed_at=seen,
            age_seconds=age,
            window_seconds=DEFAULT_FRESHNESS_SECONDS,
            stale=age is not None and age > DEFAULT_FRESHNESS_SECONDS,
            detail=f"last observed MAC for {ip}",
        )
    return None, None


async def _port_from_mac(
    db: AsyncSession, mac: str, now: datetime
) -> tuple[uuid.UUID | None, Evidence | None]:
    """Resolve MAC → switch port, preferring the device's own LLDP claim.

    LLDP beats the FDB because it is the phone announcing itself rather
    than the switch remembering a frame it forwarded — the FDB is what
    goes stale.
    """
    neighbour = (
        await db.execute(
            select(NetworkNeighbour.interface_id, NetworkNeighbour.last_seen)
            .where(
                NetworkNeighbour.interface_id.is_not(None),
                NetworkNeighbour.remote_chassis_id_subtype == LLDP_CHASSIS_SUBTYPE_MAC,
                func.lower(
                    func.replace(
                        func.replace(NetworkNeighbour.remote_chassis_id, ":", ""),
                        "-",
                        "",
                    )
                )
                == mac.replace(":", ""),
            )
            .order_by(NetworkNeighbour.last_seen.desc())
            .limit(1)
        )
    ).first()
    if neighbour is not None:
        iface_id, seen = neighbour
        assert iface_id is not None  # the WHERE requires interface_id IS NOT NULL
        window = await _freshness_window(db, iface_id)
        age = _age_seconds(seen, now)
        return iface_id, Evidence(
            kind="lldp",
            observed_at=seen,
            age_seconds=age,
            window_seconds=window,
            stale=age is not None and age > window,
            detail=f"LLDP neighbour claiming chassis-id {mac}",
        )

    # A MAC appears in the forwarding table of EVERY switch on the path to
    # it, so "most recently seen" is the wrong tie-break: on a two-tier
    # network it resolves to whichever of the access switch and the core
    # happened to be polled last, and the room-level binding then fires
    # intermittently with the evidence row naming the wrong port.
    #
    # The access port is the one with the FEWEST MACs learned on it — an
    # uplink carries every host behind it, an edge port carries one phone
    # (or a phone and the PC behind it). That is the standard way to find an
    # edge port from bridge-MIB data, and it is a property of the topology
    # rather than of polling luck. Recency is kept as the second key so a
    # genuine tie still prefers the fresher observation.
    per_interface = (
        select(
            NetworkFdbEntry.interface_id.label("iface"),
            func.count(NetworkFdbEntry.id).label("mac_count"),
        )
        .group_by(NetworkFdbEntry.interface_id)
        .subquery()
    )
    fdb = (
        await db.execute(
            select(NetworkFdbEntry.interface_id, NetworkFdbEntry.last_seen)
            .join(per_interface, per_interface.c.iface == NetworkFdbEntry.interface_id)
            .where(NetworkFdbEntry.mac_address == mac)
            .order_by(
                per_interface.c.mac_count.asc(),
                NetworkFdbEntry.last_seen.desc(),
            )
            .limit(1)
        )
    ).first()
    if fdb is None:
        return None, None
    iface_id, seen = fdb
    window = await _freshness_window(db, iface_id)
    age = _age_seconds(seen, now)
    stale = age is not None and age > window
    detail = f"switch FDB entry for {mac}"

    # Disagreement check. An LLDP neighbour on the SAME port announcing a
    # different chassis-id can mean something else is plugged in there now,
    # and that the FDB row we just matched is history — which fires
    # immediately where the age test must wait out the whole window.
    #
    # But a port legitimately carries several devices: a desk phone with a
    # PC daisy-chained behind it is the commonest wiring in exactly the
    # estates this feature serves, and the PC's MAC appears in the FDB while
    # only the phone announces LLDP. Treating that as a contradiction would
    # make a room-level answer unreachable for every such PC, permanently.
    #
    # So the signal is NEWER, not merely different: distrust the FDB row
    # only when a contradicting neighbour has been seen MORE RECENTLY than
    # it. After a swap the new device's LLDP is fresh and the old device's
    # FDB row is not, which is the case this exists for; on a daisy chain
    # both are current and neither displaces the other.
    if not stale:
        other = (
            await db.execute(
                select(NetworkNeighbour.remote_chassis_id)
                .where(
                    NetworkNeighbour.interface_id == iface_id,
                    NetworkNeighbour.remote_chassis_id_subtype == LLDP_CHASSIS_SUBTYPE_MAC,
                    NetworkNeighbour.last_seen > seen,
                    func.lower(
                        func.replace(
                            func.replace(NetworkNeighbour.remote_chassis_id, ":", ""),
                            "-",
                            "",
                        )
                    )
                    != mac.replace(":", ""),
                )
                .order_by(NetworkNeighbour.last_seen.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if other is not None:
            stale = True
            detail = (
                f"switch FDB entry for {mac}, contradicted by a MORE RECENT "
                f"LLDP neighbour on the same port announcing {other}"
            )

    return iface_id, Evidence(
        kind="fdb",
        observed_at=seen,
        age_seconds=age,
        window_seconds=window,
        stale=stale,
        detail=detail,
    )


async def _ip_row_id(db: AsyncSession, ip: str, subnet: Subnet | None) -> uuid.UUID | None:
    """The IPAM row for ``ip``, scoped to its subnet where we know it.

    ``ip_address.address`` is unique only *per subnet* — overlapping
    prefixes and VRFs are normal in IPAM, and this feature's own tests carve
    a /28 out of a /24 — so an unscoped ``scalar_one_or_none()`` raises
    MultipleResultsFound and 500s the whole lookup without even writing the
    audit row. Scoped first; ordered-and-limited as the fallback, because
    answering from one of several candidate rows beats answering nothing.
    """
    stmt = select(IPAddress.id).where(IPAddress.address == ip)
    if subnet is not None:
        scoped = (
            await db.execute(stmt.where(IPAddress.subnet_id == subnet.id).limit(1))
        ).scalar_one_or_none()
        if scoped is not None:
            return scoped
    return (await db.execute(stmt.order_by(IPAddress.id).limit(1))).scalar_one_or_none()


async def _subnet_for_ip(db: AsyncSession, ip: str) -> Subnet | None:
    """The most specific subnet containing ``ip``.

    A SQL containment test rather than the ``_find_subnet_for_ip`` helper
    the reconcilers carry: those already hold every subnet in memory for a
    batch sweep, where this resolves one address on a latency-sensitive
    path and must not read the whole table to do it.
    """
    return (
        await db.execute(
            select(Subnet)
            .where(Subnet.network.op(">>=")(cast(ip, INET)))
            .order_by(func.masklen(Subnet.network).desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def _binding(db: AsyncSession, rule_kind: str, **target: object) -> ERLBinding | None:
    stmt = select(ERLBinding).where(
        ERLBinding.rule_kind == rule_kind,
        ERLBinding.is_active.is_(True),
    )
    for column, value in target.items():
        stmt = stmt.where(getattr(ERLBinding, column) == value)
    return (await db.execute(stmt.limit(1))).scalar_one_or_none()


async def _erl(db: AsyncSession, erl_id: uuid.UUID) -> EmergencyResponseLocation | None:
    return (
        await db.execute(
            select(EmergencyResponseLocation).where(
                EmergencyResponseLocation.id == erl_id,
                EmergencyResponseLocation.is_active.is_(True),
            )
        )
    ).scalar_one_or_none()


def _declined_reason(rule_kind: str, ev: Evidence) -> str:
    """Why a precise rule was refused, in words an operator can act on.

    Names the age and the window when the refusal was an age verdict, and
    falls back to the evidence's own detail for the disagreement case —
    where the age is fine and the reason is that something else is plugged
    into the port.
    """
    aged_out = (
        ev.age_seconds is not None
        and ev.window_seconds is not None
        and ev.age_seconds > ev.window_seconds
    )
    if aged_out:
        return (
            f"declined the {rule_kind} binding: {ev.detail} is {ev.age_seconds}s old "
            f"against a {ev.window_seconds}s freshness window"
        )
    return f"declined the {rule_kind} binding: {ev.detail}"


async def resolve_location(
    db: AsyncSession,
    *,
    ip: str | None = None,
    mac: str | None = None,
    chassis_id: str | None = None,
    port_id: str | None = None,
    now: datetime | None = None,
) -> Resolution:
    """Resolve a network identity to a dispatchable location.

    Exactly one identity is expected; when several are given they are all
    used as facts, which only ever makes the answer more specific.
    """
    now = now or datetime.now(UTC)
    evidence: list[Evidence] = []

    # A malformed IP is dropped rather than passed to an INET comparison
    # (see _valid_ip). The identity below still records what was ASKED, so
    # the audit row says "someone looked up 10.20.3.4x" rather than losing
    # the query because it was a typo.
    asked_ip = ip
    ip = _valid_ip(ip)

    identity_kind, identity_value = "unknown", ""
    if chassis_id and port_id:
        identity_kind, identity_value = "chassis_port", f"{chassis_id}/{port_id}"
    elif chassis_id:
        # Permitted on its own, and it used to log as ``unknown`` / "" —
        # which silently lost the one thing the trail exists to record.
        identity_kind, identity_value = "chassis_id", chassis_id
    elif mac:
        identity_kind, identity_value = "mac", mac
    elif asked_ip:
        identity_kind, identity_value = "ip", asked_ip

    # ── Facts ────────────────────────────────────────────────────────
    #
    # The subnet is resolved FIRST, before any IP→MAC inference, because that
    # inference has to be scoped to it: leases are per-scope and the same
    # address legitimately exists in two overlapping networks. See
    # _mac_from_ip.
    subnet = await _subnet_for_ip(db, ip) if ip else None

    mac_canon: str | None = None
    for candidate in (mac, chassis_id):
        if not candidate:
            continue
        try:
            mac_canon = canonicalize_mac(candidate)
            break
        except ValueError:
            # A chassis-id that is not a MAC (LLDP subtype 7, "locally
            # assigned") is legitimate, not an error — it just cannot be
            # joined against anything we hold.
            continue

    # True when the MAC was INFERRED from the IP and that inference is
    # stale. The rules that hang off the MAC — the switch port it is learned
    # on, and a `mac` pin — are then resting on a mapping that may belong to
    # a different device, while `subnet` / `vlan` / `site_default` derive
    # from the caller's IP directly and are unaffected.
    mac_inference_stale = False
    mac_stale_age: int | None = None
    if mac_canon is None and ip:
        mac_canon, mac_evidence = await _mac_from_ip(db, ip, now, subnet=subnet)
        if mac_evidence:
            evidence.append(mac_evidence)
            mac_inference_stale = mac_evidence.stale
            mac_stale_age = mac_evidence.age_seconds

    interface_id: uuid.UUID | None = None
    port_evidence: Evidence | None = None
    if chassis_id and port_id:
        # An explicit chassis+port identity names the port directly — this
        # is how a PBX that already knows the wiremap asks.
        #
        # A MAC-shaped chassis-id is compared CANONICALLY, because the
        # endpoint documents that any common separator is accepted and a raw
        # lowercase compare silently breaks that promise: `aabb.cc11.2233`
        # would never match the same address stored as `aa:bb:cc:11:22:33`.
        # An opaque subtype-7 identifier has no canonical form and is
        # compared as given.
        if mac_canon is not None:
            chassis_match = func.lower(
                func.replace(func.replace(NetworkNeighbour.remote_chassis_id, ":", ""), "-", "")
            ) == mac_canon.replace(":", "")
        else:
            chassis_match = func.lower(NetworkNeighbour.remote_chassis_id) == (chassis_id.lower())
        row = (
            await db.execute(
                select(NetworkNeighbour.interface_id, NetworkNeighbour.last_seen)
                .where(
                    NetworkNeighbour.interface_id.is_not(None),
                    NetworkNeighbour.remote_port_id == port_id,
                    chassis_match,
                )
                .order_by(NetworkNeighbour.last_seen.desc())
                .limit(1)
            )
        ).first()
        if row is not None:
            interface_id, seen = row
            assert interface_id is not None  # the WHERE requires interface_id IS NOT NULL
            window = await _freshness_window(db, interface_id)
            age = _age_seconds(seen, now)
            port_evidence = Evidence(
                kind="lldp",
                observed_at=seen,
                age_seconds=age,
                window_seconds=window,
                stale=age is not None and age > window,
                detail=f"LLDP neighbour {chassis_id} on port {port_id}",
            )
    elif mac_canon:
        # Only when no port was NAMED. A caller that supplied `port_id` has
        # told us which port it means, and falling back to "wherever this MAC
        # is learned" would answer about a different port — so a stale or
        # mistyped port returns the wrong room while looking authoritative.
        # No port match is the honest answer there; the coarser rules still
        # apply.
        interface_id, port_evidence = await _port_from_mac(db, mac_canon, now)
    if port_evidence:
        evidence.append(port_evidence)

    site_id: uuid.UUID | None = subnet.site_id if subnet else None
    if site_id is None and interface_id is not None:
        site_id = (
            await db.execute(
                select(NetworkDevice.site_id)
                .join(NetworkInterface, NetworkInterface.device_id == NetworkDevice.id)
                .where(NetworkInterface.id == interface_id)
            )
        ).scalar_one_or_none()

    ip_row_id = await _ip_row_id(db, ip, subnet) if ip else None

    # ── Walk the precedence, most specific first ─────────────────────
    targets: dict[str, dict[str, object] | None] = {
        "switch_port": ({"network_interface_id": interface_id} if interface_id else None),
        # Nothing populates a client→AP association yet (#972 Deferred), so
        # this rule is reachable only once a wireless mirror lands. Listed
        # so the precedence is visibly complete rather than silently short.
        "wireless_ap": None,
        "mac": {"mac_address": mac_canon} if mac_canon else None,
        "ip": {"ip_address_id": ip_row_id} if ip_row_id else None,
        "subnet": {"subnet_id": subnet.id} if subnet else None,
        "vlan": ({"vlan_ref_id": subnet.vlan_ref_id} if subnet and subnet.vlan_ref_id else None),
        "site_default": {"site_id": site_id} if site_id else None,
    }

    degraded_reason: str | None = None
    for rule_kind in ERL_RULE_PRECEDENCE:
        target = targets.get(rule_kind)
        if not target:
            continue
        binding = await _binding(db, rule_kind, **target)
        if binding is None:
            continue

        # Only the port-level rules rest on an observation that can go
        # stale. The rest are operator configuration, which is as current
        # as the moment it was saved.
        if rule_kind in ("switch_port", "wireless_ap", "mac") and mac_inference_stale:
            degraded_reason = (
                f"declined the {rule_kind} binding: the IP→MAC mapping it rests "
                f"on was last observed {mac_stale_age}s ago"
            )
            continue
        if (
            rule_kind in ("switch_port", "wireless_ap")
            and port_evidence is not None
            and port_evidence.stale
        ):
            degraded_reason = _declined_reason(rule_kind, port_evidence)
            continue

        erl = await _erl(db, binding.erl_id)
        if erl is None:
            # The binding points at a deactivated or deleted ERL. Keep
            # walking: a coarser live answer beats a precise dead one.
            degraded_reason = degraded_reason or (
                f"the {rule_kind} binding points at an inactive ERL"
            )
            continue

        # Only a port-level rule rests on an observation. Reporting the
        # port evidence's age beside a `subnet` or `site_default` match
        # would put an unrelated — possibly stale — number next to a green
        # `observed` answer, in the response AND in the log column
        # documented as "the evidence the answer rests on". A config rule is
        # as current as the moment it was saved, and says so by carrying no
        # age at all.
        rests_on_observation = rule_kind in ("switch_port", "wireless_ap")
        observed_at = port_evidence.observed_at if rests_on_observation and port_evidence else None
        age = port_evidence.age_seconds if rests_on_observation and port_evidence else None
        return Resolution(
            identity_kind=identity_kind,
            identity_value=identity_value,
            evidence=evidence,
            erl=erl,
            rule_matched=rule_kind,
            confidence="degraded" if degraded_reason else "observed",
            degraded_reason=degraded_reason,
            observed_at=observed_at,
            evidence_age_seconds=age,
        )

    return Resolution(
        identity_kind=identity_kind,
        identity_value=identity_value,
        evidence=evidence,
        confidence="none",
        degraded_reason=degraded_reason or "no ERL binding matched this identity at any level",
    )


async def effective_subnet_erls(
    db: AsyncSession, subnets: list[Subnet]
) -> dict[uuid.UUID, EmergencyResponseLocation]:
    """``{subnet_id: ERL}`` for a whole page of subnets, in ONE round trip.

    DHCP can know which subnet a request came from and nothing finer, so the
    only rules that can apply are the subnet's own, its VLAN's, and its
    site's default — most specific first. A ``switch_port`` or ``mac`` rule is
    deliberately NOT consulted: those identify a device, and a DHCP option is
    written once per scope for every client in it, so honouring one would hand
    every phone on the floor the location of one desk.

    Batched because the caller is the agent ``/config`` long-poll: the
    per-subnet version cost three queries per scope, which is 600 round trips
    on a 200-scope server that has no ERL bindings at all.

    Shares its rule set with the ``e911_voice_subnet_unbound`` conformity
    check, so "this subnet is covered" means the same thing in the compliance
    report and in the rendered DHCP config.
    """
    if not subnets:
        return {}

    subnet_ids = [s.id for s in subnets]
    vlan_ids = [s.vlan_ref_id for s in subnets if s.vlan_ref_id is not None]
    site_ids = [s.site_id for s in subnets if s.site_id is not None]

    conditions = [ERLBinding.subnet_id.in_(subnet_ids)]
    if vlan_ids:
        conditions.append(ERLBinding.vlan_ref_id.in_(vlan_ids))
    if site_ids:
        conditions.append(ERLBinding.site_id.in_(site_ids))

    rows = (
        await db.execute(
            select(ERLBinding, EmergencyResponseLocation)
            .join(
                EmergencyResponseLocation,
                EmergencyResponseLocation.id == ERLBinding.erl_id,
            )
            .where(
                or_(*conditions),
                ERLBinding.rule_kind.in_(("subnet", "vlan", "site_default")),
                ERLBinding.is_active.is_(True),
                EmergencyResponseLocation.is_active.is_(True),
            )
        )
    ).all()

    by_subnet: dict[uuid.UUID, EmergencyResponseLocation] = {}
    by_vlan: dict[uuid.UUID, EmergencyResponseLocation] = {}
    by_site: dict[uuid.UUID, EmergencyResponseLocation] = {}
    for binding, bound_erl in rows:
        if binding.rule_kind == "subnet" and binding.subnet_id is not None:
            by_subnet[binding.subnet_id] = bound_erl
        elif binding.rule_kind == "vlan" and binding.vlan_ref_id is not None:
            by_vlan[binding.vlan_ref_id] = bound_erl
        elif binding.rule_kind == "site_default" and binding.site_id is not None:
            by_site[binding.site_id] = bound_erl

    out: dict[uuid.UUID, EmergencyResponseLocation] = {}
    for subnet in subnets:
        erl = by_subnet.get(subnet.id)
        if erl is None and subnet.vlan_ref_id is not None:
            erl = by_vlan.get(subnet.vlan_ref_id)
        if erl is None and subnet.site_id is not None:
            erl = by_site.get(subnet.site_id)
        if erl is not None:
            out[subnet.id] = erl
    return out


async def effective_subnet_erl(
    db: AsyncSession, subnet: Subnet
) -> EmergencyResponseLocation | None:
    """Single-subnet convenience over :func:`effective_subnet_erls`."""
    return (await effective_subnet_erls(db, [subnet])).get(subnet.id)
