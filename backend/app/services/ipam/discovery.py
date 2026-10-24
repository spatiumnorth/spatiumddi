"""IP discovery — ping sweep + ARP scan + reconciliation (issue #23).

A scheduled, per-subnet-opt-in pass that finds live hosts and folds
them back into IPAM:

* **Ping sweep** — pure-Python asyncio ICMP echo via an *unprivileged*
  ``SOCK_DGRAM`` ICMP socket (Linux "ping group range"). When that
  socket can't be created (container running as a uid outside
  ``net.ipv4.ping_group_range``), we fall back to a TCP-connect probe
  across a small set of common ports — a connect success OR a
  ``ConnectionRefusedError`` both prove the host is up. No raw sockets,
  no CAP_NET_RAW required, so it works in an unprivileged worker.
* **ARP scan** — reads the worker's own ARP cache (``/proc/net/arp``).
  Only useful for subnets the worker is L2-adjacent to, but free and
  it catches hosts that drop ICMP. Also enriches ``mac_address``.

Reconciliation writes (``reconcile_subnet``):
* existing rows → ``last_seen_at`` / ``last_seen_method`` refreshed
  (and ``mac_address`` filled only when NULL — operator data is never
  overwritten);
* live IPs with no row → inserted ``status='discovered'`` — UNLESS the
  IP sits in a dynamic DHCP pool (owned by the DHCP server) or is the
  network / broadcast address.

Rows an operator has touched (``user_modified_at`` set) keep their
status; discovery only refreshes their ``last_seen_at`` timestamp.

The read side (``build_reconciliation_report``) is pure-query and powers
``GET /ipam/subnets/{id}/reconciliation`` — see docs/features/IPAM.md §8.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import struct
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPPool, DHCPScope
from app.models.ipam import IPAddress, Subnet
from app.services.ipam.new_device import (
    MacObservationResult,
    classify_mac,
    is_locally_administered,
)

logger = structlog.get_logger(__name__)

# Hard ceiling on hosts swept in one pass. A /20 (4094 hosts) is plenty
# for a LAN; anything bigger is almost certainly a mistake (or a routed
# supernet) and would hammer the network. Larger subnets are skipped
# with a logged warning rather than silently truncated.
MAX_SWEEP_HOSTS = 4096

# Ports probed by the TCP-connect fallback. A host that accepts a
# connection OR refuses it (RST) is alive; only a timeout / no-route is
# treated as down. Kept short + common so the fallback stays fast.
_TCP_PROBE_PORTS = (22, 80, 443, 445, 3389, 8006, 53, 8080)

_ICMP_TIMEOUT_S = 2.0
_TCP_TIMEOUT_S = 1.0
_TCP_CONCURRENCY = 128


@dataclass
class SweepResult:
    """What a sweep observed on the wire for one subnet.

    ``ping_alive`` and ``arp`` are kept separate so reconciliation can
    label each IP's ``last_seen_method`` correctly — ``"ping"`` when it
    answered an echo / TCP probe, ``"arp"`` when the ARP cache is the
    only evidence. ``alive`` is the union of both.
    """

    ping_alive: set[str] = field(default_factory=set)  # answered ICMP / TCP
    arp: dict[str, str] = field(default_factory=dict)  # ip -> mac (ARP-complete)
    icmp_used: bool = False  # True when the real ICMP path ran (vs TCP fallback)

    @property
    def alive(self) -> set[str]:
        return self.ping_alive | set(self.arp)

    def method_for(self, ip: str) -> str:
        return "ping" if ip in self.ping_alive else "arp"


# ── Host enumeration ────────────────────────────────────────────────


def enumerate_hosts(cidr: str) -> list[str] | None:
    """Host addresses for an IPv4 subnet, or None if it's too big / v6.

    Uses ``ipaddress.ip_network(...).hosts()``, which per RFC 3021
    returns both addresses for a /31 and the single address for a /32
    (so those tiny subnets DO yield hosts, not an empty list). IPv6
    returns None — ARP + the /proc/net/arp read are IPv4-only and
    enumerating a v6 subnet is infeasible.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None
    if net.version != 4:
        return None
    if net.num_addresses > MAX_SWEEP_HOSTS:
        return None
    return [str(h) for h in net.hosts()]


# ── Ping sweep ──────────────────────────────────────────────────────


def _icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _icmp_echo(ident: int, seq: int) -> bytes:
    # Type 8 (echo request), code 0. The kernel rewrites id + checksum
    # for SOCK_DGRAM ICMP, but a well-formed packet is harmless.
    payload = b"spatiumddi-disco"
    header = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    chk = _icmp_checksum(header + payload)
    header = struct.pack("!BBHHH", 8, 0, chk, ident, seq)
    return header + payload


async def _icmp_sweep(hosts: list[str], timeout: float) -> set[str] | None:
    """Unprivileged ICMP echo sweep. Returns the live set, or None when
    an ICMP datagram socket can't be created (caller falls back to TCP)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except (PermissionError, OSError) as exc:
        logger.info("ipam.discovery.icmp_unavailable", error=str(exc))
        return None

    sock.setblocking(False)
    alive: set[str] = set()
    loop = asyncio.get_running_loop()
    ident = os.getpid() & 0xFFFF

    def _on_readable() -> None:
        # Drain every queued reply; the kernel demuxes only our socket's
        # replies here, so any source address that shows up is alive.
        while True:
            try:
                _data, addr = sock.recvfrom(1024)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                return
            alive.add(addr[0])

    try:
        loop.add_reader(sock.fileno(), _on_readable)
    except (OSError, ValueError):
        sock.close()
        return None

    try:
        for i, host in enumerate(hosts):
            try:
                sock.sendto(_icmp_echo(ident, i & 0xFFFF), (host, 0))
            except OSError:
                # One unreachable host (e.g. EHOSTUNREACH / no route) must
                # not abort the whole sweep — skip it and keep blasting.
                continue
            if i % 128 == 0:
                await asyncio.sleep(0)  # cooperative yield while blasting
        await asyncio.sleep(timeout)
    finally:
        try:
            loop.remove_reader(sock.fileno())
        except (OSError, ValueError):
            # Best-effort cleanup — the reader may already be gone (e.g.
            # the loop is shutting down). The socket is closed next
            # regardless, so swallow and move on.
            pass
        sock.close()
    return alive


async def _tcp_alive(host: str, ports: tuple[int, ...], timeout: float) -> bool:
    for port in ports:
        try:
            fut = asyncio.open_connection(host, port)
            _reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                # The connect already proved the host is up; a failure
                # tearing the probe socket down doesn't change that, so
                # ignore it and report alive.
                pass
            return True
        except ConnectionRefusedError:
            return True  # host up, port closed — still alive
        except (TimeoutError, OSError):
            continue
    return False


async def _tcp_sweep(hosts: list[str], timeout: float, concurrency: int) -> set[str]:
    sem = asyncio.Semaphore(concurrency)
    alive: set[str] = set()

    async def probe(host: str) -> None:
        async with sem:
            if await _tcp_alive(host, _TCP_PROBE_PORTS, timeout):
                alive.add(host)

    await asyncio.gather(*(probe(h) for h in hosts))
    return alive


def read_arp_table(path: str = "/proc/net/arp") -> dict[str, str]:
    """``/proc/net/arp`` → ``{ip: mac}`` for complete (flag 0x2) entries.

    ``path`` is overridable for tests. Best-effort: returns ``{}`` on any
    platform / permission issue."""
    out: dict[str, str] = {}
    try:
        with open(path) as fh:
            lines = fh.readlines()
    except OSError:
        return out
    for line in lines[1:]:  # skip header row
        parts = line.split()
        if len(parts) < 4:
            continue
        ip, _hwtype, flags, mac = parts[0], parts[1], parts[2], parts[3]
        try:
            complete = int(flags, 16) & 0x2
        except ValueError:
            complete = 0
        if complete and mac and mac != "00:00:00:00:00:00":
            out[ip] = mac
    return out


async def sweep_subnet(cidr: str) -> SweepResult | None:
    """Run the ping sweep + ARP read for one subnet CIDR.

    Returns None when the subnet can't be swept (IPv6 or larger than
    ``MAX_SWEEP_HOSTS``)."""
    hosts = enumerate_hosts(cidr)
    if hosts is None:
        return None

    result = SweepResult()
    if hosts:
        icmp_alive = await _icmp_sweep(hosts, _ICMP_TIMEOUT_S)
        if icmp_alive is None:
            result.ping_alive = await _tcp_sweep(hosts, _TCP_TIMEOUT_S, _TCP_CONCURRENCY)
        else:
            result.ping_alive = icmp_alive
            result.icmp_used = True

    # ARP cache — only keep entries that fall inside this subnet. An
    # ARP-complete entry means the host answered an ARP, so it's up even
    # if it dropped our ICMP/TCP probe. ``alive`` unions ping + arp.
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        net = None
    if net is not None:
        for ip, mac in read_arp_table().items():
            try:
                if ipaddress.ip_address(ip) in net:
                    result.arp[ip] = mac
            except ValueError:
                continue
    return result


# ── Reconciliation writer ───────────────────────────────────────────


async def _dynamic_pool_ranges(db: AsyncSession, subnet_id) -> list[tuple[int, int]]:
    """``[(start_int, end_int)]`` for every dynamic DHCP pool on the subnet.

    Mirrors ``api.v1.ipam.router._load_dynamic_pool_ranges`` (kept local
    so the service doesn't import the router)."""
    rows = await db.execute(
        select(DHCPPool.start_ip, DHCPPool.end_ip)
        .join(DHCPScope, DHCPScope.id == DHCPPool.scope_id)
        .where(DHCPScope.subnet_id == subnet_id)
        .where(DHCPPool.pool_type == "dynamic")
    )
    out: list[tuple[int, int]] = []
    for start_ip, end_ip in rows.all():
        try:
            s = int(ipaddress.ip_address(str(start_ip)))
            e = int(ipaddress.ip_address(str(end_ip)))
        except (ValueError, TypeError):
            continue
        if s > e:
            s, e = e, s
        out.append((s, e))
    return out


def _in_dynamic_pool(ip_int: int, ranges: list[tuple[int, int]]) -> bool:
    return any(s <= ip_int <= e for s, e in ranges)


async def reconcile_subnet(db: AsyncSession, subnet: Subnet, sweep: SweepResult) -> dict[str, int]:
    """Fold a sweep result into IPAM rows for one subnet.

    Idempotent: a second pass over the same wire data just refreshes
    ``last_seen_at``. Does not commit — the caller owns the transaction.
    """
    counts = {"updated": 0, "created": 0, "skipped_pool": 0, "arp_enriched": 0}
    if not sweep.alive:
        return counts

    now = datetime.now(UTC)
    try:
        net = ipaddress.ip_network(str(subnet.network), strict=False)
    except ValueError:
        return counts

    # Network / broadcast are real placeholders only for prefixes ≤ /30.
    # On /31 (RFC 3021) and /32 both endpoints are usable hosts, so don't
    # treat them as skip-able there — otherwise discovery could never
    # create a row for a point-to-point link or a single-host subnet
    # (matches the resize service's prefixlen ≤ 30 convention).
    skip_endpoints = net.version == 4 and net.prefixlen <= 30
    network_int = int(net.network_address) if skip_endpoints else None
    broadcast_int = int(net.broadcast_address) if skip_endpoints else None
    dynamic_ranges = await _dynamic_pool_ranges(db, subnet.id)

    existing_rows = list(
        (await db.execute(select(IPAddress).where(IPAddress.subnet_id == subnet.id)))
        .scalars()
        .all()
    )
    by_ip: dict[str, IPAddress] = {str(r.address): r for r in existing_rows}

    # New-device watch (issue #459): sightings for rows created in this pass,
    # recorded after the loop once the rows have ids (mirrors the SNMP path).
    newly_discovered: list[tuple[IPAddress, str]] = []

    for ip in sweep.alive:
        try:
            ip_int = int(ipaddress.ip_address(ip))
        except ValueError:
            continue

        method = sweep.method_for(ip)  # "ping" if it answered, else "arp"
        row = by_ip.get(ip)
        if row is not None:
            row.last_seen_at = now
            row.last_seen_method = method
            # Enrich MAC only when empty — operator data is never
            # overwritten (mirrors the SNMP cross-reference path).
            if ip in sweep.arp and row.mac_address is None:
                row.mac_address = sweep.arp[ip]
                counts["arp_enriched"] += 1
            # Always log the observed MAC to ip_mac_history so the
            # unknown-MAC-in-static-range hygiene alert (#369) can compare
            # the operator-recorded MAC against what actually answered.
            if ip in sweep.arp:
                await record_mac_observation(db, row.id, sweep.arp[ip])
            counts["updated"] += 1
            continue

        # No row yet — candidate for a ``discovered`` insert. Skip the
        # network / broadcast placeholders and anything inside a dynamic
        # DHCP pool (the DHCP server owns those slots).
        if ip_int == network_int or ip_int == broadcast_int:
            continue
        if _in_dynamic_pool(ip_int, dynamic_ranges):
            counts["skipped_pool"] += 1
            continue

        new_row = IPAddress(
            subnet_id=subnet.id,
            address=ip,
            status="discovered",
            mac_address=sweep.arp.get(ip),
            last_seen_at=now,
            last_seen_method=method,
        )
        db.add(new_row)
        counts["created"] += 1
        if ip in sweep.arp:
            newly_discovered.append((new_row, sweep.arp[ip]))

    # Log a MAC sighting for each newly-created discovered row too (#459), so a
    # never-before-tracked host found by the sweep classifies + surfaces in the
    # new-device review queue / new_mac_seen alert — not just existing rows.
    if newly_discovered:
        await db.flush()
        for new_row, mac in newly_discovered:
            if new_row.id is not None:
                await record_mac_observation(db, new_row.id, mac)

    return counts


# ── Reconciliation report (read side) ───────────────────────────────


async def record_mac_observation(
    db: AsyncSession,
    ip_id: uuid.UUID,
    mac_address: str | None,
    *,
    source: str = "sweep",
) -> MacObservationResult | None:
    """Upsert an observed ``(ip_id, mac)`` into ``ip_mac_history`` (issue #369).

    Called from the ping/ARP sweep + SNMP ARP cross-reference + DHCP lease
    events + L2 sniff for EVERY MAC observed on the wire — not just when the
    IPAddress row's canonical ``mac_address`` is empty. That's what lets the
    ``unknown_mac_in_static_range`` hygiene alert compare the operator-recorded
    MAC against what's actually answering: a differing recent history row is a
    squat.

    New-device watch (issue #459): on the *first-ever* sighting of a ``(ip, mac)``
    pair the row is stamped with a :func:`~app.services.ipam.new_device.classify_mac`
    classification (``new`` / ``known``), the ``source`` path, and an
    ``is_randomized`` flag. Subsequent sightings only bump ``last_seen`` + the
    ``source`` and never downgrade an operator-set ``acknowledged`` / ``known``
    classification. Returns a :class:`MacObservationResult` describing the
    outcome (so the caller can fire a ``device.first_seen`` event), or ``None``
    on a missing MAC.

    ``source`` is one of ``sweep`` / ``snmp`` / ``dhcp_lease`` / ``l2_sniff``.
    """
    if not mac_address:
        return None

    # Classify against the known fleet of the sighting's own IP space
    # (#2577) — a MAC allocated in another space says nothing about this one.
    # The row's space is resolved inside the fleet query, not looked up first.
    classification = await classify_mac(db, mac_address, same_space_as_ip=ip_id)
    is_randomized = is_locally_administered(mac_address)
    row = (
        await db.execute(
            text("""
                INSERT INTO ip_mac_history
                    (id, ip_address_id, mac_address, first_seen, last_seen,
                     classification, source, is_randomized)
                VALUES (gen_random_uuid(), :ip_id, CAST(:mac AS macaddr), now(), now(),
                        :classification, :source, :is_randomized)
                ON CONFLICT (ip_address_id, mac_address)
                DO UPDATE SET last_seen = now(), source = :source
                RETURNING (xmax = 0) AS inserted, classification
                """),
            {
                "ip_id": str(ip_id),
                "mac": mac_address,
                "classification": classification,
                "source": source,
                "is_randomized": is_randomized,
            },
        )
    ).one()
    return MacObservationResult(
        mac_address=mac_address,
        classification=row.classification,
        is_new_row=bool(row.inserted),
        is_randomized=is_randomized,
    )


async def build_reconciliation_report(
    db: AsyncSession, subnet: Subnet, stale_minutes: int = 1440
) -> dict:
    """Per-subnet reconciliation buckets for ``GET .../reconciliation``.

    Three subnet-scoped categories (see docs/features/IPAM.md §8):

    * ``in_ipam_not_seen`` — allocated / reserved / static rows with no
      recent liveness signal (never seen, or ``last_seen_at`` older than
      the stale window). "Allocated but nothing answered."
    * ``discovered_not_allocated`` — ``status='discovered'`` rows: seen
      on the wire but never formally allocated by an operator.
    * ``status_mismatch`` — rows marked ``available`` that are answering
      right now (recent ``last_seen_at``). "IPAM says free, host is up."
    """
    now = datetime.now(UTC)
    stale_cutoff = now - timedelta(minutes=max(1, stale_minutes))

    rows = list(
        (await db.execute(select(IPAddress).where(IPAddress.subnet_id == subnet.id)))
        .scalars()
        .all()
    )

    def _entry(r: IPAddress) -> dict:
        return {
            "id": str(r.id),
            "address": str(r.address),
            "status": r.status,
            "hostname": r.hostname,
            "mac_address": r.mac_address,
            "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
            "last_seen_method": r.last_seen_method,
        }

    allocated_states = {"allocated", "reserved", "static_dhcp"}
    in_ipam_not_seen: list[dict] = []
    discovered_not_allocated: list[dict] = []
    status_mismatch: list[dict] = []

    for r in rows:
        seen_recent = r.last_seen_at is not None and r.last_seen_at >= stale_cutoff
        if r.status in allocated_states and not seen_recent:
            in_ipam_not_seen.append(_entry(r))
        elif r.status == "discovered":
            discovered_not_allocated.append(_entry(r))
        elif r.status == "available" and seen_recent:
            status_mismatch.append(_entry(r))

    return {
        "subnet_id": str(subnet.id),
        "network": str(subnet.network),
        "generated_at": now.isoformat(),
        "stale_minutes": stale_minutes,
        "last_discovery_at": (
            subnet.last_discovery_at.isoformat() if subnet.last_discovery_at else None
        ),
        "counts": {
            "in_ipam_not_seen": len(in_ipam_not_seen),
            "discovered_not_allocated": len(discovered_not_allocated),
            "status_mismatch": len(status_mismatch),
        },
        "in_ipam_not_seen": in_ipam_not_seen,
        "discovered_not_allocated": discovered_not_allocated,
        "status_mismatch": status_mismatch,
    }


__all__ = [
    "MAX_SWEEP_HOSTS",
    "SweepResult",
    "build_reconciliation_report",
    "enumerate_hosts",
    "read_arp_table",
    "reconcile_subnet",
    "sweep_subnet",
]
