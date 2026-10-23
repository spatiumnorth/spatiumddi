"""Free-space finder — sweep an IPSpace (or one block subtree) for unused CIDRs.

Walks every IPBlock in the space (or, when ``parent_block_id`` is set, just
the subtree rooted at that block), computes the set of CIDRs that are
"allocated" inside it (the union of direct child blocks and direct child
subnets — nested children are accounted for inside their own parent), and
slides a window of the requested prefix length through the resulting free
gaps to surface candidate CIDRs.

Design choices worth recording:

* **Direct-child accounting only.** A block's free space is the difference
  between its own CIDR and the union of its *direct* descendants. Nested
  grand-children are handled when we recurse into the parent block, not
  here. This mirrors ``GET /ipam/blocks/{id}/free-space`` and keeps the
  arithmetic O(children) per block instead of O(descendants).
* **Address family is a hard filter.** Mixed v4 / v6 IPSpaces are
  legal (operators sometimes co-locate the two for one site under one
  VRF row). The caller asks for a single family; blocks of the wrong
  family are skipped without penalty.
* **No per-subnet free-IP scan by default.** ``min_free_addresses`` is an
  opt-in additional pass that, after the block-level scan finds a
  candidate, looks up whether the candidate actually exists as a subnet
  and (if it does) checks ``Subnet.total_ips - Subnet.allocated_ips``
  against the threshold. Most callers want "find me an unused CIDR" and
  the existing-subnet branch is rarely useful — but operators who want
  "find me a subnet that already exists and has at least N free hosts"
  get exact semantics with this opt-in.
* **Sliding-window enumeration.** ``ipaddress.IPv4Network.subnets(new_prefix=)``
  iterates every aligned sub-CIDR of the parent. We filter out the ones
  that overlap any allocated child. ``summarize_address_range`` would be
  cheaper for huge sweeps but the result is canonical-form supernets
  rather than aligned candidates of the requested prefix. The sliding-
  window form is what the caller expects — they asked for /24s, they
  should get aligned /24s.
* **Cap.** Hard cap of 100 candidates regardless of caller ``count``;
  enumeration over a /8 looking for /29s would otherwise emit millions
  of rows. The dataclass result honours the caller's lower cap when
  set.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPBlock, Subnet

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


_HARD_CAP = 100
"""Maximum candidates emitted regardless of caller request — see module
docstring. The router's pydantic schema clamps the request to this same
value, but the service enforces it again so direct callers (Celery
tasks, scripts) can't accidentally explode the result set."""


@dataclass
class FreeSpaceCandidate:
    """One candidate CIDR returned by the finder."""

    cidr: str
    parent_block_id: uuid.UUID
    parent_block_cidr: str
    free_addresses: int | None = None
    """Usable addresses in the candidate. A candidate is wholly free, so
    this is its full host count (network/broadcast excluded for IPv4
    shorter than /31). Always populated; ``min_free_addresses`` filters on it."""


@dataclass
class FreeSpaceResult:
    candidates: list[FreeSpaceCandidate] = field(default_factory=list)
    summary: dict[str, str | int] = field(default_factory=dict)
    """Free-form metadata — currently carries ``warning`` for the empty-
    space case and ``blocks_scanned`` / ``candidates_emitted`` counters
    so operators can tell why they got fewer rows than they asked for."""


def _usable_addresses(net: IPNetwork) -> int:
    n = net.num_addresses
    if isinstance(net, ipaddress.IPv4Network) and net.prefixlen < 31:
        n -= 2
    return min(n, 2**63 - 1)


def _validate_prefix(prefix_length: int, address_family: int) -> str | None:
    """Return an error message for an invalid prefix request, or None.

    Bounds chosen to match the request schema. /31 and /127 point-to-
    point ranges are excluded — searching for those tells you nothing
    useful (every IP in a /31 is a router interface).
    """
    if address_family == 4:
        if not (8 <= prefix_length <= 30):
            return f"prefix_length must be between 8 and 30 for IPv4 (got {prefix_length})"
    elif address_family == 6:
        if not (8 <= prefix_length <= 126):
            return f"prefix_length must be between 8 and 126 for IPv6 (got {prefix_length})"
    else:
        return f"address_family must be 4 or 6 (got {address_family})"
    return None


async def _load_blocks(
    db: AsyncSession,
    space_id: uuid.UUID,
    parent_block_id: uuid.UUID | None,
) -> list[IPBlock]:
    """Load blocks under consideration for the sweep.

    When ``parent_block_id`` is given we walk the subtree rooted there
    — the parent itself plus every recursive descendant — so the
    allocator can search inside one logical container only. When
    omitted we sweep every block in the space.
    """
    if parent_block_id is None:
        rows = await db.execute(select(IPBlock).where(IPBlock.space_id == space_id))
        return list(rows.scalars().all())

    # Subtree walk via a self-join loop. A recursive CTE would be more
    # elegant but the depth is realistically <= 6 levels and we already
    # have the `IPBlock` ORM rows we need.
    seen: dict[uuid.UUID, IPBlock] = {}
    root = await db.get(IPBlock, parent_block_id)
    if root is None:
        return []
    seen[root.id] = root
    frontier: list[uuid.UUID] = [root.id]
    while frontier:
        next_rows = await db.execute(select(IPBlock).where(IPBlock.parent_block_id.in_(frontier)))
        next_ids: list[uuid.UUID] = []
        for blk in next_rows.scalars().all():
            if blk.id in seen:
                continue
            seen[blk.id] = blk
            next_ids.append(blk.id)
        frontier = next_ids
    return list(seen.values())


def _block_matches_family(block: IPBlock, address_family: int) -> bool:
    try:
        net = ipaddress.ip_network(str(block.network), strict=False)
    except ValueError:
        return False
    if address_family == 4:
        return isinstance(net, ipaddress.IPv4Network)
    return isinstance(net, ipaddress.IPv6Network)


async def _direct_child_cidrs(
    db: AsyncSession, block: IPBlock
) -> tuple[list[IPNetwork], dict[str, Subnet]]:
    """Return the (direct child blocks ∪ direct child subnets) CIDR list
    and a dict keyed by canonical CIDR string mapping to the Subnet row
    when the CIDR corresponds to an existing subnet (used for the
    ``min_free_addresses`` opt-in).
    """
    occupants: list[IPNetwork] = []
    subnet_by_cidr: dict[str, Subnet] = {}

    child_blocks = (
        (await db.execute(select(IPBlock).where(IPBlock.parent_block_id == block.id)))
        .scalars()
        .all()
    )
    for cb in child_blocks:
        try:
            occupants.append(ipaddress.ip_network(str(cb.network), strict=False))
        except ValueError:
            continue

    child_subnets = (
        (await db.execute(select(Subnet).where(Subnet.block_id == block.id))).scalars().all()
    )
    for cs in child_subnets:
        try:
            net = ipaddress.ip_network(str(cs.network), strict=False)
        except ValueError:
            continue
        occupants.append(net)
        subnet_by_cidr[str(net)] = cs

    return occupants, subnet_by_cidr


def _candidates_for_block(
    block_net: IPNetwork,
    occupants: list[IPNetwork],
    prefix_length: int,
    remaining: int,
) -> list[IPNetwork]:
    """Yield aligned sub-CIDRs of ``block_net`` at ``prefix_length`` that
    don't overlap any occupant CIDR.

    Returns at most ``remaining`` candidates so the caller can stop the
    outer block-walk early once the global cap is reached.
    """
    if prefix_length < block_net.prefixlen:
        # The block itself is smaller than the requested CIDR — nothing
        # of this size fits in here.
        return []
    if prefix_length == block_net.prefixlen:
        # The block has exactly one slot of this size: itself, and only
        # if there are no occupants at all.
        return [block_net] if not occupants else []

    out: list[IPNetwork] = []
    # ``subnets(new_prefix=)`` raises ValueError when the new prefix is
    # smaller than the parent — already guarded above.
    for candidate in block_net.subnets(new_prefix=prefix_length):
        # Skip candidates that overlap any occupant.
        if any(candidate.overlaps(occ) for occ in occupants):  # type: ignore[arg-type]
            continue
        out.append(candidate)
        if len(out) >= remaining:
            break
    return out


async def find_free_space(
    db: AsyncSession,
    *,
    space_id: uuid.UUID,
    prefix_length: int,
    address_family: int = 4,
    count: int = 5,
    min_free_addresses: int | None = None,
    parent_block_id: uuid.UUID | None = None,
) -> FreeSpaceResult:
    """Sweep an IPSpace for free CIDRs of ``prefix_length`` size.

    Returns up to ``count`` candidates (capped at 100). On the empty-space
    edge case (no blocks at all) we surface a ``summary.warning`` rather
    than 4xx-ing — the UI uses this to render a "create a block first"
    nudge instead of an error.
    """
    cap = max(1, min(int(count), _HARD_CAP))
    err = _validate_prefix(prefix_length, address_family)
    if err:
        # Service layer doesn't raise HTTPException; the router translates
        # the empty-with-warning shape into 422 only when the prefix is
        # malformed. Caller-side validation (pydantic) catches the common
        # case before we get here.
        return FreeSpaceResult(candidates=[], summary={"warning": err})

    blocks = await _load_blocks(db, space_id, parent_block_id)
    if not blocks:
        return FreeSpaceResult(
            candidates=[],
            summary={
                "warning": (
                    "space has no blocks"
                    if parent_block_id is None
                    else "block subtree contains no blocks"
                ),
                "blocks_scanned": 0,
                "candidates_emitted": 0,
            },
        )

    # Stable order: smallest CIDR first (i.e. tightest container) so the
    # operator sees candidates within the smallest enclosing block before
    # candidates from a wider parent. Tiebreak by network address for
    # determinism across runs.
    blocks_in_family = [b for b in blocks if _block_matches_family(b, address_family)]
    blocks_in_family.sort(
        key=lambda b: (
            -ipaddress.ip_network(str(b.network), strict=False).prefixlen,
            int(ipaddress.ip_network(str(b.network), strict=False).network_address),
        )
    )

    candidates: list[FreeSpaceCandidate] = []
    seen_cidrs: set[str] = set()

    for block in blocks_in_family:
        if len(candidates) >= cap:
            break
        try:
            block_net = ipaddress.ip_network(str(block.network), strict=False)
        except ValueError:
            continue
        # If the requested prefix is wider than this block, skip — the
        # candidate would have to come from a parent block that's already
        # in this list (or doesn't exist). We never emit a candidate
        # whose `parent_block_id` doesn't actually contain it.
        if prefix_length < block_net.prefixlen:
            continue

        occupants, _ = await _direct_child_cidrs(db, block)
        remaining = cap - len(candidates)
        for cand in _candidates_for_block(block_net, occupants, prefix_length, remaining):
            cand_str = str(cand)
            if cand_str in seen_cidrs:
                # Two parents could both contain the same candidate when
                # we're walking nested blocks — emit each candidate
                # exactly once, attributed to its tightest container.
                continue
            seen_cidrs.add(cand_str)

            # A free CIDR is wholly unallocated, so every usable address in
            # it is free (same host count a Subnet row would carry as
            # total_ips: network/broadcast excluded for IPv4 < /31).
            free_addresses = _usable_addresses(cand)
            if min_free_addresses is not None and free_addresses < min_free_addresses:
                continue

            candidates.append(
                FreeSpaceCandidate(
                    cidr=cand_str,
                    parent_block_id=block.id,
                    parent_block_cidr=str(block_net),
                    free_addresses=free_addresses,
                )
            )
            if len(candidates) >= cap:
                break

    return FreeSpaceResult(
        candidates=candidates,
        summary={
            "blocks_scanned": len(blocks_in_family),
            "candidates_emitted": len(candidates),
        },
    )


__all__ = [
    "FreeSpaceCandidate",
    "FreeSpaceResult",
    "find_free_space",
]
