"""Wire shapes for global search (issue #879)."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from pydantic import BaseModel, Field

__all__ = ["QueryShape", "SearchResponse", "SearchResult", "shape_of"]


_MAC_PATTERNS = (
    re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$"),
    re.compile(r"^([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}$"),
    re.compile(r"^[0-9a-fA-F]{12}$"),
    re.compile(r"^([0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}$"),  # Cisco dotted
)


@dataclass(frozen=True)
class QueryShape:
    """What the operator typed, classified once instead of per provider.

    v1 re-ran ``_is_ip`` / ``_is_cidr`` / ``_is_mac`` inside every search
    helper. Cheap individually, but it also meant each helper could drift on
    what counts as an IP — so the classification now happens once and is
    passed down.
    """

    raw: str
    lowered: str
    is_ip: bool
    is_cidr: bool
    is_mac: bool
    mac_normalized: str
    # The network a CIDR query names, host bits cleared (``10.0.96.5/24`` ->
    # ``10.0.96.0/24``). PostgreSQL refuses ``CAST(... AS cidr)`` on a value
    # with bits set right of the mask, so providers cast this, never ``raw``.
    cidr: str = ""

    @property
    def is_address_like(self) -> bool:
        return self.is_ip or self.is_cidr

    @property
    def kind(self) -> str:
        """One of ``ip`` / ``cidr`` / ``mac`` / ``text``.

        Providers declare which kinds they can serve, so a MAC lookup runs
        the two queries that could possibly match it instead of all twenty.
        That is both faster and more accurate — a MAC substring-matched
        against a site's notes was never a result anybody wanted.
        """
        if self.is_cidr:
            return "cidr"
        if self.is_ip:
            return "ip"
        if self.is_mac:
            return "mac"
        return "text"


def _is_ip(q: str) -> bool:
    try:
        ipaddress.ip_address(q)
    except ValueError:
        return False
    return True


def _is_cidr(q: str) -> bool:
    if "/" not in q:
        return False
    try:
        ipaddress.ip_network(q, strict=False)
    except ValueError:
        return False
    return True


def _cidr_of(q: str) -> str:
    if not _is_cidr(q):
        return ""
    return str(ipaddress.ip_network(q, strict=False))


def _is_mac(q: str) -> bool:
    return any(p.match(q) for p in _MAC_PATTERNS)


def shape_of(q: str) -> QueryShape:
    return QueryShape(
        raw=q,
        lowered=q.lower(),
        is_ip=_is_ip(q),
        is_cidr=_is_cidr(q),
        is_mac=_is_mac(q),
        mac_normalized=re.sub(r"[:\-.]", "", q).lower(),
        cidr=_cidr_of(q),
    )


class SearchResult(BaseModel):
    """One hit from any resource type.

    Every context field defaults to ``None``. They used to be required-but-
    nullable, so each of the (now twenty) providers had to spell out
    ``hostname=None, mac_address=None, subnet_id=None, …`` — noise that
    grew linearly with both the number of providers and the number of
    fields, and that silently forced every new field onto every existing
    provider.
    """

    type: str
    id: str

    # Primary display
    display: str
    name: str | None = None

    # Status / detail
    status: str | None = None
    description: str | None = None

    # IP-address specific
    hostname: str | None = None
    mac_address: str | None = None

    # Breadcrumb context (IPAM)
    subnet_id: str | None = None
    subnet_network: str | None = None
    block_id: str | None = None
    space_id: str | None = None
    space_name: str | None = None

    # DNS context
    dns_group_id: str | None = None
    dns_group_name: str | None = None
    dns_zone_id: str | None = None
    dns_zone_name: str | None = None
    dns_record_type: str | None = None
    dns_record_value: str | None = None

    # Free-form breadcrumb for the types added in v2, which have no shared
    # parent shape to model (a DHCP reservation's parent is a scope, a
    # circuit's is a provider). One string the UI renders verbatim beats
    # twenty type-specific columns nothing else reads.
    context: str | None = None

    # Where selecting this row should navigate. The original seven types
    # are dispatched client-side because they pass react-router *state*
    # (which subnet to open, which row to highlight) rather than a path;
    # everything added since carries its path here instead of growing that
    # switch statement once per type.
    route: str | None = None

    # Why this row matched — "hostname", "description",
    # "custom_field:owner=alice". Rendered as a hint chip.
    matched_field: str | None = None

    # Relevance. Returned so the ordering is inspectable rather than
    # something the operator has to infer from the sequence.
    score: int = 0


class SearchTypeInfo(BaseModel):
    """One searchable type, as visible to the calling user."""

    type: str
    label: str
    group: str


class SearchResponse(BaseModel):
    query: str
    total: int
    results: list[SearchResult]
    # Types actually consulted for this request, after permission and
    # feature-module filtering. The UI builds its scope chips from this, so
    # an operator is never offered a filter that can only return nothing.
    searched_types: list[SearchTypeInfo] = Field(default_factory=list)
    # True when ``total`` is a floor: some type hit the fetch cap, so more rows
    # match than were counted. ``total`` itself never depends on ``limit``.
    total_capped: bool = False
