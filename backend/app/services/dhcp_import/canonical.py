"""Canonical IR shared by all DHCP importers (issue #129).

Every source — Kea JSON file, Windows DHCP WinRM live-pull, ISC
``dhcpd.conf`` — parses upstream config into the same neutral shape so
the commit endpoint can stay source-agnostic. The shape is a strict
subset of what ``DHCPScope`` + ``DHCPPool`` + ``DHCPStaticAssignment``
+ ``DHCPClientClass`` carry: enough to recreate a scope tree faithfully,
no source-specific extensions. Anything the source carries that we
can't model lands in ``ImportedScope.parse_warnings`` (per-scope) or
``ImportPreview.unsupported`` (the "didn't import" panel) so the UI
surfaces it on the preview.

Mirrors :mod:`app.services.dns_import.canonical` — same two-call
preview/commit contract, same conflict-action vocabulary, just keyed
on DHCP scopes instead of DNS zones.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

# Stable enum the importer stamps on every row it creates. Keep in
# sync with the values the migration writes into ``import_source``.
ImportSource = Literal["kea", "windows_dhcp", "isc_dhcp"]

# Per-scope conflict resolution. Unlike the DNS importer there is no
# ``rename`` — a DHCP scope is keyed by its subnet, not a name, and you
# can't meaningfully rename a subnet. ``skip`` leaves the existing scope
# alone; ``overwrite`` deletes it (cascading pools + statics) and
# recreates from the import.
ConflictAction = Literal["skip", "overwrite"]


@dataclass
class ImportedReservation:
    """One DHCP reservation (MAC → IP) in the canonical shape.

    Mirrors the columns ``DHCPStaticAssignment`` needs at create-time.
    ``options`` is a ``{name: value}`` map in SpatiumDDI's canonical
    option-name vocabulary (see ``drivers/dhcp/base.STANDARD_OPTION_NAMES``).
    """

    ip_address: str
    mac_address: str
    hostname: str = ""
    client_id: str | None = None
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class ImportedPool:
    """One pool (range) inside a scope.

    ``pool_type`` ∈ {dynamic, excluded, reserved}. ISC ``range``
    statements + Kea ``pools`` map to ``dynamic``; Windows exclusion
    ranges + ISC ``deny`` pools map to ``excluded``.
    """

    start_ip: str
    end_ip: str
    pool_type: str = "dynamic"
    name: str = ""
    class_restriction: str | None = None


@dataclass
class ImportedClientClass:
    """One client class — group-scoped on commit.

    ``supported`` is ``False`` when the source's classifier expression
    can't be faithfully translated to SpatiumDDI's model (ISC's
    runtime-expression DSL is richer than ours). Unsupported classes
    are surfaced for manual review and NOT created; supported ones
    (Kea ``test`` expressions, which are our native shape) are created
    verbatim.
    """

    name: str
    match_expression: str = ""
    description: str = ""
    # The daemon block the class came from (#1229) — a Kea ``Dhcp6``
    # ``client-classes`` entry is an IPv6 class.
    address_family: str = "ipv4"
    options: dict[str, Any] = field(default_factory=dict)
    supported: bool = True
    warning: str | None = None


@dataclass
class ImportedScope:
    """One DHCP scope in the canonical shape.

    ``subnet_cidr`` is the canonical network (``10.0.0.0/24``).
    ``address_family`` ∈ {ipv4, ipv6}. ``skipped_options`` records
    option values the source carried that we dropped (unmapped /
    unsupported) so the preview can warn without per-option detail.
    ``ha_info`` carries the source's failover / HA partner identity as
    an informational string — we don't reconstruct HA topology, the
    operator does that server-side post-import.
    """

    subnet_cidr: str
    address_family: str  # ipv4 | ipv6
    name: str = ""
    description: str = ""
    lease_time: int = 86400
    min_lease_time: int | None = None
    max_lease_time: int | None = None
    is_active: bool = True
    options: dict[str, Any] = field(default_factory=dict)
    pools: list[ImportedPool] = field(default_factory=list)
    reservations: list[ImportedReservation] = field(default_factory=list)
    ddns_enabled: bool = False
    ddns_hostname_policy: str = "client"
    v6_address_mode: str = "stateful"
    skipped_options: dict[str, Any] = field(default_factory=dict)
    ha_info: str | None = None
    parse_warnings: list[str] = field(default_factory=list)


@dataclass
class ScopeConflict:
    """A scope whose subnet already has a ``DHCPScope`` in the target
    group, OR whose CIDR matches an existing IPAM subnet.

    ``existing_scope_id`` is set when the target group already serves
    this subnet — that's the blocking conflict the operator resolves
    via ``action`` (skip / overwrite). ``existing_subnet_id`` is
    informational: when set, the commit links the scope to that subnet
    instead of auto-creating one. When ``existing_scope_id`` is None the
    row is advisory (no blocking conflict) — it just tells the UI
    whether the scope will link-or-create its IPAM subnet.
    """

    subnet_cidr: str
    existing_scope_id: str | None = None
    existing_subnet_id: str | None = None
    existing_subnet_name: str | None = None
    existing_pool_count: int = 0
    existing_reservation_count: int = 0
    # True when the matched scope is soft-deleted (in Trash). It still
    # occupies the ``(group_id, subnet_id)`` unique slot, so a plain
    # create would hit an IntegrityError — surfacing it as a conflict
    # lets the operator overwrite (hard-delete the trashed row + create
    # fresh) instead of seeing a cryptic SQL error.
    soft_deleted: bool = False
    action: ConflictAction = "skip"


@dataclass
class ImportPreview:
    """What ``POST /dhcp/import/{source}/preview`` returns.

    ``scopes`` + ``client_classes`` is the full canonical IR — the
    commit endpoint re-receives it from the operator (the UI passes it
    back) so we don't need to store it server-side between the two
    calls. ``unsupported`` is the "didn't import" panel (hook configs,
    failover keys, classifier rules we couldn't model).
    """

    source: ImportSource
    scopes: list[ImportedScope]
    client_classes: list[ImportedClientClass]
    conflicts: list[ScopeConflict]
    warnings: list[str]
    unsupported: list[str]
    total_pools: int
    total_reservations: int
    address_family_histogram: dict[str, int]
