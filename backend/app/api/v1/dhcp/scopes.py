"""DHCP scope CRUD. Group-centric: scopes belong to DHCPServerGroup, not
individual servers. Routes live under ``/subnets/{subnet_id}/dhcp-scopes``
(for the IPAM-side pivot) and ``/scopes/{id}``.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy import text as sa_text
from sqlalchemy.exc import IntegrityError

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.v1.dhcp._audit import write_audit
from app.api.v1.dhcp._failover_schemas import ScopeServingResponse
from app.core.agent_wake import collect_wake, dhcp_group_channel
from app.core.dns_names import validate_fqdn
from app.core.permissions import require_resource_permission
from app.models.dhcp import DHCPScope, DHCPServerGroup
from app.models.ipam import Subnet
from app.services.ai.operations import get_operation
from app.services.ai.operations_risky import DeleteScopeArgs
from app.services.approvals.gate import gate_or_execute
from app.services.dhcp.windows_failover_report import scope_serving_report
from app.services.dhcp.windows_writethrough import (
    WindowsPlacement,
    push_scope_upsert,
)
from app.services.tags import apply_tag_filter

router = APIRouter(tags=["dhcp"], dependencies=[Depends(require_resource_permission("dhcp_scope"))])

VALID_HOSTNAME_POLICIES = {"client", "server_name", "derived", "none"}
VALID_SYNC_MODES = {"disabled", "on_lease", "on_static_only", "ipam", "learned"}
# Fields on ScopeUpdate an explicit ``null`` may CLEAR (#475). Every other
# nullable column keeps its ``exclude_none`` behaviour — a stray null is dropped
# rather than applied — so a NOT-NULL column can't 500 on ``setattr(None)`` and a
# partial-body client can't silently wipe a column it didn't mean to touch.
NULLABLE_CLEARABLE_SCOPE_FIELDS = {
    "min_lease_time",
    "max_lease_time",
    # #637 — null means "inherit the group's lease-cache setting", so an
    # explicit null MUST reach the model to clear a previous override.
    "lease_cache_threshold",
    "lease_cache_max_age",
}
# DHCPv6 operating modes (issue #52). Only meaningful for ipv6 scopes.
VALID_V6_MODES = {"stateful", "stateless", "slaac"}


_CODE_TO_NAME: dict[int, str] = {
    2: "time-offset",
    3: "routers",
    6: "dns-servers",
    15: "domain-name",
    26: "mtu",
    28: "broadcast-address",
    42: "ntp-servers",
    66: "tftp-server-name",
    67: "bootfile-name",
    119: "domain-search",
    150: "tftp-server-address",
}


# Legacy / alternate option names that collapse onto a canonical name.
# The frontend historically sent option 6 as the IANA name
# ``domain-name-servers`` while the canonical stored vocabulary (and the
# Kea driver's option-name map) is ``dns-servers`` (#583). Normalise on
# write so new rows store canonically, and recognise the alias on read so
# already-persisted rows still resolve to code 6 in ``_scope_to_response``
# rather than falling through to code 0 / the custom-options bucket.
_OPTION_NAME_ALIASES: dict[str, str] = {"domain-name-servers": "dns-servers"}


def validate_domain_options(
    opts: dict[str, Any], *, previous: dict[str, Any] | None = None
) -> None:
    """Validate the FQDN-valued DHCP options (issue #597); raise 422 on a bad one.

    ``domain-name`` (option 15) is a single FQDN; ``domain-search``
    (option 119) is a list of FQDNs. Both render straight into the Kea
    config, so a malformed value would break it or ship a bad search suffix.
    Empty / whitespace-only entries are rejected too (a blank search suffix
    is meaningless). A value identical to ``previous`` is skipped, so an
    update that merely round-trips a grandfathered value doesn't block the
    edit (validate-on-*change*, matching the issue's report-don't-break stance).
    """
    prev = previous or {}
    try:
        dn = opts.get("domain-name")
        if isinstance(dn, str) and dn != prev.get("domain-name"):
            if not dn.strip():
                raise ValueError("domain-name option must not be blank")
            validate_fqdn(dn, field="domain-name option")
        ds = opts.get("domain-search")
        if isinstance(ds, list) and ds != prev.get("domain-search"):
            for d in ds:
                if not str(d).strip():
                    raise ValueError("domain-search option contains a blank entry")
                validate_fqdn(str(d), field="domain-search option")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _normalize_options(raw: Any) -> dict[str, Any]:
    """Normalize option shape (name aliases, list→dict). Does NOT validate —
    callers run ``validate_domain_options`` so the create/update paths can
    apply different only-on-change gating."""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return {_OPTION_NAME_ALIASES.get(str(k), str(k)): v for k, v in raw.items()}
    if isinstance(raw, list):
        out: dict[str, Any] = {}
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            code = entry.get("code")
            # #856 — the conditional binds looser than ``or``, so the previous
            # ``entry.get("name") or _CODE_TO_NAME.get(int(code)) if code else None``
            # evaluated as ``(name or lookup) if code else None``: an entry
            # identified by NAME with no ``code`` was silently discarded rather
            # than used as-is. Resolve the two independently.
            name = entry.get("name")
            if not name and code:
                try:
                    name = _CODE_TO_NAME.get(int(code)) or f"option-{code}"
                except (TypeError, ValueError):
                    name = None
            if not name:
                continue
            name = _OPTION_NAME_ALIASES.get(name, name)
            out[name] = entry.get("value")
        return out
    return {}


def _normalize_sync_mode(v: str | None) -> str:
    """Coerce a hostname→IPAM sync value to the canonical DB vocabulary
    (``disabled`` | ``on_static_only`` | ``on_lease``).

    The UI (and API) once used a separate ``none`` / ``ipam`` / ``learned``
    vocabulary that didn't round-trip: the response echoes the stored canonical
    value, which the old ``<select>`` couldn't render, so edits snapped back
    (#475). The UI now speaks the canonical vocabulary directly; these legacy
    values are still mapped in for backward-compatible API clients. Empty /
    missing defaults to ``on_static_only`` (the model default).
    """
    if not v:  # None or ""
        return "on_static_only"
    legacy = {"none": "disabled", "ipam": "on_static_only", "learned": "on_lease"}
    return legacy.get(v, v)


# Fields the scope write models accept under two names, as
# ``(name ScopeResponse emits, alias also accepted, comparison normaliser)``.
# Both aliases are the underlying column name, which is why they are accepted
# and why a script reaches for them first: they are what the model, the DHCP
# services layer and docs/features/DHCP.md all call the field.
_SCOPE_FIELD_ALIASES: tuple[tuple[str, str, Callable[[Any], Any]], ...] = (
    ("enabled", "is_active", lambda v: v),
    ("hostname_sync_mode", "hostname_to_ipam_sync", _normalize_sync_mode),
)


def _assert_aliases_agree(values: dict[str, Any], fields_set: set[str]) -> None:
    """Refuse a body that sets one field twice, under both its names, and
    disagrees with itself (#774).

    ``ScopeResponse`` emits only one name of each pair, so the natural
    read-modify-write — GET, edit, PUT the whole representation back — produces
    a body carrying BOTH as soon as the caller reaches for the column name.
    Whichever name the handler happened to prefer then won, and for the active
    flag that was the stale one the GET supplied: "deactivate this scope"
    answering 200 while the scope kept handing out addresses.

    A precedence rule *could* be built — the response never emits the alias, so
    an ``is_active`` in a body is always a deliberate keystroke while an
    ``enabled`` may be GET residue. We refuse anyway: silently picking between
    two contradictory instructions is the wrong posture for the flag that
    decides whether a DHCP server hands out addresses, and the entire cost of
    this bug was that it was silent. A refusal names the problem where it
    happens. Sending exactly one name is unambiguous, is what every client in
    the repo already does, and still works untouched.

    Nothing counts as a disagreement unless both names carry a real value:
    ``null`` and ``""`` mean "not supplied", and values that normalise to the
    same thing — ``learned`` and ``on_lease`` — agree. ``False`` is a real
    value and is compared as one.

    The empty-string carve-out exists because ``create_scope`` resolves this
    pair with ``a or b``, so an empty ``hostname_sync_mode`` has always fallen
    through to the other name and must not start 422-ing. ``update_scope``
    branches on key presence instead, so there an empty string still wins and
    resolves to the default — pre-existing, and unreachable from the flow this
    guard is about, because ``ScopeResponse`` reads the field from a NOT-NULL
    column that only ever holds a canonical value, so a fetched body cannot
    carry an empty one.
    """

    def _unsupplied(value: Any) -> bool:
        return value is None or (isinstance(value, str) and not value)

    for public, alias, normalize in _SCOPE_FIELD_ALIASES:
        if public not in fields_set or alias not in fields_set:
            continue
        public_value, alias_value = values.get(public), values.get(alias)
        if _unsupplied(public_value) or _unsupplied(alias_value):
            continue
        if normalize(public_value) == normalize(alias_value):
            continue
        raise ValueError(
            f"{public!r} and {alias!r} are two names for the same field and this "
            f"request sets them to different values ({public}={public_value!r}, "
            f"{alias}={alias_value!r}). Send only one of them — {public!r} is the "
            f"name the scope endpoints return, so a read-modify-write should edit "
            f"that one."
        )


def _validate_relay_addresses(v: list[str] | None) -> list[str]:
    """Validate + de-dupe relay-agent IPs (issue #337).

    Each entry must parse as a bare IPv4/IPv6 address (no CIDR — Kea's
    ``relay.ip-addresses`` takes literal giaddr values). Order is
    preserved minus duplicates so the rendered config is stable.
    """
    if not v:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for raw in v:
        addr = str(raw).strip()
        if not addr:
            continue
        try:
            normalized = str(ipaddress.ip_address(addr))
        except ValueError as exc:
            raise ValueError(f"invalid relay address: {addr!r}") from exc
        if normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out


def _validate_relay_family(addrs: list[str], address_family: str) -> None:
    """Reject relay addresses whose IP family doesn't match the scope's
    family. A v4 (subnet4) scope's giaddr relays must be IPv4 and a v6
    (subnet6) scope's relays IPv6 — a mismatch renders an invalid Kea
    subnet (issue #337). Format is already validated upstream; this only
    checks the family against the scope's subnet-derived address_family.
    """
    want_v6 = address_family == "ipv6"
    for raw in addrs or []:
        try:
            ip = ipaddress.ip_address(str(raw).strip())
        except ValueError:
            continue
        if (ip.version == 6) != want_v6:
            fam = "IPv6" if want_v6 else "IPv4"
            raise HTTPException(
                status_code=422,
                detail=(
                    f"relay address {raw!r} must be {fam} to match this " f"{address_family} scope"
                ),
            )


class WindowsPlacementIn(BaseModel):
    """Where a scope no Windows member holds goes, on a group with two or more
    Windows DHCP members (#1110) — ignored on any other group, and on a scope
    a member already holds. Give one of the two; see ``WindowsPlacement``."""

    #: Create it on this one Windows member only.
    server_id: uuid.UUID | None = None
    #: Create it on one side of this failover relationship and add it to the
    #: relationship, so Windows copies it to the partner.
    failover_relationship: str | None = Field(default=None, max_length=255)

    @model_validator(mode="after")
    def _one(self) -> WindowsPlacementIn:
        if self.server_id is not None and self.failover_relationship:
            raise ValueError("give server_id or failover_relationship, not both")
        return self


def _placement(value: WindowsPlacementIn | None) -> WindowsPlacement | None:
    if value is None:
        return None
    return WindowsPlacement(
        server_id=value.server_id, failover_relationship=value.failover_relationship
    )


class ScopeCreate(BaseModel):
    model_config = {"extra": "ignore"}

    group_id: uuid.UUID | None = None
    name: str = ""
    description: str = ""
    # Two names for one column — see ``_SCOPE_FIELD_ALIASES``. ``enabled`` is
    # the public one (it is what ``ScopeResponse`` emits) and ``is_active`` is
    # the accepted alias, kept because it is the column / model-attribute name
    # and therefore the one scripts reach for first. Sending both with
    # different values is refused rather than silently resolved (#774).
    is_active: bool = True
    enabled: bool | None = None
    lease_time: int = 86400
    min_lease_time: int | None = None
    max_lease_time: int | None = None
    # #637 — per-scope Kea lease-cache override; null = inherit the group.
    lease_cache_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    lease_cache_max_age: int | None = Field(default=None, ge=1)
    options: Any = None
    ddns_enabled: bool = False
    ddns_hostname_policy: str | None = "client"
    hostname_to_ipam_sync: str = "on_static_only"
    hostname_sync_mode: str | None = None
    # When False, this scope's dynamic-pool lease mirrors are excluded from the
    # IPAM↔DNS drift check (ephemeral leases don't read as "out of sync").
    dns_track_dynamic_leases: bool = True
    # DHCPv6 operating mode (issue #52) — ignored for v4 scopes.
    v6_address_mode: str = "stateful"
    ra_managed_flag: bool = True
    ra_other_flag: bool = True
    # IPv6 Router Advertisement management (issue #524) — v6 scopes only.
    ra_enabled: bool = False
    ra_mo_override: bool = False
    ra_router_lifetime: int = 1800
    ra_max_interval: int = 600
    ra_prefix_valid_lifetime: int = 86400
    ra_prefix_preferred_lifetime: int = 14400
    ra_prefix_on_link: bool = True
    ra_prefix_autonomous: bool = True
    ra_interface: str = ""
    # Relay-agent (giaddr) IPs (issue #337) — see DHCPScope.relay_addresses.
    relay_addresses: list[str] = Field(default_factory=list)
    tags: dict[str, Any] = Field(default_factory=dict)
    # #1110 — see ``WindowsPlacementIn``. Only consulted when no Windows
    # member holds the scope yet; an existing one stays where it is held.
    windows_placement: WindowsPlacementIn | None = None

    @model_validator(mode="after")
    def _field_aliases(self) -> ScopeCreate:
        _assert_aliases_agree(
            {
                "enabled": self.enabled,
                "is_active": self.is_active,
                "hostname_sync_mode": self.hostname_sync_mode,
                "hostname_to_ipam_sync": self.hostname_to_ipam_sync,
            },
            self.model_fields_set,
        )
        return self

    @field_validator("relay_addresses")
    @classmethod
    def _relay(cls, v: list[str] | None) -> list[str]:
        return _validate_relay_addresses(v)

    @field_validator("ddns_hostname_policy")
    @classmethod
    def _h(cls, v: str | None) -> str | None:
        if v in (None, ""):
            return "client"
        if v not in VALID_HOSTNAME_POLICIES:
            raise ValueError(
                f"ddns_hostname_policy must be one of {sorted(VALID_HOSTNAME_POLICIES)}"
            )
        return v

    @field_validator("v6_address_mode")
    @classmethod
    def _v6mode(cls, v: str | None) -> str:
        if v in (None, ""):
            return "stateful"
        if v not in VALID_V6_MODES:
            raise ValueError(f"v6_address_mode must be one of {sorted(VALID_V6_MODES)}")
        return v


class ScopeUpdate(BaseModel):
    model_config = {"extra": "ignore"}

    name: str | None = None
    description: str | None = None
    # See ScopeCreate: ``enabled`` is the public name, ``is_active`` the
    # accepted alias for the same column, and a body that sets both to
    # different values is refused instead of silently resolved (#774).
    is_active: bool | None = None
    enabled: bool | None = None
    lease_time: int | None = None
    min_lease_time: int | None = None
    max_lease_time: int | None = None
    lease_cache_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    lease_cache_max_age: int | None = Field(default=None, ge=1)
    options: Any = None
    ddns_enabled: bool | None = None
    ddns_hostname_policy: str | None = None
    # The second dual-named field (#774): ``hostname_sync_mode`` is what
    # ``ScopeResponse`` emits, ``hostname_to_ipam_sync`` is the column name.
    hostname_to_ipam_sync: str | None = None
    hostname_sync_mode: str | None = None
    dns_track_dynamic_leases: bool | None = None
    # PXE / iPXE profile binding (issue #51). Pass the UUID of a
    # ``DHCPPXEProfile`` in this scope's group to enable PXE; pass
    # null to detach. The bound profile's matches render as Kea
    # client-classes on the next bundle push.
    pxe_profile_id: uuid.UUID | None = None
    # Distinguish "set to null" from "field not present" — Pydantic
    # treats null + missing identically by default. We need this to
    # support detaching a previously-bound profile.
    clear_pxe_profile: bool | None = None
    # DHCPv6 operating mode (issue #52) — ignored for v4 scopes.
    v6_address_mode: str | None = None
    ra_managed_flag: bool | None = None
    ra_other_flag: bool | None = None
    # IPv6 Router Advertisement management (issue #524) — v6 scopes only.
    ra_enabled: bool | None = None
    ra_mo_override: bool | None = None
    ra_router_lifetime: int | None = None
    ra_max_interval: int | None = None
    ra_prefix_valid_lifetime: int | None = None
    ra_prefix_preferred_lifetime: int | None = None
    ra_prefix_on_link: bool | None = None
    ra_prefix_autonomous: bool | None = None
    ra_interface: str | None = None
    # Relay-agent (giaddr) IPs (issue #337). Pass a list to replace the
    # scope's relay set (empty list clears it); omit to leave unchanged.
    relay_addresses: list[str] | None = None
    tags: dict[str, Any] | None = None
    # #1110 — only read when no Windows member of the group holds the scope
    # (restored from Trash, or deleted on Windows): where to put it back.
    windows_placement: WindowsPlacementIn | None = None

    @model_validator(mode="after")
    def _field_aliases(self) -> ScopeUpdate:
        _assert_aliases_agree(
            {
                "enabled": self.enabled,
                "is_active": self.is_active,
                "hostname_sync_mode": self.hostname_sync_mode,
                "hostname_to_ipam_sync": self.hostname_to_ipam_sync,
            },
            self.model_fields_set,
        )
        return self

    @field_validator("v6_address_mode")
    @classmethod
    def _v6mode(cls, v: str | None) -> str | None:
        if v in (None, ""):
            return None
        if v not in VALID_V6_MODES:
            raise ValueError(f"v6_address_mode must be one of {sorted(VALID_V6_MODES)}")
        return v

    @field_validator("relay_addresses")
    @classmethod
    def _relay(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        return _validate_relay_addresses(v)


_NAME_TO_CODE = {v: k for k, v in _CODE_TO_NAME.items()}
# Existing rows may still be stored under the legacy alias (#583); map it
# to code 6 on readback so the DNS Servers field populates on edit.
for _alias, _canon in _OPTION_NAME_ALIASES.items():
    if _canon in _NAME_TO_CODE:
        _NAME_TO_CODE[_alias] = _NAME_TO_CODE[_canon]


class ScopeResponse(BaseModel):
    id: uuid.UUID
    group_id: uuid.UUID
    subnet_id: uuid.UUID
    enabled: bool
    name: str = ""
    description: str = ""
    lease_time: int
    min_lease_time: int | None
    max_lease_time: int | None
    lease_cache_threshold: float | None
    lease_cache_max_age: int | None
    options: list[dict[str, Any]]
    ddns_enabled: bool
    ddns_hostname_policy: str | None
    # #784 — there is deliberately NO ``ddns_domain_override`` here. The
    # field used to be declared and hardcoded to ``None``: no column backed
    # it, neither ScopeCreate nor ScopeUpdate accepted it, and the scope form
    # sent it on every save, so an operator typed a domain, got a 200, and
    # read back null. The DDNS domain lives on the IPAM chain, where it
    # actually works: ``services/dns/ddns.resolve_effective_ddns`` resolves
    # it most-specific-first — the subnet, then up through its blocks, then
    # the IP space. A scope maps 1:1 to a subnet, so putting a second copy
    # here would be a second source of truth for one setting.
    hostname_sync_mode: str
    dns_track_dynamic_leases: bool = True
    address_family: str = "ipv4"
    v6_address_mode: str = "stateful"
    ra_managed_flag: bool = True
    ra_other_flag: bool = True
    ra_enabled: bool = False
    ra_mo_override: bool = False
    ra_router_lifetime: int = 1800
    ra_max_interval: int = 600
    ra_prefix_valid_lifetime: int = 86400
    ra_prefix_preferred_lifetime: int = 14400
    ra_prefix_on_link: bool = True
    ra_prefix_autonomous: bool = True
    ra_interface: str = ""
    relay_addresses: list[str] = Field(default_factory=list)
    # PXE / iPXE profile binding (issue #51). Echoed so the scope edit
    # form can pre-select the bound profile — without it the picker always
    # reset to "(none)" and a save silently detached the profile (#583).
    pxe_profile_id: uuid.UUID | None = None
    last_pushed_at: datetime | None
    tags: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    modified_at: datetime


def _scope_to_response(scope: DHCPScope) -> ScopeResponse:
    raw = scope.options or {}
    opts: list[dict[str, Any]] = []
    if isinstance(raw, dict):
        for name, val in raw.items():
            opts.append({"code": _NAME_TO_CODE.get(name, 0), "name": name, "value": val})
    elif isinstance(raw, list):
        opts = list(raw)
    return ScopeResponse(
        id=scope.id,
        group_id=scope.group_id,
        subnet_id=scope.subnet_id,
        enabled=scope.is_active,
        name=scope.name or "",
        description=scope.description or "",
        lease_time=scope.lease_time,
        min_lease_time=scope.min_lease_time,
        max_lease_time=scope.max_lease_time,
        lease_cache_threshold=scope.lease_cache_threshold,
        lease_cache_max_age=scope.lease_cache_max_age,
        options=opts,
        ddns_enabled=scope.ddns_enabled,
        ddns_hostname_policy=scope.ddns_hostname_policy,
        hostname_sync_mode=scope.hostname_to_ipam_sync,
        dns_track_dynamic_leases=getattr(scope, "dns_track_dynamic_leases", True),
        address_family=getattr(scope, "address_family", "ipv4") or "ipv4",
        v6_address_mode=getattr(scope, "v6_address_mode", "stateful") or "stateful",
        ra_managed_flag=getattr(scope, "ra_managed_flag", True),
        ra_other_flag=getattr(scope, "ra_other_flag", True),
        ra_enabled=getattr(scope, "ra_enabled", False),
        ra_mo_override=getattr(scope, "ra_mo_override", False),
        ra_router_lifetime=getattr(scope, "ra_router_lifetime", 1800),
        ra_max_interval=getattr(scope, "ra_max_interval", 600),
        ra_prefix_valid_lifetime=getattr(scope, "ra_prefix_valid_lifetime", 86400),
        ra_prefix_preferred_lifetime=getattr(scope, "ra_prefix_preferred_lifetime", 14400),
        ra_prefix_on_link=getattr(scope, "ra_prefix_on_link", True),
        ra_prefix_autonomous=getattr(scope, "ra_prefix_autonomous", True),
        ra_interface=getattr(scope, "ra_interface", "") or "",
        relay_addresses=list(getattr(scope, "relay_addresses", None) or []),
        pxe_profile_id=scope.pxe_profile_id,
        last_pushed_at=scope.last_pushed_at,
        tags=scope.tags or {},
        created_at=scope.created_at,
        modified_at=scope.modified_at,
    )


@router.get("/subnets/{subnet_id}/dhcp-scopes", response_model=list[ScopeResponse])
async def list_scopes_for_subnet(
    subnet_id: uuid.UUID,
    db: DB,
    _: CurrentUser,
    tag: list[str] = Query(default_factory=list),
) -> list[ScopeResponse]:
    stmt = select(DHCPScope).where(DHCPScope.subnet_id == subnet_id)
    stmt = apply_tag_filter(stmt, DHCPScope.tags, tag)
    res = await db.execute(stmt)
    return [_scope_to_response(s) for s in res.unique().scalars().all()]


@router.get("/server-groups/{group_id}/scopes", response_model=list[ScopeResponse])
async def list_scopes_for_group(
    group_id: uuid.UUID,
    db: DB,
    _: CurrentUser,
    tag: list[str] = Query(default_factory=list),
) -> list[ScopeResponse]:
    stmt = select(DHCPScope).where(DHCPScope.group_id == group_id)
    stmt = apply_tag_filter(stmt, DHCPScope.tags, tag)
    res = await db.execute(stmt)
    return [_scope_to_response(s) for s in res.unique().scalars().all()]


async def _assert_no_overlapping_group_cidr(
    db: DB,
    group_id: uuid.UUID,
    subnet: Subnet,
    *,
    exclude_scope_id: uuid.UUID | None = None,
) -> None:
    """Refuse a scope whose subnet CIDR overlaps another ACTIVE scope's subnet
    in the same group (#844).

    IPAM deliberately allows the same CIDR in different IP spaces (VRF
    semantics), but a Kea server renders one ``subnet4``/``subnet6`` entry per
    scope and rejects the entire config at load on a duplicate prefix — so two
    overlapping-space subnets converging on one group takes DHCP down for
    every scope on that group. Same failure class as the out-of-CIDR
    reservation guard (#619): refuse at the API instead of shipping a config
    the daemon will refuse. Overlap within one space is already impossible
    (IPAM validates), so a hit here means two IP spaces — the fix is a
    separate DHCP server group per overlapping space.

    Raw SQL for the ``&&`` cidr operator (mirrors the IPAM overlap checks);
    that bypasses the ORM soft-delete filter, hence the explicit
    ``deleted_at IS NULL``.
    """
    res = await db.execute(
        sa_text("""
            SELECT s.network FROM subnet s
            JOIN dhcp_scope sc ON sc.subnet_id = s.id
            WHERE sc.group_id = CAST(:gid AS uuid)
              AND sc.subnet_id != CAST(:sid AS uuid)
              AND sc.is_active
              AND sc.deleted_at IS NULL
              AND s.network && CAST(:net AS cidr)
              AND (CAST(:excl AS uuid) IS NULL OR sc.id != CAST(:excl AS uuid))
            LIMIT 1
            """),
        {
            "gid": str(group_id),
            "sid": str(subnet.id),
            "net": str(subnet.network),
            "excl": str(exclude_scope_id) if exclude_scope_id else None,
        },
    )
    row = res.first()
    if row:
        raise HTTPException(
            status_code=409,
            detail=(
                f"An active scope in this DHCP server group already covers "
                f"{row[0]}, which overlaps {subnet.network} (another IP "
                f"space). Duplicate or overlapping prefixes on one Kea "
                f"server reject the whole config at load, taking down DHCP "
                f"for every scope in the group — use a separate DHCP server "
                f"group per overlapping IP space (#844)."
            ),
        )


@router.post(
    "/subnets/{subnet_id}/dhcp-scopes",
    response_model=ScopeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_scope(
    subnet_id: uuid.UUID,
    body: ScopeCreate,
    db: DB,
    user: SuperAdmin,
    adopt_existing: bool = False,
) -> ScopeResponse:
    """Create a scope.

    ``adopt_existing`` (cloud/FortiGate members only, #865) opts in to
    overwriting a pre-existing provider DHCP object SpatiumDDI never created;
    without it the pre-commit push 409s (``X-Adoption-Required``) and the
    create rolls back, so the UI can offer an adopt-and-retry.
    """
    subnet = await db.get(Subnet, subnet_id)
    if subnet is None:
        raise HTTPException(status_code=404, detail="Subnet not found")

    # Group is required. If only one group exists and none was specified,
    # bind to it automatically; otherwise 422.
    group_id = body.group_id
    if group_id is None:
        all_groups = (await db.execute(select(DHCPServerGroup))).scalars().all()
        if len(all_groups) == 1:
            group_id = all_groups[0].id
        else:
            raise HTTPException(
                status_code=422,
                detail="group_id is required when more than one DHCP server group exists",
            )
    grp = await db.get(DHCPServerGroup, group_id)
    if grp is None:
        raise HTTPException(status_code=404, detail="DHCP server group not found")

    existing = await db.execute(
        select(DHCPScope).where(DHCPScope.group_id == group_id, DHCPScope.subnet_id == subnet_id)
    )
    if existing.unique().scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail="A scope for this group+subnet already exists",
        )

    sync_mode = _normalize_sync_mode(body.hostname_sync_mode or body.hostname_to_ipam_sync)
    # #844 — only an ACTIVE scope reaches the rendered config, so an inactive
    # create is allowed and the guard re-fires on activation (update_scope).
    _will_be_active = body.enabled if body.enabled is not None else body.is_active
    if _will_be_active:
        await _assert_no_overlapping_group_cidr(db, group_id, subnet)
    if sync_mode not in VALID_SYNC_MODES - {"ipam", "learned"}:
        raise HTTPException(status_code=422, detail=f"invalid hostname sync mode: {sync_mode}")
    # Same alias resolution as update: ``enabled`` wins when supplied, and
    # ``ScopeCreate`` has already refused a body where the two disagree (#774).
    is_active = body.enabled if body.enabled is not None else body.is_active
    try:
        _net = ipaddress.ip_network(str(subnet.network), strict=False)
        address_family = "ipv6" if isinstance(_net, ipaddress.IPv6Network) else "ipv4"
    except ValueError:
        address_family = "ipv4"
    _validate_relay_family(body.relay_addresses, address_family)
    _create_options = _normalize_options(body.options)
    validate_domain_options(_create_options)  # always validate on create (#597)
    scope = DHCPScope(
        subnet_id=subnet_id,
        group_id=group_id,
        name=(body.name or "").strip(),
        description=(body.description or "").strip(),
        is_active=is_active,
        lease_time=body.lease_time,
        min_lease_time=body.min_lease_time,
        max_lease_time=body.max_lease_time,
        lease_cache_threshold=body.lease_cache_threshold,
        lease_cache_max_age=body.lease_cache_max_age,
        options=_create_options,
        ddns_enabled=body.ddns_enabled,
        ddns_hostname_policy=body.ddns_hostname_policy or "client",
        hostname_to_ipam_sync=sync_mode,
        dns_track_dynamic_leases=body.dns_track_dynamic_leases,
        address_family=address_family,
        v6_address_mode=body.v6_address_mode,
        ra_managed_flag=body.ra_managed_flag,
        ra_other_flag=body.ra_other_flag,
        ra_enabled=body.ra_enabled,
        ra_mo_override=body.ra_mo_override,
        ra_router_lifetime=body.ra_router_lifetime,
        ra_max_interval=body.ra_max_interval,
        ra_prefix_valid_lifetime=body.ra_prefix_valid_lifetime,
        ra_prefix_preferred_lifetime=body.ra_prefix_preferred_lifetime,
        ra_prefix_on_link=body.ra_prefix_on_link,
        ra_prefix_autonomous=body.ra_prefix_autonomous,
        ra_interface=body.ra_interface,
        relay_addresses=body.relay_addresses,
    )
    db.add(scope)
    # The pre-check above can't see a soft-deleted scope, and even for
    # live rows a concurrent create can race it, so translate a
    # (group, subnet) unique-violation into a clean 409 (#474). Any other
    # integrity failure (FK / NOT NULL / CHECK) is unexpected — roll back
    # and let it surface as a 500 rather than masking it as a conflict.
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        if "uq_dhcp_scope_group_subnet" not in str(exc.orig):
            raise
        raise HTTPException(
            status_code=409,
            detail="A scope for this group+subnet already exists",
        ) from exc
    # Push to every Windows DHCP member of the group BEFORE commit so a
    # WinRM failure rolls the DB row back.
    await push_scope_upsert(
        db,
        scope,
        adopt_existing=adopt_existing,
        placement=_placement(body.windows_placement),
    )
    collect_wake(dhcp_group_channel(group_id))
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="dhcp_scope",
        resource_id=str(scope.id),
        resource_display=f"{grp.name}:{subnet.network}",
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(scope)
    return _scope_to_response(scope)


@router.get("/scopes/{scope_id}", response_model=ScopeResponse)
async def get_scope(scope_id: uuid.UUID, db: DB, _: CurrentUser) -> ScopeResponse:
    scope = await db.get(DHCPScope, scope_id)
    if scope is None:
        raise HTTPException(status_code=404, detail="Scope not found")
    return _scope_to_response(scope)


@router.get("/scopes/{scope_id}/failover", response_model=ScopeServingResponse)
async def get_scope_failover(scope_id: uuid.UUID, db: DB, _: CurrentUser) -> ScopeServingResponse:
    """How the Windows DHCP members of the scope's group serve it (#1110).

    One row per Windows member — does it hold the scope, is it active there,
    which failover relationship covers it, does its configuration match the
    member whose view is imported — plus a verdict: ``single_server``,
    ``failover``, ``split_scope``, ``uncoordinated`` (two servers can hand out
    the same address), and so on. From the topology poll's observations, not
    a live read. ``no_windows_members`` for a group without Windows members.
    """
    scope = await db.get(DHCPScope, scope_id)
    if scope is None:
        raise HTTPException(status_code=404, detail="Scope not found")
    return ScopeServingResponse.model_validate(await scope_serving_report(db, scope))


@router.put("/scopes/{scope_id}", response_model=ScopeResponse)
async def update_scope(
    scope_id: uuid.UUID,
    body: ScopeUpdate,
    db: DB,
    user: SuperAdmin,
    adopt_existing: bool = False,
) -> ScopeResponse:
    # ``adopt_existing``: same opt-in as create (#865) — an edit of a scope
    # whose interface carries a foreign provider object hits the same
    # adoption guard on the pre-commit push.
    scope = await db.get(DHCPScope, scope_id)
    if scope is None:
        raise HTTPException(status_code=404, detail="Scope not found")
    # ``exclude_unset`` (not ``exclude_none``) so an explicit null can clear a
    # nullable column (e.g. resetting min_lease_time / max_lease_time to empty),
    # while a field the client didn't send stays untouched (#475). But keep a
    # null only for the fields we explicitly allow to clear — otherwise an
    # explicit null on a NOT-NULL column (name / description / is_active) would
    # 500 on commit, and a null a partial-body client sent for an unmanaged
    # nullable column would silently wipe it (both were dropped under
    # ``exclude_none``).
    changes = {
        k: v
        for k, v in body.model_dump(exclude_unset=True).items()
        if v is not None or k in NULLABLE_CLEARABLE_SCOPE_FIELDS
    }
    # ``enabled`` is the public alias for the ``is_active`` column. Safe to let
    # it win unconditionally now: ``ScopeUpdate`` refuses a body that sets both
    # to different values, so this can no longer overwrite a deliberate
    # ``is_active`` with the stale ``enabled`` a GET supplied (#774).
    if "enabled" in changes:
        changes["is_active"] = changes.pop("enabled")
    # Same alias resolution, same guarantee: the write model refuses a body
    # where the two names disagree, so preferring one can no longer shadow a
    # deliberate edit to the other (#774).
    if "hostname_sync_mode" in changes:
        changes["hostname_to_ipam_sync"] = _normalize_sync_mode(changes.pop("hostname_sync_mode"))
    elif "hostname_to_ipam_sync" in changes:
        changes["hostname_to_ipam_sync"] = _normalize_sync_mode(changes["hostname_to_ipam_sync"])
    # Validate the resolved sync mode with the same guard as create (#475).
    if "hostname_to_ipam_sync" in changes and changes[
        "hostname_to_ipam_sync"
    ] not in VALID_SYNC_MODES - {"ipam", "learned"}:
        raise HTTPException(
            status_code=422,
            detail=f"invalid hostname sync mode: {changes['hostname_to_ipam_sync']}",
        )
    if "options" in changes:
        normalized = _normalize_options(changes["options"])
        # Validate only domain options that CHANGED from the stored value
        # (issue #597 review) — the scope form round-trips the full options
        # dict, so re-validating an unchanged grandfathered value would block
        # an unrelated edit.
        validate_domain_options(normalized, previous=scope.options or {})
        changes["options"] = normalized
    # ``clear_pxe_profile=True`` is the explicit detach signal — Pydantic
    # collapses missing + null on ``pxe_profile_id`` so we need a
    # second boolean field to disambiguate. Apply detach first; a
    # later ``pxe_profile_id`` set in the same call (operator
    # detaches one profile and binds another) still wins.
    if changes.pop("clear_pxe_profile", False):
        scope.pxe_profile_id = None
    if "relay_addresses" in changes:
        # Family must match the scope's (subnet-derived) address_family;
        # address_family itself is immutable on update (#337).
        _validate_relay_family(changes["relay_addresses"], scope.address_family or "ipv4")
    # #844 — activation is the other door into the rendered config: a scope
    # created inactive (or deactivated to dodge the create-time guard) must
    # pass the same overlapping-CIDR check before it starts rendering.
    if changes.get("is_active") is True and not scope.is_active:
        subnet = await db.get(Subnet, scope.subnet_id)
        if subnet is not None:
            await _assert_no_overlapping_group_cidr(
                db, scope.group_id, subnet, exclude_scope_id=scope.id
            )
    placement_in = body.windows_placement
    changes.pop("windows_placement", None)
    for k, v in changes.items():
        setattr(scope, k, v)
    await db.flush()
    await push_scope_upsert(
        db,
        scope,
        adopt_existing=adopt_existing,
        placement=_placement(placement_in),
    )
    collect_wake(dhcp_group_channel(scope.group_id))
    write_audit(
        db,
        user=user,
        action="update",
        resource_type="dhcp_scope",
        resource_id=str(scope.id),
        resource_display=str(scope.id),
        changed_fields=list(changes.keys()),
        new_value=body.model_dump(mode="json", exclude_none=True),
    )
    await db.commit()
    await db.refresh(scope)
    return _scope_to_response(scope)


@router.delete("/scopes/{scope_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_scope(
    scope_id: uuid.UUID,
    db: DB,
    user: SuperAdmin,
    request: Request,
    permanent: bool = False,
) -> Any:
    """Delete a DHCP scope.

    Default soft-delete stamps the scope — plus its pools and reservations,
    which are cascade children (#617) — with a fresh batch UUID, so the whole
    set restores together from /admin/trash.

    Soft-delete means *stop serving immediately*, on every backend. The scope
    drops out of the rendered ConfigBundle at once (the global ``deleted_at IS
    NULL`` filter hides it) and ``collect_wake`` pushes agents to re-poll, so
    Kea members converge within seconds; the Windows write-through fires on this
    path too, so agentless members converge as well (#616). The purge sweep
    later hard-deletes the rows; it is not what makes the config change.

    Two-person approval (#62): when the ``governance.approvals`` module is on
    and a ``delete:dhcp_scope`` policy matches, returns ``202`` with a pending
    change-request; otherwise executes inline via ``operation.apply`` exactly
    as before (route stays SuperAdmin-gated).
    """
    op = get_operation("delete_scope")
    assert op is not None  # registered at import
    args = DeleteScopeArgs(scope_id=scope_id, permanent=permanent)
    pending = await gate_or_execute(db, user, request, operation=op, args=args)
    if pending is not None:
        return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content=pending.as_dict())
    await op.apply(db, user, args)
    return None
