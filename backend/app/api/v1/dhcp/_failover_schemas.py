"""Response models for the Windows failover views (#1110).

Shared by ``GET /dhcp/server-groups/{id}/failover`` and
``GET /dhcp/scopes/{id}/failover``; the data comes from
``services.dhcp.windows_failover_report``, which is also what the MCP tool
returns, so the page and the copilot read one source.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

#: ``services.dhcp.windows_failover.Verdict`` values, plus the one the scope
#: view adds for a group with no Windows members at all.
ServingVerdict = Literal[
    "not_on_windows",
    "single_server",
    "failover",
    "failover_one_sided",
    "split_scope",
    "uncoordinated",
    "unknown",
    "no_windows_members",
]


class ScopeServingServer(BaseModel):
    """One Windows member's view of one scope."""

    server_id: uuid.UUID
    server_name: str
    #: None when this member's scopes have never been read — unknown, not "no".
    holds: bool | None
    is_active: bool | None
    #: The failover relationship covering the scope on this member, if any.
    relationship_name: str | None
    #: For a scope several members hold: does this member's configuration of
    #: it match the reconcile owner's? None when not comparable.
    in_sync: bool | None
    observed_at: datetime | None
    #: The member's last successful scope read is older than the freshness
    #: window; what it shows is its last-known view.
    stale: bool
    #: This member's view is the one the topology poll imports.
    reconcile_owner: bool


class ScopeServingResponse(BaseModel):
    """How the Windows members of a group serve one scope."""

    #: The managed ``dhcp_scope`` row, or None for a scope a Windows member
    #: holds whose subnet is not in IPAM.
    scope_id: uuid.UUID | None
    cidr: str
    verdict: ServingVerdict
    #: No two servers can hand out the same address under this verdict.
    safe: bool
    #: One human sentence — the same text the write-through's refusals use.
    detail: str
    relationship_name: str | None
    relationship_mode: str | None
    #: Failover partners whose configuration of this scope differs.
    drift: bool | None
    servers: list[ScopeServingServer]


class FailoverMemberStatus(BaseModel):
    server_id: uuid.UUID
    server_name: str
    host: str
    scopes_observed_at: datetime | None
    #: Last SUCCESSFUL failover read. None = never read, not "has none".
    failover_observed_at: datetime | None
    #: The most recent failover read's failure, if it failed; the
    #: relationships shown are then the last ones read.
    failover_error: str | None
    fresh: bool
    relationship_count: int


class FailoverRelationshipSide(BaseModel):
    """A relationship as one member reports it."""

    server_id: uuid.UUID
    server_name: str
    #: ``PartnerServer`` verbatim, as the relationship was created.
    partner_server: str
    #: The group member that partner is, when it could be told.
    partner_server_id: uuid.UUID | None
    #: ``Active`` / ``Standby`` in hot-standby mode.
    server_role: str | None
    #: Windows failover state — ``Normal``, ``CommunicationInterrupted``,
    #: ``PartnerDown``, …
    state: str | None
    #: THIS side's share of client requests in load-balance mode.
    load_balance_percent: int | None
    reserve_percent: int | None
    modified_at: datetime


class FailoverRelationshipResponse(BaseModel):
    name: str
    #: ``LoadBalance`` / ``HotStandby``, as Windows spells it.
    mode: str | None
    max_client_lead_time_seconds: int | None
    state_switch_interval_seconds: int | None
    auto_state_transition: bool | None
    #: Message authentication on — the shared secret itself is never read.
    enable_auth: bool | None
    #: Windows ``ScopeId``s (network addresses) the relationship covers.
    scope_ids: list[str]
    sides: list[FailoverRelationshipSide]
    #: Both partners are members of this group and report the relationship.
    complete: bool
    #: One-sided: the partner as Windows names it, when it is not a member.
    partner_outside_group: str | None


class GroupFailoverResponse(BaseModel):
    group_id: uuid.UUID
    windows_member_count: int
    #: Kea members of the same group, by name. Non-empty means a mixed group:
    #: every active scope a Windows member also holds is served twice.
    kea_members: list[str] = []
    members: list[FailoverMemberStatus]
    relationships: list[FailoverRelationshipResponse]
    #: Every scope a Windows member holds, plus the group's managed IPv4
    #: scopes no member holds.
    scopes: list[ScopeServingResponse]


# ── relationship management (#1110 Phase 2) ───────────────────────────


FailoverMode = Literal["LoadBalance", "HotStandby"]
FailoverRole = Literal["Active", "Standby"]


class _Tuning(BaseModel):
    #: Hot standby: THIS side's role (the side the relationship is created
    #: on for a create; for an update, the side it runs on).
    server_role: FailoverRole | None = None
    #: Load balance: THIS side's share of client requests, 0–100.
    load_balance_percent: int | None = Field(default=None, ge=0, le=100)
    #: Hot standby: addresses reserved for the standby, 0–100.
    reserve_percent: int | None = Field(default=None, ge=0, le=100)
    #: MCLT — how far one partner may extend a lease beyond what the other knows.
    max_client_lead_time_seconds: int | None = Field(default=None, ge=0, le=86_400 * 30)
    #: Move to PartnerDown automatically after ``state_switch_interval_seconds``.
    auto_state_transition: bool | None = None
    state_switch_interval_seconds: int | None = Field(default=None, ge=0, le=86_400 * 30)
    #: Enables message authentication between the partners. Passed to Windows
    #: and never stored, logged or returned.
    shared_secret: str | None = Field(default=None, min_length=1, max_length=255)


class FailoverRelationshipCreate(_Tuning):
    name: str = Field(min_length=1, max_length=126)
    #: The member it is created on — it must hold every scope in ``scope_ids``.
    server_id: uuid.UUID
    #: The member that becomes the partner — it must hold none of them.
    partner_server_id: uuid.UUID
    mode: FailoverMode = "LoadBalance"
    #: Windows ``ScopeId``s (IPv4 network addresses). Windows requires one or more.
    scope_ids: list[str] = Field(min_length=1, max_length=500)


class FailoverRelationshipUpdate(_Tuning):
    mode: FailoverMode | None = None
    #: The side the change runs on. Windows applies ``load_balance_percent``
    #: and ``server_role`` to THAT server (the partner gets the complement),
    #: so either one requires it; otherwise any drivable side is used.
    server_id: uuid.UUID | None = None


class FailoverScopesChange(BaseModel):
    scope_ids: list[str] = Field(min_length=1, max_length=500)


class FailoverReplicate(BaseModel):
    #: The side whose configuration overwrites the partner's.
    source_server_id: uuid.UUID
    #: Empty = every scope in the relationship.
    scope_ids: list[str] = Field(default_factory=list, max_length=500)


class FailoverActionResponse(BaseModel):
    action: Literal["create", "update", "delete", "add_scopes", "remove_scopes", "replicate"]
    relationship: str
    #: The member the cmdlet ran on (and, for a removal, the one that kept
    #: the scopes).
    ran_on_server_id: uuid.UUID
    ran_on_server_name: str
    partner_server_id: uuid.UUID | None
    partner_server_name: str | None
    scope_ids: list[str]
    #: The action succeeded on Windows, but re-reading a server afterwards did
    #: not — the view below may lag until the next topology poll.
    warnings: list[str]
    #: The group's failover view after the action.
    failover: GroupFailoverResponse
