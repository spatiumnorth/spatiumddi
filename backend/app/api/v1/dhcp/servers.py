"""DHCP server CRUD + sync/approve/leases."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, field_validator
from sqlalchemy import func, or_, select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.pagination import DEFAULT_PAGE_SIZE, MAX_PAGE, MAX_PAGE_SIZE, Page, paginate
from app.api.v1.dhcp._audit import write_audit
from app.api.v1.dhcp._leases import LeaseResponse, apply_lease_filters, enrich_leases
from app.core.agent_wake import (
    collect_wake,
    dhcp_group_channel,
    dhcp_server_channel,
    dhcp_wake_channels,
    publish_wake,
)
from app.core.crypto import encrypt_dict
from app.core.permissions import require_resource_permission
from app.core.ssrf import assert_safe_target
from app.drivers._winrm import validate_transport
from app.drivers.dhcp import is_agentless, is_cloud, is_read_only
from app.drivers.dhcp.base import MACBlockDef
from app.drivers.dhcp.fortigate import test_fortigate_credentials
from app.drivers.dhcp.registry import _DRIVERS as _DHCP_DRIVERS
from app.drivers.dhcp.registry import CLOUD_DHCP_DRIVERS, get_driver
from app.drivers.dhcp.windows import test_winrm_credentials
from app.models.audit import AuditLog
from app.models.dhcp import DHCPConfigOp, DHCPLease, DHCPMACBlock, DHCPScope, DHCPServer
from app.models.ipam import Subnet
from app.models.metrics import DHCPMetricSample
from app.services.agents.spool_status import SpoolStatus
from app.services.dhcp.cloud_writethrough import push_cloud_scope_upsert
from app.services.dhcp.config_bundle import build_config_bundle
from app.services.dhcp.pull_leases import pull_leases_from_server
from app.services.dhcp.stats import (
    STATS_BUCKET_SECONDS,
    STATS_WINDOW_SECONDS,
    active_lease_count,
)

router = APIRouter(
    prefix="/servers",
    tags=["dhcp"],
    dependencies=[Depends(require_resource_permission("dhcp_server"))],
)

# Sourced from the registry so new drivers (e.g. windows_dhcp) are
# accepted automatically without having to touch this allowlist.
VALID_DRIVERS = frozenset(_DHCP_DRIVERS.keys())

logger = structlog.get_logger(__name__)


class WindowsCredentialsInput(BaseModel):
    """Windows DHCP admin credentials (for driver='windows_dhcp').

    Stored Fernet-encrypted on ``DHCPServer.credentials_encrypted``.
    Server never returns the password back — responses only expose
    ``has_credentials``.

    All fields are optional to support **partial updates** on edit: if the
    server already has stored credentials, sending just ``{"transport":
    "credssp"}`` (for example) decrypts the existing blob, merges the
    transport change, and re-encrypts. On create, ``username`` + ``password``
    are still required — the create endpoint validates that explicitly.
    """

    username: str | None = None
    password: str | None = None
    winrm_port: int | None = None
    # transport: ntlm | credssp | basic (kerberos: #1128)
    transport: str | None = None
    use_tls: bool | None = None
    verify_tls: bool | None = None

    @field_validator("transport")
    @classmethod
    def _valid_transport(cls, v: str | None) -> str | None:
        # #426 / #1128: reject a transport this build cannot speak at save,
        # instead of failing opaquely at the first call.
        return validate_transport(v)

    @field_validator("winrm_port")
    @classmethod
    def _valid_port(cls, v: int | None) -> int | None:
        if v is not None and not 1 <= v <= 65535:
            raise ValueError("winrm_port must be between 1 and 65535")
        return v


class FortiGateCredentialsInput(BaseModel):
    """FortiGate API-token credentials (for driver='fortigate').

    Stored Fernet-encrypted on ``DHCPServer.credentials_encrypted`` as
    ``{api_token, vdom, verify_tls}``. The token is never returned; the
    response echoes only ``has_credentials`` + the non-secret ``vdom``.

    All fields optional to support partial edits (change ``vdom`` /
    ``verify_tls`` without re-typing the token — the create endpoint still
    requires ``api_token`` on first set).
    """

    api_token: str | None = None
    vdom: str | None = None
    verify_tls: bool | None = None


class ServerCreate(BaseModel):
    name: str
    description: str = ""
    driver: str = "kea"
    host: str
    # None → resolved per-driver in the handler (443 for cloud/REST drivers like
    # FortiGate that dial HTTPS, 67 for agent/agentless DHCP daemons). A literal
    # 67 default would silently point a FortiGate at ``https://host:67`` (#630).
    port: int | None = None
    roles: list[str] = []
    server_group_id: uuid.UUID | None = None
    # Kea HA listener URL (this server's own endpoint). Empty string
    # = standalone / no HA. Only meaningful for Kea servers in a
    # group with another Kea peer.
    ha_peer_url: str = ""
    # Only used when driver='windows_dhcp' — ignored otherwise.
    windows_credentials: WindowsCredentialsInput | None = None
    # Provider credential dict for agentless cloud/REST drivers
    # (driver='fortigate' → {api_token, vdom, verify_tls}). Ignored for
    # other drivers.
    cloud_credentials: dict[str, Any] | None = None

    @field_validator("driver")
    @classmethod
    def _d(cls, v: str) -> str:
        if v not in VALID_DRIVERS:
            raise ValueError(f"driver must be one of {sorted(VALID_DRIVERS)}")
        return v


class ServerUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    driver: str | None = None
    host: str | None = None
    port: int | None = None
    roles: list[str] | None = None
    server_group_id: uuid.UUID | None = None
    ha_peer_url: str | None = None
    status: str | None = None
    # Pass a full ``WindowsCredentialsInput`` to replace creds; ``null``
    # (the default) leaves them untouched. To clear, set an empty dict
    # ``{}`` — server treats it as "remove credentials".
    windows_credentials: WindowsCredentialsInput | dict[str, Any] | None = None
    # Agentless cloud/REST creds (fortigate). Same contract: ``null`` =
    # leave, ``{}`` = clear, dict = decrypt-merge-reencrypt (so vdom /
    # verify_tls can change without re-typing the token).
    cloud_credentials: dict[str, Any] | None = None

    @field_validator("driver")
    @classmethod
    def _d(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_DRIVERS:
            raise ValueError(f"driver must be one of {sorted(VALID_DRIVERS)}")
        return v


class ServerResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    driver: str
    host: str
    port: int
    roles: list[str]
    server_group_id: uuid.UUID | None
    status: str
    last_sync_at: datetime | None
    last_health_check_at: datetime | None
    agent_registered: bool
    agent_approved: bool
    agent_last_seen: datetime | None
    last_seen_ip: str | None
    agent_version: str | None
    config_etag: str | None
    config_pushed_at: datetime | None
    has_credentials: bool
    is_agentless: bool
    is_read_only: bool
    # Non-secret FortiGate VDOM, echoed back from the decrypted credential
    # dict for cloud drivers so the edit modal can show / change it without
    # re-entering the token. Null for non-cloud drivers.
    vdom: str | None = None
    # Non-secret TLS-verify flag, echoed for cloud drivers so the edit modal
    # can seed the checkbox from the stored value instead of resetting it to a
    # hard-coded default (which would silently re-disable verification on any
    # unrelated edit). Null for non-cloud drivers.
    verify_tls: bool | None = None
    # Kea HA listener URL this server exposes to its partner.
    ha_peer_url: str = ""
    # Kea HA state — latest value reported by the agent's periodic
    # ``status-get`` poll. Null for standalone servers (group size < 2).
    ha_state: str | None = None
    ha_last_heartbeat_at: datetime | None = None
    # Per-server maintenance mode (issue #182).
    maintenance_mode: bool = False
    maintenance_started_at: datetime | None = None
    # #882 — last config-apply verdict reported by the agent.
    # ``ok`` / ``reverted`` / ``revert_failed`` / ``no_previous``; NULL when
    # the agent has never reported (a pre-#882 agent, or an agentless driver
    # with no apply loop). NULL means UNKNOWN, never "fine".
    config_apply_status: str | None = None
    config_apply_error: str | None = None
    config_failed_etag: str | None = None
    config_apply_at: datetime | None = None
    # #1077 — the agent's push spool as last reported on its heartbeat.
    # NULL when never reported (a pre-#1077 agent, or an agentless driver):
    # UNKNOWN, never "empty".
    spool_status: SpoolStatus | None = None
    # #1067 — the daemon state the agent reports on its heartbeat. ``ok`` or
    # ``degraded`` (the agent's own word; anything but ``ok`` is not serving);
    # NULL when the agent has never reported one — UNKNOWN, never "fine".
    # ``daemon_status_since`` is when the CURRENT status was first reported.
    daemon_status: str | None = None
    daemon_reason: str | None = None
    daemon_status_since: datetime | None = None
    maintenance_reason: str | None = None
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_model(cls, s: DHCPServer) -> ServerResponse:
        agentless = is_agentless(s.driver)
        # Echo the non-secret VDOM for cloud drivers (best-effort decrypt —
        # never surface the token, and never fail the response on a bad blob).
        vdom: str | None = None
        verify_tls: bool | None = None
        if is_cloud(s.driver) and s.credentials_encrypted:
            try:
                from app.core.crypto import decrypt_dict  # noqa: PLC0415

                _creds = decrypt_dict(s.credentials_encrypted)
                vdom = _creds.get("vdom")
                # Default the echo to True to match the secure create default
                # for rows stored before this field existed.
                verify_tls = bool(_creds.get("verify_tls", True))
            except Exception:  # noqa: BLE001 — never break the listing
                vdom = None
                verify_tls = None
        return cls(
            id=s.id,
            name=s.name,
            description=s.description,
            driver=s.driver,
            host=s.host,
            port=s.port,
            roles=list(s.roles or []),
            server_group_id=s.server_group_id,
            status=s.status,
            last_sync_at=s.last_sync_at,
            last_health_check_at=s.last_health_check_at,
            agent_registered=s.agent_registered,
            # Agentless drivers have no agent to approve, so "approval" is
            # a no-op concept for them. Return True unconditionally so the
            # UI doesn't display a bogus "pending approval" affordance on
            # windows_dhcp rows (including rows created before the
            # create-path auto-approve landed).
            agent_approved=True if agentless else s.agent_approved,
            agent_last_seen=s.agent_last_seen,
            last_seen_ip=s.last_seen_ip,
            agent_version=s.agent_version,
            config_etag=s.config_etag,
            config_pushed_at=s.config_pushed_at,
            has_credentials=bool(s.credentials_encrypted),
            is_agentless=agentless,
            is_read_only=is_read_only(s.driver),
            vdom=vdom,
            verify_tls=verify_tls,
            ha_peer_url=s.ha_peer_url or "",
            ha_state=s.ha_state,
            ha_last_heartbeat_at=s.ha_last_heartbeat_at,
            maintenance_mode=s.maintenance_mode,
            maintenance_started_at=s.maintenance_started_at,
            maintenance_reason=s.maintenance_reason,
            config_apply_status=s.config_apply_status,
            config_apply_error=s.config_apply_error,
            config_failed_etag=s.config_failed_etag,
            config_apply_at=s.config_apply_at,
            spool_status=s.spool_status,
            daemon_status=s.daemon_status,
            daemon_reason=s.daemon_reason,
            daemon_status_since=s.daemon_status_since,
            created_at=s.created_at,
            modified_at=s.modified_at,
        )


class ServerSyncResponse(BaseModel):
    """Result of ``POST /servers/{id}/sync``.

    Two shapes behind one route, which is why it needs its own model rather
    than the shared ``StatusResponse``: an agentless cloud driver reconciles
    scopes inline and reports how many; an agent-based one queues a config op
    and reports the op id + the bundle etag the agent will converge on.
    Whichever branch ran, the fields belonging to the other are ``null``.
    """

    status: str
    #: Cloud/agentless branch — scopes pushed in this reconcile.
    #:
    #: **Wire change (#917):** this was previously emitted as a JSON *string*
    #: (``"3"``) because the untyped handler returned ``dict[str, str]``.
    #: Typing the route corrected it to a number. Called out rather than
    #: slipped in: a change in a PR about client contracts is exactly the
    #: kind that should not be silent. No shipped caller reads it — the UI
    #: shows the audit row, not this field.
    scopes: int | None = None
    #: Agent branch — the queued ``dhcp_config_op`` and the bundle etag.
    op_id: uuid.UUID | None = None
    etag: str | None = None


class TestWindowsCredentialsRequest(BaseModel):
    """Pre-save dry-run: test a host + creds without writing them to the DB.

    For editing an existing server, omit ``credentials`` and pass the
    ``server_id`` — the endpoint decrypts the stored credentials and runs
    the same probe. If both are omitted, the request is rejected.
    """

    host: str
    credentials: WindowsCredentialsInput | None = None
    server_id: uuid.UUID | None = None


class TestResult(BaseModel):
    ok: bool
    message: str


class TestFortiGateCredentialsRequest(BaseModel):
    """Pre-save / post-save dry-run probe for a FortiGate DHCP server.

    * **Pre-save** — pass ``host`` + ``port`` + ``credentials`` (typed in
      the create/edit form). Nothing is written to the DB.
    * **Post-save** — pass ``server_id`` only; stored Fernet-encrypted
      credentials are decrypted and used. A partial ``credentials`` dict
      (e.g. a new ``vdom`` without the token) is merged with the stored
      blob when ``server_id`` is also supplied.
    """

    host: str | None = None
    port: int = 443
    credentials: FortiGateCredentialsInput | None = None
    server_id: uuid.UUID | None = None


class FortiGateExistingDHCPServer(BaseModel):
    """A DHCP-server object already present on a FortiGate interface — the
    preflight surfaces its counts so a destructive sync/adopt is visible."""

    mkey: int | None = None
    ip_range_count: int = 0
    reserved_count: int = 0
    option_count: int = 0
    # True when this object is one SpatiumDDI already owns (its mkey is
    # recorded in some scope's provider_refs), so adopting it is a no-op —
    # False means a plain sync would clobber operator-managed config.
    managed: bool = False


class FortiGateInterface(BaseModel):
    name: str
    cidr: str
    ip: str
    netmask: str
    status: str = ""
    alias: str = ""
    # Which managed scope (if any) this interface's CIDR matches.
    matched_subnet_id: uuid.UUID | None = None
    matched_scope_id: uuid.UUID | None = None
    # A pre-existing DHCP server on this interface, or null if none.
    existing_dhcp_server: FortiGateExistingDHCPServer | None = None


class SyncLeasesResponse(BaseModel):
    server_leases: int
    imported: int
    refreshed: int
    removed: int = 0
    ipam_created: int
    ipam_refreshed: int
    ipam_revoked: int = 0
    out_of_scope: int
    scopes_imported: int = 0
    scopes_refreshed: int = 0
    scopes_skipped_no_subnet: int = 0
    pools_synced: int = 0
    statics_synced: int = 0
    pools_removed: int = 0
    statics_removed: int = 0
    # #1110 — scopes this server holds whose import belongs to another member
    # of its group (one member imports a shared scope; the rest report).
    scopes_deferred: int = 0
    # MAC deny-filter reconciliation against the group's active blocks.
    # Zero when the server isn't in a group or has no blocks configured.
    mac_blocks_added: int = 0
    mac_blocks_removed: int = 0
    errors: list[str]
    # #1110 — standing conditions rather than failures of this sync: a scope
    # two Windows members serve uncoordinated, failover partners whose
    # configuration has drifted, a failover read that was denied.
    warnings: list[str] = []
    # Set on the agent-based no-op path (Kea): a human-readable explanation
    # that there was nothing to pull and the agent was nudged to re-poll its
    # config. ``None`` for the normal agentless lease-pull path.
    note: str | None = None


# #1110 — Kea serves every scope of its group through the bundle, and Windows
# serves the scopes the write-through puts on it. The two have no protocol in
# common: Kea's HA hook and Windows failover cannot coordinate, so a group
# with both kinds of member hands every Windows-held scope out twice. Refused
# at the two places a server joins a group from the API; an existing mixed
# group is surfaced on the group's Windows failover view instead.
_UNCOORDINATABLE_DRIVERS = frozenset({"kea", "windows_dhcp"})


async def _assert_driver_mix_allowed(
    db: DB, group_id: uuid.UUID | None, driver: str, *, exclude_server_id: uuid.UUID | None = None
) -> None:
    if group_id is None or driver not in _UNCOORDINATABLE_DRIVERS:
        return
    other = "windows_dhcp" if driver == "kea" else "kea"
    q = select(DHCPServer.name).where(
        DHCPServer.server_group_id == group_id, DHCPServer.driver == other
    )
    if exclude_server_id is not None:
        q = q.where(DHCPServer.id != exclude_server_id)
    clash = (await db.execute(q.limit(3))).scalars().all()
    if clash:
        kinds = {"kea": "Kea", "windows_dhcp": "Windows DHCP"}
        raise HTTPException(
            status_code=422,
            detail=(
                f"This server group already has {kinds[other]} members "
                f"({', '.join(clash)}). Kea and Windows DHCP servers cannot coordinate — "
                f"Kea's HA and Windows failover do not speak to each other — so a group "
                f"with both would hand out every scope's addresses from two servers that "
                f"do not know about each other. Put the {kinds[driver]} server in its own "
                f"server group."
            ),
        )


@router.get("", response_model=list[ServerResponse])
async def list_servers(db: DB, _: CurrentUser) -> list[ServerResponse]:
    res = await db.execute(select(DHCPServer).order_by(DHCPServer.name))
    return [ServerResponse.from_model(s) for s in res.scalars().all()]


@router.post("", response_model=ServerResponse, status_code=status.HTTP_201_CREATED)
async def create_server(body: ServerCreate, db: DB, user: SuperAdmin) -> ServerResponse:
    existing = await db.execute(select(DHCPServer).where(DHCPServer.name == body.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A DHCP server with that name exists")

    await _assert_driver_mix_allowed(db, body.server_group_id, body.driver)
    payload = body.model_dump(exclude={"windows_credentials", "cloud_credentials"})
    # Resolve the per-driver default port when the caller omitted it: cloud/REST
    # drivers (FortiGate) speak HTTPS on 443; agent/agentless DHCP daemons use 67.
    if payload.get("port") is None:
        payload["port"] = 443 if body.driver in CLOUD_DHCP_DRIVERS else 67
    s = DHCPServer(**payload)
    if body.driver == "windows_dhcp" and body.windows_credentials is not None:
        creds = body.windows_credentials.model_dump(exclude_none=True)
        if not creds.get("username") or not creds.get("password"):
            raise HTTPException(
                status_code=400,
                detail="windows_dhcp create requires both username and password",
            )
        # Fill in sensible defaults for optional fields not set by the client.
        creds.setdefault("transport", "ntlm")
        creds.setdefault("use_tls", False)
        creds.setdefault("verify_tls", False)
        # #426: HTTPS WinRM listens on 5986, not 5985 — derive the port
        # default from the (now-resolved) use_tls flag.
        creds.setdefault("winrm_port", 5986 if creds.get("use_tls") else 5985)
        s.credentials_encrypted = encrypt_dict(creds)
    elif body.driver in CLOUD_DHCP_DRIVERS:
        cloud = dict(body.cloud_credentials or {})
        if not cloud.get("api_token"):
            raise HTTPException(
                status_code=400,
                detail=f"{body.driver} create requires an 'api_token' in cloud_credentials",
            )
        cloud.setdefault("vdom", "root")
        # Secure-by-default: the FortiOS admin Bearer token is sensitive, so
        # verify the TLS chain unless the operator explicitly opts out. Any
        # ``ca_bundle_pem`` the caller supplied flows through untouched.
        cloud.setdefault("verify_tls", True)
        s.credentials_encrypted = encrypt_dict(cloud)
    # Agentless drivers have no agent to approve; skip the pending-approval
    # dance entirely so the UI doesn't show a bogus "Approve" button.
    if is_agentless(body.driver):
        s.agent_approved = True
    db.add(s)
    await db.flush()

    audit_payload = body.model_dump(
        mode="json", exclude={"windows_credentials", "cloud_credentials"}
    )
    audit_payload["windows_credentials_set"] = bool(body.windows_credentials)
    audit_payload["cloud_credentials_set"] = bool(body.cloud_credentials)
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="dhcp_server",
        resource_id=str(s.id),
        resource_display=s.name,
        new_value=audit_payload,
    )
    # #430 — a new member can flip a group from standalone to HA (≥2 Kea
    # members), re-rendering every peer's failover block. Wake the group so
    # survivors converge at ~0 s instead of the 12 s safety tick.
    if s.server_group_id is not None:
        collect_wake(dhcp_group_channel(s.server_group_id))
    await db.commit()
    await db.refresh(s)
    return ServerResponse.from_model(s)


@router.get("/{server_id}", response_model=ServerResponse)
async def get_server(server_id: uuid.UUID, db: DB, _: CurrentUser) -> ServerResponse:
    s = await db.get(DHCPServer, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Server not found")
    return ServerResponse.from_model(s)


@router.put("/{server_id}", response_model=ServerResponse)
async def update_server(
    server_id: uuid.UUID, body: ServerUpdate, db: DB, user: SuperAdmin
) -> ServerResponse:
    s = await db.get(DHCPServer, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Server not found")

    old_group_id = s.server_group_id
    old_ha_peer_url = s.ha_peer_url

    changes = body.model_dump(
        exclude_none=True, exclude={"windows_credentials", "cloud_credentials"}
    )
    target_group = changes.get("server_group_id", s.server_group_id)
    target_driver = changes.get("driver", s.driver)
    if target_group != s.server_group_id or target_driver != s.driver:
        await _assert_driver_mix_allowed(db, target_group, target_driver, exclude_server_id=s.id)
    for k, v in changes.items():
        setattr(s, k, v)

    # Wake the server's own long-poll on any update; if its group
    # membership or HA listener URL changed, also wake BOTH the old and
    # new group channels (a peer add/remove/move shifts the group bundle
    # for every member, not just this server).
    collect_wake(dhcp_server_channel(s.id))
    if s.server_group_id != old_group_id or s.ha_peer_url != old_ha_peer_url:
        for gid in (old_group_id, s.server_group_id):
            if gid is not None:
                collect_wake(dhcp_group_channel(gid))

    # Credentials handling:
    #   * None → leave alone
    #   * {}   → clear
    #   * dict with any subset of fields → decrypt-merge-reencrypt (so the
    #     UI can change just the transport/port/tls without re-typing the
    #     password).
    if body.windows_credentials is not None:
        if isinstance(body.windows_credentials, WindowsCredentialsInput):
            patch = body.windows_credentials.model_dump(exclude_none=True)
            if not patch:
                # Empty WindowsCredentialsInput — treat as no-op.
                pass
            elif s.credentials_encrypted:
                from app.core.crypto import decrypt_dict  # noqa: PLC0415

                existing = decrypt_dict(s.credentials_encrypted)
                existing.update(patch)
                s.credentials_encrypted = encrypt_dict(existing)
                changes["windows_credentials_updated"] = sorted(patch.keys())
            else:
                # No stored creds — require a full username/password on first set.
                if not patch.get("username") or not patch.get("password"):
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "First-time credentials require both username and "
                            "password (other fields are optional)."
                        ),
                    )
                patch.setdefault("transport", "ntlm")
                patch.setdefault("use_tls", False)
                patch.setdefault("verify_tls", False)
                # #426: TLS-aware port default (5986 for HTTPS WinRM).
                patch.setdefault("winrm_port", 5986 if patch.get("use_tls") else 5985)
                s.credentials_encrypted = encrypt_dict(patch)
                changes["windows_credentials_set"] = True
        elif body.windows_credentials == {}:
            s.credentials_encrypted = None
            changes["windows_credentials_cleared"] = True

    # Cloud/REST creds (fortigate): None → leave, {} → clear, dict → merge.
    if body.cloud_credentials is not None:
        if body.cloud_credentials == {}:
            s.credentials_encrypted = None
            changes["cloud_credentials_cleared"] = True
        else:
            patch = {k: v for k, v in body.cloud_credentials.items() if v is not None}
            if s.credentials_encrypted:
                from app.core.crypto import decrypt_dict  # noqa: PLC0415

                existing = decrypt_dict(s.credentials_encrypted)
                existing.update(patch)
                s.credentials_encrypted = encrypt_dict(existing)
                changes["cloud_credentials_updated"] = sorted(patch.keys())
            else:
                if not patch.get("api_token"):
                    raise HTTPException(
                        status_code=400,
                        detail="First-time cloud credentials require an 'api_token'.",
                    )
                patch.setdefault("vdom", "root")
                patch.setdefault("verify_tls", True)
                s.credentials_encrypted = encrypt_dict(patch)
                changes["cloud_credentials_set"] = True

    audit_payload = body.model_dump(
        mode="json", exclude_none=True, exclude={"windows_credentials", "cloud_credentials"}
    )
    if "windows_credentials_set" in changes:
        audit_payload["windows_credentials_set"] = True
    if "windows_credentials_cleared" in changes:
        audit_payload["windows_credentials_cleared"] = True
    if "cloud_credentials_set" in changes:
        audit_payload["cloud_credentials_set"] = True
    if "cloud_credentials_updated" in changes:
        audit_payload["cloud_credentials_updated"] = changes["cloud_credentials_updated"]
    if "cloud_credentials_cleared" in changes:
        audit_payload["cloud_credentials_cleared"] = True

    write_audit(
        db,
        user=user,
        action="update",
        resource_type="dhcp_server",
        resource_id=str(s.id),
        resource_display=s.name,
        changed_fields=list(changes.keys()),
        new_value=audit_payload,
    )
    await db.commit()
    await db.refresh(s)
    return ServerResponse.from_model(s)


@router.delete("/{server_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_server(server_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    s = await db.get(DHCPServer, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Server not found")
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="dhcp_server",
        resource_id=str(s.id),
        resource_display=s.name,
    )
    # #430 — capture the group before delete; removing a member can drop a
    # group out of HA, re-rendering the survivors' failover block. Wake it.
    gid = s.server_group_id
    await db.delete(s)
    if gid is not None:
        collect_wake(dhcp_group_channel(gid))
    await db.commit()


@router.post(
    "/{server_id}/sync",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ServerSyncResponse,
)
async def sync_server(
    server_id: uuid.UUID,
    db: DB,
    user: SuperAdmin,
    adopt_existing: bool = False,
) -> ServerSyncResponse:
    """Force a config push: rebuild the bundle, enqueue an apply_config op.

    Coalesces consecutive clicks: if an ``apply_config`` op is already
    pending for this server, reuse it instead of queueing another reload.

    Rejects read-only drivers (windows_dhcp): there's no config to push.

    ``adopt_existing`` (cloud/FortiGate only) opts in to overwriting a
    pre-existing provider DHCP object SpatiumDDI never created; without it a
    clobber-risk sync returns 409 so the operator can review the preflight.
    """
    s = await db.get(DHCPServer, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Server not found")
    if is_cloud(s.driver):
        # Agentless cloud/REST driver (FortiGate): no agent drains ops.
        # Do a synchronous full reconcile — push every active scope's whole
        # object to the provider. A REST failure raises CloudPushError (502)
        # and rolls the transaction back.
        if s.server_group_id is None:
            raise HTTPException(
                status_code=400,
                detail="Server is not in a group; attach it to a group with scopes first",
            )
        assert_safe_target(s.host, label="fortigate")
        scopes = list(
            (
                await db.execute(
                    select(DHCPScope).where(
                        DHCPScope.group_id == s.server_group_id,
                        DHCPScope.is_active.is_(True),
                    )
                )
            )
            .unique()
            .scalars()
            .all()
        )
        for scope in scopes:
            await push_cloud_scope_upsert(db, scope, adopt_existing=adopt_existing)
        s.last_sync_at = datetime.now(UTC)
        write_audit(
            db,
            user=user,
            action="dhcp.server.sync",
            resource_type="dhcp_server",
            resource_id=str(s.id),
            resource_display=s.name,
            new_value={"reconciled_scopes": len(scopes)},
        )
        await db.commit()
        return ServerSyncResponse(status="reconciled", scopes=len(scopes))
    if is_read_only(s.driver):
        raise HTTPException(
            status_code=400,
            detail=f"driver {s.driver!r} is read-only; use /sync-leases instead",
        )
    bundle = await build_config_bundle(db, s)
    s.config_etag = bundle.etag
    existing = await db.execute(
        select(DHCPConfigOp).where(
            DHCPConfigOp.server_id == s.id,
            DHCPConfigOp.op_type == "apply_config",
            DHCPConfigOp.status == "pending",
        )
    )
    op = existing.scalar_one_or_none()
    if op is None:
        op = DHCPConfigOp(
            server_id=s.id,
            op_type="apply_config",
            payload={"etag": bundle.etag},
            status="pending",
        )
        db.add(op)
        await db.flush()
    else:
        op.payload = {"etag": bundle.etag}
        await db.flush()
    collect_wake(dhcp_server_channel(s.id))
    write_audit(
        db,
        user=user,
        action="dhcp.server.sync",
        resource_type="dhcp_server",
        resource_id=str(s.id),
        resource_display=s.name,
        new_value={"etag": bundle.etag, "op_id": str(op.id)},
    )
    await db.commit()
    return ServerSyncResponse(status="queued", op_id=op.id, etag=bundle.etag)


@router.post("/test-windows-credentials", response_model=TestResult)
async def test_windows_credentials_endpoint(
    body: TestWindowsCredentialsRequest, db: DB, _user: SuperAdmin
) -> TestResult:
    """Dry-run WinRM probe — reach the host, run ``Get-DhcpServerVersion``.

    Two modes:
      * **Pre-save** (create/edit form) — pass plaintext ``credentials``
        and the typed ``host``. Nothing is written to the DB.
      * **Post-save** (existing server) — pass ``server_id`` only;
        stored Fernet-encrypted credentials are decrypted and used.
    """
    from app.core.crypto import decrypt_dict  # noqa: PLC0415

    if body.credentials is not None:
        creds = body.credentials.model_dump(exclude_none=True)
        if not creds.get("username") or not creds.get("password"):
            # Partial credentials (e.g. transport-only tweak) — merge with
            # stored if a server_id was also sent, else reject as ambiguous.
            if body.server_id is None:
                raise HTTPException(
                    status_code=400,
                    detail="Partial credentials require 'server_id' to merge with stored",
                )
            s = await db.get(DHCPServer, body.server_id)
            if s is None:
                raise HTTPException(status_code=404, detail="Server not found")
            if not s.credentials_encrypted:
                raise HTTPException(
                    status_code=400,
                    detail="Server has no stored credentials to merge against",
                )
            existing = decrypt_dict(s.credentials_encrypted)
            existing.update(creds)
            creds = existing
        creds.setdefault("transport", "ntlm")
        creds.setdefault("use_tls", False)
        creds.setdefault("verify_tls", False)
        # #426: HTTPS WinRM listens on 5986, not 5985 — derive the port
        # default from the (now-resolved) use_tls flag.
        creds.setdefault("winrm_port", 5986 if creds.get("use_tls") else 5985)
        host = body.host
    elif body.server_id is not None:
        s = await db.get(DHCPServer, body.server_id)
        if s is None:
            raise HTTPException(status_code=404, detail="Server not found")
        if not s.credentials_encrypted:
            raise HTTPException(status_code=400, detail="Server has no stored credentials to test")
        creds = decrypt_dict(s.credentials_encrypted)
        host = body.host or s.host
    else:
        raise HTTPException(
            status_code=400,
            detail="Provide either 'credentials' (dry-run) or 'server_id' (stored)",
        )

    ok, msg = await test_winrm_credentials(host, creds)
    return TestResult(ok=ok, message=msg)


@router.post("/test-fortigate-credentials", response_model=TestResult)
async def test_fortigate_credentials_endpoint(
    body: TestFortiGateCredentialsRequest, db: DB, _user: SuperAdmin
) -> TestResult:
    """Dry-run FortiOS probe — reach the FortiGate, list L3 interfaces."""
    from app.core.crypto import decrypt_dict  # noqa: PLC0415

    if body.credentials is not None:
        creds = body.credentials.model_dump(exclude_none=True)
        host = body.host
        port = body.port
        if not creds.get("api_token"):
            # Partial creds (e.g. vdom-only tweak) — merge with stored.
            if body.server_id is None:
                raise HTTPException(
                    status_code=400,
                    detail="Partial credentials require 'server_id' to merge with stored",
                )
            s = await db.get(DHCPServer, body.server_id)
            if s is None:
                raise HTTPException(status_code=404, detail="Server not found")
            if not s.credentials_encrypted:
                raise HTTPException(
                    status_code=400,
                    detail="Server has no stored credentials to merge against",
                )
            existing = decrypt_dict(s.credentials_encrypted)
            existing.update(creds)
            creds = existing
            host = host or s.host
            port = body.port or s.port
        creds.setdefault("vdom", "root")
        creds.setdefault("verify_tls", True)
    elif body.server_id is not None:
        s = await db.get(DHCPServer, body.server_id)
        if s is None:
            raise HTTPException(status_code=404, detail="Server not found")
        if not s.credentials_encrypted:
            raise HTTPException(status_code=400, detail="Server has no stored credentials to test")
        creds = decrypt_dict(s.credentials_encrypted)
        host = body.host or s.host
        port = body.port or s.port
    else:
        raise HTTPException(
            status_code=400,
            detail="Provide either 'credentials' (dry-run) or 'server_id' (stored)",
        )

    if not host:
        raise HTTPException(status_code=400, detail="host is required")
    assert_safe_target(host, label="fortigate")
    ok, msg = await test_fortigate_credentials(host, port, creds)
    return TestResult(ok=ok, message=msg)


@router.get("/{server_id}/fortigate-interfaces", response_model=list[FortiGateInterface])
async def fortigate_interfaces(
    server_id: uuid.UUID, db: DB, _user: SuperAdmin
) -> list[FortiGateInterface]:
    """Preflight: list the FortiGate's L3 interfaces + which managed scope
    each one's CIDR matches, so the operator sees what will bind before sync.
    """
    import ipaddress as _ipaddress  # noqa: PLC0415

    s = await db.get(DHCPServer, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Server not found")
    if s.driver not in CLOUD_DHCP_DRIVERS:
        raise HTTPException(
            status_code=400,
            detail=f"driver {s.driver!r} is not a FortiGate server",
        )
    assert_safe_target(s.host, label="fortigate")
    driver = get_driver(s.driver)
    try:
        ifaces = await driver.list_interfaces(s)  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001 — surface the FortiOS error cleanly
        raise HTTPException(
            status_code=502, detail=f"FortiGate interface query failed: {exc}"
        ) from exc

    # Build a CIDR → (subnet_id, scope_id) map for this server's group so we
    # can annotate which interface will bind to which scope. Also collect the
    # set of FortiOS mkeys SpatiumDDI already owns (from every scope's
    # provider_refs for THIS server) so the preflight can tell an adopt-safe
    # managed object apart from an operator's unmanaged one.
    scope_map: dict[str, tuple[uuid.UUID, uuid.UUID]] = {}
    owned_mkeys: set[int] = set()
    if s.server_group_id is not None:
        rows = (
            await db.execute(
                select(
                    DHCPScope.id,
                    DHCPScope.subnet_id,
                    DHCPScope.provider_refs,
                    Subnet.network,
                )
                .join(Subnet, Subnet.id == DHCPScope.subnet_id)
                .where(
                    DHCPScope.group_id == s.server_group_id,
                    DHCPScope.is_active.is_(True),
                )
            )
        ).all()
        for scope_id, subnet_id, provider_refs, network in rows:
            try:
                key = str(_ipaddress.ip_network(str(network), strict=False))
            except (ValueError, TypeError):
                continue
            scope_map[key] = (subnet_id, scope_id)
            ref = (provider_refs or {}).get(str(s.id)) if provider_refs else None
            if isinstance(ref, dict):
                try:
                    owned_mkeys.add(int(ref["mkey"]))
                except (KeyError, TypeError, ValueError):
                    # A ref with a missing or non-numeric mkey means we never
                    # successfully pushed this scope to the FortiGate, so there
                    # is no object of ours to claim. Leaving it out of
                    # owned_mkeys is the correct outcome: any DHCP server the
                    # preflight finds on that interface is then reported as
                    # unmanaged, which is the safe side to err on (we refuse to
                    # adopt it rather than silently clobbering operator config).
                    pass

    out: list[FortiGateInterface] = []
    for iface in ifaces:
        try:
            key = str(_ipaddress.ip_network(iface["cidr"], strict=False))
        except (ValueError, TypeError):
            key = iface.get("cidr", "")
        match = scope_map.get(key)
        existing_raw = iface.get("existing_dhcp_server")
        existing: FortiGateExistingDHCPServer | None = None
        if isinstance(existing_raw, dict):
            mkey = existing_raw.get("mkey")
            existing = FortiGateExistingDHCPServer(
                mkey=mkey,
                ip_range_count=int(existing_raw.get("ip_range_count", 0) or 0),
                reserved_count=int(existing_raw.get("reserved_count", 0) or 0),
                option_count=int(existing_raw.get("option_count", 0) or 0),
                managed=(isinstance(mkey, int) and mkey in owned_mkeys),
            )
        out.append(
            FortiGateInterface(
                name=iface.get("name", ""),
                cidr=iface.get("cidr", ""),
                ip=iface.get("ip", ""),
                netmask=iface.get("netmask", ""),
                status=iface.get("status", ""),
                alias=iface.get("alias", ""),
                matched_subnet_id=match[0] if match else None,
                matched_scope_id=match[1] if match else None,
                existing_dhcp_server=existing,
            )
        )
    return out


@router.post("/{server_id}/sync-leases", response_model=SyncLeasesResponse)
async def sync_leases_now(server_id: uuid.UUID, db: DB, user: SuperAdmin) -> SyncLeasesResponse:
    """Poll the DHCP server for current leases and reconcile into the DB.

    Only valid for agentless drivers (windows_dhcp, fortigate). Agent-based
    drivers stream lease events continuously and don't need polling.
    """
    s = await db.get(DHCPServer, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Server not found")
    if not is_agentless(s.driver):
        # Agent-based drivers (Kea) stream lease events continuously and pick
        # up scope/config changes through the ConfigBundle long-poll, so there
        # is nothing to *pull*. Returning 400 here made the IPAM "Sync → DHCP"
        # action look broken for operators whose subnet is backed by a Kea
        # appliance (#453) — the modal fans this endpoint out to every server
        # behind the subnet, agent-based ones included. Instead, nudge the
        # agent to re-poll its config now so the subnet/scope definition
        # converges immediately, and return a no-op result with an explanatory
        # note rather than an error.
        await publish_wake(*dhcp_wake_channels(s))
        return SyncLeasesResponse(
            server_leases=0,
            imported=0,
            refreshed=0,
            ipam_created=0,
            ipam_refreshed=0,
            out_of_scope=0,
            errors=[],
            note=(
                f"{s.driver} is agent-based: leases stream live from the agent and the "
                "scope/subnet definition converges automatically via the agent's config "
                "poll. Nudged the agent to re-poll now."
            ),
        )
    result = await pull_leases_from_server(db, s, apply=True)

    # Reconcile the server's MAC deny-filter list against the group's
    # active blocks while we're already holding the WinRM session up.
    # Any driver error here is reported as an extra entry in `errors`
    # rather than failing the whole sync — lease pull is the primary
    # job; mac-block reconciliation is a best-effort piggy-back.
    mac_added = 0
    mac_removed = 0
    if s.server_group_id is not None:
        now = datetime.now(UTC)
        mb_rows = list(
            (
                await db.execute(
                    select(DHCPMACBlock).where(
                        DHCPMACBlock.group_id == s.server_group_id,
                        DHCPMACBlock.enabled.is_(True),
                        or_(
                            DHCPMACBlock.expires_at.is_(None),
                            DHCPMACBlock.expires_at > now,
                        ),
                    )
                )
            )
            .scalars()
            .all()
        )
        desired = [
            MACBlockDef(
                mac_address=str(r.mac_address).lower(),
                reason=r.reason or "other",
                description=r.description or "",
            )
            for r in mb_rows
        ]
        try:
            driver = get_driver(s.driver)
            mac_added, mac_removed = await driver.sync_mac_blocks(s, desired=desired)
        except Exception as exc:  # noqa: BLE001 — don't fail the lease sync
            result.errors.append(f"sync_mac_blocks failed: {exc}")

    write_audit(
        db,
        user=user,
        action="dhcp.server.sync-leases",
        resource_type="dhcp_server",
        resource_id=str(s.id),
        resource_display=s.name,
        new_value={
            "server_leases": result.server_leases,
            "imported": result.imported,
            "refreshed": result.refreshed,
            "removed": result.removed,
            "ipam_created": result.ipam_created,
            "ipam_refreshed": result.ipam_refreshed,
            "ipam_revoked": result.ipam_revoked,
            "out_of_scope": result.out_of_scope,
            "scopes_imported": result.scopes_imported,
            "scopes_refreshed": result.scopes_refreshed,
            "scopes_skipped_no_subnet": result.scopes_skipped_no_subnet,
            "pools_synced": result.pools_synced,
            "statics_synced": result.statics_synced,
            "pools_removed": result.pools_removed,
            "statics_removed": result.statics_removed,
            "scopes_deferred": result.scopes_deferred,
            "mac_blocks_added": mac_added,
            "mac_blocks_removed": mac_removed,
            "errors": result.errors[:20],
            "warnings": result.warnings[:20],
        },
    )
    await db.commit()
    return SyncLeasesResponse(
        server_leases=result.server_leases,
        imported=result.imported,
        refreshed=result.refreshed,
        removed=result.removed,
        ipam_created=result.ipam_created,
        ipam_refreshed=result.ipam_refreshed,
        ipam_revoked=result.ipam_revoked,
        out_of_scope=result.out_of_scope,
        scopes_imported=result.scopes_imported,
        scopes_refreshed=result.scopes_refreshed,
        scopes_skipped_no_subnet=result.scopes_skipped_no_subnet,
        pools_synced=result.pools_synced,
        statics_synced=result.statics_synced,
        pools_removed=result.pools_removed,
        statics_removed=result.statics_removed,
        scopes_deferred=result.scopes_deferred,
        mac_blocks_added=mac_added,
        mac_blocks_removed=mac_removed,
        errors=result.errors,
        warnings=result.warnings,
    )


@router.post("/{server_id}/approve", response_model=ServerResponse)
async def approve_server(server_id: uuid.UUID, db: DB, user: SuperAdmin) -> ServerResponse:
    s = await db.get(DHCPServer, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Server not found")
    s.agent_approved = True
    collect_wake(dhcp_server_channel(s.id))
    write_audit(
        db,
        user=user,
        action="dhcp.server.approve",
        resource_type="dhcp_server",
        resource_id=str(s.id),
        resource_display=s.name,
    )
    await db.commit()
    await db.refresh(s)
    return ServerResponse.from_model(s)


# ── Maintenance mode (issue #182) ────────────────────────────────────


class MaintenancePauseRequest(BaseModel):
    """Body for ``POST /dhcp/servers/{id}/pause`` — reason is optional but
    strongly encouraged so the audit trail explains *why* an operator
    took a server offline."""

    reason: str | None = None


@router.post("/{server_id}/pause", response_model=ServerResponse)
async def pause_server(
    server_id: uuid.UUID,
    body: MaintenancePauseRequest,
    db: DB,
    user: SuperAdmin,
) -> ServerResponse:
    """Mark this DHCP server as in operator-set maintenance mode.

    Effects of the flag:
      * pending DHCPConfigOp rows aren't shipped to the agent
      * heartbeat-stale alerts auto-resolve and won't re-fire
      * HA peer accounting treats the server as expected-but-quiet
    The container itself isn't stopped from this endpoint; appliance
    deployments use the supervisor to act on the flag (planned), and
    docker / k8s operators stop the container however they normally
    would. The point is to silence the noise about it.
    """
    s = await db.get(DHCPServer, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Server not found")
    # Idempotent — re-pausing an already-paused server just refreshes
    # the reason (operator may have figured out *why* mid-window and
    # wants the audit trail updated). started_at stays anchored on the
    # original transition so the UI's "Paused 2h ago" doesn't reset.
    was_paused = s.maintenance_mode
    s.maintenance_mode = True
    if not was_paused:
        s.maintenance_started_at = datetime.now(UTC)
    if body.reason is not None:
        s.maintenance_reason = body.reason.strip() or None
    write_audit(
        db,
        user=user,
        action=(
            "dhcp.server.maintenance_entered"
            if not was_paused
            else "dhcp.server.maintenance_updated"
        ),
        resource_type="dhcp_server",
        resource_id=str(s.id),
        resource_display=s.name,
        new_value={"reason": s.maintenance_reason},
    )
    await db.commit()
    await db.refresh(s)
    return ServerResponse.from_model(s)


@router.post("/{server_id}/resume", response_model=ServerResponse)
async def resume_server(
    server_id: uuid.UUID,
    db: DB,
    user: SuperAdmin,
) -> ServerResponse:
    """Exit maintenance mode — pending ops resume shipping, alerts
    fire normally, HA accounting treats the server as live again.

    Operator is expected to have already started the container if
    they stopped it themselves; we don't dispatch a start command
    from here (it'd be too easy to surprise someone whose container
    is intentionally still down).
    """
    s = await db.get(DHCPServer, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Server not found")
    if not s.maintenance_mode:
        # Idempotent — already running normally. Return current state
        # without writing an audit row.
        return ServerResponse.from_model(s)
    s.maintenance_mode = False
    s.maintenance_started_at = None
    s.maintenance_reason = None
    # Resuming flips pending-op shipping back on, so wake the long-poll
    # immediately. (Pause must NOT wake — it only quiets the server.)
    collect_wake(dhcp_server_channel(s.id))
    write_audit(
        db,
        user=user,
        action="dhcp.server.maintenance_exited",
        resource_type="dhcp_server",
        resource_id=str(s.id),
        resource_display=s.name,
    )
    await db.commit()
    await db.refresh(s)
    return ServerResponse.from_model(s)


# ── Server Detail modal endpoints (issue #181) ───────────────────────
#
# Mirrors the per-server endpoints on the DNS side (zone-state /
# pending-ops / recent-events / rendered-config). The DHCP equivalents
# are simpler: no per-zone state since Kea bundles are applied
# atomically, no agent-pushed rendered config snapshot (we render from
# the current bundle on demand). Used by the DHCP ServerDetailModal in
# the frontend; same shape contract as DNS so the UI tabs feel
# identical.


class DHCPPendingOpEntry(BaseModel):
    op_id: str
    op_type: str
    status: str
    attempts: int
    error_msg: str | None
    created_at: datetime
    acked_at: datetime | None

    @field_validator("op_id", mode="before")
    @classmethod
    def _coerce_op_id(cls, v: object) -> str:
        return str(v)


class DHCPPendingOpsResponse(BaseModel):
    server_id: uuid.UUID
    counts: dict[str, int]
    items: list[DHCPPendingOpEntry]


@router.get(
    "/{server_id}/pending-ops",
    response_model=DHCPPendingOpsResponse,
)
async def get_server_pending_ops(
    server_id: uuid.UUID, db: DB, _: CurrentUser, limit: int = 50
) -> DHCPPendingOpsResponse:
    """Queued / in-flight / recently-applied / failed config ops.

    Drives the ServerDetailModal's "Sync" tab. The counts dict keys
    on ``status`` (``pending`` / ``in_flight`` / ``applied`` /
    ``failed``). Items are ordered by ``created_at DESC`` and capped
    at ``limit``.
    """
    server = await db.get(DHCPServer, server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="Server not found")

    counts_res = await db.execute(
        select(DHCPConfigOp.status, func.count())
        .where(DHCPConfigOp.server_id == server_id)
        .group_by(DHCPConfigOp.status)
    )
    counts: dict[str, int] = {row[0]: int(row[1]) for row in counts_res.all()}

    ops_res = await db.execute(
        select(DHCPConfigOp)
        .where(DHCPConfigOp.server_id == server_id)
        .order_by(DHCPConfigOp.created_at.desc())
        .limit(limit)
    )
    items = [
        DHCPPendingOpEntry(
            op_id=str(op.id),
            op_type=op.op_type,
            status=op.status,
            attempts=op.attempts,
            error_msg=op.error_msg,
            created_at=op.created_at,
            acked_at=op.acked_at,
        )
        for op in ops_res.scalars().all()
    ]
    return DHCPPendingOpsResponse(
        server_id=server.id,
        counts=counts,
        items=items,
    )


class DHCPServerEventEntry(BaseModel):
    id: str
    timestamp: datetime
    user_display_name: str
    action: str
    resource_type: str
    resource_display: str
    result: str

    @field_validator("id", mode="before")
    @classmethod
    def _coerce_id(cls, v: object) -> str:
        return str(v)


class DHCPServerEventsResponse(BaseModel):
    server_id: uuid.UUID
    items: list[DHCPServerEventEntry]


@router.get(
    "/{server_id}/recent-events",
    response_model=DHCPServerEventsResponse,
)
async def get_server_recent_events(
    server_id: uuid.UUID, db: DB, _: CurrentUser, limit: int = 50
) -> DHCPServerEventsResponse:
    """Audit-log rows where ``resource_id`` matches this DHCP server.

    Drives the ServerDetailModal's "Events" tab. Matches the DNS
    side's contract verbatim.
    """
    server = await db.get(DHCPServer, server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="Server not found")

    rows = (
        (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.resource_id == str(server_id))
                .order_by(AuditLog.timestamp.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    items = [
        DHCPServerEventEntry(
            id=str(r.id),
            timestamp=r.timestamp,
            user_display_name=r.user_display_name,
            action=r.action,
            resource_type=r.resource_type,
            resource_display=r.resource_display,
            result=r.result,
        )
        for r in rows
    ]
    return DHCPServerEventsResponse(server_id=server.id, items=items)


class DHCPRenderedConfigResponse(BaseModel):
    server_id: uuid.UUID
    driver: str
    etag: str
    rendered_at: datetime
    # Kea config as JSON text. Empty for read-only drivers (windows_dhcp)
    # which have no on-disk config we render.
    config: str


@router.get(
    "/{server_id}/rendered-config",
    response_model=DHCPRenderedConfigResponse,
)
async def get_server_rendered_config(
    server_id: uuid.UUID, db: DB, _: CurrentUser
) -> DHCPRenderedConfigResponse:
    """Render this server's current ConfigBundle through its driver.

    A **preview** of what is in flight — the subnets, pools, classes,
    options and group tunables the agent will apply — not a copy of the
    file it writes. The driver-side render deliberately omits the daemon
    plumbing the agent adds (control socket, hooks, timers, expired-lease
    processing, the full logger block) and does not parse as a Kea config
    on its own. Useful for checking a setting took without SSHing into the
    agent; not for diffing against ``kea-dhcp4.conf``.

    Read-only drivers (``windows_dhcp``) return an empty ``config``
    payload since there's no rendered config to show; the UI tab handles
    that case.
    """
    server = await db.get(DHCPServer, server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="Server not found")

    if is_read_only(server.driver):
        return DHCPRenderedConfigResponse(
            server_id=server.id,
            driver=server.driver,
            etag="",
            rendered_at=datetime.now(UTC),
            config="",
        )

    bundle = await build_config_bundle(db, server)
    try:
        driver = get_driver(server.driver)
    except KeyError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"unknown driver {server.driver!r}",
        ) from exc
    rendered = driver.render_config(bundle)
    return DHCPRenderedConfigResponse(
        server_id=server.id,
        driver=server.driver,
        etag=bundle.etag,
        rendered_at=bundle.generated_at,
        config=rendered,
    )


@router.get("/{server_id}/leases", response_model=Page[LeaseResponse])
async def list_leases(
    server_id: uuid.UUID,
    db: DB,
    _: CurrentUser,
    search: str | None = Query(None, description="substring over ip / mac / hostname"),
    state: str | None = Query(None, description="exact lease state filter"),
    device_class: str | None = None,
    page: int = Query(1, ge=1, le=MAX_PAGE),
    page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
) -> Page[LeaseResponse]:
    """Leases for a server, server-side paginated (#455), enriched with OUI
    vendor + fingerbank device class (#373).

    A busy server's older leases used to be unreachable past the most-recent N.
    ``search`` matches ip / mac / hostname; ``state`` and ``device_class`` are
    exact filters (the latter joins the fingerprint table so the page lands on
    matching rows). When fingerprinting is off the device fields are blank.
    """
    s = await db.get(DHCPServer, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Server not found")
    q = apply_lease_filters(
        select(DHCPLease).where(DHCPLease.server_id == server_id),
        search=search,
        state=state,
        device_class=device_class,
    ).order_by(DHCPLease.last_seen_at.desc())
    rows, total = await paginate(db, q, page=page, page_size=page_size)
    await enrich_leases(db, rows)
    return Page[LeaseResponse](
        items=[LeaseResponse.model_validate(lease) for lease in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.delete(
    "/{server_id}/leases/{lease_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def delete_lease(server_id: uuid.UUID, lease_id: uuid.UUID, db: DB, user: SuperAdmin) -> Any:
    """Manually delete a single lease + its ``auto_from_lease`` IPAM mirror.

    Agent-based (Kea) servers have no absence-delete reconciler (pull_leases is
    agentless-only), so an ``expired`` lease otherwise lingers in the view until
    the 24h GC sweep — this lets an operator drop one now (#478). Scoped to the
    lease's own subnet so an overlapping same-address mirror in another
    IPSpace/VRF is untouched; stamps ``removed`` history, revokes any DDNS the
    mirror published, and audits.
    """
    lease = await db.get(DHCPLease, lease_id)
    if lease is None or lease.server_id != server_id:
        raise HTTPException(status_code=404, detail="Lease not found")

    # Shared teardown: resolve the lease's subnet (scope-FK-first / prefix-match),
    # revoke any DDNS the mirror published, delete the auto_from_lease mirror, stamp
    # ``removed`` history, delete the lease. Same helper the pull-leases
    # absence-delete branch and scope deletion use (#329, DRY).
    from app.services.dhcp.lease_cleanup import purge_lease

    ip = str(lease.ip_address)
    mirror_removed = await purge_lease(db, lease)
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="dhcp_lease",
        resource_id=str(lease_id),
        resource_display=ip,
        new_value={"ip_address": ip, "mirror_removed": mirror_removed},
    )
    await db.commit()
    return None


# --- Per-server stats (#195) ------------------------------------------------
# The range -> window/bucket maps + the active-lease count live in
# app.services.dhcp.stats so this endpoint and the find_dhcp_server_stats MCP
# tool stay in lockstep.


class DHCPRateBucket(BaseModel):
    """One time bucket of DHCP message-type counts (#195) and loss (#980).

    The 7 message-type keys are the pinned #195 contract — ``inform`` is
    summed in the DB but dropped here to match it. The two loss counters
    were added by #980 and are ``None``, never 0, when no sample in the
    bucket reported them: an agent older than #980 measures neither, and a
    bucket of zeroes from such an agent is the false "nothing was lost" this
    endpoint exists to stop showing.
    """

    ts: datetime
    discover: int
    offer: int
    request: int
    ack: int
    nak: int
    decline: int
    release: int
    # Packets Kea read and discarded (unparseable, DROP class, no subnet).
    receive_drop: int | None = None
    # Packets the kernel dropped before Kea could read them, because its
    # receive buffer was full. The one that moves when a node is short of
    # CPU; ``receive_drop`` stays at 0 through exactly that failure.
    socket_drop: int | None = None


class DHCPServerStatsResponse(BaseModel):
    leases_active: int
    range: str
    bucket_seconds: int
    rate_buckets: list[DHCPRateBucket]


@router.get("/{server_id}/stats", response_model=DHCPServerStatsResponse)
async def get_server_stats(
    server_id: uuid.UUID,
    db: DB,
    _: CurrentUser,
    range: str = "1h",
) -> DHCPServerStatsResponse:
    """Lease-rate timeseries + active lease count for the modal Stats tab (#195).

    Aggregates ``DHCPMetricSample`` (agent-reported Kea pkt4 counter deltas)
    into fixed time buckets, plus the current active lease count. Read-only:
    no audit_log write (this endpoint performs no mutation).

    Empty servers / windows return ``leases_active`` and an empty
    ``rate_buckets`` list without error — the UI shows a "no activity"
    empty state. ``date_bin`` emits rows only for buckets that have samples
    (sparse), so empty windows naturally yield ``[]``; the client renders
    whatever points exist. Agentless (windows_dhcp, fortigate) servers are not
    special-cased — they return synced ``leases_active`` and empty
    ``rate_buckets`` (no Kea metric stream); the frontend hides the tab for
    them anyway.
    """
    if range not in STATS_WINDOW_SECONDS:
        raise HTTPException(
            status_code=400,
            detail=f"range must be one of {sorted(STATS_WINDOW_SECONDS)}",
        )
    server = await db.get(DHCPServer, server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="Server not found")

    bucket_s = STATS_BUCKET_SECONDS[range]
    since = datetime.now(UTC) - timedelta(seconds=STATS_WINDOW_SECONDS[range])

    leases_active = await active_lease_count(db, server_id)

    # Bucketed message-type sums. date_bin anchors buckets on stable
    # boundaries across requests (same pattern as /metrics/dhcp/timeseries).
    # coalesce keeps the per-bucket sums non-null so the rows map straight to
    # ints (matches the find_dhcp_server_stats tool's SQL-side null handling).
    bucket_col = func.date_bin(
        timedelta(seconds=bucket_s),
        DHCPMetricSample.bucket_at,
        datetime(2000, 1, 1, tzinfo=UTC),
    ).label("ts")
    stmt = (
        select(
            bucket_col,
            func.coalesce(func.sum(DHCPMetricSample.discover), 0).label("discover"),
            func.coalesce(func.sum(DHCPMetricSample.offer), 0).label("offer"),
            func.coalesce(func.sum(DHCPMetricSample.request), 0).label("request"),
            func.coalesce(func.sum(DHCPMetricSample.ack), 0).label("ack"),
            func.coalesce(func.sum(DHCPMetricSample.nak), 0).label("nak"),
            func.coalesce(func.sum(DHCPMetricSample.decline), 0).label("decline"),
            func.coalesce(func.sum(DHCPMetricSample.release), 0).label("release"),
            # #980 — deliberately NOT coalesced. SUM over an all-NULL group
            # is NULL, which is the answer: nothing in this bucket measured
            # loss. A partially-measured bucket sums the samples that did.
            func.sum(DHCPMetricSample.receive_drop).label("receive_drop"),
            func.sum(DHCPMetricSample.socket_drop).label("socket_drop"),
        )
        .where(DHCPMetricSample.server_id == server_id)
        .where(DHCPMetricSample.bucket_at >= since)
        .group_by(bucket_col)
        .order_by(bucket_col)
    )
    rows = (await db.execute(stmt)).all()
    rate_buckets = [
        DHCPRateBucket(
            ts=r._mapping["ts"],
            discover=int(r.discover or 0),
            offer=int(r.offer or 0),
            request=int(r.request or 0),
            ack=int(r.ack or 0),
            nak=int(r.nak or 0),
            decline=int(r.decline or 0),
            release=int(r.release or 0),
            # ``is None`` rather than ``or``: 0 is a real, measured value.
            receive_drop=None if r.receive_drop is None else int(r.receive_drop),
            socket_drop=None if r.socket_drop is None else int(r.socket_drop),
        )
        for r in rows
    ]
    return DHCPServerStatsResponse(
        leases_active=int(leases_active),
        range=range,
        bucket_seconds=bucket_s,
        rate_buckets=rate_buckets,
    )
