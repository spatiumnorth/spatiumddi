"""DHCP agent endpoints: register, heartbeat, config long-poll, lease ingestion, ops ack.

Mirrors ``app.api.v1.dns.agents``. See docs/deployment/DNS_AGENT.md for the
protocol shape — DHCP reuses identical semantics.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from jose import JWTError
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select

from app.api.deps import DB
from app.api.v1.dhcp._audit import write_audit
from app.core.agent_wake import (
    WAKE_TICK_SECONDS,
    dhcp_wake_channels,
    wake_subscription,
)
from app.core.dns_names import sanitize_hostname
from app.core.http_etag import etag_matches, format_etag
from app.drivers.dhcp.kea import option_defs_for_option_maps
from app.models.dhcp import (
    DHCPConfigOp,
    DHCPLease,
    DHCPServer,
    DHCPServerGroup,
)
from app.models.logs import DHCPLogEntry
from app.models.metrics import DHCPMetricSample
from app.models.settings import PlatformSettings
from app.services.agents.config_apply import apply_reported_status
from app.services.agents.daemon_state import apply_reported_daemon_state
from app.services.agents.ingest_receipt import (
    BatchId,
    IngestAck,
    claim_batch,
    duplicate_response,
)
from app.services.agents.spool_status import apply_reported_spool
from app.services.appliance.lldp import lldp_bundle
from app.services.appliance.ntp import ntp_bundle
from app.services.appliance.resolver import resolver_bundle
from app.services.appliance.snmp import snmp_bundle
from app.services.appliance.ssh import ssh_bundle
from app.services.appliance.syslog import syslog_bundle
from app.services.dhcp.agent_token import (
    hash_token,
    mint_agent_token,
    needs_rotation,
    verify_agent_token,
)
from app.services.dhcp.config_bundle import build_config_bundle
from app.services.dhcp.ipam_mirror import insert_ipam_mirror_row
from app.services.dhcp.lease_cleanup import peer_holds_active_lease
from app.services.dhcp.normalize import canonical_duid, norm_duid, norm_ip, norm_mac
from app.tasks.prune_logs import DEFAULT_RETENTION_HOURS as ACTIVITY_LOG_RETENTION_HOURS

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/agents", tags=["dhcp-agents"])

LONGPOLL_TIMEOUT_SECONDS = int(os.environ.get("DHCP_AGENT_LONGPOLL_TIMEOUT", "30"))
LONGPOLL_POLL_INTERVAL = 2.0


# ── Schemas ─────────────────────────────────────────────────────────────────


class AgentRegisterRequest(BaseModel):
    # Bounds mirror the columns these land in (DHCPServer.name/host 255,
    # .driver 50, .agent_fingerprint 128, DHCPServerGroup.name 255) — an
    # over-length value used to reach asyncpg and surface as 500 instead
    # of the 422 it is.
    hostname: str = Field(max_length=255)
    driver: str = Field(default="kea", max_length=50)
    roles: list[str] = ["standalone"]
    version: str | None = Field(default=None, max_length=64)
    group_name: str | None = Field(default=None, max_length=255)
    fingerprint: str = Field(max_length=128)
    agent_id: str | None = None


class AgentRegisterResponse(BaseModel):
    server_id: str
    agent_id: str
    agent_token: str
    token_expires_at: datetime
    config_etag: str | None
    pending_approval: bool


class AgentHeartbeatRequest(BaseModel):
    # #482 — reject a wrong-envelope heartbeat loudly instead of validating
    # into an all-default body (ops_ack=[] → the ACK loop runs 0× → 200 → the
    # agent clears its ACK buffer, losing the ACKs). Mirrors the DNS heartbeat
    # hardening (#430 D4). forbid requires this model to be a strict SUPERSET
    # of every field any DHCP agent sends: the pid / status /
    # lease_count_since_start telemetry below is accepted-but-unused so the
    # current agent's body validates, and the Phase 8f-2 slot fields keep
    # pre-Wave-C1 agents valid too.
    model_config = ConfigDict(extra="forbid")

    # Bounded to the column (String(64)); the heartbeat is the OTHER route
    # the same value arrives by, and leaving it unbounded here would let
    # an over-length version in through the side door that register now
    # rejects at the field.
    agent_version: str | None = Field(default=None, max_length=64)
    # #637 — running Kea daemon version, e.g. "3.0.3". MUST be declared here:
    # this model is extra="forbid", so an undeclared field would 422 every
    # heartbeat from a current agent.
    kea_version: str | None = None
    daemon: dict[str, Any] = {}
    # #882 — the agent's last config-apply verdict:
    # ``{status, etag, failed_etag, phase, error}``. See the DNS agent's
    # AgentHeartbeatRequest for why this stays a loose dict.
    config: dict[str, Any] = {}
    # #1077 — the agent's durable push spool (``SpoolManager.status()``):
    # bytes / entries queued, oldest entry, cumulative trim counters and a
    # per-stream breakdown. Loose dict at the edge for the same reason as
    # ``config``; ``apply_reported_spool`` validates it against
    # ``SpoolStatus`` and ignores (with a log line) a malformed report rather
    # than 422-ing the heartbeat. Absent (None) on a pre-#1077 agent, which
    # leaves the stored value untouched.
    spool: dict[str, Any] | None = None
    # Bound the ACK list so a malformed / hostile heartbeat can't pin memory.
    ops_ack: list[dict[str, Any]] = Field(default_factory=list, max_length=5000)
    failed_ops_count: int = 0
    # Accepted-but-unused telemetry the current DHCP agent ships every beat
    # (agent/dhcp/spatium_dhcp_agent/heartbeat.py). Listed so extra="forbid"
    # doesn't 422 a real heartbeat; the handler doesn't read them today.
    pid: int | None = None
    status: str | None = None
    lease_count_since_start: int | None = None
    # Phase 8f-2 — agent reports its slot state + deployment environment.
    # See DNSServer agents.py for the per-field semantics. All optional
    # so older agents keep heartbeating without a 422.
    deployment_kind: str | None = None
    installed_appliance_version: str | None = None
    current_slot: str | None = None
    durable_default: str | None = None
    is_trial_boot: bool | None = None
    last_upgrade_state: str | None = None
    last_upgrade_state_at: datetime | None = None


class AgentHeartbeatResponse(BaseModel):
    server_id: str
    status: str
    acknowledged_at: datetime
    rotated_token: str | None = None
    rotated_expires_at: datetime | None = None


class HAStatusReport(BaseModel):
    """One ``ha-status-get`` observation, relayed upstream by the agent.

    ``state`` matches the Kea state names verbatim so the UI can
    present them without translation (``waiting`` / ``syncing`` /
    ``ready`` / ``normal`` / ``communications-interrupted`` /
    ``partner-down`` / ``hot-standby`` / ``load-balancing`` /
    ``backup`` / ``passive-backup`` / ``terminated``).

    ``raw`` carries the full Kea response so future additions like
    ``unsent-update-count`` / ``in-touch`` show up in the UI without a
    schema change here.
    """

    state: str
    raw: dict[str, Any] | None = None


class LeaseEvent(BaseModel):
    ip_address: str
    # Required on a DHCPv4 lease — it is the lease's identity. Optional on a
    # DHCPv6 one (#1141): Kea records a hardware address only when it can
    # derive one, so most v6 leases arrive without; it is enrichment there.
    mac_address: str | None = None
    # DHCPv6 identity (#1141), required on a v6 lease: the client DUID and
    # the IA's IAID — what Kea itself keys a v6 lease on.
    duid: str | None = None
    iaid: int | None = Field(default=None, ge=0, le=0xFFFFFFFF)
    hostname: str | None = None
    client_id: str | None = None
    user_class: str | None = None
    state: str = "active"
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    expires_at: datetime | None = None

    @field_validator("hostname")
    @classmethod
    def _sanitize_client_hostname(cls, v: str | None) -> str | None:
        # The client-supplied DHCP hostname arrives off the wire and flows
        # into IPAM.hostname + the lease row + DDNS. Fold it to a safe LDH
        # form at ingress (issue #597) rather than rejecting — a malformed
        # client hostname must never fail the lease ingest. Empty result →
        # None ("no usable hostname").
        if v is None:
            return None
        return sanitize_hostname(v) or None

    @field_validator("duid")
    @classmethod
    def _canonical_duid(cls, v: str | None) -> str | None:
        return canonical_duid(v) if v is not None else None

    @model_validator(mode="after")
    def _has_identity(self) -> LeaseEvent:
        # An unparseable address keeps the pre-#1141 rule (a MAC is
        # required) rather than being guessed at.
        try:
            family = ipaddress.ip_address(self.ip_address.strip()).version
        except ValueError:
            family = 4
        if family == 6:
            if not self.duid:
                raise ValueError("a DHCPv6 lease needs a duid")
        elif not self.mac_address:
            raise ValueError("a DHCPv4 lease needs a mac_address")
        return self


def _lease_identity(
    ip: str, mac: str | None, duid: str | None, iaid: int | None
) -> tuple[Any, ...]:
    """What makes two lease reports the same lease (#1110, #1141).

    DHCPv4: the address + the client's MAC. DHCPv6: the address + DUID +
    IAID — most v6 leases carry no MAC, and one that does must not match a
    v4-shaped key. Normalised, because the event carries strings and a row
    read back from the database carries an ``IPv4Address`` / canonical MAC
    (the #1110 duplicate-row bug).
    """
    if duid:
        return (norm_ip(ip), "duid", norm_duid(duid), iaid)
    return (norm_ip(ip), "mac", norm_mac(mac or ""))


class LeaseEventBatch(BaseModel):
    # #428: forbid unknown top-level keys. ``leases`` defaults to [], so an
    # agent that posts the wrong envelope (e.g. the old ``{"events":[…]}``
    # shape) would otherwise validate to an EMPTY batch and the endpoint
    # would 200-no-op — silently dropping every lease. ``extra="forbid"``
    # turns that into a loud 422 the agent logs as ``lease_events_failed``
    # instead of a phantom success. (Per-event field drift already fails
    # loudly: ip_address/mac_address are required.)
    model_config = {"extra": "forbid"}

    # The agent batches up to 100 events per POST (``leases._BATCH_MAX_EVENTS``);
    # cap with generous headroom so a malformed/hostile client can't ship an
    # unbounded batch into the per-event ingestion loop.
    leases: list[LeaseEvent] = Field(default_factory=list, max_length=500)
    # #1077 — replay-dedupe key minted by the agent's spool.
    batch_id: BatchId = None


class DHCPFingerprintEntry(BaseModel):
    """One DHCP fingerprint observation pushed by the agent's scapy sniffer.

    All fields except ``mac_address`` are nullable — devices with
    minimal DHCP option chatter still produce a useful row even if
    fingerbank can't enrich them.
    """

    mac_address: str
    option_55: str | None = None
    option_60: str | None = None
    option_77: str | None = None
    client_id: str | None = None


class DHCPFingerprintBatch(BaseModel):
    fingerprints: list[DHCPFingerprintEntry]
    batch_id: BatchId = None


class DHCPOfferEntry(BaseModel):
    """One OFFER the agent's rogue-DHCP probe observed (issue #370)."""

    server_identifier: str
    source_ip: str
    source_mac: str | None = None
    giaddr: str | None = None
    offered_ip: str | None = None


class DHCPOfferBatch(BaseModel):
    offers: list[DHCPOfferEntry]
    batch_id: BatchId = None


class RAObservationEntry(BaseModel):
    """One ICMPv6 Router Advertisement the agent's RA sniffer observed (#524)."""

    source_ip: str
    source_mac: str | None = None
    prefixes: list[str] = Field(default_factory=list)
    managed_flag: bool = False
    other_flag: bool = False
    router_lifetime: int | None = None
    iface: str | None = None


class RAObservationBatch(BaseModel):
    observations: list[RAObservationEntry] = Field(default_factory=list, max_length=200)
    batch_id: BatchId = None


# ── Batch-ingest responses (#1077) ──────────────────────────────────────────
#
# Every batch-ingest route answers an ``IngestAck`` subclass: the shared
# ``status`` / ``duplicate`` pair plus that route's own counters. A replayed
# batch (same ``batch_id``, already committed) comes back ``duplicate=true``
# with every counter at zero.


class LeaseEventsAck(IngestAck):
    upserted: int = 0


class MacSightingsAck(IngestAck):
    recorded: int = 0
    new: int = 0


class DHCPMetricsAck(IngestAck):
    pass


class DHCPLogAck(IngestAck):
    inserted: int = 0
    dropped: int = 0
    #: Lines older than the control plane's activity-log retention
    #: (``prune_logs.DEFAULT_RETENTION_HOURS``), skipped rather than inserted
    #: into a table the nightly prune would empty straight away.
    expired: int = 0


class DHCPFingerprintsAck(IngestAck):
    upserted: int = 0
    dropped: int = 0
    enqueued: int = 0


class DHCPOffersAck(IngestAck):
    """Per-classification counts (``expected`` / ``acknowledged`` / ``rogue`` /
    ``skipped``) from ``record_offers``."""


class RAObservationsAck(IngestAck):
    expected: int = 0
    acknowledged: int = 0
    rogue: int = 0
    skipped: int = 0


# ── Auth ────────────────────────────────────────────────────────────────────


def _require_bootstrap_key(
    x_dhcp_agent_key: str | None = Header(default=None, alias="X-DHCP-Agent-Key"),
) -> str:
    expected = os.environ.get("DHCP_AGENT_KEY", "")
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="DHCP_AGENT_KEY is not configured on the control plane",
        )
    # Compare BYTES: hmac.compare_digest raises TypeError on a str with
    # non-ASCII characters, so any client that sent one (fuzz: '\x80')
    # got a 500 out of the auth gate instead of the 401 a wrong key is.
    if not x_dhcp_agent_key or not hmac.compare_digest(
        x_dhcp_agent_key.encode("utf-8", "surrogateescape"),
        expected.encode("utf-8", "surrogateescape"),
    ):
        raise HTTPException(status_code=401, detail="Invalid bootstrap key")
    return x_dhcp_agent_key


async def _auth_agent(
    db: DB, authorization: str | None = Header(default=None)
) -> tuple[DHCPServer, dict[str, Any]]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization.split(None, 1)[1].strip()
    try:
        payload = verify_agent_token(token)
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}") from e
    server_id = payload.get("sub")
    if not server_id:
        raise HTTPException(status_code=401, detail="Token missing subject")
    server = await db.get(DHCPServer, uuid.UUID(server_id))
    if server is None:
        raise HTTPException(status_code=404, detail="Server not found")
    if server.agent_token_hash and server.agent_token_hash != hash_token(token):
        raise HTTPException(status_code=401, detail="Stale token")
    return server, payload


# ── Endpoints ───────────────────────────────────────────────────────────────


@router.post("/register", response_model=AgentRegisterResponse)
async def agent_register(
    body: AgentRegisterRequest,
    db: DB,
    _psk: str = Depends(_require_bootstrap_key),
) -> AgentRegisterResponse:
    """Bootstrap registration — PSK → per-server JWT."""
    # #1068 — registration is the one agent call that CREATES a server
    # row, so it is the one that can undo the refuse-while-populated
    # guard on the core.dhcp toggle: delete the servers, disable the
    # module, and a still-running agent re-registers seconds later,
    # leaving a live server stranded behind a 404 surface.
    #
    # Declined with 403, never 404. A 404 is what tells an agent its
    # registration is gone and it should re-bootstrap from the PSK, so
    # answering 404 here would produce exactly the tight re-bootstrap
    # loop the ungated mount exists to avoid. 403 is terminal, logged by
    # the agent, and leaves an already-registered agent's config
    # long-poll and heartbeat working untouched.
    from app.services.feature_modules import is_module_enabled  # noqa: PLC0415

    if not await is_module_enabled(db, "core.dhcp"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "The DHCP subsystem is disabled on this control plane, so "
                "new agents cannot register. Enable it under Settings → "
                "Features."
            ),
        )
    group: DHCPServerGroup | None = None
    if body.group_name:
        res = await db.execute(
            select(DHCPServerGroup).where(DHCPServerGroup.name == body.group_name)
        )
        group = res.scalar_one_or_none()
        if group is None:
            group = DHCPServerGroup(
                name=body.group_name,
                description="Auto-created by DHCP agent registration",
            )
            db.add(group)
            await db.flush()

    server: DHCPServer | None = None
    if body.agent_id:
        try:
            aid = uuid.UUID(body.agent_id)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=f"Invalid agent_id: {e}") from e
        res = await db.execute(select(DHCPServer).where(DHCPServer.agent_id == aid))
        server = res.scalar_one_or_none()
    if server is None:
        res = await db.execute(select(DHCPServer).where(DHCPServer.name == body.hostname))
        server = res.scalar_one_or_none()

    require_approval = os.environ.get("DHCP_REQUIRE_AGENT_APPROVAL", "false").lower() == "true"
    pending_approval = False
    if server is None:
        agent_id = uuid.UUID(body.agent_id) if body.agent_id else uuid.uuid4()
        server = DHCPServer(
            name=body.hostname,
            driver=body.driver,
            host=body.hostname,
            port=67,
            roles=body.roles,
            status="active",
            server_group_id=group.id if group else None,
            agent_id=agent_id,
            agent_registered=True,
            agent_approved=not require_approval,
            agent_fingerprint=body.fingerprint,
            agent_version=body.version,
            description=(
                f"auto-registered agent v{body.version}" if body.version else "auto-registered"
            ),
        )
        pending_approval = require_approval
        db.add(server)
        await db.flush()
    else:
        if server.agent_fingerprint and server.agent_fingerprint != body.fingerprint:
            server.agent_approved = False
            pending_approval = True
            logger.warning("dhcp_agent_fingerprint_mismatch", server_id=str(server.id))
        server.agent_fingerprint = body.fingerprint
        server.driver = body.driver
        server.roles = body.roles
        server.status = "active"
        server.agent_version = body.version
        server.agent_registered = True
        if server.agent_id is None:
            server.agent_id = uuid.UUID(body.agent_id) if body.agent_id else uuid.uuid4()

    token, exp = mint_agent_token(
        server_id=str(server.id),
        agent_id=str(server.agent_id),
        fingerprint=body.fingerprint,
    )
    server.agent_token_hash = hash_token(token)
    server.agent_last_seen = datetime.now(UTC)

    write_audit(
        db,
        user=None,
        action="dhcp.agent.register",
        resource_type="dhcp_server",
        resource_id=str(server.id),
        resource_display=body.hostname,
        new_value={"driver": body.driver, "version": body.version, "roles": body.roles},
    )
    await db.commit()
    await db.refresh(server)

    logger.info(
        "dhcp_agent_registered",
        server_id=str(server.id),
        hostname=body.hostname,
        pending_approval=pending_approval,
    )
    return AgentRegisterResponse(
        server_id=str(server.id),
        agent_id=str(server.agent_id),
        agent_token=token,
        token_expires_at=exp,
        config_etag=server.config_etag,
        pending_approval=pending_approval,
    )


@router.get("/config")
async def agent_config_longpoll(
    db: DB,
    response: Response,
    if_none_match: str | None = Header(default=None, alias="If-None-Match"),
    auth: tuple[DHCPServer, dict[str, Any]] = Depends(_auth_agent),
) -> Any:
    """Long-poll for config changes. Returns 304 if unchanged, bundle JSON otherwise."""
    server, _payload = auth
    if not server.agent_approved:
        response.headers["X-Spatium-Pending-Approval"] = "1"
        return {"pending_approval": True, "etag": None}

    deadline = asyncio.get_running_loop().time() + LONGPOLL_TIMEOUT_SECONDS
    async with wake_subscription(dhcp_wake_channels(server)) as wake:
        # #358 — subscribe before the first bundle build so a committed +
        # published config change wakes this poll immediately; Redis-down
        # degrades to the old LONGPOLL_POLL_INTERVAL sleep (see the DNS agent).
        while True:
            # Pick up server-row column changes a wake signals (fleet markers,
            # group, maintenance) — read off this cached instance, since the
            # bundle re-queries collections but not the server row.
            await db.refresh(server)
            bundle = await build_config_bundle(db, server)
            # Issue #153 — fold the rendered snmpd.conf hash into the ETag
            # mix below so a Settings → Appliance → SNMP change wakes the
            # agent's long-poll even when nothing in the DHCP driver
            # bundle changed.
            settings_row = await db.get(PlatformSettings, 1)
            snmp_block = (
                snmp_bundle(settings_row)
                if settings_row is not None
                else {"enabled": False, "config_hash": "", "snmpd_conf": ""}
            )
            # Issue #154 — same pattern for chrony / NTP. ntp_bundle
            # returns a stable dict shape so the etag math below stays
            # uniform whether settings exist or not.
            ntp_block = (
                ntp_bundle(settings_row)
                if settings_row is not None
                else {
                    "enabled": False,
                    "allow_clients": False,
                    "config_hash": "",
                    "chrony_conf": "",
                }
            )
            # Issue #343 — same pattern for lldpd. Stable dict shape so the etag
            # math stays uniform whether settings exist or not.
            lldp_block = (
                lldp_bundle(settings_row)
                if settings_row is not None
                else {
                    "enabled": False,
                    "config_hash": "",
                    "lldpd_conf": "",
                    "daemon_args": "",
                }
            )
            # Issue #156 — same pattern for rsyslog. Stable dict shape so the
            # etag math stays uniform whether settings exist or not.
            syslog_block = (
                syslog_bundle(settings_row)
                if settings_row is not None
                else {
                    "enabled": False,
                    "config_hash": "",
                    "rsyslog_conf": "",
                    "ca_certs": {},
                }
            )
            # Issue #157 — same pattern for SSH. Stable dict shape so the
            # etag math stays uniform whether settings exist or not.
            ssh_block = (
                ssh_bundle(settings_row)
                if settings_row is not None
                else {
                    "enabled": False,
                    "config_hash": "",
                    "authorized_keys": "",
                    "sshd_conf": "",
                    "ssh_port": 22,
                    "allowed_source_networks": [],
                    "password_auth": True,
                    "key_count": 0,
                }
            )
            # Issue #158 — same pattern for systemd-resolved. Stable dict
            # shape so the etag math stays uniform whether settings exist
            # or not.
            resolver_block = (
                resolver_bundle(settings_row)
                if settings_row is not None
                else {"enabled": False, "config_hash": "", "resolved_conf": ""}
            )
            # Phase 8f-3 — mix the fleet-upgrade intent into the ETag so a
            # Fleet view change wakes the agent's long-poll even when the
            # driver-side bundle is unchanged. Deterministic — re-reading
            # the same DB state yields the same combined ETag.
            fleet_marker = (
                f"{server.desired_appliance_version}"
                f"|{server.desired_slot_image_url}"
                f"|{int(server.reboot_requested)}"
                f"|snmp:{int(bool(snmp_block.get('enabled')))}:{snmp_block.get('config_hash', '')}"
                f"|ntp:{int(bool(ntp_block.get('allow_clients')))}:{ntp_block.get('config_hash', '')}"
                f"|lldp:{int(bool(lldp_block.get('enabled')))}:{lldp_block.get('config_hash', '')}"
                f"|syslog:{int(bool(syslog_block.get('enabled')))}"
                f":{syslog_block.get('config_hash', '')}"
                f"|ssh:{int(bool(ssh_block.get('enabled')))}"
                f":{ssh_block.get('config_hash', '')}"
                f"|resolver:{int(bool(resolver_block.get('enabled')))}"
                f":{resolver_block.get('config_hash', '')}"
            )
            etag = "sha256:" + hashlib.sha256(f"{bundle.etag}|{fleet_marker}".encode()).hexdigest()

            # Pending ops fast-path. Issue #182: paused servers don't ship
            # ops — they accumulate as ``pending`` and dispatch as soon as
            # the operator resumes.
            if server.maintenance_mode:
                pending_ops: list[dict[str, Any]] = []
            else:
                ops_res = await db.execute(
                    select(DHCPConfigOp).where(
                        DHCPConfigOp.server_id == server.id,
                        DHCPConfigOp.status == "pending",
                    )
                )
                pending_ops = [
                    {"op_id": str(o.id), "op_type": o.op_type, "payload": o.payload}
                    for o in ops_res.scalars().all()
                ]

            if not etag_matches(if_none_match, etag) or pending_ops:
                logger.info(
                    "dhcp_agent_config_200",
                    server_id=str(server.id),
                    etag=etag,
                    if_none_match=if_none_match,
                    etag_match=etag_matches(if_none_match, etag),
                    pending_ops=len(pending_ops),
                )
                server.config_etag = etag
                await db.commit()
                response.headers["ETag"] = format_etag(etag)
                return {
                    "server_id": str(server.id),
                    "etag": etag,
                    "bundle": {
                        "server_name": bundle.server_name,
                        "driver": bundle.driver,
                        "roles": list(bundle.roles),
                        # Issue #365 — server-wide Kea interfaces-config. The
                        # agent's render_kea reads ``dhcp_socket_type`` here;
                        # ``raw`` (from group socket_mode "direct") lets Kea
                        # receive broadcast DISCOVERs from directly-attached
                        # clients, ``udp`` is relay-only. Folded into the
                        # bundle ETag so a mode change wakes the long-poll.
                        "server": {
                            "interfaces": ["*"],
                            "dhcp_socket_type": bundle.dhcp_socket_type,
                            # #637 — group-wide Kea lease cache. Scopes may
                            # override (see the per-scope keys below); the agent
                            # falls back to these when the scope value is null.
                            "lease_cache_threshold": bundle.lease_cache_threshold,
                            "lease_cache_max_age": bundle.lease_cache_max_age,
                            # #980 — Kea's packet-worker pool. Serialized here
                            # as well as folded into the ETag; those are
                            # separate steps and skipping this one is the #430
                            # silent no-op the lease-cache keys above call out.
                            "kea_thread_pool_size": bundle.kea_thread_pool_size,
                            "kea_packet_logging": bundle.kea_packet_logging,
                        },
                        "scopes": [
                            {
                                "subnet_cidr": s.subnet_cidr,
                                "lease_time": s.lease_time,
                                # #430 — min/max were settable + in the ETag but
                                # never shipped, so the agent never rendered
                                # min/max-valid-lifetime (silent no-op).
                                "min_lease_time": s.min_lease_time,
                                "max_lease_time": s.max_lease_time,
                                # #637 — per-scope lease-cache override; null =
                                # inherit the group value from the "server" block
                                # above. Serialized here as well as folded into
                                # the ETag: those are separate steps, and skipping
                                # this one is exactly the #430 silent no-op.
                                "lease_cache_threshold": s.lease_cache_threshold,
                                "lease_cache_max_age": s.lease_cache_max_age,
                                "options": s.options,
                                # Issue #330 — the agent's render_kea branches on
                                # these to emit a Dhcp6/subnet6 entry for v6
                                # scopes. Without them every scope rendered as
                                # Dhcp4 regardless of family. v6_address_mode
                                # gates whether the v6 subnet serves pools /
                                # options (stateful | stateless | slaac).
                                "address_family": s.address_family,
                                "v6_address_mode": s.v6_address_mode,
                                # Issue #337 — relay-agent IPs the agent's
                                # render_kea emits as ``relay: {"ip-addresses":
                                # [...]}`` so a centralized Kea matches this
                                # scope on giaddr for relayed remote subnets.
                                "relay_addresses": list(s.relay_addresses),
                                "pools": [
                                    {
                                        "start_ip": p.start_ip,
                                        "end_ip": p.end_ip,
                                        "pool_type": p.pool_type,
                                        # DHCPv6 prefix delegation (#368) — the
                                        # agent's render_kea reads these for
                                        # pool_type == "pd". Null for v4 / range
                                        # pools.
                                        "pd_prefix": p.pd_prefix,
                                        "delegated_length": p.delegated_length,
                                        "excluded_prefix": p.excluded_prefix,
                                        "class_restriction": p.class_restriction,
                                        # #858 — per-pool option overrides are
                                        # settable and ETag-hashed, and the
                                        # control-plane driver renders them, but
                                        # were omitted here: the same silent drop
                                        # #430 hit for statics' options_override
                                        # (serialized on the very next block).
                                        "options_override": p.options_override,
                                    }
                                    for p in s.pools
                                ],
                                "statics": [
                                    {
                                        "ip_address": st.ip_address,
                                        "mac_address": st.mac_address,
                                        "hostname": st.hostname,
                                        # #430 — client_id + options_override
                                        # are settable, ETag-hashed, and the
                                        # agent renderer reads them, but were
                                        # omitted here: a client-id-keyed
                                        # reservation silently fell back to MAC
                                        # and per-host options were dropped.
                                        "client_id": st.client_id,
                                        "options_override": st.options_override,
                                        # DHCPv6 DUID (#368) — keys the v6
                                        # reservation instead of the MAC.
                                        "duid": st.duid,
                                    }
                                    for st in s.statics
                                ],
                                "ddns_enabled": s.ddns_enabled,
                            }
                            for s in bundle.scopes
                        ],
                        "client_classes": [
                            {
                                "name": c.name,
                                "match_expression": c.match_expression,
                                "options": c.options,
                            }
                            for c in bundle.client_classes
                        ],
                        # #858 — PXE + phone classes were folded into the bundle
                        # ETag and rendered by the control-plane driver, but
                        # never serialized here. The consequence was worse than a
                        # plain omission: editing a PXE profile DID move the
                        # ETag, so it broke every agent's /config long-poll and
                        # they all re-fetched — a payload with no PXE classes in
                        # it, which re-rendered byte-identical config. A
                        # guaranteed no-op resync of the whole group, and a
                        # feature (README-advertised PXE provisioning profiles)
                        # that could never reach agent-managed Kea at all.
                        "pxe_classes": [
                            {
                                "name": p.name,
                                "match_expression": p.match_expression,
                                "next_server": p.next_server,
                                "boot_file_name": p.boot_file_name,
                                "is_ipxe_chain": p.is_ipxe_chain,
                            }
                            for p in bundle.pxe_classes
                        ],
                        "phone_classes": [
                            {
                                "name": c.name,
                                "match_expression": c.match_expression,
                                "options": c.options,
                            }
                            for c in bundle.phone_classes
                        ],
                        # #700 — fingerprint-driven device policies. Serialized
                        # here for the reason #858 documents one block up: a
                        # class that is ETag-hashed and rendered by the
                        # control-plane driver but absent from the wire cannot
                        # reach agent-managed Kea, which is how both the
                        # appliance and the Compose stack run DHCP — i.e. the
                        # feature would work nowhere it actually runs.
                        "device_policy_classes": [
                            {
                                "name": c.name,
                                "match_expression": c.match_expression,
                                "options": c.options,
                                "lease_time": c.lease_time,
                            }
                            for c in bundle.device_policy_classes
                        ],
                        # #858 — Kea types a raw ``code:NN`` option as BINARY,
                        # so an operator's string value ("not a valid string of
                        # hexadecimal digits") fails the WHOLE config. The real
                        # type comes from the VoIP / option-code catalogues,
                        # which live in this package and not the agent's, so the
                        # control plane resolves the definitions once and the
                        # agent emits them verbatim — rather than keeping a
                        # second copy of the table, which is the drift that
                        # caused #856.
                        "option_defs": option_defs_for_option_maps(
                            [bundle.options.options]
                            + [s.options for s in bundle.scopes]
                            + [p.options_override for s in bundle.scopes for p in s.pools]
                            + [st.options_override for s in bundle.scopes for st in s.statics]
                            + [c.options for c in bundle.client_classes]
                            + [c.options for c in bundle.phone_classes]
                            # #700 — a device policy can deliver a raw
                            # ``code:NN`` vendor option just as a phone profile
                            # can; without its definition Kea types the value
                            # BINARY and rejects the WHOLE config.
                            + [c.options for c in bundle.device_policy_classes]
                        ),
                        "mac_blocks": [
                            {
                                "mac_address": m.mac_address,
                                "reason": m.reason,
                                "description": m.description,
                            }
                            for m in bundle.mac_blocks
                        ],
                        # Kea HA hook configuration — absent when the
                        # server isn't part of a failover channel. The
                        # agent's render_kea.py keys off the presence of
                        # this ``peers`` list to decide whether to emit
                        # ``libdhcp_ha.so``.
                        "failover": (
                            {
                                "channel_id": bundle.failover.channel_id,
                                "channel_name": bundle.failover.channel_name,
                                "mode": bundle.failover.mode,
                                "this_server_name": bundle.failover.this_server_name,
                                "peers": list(bundle.failover.peers),
                                "heartbeat_delay_ms": bundle.failover.heartbeat_delay_ms,
                                "max_response_delay_ms": bundle.failover.max_response_delay_ms,
                                "max_ack_delay_ms": bundle.failover.max_ack_delay_ms,
                                "max_unacked_clients": bundle.failover.max_unacked_clients,
                            }
                            if bundle.failover is not None
                            else None
                        ),
                        # IPv6 Router Advertisements (issue #524) — the
                        # pre-rendered radvd.conf the agent writes + runs
                        # radvd from when RADVD_MANAGED=1. Empty string when
                        # no scope in the group has ``ra_enabled`` set.
                        "radvd_conf": bundle.radvd_conf,
                    },
                    "pending_ops": pending_ops,
                    # Phase 8f-3 — fleet upgrade intent the operator set
                    # from the Fleet view. Agent reads desired_*, compares
                    # against its own installed version on next heartbeat /
                    # bundle pickup, and writes the slot-upgrade trigger
                    # if mismatched. Both values None when nothing pending.
                    "fleet_upgrade": {
                        "desired_appliance_version": server.desired_appliance_version,
                        "desired_slot_image_url": server.desired_slot_image_url,
                        # Phase 8f-8 — operator-triggered reboot intent.
                        # Agent fires the reboot-pending trigger when this
                        # flips to True; heartbeat handler clears it
                        # post-reconnect.
                        "reboot_requested": server.reboot_requested,
                    },
                    # Issue #153 — rendered snmpd.conf body + config hash.
                    # Agent writes the snmp-reload trigger when the hash
                    # differs from its last-rendered config; host-side
                    # spatiumddi-snmp-reload.path picks the file up and
                    # reloads snmpd.
                    "snmp_settings": snmp_block,
                    # Issue #154 — same shape for chrony / NTP. Agent
                    # writes ntp-config-pending on hash change; host-side
                    # spatiumddi-chrony-reload.path applies + reloads.
                    "ntp_settings": ntp_block,
                    # Issue #343 — rendered lldpd config + daemon args. Agent
                    # writes lldp-config-pending on hash change; host-side
                    # spatiumddi-lldp-reload.path applies + reloads lldpd.
                    "lldp_settings": lldp_block,
                    # Issue #156 — rendered rsyslog forward config + per-target
                    # CA PEMs. Agent writes syslog-config-pending on hash
                    # change; host-side spatiumddi-syslog-reload.path stages
                    # the conf + CA files, validates with rsyslogd -N1, and
                    # restarts rsyslog.
                    "syslog_settings": syslog_block,
                    # Issue #157 — rendered authorized_keys + sshd drop-in +
                    # source-scope CIDRs. Agent writes ssh-config-pending on
                    # hash change; host-side spatiumddi-ssh-reload.path stages
                    # the files, validates with sshd -t, applies the
                    # source-scoped nft drop-in, and reloads sshd.
                    "ssh_settings": ssh_block,
                    # Issue #158 — rendered systemd-resolved drop-in. Agent
                    # writes resolver-config-pending on hash change; host-side
                    # spatiumddi-resolved-reload.path stages the drop-in (or
                    # removes it on revert-to-automatic) and reloads
                    # systemd-resolved.
                    "resolver_settings": resolver_block,
                }
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return Response(status_code=304, headers={"ETag": format_etag(etag)})
            await wake.wait(min(WAKE_TICK_SECONDS, remaining))


@router.post("/heartbeat", response_model=AgentHeartbeatResponse)
async def agent_heartbeat(
    request: Request,
    body: AgentHeartbeatRequest,
    db: DB,
    auth: tuple[DHCPServer, dict[str, Any]] = Depends(_auth_agent),
) -> AgentHeartbeatResponse:
    server, payload = auth
    now = datetime.now(UTC)
    server.agent_last_seen = now
    server.last_health_check_at = now
    server.status = "active"
    # Capture the source IP so the operator can identify which host
    # the agent is on — the operator-set ``host`` column may not
    # match the real machine in NAT / distributed deployments.
    if request.client is not None:
        server.last_seen_ip = request.client.host
    if body.agent_version:
        server.agent_version = body.agent_version
    # #637 — only overwrite when the agent actually reported a version. A cold
    # daemon answers None, and clobbering a known-good value with NULL would
    # make the HA-skew preflight fall back to "unknown" for no reason.
    if body.kea_version:
        server.kea_version = body.kea_version

    # Phase 8f-2 — persist whatever slot state the agent reported. Only
    # overwrite when the agent actually sent a value (older agents
    # leave these as None, in which case we leave the DB columns
    # untouched rather than nulling out previously-known state).
    if body.deployment_kind is not None:
        server.deployment_kind = body.deployment_kind
    if body.installed_appliance_version is not None:
        server.installed_appliance_version = body.installed_appliance_version
    if body.current_slot is not None:
        server.current_slot = body.current_slot
    if body.durable_default is not None:
        server.durable_default = body.durable_default
    if body.is_trial_boot is not None:
        server.is_trial_boot = body.is_trial_boot
    if body.last_upgrade_state is not None:
        server.last_upgrade_state = body.last_upgrade_state
    if body.last_upgrade_state_at is not None:
        server.last_upgrade_state_at = body.last_upgrade_state_at

    # Phase 8f-7 — auto-clear operator intent once the agent confirms
    # the upgrade landed. See dns/agents.py for the full rationale.
    if (
        server.desired_appliance_version is not None
        and server.installed_appliance_version
        and server.installed_appliance_version == server.desired_appliance_version
        and (server.last_upgrade_state in ("done", None))
    ):
        server.desired_appliance_version = None
        server.desired_slot_image_url = None

    # Phase 8f-8 — clear reboot_requested once the agent reconnects
    # post-reboot. See dns/agents.py for the full rationale; ~15 s
    # safety margin so a near-instant heartbeat doesn't false-clear.
    if server.reboot_requested and server.reboot_requested_at is not None:
        elapsed = (datetime.now(UTC) - server.reboot_requested_at).total_seconds()
        if elapsed > 15:
            server.reboot_requested = False
            server.reboot_requested_at = None

    # #882 — the config-apply verdict. Pre-#882 a config Kea REFUSED still
    # reached here as a healthy heartbeat: the agent advanced its etag,
    # recorded success and stamped its readiness marker, so nothing on this
    # side ever learned the scope changes were not live.
    apply_reported_status(server, body.config, agent_kind="dhcp", server_id=str(server.id))
    # #1077 — spool state. Only written when the heartbeat carries it.
    apply_reported_spool(server, body.spool, agent_kind="dhcp", server_id=str(server.id))
    # #1067 — the daemon state (the DHCP agent ships it as ``daemon`` and, from
    # the same dict, the top-level ``status``; ``daemon`` is the source). Same
    # gap as the DNS side: declared, accepted, never read.
    apply_reported_daemon_state(server, body.daemon, agent_kind="dhcp", server_id=str(server.id))

    for ack in body.ops_ack:
        op_id = ack.get("op_id")
        result = ack.get("result", "error")
        message = ack.get("message")
        if op_id:
            op = await db.get(DHCPConfigOp, uuid.UUID(op_id))
            if op is not None and op.server_id == server.id:
                op.status = "acked" if result == "ok" else "failed"
                op.error_msg = message
                op.acked_at = now

    rotated_token = None
    rotated_exp = None
    if needs_rotation(payload):
        rotated_token, rotated_exp = mint_agent_token(
            server_id=str(server.id),
            agent_id=str(server.agent_id),
            fingerprint=server.agent_fingerprint or "",
        )
        server.agent_token_hash = hash_token(rotated_token)

    await db.commit()
    return AgentHeartbeatResponse(
        server_id=str(server.id),
        status=server.status,
        acknowledged_at=now,
        rotated_token=rotated_token,
        rotated_expires_at=rotated_exp,
    )


@router.post("/lease-events", response_model=LeaseEventsAck)
async def agent_lease_events(
    body: LeaseEventBatch,
    db: DB,
    auth: tuple[DHCPServer, dict[str, Any]] = Depends(_auth_agent),
) -> dict[str, Any]:
    """Bulk lease ingestion from the agent.

    In addition to upserting the DHCPLease row, we mirror live leases into
    IPAM as ``status='dhcp'`` rows (flagged ``auto_from_lease=True``) so the
    subnet view shows actively-leased addresses alongside manual ones.

    Policy:
      - Active lease + no IPAM row → create row with status='dhcp'.
      - Active lease + existing IPAM row that's 'available' or already
        auto_from_lease → overwrite hostname/MAC and flip to 'dhcp'.
      - Active lease + existing row that's manually allocated / static_dhcp
        / reserved → leave alone (operator owns that row; lease just
        co-exists in DHCPLease).
      - Released/expired lease → if the IPAM row is auto_from_lease, remove it —
        unless another server in the group still reports the lease active
        (an HA peer that has not reported the release yet, #1110).
    """
    from app.models.ipam import IPAddress
    from app.services.dhcp.pull_leases import (
        _find_containing_subnet,
        _load_scope_cache,
        _load_subnet_cache,
    )
    from app.services.feature_modules import is_module_enabled

    server, _ = auth
    # #1077 — a replay of a batch already committed writes nothing. Claimed
    # before any write so the receipt and the rows share one transaction.
    if not await claim_batch(
        db, server_id=server.id, batch_id=body.batch_id, stream="dhcp.lease_events"
    ):
        return duplicate_response(upserted=0)
    now = datetime.now(UTC)
    events = body.leases
    if not events:
        return {"upserted": 0}

    # New-device watch (issue #459) — only log MAC sightings to ip_mac_history
    # when the operator has opted in; keeps this hot ingestion path (up to 100
    # events/POST) at its current cost when the feature is off.
    watch_enabled = await is_module_enabled(db, "security.new_device_watch")
    # (ipam_row, mac) pairs to classify after the mirror pass flushes ids.
    to_observe: list[tuple[IPAddress, str]] = []

    # ── Bulk preload (avoid the per-event N+1: this is the hottest DHCP
    # ingestion path, up to 100 events/POST). Three queries total instead
    # of ~3 per event. ──────────────────────────────────────────────────
    ips = list({ev.ip_address for ev in events})

    # Resolve subnets once (Python longest-prefix match, no per-IP SQL),
    # BEFORE the lease upsert so new rows get their scope FK stamped. #844:
    # prefer subnets actually scoped to this server's group — IPAM allows the
    # same CIDR in different IP spaces, and an unranked longest-prefix match
    # would mirror every customer's leases into one arbitrary space's subnet
    # (and fire DDNS into the wrong customer's zone). The IPAM mirror is
    # keyed by (subnet_id, address) below, which only disambiguates once the
    # subnet itself is resolved correctly.
    subnets = await _load_subnet_cache(db)
    scope_cache = await _load_scope_cache(db, server.server_group_id)
    subnet_for_ip = {
        ip: _find_containing_subnet(ip, subnets, preferred_subnet_ids=set(scope_cache))
        for ip in ips
    }

    def _scope_for_ip(ip: str) -> Any:
        subnet = subnet_for_ip.get(ip)
        return scope_cache.get(subnet.id) if subnet is not None else None

    existing_leases = (
        (
            await db.execute(
                select(DHCPLease).where(
                    DHCPLease.server_id == server.id,
                    DHCPLease.ip_address.in_(ips),
                )
            )
        )
        .scalars()
        .all()
    )
    # Keyed on the NORMALISED pair (#1110). The event carries strings; a row
    # loaded from the database carries an ``IPv4Address`` (asyncpg decodes
    # INET natively) — so keying the map on the raw values never matched a
    # stored lease, and every renewal event INSERTED another ``dhcp_lease``
    # row for the same lease instead of updating the one it had. Harmless-
    # looking until something counts rows per address: a release then only
    # ever reached the new row, leaving the original "active" until its
    # expiry, which kept a Kea HA partner's shared IPAM mirror alive.
    lease_by_key: dict[tuple[Any, ...], DHCPLease] = {
        _lease_identity(
            str(lease.ip_address),
            str(lease.mac_address) if lease.mac_address else None,
            lease.duid,
            lease.iaid,
        ): lease
        for lease in existing_leases
    }

    # Upsert every DHCPLease first, then a single flush so new rows get
    # their ids before we wire dhcp_lease_id on the IPAM mirror.
    upserted = 0
    for ev in events:
        key = _lease_identity(ev.ip_address, ev.mac_address, ev.duid, ev.iaid)
        # #428: fall back to ends_at when the agent didn't send a distinct
        # expires_at (Kea ships the same absolute reclaim time as ends_at).
        # Without a non-NULL expires_at the time-based sweep_expired_leases
        # — which filters `expires_at IS NOT NULL` — can never reap the row.
        expires_at = ev.expires_at or ev.ends_at
        lease = lease_by_key.get(key)
        if lease is None:
            lease = DHCPLease(
                server_id=server.id,
                ip_address=ev.ip_address,
                mac_address=ev.mac_address,
                duid=ev.duid,
                iaid=ev.iaid,
                hostname=ev.hostname,
                client_id=ev.client_id,
                user_class=ev.user_class,
                state=ev.state,
                starts_at=ev.starts_at,
                ends_at=ev.ends_at,
                expires_at=expires_at,
                last_seen_at=now,
                # #844 — wire the scope FK at ingestion so downstream
                # consumers (lease cleanup, mirror scoping) never have to
                # fall back to the space-ambiguous CIDR match.
                scope_id=_scope_for_ip(ev.ip_address),
            )
            db.add(lease)
            lease_by_key[key] = lease
        else:
            lease.hostname = ev.hostname
            if ev.mac_address:
                # A v6 lease's hardware address can arrive on a later report
                # than the lease itself; keep it once known (#1141).
                lease.mac_address = ev.mac_address
            lease.client_id = ev.client_id
            lease.user_class = ev.user_class
            lease.state = ev.state
            lease.starts_at = ev.starts_at
            lease.ends_at = ev.ends_at
            lease.expires_at = expires_at
            lease.last_seen_at = now
            if lease.scope_id is None:
                # Backfill legacy rows created before scope stamping (#844).
                lease.scope_id = _scope_for_ip(ev.ip_address)
        upserted += 1
    await db.flush()

    # Bulk-load the existing IPAM mirror rows. Keyed by (subnet_id, address)
    # so overlapping ranges across spaces stay disambiguated (subnets were
    # resolved space-aware above).
    ipam_existing = (
        (await db.execute(select(IPAddress).where(IPAddress.address.in_(ips)))).scalars().all()
    )
    # Normalised for the same reason as ``lease_by_key`` above (#1110): the
    # stored ``address`` is an ``IPv4Address``, the event's is a string. Raw
    # keys never matched a stored row, so a release / expiry event found no
    # mirror to tear down — the IPAM row and its DDNS records outlived the
    # lease until the time-based sweep caught up with its expiry — and every
    # active event for a known address fell through to a doomed INSERT that
    # only the #564 savepoint rescued.
    ipam_by_key: dict[tuple[Any, str], IPAddress] = {
        (row.subnet_id, norm_ip(str(row.address))): row for row in ipam_existing
    }

    def _apply_lease_fields(row: IPAddress, ev: Any, lease: Any) -> None:
        """Stamp lease state onto a mirror row we own (auto/available)."""
        row.hostname = (ev.hostname or row.hostname or "")[:253]
        # A DHCPv6 lease usually has no MAC (#1141) — keep what the row has
        # rather than blanking it.
        row.mac_address = ev.mac_address or row.mac_address
        row.status = "dhcp"
        row.auto_from_lease = True
        row.dhcp_lease_id = str(lease.id) if lease.id else None
        # The lease IS the sighting. The pull path always stamped this
        # (``pull_leases._refresh_lease_owned_row``); the agent path never
        # did, so every Kea-sourced row read "Seen: Never" (#1141).
        row.last_seen_at = now
        row.last_seen_method = "dhcp"

    # ── IPAM mirror pass ────────────────────────────────────────────────
    for ev in events:
        subnet = subnet_for_ip.get(ev.ip_address)
        if subnet is None:
            continue  # IP not in any known subnet — can't mirror
        lease = lease_by_key[_lease_identity(ev.ip_address, ev.mac_address, ev.duid, ev.iaid)]
        ipam_row = ipam_by_key.get((subnet.id, norm_ip(ev.ip_address)))

        is_active = ev.state == "active"
        if is_active:
            if ipam_row is None:
                candidate = IPAddress(
                    subnet_id=subnet.id,
                    address=ev.ip_address,
                    hostname=(ev.hostname or "")[:253],
                    mac_address=ev.mac_address,
                    status="dhcp",
                    auto_from_lease=True,
                    dhcp_lease_id=str(lease.id) if lease.id else None,
                    last_seen_at=now,
                    last_seen_method="dhcp",
                )
                # #564 — a concurrent Sync-DHCP / static-reservation
                # writer may have already committed this
                # (subnet_id, address) pair. Insert inside a savepoint
                # so a unique-violation self-heals into the incumbent
                # row instead of 500-ing on uq_ip_address_subnet_address.
                ipam_row, created = await insert_ipam_mirror_row(db, candidate)
                ipam_by_key[(subnet.id, norm_ip(ev.ip_address))] = ipam_row
                # A fresh insert already carries the right fields; only a
                # race-lost incumbent we own gets the same update a
                # pre-existing row would take (never a manual/static row).
                if not created and (ipam_row.status == "available" or ipam_row.auto_from_lease):
                    _apply_lease_fields(ipam_row, ev, lease)
            elif ipam_row.status in ("available",) or ipam_row.auto_from_lease:
                _apply_lease_fields(ipam_row, ev, lease)
            # else: manual/static — leave it alone

            # New-device watch: record the MAC sighting for this lease,
            # regardless of whether the IPAM row is auto/manual (a new MAC
            # squatting a static IP is exactly worth flagging). Deferred until
            # after the flush below so new rows have ids.
            if watch_enabled and ipam_row is not None and ev.mac_address:
                to_observe.append((ipam_row, ev.mac_address))

            # DDNS — mirrors services/dhcp/pull_leases.py. Only fires on
            # auto-from-lease rows inside DDNS-enabled subnets; errors are
            # logged but never break the lease upsert pass (DNS will
            # reconcile on the next event or sweep).
            if ipam_row is not None and ipam_row.auto_from_lease:
                try:
                    from app.services.dns.ddns import apply_ddns_for_lease

                    await apply_ddns_for_lease(
                        db,
                        subnet=subnet,
                        ipam_row=ipam_row,
                        client_hostname=ev.hostname,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "dhcp_agent_lease_ddns_failed",
                        server=str(server.id),
                        ip=ev.ip_address,
                        error=str(exc),
                    )

            # Auto-profile (Phase 1: active layer). Subnet-level opt-in;
            # the service applies the refresh-window dedupe + per-subnet
            # concurrency cap. Like the DDNS branch above, errors are
            # logged but never break the lease pass — profiling is
            # opportunistic.
            if ipam_row is not None and ipam_row.auto_from_lease:
                try:
                    from app.services.profiling.auto_profile import (
                        maybe_enqueue_for_lease,
                    )

                    await maybe_enqueue_for_lease(db, subnet=subnet, ipam_row=ipam_row)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "dhcp_agent_lease_auto_profile_failed",
                        server=str(server.id),
                        ip=ev.ip_address,
                        error=str(exc),
                    )
        else:  # expired / released / declined
            # #1110 — under Kea HA both peers report every lease, so a
            # release reaches us once per peer. The first to arrive must not
            # take the shared mirror + DDNS away while the other peer still
            # reports the lease active; the second one (or the expiry sweep,
            # if the other peer never reports) does.
            if (
                ipam_row is not None
                and ipam_row.auto_from_lease
                and await peer_holds_active_lease(db, lease, now=now)
            ):
                continue
            if ipam_row is not None and ipam_row.auto_from_lease:
                # Revoke DDNS BEFORE deleting the row — revoke reads
                # dns_record_id / hostname off the row to find what to
                # delete, and we don't want those fields gone yet.
                try:
                    from app.services.dns.ddns import revoke_ddns_for_lease

                    await revoke_ddns_for_lease(db, subnet=subnet, ipam_row=ipam_row)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "dhcp_agent_lease_ddns_revoke_failed",
                        server=str(server.id),
                        ip=ev.ip_address,
                        error=str(exc),
                    )
                await db.delete(ipam_row)
                ipam_by_key.pop((subnet.id, norm_ip(ev.ip_address)), None)

    # ── New-device watch: classify the collected MAC sightings (issue #459) ──
    # Flush first so freshly-created mirror rows have ids for the FK. Each
    # genuinely-new device writes a device.first_seen audit row, which the
    # after-commit publisher turns into a typed event (≤10 s) — the real-time
    # "something new joined" signal, independent of the 60 s alert tick.
    if to_observe:
        from app.api.v1.dhcp._audit import write_audit
        from app.services.ipam.discovery import record_mac_observation

        await db.flush()
        for ipam_row, mac in to_observe:
            if ipam_row.id is None:
                continue
            try:
                result = await record_mac_observation(db, ipam_row.id, mac, source="dhcp_lease")
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "dhcp_agent_lease_mac_observation_failed",
                    server=str(server.id),
                    ip=str(ipam_row.address),
                    error=str(exc),
                )
                continue
            if result is not None and result.is_first_seen_new:
                write_audit(
                    db,
                    user=None,
                    action="first_seen",
                    resource_type="ip_mac_observation",
                    resource_id=f"{ipam_row.id}:{result.mac_address}",
                    resource_display=f"{ipam_row.address} ({result.mac_address})",
                    new_value={
                        "mac_address": result.mac_address,
                        "ip_address": str(ipam_row.address),
                        "source": "dhcp_lease",
                        "is_randomized": result.is_randomized,
                    },
                )

    await db.commit()
    return {"upserted": upserted}


class MacSightingEntry(BaseModel):
    """One first-sighting from the agent's L2 (ARP / ND) sniffer (issue #459).

    ``ip_address`` is the sender protocol address from the ARP / ND frame —
    required, since the sighting is logged against an IPAM row.
    """

    mac_address: str
    ip_address: str


class MacSightingBatch(BaseModel):
    model_config = {"extra": "forbid"}

    sightings: list[MacSightingEntry] = Field(default_factory=list, max_length=500)
    batch_id: BatchId = None


@router.post("/mac-sightings", response_model=MacSightingsAck)
async def agent_mac_sightings(
    body: MacSightingBatch,
    db: DB,
    auth: tuple[DHCPServer, dict[str, Any]] = Depends(_auth_agent),
) -> dict[str, Any]:
    """Ingest first-sighting (mac, ip) pairs from the agent's opt-in L2 sniffer.

    arpwatch-style: a MAC seen on the wire even if it never does DHCP (static
    IP, link-local, rogue). Resolves each IP to a subnet, creates a
    ``discovered`` IPAM row if there's none yet (like the SNMP ARP path), and
    records the MAC sighting with ``source='l2_sniff'``. Genuinely-new devices
    write a ``device.first_seen`` audit row → typed event. No-op (zero writes)
    when new-device watch is off, so an agent left sniffing costs nothing
    server-side until the operator arms the feature.
    """
    from app.models.ipam import IPAddress
    from app.services.dhcp.pull_leases import (
        _find_containing_subnet,
        _load_scope_cache,
        _load_subnet_cache,
    )
    from app.services.feature_modules import is_module_enabled

    server, _ = auth
    if not await claim_batch(
        db, server_id=server.id, batch_id=body.batch_id, stream="dhcp.mac_sightings"
    ):
        return duplicate_response(recorded=0, new=0)
    if not body.sightings:
        return {"recorded": 0, "new": 0}
    if not await is_module_enabled(db, "security.new_device_watch"):
        return {"recorded": 0, "new": 0}

    from app.api.v1.dhcp._audit import write_audit
    from app.services.ipam.discovery import record_mac_observation

    now = datetime.now(UTC)
    subnets = await _load_subnet_cache(db)
    # #844 — prefer this server's own scoped subnets over an equal prefix
    # from an unrelated IP space (same ambiguity as the lease-event path).
    sighting_preferred = set(await _load_scope_cache(db, server.server_group_id))
    ips = list({s.ip_address for s in body.sightings})
    existing = (
        (await db.execute(select(IPAddress).where(IPAddress.address.in_(ips)))).scalars().all()
    )
    by_key: dict[tuple[Any, str], IPAddress] = {(r.subnet_id, r.address): r for r in existing}

    # (ipam_row, mac) pairs to classify after the flush assigns new-row ids.
    to_observe: list[tuple[IPAddress, str]] = []
    for s in body.sightings:
        subnet = _find_containing_subnet(
            s.ip_address, subnets, preferred_subnet_ids=sighting_preferred
        )
        if subnet is None:
            continue
        row = by_key.get((subnet.id, s.ip_address))
        if row is None:
            # #564 — a concurrent lease-event / Sync-DHCP writer may have
            # already committed this (subnet_id, address). Insert inside a
            # savepoint so the unique-violation self-heals into the
            # incumbent instead of poisoning the whole sightings batch on
            # the shared flush below.
            row, created = await insert_ipam_mirror_row(
                db,
                IPAddress(
                    subnet_id=subnet.id,
                    address=s.ip_address,
                    status="discovered",
                    mac_address=s.mac_address,
                    last_seen_at=now,
                    last_seen_method="l2_sniff",
                ),
            )
            by_key[(subnet.id, s.ip_address)] = row
            if not created:
                # Lost the race — just bump the sighting timestamp on the
                # incumbent (don't clobber its status/mac; the observation
                # below records the MAC either way).
                row.last_seen_at = now
                row.last_seen_method = "l2_sniff"
        else:
            row.last_seen_at = now
            row.last_seen_method = "l2_sniff"
        to_observe.append((row, s.mac_address))

    recorded = 0
    new_count = 0
    if to_observe:
        await db.flush()
        for row, mac in to_observe:
            if row.id is None:
                continue
            try:
                result = await record_mac_observation(db, row.id, mac, source="l2_sniff")
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "dhcp_agent_mac_sighting_failed",
                    server=str(server.id),
                    ip=str(row.address),
                    error=str(exc),
                )
                continue
            recorded += 1
            if result is not None and result.is_first_seen_new:
                new_count += 1
                write_audit(
                    db,
                    user=None,
                    action="first_seen",
                    resource_type="ip_mac_observation",
                    resource_id=f"{row.id}:{result.mac_address}",
                    resource_display=f"{row.address} ({result.mac_address})",
                    new_value={
                        "mac_address": result.mac_address,
                        "ip_address": str(row.address),
                        "source": "l2_sniff",
                        "is_randomized": result.is_randomized,
                    },
                )
    await db.commit()
    return {"recorded": recorded, "new": new_count}


@router.post("/ha-status")
async def agent_ha_status(
    body: HAStatusReport,
    db: DB,
    auth: tuple[DHCPServer, dict[str, Any]] = Depends(_auth_agent),
) -> dict[str, str]:
    """Update this server's Kea HA state from the agent's periodic poll.

    Idempotent — the agent is free to call this as often as it wants
    (typical cadence is every 15-30s alongside its existing heartbeat).
    Only updates the two ``ha_*`` columns on DHCPServer; never rewrites
    config or creates audit rows. Drift-free reporting is out of band
    from the config push path.
    """
    server, _ = auth
    server.ha_state = body.state
    server.ha_last_heartbeat_at = datetime.now(UTC)
    await db.commit()
    return {"status": "ok"}


class DHCPMetricReport(BaseModel):
    """One time-bucketed sample of Kea packet counters.

    Shape mirrors ``DNSMetricReport`` — the agent emits deltas
    computed from two consecutive ``statistic-get-all`` snapshots so
    a Kea restart (counters reset to zero) only drops one bucket on
    the floor instead of creating a spurious spike when the next
    poll's counters come in lower than the previous ones.
    """

    bucket_at: datetime
    discover: int = 0
    offer: int = 0
    request: int = 0
    ack: int = 0
    nak: int = 0
    decline: int = 0
    release: int = 0
    inform: int = 0
    # #980 — loss counters. ``None`` (the default, and what an agent older
    # than #980 sends by omission) means NOT MEASURED and is stored as NULL;
    # 0 means measured and no loss. They must not collapse together, or an
    # un-upgraded fleet reads as a fleet that has never dropped a packet.
    receive_drop: int | None = None
    socket_drop: int | None = None
    batch_id: BatchId = None


@router.post("/metrics", response_model=DHCPMetricsAck)
async def agent_metrics(
    body: DHCPMetricReport,
    db: DB,
    auth: tuple[DHCPServer, dict[str, Any]] = Depends(_auth_agent),
) -> dict[str, Any]:
    """Ingest one sample row, accumulating into ``(server_id, bucket_at)``.

    A second report for a bucket that already exists is ADDED to it rather
    than replacing it, because these are counter *deltas* over disjoint
    intervals and two of them landing in one bucket are two things that both
    happened. Replacing was the original behaviour and it silently discarded
    a poll: the agent floors ``bucket_at`` to the minute while its own
    interval is 60 s ± 3 s of jitter, so a tick early in a minute followed by
    a 57-59 s gap puts two genuinely different deltas in the same bucket —
    roughly one bucket in forty. Harmless-looking on a traffic chart, and
    exactly wrong for the #980 loss counters, where the discarded minute is
    the one an operator is looking for.

    Accumulating means a retried body must not be counted twice, and since
    #1077 agents DO retry: a failed POST is spooled to disk and replayed on
    reconnect. The replay carries the same ``batch_id`` and is answered as a
    duplicate before anything is added — the idempotency key this docstring
    used to say a future retry would need. A body without ``batch_id`` (an
    agent older than #1077, which never retries) accumulates unconditionally.
    """
    server, _ = auth
    if not await claim_batch(
        db, server_id=server.id, batch_id=body.batch_id, stream="dhcp.metrics"
    ):
        return duplicate_response()
    values = {
        "discover": max(0, body.discover),
        "offer": max(0, body.offer),
        "request": max(0, body.request),
        "ack": max(0, body.ack),
        "nak": max(0, body.nak),
        "decline": max(0, body.decline),
        "release": max(0, body.release),
        "inform": max(0, body.inform),
    }
    # #980 — nullable, so kept out of ``values``: None must be stored as NULL
    # (not measured) and must not be clamped to 0 by the max() above.
    nullable_values = {
        "receive_drop": None if body.receive_drop is None else max(0, body.receive_drop),
        "socket_drop": None if body.socket_drop is None else max(0, body.socket_drop),
    }
    existing = await db.get(DHCPMetricSample, (server.id, body.bucket_at))
    if existing is None:
        db.add(
            DHCPMetricSample(
                server_id=server.id, bucket_at=body.bucket_at, **values, **nullable_values
            )
        )
    else:
        for k, v in values.items():
            setattr(existing, k, getattr(existing, k, 0) + v)
        for k, v in nullable_values.items():
            prior = getattr(existing, k, None)
            # UNKNOWN + n = n: one poll failing to measure does not erase
            # what its neighbour in the same bucket did measure. Only two
            # unmeasured polls leave the bucket unmeasured.
            if v is None:
                continue
            setattr(existing, k, v if prior is None else prior + v)
    await db.commit()
    return {"status": "ok", "duplicate": False}


@router.post("/ops/{op_id}/ack")
async def agent_ops_ack(
    op_id: uuid.UUID,
    body: dict[str, Any],
    db: DB,
    auth: tuple[DHCPServer, dict[str, Any]] = Depends(_auth_agent),
) -> dict[str, str]:
    server, _ = auth
    op = await db.get(DHCPConfigOp, op_id)
    if op is None or op.server_id != server.id:
        raise HTTPException(status_code=404, detail="Op not found")
    result = body.get("result", "error")
    op.status = "acked" if result == "ok" else "failed"
    op.error_msg = body.get("message")
    op.acked_at = datetime.now(UTC)
    await db.commit()
    return {"status": "ok"}


# ── Activity log ingestion ───────────────────────────────────────────


class DHCPLogBatch(BaseModel):
    """Batch of raw ``kea-dhcp4`` log lines pushed by the agent.

    Same shape as the DNS query log batch. The agent tails Kea's
    file output (we configure a file ``output_options`` in the
    rendered ``kea-dhcp4.conf`` so the lines are tail-able), batches
    them, and POSTs every few seconds. Replays are deduplicated per batch
    by ``batch_id`` (#1077).
    """

    lines: list[str]
    batch_id: BatchId = None


@router.post("/log-entries", response_model=DHCPLogAck)
async def agent_log_entries(
    body: DHCPLogBatch,
    db: DB,
    auth: tuple[DHCPServer, dict[str, Any]] = Depends(_auth_agent),
) -> dict[str, Any]:
    """Ingest a batch of Kea log lines from the agent.

    Capped at 1000 lines per request. The parser tolerates lines it
    can't fully match — they still get inserted with the raw text
    preserved so the UI shows everything Kea emitted.

    Lines whose own timestamp is older than the activity-log retention
    window are counted as ``expired`` and not inserted (#1077): a replayed
    outage backlog would otherwise write rows the nightly prune deletes on
    its next run. A line with no parseable timestamp is stamped with the
    arrival time by the parser, so it is never expired.
    """
    from app.services.logs.kea_parser import parse_kea_line  # noqa: PLC0415

    server, _ = auth
    if not await claim_batch(db, server_id=server.id, batch_id=body.batch_id, stream="dhcp.log"):
        return duplicate_response(inserted=0)
    capped = body.lines[:1000]
    dropped = max(0, len(body.lines) - len(capped))
    now = datetime.now(UTC)
    expired_cutoff = now - timedelta(hours=ACTIVITY_LOG_RETENTION_HOURS)
    inserted = 0
    expired = 0
    for raw in capped:
        parsed = parse_kea_line(raw, fallback_ts=now)
        if parsed is None:
            continue
        if parsed.ts < expired_cutoff:
            expired += 1
            continue
        db.add(
            DHCPLogEntry(
                server_id=server.id,
                ts=parsed.ts,
                severity=parsed.severity,
                code=parsed.code,
                mac_address=parsed.mac_address,
                ip_address=parsed.ip_address,
                transaction_id=parsed.transaction_id,
                raw=parsed.raw,
            )
        )
        inserted += 1
    await db.commit()
    return {"status": "ok", "inserted": inserted, "dropped": dropped, "expired": expired}


# ── DHCP fingerprint ingestion (Phase 2 device profiling) ─────────────


@router.post("/dhcp-fingerprints", response_model=DHCPFingerprintsAck)
async def agent_dhcp_fingerprints(
    body: DHCPFingerprintBatch,
    db: DB,
    auth: tuple[DHCPServer, dict[str, Any]] = Depends(_auth_agent),
) -> dict[str, Any]:
    """Bulk fingerprint upsert from the agent's scapy sniffer.

    Capped at 500 entries per request so a misbehaving agent can't
    OOM us. For each fingerprint we either create a new
    ``dhcp_fingerprint`` row or refresh ``last_seen_at`` on the
    existing one. Fresh / signature-changed rows enqueue a Celery
    task that does the slow part (fingerbank lookup +
    ``IPAddress.device_*`` stamping) so the agent's POST returns
    fast.

    No audit row written — fingerprint observations are too
    high-volume to land in the audit log; the agent generates one
    per DISCOVER/REQUEST per device. Operator-triggered actions
    against this surface DO write audit (see the IPAM router's
    fingerprint endpoints).
    """
    from app.services.profiling.passive import upsert_fingerprint

    server, _ = auth
    if not await claim_batch(
        db, server_id=server.id, batch_id=body.batch_id, stream="dhcp.fingerprints"
    ):
        return duplicate_response(upserted=0, dropped=0, enqueued=0)
    capped = body.fingerprints[:500]
    dropped = max(0, len(body.fingerprints) - len(capped))
    upserted = 0
    enqueue_macs: list[str] = []
    for fp in capped:
        try:
            _, signature_changed = await upsert_fingerprint(
                db,
                mac_address=fp.mac_address,
                option_55=fp.option_55,
                option_60=fp.option_60,
                option_77=fp.option_77,
                client_id=fp.client_id,
            )
        except Exception as exc:  # noqa: BLE001
            # One bad row shouldn't kill the batch — log + skip.
            logger.warning(
                "dhcp_fingerprint_upsert_failed",
                server=str(server.id),
                mac=fp.mac_address,
                error=str(exc),
            )
            continue
        upserted += 1
        if signature_changed:
            enqueue_macs.append(fp.mac_address)

    await db.commit()

    # Dispatch Celery tasks for fresh / changed fingerprints. Lazy
    # import to avoid pulling Celery into the request import graph
    # for every other endpoint in this module.
    if enqueue_macs:
        try:
            from app.tasks.dhcp_fingerprint import lookup_fingerprint_task

            for mac in enqueue_macs:
                lookup_fingerprint_task.delay(mac)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "dhcp_fingerprint_dispatch_failed",
                server=str(server.id),
                count=len(enqueue_macs),
                error=str(exc),
            )

    return {
        "upserted": upserted,
        "dropped": dropped,
        "enqueued": len(enqueue_macs),
    }


@router.post("/dhcp-offers", response_model=DHCPOffersAck)
async def agent_dhcp_offers(
    body: DHCPOfferBatch,
    db: DB,
    auth: tuple[DHCPServer, dict[str, Any]] = Depends(_auth_agent),
) -> dict[str, Any]:
    """Ingest observed DHCP OFFERs from the agent's rogue-detection probe (#370).

    The agent broadcasts a DISCOVER and ships every OFFER it gets back; we
    classify each responder against the group's known DHCP servers + the
    operator allowlist and upsert a ``dhcp_observed_responder`` row. The
    ``rogue_dhcp`` alert fires on rows that classify ``rogue``. Capped at 200
    offers per request. No audit row — observations are high-volume telemetry.
    """
    from app.services.dhcp.rogue_detection import ObservedOffer, record_offers

    server, _ = auth
    if not await claim_batch(db, server_id=server.id, batch_id=body.batch_id, stream="dhcp.offers"):
        return duplicate_response()
    capped = body.offers[:200]
    offers = [
        ObservedOffer(
            server_identifier=o.server_identifier,
            source_ip=o.source_ip,
            source_mac=o.source_mac,
            giaddr=o.giaddr,
            offered_ip=o.offered_ip,
        )
        for o in capped
    ]
    counts = await record_offers(db, server, offers)
    return counts


@router.post("/ra-observations", response_model=RAObservationsAck)
async def agent_ra_observations(
    body: RAObservationBatch,
    db: DB,
    auth: tuple[DHCPServer, dict[str, Any]] = Depends(_auth_agent),
) -> dict[str, Any]:
    """Ingest observed IPv6 Router Advertisements from the agent's RA sniffer (#524).

    The agent's opt-in passive sniffer ships every ICMPv6 type-134 RA it sees;
    we classify each source router against the group's expected-router allowlist
    and upsert a ``ra_observed_router`` row. The ``rogue_ra`` alert fires on rows
    that classify ``rogue``. No-op (zero writes) when the RA module is off, so an
    agent left sniffing costs nothing server-side until the operator opts in.
    Capped at 200 observations per request. No audit row — high-volume telemetry.
    """
    from app.services.dhcp.ra_detection import ObservedRA, record_observations
    from app.services.feature_modules import is_module_enabled

    server, _ = auth
    if not await claim_batch(
        db, server_id=server.id, batch_id=body.batch_id, stream="dhcp.ra_observations"
    ):
        return duplicate_response()
    if not body.observations:
        return {"expected": 0, "acknowledged": 0, "rogue": 0, "skipped": 0}
    if not await is_module_enabled(db, "ipv6.router_advertisements"):
        return {"expected": 0, "acknowledged": 0, "rogue": 0, "skipped": 0}

    observations = [
        ObservedRA(
            source_ip=o.source_ip,
            source_mac=o.source_mac,
            prefixes=list(o.prefixes or []),
            managed_flag=o.managed_flag,
            other_flag=o.other_flag,
            router_lifetime=o.router_lifetime,
            iface=o.iface,
        )
        for o in body.observations[:200]
    ]
    counts = await record_observations(db, server, observations)
    return counts
