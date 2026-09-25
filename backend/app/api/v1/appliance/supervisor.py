"""Supervisor register endpoint (#170 Wave A2).

Lands the new ``POST /api/v1/appliance/supervisor/register`` surface
the new ``spatium-supervisor`` container will call on first boot.
Behind ``platform_settings.supervisor_registration_enabled`` — default
FALSE, so Wave A's landing doesn't change behaviour for any existing
dns / dhcp agent install (which still uses ``/dns/agents/register`` /
``/dhcp/agents/register`` + the long PSK).

Flow:

1. Supervisor generates an Ed25519 keypair on first boot, persists
   the private key on ``/var/persist/spatium-supervisor/``.
2. Supervisor POSTs ``{pairing_code, hostname, public_key_der_b64,
   supervisor_version}`` here.
3. Endpoint validates the pairing code via the existing #169 single-
   use code logic (sha256 lookup, expiry / revoked / already-used
   checks, constant-time friction sleep on every failure mode).
4. On success, atomically marks the code claimed + writes an
   ``appliance`` row in ``pending_approval`` state + emits two audit
   rows (one for the pairing-code claim, one for the registration).
5. Returns ``{appliance_id, state}`` — no bootstrap key, no JWT, no
   cert. Cert signing lands in Wave B1; until then a registered
   supervisor sits in pending until an admin clicks Approve.

Re-register-from-cache semantics: if the supervisor restarts before
hearing back (network blip, container restart), it submits the SAME
public key. We detect the duplicate by ``public_key_fingerprint`` and
short-circuit to "you already exist, here's your appliance_id" rather
than refusing the call — this lets the supervisor recover without
needing a fresh pairing code. The original pairing code stays claimed
to its original IP / hostname.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import re
import secrets
import uuid
from collections.abc import Sequence
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import structlog
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, ValidationInfo, field_validator, model_validator
from sqlalchemy import func as sa_func
from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.api.deps import DB, CurrentUser
from app.core.agent_wake import (
    HOSTCONFIG_ALL,
    WAKE_TICK_SECONDS,
    WakeResult,
    appliance_channel,
    appliance_wake_channels,
    publish_wake,
    wake_subscription,
)
from app.core.permissions import is_effective_superadmin, require_permission
from app.core.responses import PlainTextStreamResponse
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    APPLIANCE_STATE_PENDING_APPROVAL,
    APPLIANCE_STATE_REVOKED,
    CLUSTER_JOIN_STATE_EVICTING,
    CLUSTER_JOIN_STATE_FAILED,
    CLUSTER_JOIN_STATE_JOINING,
    CLUSTER_JOIN_STATE_LEAVING,
    CLUSTER_JOIN_STATE_LEFT,
    CLUSTER_JOIN_STATE_READY,
    CLUSTER_JOIN_STATES_TERMINAL,
    CLUSTER_ROLE_MEMBER,
    CLUSTER_ROLE_PRIMARY,
    DESIRED_CLUSTER_ROLE_MEMBER,
    DESIRED_CLUSTER_ROLE_NONE,
    Appliance,
    PairingClaim,
    PairingCode,
)
from app.models.audit import AuditLog
from app.models.firewall import FirewallApplyState
from app.models.settings import PlatformSettings
from app.services.appliance.apt import apt_bundle
from app.services.appliance.ca import (
    ensure_ca,
    generate_session_token,
    sign_supervisor_cert,
    verify_session_token,
)
from app.services.appliance.firewall import firewall_bundle
from app.services.appliance.lldp import lldp_bundle
from app.services.appliance.network_mtu import (
    evaluate_node as evaluate_node_mtu,
)
from app.services.appliance.network_mtu import (
    fleet_summary_for_appliances,
    network_report,
)
from app.services.appliance.ntp import ntp_bundle
from app.services.appliance.removable import (
    RemovableError,
    archive_path,
    merge_state,
    normalise_desired,
    removable_bundle_safe,
    removable_disk_fields,
    validate_name,
)
from app.services.appliance.removable import (
    report as removable_report,
)
from app.services.appliance.resolver import resolver_bundle
from app.services.appliance.slot_image_target import (
    SlotImageResolutionError,
    new_refire_nonce,
    resolve_slot_image_target,
    stamp_desired_slot_image,
)
from app.services.appliance.snmp import snmp_bundle
from app.services.appliance.ssh import effective_ssh_scope, ssh_bundle
from app.services.appliance.storage_health import (
    StorageFinding,
    evaluate_storage,
    has_storage_report,
    worst_severity,
)
from app.services.appliance.syslog import syslog_bundle
from app.services.dhcp.ha_firewall import dhcp_ha_firewall_inputs

logger = structlog.get_logger(__name__)

# A transient join failure keeps the promote desired-state (so the supervisor
# re-fires the join, bounded by its own per-target attempt ceiling) for this
# long after the latest reported failure; then the row is cleared exactly as
# a permanent failure is, and the operator re-promotes.
_JOIN_AUTO_RETRY_WINDOW = timedelta(minutes=15)
# The three failures no retry can fix, matched against what the runner's
# classifier (appliance/.../spatium-cluster-join ``classify_join_failure``)
# EMITS — not against the k3s log lines it matches on. That distinction is
# the whole content of this constant: ``cluster_join_reason`` is the
# classifier's output message, so a marker lifted from its ``case`` patterns
# ("different token", from "bootstrap data already found and encrypted with
# different token") never matches anything that reaches this function, and
# the failure it was meant to catch is retried for the full window instead
# of clearing at once. ``tests/test_appliance_join_auto_retry.py`` pins each
# marker against the runner's real output so the two cannot drift apart.
_PERMANENT_JOIN_FAILURE_MARKERS = (
    # "this hostname is already an etcd member of the target cluster — evict
    # it (Fleet → Replace, or delete its k8s Node) before re-joining"
    "already an etcd member",
    # "stale k3s bootstrap data on disk — the join token does not match the
    # cluster"
    "the join token does not match",
    # "this node's etcd member was removed from the cluster — it must re-join
    # as a NEW member (leave first)"
    "must re-join as a new member",
)


def _join_failure_is_permanent(reason: str | None) -> bool:
    """PURE: a join failure an automatic retry cannot fix — a stale etcd
    member under this hostname, a bootstrap-token mismatch on disk, or an
    etcd member the cluster has permanently removed. All three need an
    operator to evict, re-pair or leave first.

    Everything else — the seed unreachable while it adds a learner, a
    readiness timeout, an unclassified k3s exit — is treated as transient
    and retried. "the seed rejected the join token" is deliberately in that
    transient set despite naming the token: the campaign's own drill
    produced it from a NETWORK block (2026-09-04 00:55Z), and the retry then
    succeeded once the block lifted."""
    text = (reason or "").lower()
    return any(marker in text for marker in _PERMANENT_JOIN_FAILURE_MARKERS)


def _join_retry_window_elapsed(state_at: datetime | None, now: datetime | None = None) -> bool:
    """PURE: whether the latest failure is older than the auto-retry window.
    An unknown clock counts as elapsed — never retry blind."""
    if state_at is None:
        return True
    now = now or datetime.now(UTC)
    if state_at.tzinfo is None:
        state_at = state_at.replace(tzinfo=UTC)
    return now - state_at > _JOIN_AUTO_RETRY_WINDOW


router = APIRouter()


# Pairing-code constants — kept private to this module rather than
# imported from ``pairing.py`` so the supervisor flow doesn't pick up
# unrelated changes if the existing surface is reshaped in A3.
_CODE_LENGTH = 8
_CONSUME_FAILURE_DELAY_S = 0.5


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("ascii")).hexdigest()


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


# #272 Phase 1 — self-bootstrap path for the control-plane appliance.
# The local supervisor calls
# ``POST /api/v1/appliance/self-register-bootstrap`` with its
# variant; the api gates on the host-mounted ``role-config`` (the
# api itself has a bind mount of ``/etc/spatiumddi-host/role-
# config`` per #209) so we can prove the caller is the local
# supervisor by matching the variant claim against the file the
# installer wrote. Only the control-plane node self-bootstraps (it IS
# the control plane); an ``appliance`` pairs against a remote one.
# Legacy ``full-stack`` / ``frontend-core`` accepted as aliases for a
# not-yet-reinstalled box.
_HOST_ROLE_CONFIG = Path("/etc/spatiumddi-host/role-config")
_SELF_BOOTSTRAP_VARIANTS = frozenset({"control-plane", "full-stack", "frontend-core"})
_SELF_BOOTSTRAP_CODE_TTL = timedelta(minutes=10)


def _read_host_role() -> str | None:
    """Parse ``ROLE=`` out of ``/etc/spatiumddi-host/role-config``.

    Mirror of the supervisor's ``detect_appliance_variant`` — read by
    the api via its #209 host bind mount. Returns None when the file
    isn't mounted (docker / k8s) or the parsed value isn't one the
    self-bootstrap gate recognises.
    """
    try:
        text = _HOST_ROLE_CONFIG.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("ROLE="):
            value = line.split("=", 1)[1].strip().strip('"').strip("'")
            return value if value in _SELF_BOOTSTRAP_VARIANTS else None
    return None


def _gen_self_bootstrap_code() -> str:
    """8-digit numeric pairing code, same shape the installer wizard
    produces. ``secrets.choice`` for cryptographically-uniform
    digits (no modulo bias from int conversion)."""
    return "".join(secrets.choice("0123456789") for _ in range(_CODE_LENGTH))


# ── Schemas ────────────────────────────────────────────────────────


class SupervisorCapabilities(BaseModel):
    """Facts the supervisor advertises on register + every heartbeat.

    All fields optional / defaulted — additive evolution is the only
    forward-compat shape we'll need; the control plane stores the
    block verbatim and ignores keys it doesn't recognise. New
    capability flags ship in supervisor releases and surface on the
    control plane without a migration.
    """

    can_run_dns_bind9: bool = False
    can_run_dns_powerdns: bool = False
    can_run_dns_technitium: bool = False
    can_run_dhcp: bool = False
    can_run_looking_glass: bool = False
    can_run_observer: bool = False
    has_baked_images: bool = False
    baked_images_version: str | None = None
    cpu_count: int | None = None
    memory_mb: int | None = None
    storage_type: str | None = None
    host_nics: list[str] = Field(default_factory=list)
    # The supervisor has sent this in every heartbeat's capabilities, and
    # until #1183 nothing read it: ``Appliance.supervisor_version`` was
    # written only at registration, which a registered supervisor never
    # repeats, so the column kept its first value through every upgrade.
    # No max_length here: a bad value must not 422 the whole heartbeat.
    supervisor_version: str | None = None


class SupervisorRegisterRequest(BaseModel):
    pairing_code: str = Field(
        min_length=_CODE_LENGTH,
        max_length=_CODE_LENGTH,
        description="8-digit pairing code minted by an admin in the Pairing tab.",
    )
    hostname: str = Field(
        min_length=1,
        max_length=255,
        description="Operator-supplied hostname; surfaces in the fleet UI.",
    )
    public_key_der_b64: str = Field(
        description=(
            "Base64-encoded DER form of the supervisor's Ed25519 "
            "public key. The supervisor generates the keypair on "
            "first boot and stores the private half on /var so it "
            "survives slot swaps."
        )
    )
    supervisor_version: str | None = Field(
        default=None,
        max_length=64,
        description="Supervisor build version, e.g. '2026.09.04-1'.",
    )
    capabilities: SupervisorCapabilities | None = Field(
        default=None,
        description=(
            "Supervisor-advertised facts used by the control plane "
            "to filter role assignment options."
        ),
    )
    # #272 Phase 1 — installer-role variant from
    # /etc/spatiumddi-host/role-config:ROLE. Lets the control plane
    # stamp ``appliance_variant`` + auto-assign the variant's fixed
    # role set on the resulting Appliance row at register time
    # instead of waiting for the first heartbeat. None for pre-#272
    # supervisors.
    appliance_variant: (
        Literal[
            "control-plane",
            "appliance",
            # legacy (pre-#272) — accepted from not-yet-reinstalled boxes
            "full-stack",
            "frontend-core",
            "application",
        ]
        | None
    ) = None

    @field_validator("pairing_code")
    @classmethod
    def _digits_only(cls, v: str) -> str:
        # Operator-facing presentation can carry dashes / spaces
        # (frontend chunks the code as ``1234-5678`` for
        # readability); strip every non-digit before validating so
        # ``1234-5678`` / ``1234 5678`` / ``12345678`` all
        # resolve to the same canonical hash.
        cleaned = "".join(ch for ch in v if ch.isdigit())
        if len(cleaned) != 8:
            raise ValueError("Pairing code must be 8 decimal digits.")
        return cleaned


class SupervisorRegisterResponse(BaseModel):
    """Register response shape. The supervisor stashes ``session_token``
    locally and uses it for ``/supervisor/poll`` until the appliance
    is approved; after approval it switches to mTLS with the cert
    that ``/supervisor/poll`` returns.
    """

    appliance_id: uuid.UUID
    state: Literal["pending_approval", "approved"]
    # Echoed back for the supervisor's audit log line, so the log
    # reads "registered as ab-cd-… with fingerprint 1234abcd…" without
    # needing to re-derive the hash on the client side.
    public_key_fingerprint: str
    # One-time token returned to the supervisor for /supervisor/poll
    # calls until cert issuance. Stored sha256'd on the appliance row;
    # cleartext is shown exactly once. On re-register-from-cache
    # (idempotent path) the token is rotated — the previous one is
    # implicitly invalidated by hash mismatch.
    session_token: str


class SupervisorPollRequest(BaseModel):
    appliance_id: uuid.UUID
    session_token: str = Field(min_length=1)


class SupervisorPollResponse(BaseModel):
    """Polled by the supervisor every few seconds between register
    and approval. Once approved, ``cert_pem`` + ``ca_chain_pem`` are
    populated and the supervisor switches to mTLS for everything else.
    """

    appliance_id: uuid.UUID
    state: Literal["pending_approval", "approved"]
    cert_pem: str | None = None
    ca_chain_pem: str | None = None
    cert_expires_at: datetime | None = None


# ── Helpers ────────────────────────────────────────────────────────


def _decode_pubkey(payload: str) -> tuple[bytes, str]:
    """Return (der_bytes, sha256_fingerprint_hex). Raises HTTPException
    422 on any decoding / parsing failure."""
    try:
        raw = base64.b64decode(payload, validate=True)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "public_key_der_b64 is not valid base64.",
        ) from exc
    if len(raw) > 1024:
        # Ed25519 DER is 44 bytes; anything over 1 KB is malformed or
        # an attempted resource exhaustion via a giant blob.
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "public_key_der_b64 exceeds 1024 bytes.",
        )
    try:
        pubkey = load_der_public_key(raw)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "public_key_der_b64 is not a parseable DER public key.",
        ) from exc
    if not isinstance(pubkey, Ed25519PublicKey):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "public_key_der_b64 must be an Ed25519 public key.",
        )
    # Re-serialise to canonical SubjectPublicKeyInfo DER so the
    # fingerprint is over a stable form regardless of which encoding
    # the caller submitted (e.g. raw 32-byte key wrapped vs already-
    # SPKI). Cryptography rejected the raw form above; here we just
    # normalise.
    canonical = pubkey.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(canonical).hexdigest()
    return canonical, fingerprint


async def _module_enabled(db: DB) -> bool:
    """Read the feature flag. Cached settings row is fine — operator
    flipping the toggle takes effect on the next API call without a
    process restart."""
    stmt = select(PlatformSettings).where(PlatformSettings.id == 1)
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is None:
        return False
    return bool(row.supervisor_registration_enabled)


# ── Self-bootstrap (full-stack / frontend-core) ────────────────────


class SelfRegisterBootstrapRequest(BaseModel):
    """Body for ``POST /appliance/self-register-bootstrap`` — the
    local supervisor's first call on full-stack / frontend-core
    variants, where the installer wizard didn't capture a pairing
    code (the control plane IS local).

    The supervisor claims its variant; the api validates against
    the host-mounted ``role-config:ROLE`` before minting a code.
    """

    appliance_variant: Literal["control-plane", "full-stack", "frontend-core"]


class SelfRegisterBootstrapResponse(BaseModel):
    code: str = Field(min_length=_CODE_LENGTH, max_length=_CODE_LENGTH)
    control_plane_url: str
    expires_in_seconds: int


@router.post(
    "/self-register-bootstrap",
    response_model=SelfRegisterBootstrapResponse,
    summary=(
        "Mint a pairing code for the local supervisor on full-stack / "
        "frontend-core appliances (single-shot)"
    ),
)
async def self_register_bootstrap(
    body: SelfRegisterBootstrapRequest,
    request: Request,
    db: DB,
) -> SelfRegisterBootstrapResponse:
    """Mint a one-shot pairing code so the local supervisor can
    register against its own control plane.

    Gates (all required, in order):

    1. Variant must be ``full-stack`` or ``frontend-core``.
       ``application`` uses the operator-typed pairing code from
       the installer wizard; this endpoint refuses to short-
       circuit that flow.
    2. The api's host bind mount ``/etc/spatiumddi-host/role-
       config:ROLE`` must equal the requested variant. Proves the
       caller has host access AND the host's installer-baked role
       matches the claim. On non-appliance deploys the file isn't
       mounted and the endpoint refuses outright.
    3. No LIVE ``Appliance`` row may exist (``last_seen_at IS NOT
       NULL``). Orphan rows (``last_seen_at IS NULL``) from a
       botched earlier attempt get cleared on each call so the
       endpoint is safe to re-fire when the supervisor lost its
       local state. Multi-node HA (#272 Phase 7) provisions
       additional supervisors through the operator-typed pairing-
       code flow, not this endpoint.
    4. Module gate (``supervisor_registration_enabled``) — same
       gate the normal pair-and-register endpoint honours.

    Failures collapse into 403 with a constant friction delay so
    the gate decision doesn't leak via response-time delta. Hits
    one of: variant mismatch / appliances already registered /
    module disabled / role-config missing.

    On success the response carries the cleartext pairing code +
    the appliance-local control-plane URL (``https://localhost``).
    The supervisor stamps these into its env and proceeds through
    the normal ``/supervisor/register`` flow.

    Note: this endpoint deliberately does NOT honour the
    ``supervisor_registration_enabled`` module gate (which guards
    the public ``/supervisor/register`` endpoint). The local
    supervisor MUST be able to register or the appliance is
    unusable; the operator-controlled module gate gets re-applied
    once they reach the Fleet UI to control remote pairing.
    Strong gates remain via host role-config + variant + single-
    shot Appliance-count check below.
    """
    # Variant gate.
    if body.appliance_variant not in _SELF_BOOTSTRAP_VARIANTS:
        await asyncio.sleep(_CONSUME_FAILURE_DELAY_S)
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="Self-bootstrap is only available for full-stack / frontend-core variants",
        )

    # Host role-config gate — read /etc/spatiumddi-host/role-config
    # and verify ROLE matches what the caller claims. On non-appliance
    # deploys the file doesn't exist and we refuse.
    host_role = _read_host_role()
    if host_role is None or host_role != body.appliance_variant:
        await asyncio.sleep(_CONSUME_FAILURE_DELAY_S)
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="Self-bootstrap unavailable on this host",
        )

    # Single-shot gate — refuse if any LIVE Appliance row exists.
    # "Live" = at least one successful heartbeat (last_seen_at IS NOT
    # NULL). Orphan rows from a botched earlier self-bootstrap (the
    # supervisor minted a row, never finished register, then lost its
    # local state — verified live on .199 after a Fleet-UI delete +
    # service restart) leave a phantom row with last_seen_at=NULL
    # that would otherwise lock this endpoint forever. Promotion of
    # additional control-plane members (#272 Phase 7) uses operator-
    # typed codes through the normal pairing flow, so this gate
    # treats any heartbeating row as "real" and refuses.
    live_count = await db.scalar(
        select(sa_func.count(Appliance.id)).where(Appliance.last_seen_at.is_not(None))
    )
    if live_count and live_count > 0:
        await asyncio.sleep(_CONSUME_FAILURE_DELAY_S)
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="Live appliances already registered; self-bootstrap is single-shot",
        )

    # Clear orphan rows (last_seen_at IS NULL) before minting. These
    # are leftovers from prior self-bootstrap attempts that didn't
    # complete — leaving them would just confuse the Fleet UI with a
    # ghost row that never resurrects. Audit-logged so the operator
    # can trace what got removed if anything seemed odd.
    orphan_rows = (
        (await db.execute(select(Appliance).where(Appliance.last_seen_at.is_(None))))
        .scalars()
        .all()
    )
    for orphan in orphan_rows:
        db.add(
            AuditLog(
                user_id=None,
                user_display_name="anonymous supervisor",
                auth_source="anonymous",
                source_ip=_client_ip(request),
                action="appliance.self_bootstrap_orphan_cleared",
                resource_type="appliance",
                resource_id=str(orphan.id),
                resource_display=orphan.hostname or str(orphan.id),
                result="ok",
                old_value={
                    "hostname": orphan.hostname,
                    "state": orphan.state,
                    "appliance_variant": orphan.appliance_variant,
                },
            )
        )
        await db.delete(orphan)

    # Mint the code.
    code = _gen_self_bootstrap_code()
    expires_at = datetime.now(UTC) + _SELF_BOOTSTRAP_CODE_TTL
    db.add(
        PairingCode(
            code_hash=_hash_code(code),
            code_last_two=code[-2:],
            expires_at=expires_at,
            persistent=False,
            enabled=True,
            # The supervisor that consumes this code on
            # /supervisor/register gets auto-approved (cert signed +
            # state=approved). The operator doesn't have to manually
            # approve their own local supervisor on full-stack /
            # frontend-core — they'd have no other choice anyway.
            auto_approve=True,
            note=f"Self-bootstrap pairing code for {body.appliance_variant}",
        )
    )
    # Atomically flip the supervisor_registration_enabled gate on so
    # the supervisor's follow-up ``/supervisor/register`` call doesn't
    # 404 against the same module gate that the public-endpoint
    # default-off protects against. The operator can turn it off
    # again in Settings once they're done pairing — single-shot
    # on the self-bootstrap side (no further auto-enables) and the
    # module gate works as before for any subsequent operator-driven
    # remote pairings.
    settings_row = (
        await db.execute(select(PlatformSettings).where(PlatformSettings.id == 1))
    ).scalar_one_or_none()
    if settings_row is None:
        db.add(PlatformSettings(id=1, supervisor_registration_enabled=True))
    elif not settings_row.supervisor_registration_enabled:
        settings_row.supervisor_registration_enabled = True
    db.add(
        AuditLog(
            user_id=None,
            user_display_name="anonymous supervisor",
            auth_source="anonymous",
            source_ip=_client_ip(request),
            action="appliance.self_bootstrap_minted",
            resource_type="pairing_code",
            resource_id=code[-2:],
            resource_display=f"self-bootstrap code (…{code[-2:]})",
            result="ok",
            new_value={
                "appliance_variant": body.appliance_variant,
                "expires_at": expires_at.isoformat(),
            },
        )
    )
    await db.commit()

    logger.info(
        "appliance.self_bootstrap.minted",
        variant=body.appliance_variant,
        code_last_two=code[-2:],
        expires_at=expires_at.isoformat(),
    )

    # Return the in-cluster Service URL — ``https://localhost`` from
    # inside a Kubernetes pod is the pod's own loopback, not the api.
    # The supervisor will use this URL for every subsequent
    # /supervisor/register + /supervisor/heartbeat call. http:// is
    # fine inside the cluster — nothing exits the spatium namespace.
    return SelfRegisterBootstrapResponse(
        code=code,
        control_plane_url="http://spatium-control-spatiumddi-api.spatium.svc.cluster.local:8000",
        expires_in_seconds=int(_SELF_BOOTSTRAP_CODE_TTL.total_seconds()),
    )


# ── Endpoint ───────────────────────────────────────────────────────


@router.post(
    "/supervisor/register",
    response_model=SupervisorRegisterResponse,
    summary="Register a spatium-supervisor with a pairing code (unauthenticated)",
)
async def supervisor_register(
    body: SupervisorRegisterRequest,
    request: Request,
    db: DB,
) -> SupervisorRegisterResponse:
    """Register a supervisor + claim its pairing code in one shot.

    UNAUTHENTICATED — the pairing code IS the auth, same shape as
    ``POST /api/v1/appliance/pair``. Failure modes are deliberately
    collapsed into a single 403 with a constant friction delay so a
    brute-forcer can't distinguish "wrong code" from "expired" from
    "supervisor registration disabled" via timing or response shape.
    """
    # Feature gate. While disabled the endpoint behaves exactly like
    # "not found" — same shape an attacker probing for the path would
    # see if it didn't exist. Sleep before the 404 so toggling the
    # flag doesn't reveal itself via response-time delta.
    if not await _module_enabled(db):
        await asyncio.sleep(_CONSUME_FAILURE_DELAY_S)
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Not found.",
        )

    # Parse + normalise pubkey before touching the pairing-code path —
    # 422s on a malformed pubkey shouldn't burn a real pairing code.
    pubkey_der, pubkey_fingerprint = _decode_pubkey(body.public_key_der_b64)

    submitted_hash = _hash_code(body.pairing_code)
    client_ip = _client_ip(request)
    now = datetime.now(UTC)

    # Re-register-from-cache short circuit — same pubkey resubmits hit
    # the same row. We don't even validate the pairing code in this
    # case (the original registration already burned it, and re-
    # submitting the same code would 403 here, locking the supervisor
    # out of recovery). The supervisor's local state-dir is the
    # source of truth for its identity; if the operator wants to
    # force a fresh registration they delete the row in the fleet UI,
    # which causes the supervisor to clear its identity + claim a new
    # pairing code on next boot.
    existing_stmt = select(Appliance).where(Appliance.public_key_fingerprint == pubkey_fingerprint)
    existing = (await db.execute(existing_stmt)).scalar_one_or_none()
    if existing is not None:
        # Idempotent re-register. Touch last_seen_at so the heartbeat
        # path stays useful even before A2+ ships a separate
        # heartbeat endpoint. Update capabilities + supervisor_version
        # since the supervisor may have upgraded between calls.
        existing.last_seen_at = now
        existing.last_seen_ip = client_ip
        if body.supervisor_version:
            existing.supervisor_version = body.supervisor_version
        if body.capabilities is not None:
            existing.capabilities = body.capabilities.model_dump()
        # Rotate the session token — supervisor must use the fresh one
        # for subsequent polls. Old cached tokens fail hash compare.
        # #411 — ALWAYS mint + return a fresh token, even for a cert'd
        # (approved) row. Previously this blanked the token for cert'd
        # rows ("supervisor uses mTLS"), but the heartbeat's mTLS verifier
        # is not yet enforced — it's a fallback that supersedes the token
        # only when the cert actually validates. Once #400 C1 removed the
        # approved-state heartbeat bypass, an approved box whose cert isn't
        # validating in the field had NO usable credential and 403'd every
        # heartbeat (no reboot / upgrade / role delivery). The session
        # token stays the dependable heartbeat credential until cert-auth
        # is proven + enforced in the field.
        cleartext, digest = generate_session_token()
        existing.session_token_hash = digest
        await db.commit()
        logger.info(
            "supervisor_register_idempotent",
            appliance_id=str(existing.id),
            fingerprint=pubkey_fingerprint,
            ip=client_ip,
        )
        return SupervisorRegisterResponse(
            appliance_id=existing.id,
            state=existing.state,  # type: ignore[arg-type]
            public_key_fingerprint=pubkey_fingerprint,
            session_token=cleartext,
        )

    # Look up pairing code by hash. Single-row index hit.
    stmt = select(PairingCode).where(PairingCode.code_hash == submitted_hash)
    code_row = (await db.execute(stmt)).scalar_one_or_none()

    # Claim count for the code — disambiguates ephemeral (single-use)
    # from persistent (multi-use) gating below.
    claim_count = 0
    if code_row is not None:
        claim_count = int(
            (
                await db.execute(
                    select(sa_func.count(PairingClaim.id)).where(
                        PairingClaim.pairing_code_id == code_row.id
                    )
                )
            ).scalar_one()
        )

    failure_reason: str | None = None
    if code_row is None:
        failure_reason = "unknown_code"
    elif code_row.revoked_at is not None:
        failure_reason = "revoked"
    elif code_row.expires_at is not None and code_row.expires_at <= now:
        failure_reason = "expired"
    elif not code_row.persistent and claim_count > 0:
        # Ephemeral codes: any prior claim disqualifies the code from
        # future claims (today's #169 single-use semantics).
        failure_reason = "already_used"
    elif code_row.persistent and not code_row.enabled:
        # Persistent code paused by admin.
        failure_reason = "disabled"
    elif (
        code_row.persistent
        and code_row.max_claims is not None
        and claim_count >= code_row.max_claims
    ):
        failure_reason = "exhausted"

    if failure_reason is not None:
        db.add(
            AuditLog(
                user_id=None,
                user_display_name="anonymous supervisor",
                auth_source="anonymous",
                source_ip=client_ip,
                action="appliance.supervisor_register_denied",
                resource_type="pairing_code",
                resource_id=str(code_row.id) if code_row is not None else "unknown",
                resource_display=(
                    "supervisor pairing code" if code_row is not None else "unknown pairing code"
                ),
                result="forbidden",
                new_value={
                    "reason": failure_reason,
                    "hostname": body.hostname,
                    "fingerprint": pubkey_fingerprint,
                },
            )
        )
        await db.commit()
        logger.warning(
            "supervisor_register_denied",
            reason=failure_reason,
            ip=client_ip,
            hostname=body.hostname,
            fingerprint=pubkey_fingerprint,
        )
        await asyncio.sleep(_CONSUME_FAILURE_DELAY_S)
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Pairing code is invalid, expired, or already used. "
            "Ask your platform admin to generate a new code.",
        )

    assert code_row is not None
    # Constant-time hash compare — index lookup already matched on
    # exact equality, but the canonical idiom keeps future refactors
    # honest.
    if not hmac.compare_digest(code_row.code_hash, submitted_hash):  # pragma: no cover
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Hash mismatch.")

    # Create the appliance row + the pairing_claim audit row
    # atomically. PairingCode no longer carries used_at semantics —
    # claim accounting lives in pairing_claim now (A3).
    appliance_id = uuid.uuid4()
    session_cleartext, session_hash = generate_session_token()
    # #272 Phase 1 — stamp variant + auto-assign fixed roles at
    # register time. Variant comes from /etc/spatiumddi-host/role-
    # config:ROLE on the supervisor side; control plane uses it to
    # populate ``Appliance.assigned_roles`` so the Fleet UI's
    # Services chips render correctly without waiting for the
    # operator to open the role-picker.
    initial_assigned_roles: list[str] = []
    if body.appliance_variant is not None:
        initial_assigned_roles = list(_REGISTER_VARIANT_FIXED_ROLES.get(body.appliance_variant, []))
    appliance_row = Appliance(
        id=appliance_id,
        hostname=body.hostname,
        public_key_der=pubkey_der,
        public_key_fingerprint=pubkey_fingerprint,
        supervisor_version=body.supervisor_version,
        capabilities=(body.capabilities.model_dump() if body.capabilities else {}),
        session_token_hash=session_hash,
        paired_at=now,
        paired_from_ip=client_ip,
        paired_via_code_id=code_row.id,
        state=APPLIANCE_STATE_PENDING_APPROVAL,
        appliance_variant=body.appliance_variant,
        assigned_roles=initial_assigned_roles,
    )
    db.add(appliance_row)
    # #272 Phase 1 — auto-approve when the consumed pairing code was
    # minted by /self-register-bootstrap (i.e. the operator's own
    # local supervisor on full-stack / frontend-core). The operator
    # has no other choice but to approve themselves; doing it inline
    # here saves a click + makes the Fleet row green from the first
    # render. Operator-typed pairing codes from the Fleet → Pairing
    # tab keep ``auto_approve=False`` so manual approval stays the
    # norm for any remote pairing.
    if code_row.auto_approve:
        await _approve_appliance_inline(db, appliance_row, approved_by_user_id=None)
        db.add(
            AuditLog(
                user_id=None,
                user_display_name=body.hostname,
                auth_source="self_bootstrap",
                source_ip=client_ip,
                action="appliance.auto_approved",
                resource_type="appliance",
                resource_id=str(appliance_id),
                resource_display=body.hostname,
                result="success",
                new_value={
                    "hostname": body.hostname,
                    "fingerprint": pubkey_fingerprint,
                    "appliance_variant": body.appliance_variant,
                    "cert_serial": appliance_row.cert_serial,
                },
            )
        )
    db.add(
        PairingClaim(
            pairing_code_id=code_row.id,
            appliance_id=appliance_id,
            claimed_at=now,
            claimed_from_ip=client_ip,
            hostname=body.hostname,
        )
    )

    # Audit row pair — claim + registration. Two rows make it easier
    # to filter for "appliance lifecycle" in the audit UI without
    # losing pairing-code accountability.
    db.add(
        AuditLog(
            user_id=None,
            user_display_name=body.hostname,
            auth_source="pairing_code",
            source_ip=client_ip,
            action="appliance.pairing_code_claimed",
            resource_type="pairing_code",
            resource_id=str(code_row.id),
            resource_display="supervisor pairing code",
            result="success",
            new_value={
                "hostname": body.hostname,
                "appliance_id": str(appliance_id),
                "claim_kind": "supervisor",
            },
        )
    )
    db.add(
        AuditLog(
            user_id=None,
            user_display_name=body.hostname,
            auth_source="pairing_code",
            source_ip=client_ip,
            action="appliance.registration_pending",
            resource_type="appliance",
            resource_id=str(appliance_id),
            resource_display=body.hostname,
            result="success",
            new_value={
                "hostname": body.hostname,
                "fingerprint": pubkey_fingerprint,
                "supervisor_version": body.supervisor_version,
                "paired_via_code_id": str(code_row.id),
            },
        )
    )
    await db.commit()
    logger.info(
        "supervisor_registration_pending",
        appliance_id=str(appliance_id),
        hostname=body.hostname,
        fingerprint=pubkey_fingerprint,
        ip=client_ip,
    )

    return SupervisorRegisterResponse(
        appliance_id=appliance_id,
        # The auto-approve branch above flipped row.state to
        # ``approved``; otherwise stays at ``pending_approval``.
        state=appliance_row.state,  # type: ignore[arg-type]
        public_key_fingerprint=pubkey_fingerprint,
        session_token=session_cleartext,
    )


# ── /supervisor/poll ───────────────────────────────────────────────


@router.post(
    "/supervisor/poll",
    response_model=SupervisorPollResponse,
    summary="Poll for approval state + cert (unauthenticated, session-token gated)",
)
async def supervisor_poll(
    body: SupervisorPollRequest,
    request: Request,
    db: DB,
) -> SupervisorPollResponse:
    """Polled by the supervisor every few seconds between register
    and approval. Verifies the appliance's session token (constant-
    time hash compare) and returns the current state. On approval
    the cert + CA chain are populated; the supervisor switches to
    mTLS for everything subsequent.

    Unauth — the session_token IS the auth. After approval the
    session_token is cleared from the row and this endpoint returns
    403; the supervisor is expected to be using mTLS by then.

    Like the other unauth endpoints, friction-sleep on every failure
    mode so an attacker probing for valid appliance_ids can't
    distinguish "wrong token" from "doesn't exist" via timing.
    """
    if not await _module_enabled(db):
        await asyncio.sleep(_CONSUME_FAILURE_DELAY_S)
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")

    row = await db.get(Appliance, body.appliance_id)
    valid = row is not None and verify_session_token(body.session_token, row.session_token_hash)
    if not valid:
        await asyncio.sleep(_CONSUME_FAILURE_DELAY_S)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid appliance or session.")

    assert row is not None  # narrowed by valid above

    # Touch last-seen on every poll so the fleet UI knows the
    # supervisor is alive even before mTLS / heartbeat lands.
    row.last_seen_at = datetime.now(UTC)
    row.last_seen_ip = _client_ip(request)

    ca_chain_pem: str | None = None
    if row.cert_pem is not None:
        # Lazy CA fetch — the CA must exist if cert_pem is populated
        # (the approve endpoint guarantees this), but we still go
        # through ensure_ca() so a fresh DB without an approved
        # appliance yet doesn't fail this read.
        ca = await ensure_ca(db)
        ca_chain_pem = ca.cert_pem
        await db.commit()
    else:
        await db.commit()

    return SupervisorPollResponse(
        appliance_id=row.id,
        state=row.state,  # type: ignore[arg-type]
        cert_pem=row.cert_pem,
        ca_chain_pem=ca_chain_pem,
        cert_expires_at=row.cert_expires_at,
    )


# ── /supervisor/heartbeat ─────────────────────────────────────────


class SupervisorHeartbeatRequest(BaseModel):
    """Periodic heartbeat from the supervisor (#170 Wave C1).

    Carries the appliance-host telemetry block the service agents used
    to ship on their own per-row heartbeats in #138 Phase 8f-2. The
    supervisor is now the single source of truth for appliance-host
    state — service agents drop their host bind mounts in C1.

    Auth model is interim: session-token gated for now (same shape as
    /supervisor/poll). Wave C2/D will require mTLS once the verifier
    middleware lands, and the session_token field becomes optional
    (mTLS subject CN = appliance_id is the auth principal). Both
    paths persist the same fields.
    """

    appliance_id: uuid.UUID
    session_token: str | None = None
    # #358 Phase 1b — opt-in heartbeat long-poll. >0 asks the control
    # plane to hold the response open up to this many seconds (capped
    # server-side) waiting for a per-appliance wake, so operator commands
    # start in ~0 s. Omitted/0 by pre-#358 supervisors → return at once
    # (today's behavior), which keeps the rolling-upgrade skew window safe.
    wait_seconds: int = Field(default=0, ge=0)
    capabilities: SupervisorCapabilities | None = None
    deployment_kind: Literal["appliance", "docker", "k8s", "unknown"] | None = None
    # #272 Phase 1 — installer-role variant read by the supervisor from
    # ``/etc/spatiumddi-host/role-config:ROLE``. None on pre-#272
    # supervisors; the persistence handler leaves the column
    # untouched in that case (no nulling of an existing variant).
    appliance_variant: (
        Literal[
            "control-plane",
            "appliance",
            # legacy (pre-#272) — accepted from not-yet-reinstalled boxes
            "full-stack",
            "frontend-core",
            "application",
        ]
        | None
    ) = None
    # #1026 — the node's CPU architecture from the supervisor's
    # ``platform.machine()``, normalised to the artifact vocabulary.
    # None on a supervisor too old to report it; the handler leaves the
    # column untouched in that case, same as ``appliance_variant``.
    #
    # A ``Literal`` rather than a free string, so an unrecognised value
    # is a 422 at the door instead of a row that compares unequal to
    # every real architecture and silently refuses every upgrade.
    architecture: Literal["amd64", "arm64"] | None = None
    installed_appliance_version: str | None = None
    current_slot: Literal["slot_a", "slot_b"] | None = None
    durable_default: Literal["slot_a", "slot_b"] | None = None
    # Per-slot installed version — read by the supervisor from the
    # ``slot-versions.json`` sidecar maintained by
    # ``spatium-upgrade-slot sync-versions``. Either / both may be
    # ``None`` (sidecar missing, or freshly imaged inactive slot has
    # never been stamped). The empty-string-mapped values used by the
    # CLI sidecar (``"unstamped"`` / ``"unreadable"`` / ``"unknown"``)
    # are accepted verbatim — the UI's ``slotVersion`` helper renders
    # them as ``"—"``.
    slot_a_version: str | None = None
    slot_b_version: str | None = None
    is_trial_boot: bool | None = None
    last_upgrade_state: Literal["ready", "in-flight", "done", "failed"] | None = None
    last_upgrade_state_at: datetime | None = None
    # Issue #386 Part C — tail of the host ``slot-upgrade.log`` so the
    # Fleet drilldown can show what an in-flight / failed apply is doing.
    # The supervisor ships the last lines while state is in-flight/failed
    # and ``""`` once ready/done (clears a stale tail); None on
    # non-appliance so the handler leaves the column alone.
    last_upgrade_log_tail: str | None = None
    # Issue #386 Part C — structured per-phase progress (step / pct /
    # detail / at) so the Fleet UI renders a real status stepper. ``{}``
    # once no longer in-flight (clear); None on non-appliance.
    last_upgrade_progress: dict[str, Any] | None = None
    snmpd_running: bool | None = None
    # Issue #430 — the supervisor already ships this every heartbeat
    # (appliance_state lldpd sidecar); it was silently dropped (no field /
    # column / handler). Now persisted alongside lldp_neighbours.
    lldpd_running: bool | None = None
    ntp_sync_state: Literal["synchronized", "unsynchronized", "unknown"] | None = None
    # Issue #156 — best-effort rsyslog-forwarding status. None = not
    # collected (leave the stored column alone); a value persists.
    syslog_forwarding: Literal["forwarding", "unreachable", "disabled"] | None = None
    # Issue #157 — count of authorized_keys lines the host runner actually
    # applied to ``~admin/.ssh/authorized_keys``. PER-HOST. None = not
    # collected (leave the stored column alone); a value (incl. 0) persists.
    ssh_key_count: int | None = None
    # Issue #158 — systemd-resolved state the host runner reports after
    # applying the resolver config. None = not collected (leave the stored
    # column alone); a value persists. ``override`` = spatiumddi.conf
    # drop-in applied; ``automatic`` = no drop-in; ``failed`` = apply error.
    resolver_status: Literal["override", "automatic", "failed"] | None = None
    # Issue #155 — APT host-config state the runner reports from its
    # .state sidecar after validate + swap. None = not collected (leave
    # the stored column alone); a value persists.
    apt_state: (
        Literal[
            "synced",
            "proxy-failed",
            "mirror-unreachable",
            "signature-mismatch",
            "no-sources",
            "unmanaged",
            "unknown",
        ]
        | None
    ) = None
    # Issue #347 — LLDP neighbours the local lldpd discovered. ``None`` = not
    # collected (leave the stored set alone); a list (possibly empty) is the
    # authoritative current set the handler upserts + absence-deletes against.
    lldp_neighbours: list[dict[str, Any]] | None = None
    # #170 Phase E2 — host-side port conflicts probed by the
    # supervisor. Free-form dict keyed by ``<proto>_<port>``; values
    # are the ``users`` string from ``ss -p`` (process name / pid).
    # None / omitted = supervisor didn't run the probe this tick.
    port_conflicts: dict[str, str] | None = None
    # #593 — the supervisor refused a firewall drop-in that would have closed
    # etcd's peer port on a node k3s still calls an etcd member (a stale row).
    # ``{}`` when healthy; None / omitted = an older supervisor didn't report,
    # so the stored value is left untouched.
    firewall_state: dict[str, str] | None = None
    # #170 Wave D follow-up — outcome of the supervisor's last
    # compose-lifecycle apply (``idle`` / ``ready`` / ``failed``).
    # None on the first heartbeat / before any role assignment.
    role_switch_state: Literal["idle", "ready", "failed"] | None = None
    role_switch_reason: str | None = None
    # #170 Wave E — service-container watchdog. Free-form dict keyed
    # by compose service name (``dns-bind9`` / ``dns-powerdns`` /
    # ``dns-technitium`` / ``dhcp-kea``); each value carries ``{role, status, since,
    # container_id}`` where status ∈ {healthy, missing, unhealthy,
    # starting}. The supervisor probes every 5 min and ships the
    # cached verdict on every heartbeat; the Fleet drilldown surfaces
    # the per-service status alongside the role-assignment block.
    # None / omitted = supervisor didn't run the watchdog this tick
    # (typical on docker / k8s deployments or before the first probe).
    role_health: dict[str, dict[str, Any]] | None = None
    # #387 — per-plane host-config apply health from the supervisor's
    # bounded-retry fire-guard. ``{<plane>: {state, attempts, at}}`` for
    # the hash-keyed runners (snmp / ntp / lldp / syslog / ssh /
    # resolver / firewall / timezone). Empty dict = all applied / healthy
    # (clears stale entries); None / omitted = pre-#387 supervisor.
    host_config_health: dict[str, dict[str, Any]] | None = None
    # #395 — host-migration reconcile health from the supervisor's read
    # of the ``host-patches-applied.json`` ledger. ``{<patch-id>:
    # {state, attempts, at, error?}}``; only patches with ``ok: false``
    # appear. Empty dict = all patches applied (clears stale entries);
    # None / omitted = pre-#395 supervisor (leave the column alone).
    host_migration_health: dict[str, dict[str, Any]] | None = None
    # Issue #183 Phase 4 — local k3s cluster health summary. Shape:
    # ``{"kubeapi_ready": bool, "nodes_total": int, "nodes_ready":
    # int, "pods_total": int, "pods_by_phase": {<phase>: count}}``.
    # Empty dict on legacy compose appliances; None / omitted = the
    # supervisor didn't run the probe this tick (pre-#183 supervisors).
    cluster_health: dict[str, Any] | None = None
    # #59 — host NICs the supervisor read from /run/udev/data (real
    # NICs like ens18 + cni0; ephemeral veth* filtered). Surfaced as the
    # appliance-vantage packet-capture interface picker. None / omitted =
    # the supervisor didn't enumerate this tick (non-appliance or
    # pre-#59 supervisor); empty list = enumerated but found nothing.
    host_interfaces: list[str] | None = None
    # Issue #183 Phase 5 — operator-facing k3s metadata.
    # ``k3s_version`` is the upstream release tag the slot was baked
    # against (e.g. ``v1.36.4+k3s1``). ``kubeconfig`` is the raw
    # admin kubeconfig YAML straight off the appliance — the backend
    # rewrites ``server:`` for operator reachability + Fernet-encrypts
    # before persisting. Both ``None`` = supervisor didn't ship them
    # this tick (legacy compose / pre-Phase-5 / k3s not yet started).
    k3s_version: str | None = None
    kubeconfig: str | None = None
    # Issue #183 Phase 6 — k3s server-cert ``Not After`` timestamp
    # (ISO-8601 UTC). None when not k3s; the heartbeat handler
    # leaves the column untouched in that case.
    k3s_api_cert_expires_at: datetime | None = None
    # #272 Phase 7 — control-plane cluster membership.
    # ``k3s_join_token`` is the seed's node-token (read by the PRIMARY's
    # supervisor from /var/lib/rancher/k3s/server/token); the backend
    # Fernet-encrypts it and the promote endpoint hands it to joiners.
    # Only the primary reports it; None elsewhere (leaves the column
    # untouched). ``cluster_join_state`` / ``cluster_join_reason`` are
    # the joiner/leaver's progress report (joining / ready / leaving /
    # left / failed) that drives the desired-state auto-clear.
    k3s_join_token: str | None = None
    cluster_join_state: str | None = None
    cluster_join_reason: str | None = None
    # #272 Phase 7b — the node's real routable k3s InternalIP. Distinct
    # from ``last_seen_ip`` (the supervisor POD's source IP, 10.42.x.x,
    # since it heartbeats from inside the cluster). The promote endpoint
    # builds the join URL from the seed's ``node_ip``. None on
    # non-appliance / non-k3s; the handler leaves the column untouched.
    node_ip: str | None = None
    # Issue #285 Phase 1 — fleet-firewall prerequisites. The (future)
    # server-side firewall compiler needs these to scope the k3s rules
    # before the LAN-wide base accept is removed. All None / absent on a
    # legacy supervisor → the handler leaves the columns alone. Purely
    # additive telemetry; nothing here changes a live firewall yet.
    #   node_ips           — every InternalIP (both families) for
    #                        family-split /32 + /128 peer scoping.
    #   pod_cidr/service_cidr — operator-chosen k3s CIDRs (#302).
    #   dataplane_backend  — vxlan / wireguard-native / … (data-plane port).
    #   base_conf_marker   — sha256 of the live /etc/nftables.conf.
    #   base_lanwide_k3s   — legacy LAN-wide k3s-ha accept still present?
    node_ips: list[str] | None = None
    pod_cidr: str | None = None
    service_cidr: str | None = None
    dataplane_backend: str | None = None
    base_conf_marker: str | None = None
    base_lanwide_k3s: bool | None = None
    # Issue #285 Phase 2b — the host runner's firewall apply outcome,
    # echoed back so the control plane can see drift + drive the apply
    # alarm. The runner already WRITES these sidecars; nothing read them
    # back before. None on a legacy runner / non-appliance → the upsert
    # leaves the column untouched. ``firewall_base_marker`` is the sha256
    # of the live base /etc/nftables.conf (distinct from the Phase-1
    # ``base_conf_marker`` telemetry above, which the supervisor reads
    # directly off the mounted file — this one is what the RUNNER applied
    # against).
    firewall_applied_hash: str | None = None
    firewall_applied_status: str | None = None
    firewall_base_marker: str | None = None
    # #272 Phase 9 — dead-node replacement. The SEED supervisor reports
    # the hostnames of k8s Nodes it successfully evicted (deleting the
    # Node makes k3s drop the etcd member). The handler clears
    # ``evict_requested`` + settles those rows to ``left``. Empty on
    # every non-seed heartbeat + when there's nothing to evict.
    evicted_node_names: list[str] = Field(default_factory=list)
    # #272 Phase 9b — etcd snapshot inventory + restore progress. The
    # SEED reports its local ``k3s etcd-snapshot list`` so the Fleet tab
    # can show recoverable snapshots; ``restore_state`` /
    # ``restore_reason`` mirror the host runner's ``.state`` sidecar
    # while a guided restore is in flight. All "only update when not
    # None / non-empty-on-seed" so a member heartbeat never blanks the
    # seed's inventory. None = no report this tick (leave the row as-is).
    etcd_snapshots: list[dict[str, Any]] | None = None
    restore_state: str | None = None
    restore_reason: str | None = None


class SupervisorRoleAssignment(BaseModel):
    """Per-role config block the supervisor needs to bring up a
    service container (#170 Wave C2).

    DNS / DHCP groups carry an ``agent_key`` so the service container
    can register against the existing ``/dns/agents/register`` /
    ``/dhcp/agents/register`` endpoints. The key is the platform-level
    bootstrap PSK the operator already revealed under Settings →
    Security; the supervisor passes it into the service container's
    env via ``role-compose.env`` so the operator doesn't have to SSH
    in and edit the appliance's ``/etc/spatiumddi/.env`` by hand.

    Returned only when the corresponding role is in the appliance's
    ``assigned_roles`` list — a DHCP-only appliance doesn't get the
    DNS key, even though both PSKs are global.
    """

    roles: list[str] = Field(default_factory=list)
    dns_group_id: uuid.UUID | None = None
    dns_group_name: str | None = None
    dns_engine: str | None = None  # bind9 / powerdns
    # #170 Wave D follow-up — platform-level DNS agent PSK (mirror of
    # ``settings.dns_agent_key``). Populated when a DNS role is
    # assigned + the control plane has the key configured; ``None``
    # otherwise. The supervisor writes ``DNS_AGENT_KEY=<this>`` into
    # role-compose.env so the bind9 / powerdns service container can
    # register against ``/api/v1/dns/agents/register`` without
    # operator-side .env edits.
    dns_agent_key: str | None = None
    dhcp_group_id: uuid.UUID | None = None
    dhcp_group_name: str | None = None
    dhcp_network_mode: str | None = None  # host / bridged
    dhcp_agent_key: str | None = None
    # #566 — platform-level Looking Glass collector PSK (mirror of
    # ``settings.lg_agent_key``). Populated only when the ``looking-glass``
    # role is assigned; the supervisor writes ``LG_AGENT_KEY=<this>`` into
    # role-compose.env so the collector container can register against
    # ``/api/v1/looking-glass/agents/register`` without operator-side .env
    # edits. There is no group concept for the collector (like DNS/DHCP).
    lg_agent_key: str | None = None
    # #170 Wave C3 — operator-pasted nft fragment rendered after the
    # role-driven mgmt + per-role blocks. NULL / empty → role-driven
    # rules only.
    firewall_extra: str | None = None
    # Issue #183 Phase 6 — operator-allowed CIDRs for direct kubeapi
    # access on tcp/6443. Empty = proxy-only (kubeapi stays on
    # 127.0.0.1, only the supervisor's outbound proxy channel can
    # drive it). The supervisor's firewall renderer emits one
    # ``ip saddr { ... } tcp dport 6443 accept`` rule per heartbeat.
    kubeapi_expose_cidrs: list[str] = Field(default_factory=list)
    # Issue #50 — TCP ports of the assigned DNS group's live DoT / DoH
    # listeners. Operator-chosen, so they can't live in the supervisor's
    # static per-role port table the way Do53's 53 does. Empty = no
    # encrypted listener (or no usable cert), and the renderer opens
    # nothing extra.
    dns_encrypted_tcp_ports: list[int] = Field(default_factory=list)
    # #741 — DoQ is UDP, so it needs its own channel: opening its port on
    # tcp would leave the listener unreachable while looking configured.
    dns_encrypted_udp_ports: list[int] = Field(default_factory=list)
    # #1167 — Kea HA: the TCP port this node's HA listener binds (from its own
    # ``ha_peer_url``) and the host CIDRs of the group's other Kea members.
    # The renderer opens that port to exactly those sources — never ``any``:
    # Kea's HA API is unauthenticated by default and accepts lease updates.
    # None / empty = not in a rendered HA group, and nothing is opened.
    dhcp_ha_port: int | None = None
    dhcp_ha_peer_cidrs: list[str] = Field(default_factory=list)


class SupervisorHeartbeatResponse(BaseModel):
    """Operator-driven desired state returned to the supervisor.

    The supervisor compares each field to its local state + fires the
    matching trigger file on the appliance host. Idempotent — same
    desired_version returning across heartbeats produces one trigger
    write, not many (the trigger file's presence is the marker).
    """

    appliance_id: uuid.UUID
    state: Literal["pending_approval", "approved", "rejected"]
    # #358 Phase 1b — True when the control plane long-poll-held this
    # heartbeat (new server honoring wait_seconds). The supervisor uses it
    # to re-arm the hold immediately instead of double-sleeping the
    # interval; absent/False from old control planes.
    long_poll: bool = False
    desired_appliance_version: str | None = None
    desired_slot_image_url: str | None = None
    # Issue #386 Part A — integrity + transport hints the host-side
    # ``spatium-upgrade-slot`` runner uses for the fetch. ``sha256`` is
    # the image's stored hash (the runner verifies bytes against it);
    # ``tls_insecure`` allows skipping cert-verify for the appliance's
    # OWN self-served URL only — honoured host-side ONLY when a sha256
    # is also present. External (public-CA) URLs leave both unset.
    desired_slot_image_sha256: str | None = None
    desired_slot_image_tls_insecure: bool = False
    # Operator's per-slot boot intents. The supervisor writes the
    # matching trigger file when non-null + the current state doesn't
    # already satisfy the request. Both auto-clear in the heartbeat
    # handler once the supervisor reports back that the action landed.
    #
    # ``desired_next_boot_slot`` = one-shot (``grub-reboot``, reverts
    # on the NEXT reboot if the operator doesn't commit). Used to
    # test an inactive slot. Cleared once the supervisor reports the
    # target slot as ``current_slot``.
    # ``desired_default_slot`` = durable (``grub-set-default``,
    # survives reboots). Used to commit a trial boot, or to durably
    # revert. Cleared once the supervisor reports the target slot as
    # ``durable_default``.
    desired_next_boot_slot: Literal["slot_a", "slot_b"] | None = None
    desired_default_slot: Literal["slot_a", "slot_b"] | None = None
    reboot_requested: bool = False
    # #786 — one-shot: reset the host's slot-upgrade sidecars + drop any
    # stranded trigger, so a cleared failure stays cleared instead of
    # being re-published on the next heartbeat.
    clear_upgrade_requested: bool = False
    # #170 Wave D follow-up — supervisor's signed cert + CA chain.
    # Populated when the appliance has been approved + the supervisor
    # hasn't picked them up yet. The supervisor saves them to
    # /var/persist/spatium-supervisor/tls/ + switches its next
    # heartbeat to cert auth (X-Appliance-Cert + X-Appliance-Signature
    # + X-Appliance-Timestamp). Same fields the legacy /supervisor/poll
    # response carried; in-lining them here lets the supervisor stop
    # polling separately.
    cert_pem: str | None = None
    ca_chain_pem: str | None = None
    cert_expires_at: datetime | None = None
    # #170 Wave C2 — assigned roles + group config. The supervisor
    # uses this to bring up dns-bind9 / dns-powerdns / dns-technitium /
    # dhcp-kea service containers via docker compose. Empty roles list = idle
    # (approved but no service running).
    role_assignment: SupervisorRoleAssignment = Field(default_factory=SupervisorRoleAssignment)
    # #272 Phase 7 — control-plane promote/demote desired state.
    # ``desired_cluster_role`` = "member" → join the seed via
    # ``desired_k3s_server_url`` + ``desired_k3s_join_token``; "none" →
    # leave the cluster + revert to a plain application appliance.
    # NULL = no change. The token is the plaintext node-token (the
    # heartbeat channel is mTLS); the supervisor's host-side runner
    # (Phase 7b) reconfigures k3s + reports back via cluster_join_state.
    desired_cluster_role: Literal["member", "none"] | None = None
    desired_k3s_server_url: str | None = None
    desired_k3s_join_token: str | None = None
    # #272 Phase 7b — the node IPs (as ``/32`` CIDRs) of every OTHER
    # control-plane peer this node must reach (and be reachable from) on
    # the k3s server ports (6443 apiserver, 2379/2380 etcd, 10250
    # kubelet). The base appliance firewall only opens :6443 from the pod
    # CIDR, so cross-node server traffic (the join handshake + etcd
    # quorum) is dropped without this. The supervisor renders an
    # nftables drop-in opening those ports from these peers. Empty on a
    # single-node / non-control-plane appliance.
    cluster_peer_cidrs: list[str] = Field(default_factory=list)
    # #285 Phase 1 — derived firewall inputs the in-pod renderer uses to
    # scope the k3s rules. ``firewall_pod_cidrs`` / ``firewall_service_cidrs``
    # widen the 6443 accept (in-cluster apiserver access traverses INPUT
    # via the service-IP DNAT with saddr=pod-IP); sent only for nodes that
    # run the apiserver. (No data-plane / flannel-VXLAN fields: that
    # inter-node traffic doesn't traverse the host INPUT chain on
    # k3s+flannel — field-verified — so no INPUT rule is needed for it.)
    firewall_pod_cidrs: list[str] = Field(default_factory=list)
    firewall_service_cidrs: list[str] = Field(default_factory=list)
    # #285 Phase 6 — operator Web-UI source restriction. Empty = open. The
    # supervisor's in-pod render_drop_in scopes 80/443 to these CIDRs (the
    # base /etc/nftables.conf no longer opens 80/443 LAN-wide).
    web_ui_allowed_cidrs: list[str] = Field(default_factory=list)
    # #1009 — the EFFECTIVE SSH source scope: the operator's allowlist when
    # ``ssh_lockdown`` is on, and EMPTY otherwise. Non-empty is what makes
    # the supervisor's in-pod render stamp ``# spatium-ssh: retire`` and
    # scope the port-22 management line, so the baked floor is only removed
    # when the operator asked for it. Empty is what every consumer already
    # reads as "open unconditionally", which is why an older supervisor that
    # ignores this field keeps the floor — the safe direction.
    ssh_scope_cidrs: list[str] = Field(default_factory=list)
    # #277 — the committed control-plane size (count of settled
    # primary + member nodes, floored at 1). The seed's supervisor
    # patches the spatium-control HelmChart's ``# spatium:cp-size`` lines
    # to this so the CNPG postgres cluster + api/frontend/worker
    # Deployments scale with the cluster (1 instance single-node →
    # 3/5/7 with streaming replicas + failover after promote).
    control_plane_size: int = 1
    # #272 Phase 7c — cluster-wide MetalLB / control-plane-VIP desired
    # state (from platform_settings). Returned to every supervisor but
    # acted on only by the seed (control-plane variant): it patches
    # ``metallb.*`` on spatium-bootstrap + ``frontend.controlPlaneVIP``
    # on spatium-control. Disabled / empty = no VIP (hostNetwork
    # frontend), the single-node default.
    desired_metallb_enabled: bool = False
    desired_metallb_pool_addresses: list[str] = Field(default_factory=list)
    desired_control_plane_vip: str = ""
    # #272 Phase 10 — data-plane resolver VIPs. Acted on only by the seed:
    # it patches ``dns.useMetalLBVIP`` / ``dns.vip`` / ``dhcpKea.relayVIP``
    # on the spatiumddi-appliance HelmChartConfig overlay. Empty = the
    # hostNetwork data plane (single-node default).
    desired_dns_vip: str = ""
    desired_dhcp_relay_vip: str = ""
    # #566 decision D1 — BGP mode. Acted on only by the seed via the
    # SAME apply_metallb_overrides call as the L2 pool (one combined
    # HelmChartConfig body — see k8s_api.py). Empty/false = L2-only
    # MetalLB (today's behaviour, unchanged).
    desired_metallb_bgp_enabled: bool = False
    desired_metallb_bgp_peers: list[dict] = Field(default_factory=list)
    desired_metallb_bgp_advertisements: list[dict] = Field(default_factory=list)
    # #272 Phase 9 — dead-node replacement. Hostnames of k8s Nodes the
    # SEED should evict (delete the Node → k3s removes the etcd member).
    # Populated from rows flagged ``evict_requested``; only the
    # control-plane-variant seed acts on it. The supervisor reports the
    # ones it deleted back via ``evicted_node_names`` so the backend
    # clears the flag. Empty in the steady state.
    evict_node_names: list[str] = Field(default_factory=list)
    # Issue #165 — operator-set IANA timezone from
    # ``platform_settings.timezone``. Empty string = follow the
    # install-time default (no override). The supervisor compares
    # against the host's current tz on every heartbeat + writes the
    # ``spatium-tz-reload`` trigger file when they differ.
    desired_timezone: str = ""
    # #393 — appliance console mode (dashboard / verbose_dashboard /
    # text_console). The supervisor maps it to the grubenv variable
    # (spatium_verbose) the grub.cfg menuentries read, so it survives A/B slot
    # swaps + the /etc overlay and applies on next reboot. Mirrors the
    # desired_timezone delivery exactly.
    desired_console_mode: str = "dashboard"
    # Issue #346 — appliance host-config blocks delivered to the supervisor,
    # which compares each block's ``config_hash`` against its applied sidecar
    # and fires the matching ``spatium-{snmp,chrony,lldp}-reload`` trigger when
    # it differs. Same shape the DHCP-agent ConfigBundle ships; rendered from
    # ``platform_settings`` via the ``*_bundle`` helpers. Empty/disabled blocks
    # are still sent (stable key set) so the supervisor can retract config.
    snmp_settings: dict[str, Any] = Field(default_factory=dict)
    ntp_settings: dict[str, Any] = Field(default_factory=dict)
    lldp_settings: dict[str, Any] = Field(default_factory=dict)
    # Issue #156 — rendered rsyslog forward config + per-target CA PEMs.
    # Same shape the DHCP-agent ConfigBundle ships; disabled-shape block
    # still sent so the supervisor can retract config.
    syslog_settings: dict[str, Any] = Field(default_factory=dict)
    # Issue #157 — rendered authorized_keys + sshd drop-in + source-scope
    # CIDRs. Same shape the DHCP-agent ConfigBundle ships; disabled-shape
    # block still sent so the supervisor can retract managed SSH config.
    ssh_settings: dict[str, Any] = Field(default_factory=dict)
    # Issue #158 — rendered systemd-resolved drop-in. Same shape the
    # DHCP-agent ConfigBundle ships; disabled-shape block (automatic mode)
    # still sent so the supervisor can retract the managed drop-in (revert
    # to per-link DHCP / NetworkManager DNS).
    resolver_settings: dict[str, Any] = Field(default_factory=dict)
    # Issue #155 — rendered APT artifacts (sources.list / proxy / auth /
    # keyrings) + unattended-upgrades flag. Disabled-shape block still
    # sent so the supervisor can retract managed apt config.
    apt_settings: dict[str, Any] = Field(default_factory=dict)
    # #285 Phase 2a — server-side firewall render. ``{enabled, config_hash,
    # firewall_conf}``; empty config_hash when firewall_enabled is off (the
    # supervisor then keeps its in-pod fallback render). The supervisor
    # pipes a non-empty block to the firewall-pending trigger verbatim.
    firewall_settings: dict[str, Any] = Field(default_factory=dict)
    # #989 item 3 — removable (USB) backup disks this node should mount.
    # ``{enabled, config_hash, mounts: [{name, fs_uuid, fstype}]}``.
    #
    # The one host-config block rendered from the APPLIANCE ROW rather
    # than from platform_settings, because a USB disk is plugged into
    # exactly one node — a fleet-wide list would ask every other node to
    # mount a disk it cannot see. Empty-shape block still sent, because
    # an empty desired set is how an EJECT reaches the host.
    removable_settings: dict[str, Any] = Field(default_factory=dict)


def _s(v: object, limit: int = 255) -> str | None:
    """Normalise a neighbour string field — trim, truncate, empty → None."""
    if v is None:
        return None
    s = str(v).strip()
    return s[:limit] if s else None


async def _ingest_lldp_neighbours(
    db: DB, appliance_id: uuid.UUID, neighbours: list[dict[str, Any]]
) -> None:
    """Upsert the appliance's LLDP neighbours + absence-delete the rest (#347).

    ``neighbours`` is the authoritative current set from the supervisor's local
    lldpd. Keyed on ``(local_iface, remote_chassis_id, remote_port_id)`` — the
    same identity the model's unique constraint uses. Rows no longer present
    are deleted, mirroring how the switch-polled NetworkNeighbour table behaves.
    """
    from app.models.network import ApplianceLldpNeighbour

    desired: dict[tuple[str, str, str], dict[str, Any]] = {}
    for n in neighbours:
        if not isinstance(n, dict):
            continue
        li = _s(n.get("local_iface"), 64)
        ch = _s(n.get("remote_chassis_id"))
        pt = _s(n.get("remote_port_id"))
        if not (li and ch and pt):
            continue
        desired[(li, ch, pt)] = n

    existing = (
        (
            await db.execute(
                select(ApplianceLldpNeighbour).where(
                    ApplianceLldpNeighbour.appliance_id == appliance_id
                )
            )
        )
        .scalars()
        .all()
    )
    by_key = {(e.local_iface, e.remote_chassis_id, e.remote_port_id): e for e in existing}
    now = datetime.now(UTC)

    for key, n in desired.items():
        row = by_key.get(key)
        if row is None:
            db.add(
                ApplianceLldpNeighbour(
                    appliance_id=appliance_id,
                    local_iface=key[0],
                    remote_chassis_id=key[1],
                    remote_port_id=key[2],
                    remote_port_descr=_s(n.get("remote_port_descr")),
                    remote_sys_name=_s(n.get("remote_sys_name")),
                    remote_sys_descr=_s(n.get("remote_sys_descr"), 4096),
                    remote_mgmt_ip=_s(n.get("remote_mgmt_ip"), 64),
                    remote_caps=_s(n.get("remote_caps")),
                    last_seen=now,
                )
            )
        else:
            row.remote_port_descr = _s(n.get("remote_port_descr"))
            row.remote_sys_name = _s(n.get("remote_sys_name"))
            row.remote_sys_descr = _s(n.get("remote_sys_descr"), 4096)
            row.remote_mgmt_ip = _s(n.get("remote_mgmt_ip"), 64)
            row.remote_caps = _s(n.get("remote_caps"))
            row.last_seen = now

    for key, row in by_key.items():
        if key not in desired:
            await db.delete(row)


# #358 Phase 1b — server-side cap on how long the heartbeat long-poll holds
# the connection. Must stay under the supervisor's client timeout
# #786 — how long the control plane keeps re-sending a clear-upgrade
# command before giving up on it. Not a delivery window: the command is
# retired the moment the host acknowledges by reporting a non-``failed``
# state. This is only the backstop for a host that can NEVER comply — a
# trigger it does not own is unlinkable out of the sticky release-state
# directory — so the flag can't pin the heartbeat long-poll off forever.
_CLEAR_UPGRADE_GIVE_UP_SECONDS = 600.0


# (heartbeat_interval + 10 s) so the hold returns before the client gives up.
_HEARTBEAT_HOLD_CAP_S = 28.0


@router.post(
    "/supervisor/heartbeat",
    response_model=SupervisorHeartbeatResponse,
    summary="Supervisor heartbeat — appliance-host telemetry + desired state",
)
async def supervisor_heartbeat(
    body: SupervisorHeartbeatRequest,
    request: Request,
    db: DB,
) -> SupervisorHeartbeatResponse:
    """Persist supervisor-reported appliance-host state + return the
    operator's desired state for the supervisor to act on.

    Auth: session-token interim (per the SupervisorHeartbeatRequest
    docstring); after Wave C2/D this endpoint will be mTLS-gated and
    session_token becomes optional.

    On success:
    * Updates last_seen_at / last_seen_ip.
    * Overwrites the slot-telemetry columns when the supervisor
      reports non-None values (None leaves the column alone so a
      partial heartbeat doesn't blank fields the supervisor isn't
      currently sourcing).
    * Auto-clears ``desired_appliance_version`` once
      ``installed_appliance_version`` matches it AND the upgrade
      state is ``done`` or ``ready`` — the upgrade has landed and
      the operator's target is no longer load-bearing.
    * Auto-clears ``reboot_requested`` 15 s after the stamp on the
      assumption that the supervisor's heartbeat proves it survived
      the reboot. Same auto-heal shape as the legacy
      ``dns_server.reboot_requested`` / ``dhcp_server.reboot_requested``
      flags in Phase 8f-8.
    """
    if not await _module_enabled(db):
        await asyncio.sleep(_CONSUME_FAILURE_DELAY_S)
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")

    # #170 Wave D follow-up — cert auth takes precedence when the
    # supervisor presents X-Appliance-Cert + X-Appliance-Signature +
    # X-Appliance-Timestamp headers. The session-token path remains
    # as the fallback for pending_approval rows (which don't have a
    # cert yet).
    from app.services.appliance.cert_auth import (  # noqa: PLC0415
        CertAuthFailed,
        authenticate_cert,
    )

    cert_principal = None
    try:
        cert_principal = await authenticate_cert(request, db)
    except CertAuthFailed as exc:
        # #411 — a cert-auth FAILURE no longer hard-403s. The mTLS verifier
        # is a fallback that supersedes the session token only when the cert
        # actually validates; when it doesn't (no cert delivered yet, clock
        # skew, chain mismatch), fall through to the session-token path below
        # so an approved supervisor can still authenticate its heartbeat.
        # The session token is a real per-appliance secret (stored as a
        # hash), so this is NOT the credential-less UUID-only bypass #400 C1
        # closed — the no-cert branch still REQUIRES a valid token. The
        # cluster-admin k3s join token stays gated on ``cert_principal is not
        # None`` below, so a token-only heartbeat can never harvest it. The
        # warning is kept for the cert-auth-steady-state follow-up.
        logger.warning(
            "supervisor_heartbeat_cert_auth_failed",
            appliance_id=str(body.appliance_id),
            reason=exc.reason,
        )
        cert_principal = None

    if cert_principal is not None:
        # Cert subject CN must match the body's appliance_id (defence-
        # in-depth: a supervisor with cert for A can't post telemetry
        # claiming to be B).
        if cert_principal.appliance.id != body.appliance_id:
            await asyncio.sleep(_CONSUME_FAILURE_DELAY_S)
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Cert subject mismatch.",
            )
        row = cert_principal.appliance
    else:
        # No client cert presented — authenticate via the session token
        # (minted at register, stored only as a hash, held by the real
        # supervisor). This is the legitimate non-mTLS path: a not-yet-cert
        # supervisor and HTTP-only remote supervisors heartbeat with it.
        #
        # SECURITY (GHSA-mj4g-hw3m-62rm / #400 C1): this previously read
        # ``row.state == APPROVED or (session_token ...)``. Python ``or``
        # short-circuits, so for ANY approved row (the steady state of every
        # registered appliance) it returned valid with NO cert AND NO session
        # token — i.e. anyone who knew an appliance UUID (UUIDs leak via logs /
        # UI / audit) could drive the heartbeat. We now REQUIRE a valid
        # credential (the session token) on every no-cert heartbeat — the
        # UUID alone is no longer sufficient. The cluster-admin k3s join token
        # is additionally gated on mTLS below, so even a leaked session token
        # cannot harvest it.
        row = await db.get(Appliance, body.appliance_id)
        valid = (
            row is not None
            and body.session_token is not None
            and verify_session_token(body.session_token, row.session_token_hash)
        )
        if not valid:
            await asyncio.sleep(_CONSUME_FAILURE_DELAY_S)
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid appliance or session.")

    assert row is not None
    # Issue #170 Wave E follow-up — reject heartbeats from soft-deleted
    # appliances even when the cert chain still validates. The
    # supervisor's three-strike detector turns the 403 into local
    # ``revoked`` state + tears down service containers. Keeps the
    # cert-auth path simple (still trust the cert) while honouring
    # the operator's soft-delete intent at the API boundary.
    if row.state == APPLIANCE_STATE_REVOKED:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Appliance has been revoked. Re-authorize on the Fleet page to restore.",
        )

    row.last_seen_at = datetime.now(UTC)
    row.last_seen_ip = _client_ip(request)
    if body.capabilities is not None:
        row.capabilities = body.capabilities.model_dump()
        reported = body.capabilities.supervisor_version
        if reported and len(reported) <= 64:  # the column's width
            row.supervisor_version = reported

    # Slot telemetry — only overwrite when the supervisor sent a non-
    # None value. Lets the supervisor send partial heartbeats (e.g.
    # NTP sidecar unreadable this tick) without blanking columns it
    # doesn't currently know about.
    if body.deployment_kind is not None:
        row.deployment_kind = body.deployment_kind
    if body.appliance_variant is not None:
        # #272 Phase 1 — supervisor reads /etc/spatiumddi-host/role-
        # config:ROLE and reports here. Leave the existing value alone
        # if the supervisor didn't ship the field this tick (pre-#272).
        row.appliance_variant = body.appliance_variant
    if body.architecture is not None:
        # #1026 — same partial-heartbeat rule: a supervisor that didn't
        # ship the field leaves the known value in place rather than
        # blanking it back to UNKNOWN, which would silently disarm the
        # upgrade-architecture gate on every node during a rollout.
        row.architecture = body.architecture
    if body.installed_appliance_version is not None:
        row.installed_appliance_version = body.installed_appliance_version
    if body.current_slot is not None:
        row.current_slot = body.current_slot
    if body.durable_default is not None:
        row.durable_default = body.durable_default
    if body.slot_a_version is not None:
        row.slot_a_version = body.slot_a_version
    if body.slot_b_version is not None:
        row.slot_b_version = body.slot_b_version
    if body.is_trial_boot is not None:
        row.is_trial_boot = body.is_trial_boot
    # #786 — while a clear is outstanding, drop ONLY a report that still
    # carries the dismissed failure. The supervisor collected it before it
    # saw the command, so ingesting it would re-stamp the row we cleared
    # and the red card would never go away.
    #
    # Scoped to ``failed`` on purpose. Blanket-suppressing every
    # ``last_upgrade_*`` for the whole window also threw away the host's
    # post-reset ``ready`` — the very acknowledgement this waits for — and
    # any progress from an upgrade the operator retried straight after
    # clearing, which is the normal recovery gesture.
    suppress_stale_failure = row.clear_upgrade_requested and body.last_upgrade_state == "failed"
    if not suppress_stale_failure:
        if body.last_upgrade_state is not None:
            row.last_upgrade_state = body.last_upgrade_state
        if body.last_upgrade_state_at is not None:
            row.last_upgrade_state_at = body.last_upgrade_state_at
        # #386 Part C — empty string is a meaningful value here ("no
        # in-flight upgrade, clear any stale tail"), so persist on
        # ``is not None`` rather than truthiness.
        if body.last_upgrade_log_tail is not None:
            row.last_upgrade_log_tail = body.last_upgrade_log_tail or None
        if body.last_upgrade_progress is not None:
            row.last_upgrade_progress = body.last_upgrade_progress or None
    if body.snmpd_running is not None:
        row.snmpd_running = body.snmpd_running
    if body.lldpd_running is not None:
        row.lldpd_running = body.lldpd_running
    if body.ntp_sync_state is not None:
        row.ntp_sync_state = body.ntp_sync_state
    if body.syslog_forwarding is not None:
        row.syslog_forwarding = body.syslog_forwarding
    # Issue #157 — applied authorized_keys count (per-host). None = not
    # collected (leave the column alone); a value (incl. 0) persists.
    if body.ssh_key_count is not None:
        row.ssh_key_count = body.ssh_key_count
    # Issue #158 — applied systemd-resolved state (per-host). None = not
    # collected (leave the column alone); a value persists.
    if body.resolver_status is not None:
        row.resolver_status = body.resolver_status
    # Issue #155 — applied APT host-config state (per-host). None = not
    # collected (leave the column alone); a value persists.
    if body.apt_state is not None:
        row.apt_state = body.apt_state
    # Issue #347 — ingest the supervisor's local LLDP neighbours (upsert +
    # absence-delete). None = not collected (leave the set alone).
    if body.lldp_neighbours is not None:
        await _ingest_lldp_neighbours(db, row.id, body.lldp_neighbours)
    if body.port_conflicts is not None:
        # Overwrite verbatim — the supervisor's probe is the source of
        # truth. Empty dict explicitly clears prior conflicts; the
        # operator-visible banner stops showing on the next render.
        row.port_conflicts = dict(body.port_conflicts)
    if body.firewall_state is not None:
        # #593 — same contract as port_conflicts: overwrite verbatim, and an
        # empty dict is the supervisor telling us the node has healed. Only a
        # missing key (old supervisor) leaves the stored value alone.
        row.firewall_state = dict(body.firewall_state)
    if body.role_switch_state is not None:
        row.role_switch_state = body.role_switch_state
        # ``reason`` is paired with the state — clear it on idle /
        # ready (the prior failure is moot) so the Fleet UI doesn't
        # carry stale red text once the operator fixes the cause.
        if body.role_switch_state == "failed":
            row.role_switch_reason = body.role_switch_reason
        else:
            row.role_switch_reason = None
    if body.role_health is not None:
        # #170 Wave E — supervisor's per-service watchdog verdict.
        # Overwrite verbatim every tick: empty dict clears stale
        # entries when the operator removes a role, and the
        # supervisor's ``since`` timestamp is the canonical "first
        # observed in this status" anchor across heartbeats.
        row.role_health = dict(body.role_health)
    if body.host_config_health is not None:
        # #387 — supervisor's per-plane host-config apply health.
        # Overwrite verbatim every tick: empty dict clears stale stuck-
        # apply entries once a plane converges; a non-empty dict means
        # at least one plane's desired config isn't applied (the guard
        # is backing it off), which the Fleet UI surfaces as a banner.
        row.host_config_health = dict(body.host_config_health)
    if body.host_migration_health is not None:
        # #395 — supervisor's host-migration reconcile health. Overwrite
        # verbatim every tick: empty dict clears stale failing-patch
        # entries once the reconcile succeeds; a non-empty dict means at
        # least one numbered patch's grub/ESP change didn't apply (e.g.
        # grub-script-check rejected the rendered grub.cfg), surfaced as
        # a banner in the Fleet drilldown.
        row.host_migration_health = dict(body.host_migration_health)
    if body.cluster_health is not None:
        # Issue #183 Phase 4 — supervisor's local-k3s health summary.
        # Same overwrite-verbatim shape as role_health. Empty dict
        # is a meaningful signal (legacy compose; clear stale state).
        row.cluster_health = dict(body.cluster_health)
    if body.host_interfaces is not None:
        # #59 — host NICs for the appliance-vantage capture picker.
        # Overwrite verbatim (the supervisor sends the current host set
        # each tick); only update when reported so non-appliance /
        # pre-#59 supervisors don't wipe a previously-learned list.
        row.host_interfaces = list(body.host_interfaces)

    # Issue #183 Phase 5 — k3s version + kubeconfig persist. Both
    # follow "only update when not None" so legacy compose / pre-
    # Phase-5 supervisors don't blank the columns out.
    if body.k3s_version is not None:
        row.k3s_version = body.k3s_version
    if body.k3s_api_cert_expires_at is not None:
        # Issue #183 Phase 6 — k3s serving-cert expiry. Drives the
        # ``k3s_api_cert_expiring`` alert rule. Overwrite-verbatim so
        # k3s cert rotation (1-year default) propagates on the next
        # tick.
        row.k3s_api_cert_expires_at = body.k3s_api_cert_expires_at
    if body.kubeconfig is not None:
        from app.core.crypto import encrypt_str  # noqa: PLC0415

        # Rewrite ``server: https://127.0.0.1:6443`` → the appliance's
        # real node IP so the operator's downloaded kubeconfig actually
        # works against the appliance over the wire. Prefer the
        # k3s-registered ``node_ip`` over ``last_seen_ip`` — the latter
        # is the supervisor POD's source IP (10.42.x.x), which the
        # operator can't reach. Falls back to localhost when neither is
        # known (operator can edit themselves).
        rewritten = body.kubeconfig
        kubeconfig_host = body.node_ip or row.node_ip or row.last_seen_ip
        if kubeconfig_host:
            # k3s.yaml's server line is structured + greppable; the
            # supervisor doesn't run a port-7443 listener so 6443 is
            # always the right target port.
            new_server = f"server: https://{kubeconfig_host}:6443"
            rewritten = re.sub(
                r"server:\s*https://127\.0\.0\.1:6443",
                new_server,
                rewritten,
            )
            rewritten = re.sub(
                r"server:\s*https://0\.0\.0\.0:6443",
                new_server,
                rewritten,
            )
        row.kubeconfig_encrypted = encrypt_str(rewritten)

    # #272 Phase 7 — persist control-plane cluster telemetry.
    if body.k3s_join_token is not None:
        from app.core.crypto import encrypt_str  # noqa: PLC0415

        # Only the primary reports a token; store it Fernet-encrypted so
        # the promote endpoint can hand it to joiners.
        row.k3s_join_token_encrypted = encrypt_str(body.k3s_join_token)
    if body.cluster_join_state is not None:
        # #590 — stamp only on a real CHANGE, so the staleness clock the
        # escape hatch keys on measures how long we've been stuck in this
        # state, not how long ago the last heartbeat landed.
        if body.cluster_join_state != row.cluster_join_state:
            row.cluster_join_state_at = datetime.now(UTC)
        row.cluster_join_state = body.cluster_join_state
        row.cluster_join_reason = body.cluster_join_reason
    # The node's real routable InternalIP — used by the promote endpoint
    # for the join URL + the cross-node firewall peer set. Only update
    # when the supervisor sourced it (k3s appliances); None leaves the
    # column untouched.
    if body.node_ip is not None:
        row.node_ip = body.node_ip

    # #272 Phase 9b — etcd snapshot inventory (seed-reported). "Only
    # update when not None" so a member / pre-9b supervisor never blanks
    # the seed's list. Cap the stored list defensively (the runner already
    # sorts newest-first; a runaway snapshot dir shouldn't bloat the row).
    if body.etcd_snapshots is not None:
        row.etcd_snapshots = list(body.etcd_snapshots)[:200]

    # Issue #285 Phase 1 — fleet-firewall prerequisites. "Only update when
    # not None" so a legacy / pre-#285 supervisor never blanks them.
    if body.node_ips is not None:
        row.node_ips = list(body.node_ips)
    if body.pod_cidr is not None:
        row.pod_cidr = body.pod_cidr
    if body.service_cidr is not None:
        row.service_cidr = body.service_cidr
    if body.dataplane_backend is not None:
        row.dataplane_backend = body.dataplane_backend
    if body.base_conf_marker is not None:
        row.base_conf_marker = body.base_conf_marker
    if body.base_lanwide_k3s is not None:
        row.base_lanwide_k3s = body.base_lanwide_k3s

    # Issue #285 Phase 2b — mirror the host runner's firewall apply outcome
    # into firewall_apply_state. Upsert (on_conflict_do_update) rather than
    # get-or-create so overlapping/retried heartbeats from one appliance
    # can't 500, and a field absent this tick is never clobbered. Only
    # touch the row when the runner actually reported something.
    if (
        body.firewall_applied_hash is not None
        or body.firewall_applied_status is not None
        or body.firewall_base_marker is not None
    ):
        fw_sets: dict[str, Any] = {}
        if body.firewall_applied_hash is not None:
            fw_sets["applied_hash"] = body.firewall_applied_hash
            fw_sets["last_applied_at"] = datetime.now(UTC)
        if body.firewall_applied_status is not None:
            fw_sets["applied_status"] = body.firewall_applied_status
        if body.firewall_base_marker is not None:
            fw_sets["base_conf_marker"] = body.firewall_base_marker
        await db.execute(
            pg_insert(FirewallApplyState)
            .values(appliance_id=row.id, **fw_sets)
            .on_conflict_do_update(index_elements=["appliance_id"], set_=fw_sets)
        )

    # #272 Phase 9 — the seed reports k8s Nodes it evicted (dead-node
    # replacement). Clear the flag + settle those rows to ``left`` so
    # they stop appearing in the seed's evict list on the next tick.
    if body.evicted_node_names:
        evicted = (
            (
                await db.execute(
                    select(Appliance).where(
                        Appliance.hostname.in_(body.evicted_node_names),
                        Appliance.evict_requested.is_(True),
                    )
                )
            )
            .scalars()
            .all()
        )
        for ev in evicted:
            ev.evict_requested = False
            ev.cluster_join_state = CLUSTER_JOIN_STATE_LEFT
            logger.info("control_plane_node_evicted", hostname=ev.hostname, by=str(row.id))

    # Auto-clear the promote desired-state once the join landed: the
    # supervisor reports ``ready`` → the node IS a member now, so settle
    # cluster_role and drop the (sensitive) join coordinates.
    #
    # #590 — the settle deliberately does NOT require ``desired_cluster_role
    # == member``. The node reports ``ready`` on every heartbeat (it is that
    # node's local source of truth for control-plane membership, so it is
    # never retired), and the desired-state can legitimately be gone by the
    # time it lands: an operator clearing a "stuck" transition mid-join used
    # to strand the row at ``cluster_role = NULL`` forever, leaving a live
    # k3s control-plane member that cp-size scaling, MetalLB and quorum math
    # all undercount. Settling on ``cluster_role is None`` makes that
    # self-healing. ``evict_requested`` rows are excluded — a node we are
    # deliberately evicting must not re-add itself.
    if (
        row.cluster_join_state == CLUSTER_JOIN_STATE_READY
        and not row.evict_requested
        and (row.desired_cluster_role == DESIRED_CLUSTER_ROLE_MEMBER or row.cluster_role is None)
    ):
        row.cluster_role = CLUSTER_ROLE_MEMBER
        row.desired_cluster_role = None
        row.desired_k3s_server_url = None
        row.desired_k3s_join_token_encrypted = None
    # #590 — clear the promote desired-state on a reported ``failed`` too.
    # The host runner rolls the node back to its prior single-node seed and
    # renames its trigger out of the way, so leaving desired_cluster_role
    # set meant the supervisor re-fired the DESTRUCTIVE wipe-and-rejoin on
    # every heartbeat — the row read "joining" forever (observed: 50+ min
    # on a dead-node replace) instead of surfacing a clean failure. The
    # node is healthy and standalone; the operator re-promotes to retry.
    # cluster_join_state + cluster_join_reason are left as reported so the
    # Fleet UI shows WHY.
    elif (
        row.desired_cluster_role == DESIRED_CLUSTER_ROLE_MEMBER
        and row.cluster_join_state == CLUSTER_JOIN_STATE_FAILED
    ):
        # …but not on the FIRST transient failure. Two members promoted
        # together race each other into the seed's etcd (one of them is a
        # learner while the other is being added), and the loser's join
        # dies with "could not reach the seed" / a readiness timeout that a
        # second attempt a minute later survives. Clearing the desired-state
        # here turned that flake into an operator round-trip on every third
        # formation (appliance sizing campaign, 2026-09-02/03: 3-node
        # formations stuck at 2 until someone re-promoted by hand).
        #
        # So a transient failure keeps the desired-state and lets the
        # supervisor re-fire the join — it does so on its own once the row
        # still says "member" and its `.state` says failed, bounded by its
        # per-target attempt ceiling (appliance_state._CLUSTER_JOIN_MAX_
        # ATTEMPTS) — for up to _JOIN_AUTO_RETRY_WINDOW after the latest
        # failure. A PERMANENT failure (the runner's classifier names three:
        # a stale etcd member under this hostname, a bootstrap-token mismatch
        # on disk, an etcd member the cluster permanently removed) clears
        # immediately as before: no retry can fix those, the operator has to
        # evict, re-pair or leave first.
        if _join_failure_is_permanent(row.cluster_join_reason) or _join_retry_window_elapsed(
            row.cluster_join_state_at
        ):
            row.desired_cluster_role = None
            row.desired_k3s_server_url = None
            row.desired_k3s_join_token_encrypted = None
            logger.warning(
                "control_plane_join_failed",
                appliance_id=str(row.id),
                hostname=row.hostname,
                reason=row.cluster_join_reason,
                detail="cleared desired-state; re-promote to retry",
            )
        else:
            logger.warning(
                "control_plane_join_retrying",
                appliance_id=str(row.id),
                hostname=row.hostname,
                reason=row.cluster_join_reason,
                detail=(
                    "transient join failure — desired-state kept so the supervisor "
                    f"re-fires the join (window {_JOIN_AUTO_RETRY_WINDOW})"
                ),
            )
    # Auto-clear the demote desired-state once the leave landed: the
    # supervisor reports ``left`` → the node is back to a plain
    # application appliance.
    if (
        row.desired_cluster_role == DESIRED_CLUSTER_ROLE_NONE
        and row.cluster_join_state == CLUSTER_JOIN_STATE_LEFT
    ):
        row.cluster_role = None
        row.desired_cluster_role = None
    # #590 — and clear it on a failed leave, for the same reason a failed
    # join clears above: the leave runner also renames its trigger away, so
    # a desired-state left standing re-fires the destructive leave every
    # heartbeat. cluster_role is left as-is (the node did NOT leave).
    elif (
        row.desired_cluster_role == DESIRED_CLUSTER_ROLE_NONE
        and row.cluster_join_state == CLUSTER_JOIN_STATE_FAILED
    ):
        row.desired_cluster_role = None
        logger.warning(
            "control_plane_leave_failed",
            appliance_id=str(row.id),
            hostname=row.hostname,
            reason=row.cluster_join_reason,
            detail="cleared desired-state; re-demote to retry",
        )

    # #272 Phase 9b — guided etcd restore. Persist the runner-reported
    # progress, and auto-clear the desired snapshot once it lands ``done``
    # (so a converged restore stops re-firing the trigger). A ``failed``
    # restore keeps ``desired_restore_snapshot`` set so the operator sees
    # the failure on the row and can retry / pick another snapshot.
    if body.restore_state is not None:
        row.restore_state = body.restore_state
        row.restore_reason = body.restore_reason
    if row.desired_restore_snapshot is not None and row.restore_state == "done":
        logger.info(
            "control_plane_restore_done",
            appliance_id=str(row.id),
            snapshot=row.desired_restore_snapshot,
        )
        row.desired_restore_snapshot = None

    # Auto-clear desired_appliance_version once installed matches +
    # the upgrade landed cleanly. Same shape as #138 Phase 8f-4's
    # legacy dns_server / dhcp_server auto-clear.
    if (
        row.desired_appliance_version is not None
        and row.installed_appliance_version == row.desired_appliance_version
        and row.last_upgrade_state in (None, "done", "ready")
    ):
        row.desired_appliance_version = None
        row.desired_slot_image_url = None
        row.desired_slot_image_sha256 = None
        row.desired_slot_image_tls_insecure = False

    # Auto-clear desired_next_boot_slot once the supervisor reports
    # the requested slot as ``current_slot`` — the operator's intent
    # was "boot into this slot next", and we got there. ``durable_
    # default`` is irrelevant here (next-boot is one-shot by design).
    if row.desired_next_boot_slot is not None and row.current_slot == row.desired_next_boot_slot:
        row.desired_next_boot_slot = None

    # Auto-clear desired_default_slot once the supervisor reports the
    # requested slot as ``durable_default`` — grub-set-default landed
    # and survives subsequent reboots.
    if row.desired_default_slot is not None and row.durable_default == row.desired_default_slot:
        row.desired_default_slot = None

    # Auto-clear reboot_requested 15 s after the stamp — by that
    # point the heartbeat is itself proof the reboot landed (or that
    # the reboot trigger has been written + the host runner is about
    # to fire). Reduces the chance of a stale flag stalling the
    # operator's next reboot request.
    if (
        row.reboot_requested
        and row.reboot_requested_at is not None
        and (datetime.now(UTC) - row.reboot_requested_at).total_seconds() >= 15
    ):
        row.reboot_requested = False
        row.reboot_requested_at = None

    # Retire clear_upgrade_requested on ACKNOWLEDGEMENT, not on a clock
    # (#786). The host's compliance is already observable: the clear's
    # whole job is to turn a ``failed`` sidecar into ``ready``, so the
    # first heartbeat reporting anything other than ``failed`` IS the ack.
    # Until then the command keeps riding every response, so a supervisor
    # that was offline, restarting, or simply slow still receives it.
    #
    # This replaces a 15 s stopwatch that could expire before the command
    # was ever delivered: a wedged appliance keeps ``desired_appliance_
    # version`` set, which suppresses the long-poll, so its heartbeats
    # arrive a full interval apart and landed past the window about half
    # the time. No clock comparison between host and control plane is
    # involved either, so appliance clock skew cannot strand the flag.
    #
    # ``deliver_clear_upgrade`` is still captured BEFORE the retire,
    # because the response is built from the row ~300 lines below and the
    # acknowledging heartbeat must carry the command one last time (it is
    # idempotent host-side, and the alternative is dropping it).
    deliver_clear_upgrade = row.clear_upgrade_requested
    if row.clear_upgrade_requested:
        acknowledged = body.last_upgrade_state is not None and body.last_upgrade_state != "failed"
        # Backstop so a host that can never comply — e.g. a trigger it does
        # not own, which it can never unlink out of the sticky release-state
        # directory — cannot pin the flag on forever and permanently
        # suppress this appliance's heartbeat long-poll.
        stalled = (
            row.clear_upgrade_requested_at is not None
            and (datetime.now(UTC) - row.clear_upgrade_requested_at).total_seconds()
            >= _CLEAR_UPGRADE_GIVE_UP_SECONDS
        )
        if acknowledged or stalled:
            if stalled and not acknowledged:
                logger.warning(
                    "appliance_clear_upgrade_unacknowledged",
                    appliance_id=str(row.id),
                    hostname=row.hostname,
                    last_upgrade_state=body.last_upgrade_state,
                )
            row.clear_upgrade_requested = False
            row.clear_upgrade_requested_at = None

    await db.commit()

    # #358 Phase 1b — heartbeat long-poll. When the supervisor opts in
    # (wait_seconds > 0) and there's no concrete pending host command,
    # hold the response open until a per-appliance wake fires (upgrade /
    # reboot / role / firewall / host-config) or a bounded timeout — so
    # operator commands start in ~0 s instead of waiting a full heartbeat.
    # Fallback-safe by construction: wait_seconds == 0 (old supervisor)
    # returns immediately as before; a concrete pending command skips the
    # hold so it's never delayed; and a Redis outage degrades wake.wait to
    # a bounded sleep (no fast-return storm), with the supervisor's own
    # interval still delivering everything (non-negotiable #5). The
    # telemetry commit above already ran, so no DB connection is held
    # across the wait.
    #
    # ``long_poll`` reports whether we ACTUALLY held this heartbeat (entered
    # the wake wait), NOT merely that the supervisor opted in. A pending
    # command returns immediately with long_poll=False so the supervisor
    # keeps its normal interval cadence instead of re-arming every floor for
    # the whole duration an upgrade/reboot intent persists (the command was
    # already delivered instantly by the publish_wake on its stamp, and is
    # re-delivered idempotently on each normal heartbeat).
    long_poll = False
    if body.wait_seconds > 0:
        has_pending_command = (
            row.desired_appliance_version is not None
            or row.reboot_requested
            # ``deliver_clear_upgrade``, not the row: the auto-expiry above
            # may have just cleared the flag while the response below still
            # carries the command. Reading the row here would make this look
            # idle — and a clear also nulls ``desired_appliance_version``, so
            # nothing else keeps it pending — so we would hold the very
            # response that delivers the clear for up to the hold cap.
            or deliver_clear_upgrade
            or row.desired_next_boot_slot is not None
            or row.desired_default_slot is not None
        )
        if not has_pending_command:
            long_poll = True
            hold_for = min(float(body.wait_seconds), _HEARTBEAT_HOLD_CAP_S)
            deadline = asyncio.get_running_loop().time() + hold_for
            async with wake_subscription([*appliance_wake_channels(row), HOSTCONFIG_ALL]) as wake:
                while True:
                    remaining = deadline - asyncio.get_running_loop().time()
                    if remaining <= 0:
                        break
                    if await wake.wait(min(WAKE_TICK_SECONDS, remaining)) == WakeResult.WAKE:
                        break
            # Pick up anything that committed during the hold (role /
            # firewall / desired-state edits land on other requests) before
            # building the desired-state response below. Guarded: if the row
            # was hard-deleted during the hold, refresh raises — serve one
            # last response from the in-memory row (the next heartbeat
            # 403/404s cleanly) instead of 500ing.
            try:
                await db.refresh(row)
            except Exception:  # noqa: BLE001
                logger.info(
                    "supervisor_heartbeat_refresh_after_hold_failed",
                    appliance_id=str(row.id),
                )

    # Resolve assigned role config so the supervisor can bring up
    # service containers. DNS / DHCP group lookups are best-effort —
    # if the operator deleted a group out from under an approved
    # appliance, the supervisor sees the role with a null group_id
    # and skips bringing the service container up (the empty role
    # set is itself the idle marker).
    role_assignment = await _build_role_assignment(db, row)

    # #170 Wave D follow-up — include cert + CA chain so the
    # supervisor picks them up on the heartbeat right after approval
    # + switches to cert auth on subsequent calls. Always emit them
    # for approved rows (idempotent on the supervisor side — re-saving
    # the same bytes is a no-op); pending_approval rows have NULL
    # cert_pem so the field stays None.
    ca_chain_pem: str | None = None
    if row.cert_pem is not None:
        ca = await ensure_ca(db)
        ca_chain_pem = ca.cert_pem

    # #272 Phase 7 — decrypt the join token for the joiner (mTLS channel).
    # SECURITY (GHSA-mj4g-hw3m-62rm / #400 C1, defence-in-depth): the k3s
    # join token is cluster-admin-equivalent, so only ever hand it back over a
    # cert-authenticated (mTLS) request — never the credential-less /
    # session-token path. The auth gate above already closes the no-cert path
    # for approved rows; this is the belt-and-braces so the secret can't leak
    # even if that gate is later loosened.
    desired_join_token: str | None = None
    if (
        cert_principal is not None
        and row.desired_cluster_role == DESIRED_CLUSTER_ROLE_MEMBER
        and row.desired_k3s_join_token_encrypted is not None
    ):
        from app.core.crypto import decrypt_str  # noqa: PLC0415

        try:
            desired_join_token = decrypt_str(row.desired_k3s_join_token_encrypted)
        except Exception:  # noqa: BLE001
            logger.warning(
                "supervisor_heartbeat_join_token_decrypt_failed",
                appliance_id=str(row.id),
            )

    # #272 Phase 7b — the cross-node firewall peer set this node must
    # open its k3s server ports to (empty unless row is a CP node).
    cluster_peer_cidrs = await _cluster_peer_cidrs(db, row)

    # #285 Phase 1 — derived firewall inputs for the in-pod renderer.
    # A node "runs the apiserver" (so 6443 must accept from the pod /
    # service CIDR) when it's a control-plane variant OR a settled /
    # in-flight / leaving CP member. pod/service CIDR are sent only for
    # those nodes so a plain worker doesn't pointlessly open 6443.
    runs_apiserver = _runs_apiserver(row)
    firewall_pod_cidrs = _split_cidr_csv(row.pod_cidr) if runs_apiserver else []
    firewall_service_cidrs = _split_cidr_csv(row.service_cidr) if runs_apiserver else []

    # #277 — committed control-plane size (settled primary + members,
    # floored at 1). The seed supervisor scales CNPG instances +
    # workload replicas to this.
    control_plane_size = await _committed_cp_count(db)

    # #272 Phase 7c — cluster-wide MetalLB / VIP desired state. Read
    # from the platform_settings singleton; the seed supervisor applies
    # it to the HelmCharts. Best-effort — a missing settings row (never
    # the case in practice; seeded at startup) renders the disabled
    # default so the heartbeat still succeeds.
    cfg_row = (
        await db.execute(select(PlatformSettings).where(PlatformSettings.id == 1))
    ).scalar_one_or_none()
    metallb_enabled = bool(cfg_row.metallb_enabled) if cfg_row else False
    metallb_pool = list(cfg_row.metallb_pool_addresses or []) if cfg_row else []
    metallb_vip = (cfg_row.control_plane_vip or "") if cfg_row else ""
    # #272 Phase 10 — data-plane resolver VIPs (only the seed acts).
    dns_vip = (cfg_row.dns_vip or "") if cfg_row else ""
    dhcp_relay_vip = (cfg_row.dhcp_relay_vip or "") if cfg_row else ""
    # #566 decision D1 — BGP mode (only the seed acts).
    metallb_bgp_enabled = bool(cfg_row.metallb_bgp_enabled) if cfg_row else False
    metallb_bgp_peers = list(cfg_row.metallb_bgp_peers or []) if cfg_row else []
    metallb_bgp_advertisements = list(cfg_row.metallb_bgp_advertisements or []) if cfg_row else []
    # Issue #165 — operator-set timezone. Empty string = no override.
    desired_timezone = (cfg_row.timezone or "") if cfg_row else ""
    # #393 — appliance console mode (grubenv-driven, applies next reboot).
    desired_console_mode = (cfg_row.console_mode or "dashboard") if cfg_row else "dashboard"
    # Issue #346 — host-config blocks for snmp / chrony / lldp. Built from the
    # same ``*_bundle`` helpers the DHCP-agent ConfigBundle uses; the
    # disabled-shape fallback keeps a stable key set when no settings row
    # exists yet so the supervisor's hash compare never KeyErrors.
    snmp_block = (
        snmp_bundle(cfg_row)
        if cfg_row is not None
        else {"enabled": False, "config_hash": "", "snmpd_conf": ""}
    )
    ntp_block = (
        ntp_bundle(cfg_row)
        if cfg_row is not None
        else {
            "enabled": False,
            "allow_clients": False,
            "config_hash": "",
            "chrony_conf": "",
        }
    )
    lldp_block = (
        lldp_bundle(cfg_row)
        if cfg_row is not None
        else {"enabled": False, "config_hash": "", "lldpd_conf": "", "daemon_args": ""}
    )
    # Issue #156 — rsyslog forward config. Disabled-shape fallback keeps
    # a stable key set when no settings row exists yet so the supervisor's
    # hash compare never KeyErrors.
    syslog_block = (
        syslog_bundle(cfg_row)
        if cfg_row is not None
        else {"enabled": False, "config_hash": "", "rsyslog_conf": "", "ca_certs": {}}
    )
    # Issue #157 — SSH authorized_keys + sshd drop-in. Disabled-shape
    # fallback keeps a stable key set when no settings row exists yet so
    # the supervisor's hash compare never KeyErrors.
    ssh_block = (
        ssh_bundle(cfg_row)
        if cfg_row is not None
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
    # Issue #158 — systemd-resolved drop-in. Disabled-shape fallback
    # (automatic mode) keeps a stable key set when no settings row exists
    # yet so the supervisor's hash compare never KeyErrors.
    resolver_block = (
        resolver_bundle(cfg_row)
        if cfg_row is not None
        else {"enabled": False, "config_hash": "", "resolved_conf": ""}
    )
    # Issue #155 — APT host-config. Disabled-shape fallback keeps a stable
    # key set when no settings row exists yet so the supervisor's hash
    # compare never KeyErrors.
    apt_block = (
        apt_bundle(cfg_row)
        if cfg_row is not None
        else {
            "enabled": False,
            "config_hash": "",
            "sources_list": "",
            "proxy_conf": "",
            "auth_conf": "",
            "keyrings": {},
            "unattended_upgrades_enabled": True,
        }
    )
    # #285 Phase 2a — server-side firewall render. Same inputs the in-pod
    # renderer consumes (byte-identical body). Gated on the firewall_enabled
    # master switch (default off → disabled-shape block → supervisor keeps
    # its in-pod fallback). role_assignment is the SupervisorRoleAssignment
    # built above; pass its dict form so compile_firewall_body reads roles /
    # firewall_extra / kubeapi_expose_cidrs the same way the supervisor does.
    firewall_block = await firewall_bundle(
        db,
        role_assignment=role_assignment.model_dump(),
        cluster_peer_cidrs=cluster_peer_cidrs,
        pod_cidrs=firewall_pod_cidrs,
        service_cidrs=firewall_service_cidrs,
        cp_member_count=control_plane_size,
        vip_configured=bool(metallb_vip),
        firewall_enabled=bool(cfg_row.firewall_enabled) if cfg_row else False,
        appliance_id=row.id,
        web_ui_allowed_cidrs=(list(cfg_row.web_ui_allowed_cidrs or []) if cfg_row else []),
        # #1009 — the EFFECTIVE ssh scope, not the typed list: empty unless
        # the operator turned lockdown on. Non-empty is what retires the
        # baked port-22 floor, so it must be resolved in exactly one place
        # (services.appliance.ssh.effective_ssh_scope) or the firewall and
        # the ssh plane could disagree about whether SSH is restricted.
        ssh_scope_cidrs=(effective_ssh_scope(cfg_row) if cfg_row else []),
        firewall_logging_enabled=(bool(cfg_row.firewall_logging_enabled) if cfg_row else False),
    )
    # Persist the rendered hash so 2d's apply-stalled alarm + the Fleet drift
    # chip can compare it against the runner's reported applied_hash. Only
    # when authoritative render is on; a dedicated upsert+commit (the main
    # handler commit already ran) — skipped entirely in the default-off path.
    if firewall_block["enabled"]:
        rendered_at = datetime.now(UTC)
        await db.execute(
            pg_insert(FirewallApplyState)
            .values(
                appliance_id=row.id,
                rendered_hash=firewall_block["config_hash"],
                last_rendered_at=rendered_at,
            )
            .on_conflict_do_update(
                index_elements=["appliance_id"],
                set_={
                    "rendered_hash": firewall_block["config_hash"],
                    "last_rendered_at": rendered_at,
                },
            )
        )
        await db.commit()

    # #272 Phase 9 — dead k8s Nodes the seed should evict. Returned to
    # every CP supervisor but only the control-plane-variant seed acts.
    evict_names = [
        h
        for (h,) in (
            await db.execute(
                select(Appliance.hostname).where(
                    Appliance.evict_requested.is_(True),
                    Appliance.hostname.isnot(None),
                )
            )
        ).all()
    ]

    return SupervisorHeartbeatResponse(
        appliance_id=row.id,
        state=row.state,  # type: ignore[arg-type]
        desired_appliance_version=row.desired_appliance_version,
        desired_slot_image_url=row.desired_slot_image_url,
        desired_slot_image_sha256=row.desired_slot_image_sha256,
        desired_slot_image_tls_insecure=row.desired_slot_image_tls_insecure,
        desired_next_boot_slot=row.desired_next_boot_slot,  # type: ignore[arg-type]
        desired_default_slot=row.desired_default_slot,  # type: ignore[arg-type]
        reboot_requested=row.reboot_requested,
        clear_upgrade_requested=deliver_clear_upgrade,
        cert_pem=row.cert_pem,
        ca_chain_pem=ca_chain_pem,
        cert_expires_at=row.cert_expires_at,
        role_assignment=role_assignment,
        desired_cluster_role=row.desired_cluster_role,  # type: ignore[arg-type]
        desired_k3s_server_url=row.desired_k3s_server_url,
        desired_k3s_join_token=desired_join_token,
        cluster_peer_cidrs=cluster_peer_cidrs,
        firewall_pod_cidrs=firewall_pod_cidrs,
        firewall_service_cidrs=firewall_service_cidrs,
        web_ui_allowed_cidrs=(list(cfg_row.web_ui_allowed_cidrs or []) if cfg_row else []),
        # #1009 — the EFFECTIVE ssh scope, not the typed list: empty unless
        # the operator turned lockdown on. Non-empty is what retires the
        # baked port-22 floor, so it must be resolved in exactly one place
        # (services.appliance.ssh.effective_ssh_scope) or the firewall and
        # the ssh plane could disagree about whether SSH is restricted.
        ssh_scope_cidrs=(effective_ssh_scope(cfg_row) if cfg_row else []),
        control_plane_size=control_plane_size,
        desired_metallb_enabled=metallb_enabled,
        desired_metallb_pool_addresses=metallb_pool,
        desired_control_plane_vip=metallb_vip,
        desired_dns_vip=dns_vip,
        desired_dhcp_relay_vip=dhcp_relay_vip,
        desired_metallb_bgp_enabled=metallb_bgp_enabled,
        desired_metallb_bgp_peers=metallb_bgp_peers,
        desired_metallb_bgp_advertisements=metallb_bgp_advertisements,
        evict_node_names=evict_names,
        desired_timezone=desired_timezone,
        desired_console_mode=desired_console_mode,
        snmp_settings=snmp_block,
        ntp_settings=ntp_block,
        lldp_settings=lldp_block,
        syslog_settings=syslog_block,
        ssh_settings=ssh_block,
        resolver_settings=resolver_block,
        apt_settings=apt_block,
        firewall_settings=firewall_block,
        removable_settings=removable_bundle_safe(row.desired_removable_mounts),
        long_poll=long_poll,
    )


def _runs_apiserver(row: Appliance) -> bool:
    """#285 — a node "runs the apiserver" (so 6443 + the pod/service CIDR are
    in firewall scope) when it's a control-plane variant OR a settled /
    in-flight / leaving CP member. Shared by the heartbeat render and the
    firewall effective/preview endpoints so both gate pod/service identically.
    """
    return (
        row.appliance_variant in ("control-plane", "full-stack", "frontend-core")
        or row.cluster_role in (CLUSTER_ROLE_PRIMARY, CLUSTER_ROLE_MEMBER)
        or row.desired_cluster_role == DESIRED_CLUSTER_ROLE_MEMBER
        or (
            row.desired_cluster_role == DESIRED_CLUSTER_ROLE_NONE
            and row.cluster_join_state != CLUSTER_JOIN_STATE_LEFT
        )
    )


async def firewall_render_inputs(db: DB, row: Appliance) -> dict[str, Any]:
    """The per-node inputs the #285 fleet-firewall merge consumes — reproduced
    from the heartbeat's own derivation (same ``_build_role_assignment`` /
    ``_cluster_peer_cidrs`` / ``_committed_cp_count`` / ``_runs_apiserver``
    helpers) so the effective/preview endpoints render a body BYTE-IDENTICAL
    to what the heartbeat ships. The heartbeat handler keeps its inline copies
    (they also feed response telemetry); this is the read-path twin.
    """
    role_assignment = await _build_role_assignment(db, row)
    runs_apiserver = _runs_apiserver(row)
    cfg_row = (
        await db.execute(select(PlatformSettings).where(PlatformSettings.id == 1))
    ).scalar_one_or_none()
    return {
        "role_assignment": role_assignment.model_dump(),
        "cluster_peer_cidrs": await _cluster_peer_cidrs(db, row),
        "pod_cidrs": _split_cidr_csv(row.pod_cidr) if runs_apiserver else [],
        "service_cidrs": _split_cidr_csv(row.service_cidr) if runs_apiserver else [],
        "cp_member_count": await _committed_cp_count(db),
        "vip_configured": bool((cfg_row.control_plane_vip or "") if cfg_row else ""),
        "firewall_enabled": bool(cfg_row.firewall_enabled) if cfg_row else False,
        "web_ui_allowed_cidrs": (list(cfg_row.web_ui_allowed_cidrs or []) if cfg_row else []),
        # #1009 — mirrors web_ui_allowed_cidrs: the supervisor's in-pod
        # fallback renderer needs the same input the server-authoritative
        # render used, or the two would disagree about the floor.
        "ssh_scope_cidrs": (effective_ssh_scope(cfg_row) if cfg_row else []),
    }


async def _build_role_assignment(db: DB, row: Appliance) -> SupervisorRoleAssignment:
    """Resolve the assigned roles + group identities for a supervisor
    heartbeat response. Best-effort — a missing group falls through
    as a null group_id; the supervisor treats that as "skip this
    role" (idle on the affected service)."""
    from app.config import settings as app_settings
    from app.models.dhcp import DHCPServerGroup
    from app.models.dns import DNSServerGroup, DNSServerOptions

    assigned_roles = list(row.assigned_roles or [])
    dns_role_assigned = any(r in assigned_roles for r in _DNS_ROLES)
    dhcp_role_assigned = "dhcp" in assigned_roles
    lg_role_assigned = "looking-glass" in assigned_roles

    dns_engine: str | None = None
    if "dns-bind9" in assigned_roles:
        dns_engine = "bind9"
    elif "dns-powerdns" in assigned_roles:
        dns_engine = "powerdns"
    elif "dns-technitium" in assigned_roles:
        dns_engine = "technitium"

    dns_group_name: str | None = None
    # #50 — DoT / DoH listen on operator-chosen ports, so the firewall can't
    # use a static per-role list the way Do53 does. Derive the live ports
    # from the assigned group's options and ship them with the assignment;
    # the supervisor's renderer opens exactly these and nothing more, so
    # turning a listener off closes its port on the next apply.
    dns_encrypted_tcp_ports: list[int] = []
    dns_encrypted_udp_ports: list[int] = []
    if row.assigned_dns_group_id is not None:
        dns_group = await db.get(DNSServerGroup, row.assigned_dns_group_id)
        if dns_group is not None:
            dns_group_name = dns_group.name
        if dns_role_assigned:
            dns_opts = (
                await db.execute(
                    select(DNSServerOptions).where(
                        DNSServerOptions.group_id == row.assigned_dns_group_id
                    )
                )
            ).scalar_one_or_none()
            if dns_opts is not None:
                # Gate on tls_certificate_id too: without a cert the agent
                # renderers skip the listener entirely, so opening the port
                # would advertise a service that isn't there.
                if dns_opts.tls_certificate_id is not None:
                    if dns_opts.dot_enabled:
                        dns_encrypted_tcp_ports.append(int(dns_opts.dot_port))
                    if dns_opts.doh_enabled:
                        dns_encrypted_tcp_ports.append(int(dns_opts.doh_port))
                    # DoQ rides UDP (#741). It may share a port number with
                    # DoT — 853 is the RFC default for both — which is why
                    # the two lists are separate rather than one merged set.
                    if getattr(dns_opts, "doq_enabled", False):
                        dns_encrypted_udp_ports.append(int(dns_opts.doq_port))
            dns_encrypted_tcp_ports = sorted(set(dns_encrypted_tcp_ports))
            dns_encrypted_udp_ports = sorted(set(dns_encrypted_udp_ports))

    dhcp_group_name: str | None = None
    dhcp_network_mode: str | None = None
    if row.assigned_dhcp_group_id is not None:
        dhcp_group = await db.get(DHCPServerGroup, row.assigned_dhcp_group_id)
        if dhcp_group is not None:
            dhcp_group_name = dhcp_group.name
            dhcp_network_mode = dhcp_group.network_mode
    # #1167 — the Kea HA listener, when this node's DHCP group is an HA pair.
    dhcp_ha_port, dhcp_ha_peer_cidrs = await dhcp_ha_firewall_inputs(db, row)

    # #170 Wave D follow-up — only ship the bootstrap PSK to
    # supervisors whose appliance has the matching role assigned.
    # An observer-only appliance gets neither; a DNS-only appliance
    # gets only the DNS key. Keeps blast radius bounded if a single
    # supervisor cert leaks.
    dns_agent_key: str | None = None
    if dns_role_assigned:
        dns_agent_key = app_settings.dns_agent_key or None
    dhcp_agent_key: str | None = None
    if dhcp_role_assigned:
        dhcp_agent_key = app_settings.dhcp_agent_key or None
    lg_agent_key: str | None = None
    if lg_role_assigned:
        lg_agent_key = app_settings.lg_agent_key or None

    return SupervisorRoleAssignment(
        roles=assigned_roles,
        dns_group_id=row.assigned_dns_group_id,
        dns_group_name=dns_group_name,
        dns_engine=dns_engine,
        dns_agent_key=dns_agent_key,
        dhcp_group_id=row.assigned_dhcp_group_id,
        dhcp_group_name=dhcp_group_name,
        dhcp_network_mode=dhcp_network_mode,
        dhcp_agent_key=dhcp_agent_key,
        lg_agent_key=lg_agent_key,
        firewall_extra=row.firewall_extra,
        kubeapi_expose_cidrs=list(row.kubeapi_expose_cidrs or []),
        dns_encrypted_tcp_ports=dns_encrypted_tcp_ports,
        dns_encrypted_udp_ports=dns_encrypted_udp_ports,
        dhcp_ha_port=dhcp_ha_port,
        dhcp_ha_peer_cidrs=dhcp_ha_peer_cidrs,
    )


# ── Admin: approve / reject / delete / re-key ─────────────────────


class ApplianceRow(BaseModel):
    """Operator-facing summary of an appliance row. Cert / pubkey
    bytes are not exposed — only their derived metadata."""

    id: uuid.UUID
    hostname: str
    state: Literal["pending_approval", "approved", "rejected", "revoked"]
    public_key_fingerprint: str
    supervisor_version: str | None
    capabilities: dict
    paired_at: datetime
    paired_from_ip: str | None
    last_seen_at: datetime | None
    last_seen_ip: str | None
    approved_at: datetime | None
    approved_by_user_id: uuid.UUID | None
    rejected_at: datetime | None
    cert_serial: str | None
    cert_issued_at: datetime | None
    cert_expires_at: datetime | None
    # #170 Wave C1 — slot telemetry surfaced from the appliance row.
    deployment_kind: str | None
    # #272 Phase 1 — installer-role variant. NULL on pre-#272
    # supervisors that haven't slot-upgraded yet.
    appliance_variant: str | None
    # #1026 — the node's CPU architecture, so the Fleet drilldown can
    # show it and the upgrade picker can refuse an image built for the
    # other one before the operator schedules it.
    architecture: str | None
    installed_appliance_version: str | None
    current_slot: str | None
    durable_default: str | None
    slot_a_version: str | None
    slot_b_version: str | None
    is_trial_boot: bool
    last_upgrade_state: str | None
    last_upgrade_state_at: datetime | None
    # Issue #386 Part C — tail of the host slot-upgrade.log + structured
    # per-phase progress while an apply is in-flight / failed, so the
    # Fleet drilldown shows a real status stepper + the failure reason
    # instead of just the coarse state chip.
    last_upgrade_log_tail: str | None
    last_upgrade_progress: dict[str, Any] | None
    snmpd_running: bool | None
    lldpd_running: bool | None
    ntp_sync_state: str | None
    # Issue #156 — best-effort rsyslog-forwarding status surfaced from
    # the appliance row (forwarding / unreachable / disabled).
    syslog_forwarding: str | None
    # Issue #157 — count of authorized_keys lines the host runner applied
    # (per-host). None on non-appliance / pre-#157 / never-reported rows.
    ssh_key_count: int | None
    # Issue #158 — systemd-resolved state the host runner reported
    # (override / automatic / failed). None on non-appliance / pre-#158 /
    # never-reported rows.
    resolver_status: str | None
    # Issue #155 — APT host-config state (synced / proxy-failed /
    # mirror-unreachable / signature-mismatch / no-sources / unmanaged /
    # unknown). None on non-appliance / pre-#155 / never-reported rows.
    apt_state: str | None
    desired_appliance_version: str | None
    desired_slot_image_url: str | None
    # #386 Part A — integrity + transport hints surfaced for the UI /
    # debugging (not secret). sha256 the host verifies the bytes against;
    # tls_insecure is true only for the appliance's own self-served URL.
    desired_slot_image_sha256: str | None
    desired_slot_image_tls_insecure: bool
    desired_next_boot_slot: str | None
    desired_default_slot: str | None
    reboot_requested: bool
    reboot_requested_at: datetime | None
    # #170 Wave C2 — role assignment + free-form tags.
    assigned_roles: list[str]
    assigned_dns_group_id: uuid.UUID | None
    assigned_dhcp_group_id: uuid.UUID | None
    tags: dict[str, str]
    # #170 Wave C3 — operator-pasted nft fragment.
    firewall_extra: str | None
    # #170 Phase E2 — supervisor-reported host-side port conflicts.
    port_conflicts: dict[str, str]
    # #593 — refused self-partitioning firewall drop-in ({} when healthy).
    firewall_state: dict[str, str]
    # #170 Wave D follow-up — outcome of the supervisor's last
    # compose-lifecycle apply.
    role_switch_state: str | None
    role_switch_reason: str | None
    # #170 Wave E — service-container watchdog. Per-service health
    # the supervisor reports every 5 min via heartbeat. Keys are
    # compose service names (``dns-bind9`` / ``dns-powerdns`` /
    # ``dns-technitium`` / ``dhcp-kea``); values carry ``{role, status, since,
    # container_id}``.
    role_health: dict[str, dict[str, Any]]
    # #387 — per-plane host-config apply health (snmp / ntp / lldp /
    # syslog / ssh / resolver / firewall / timezone). ``{<plane>:
    # {state, attempts, at}}``; only planes with an unapplied desired
    # config appear. Empty when all healthy.
    host_config_health: dict[str, dict[str, Any]]
    # #395 — host-migration reconcile health (numbered host-patches,
    # e.g. ``001-grub-render``). ``{<patch-id>: {state, attempts, at,
    # error?}}``; only patches with ``ok: false`` in the ledger appear.
    # Empty when all patches are applied / pre-#395 box.
    host_migration_health: dict[str, dict[str, Any]]
    # Issue #183 Phase 4 — local k3s cluster health summary. Also
    # carries the #402 host partitions and the #999 ``storage`` block.
    cluster_health: dict[str, Any]
    # #999 Part A — storage redundancy, CLASSIFIED server-side from
    # ``cluster_health["storage"]``. The raw block stays available above
    # for the per-member / per-path table; this is the verdict, derived
    # by the one function the alert rule and the copilot tool also call
    # so no two surfaces can disagree about whether an array is in
    # trouble. Empty on an appliance with no arrays AND on a supervisor
    # too old to report — ``storage_reported`` separates those, because
    # "nothing to say" and "we never looked" must not render alike.
    storage_findings: list[dict[str, str]] = []
    storage_worst_severity: str | None = None
    storage_reported: bool = False
    # #1017 — the interface MTU spatium-etc-render actually APPLIED at
    # this node's last boot, not what STATE asked for: the renderer drops
    # a value that is out of range, that would break a pinned IPv6
    # address, or that has no keyfile to live in. ``mtu_requested``
    # carries the operator's value so the difference is diagnosable.
    #
    # All three are None on a supervisor too old to report, which is
    # UNKNOWN and must not render like "at the default" —
    # ``mtu_reported`` separates them.
    mtu: int | None = None
    # A string, not an int: the value it reports is the operator's, and
    # the case it exists for is the one where that value was not a
    # number (the renderer dropped it). Typing it as an int makes it
    # null exactly when it is needed.
    # NOTE for anyone adding a field here off ``cluster_health``: that
    # column is stored VERBATIM from the heartbeat with no inner-shape
    # validation, so every value read out of it must be coerced before it
    # reaches a typed field — see ``mtu_fields``.
    mtu_requested: str | None = None
    #: ``applied`` / ``default`` / ``dropped`` / ``n/a``.
    mtu_applied: str | None = None
    mtu_reported: bool = False
    #: Per-node findings only. The fleet-consistency verdict is on
    #: ``ApplianceList`` — it needs every row, and a finding that showed
    #: up on the list response but not on the drilldown would be a
    #: per-endpoint inconsistency the UI would have to paper over.
    mtu_findings: list[dict[str, str]] = []
    # Issue #183 Phase 5 — installed k3s version (plain text, public).
    # NULL on legacy compose appliances / pre-#183 supervisors.
    k3s_version: str | None
    # Issue #183 Phase 5 — boolean indicating whether the supervisor
    # has shipped a kubeconfig the operator can reveal. The cipher-
    # text itself never leaves the server outside the reveal endpoint;
    # the row schema only exposes a "have I got one" bit.
    kubeconfig_set: bool
    # Issue #183 Phase 6 — k3s server-cert ``Not After`` timestamp.
    # NULL on legacy compose appliances; drives the
    # ``k3s_api_cert_expiring`` alert rule.
    k3s_api_cert_expires_at: datetime | None
    # Issue #183 Phase 6 — operator-controlled CIDR allowlist for
    # direct kubeapi access on tcp/6443. Empty = proxy-only.
    kubeapi_expose_cidrs: list[str]
    # #272 Phase 7 — control-plane cluster membership. ``cluster_role``
    # is the settled role (primary / member / null); ``desired_*`` +
    # ``cluster_join_state`` reflect an in-flight promote/demote so the
    # Fleet UI can show a "joining…" / "leaving…" / "failed" chip.
    cluster_role: str | None = None
    desired_cluster_role: str | None = None
    cluster_join_state: str | None = None
    cluster_join_reason: str | None = None
    # #590 — when cluster_join_state last changed. The Fleet UI keys the
    # "Clear stuck state" affordance off its age so the destructive escape
    # hatch isn't offered during a healthy multi-minute k3s join.
    cluster_join_state_at: datetime | None = None
    # #170 Wave E follow-up — soft-delete timestamp. Non-null on
    # ``state=revoked`` rows; cleared by re-authorize.
    revoked_at: datetime | None = None
    created_at: datetime


class MtuFleet(BaseModel):
    """#1017 — whether every node is on the same interface MTU.

    Computed over the rows the list endpoint already holds, so it costs
    no extra query. ``consistent`` is True when nobody reported: the
    absence of a reading is not a fault, and every appliance installed
    before this feature reports nothing.
    """

    reported: int = 0
    answers: dict[str, list[str]] = {}
    consistent: bool = True
    detail: str | None = None


class ApplianceList(BaseModel):
    appliances: list[ApplianceRow]
    mtu_fleet: MtuFleet = MtuFleet()


def _require_superadmin(user: CurrentUser) -> None:
    if not is_effective_superadmin(user):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Appliance approval is restricted to superadmins.",
        )


def _storage_findings(row: Appliance) -> list[StorageFinding]:
    """Classified storage findings for one appliance row (#999 Part A)."""
    ch = row.cluster_health if isinstance(row.cluster_health, dict) else {}
    return evaluate_storage(ch.get("storage"))


def _storage_worst_severity(row: Appliance) -> str | None:
    return worst_severity(_storage_findings(row))


def mtu_fields(cluster_health: Any) -> dict[str, Any]:
    """#1017 — the MTU half of one appliance row, from ONE read.

    Shared with the copilot's row builder so the two surfaces cannot
    disagree about how to read the same field, and resolved once so the
    reading and the findings come from the same report — reading
    ``cluster_health`` again at the call site is how a row ends up
    showing a value with no finding attached to it.

    Every value is coerced on the way out, because ``cluster_health`` is
    stored verbatim from the heartbeat with no inner-shape validation: a
    supervisor (buggy, downgraded, or a hand-edited row) reporting
    ``{"mtu": "abc"}`` would otherwise raise ValidationError inside
    ``_row_to_schema`` and 500 the list endpoint for the WHOLE fleet.
    ``bool`` is excluded explicitly, being an ``int``.
    """
    report = network_report(cluster_health)
    data = report or {}
    raw_mtu = data.get("mtu")
    raw_applied = data.get("mtu_applied")
    raw_requested = data.get("mtu_requested")
    return {
        "mtu": (raw_mtu if isinstance(raw_mtu, int) and not isinstance(raw_mtu, bool) else None),
        "mtu_requested": (str(raw_requested) if isinstance(raw_requested, (str, int)) else None),
        "mtu_applied": raw_applied if isinstance(raw_applied, str) else None,
        "mtu_reported": report is not None,
        "mtu_findings": [
            {"severity": f.severity, "kind": f.kind, "detail": f.detail}
            for f in evaluate_node_mtu(cluster_health)
        ],
    }


def _mtu_fleet(rows: Sequence[Appliance]) -> MtuFleet:
    """The fleet verdict over the rows a list endpoint already loaded.

    Membership is decided by ``network_mtu.in_cluster`` — shared with the
    copilot tool, because a predicate this load-bearing living in two
    places means the API and the copilot can give different verdicts for
    the same cluster.
    """
    return MtuFleet(**asdict(fleet_summary_for_appliances(rows)))


def _row_to_schema(row: Appliance) -> ApplianceRow:
    return ApplianceRow(
        id=row.id,
        hostname=row.hostname,
        state=row.state,  # type: ignore[arg-type]
        public_key_fingerprint=row.public_key_fingerprint,
        supervisor_version=row.supervisor_version,
        capabilities=row.capabilities or {},
        paired_at=row.paired_at,
        paired_from_ip=row.paired_from_ip,
        last_seen_at=row.last_seen_at,
        last_seen_ip=row.last_seen_ip,
        approved_at=row.approved_at,
        approved_by_user_id=row.approved_by_user_id,
        rejected_at=row.rejected_at,
        cert_serial=row.cert_serial,
        cert_issued_at=row.cert_issued_at,
        cert_expires_at=row.cert_expires_at,
        deployment_kind=row.deployment_kind,
        appliance_variant=row.appliance_variant,
        architecture=row.architecture,
        installed_appliance_version=row.installed_appliance_version,
        current_slot=row.current_slot,
        durable_default=row.durable_default,
        slot_a_version=row.slot_a_version,
        slot_b_version=row.slot_b_version,
        is_trial_boot=row.is_trial_boot,
        last_upgrade_state=row.last_upgrade_state,
        last_upgrade_state_at=row.last_upgrade_state_at,
        last_upgrade_log_tail=row.last_upgrade_log_tail,
        last_upgrade_progress=row.last_upgrade_progress,
        snmpd_running=row.snmpd_running,
        lldpd_running=row.lldpd_running,
        ntp_sync_state=row.ntp_sync_state,
        syslog_forwarding=row.syslog_forwarding,
        ssh_key_count=row.ssh_key_count,
        resolver_status=row.resolver_status,
        apt_state=row.apt_state,
        desired_appliance_version=row.desired_appliance_version,
        desired_slot_image_url=row.desired_slot_image_url,
        desired_slot_image_sha256=row.desired_slot_image_sha256,
        desired_slot_image_tls_insecure=row.desired_slot_image_tls_insecure,
        desired_next_boot_slot=row.desired_next_boot_slot,
        desired_default_slot=row.desired_default_slot,
        reboot_requested=row.reboot_requested,
        reboot_requested_at=row.reboot_requested_at,
        assigned_roles=list(row.assigned_roles or []),
        assigned_dns_group_id=row.assigned_dns_group_id,
        assigned_dhcp_group_id=row.assigned_dhcp_group_id,
        tags=dict(row.tags or {}),
        firewall_extra=row.firewall_extra,
        port_conflicts=dict(row.port_conflicts or {}),
        firewall_state=dict(row.firewall_state or {}),
        role_switch_state=row.role_switch_state,
        role_switch_reason=row.role_switch_reason,
        role_health=dict(row.role_health or {}),
        host_config_health=dict(row.host_config_health or {}),
        host_migration_health=dict(row.host_migration_health or {}),
        cluster_health=dict(row.cluster_health or {}),
        storage_findings=[
            {"severity": f.severity, "kind": f.kind, "name": f.name, "detail": f.detail}
            for f in _storage_findings(row)
        ],
        storage_worst_severity=_storage_worst_severity(row),
        storage_reported=has_storage_report(row.cluster_health),
        **mtu_fields(row.cluster_health),
        k3s_version=row.k3s_version,
        kubeconfig_set=row.kubeconfig_encrypted is not None,
        k3s_api_cert_expires_at=row.k3s_api_cert_expires_at,
        kubeapi_expose_cidrs=list(row.kubeapi_expose_cidrs or []),
        cluster_role=row.cluster_role,
        desired_cluster_role=row.desired_cluster_role,
        cluster_join_state=row.cluster_join_state,
        cluster_join_reason=row.cluster_join_reason,
        cluster_join_state_at=row.cluster_join_state_at,
        revoked_at=row.revoked_at,
        created_at=row.created_at,
    )


@router.get(
    "/appliances",
    response_model=ApplianceList,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="List registered appliances (superadmin)",
)
async def list_appliances(current_user: CurrentUser, db: DB) -> ApplianceList:
    _require_superadmin(current_user)
    rows = (
        (await db.execute(select(Appliance).order_by(Appliance.paired_at.desc()))).scalars().all()
    )
    return ApplianceList(
        appliances=[_row_to_schema(r) for r in rows],
        mtu_fleet=_mtu_fleet(rows),
    )


@router.get(
    "/appliances/{appliance_id}",
    response_model=ApplianceRow,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Fetch a single appliance (superadmin)",
)
async def get_appliance(appliance_id: uuid.UUID, current_user: CurrentUser, db: DB) -> ApplianceRow:
    _require_superadmin(current_user)
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    return _row_to_schema(row)


async def _approve_appliance_inline(
    db: DB,
    row: Appliance,
    approved_by_user_id: uuid.UUID | None,
) -> None:
    """Sign + persist a supervisor cert on the row, transition to
    ``approved``. Shared by the operator-driven
    /appliances/{id}/approve endpoint and the auto-approve path
    that /supervisor/register hits for self-bootstrap codes (#272
    Phase 1).

    Caller commits. Idempotent on already-approved rows.
    """
    if row.state == APPLIANCE_STATE_APPROVED:
        return
    ca = await ensure_ca(db)
    cert_pem, serial_hex, issued_at, expires_at = sign_supervisor_cert(
        ca=ca,
        appliance_id=row.id,
        public_key_der=row.public_key_der,
        public_key_fingerprint=row.public_key_fingerprint,
        hostname=row.hostname,
    )
    row.cert_pem = cert_pem
    row.cert_serial = serial_hex
    row.cert_issued_at = issued_at
    row.cert_expires_at = expires_at
    row.state = APPLIANCE_STATE_APPROVED
    row.approved_at = issued_at
    row.approved_by_user_id = approved_by_user_id


# #272 — per-variant DEFAULT role set the api stamps on
# ``Appliance.assigned_roles`` when a supervisor registers.
#
# DNS/DHCP are NOT auto-assigned to the control-plane node: the
# operator turns them on per node via the Fleet role toggle, so the
# data plane is always a deliberate fleet decision and a fresh control
# plane ships pure-control. Every variant therefore defaults to an
# empty role set. Kept as a table (rather than dropped) for the
# auto-assign mechanism + so a future variant can default differently.
# Legacy variant strings map to the same empty default.
_REGISTER_VARIANT_FIXED_ROLES: dict[str, list[str]] = {
    "control-plane": [],
    "appliance": [],
    "full-stack": [],
    "frontend-core": [],
    "application": [],
}


@router.post(
    "/appliances/{appliance_id}/approve",
    response_model=ApplianceRow,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Approve a pending appliance — issues a cert (superadmin)",
)
async def approve_appliance(
    appliance_id: uuid.UUID, current_user: CurrentUser, db: DB
) -> ApplianceRow:
    """Approve + sign in one shot. Idempotent on already-approved rows
    (no fresh cert is issued — use ``/appliances/{id}/rekey`` for
    that). Rejects rows already in ``rejected`` state with 409.
    """
    _require_superadmin(current_user)

    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    if row.state == APPLIANCE_STATE_APPROVED:
        return _row_to_schema(row)  # idempotent

    await _approve_appliance_inline(db, row, current_user.id)
    serial_hex = row.cert_serial or ""
    expires_at = row.cert_expires_at
    # Session token cleared — supervisor now uses mTLS. Keep the
    # current value on disk so an in-flight /poll succeeds before the
    # supervisor learns to switch; B3's UI will clarify the transition.
    # Actually — clearing it immediately means the supervisor's
    # in-flight /poll will 403. Leave it for now; the supervisor
    # discards it on its side after receiving cert_pem.

    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.approved",
            resource_type="appliance",
            resource_id=str(row.id),
            resource_display=row.hostname,
            result="success",
            new_value={
                "hostname": row.hostname,
                "fingerprint": row.public_key_fingerprint,
                "cert_serial": serial_hex,
                "cert_expires_at": expires_at.isoformat() if expires_at else None,
            },
        )
    )
    await db.commit()
    logger.info(
        "appliance_approved",
        appliance_id=str(row.id),
        hostname=row.hostname,
        cert_serial=serial_hex,
        user=current_user.username,
    )
    return _row_to_schema(row)


@router.post(
    "/appliances/{appliance_id}/reject",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Reject a pending appliance (deletes the row, superadmin)",
)
async def reject_appliance(appliance_id: uuid.UUID, current_user: CurrentUser, db: DB) -> None:
    """Reject = DELETE the row. Supervisor's next poll gets 403 +
    falls back to bootstrapping. Distinct from delete (next endpoint)
    only in the audit verb — operationally identical."""
    _require_superadmin(current_user)
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    if row.state == APPLIANCE_STATE_APPROVED:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Cannot reject an already-approved appliance. Use /delete instead.",
        )
    hostname = row.hostname
    fingerprint = row.public_key_fingerprint
    await db.delete(row)
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.rejected",
            resource_type="appliance",
            resource_id=str(appliance_id),
            resource_display=hostname,
            result="success",
            new_value={"fingerprint": fingerprint},
        )
    )
    await db.commit()
    logger.info(
        "appliance_rejected",
        appliance_id=str(appliance_id),
        hostname=hostname,
        user=current_user.username,
    )


class DeleteApplianceRequest(BaseModel):
    """Body for ``DELETE /appliances/{id}`` — operator's current
    password gates the destructive action. Same shape as the
    factory-reset re-auth and the agent-bootstrap-key reveal: the
    server verifies against the caller's ``hashed_password`` so a
    leaked session token alone can't drop fleet rows."""

    password: str = Field(min_length=1, max_length=256)


# Issue #197 — dependents preview + cleanup helpers.
#
# When an operator deletes an appliance, the dns_server / dhcp_server
# rows the supervisor registered as part of role assignment must go
# too — otherwise they linger as ghost offline servers, eat long-poll
# connections, generate 404-on-heartbeat noise, and count against HA
# Kea quorum. This module discovers the dependents both by FK
# (``appliance_id`` populated at supervisor-driven register time —
# forward-compatible; legacy rows stay NULL) and by hostname match
# (covers every pre-#197 row + handles edge cases where the FK
# wiring didn't catch).


class ApplianceDependentServer(BaseModel):
    """One DNS or DHCP server row tied to an appliance about to be
    deleted. Surfaced to the operator in the delete-confirm modal so
    they see the full blast radius before clicking."""

    kind: str  # "dns" | "dhcp"
    id: uuid.UUID
    name: str
    host: str
    status: str


class ApplianceDependents(BaseModel):
    dns: list[ApplianceDependentServer]
    dhcp: list[ApplianceDependentServer]


async def _find_appliance_dependents(
    db: DB,
    appliance: Appliance,
) -> ApplianceDependents:
    """Return the dns_server + dhcp_server rows that belong to this
    appliance. Matches on EITHER ``appliance_id`` (FK populated at
    register time per #197) OR ``hostname`` (legacy / pre-FK rows).
    Duplicates de-duped by row id.
    """
    from app.models.dhcp import DHCPServer  # noqa: PLC0415
    from app.models.dns import DNSServer  # noqa: PLC0415

    # DNS — FK match OR host-match. We DELIBERATELY do NOT match on
    # ``DNSServer.name`` because ``name`` is an operator-controlled
    # label (not a hostname guarantee) and could collide with an
    # unrelated remote DNS server an operator labelled with the
    # appliance's hostname. Review polish from #305 — Copilot caught
    # the over-match. ``DNSServer.host`` is set to the appliance's
    # hostname by the agent's ``register`` call (see dns/agents.py)
    # so it's the reliable identifier for appliance-owned rows.
    dns_rows = (
        (
            await db.execute(
                select(DNSServer).where(
                    or_(
                        DNSServer.appliance_id == appliance.id,
                        DNSServer.host == appliance.hostname,
                    )
                )
            )
        )
        .scalars()
        .all()
    )

    # DHCP — same logic. ``DHCPServer.name`` is unique + operator-
    # set; matching against it risks deleting unrelated server rows
    # an operator labelled with the appliance's hostname.
    dhcp_rows = (
        (
            await db.execute(
                select(DHCPServer).where(
                    or_(
                        DHCPServer.appliance_id == appliance.id,
                        DHCPServer.host == appliance.hostname,
                    )
                )
            )
        )
        .scalars()
        .all()
    )

    return ApplianceDependents(
        dns=[
            ApplianceDependentServer(kind="dns", id=r.id, name=r.name, host=r.host, status=r.status)
            for r in dns_rows
        ],
        dhcp=[
            ApplianceDependentServer(
                kind="dhcp", id=r.id, name=r.name, host=r.host, status=r.status
            )
            for r in dhcp_rows
        ],
    )


@router.get(
    "/appliances/{appliance_id}/dependents",
    response_model=ApplianceDependents,
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Preview dns_server + dhcp_server rows tied to this appliance",
)
async def get_appliance_dependents(
    appliance_id: uuid.UUID,
    db: DB,
) -> ApplianceDependents:
    """Returns the dns_server + dhcp_server rows that the
    delete-appliance flow will sweep. Operator-facing preview so the
    delete-confirm modal can render "this will also remove X DNS
    servers and Y DHCP servers" — no surprises (#197).
    """
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    return await _find_appliance_dependents(db, row)


@router.delete(
    "/appliances/{appliance_id}",
    response_model=ApplianceRow,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Soft-delete an appliance (superadmin + password re-auth)",
)
async def delete_appliance(
    appliance_id: uuid.UUID,
    body: DeleteApplianceRequest,
    current_user: CurrentUser,
    db: DB,
) -> ApplianceRow:
    """Soft-delete an appliance (#170 Wave E follow-up).

    The row stays — ``state`` flips to ``revoked`` + ``revoked_at``
    stamped — so heartbeats from that appliance return 403, the
    supervisor's revocation detector trips, and its DNS/DHCP service
    containers tear down. An admin can later either
    ``POST /appliances/{id}/reauthorize`` (flip back to ``approved``
    + clear ``revoked_at``) or
    ``POST /appliances/{id}/permanent-delete`` (real DELETE).

    A Celery beat sweep eventually hard-deletes rows whose
    ``revoked_at`` is older than
    ``platform_settings.appliance_revoked_retention_days`` (default
    30, ``0`` disables auto-purge).

    Requires the operator's current password — UI mis-click guard
    even with the per-row Delete button + checkbox.
    """
    from app.core.security import verify_password  # noqa: PLC0415

    _require_superadmin(current_user)
    if not current_user.hashed_password or not verify_password(
        body.password, current_user.hashed_password
    ):
        db.add(
            AuditLog(
                user_id=current_user.id,
                user_display_name=current_user.display_name,
                auth_source=current_user.auth_source,
                action="appliance.delete_denied",
                resource_type="appliance",
                resource_id=str(appliance_id),
                resource_display=str(appliance_id),
                result="denied",
                # `error_detail` is the column; `error_message=` raised
                # TypeError at construction, so the DENIAL path itself
                # answered 500 — every wrong-password delete attempt, ever.
                error_detail="bad_password",
            )
        )
        await db.commit()
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Current password incorrect.",
        )
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")

    # #272 — refuse revoking the only control-plane node. It runs THIS
    # control plane (api / db / frontend) AND is the etcd seed; revoking
    # it makes its heartbeats 403, trips the supervisor's revocation
    # detector, and tears the control plane down — bricking the cluster.
    # A control-plane node must be demoted (or another promoted) first.
    def _is_control_plane(a: Appliance) -> bool:
        return a.appliance_variant in _SELF_BOOTSTRAP_VARIANTS or a.cluster_role in (
            CLUSTER_ROLE_PRIMARY,
            CLUSTER_ROLE_MEMBER,
        )

    if _is_control_plane(row):
        other_cp = (
            await db.execute(
                select(sa_func.count())
                .select_from(Appliance)
                .where(
                    Appliance.id != row.id,
                    Appliance.state != APPLIANCE_STATE_REVOKED,
                    or_(
                        Appliance.appliance_variant.in_(tuple(_SELF_BOOTSTRAP_VARIANTS)),
                        Appliance.cluster_role.in_((CLUSTER_ROLE_PRIMARY, CLUSTER_ROLE_MEMBER)),
                    ),
                )
            )
        ).scalar() or 0
        if other_cp == 0:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Refusing to revoke the only control-plane node — it runs the "
                "control plane and is the etcd seed. Promote another node first, "
                "or factory-reset / reinstall this box to decommission it.",
            )

    state_at_delete = row.state
    row.state = APPLIANCE_STATE_REVOKED
    row.revoked_at = datetime.now(UTC)

    # Issue #197 — drop the dependent dns_server / dhcp_server rows
    # in the same transaction as the appliance revoke. Operator
    # expectation is "Delete = gone"; leaving ghost server rows in the
    # DNS / DHCP server-groups view is the exact bug this issue fixes.
    # Reauthorize (the soft-delete recovery flow) doesn't lose data —
    # the supervisor's next heartbeat post-reauthorize re-runs role
    # assignment and the agent containers re-register, recreating the
    # rows automatically. Eventual consistency, but operator-invisible.
    dependents = await _find_appliance_dependents(db, row)
    dependent_dns_names = [d.name for d in dependents.dns]
    dependent_dhcp_names = [d.name for d in dependents.dhcp]
    if dependents.dns or dependents.dhcp:
        from app.models.dhcp import DHCPServer  # noqa: PLC0415
        from app.models.dns import DNSServer  # noqa: PLC0415

        for d in dependents.dns:
            dns_server = await db.get(DNSServer, d.id)
            if dns_server is not None:
                await db.delete(dns_server)
        for d in dependents.dhcp:
            dhcp_server = await db.get(DHCPServer, d.id)
            if dhcp_server is not None:
                await db.delete(dhcp_server)
        logger.info(
            "appliance_dependents_cleaned",
            appliance_id=str(appliance_id),
            dns_dropped=len(dependent_dns_names),
            dhcp_dropped=len(dependent_dhcp_names),
        )

    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.soft_deleted",
            resource_type="appliance",
            resource_id=str(appliance_id),
            resource_display=row.hostname,
            result="success",
            new_value={
                "state_at_delete": state_at_delete,
                "revoked_at": row.revoked_at.isoformat(),
                # #197 — recorded for audit so an operator chasing
                # "what disappeared on 2026-05-25 14:22" can match the
                # appliance delete to the missing server rows.
                "cascaded_dns_servers": dependent_dns_names,
                "cascaded_dhcp_servers": dependent_dhcp_names,
            },
        )
    )
    await db.commit()
    await db.refresh(row)
    logger.info(
        "appliance_soft_deleted",
        appliance_id=str(appliance_id),
        hostname=row.hostname,
        user=current_user.username,
    )
    return _row_to_schema(row)


@router.post(
    "/appliances/{appliance_id}/reauthorize",
    response_model=ApplianceRow,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Re-authorize a revoked appliance (superadmin)",
)
async def reauthorize_appliance(
    appliance_id: uuid.UUID,
    current_user: CurrentUser,
    db: DB,
) -> ApplianceRow:
    """Lift a soft-delete: clear ``revoked_at`` and put the appliance
    back in ``approved``. The supervisor's three-strike detector will
    self-clear on the next 200 heartbeat — but bringing service
    containers BACK up requires the operator to re-fire the role
    assignment (the supervisor's revoke-teardown ran a ``compose stop``;
    a fresh role-assignment apply re-runs ``up -d``).
    """
    _require_superadmin(current_user)
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    if row.state != APPLIANCE_STATE_REVOKED:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Appliance is in state {row.state!r}; only revoked rows can be re-authorized.",
        )
    row.state = APPLIANCE_STATE_APPROVED
    row.revoked_at = None
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.reauthorized",
            resource_type="appliance",
            resource_id=str(appliance_id),
            resource_display=row.hostname,
            result="success",
        )
    )
    await db.commit()
    await db.refresh(row)
    logger.info(
        "appliance_reauthorized",
        appliance_id=str(appliance_id),
        hostname=row.hostname,
        user=current_user.username,
    )
    return _row_to_schema(row)


@router.post(
    "/appliances/{appliance_id}/permanent-delete",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Permanently delete an appliance row (superadmin + password)",
)
async def permanent_delete_appliance(
    appliance_id: uuid.UUID,
    body: DeleteApplianceRequest,
    current_user: CurrentUser,
    db: DB,
) -> None:
    """Hard DELETE the appliance row. Same password gate as the soft
    delete + an explicit state check: the row must already be
    ``revoked`` (operator went through soft-delete first). This is
    the recovery path for after-the-fact "yes I'm sure" + the action
    invoked by the retention sweep when ``revoked_at`` is older than
    the retention window.
    """
    from app.core.security import verify_password  # noqa: PLC0415

    _require_superadmin(current_user)
    if not current_user.hashed_password or not verify_password(
        body.password, current_user.hashed_password
    ):
        db.add(
            AuditLog(
                user_id=current_user.id,
                user_display_name=current_user.display_name,
                auth_source=current_user.auth_source,
                action="appliance.permanent_delete_denied",
                resource_type="appliance",
                resource_id=str(appliance_id),
                resource_display=str(appliance_id),
                result="denied",
                # Same construction defect as delete_appliance above.
                error_detail="bad_password",
            )
        )
        await db.commit()
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Current password incorrect.",
        )
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    if row.state != APPLIANCE_STATE_REVOKED:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Permanent delete is only allowed on revoked appliances; soft-delete first.",
        )
    hostname = row.hostname
    fingerprint = row.public_key_fingerprint
    cert_serial = row.cert_serial
    await db.delete(row)
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.permanently_deleted",
            resource_type="appliance",
            resource_id=str(appliance_id),
            resource_display=hostname,
            result="success",
            new_value={
                "fingerprint": fingerprint,
                "cert_serial": cert_serial,
            },
        )
    )
    await db.commit()
    logger.info(
        "appliance_permanently_deleted",
        appliance_id=str(appliance_id),
        hostname=hostname,
        user=current_user.username,
    )


@router.post(
    "/appliances/{appliance_id}/rekey",
    response_model=ApplianceRow,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Re-sign the appliance's cert (rotation, superadmin)",
)
async def rekey_appliance(
    appliance_id: uuid.UUID, current_user: CurrentUser, db: DB
) -> ApplianceRow:
    """Issue a fresh cert against the existing supervisor pubkey.
    Used for routine 60-day renewal + emergency forced rotation
    (suspected compromise). Subject + SAN identical to the original;
    only the serial + validity window change. Older certs against
    the same pubkey remain technically valid in the CA's eye until
    they expire — Wave-D-or-later CRL work plugs that gap."""
    _require_superadmin(current_user)
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    if row.state != APPLIANCE_STATE_APPROVED:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Cannot re-key an appliance in state {row.state!r}; approve it first.",
        )

    ca = await ensure_ca(db)
    cert_pem, serial_hex, issued_at, expires_at = sign_supervisor_cert(
        ca=ca,
        appliance_id=row.id,
        public_key_der=row.public_key_der,
        public_key_fingerprint=row.public_key_fingerprint,
        hostname=row.hostname,
    )
    previous_serial = row.cert_serial
    row.cert_pem = cert_pem
    row.cert_serial = serial_hex
    row.cert_issued_at = issued_at
    row.cert_expires_at = expires_at
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.cert_renewed",
            resource_type="appliance",
            resource_id=str(row.id),
            resource_display=row.hostname,
            result="success",
            new_value={
                "previous_cert_serial": previous_serial,
                "new_cert_serial": serial_hex,
                "expires_at": expires_at.isoformat(),
            },
        )
    )
    await db.commit()
    logger.info(
        "appliance_rekeyed",
        appliance_id=str(row.id),
        hostname=row.hostname,
        new_cert_serial=serial_hex,
        previous_cert_serial=previous_serial,
        user=current_user.username,
    )
    return _row_to_schema(row)


# ── Admin: role assignment + tags (#170 Wave C2) ──────────────────


_VALID_ROLES = {
    "dns-bind9",
    "dns-powerdns",
    "dns-technitium",
    "dhcp",
    "looking-glass",
    "observer",
    "custom",
}
_DNS_ROLES = {"dns-bind9", "dns-powerdns", "dns-technitium"}


class ApplianceRolesUpdate(BaseModel):
    """Operator-driven role + group + tag assignment payload.

    Each field is optional — operator can update a subset without
    blanking the others. ``roles=[]`` is the explicit "idle" signal
    (approved but running nothing); ``roles=None`` (omitted) leaves
    the current role list intact.
    """

    roles: list[str] | None = Field(
        default=None,
        description=(
            "Subset of dns-bind9 / dns-powerdns / dns-technitium / dhcp / "
            "looking-glass / observer / custom. The three dns-* roles are "
            "mutually exclusive — one engine per appliance."
        ),
    )
    dns_group_id: uuid.UUID | None = None
    dhcp_group_id: uuid.UUID | None = None
    tags: dict[str, str] | None = None
    # #170 Wave C3 — operator-pasted nft fragment. ``None`` leaves the
    # current value alone; ``""`` clears it; any other string replaces
    # it. The supervisor runs ``nft -c -f`` against the rendered
    # drop-in before live-swap, so a syntactically invalid value
    # rejects supervisor-side rather than at this endpoint.
    firewall_extra: str | None = None


@router.put(
    "/appliances/{appliance_id}/roles",
    response_model=ApplianceRow,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Assign roles + groups + tags (superadmin)",
)
async def update_appliance_roles(
    appliance_id: uuid.UUID,
    body: ApplianceRolesUpdate,
    current_user: CurrentUser,
    db: DB,
) -> ApplianceRow:
    """Validate + persist a role assignment. Refuses to assign a role
    the supervisor doesn't advertise the capability for (BIND9 needs
    ``can_run_dns_bind9``, PowerDNS needs ``can_run_dns_powerdns``,
    Technitium needs ``can_run_dns_technitium``, DHCP needs
    ``can_run_dhcp``). Refuses combining more than one dns-* role (one
    engine per box). 422 on validation failure.

    The supervisor's next heartbeat picks up the change via
    ``role_assignment`` in the response. Service-container lifecycle
    (load image + start / stop / restart) lives on the supervisor —
    this endpoint just records intent.
    """
    _require_superadmin(current_user)

    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    if row.state != APPLIANCE_STATE_APPROVED:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Cannot assign roles to appliance in state {row.state!r}; approve it first.",
        )

    if body.roles is not None:
        # Reject unknown role tokens explicitly so a typo on the API
        # surface doesn't silently roll through the JSONB column.
        for r in body.roles:
            if r not in _VALID_ROLES:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    f"Unknown role {r!r}. Valid: {sorted(_VALID_ROLES)}.",
                )
        # Mutually-exclusive DNS engines.
        dns_engines = _DNS_ROLES.intersection(body.roles)
        if len(dns_engines) > 1:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"{sorted(dns_engines)} are mutually exclusive — one DNS engine per appliance.",
            )
        # Capability gate. Each requested role must be backed by the
        # supervisor's advertised cap. Skips for ``observer`` / ``custom``
        # which don't have a single-flag capability today.
        caps = row.capabilities or {}
        for r in body.roles:
            cap_key = {
                "dns-bind9": "can_run_dns_bind9",
                "dns-powerdns": "can_run_dns_powerdns",
                "dns-technitium": "can_run_dns_technitium",
                "dhcp": "can_run_dhcp",
                "looking-glass": "can_run_looking_glass",
                "observer": "can_run_observer",
            }.get(r)
            if cap_key is not None and not caps.get(cap_key, False):
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    (
                        f"Appliance {row.hostname!r} doesn't advertise "
                        f"capability {cap_key}=true; cannot assign role {r!r}."
                    ),
                )
        row.assigned_roles = list(body.roles)

    if body.dns_group_id is not None:
        # Best-effort existence check — wrong group_id → 422.
        from app.models.dns import DNSServerGroup

        dns_group = await db.get(DNSServerGroup, body.dns_group_id)
        if dns_group is None:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"DNS server group {body.dns_group_id} not found.",
            )
        row.assigned_dns_group_id = dns_group.id
    if body.dhcp_group_id is not None:
        from app.models.dhcp import DHCPServerGroup

        dhcp_group = await db.get(DHCPServerGroup, body.dhcp_group_id)
        if dhcp_group is None:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"DHCP server group {body.dhcp_group_id} not found.",
            )
        row.assigned_dhcp_group_id = dhcp_group.id

    if body.tags is not None:
        # Coerce every value to string — JSONB will accept anything
        # but the public contract is "string : string" for fleet
        # filters / MCP `tags_match`. Reject non-string values up-front
        # so the operator sees the issue at submit time.
        for k, v in body.tags.items():
            if not isinstance(v, str):
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    f"Tag {k!r} must be a string; got {type(v).__name__}.",
                )
        row.tags = dict(body.tags)
    if body.firewall_extra is not None:
        # #285 Phase 3d — lint ONLY the delta (this PATCH carries a new
        # firewall_extra), so a pre-3d value that predates the grammar is
        # never retro-rejected. Hard-422 only on genuinely dangerous patterns
        # (nft-injection chars / unbalanced braces / drop-22); grammar nits
        # are advisory warnings surfaced in the preview, and `nft -c -f` on
        # the host is the final syntax authority.
        from app.services.appliance.firewall_lint import errors, lint_firewall_extra

        fw_errors = errors(lint_firewall_extra(body.firewall_extra))
        if fw_errors:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "firewall_extra rejected: "
                + "; ".join(f"line {f.line}: {f.message}" for f in fw_errors),
            )
        # Empty string is meaningful — operator clearing the extra
        # block. The supervisor renders an empty fragment then; the
        # role-driven mgmt + per-role rules still ship.
        row.firewall_extra = body.firewall_extra if body.firewall_extra else None

    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.role_assigned",
            resource_type="appliance",
            resource_id=str(row.id),
            resource_display=row.hostname,
            result="success",
            new_value={
                "roles": list(row.assigned_roles or []),
                "dns_group_id": (
                    str(row.assigned_dns_group_id) if row.assigned_dns_group_id else None
                ),
                "dhcp_group_id": (
                    str(row.assigned_dhcp_group_id) if row.assigned_dhcp_group_id else None
                ),
                "tags": dict(row.tags or {}),
            },
        )
    )
    await db.commit()
    logger.info(
        "appliance_roles_assigned",
        appliance_id=str(row.id),
        hostname=row.hostname,
        roles=list(row.assigned_roles or []),
        user=current_user.username,
    )
    # #358 Phase 1 — wake the supervisor heartbeat long-poll so the new
    # role/group/firewall assignment applies in ~0 s instead of waiting
    # for the next heartbeat. Advisory; the heartbeat tick is the fallback.
    await publish_wake(appliance_channel(row.id))
    return _row_to_schema(row)


# ── Admin: control-plane promotion (#272 Phase 7) ────────────────


class ControlPlaneMembersRequest(BaseModel):
    """Batch promote/demote payload — a list of appliance IDs.

    k3s embedded-etcd HA wants odd server counts (1 / 3 / 5 / 7), so
    promotion is done in batches that land on an odd total instead of
    one-at-a-time (which would pause at a fragile even count). The
    endpoint validates the RESULTING committed-or-in-flight member
    count is odd and refuses otherwise (operator sees it inline).
    """

    appliance_ids: list[uuid.UUID] = Field(..., min_length=1)


async def _effective_cp_members(db: DB) -> list[Appliance]:
    """Every appliance that is, or is becoming, a control-plane member.

    Counts settled members (``cluster_role`` in primary/member) PLUS
    in-flight joiners (``desired_cluster_role='member'``) and excludes
    in-flight leavers (``desired_cluster_role='none'``) — so two
    overlapping promote calls can't both think the cluster is still at
    1 and each add 2 (→ silently landing at 5).
    """
    rows = (
        (
            await db.execute(
                select(Appliance).where(
                    Appliance.state == APPLIANCE_STATE_APPROVED,
                    or_(
                        Appliance.cluster_role.in_((CLUSTER_ROLE_PRIMARY, CLUSTER_ROLE_MEMBER)),
                        Appliance.desired_cluster_role == DESIRED_CLUSTER_ROLE_MEMBER,
                    ),
                )
            )
        )
        .scalars()
        .all()
    )
    return [r for r in rows if r.desired_cluster_role != DESIRED_CLUSTER_ROLE_NONE]


async def _committed_cp_count(db: DB) -> int:
    """Count of SETTLED control-plane nodes (``cluster_role`` in
    primary/member), floored at 1 (#277).

    Used to scale the CNPG postgres cluster + control-plane workload
    replicas. Counts only settled members — NOT in-flight joiners
    (``desired_cluster_role='member'`` but ``cluster_role`` still NULL)
    — so CNPG doesn't try to provision a replica for a node that hasn't
    finished joining + getting labeled yet. Floored at 1 so a fresh
    single-node install (seed's cluster_role still NULL pre-promote)
    renders instances=1, not 0.
    """
    n = (
        await db.execute(
            select(sa_func.count())
            .select_from(Appliance)
            .where(
                Appliance.state == APPLIANCE_STATE_APPROVED,
                Appliance.cluster_role.in_((CLUSTER_ROLE_PRIMARY, CLUSTER_ROLE_MEMBER)),
            )
        )
    ).scalar() or 0
    return max(1, int(n))


def _split_cidr_csv(value: str | None) -> list[str]:
    """Split a (possibly comma-joined dual-stack) CIDR field into entries.

    k3s ``cluster-cidr`` / ``service-cidr`` are a single value on a
    v4-only cluster and a comma-joined pair on a dual-stack cluster
    (``10.42.0.0/16,2001:cafe:42::/56``). The renderer family-splits the
    result, so order doesn't matter here.
    """
    return [c.strip() for c in (value or "").split(",") if c.strip()]


def _node_cidrs(ap: Appliance) -> list[str]:
    """Every InternalIP of an appliance as a host CIDR — ``/32`` for v4,
    ``/128`` for v6 (#285 Phase 1).

    Prefers the all-family ``node_ips`` list; falls back to the single
    ``node_ip`` (as ``/32``) for a pre-#285 supervisor that hasn't
    reported ``node_ips`` yet. The family split is what lets a v6 peer
    be scoped by its real ``/128`` rather than a fabricated ``/32``.
    """
    ips = list(ap.node_ips or [])
    if not ips and ap.node_ip:
        ips = [ap.node_ip]
    out: list[str] = []
    for ip in ips:
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            continue
        out.append(f"{addr}/{128 if addr.version == 6 else 32}")
    return out


async def _firewall_peer_members(db: DB) -> list[Appliance]:
    """CP members for firewall peer-scoping — like ``_effective_cp_members``
    but ASYMMETRIC ON LEAVE (#285 Phase 1).

    An in-flight leaver (``desired_cluster_role='none'``) is KEPT in the
    set until its ``cluster_join_state`` reaches ``left``, so the
    destructive etcd member-remove can still reach its peers (and they
    it) during the leave window. Only the next render after ``left``
    drops it. Mirrors the cert-SAN only-grow safety exactly — the
    dangerous direction (removing a peer) is delayed until the operation
    that needs the rule has completed.
    """
    rows = (
        (
            await db.execute(
                select(Appliance).where(
                    Appliance.state == APPLIANCE_STATE_APPROVED,
                    or_(
                        Appliance.cluster_role.in_((CLUSTER_ROLE_PRIMARY, CLUSTER_ROLE_MEMBER)),
                        Appliance.desired_cluster_role == DESIRED_CLUSTER_ROLE_MEMBER,
                    ),
                )
            )
        )
        .scalars()
        .all()
    )
    # Keep settled members + in-flight joiners + in-flight leavers; drop
    # only a leaver that has fully reported ``left`` (its etcd surgery is
    # done, so it no longer needs — nor should be granted — peer access).
    return [r for r in rows if r.cluster_join_state != CLUSTER_JOIN_STATE_LEFT]


async def _cluster_peer_cidrs(db: DB, row: Appliance) -> list[str]:
    """Host CIDRs (``/32`` v4 + ``/128`` v6) of every OTHER control-plane
    peer ``row`` must open its k3s server ports to (#272 Phase 7b, #285).

    Only meaningful when ``row`` is itself a control-plane node — a
    settled member/primary, a node mid-promotion
    (``desired_cluster_role='member'``), or a node mid-LEAVE that hasn't
    fully left yet (so the etcd member-remove can complete). In-flight
    joiners need the peer set too: the seed must open :6443 to the joiner
    BEFORE it connects, and the joiner must open etcd ports back. Returns
    an empty list for plain application appliances + single-node installs
    (no peers).
    """
    is_cp = (
        row.cluster_role in (CLUSTER_ROLE_PRIMARY, CLUSTER_ROLE_MEMBER)
        or row.desired_cluster_role == DESIRED_CLUSTER_ROLE_MEMBER
        or (
            row.desired_cluster_role == DESIRED_CLUSTER_ROLE_NONE
            and row.cluster_join_state != CLUSTER_JOIN_STATE_LEFT
        )
    )
    if not is_cp:
        return []
    members = await _firewall_peer_members(db)
    out: list[str] = []
    for m in members:
        if m.id == row.id:
            continue
        out.extend(_node_cidrs(m))
    return sorted(set(out))


async def _resolve_primary(db: DB, members: list[Appliance]) -> Appliance | None:
    """Return the etcd seed (``cluster_role='primary'``), designating
    one on the first promote.

    On a fresh single-node install no row carries ``cluster_role`` yet.
    The seed is the lone approved control-plane appliance (full-stack /
    frontend-core); designate it primary so subsequent joiners point at
    it. Ambiguous (0 or >1 candidates) → caller raises 409.
    """
    for m in members:
        if m.cluster_role == CLUSTER_ROLE_PRIMARY:
            return m
    candidates = (
        (
            await db.execute(
                select(Appliance).where(
                    Appliance.state == APPLIANCE_STATE_APPROVED,
                    Appliance.appliance_variant.in_(
                        ("control-plane", "full-stack", "frontend-core")
                    ),
                )
            )
        )
        .scalars()
        .all()
    )
    if len(candidates) == 1:
        candidates[0].cluster_role = CLUSTER_ROLE_PRIMARY
        return candidates[0]
    return None


@router.post(
    "/fleet/control-plane/promote",
    response_model=ApplianceList,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Promote application appliances into the control-plane cluster (superadmin)",
)
async def promote_control_plane(
    body: ControlPlaneMembersRequest,
    current_user: CurrentUser,
    db: DB,
) -> ApplianceList:
    """Batch-promote the given appliances to k3s control-plane members.

    Stamps each with the seed's join coordinates (server URL + token);
    the supervisor's host-side runner reconfigures k3s + reports back
    via ``cluster_join_state``. Refuses a batch that wouldn't land on an
    odd total member count (etcd quorum hygiene).
    """
    _require_superadmin(current_user)

    members = await _effective_cp_members(db)
    primary = await _resolve_primary(db, members)
    if primary is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "No single control-plane seed found to join. Exactly one approved "
            "full-stack / frontend-core appliance is required as the etcd seed.",
        )
    if primary.k3s_join_token_encrypted is None or not primary.node_ip:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "The control-plane seed hasn't reported its k3s join token / node IP yet — "
            "wait for its next heartbeat and retry. (The join URL needs the seed's real "
            "node IP, not the supervisor pod IP.)",
        )

    # Count the seed even when it was just designated (cluster_role was
    # NULL on a fresh single-node install, so it isn't in ``members``).
    current_count = len({m.id for m in members} | {primary.id})
    targets: list[Appliance] = []
    seen: set[uuid.UUID] = set()
    for aid in body.appliance_ids:
        if aid in seen:
            continue
        seen.add(aid)
        row = await db.get(Appliance, aid)
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"Appliance {aid} not found.")
        if row.id == primary.id:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"Appliance {row.hostname!r} is the control-plane seed; it's already a member.",
            )
        if row.state != APPLIANCE_STATE_APPROVED:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"Appliance {row.hostname!r} is in state {row.state!r}; approve it first.",
            )
        if row.cluster_role is not None or row.desired_cluster_role == DESIRED_CLUSTER_ROLE_MEMBER:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"Appliance {row.hostname!r} is already a control-plane member (or joining).",
            )
        # A control-plane-variant node is already a control plane — you
        # can't promote a control plane to a control plane. (The seed is
        # caught by the primary check above; this catches any other
        # control-plane-variant box, designated or not.)
        if row.appliance_variant in _SELF_BOOTSTRAP_VARIANTS:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"Appliance {row.hostname!r} is a control-plane node "
                f"(variant {row.appliance_variant!r}) — it's already a control plane, "
                "not promotable. Only Appliance-role nodes join as members.",
            )
        if row.deployment_kind != "appliance":
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"Appliance {row.hostname!r} (deployment_kind={row.deployment_kind!r}) can't join "
                "a k3s control-plane cluster — only OS-appliance nodes can.",
            )
        targets.append(row)

    new_total = current_count + len(targets)
    if new_total % 2 == 0:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Promoting {len(targets)} appliance(s) would leave the control-plane cluster at "
            f"{new_total} members. etcd HA wants an ODD count (1 / 3 / 5 / 7) — promote "
            f"{'one fewer' if len(targets) > 1 else 'one more'} so the total is odd.",
        )

    # Build the join URL from the seed's REAL node IP, never
    # ``last_seen_ip`` (the supervisor pod IP, 10.42.x.x — unreachable
    # by joiners). ``node_ip`` is the k3s-registered InternalIP the
    # supervisor reports on heartbeat.
    server_url = f"https://{primary.node_ip}:6443"
    for row in targets:
        row.desired_cluster_role = DESIRED_CLUSTER_ROLE_MEMBER
        row.desired_k3s_server_url = server_url
        row.desired_k3s_join_token_encrypted = primary.k3s_join_token_encrypted
        row.cluster_join_state = CLUSTER_JOIN_STATE_JOINING
        row.cluster_join_state_at = datetime.now(UTC)  # #590 staleness clock
        row.cluster_join_reason = None
        db.add(
            AuditLog(
                user_id=current_user.id,
                user_display_name=current_user.display_name,
                auth_source=current_user.auth_source,
                action="appliance.control_plane_promoted",
                resource_type="appliance",
                resource_id=str(row.id),
                resource_display=row.hostname,
                result="success",
                new_value={"server_url": server_url, "new_total_members": new_total},
            )
        )
    await db.commit()
    logger.info(
        "control_plane_promote",
        primary=str(primary.id),
        promoted=[str(r.id) for r in targets],
        new_total=new_total,
        user=current_user.username,
    )
    return ApplianceList(appliances=[_row_to_schema(r) for r in targets])


@router.post(
    "/fleet/control-plane/demote",
    response_model=ApplianceList,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Demote control-plane members back to application appliances (superadmin)",
)
async def demote_control_plane(
    body: ControlPlaneMembersRequest,
    current_user: CurrentUser,
    db: DB,
) -> ApplianceList:
    """Batch-demote the given control-plane members back to application
    appliances. Refuses a batch that would leave the cluster at an even
    count, and refuses demoting the seed (use a dedicated seed-migration
    flow for that — out of scope for Phase 7)."""
    _require_superadmin(current_user)

    members = await _effective_cp_members(db)
    current_count = len(members)

    targets: list[Appliance] = []
    seen: set[uuid.UUID] = set()
    for aid in body.appliance_ids:
        if aid in seen:
            continue
        seen.add(aid)
        row = await db.get(Appliance, aid)
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"Appliance {aid} not found.")
        if row.cluster_role == CLUSTER_ROLE_PRIMARY:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"Appliance {row.hostname!r} is the etcd seed and can't be demoted here.",
            )
        if row.cluster_role != CLUSTER_ROLE_MEMBER:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"Appliance {row.hostname!r} isn't a control-plane member.",
            )
        targets.append(row)

    remaining = current_count - len(targets)
    if remaining % 2 == 0:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Demoting {len(targets)} appliance(s) would leave the control-plane cluster at "
            f"{remaining} members. etcd HA wants an ODD count (1 / 3 / 5 / 7) — demote "
            f"{'one fewer' if len(targets) > 1 else 'one more'} so the remainder is odd.",
        )

    for row in targets:
        row.desired_cluster_role = DESIRED_CLUSTER_ROLE_NONE
        row.cluster_join_state = CLUSTER_JOIN_STATE_LEAVING
        row.cluster_join_state_at = datetime.now(UTC)  # #590 staleness clock
        row.cluster_join_reason = None
        # The join coordinates aren't needed for a leave; clear any stale ones.
        row.desired_k3s_server_url = None
        row.desired_k3s_join_token_encrypted = None
        db.add(
            AuditLog(
                user_id=current_user.id,
                user_display_name=current_user.display_name,
                auth_source=current_user.auth_source,
                action="appliance.control_plane_demoted",
                resource_type="appliance",
                resource_id=str(row.id),
                resource_display=row.hostname,
                result="success",
                new_value={"remaining_members": remaining},
            )
        )
    await db.commit()
    logger.info(
        "control_plane_demote",
        demoted=[str(r.id) for r in targets],
        remaining=remaining,
        user=current_user.username,
    )
    return ApplianceList(appliances=[_row_to_schema(r) for r in targets])


# ── Admin: dead-node replacement (#272 Phase 9) ──────────────────


class ControlPlaneReplaceResponse(BaseModel):
    """Result of replacing a dead control-plane member.

    The dead row is flagged for eviction (the seed deletes its k8s Node
    on the next heartbeat, which makes k3s drop the etcd member) and a
    fresh single-use pairing code is minted so a replacement appliance
    can pair → be approved → be promoted into the freed slot.
    """

    evicted: ApplianceRow
    pairing_code: str
    pairing_expires_at: datetime


@router.post(
    "/fleet/control-plane/{appliance_id}/replace",
    response_model=ControlPlaneReplaceResponse,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Replace a dead control-plane member — evict + mint a pairing code (superadmin)",
)
async def replace_control_plane_member(
    appliance_id: uuid.UUID,
    current_user: CurrentUser,
    db: DB,
) -> ControlPlaneReplaceResponse:
    """Recover a control-plane node that died ungracefully.

    Unlike demote (which the leaving node's own supervisor drives), a
    dead node can't wipe itself — so the SEED evicts it: this endpoint
    flags the row ``evict_requested`` + drops it from the cluster
    accounting, the seed supervisor deletes the k8s Node on its next
    heartbeat (k3s removes the etcd member with it), and a single-use
    pairing code is minted for the replacement box. Refuses the etcd
    seed (migrating the seed is a separate flow) and any row that isn't
    a settled control-plane member.
    """
    _require_superadmin(current_user)

    from app.api.v1.appliance.pairing import _generate_code, _hash_code  # noqa: PLC0415
    from app.models.appliance import PairingCode  # noqa: PLC0415

    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Appliance {appliance_id} not found.")
    if row.cluster_role == CLUSTER_ROLE_PRIMARY:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Appliance {row.hostname!r} is the etcd seed — replacing the seed is a "
            "separate migration flow, out of scope here.",
        )
    # A joiner whose join FAILED is replaceable too. The failure that needs
    # this flow is the one the classifier names "already an etcd member":
    # the node's k3s got far enough to register its etcd member (or the
    # seed kept a stale one under its hostname), then died — so the seed
    # holds a member nobody serves, every re-promote is refused with
    # "duplicate node name", and Replace was the one route that evicts the
    # stale Node/member by name, yet it 409'd on the row not being settled
    # (appliance sizing campaign, 2026-09-02: a 3-node formation stuck on
    # one such joiner, cleared only by hand). In-flight joiners still 409.
    #
    # The failed joiner is accepted WHETHER OR NOT its desired-state is still
    # set: a transient failure keeps `desired_cluster_role` for the
    # supervisor's automatic retry window (the heartbeat path above), and an
    # operator who reaches for Replace during that window is overriding the
    # retry on purpose — refusing them because a retry is pending is exactly
    # the contradiction this route exists to remove (live 2026-09-04
    # 01:34Z: a blocked join, desired-state kept, Replace answered 409).
    # The fields are cleared just below, which also ends the retry.
    failed_joiner = row.cluster_role is None and row.cluster_join_state == CLUSTER_JOIN_STATE_FAILED
    if row.cluster_role != CLUSTER_ROLE_MEMBER and not failed_joiner:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Appliance {row.hostname!r} isn't a settled control-plane member or a "
            "failed joiner — nothing to evict. (Demote in-flight joiners; this is for "
            "replacing a dead member or clearing a failed join's stale etcd member.)",
        )

    # Drop the dead member from the cluster accounting + flag it for the
    # seed to evict. Keep the hostname (the seed deletes the Node by
    # name); clear the join coordinates + role.
    row.cluster_role = None
    row.desired_cluster_role = None
    row.desired_k3s_server_url = None
    row.desired_k3s_join_token_encrypted = None
    row.cluster_join_state = CLUSTER_JOIN_STATE_EVICTING
    row.cluster_join_state_at = datetime.now(UTC)  # #590 staleness clock
    row.cluster_join_reason = None
    row.evict_requested = True

    # Mint a single-use 60-min pairing code for the replacement box.
    code = _generate_code()
    expires_at = datetime.now(UTC) + timedelta(minutes=60)
    pc_id = uuid.uuid4()
    db.add(
        PairingCode(
            id=pc_id,
            code_hash=_hash_code(code),
            code_last_two=code[-2:],
            persistent=False,
            enabled=True,
            expires_at=expires_at,
            code_encrypted=None,
            note=f"replacement for {row.hostname}",
            created_by_user_id=current_user.id,
        )
    )
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.control_plane_replaced",
            resource_type="appliance",
            resource_id=str(row.id),
            resource_display=row.hostname,
            result="success",
            new_value={
                "pairing_code_id": str(pc_id),
                "pairing_expires_at": expires_at.isoformat(),
            },
        )
    )
    await db.commit()
    await db.refresh(row)
    logger.info(
        "control_plane_replace",
        appliance_id=str(row.id),
        hostname=row.hostname,
        user=current_user.username,
    )
    return ControlPlaneReplaceResponse(
        evicted=_row_to_schema(row),
        pairing_code=code,
        pairing_expires_at=expires_at,
    )


# #590 — how long a cluster transition may sit before the escape hatch will
# clear it without ``force``. A k3s server join on a loaded 3-node cluster is
# minutes, not seconds (the host runner's own wait_ready caps at 180s, and a
# promote also waits on the trigger-file pickup + a full k3s restart), so the
# threshold has to be comfortably above the healthy worst case.
_CLUSTER_TRANSITION_STUCK_AFTER = timedelta(minutes=10)


class ClearClusterStateRequest(BaseModel):
    """Body for the clear-cluster-state escape hatch (#590)."""

    force: bool = Field(
        default=False,
        description=(
            "Clear even a transition younger than the staleness threshold. "
            "Only set this when the node is known to be gone for good — "
            "clearing a running join strands it as an unaccounted member."
        ),
    )


@router.post(
    "/fleet/control-plane/{appliance_id}/clear-cluster-state",
    response_model=ApplianceRow,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Clear a stuck cluster transition on an appliance row (superadmin)",
)
async def clear_control_plane_state(
    appliance_id: uuid.UUID,
    current_user: CurrentUser,
    db: DB,
    body: ClearClusterStateRequest | None = None,
) -> ApplianceRow:
    """Operator escape hatch for a wedged promote / demote / eviction (#590).

    Every cluster transition converges on a supervisor report: a promote
    settles when the joiner reports ``ready``, a demote when it reports
    ``left``, an eviction when the SEED reports the k8s Node deleted. None
    of those has a timeout, so a transition whose reporter never comes back
    — a node that died mid-join, a seed that can't reach the kubeapi, a
    supervisor that will never run again — leaves the row pinned in
    ``joining`` / ``leaving`` / ``evicting`` forever with no way out. That
    is precisely how a dead-node replace stranded a cluster at 2/3 for 50+
    minutes.

    This clears the *bookkeeping* only. It does not touch the node, k3s, or
    etcd: ``cluster_role`` (what the row IS) is left alone, while the
    desired-state, the in-flight join coordinates, and the evict flag (what
    we were trying to make it BE) are dropped. Use it to unstick the row,
    then re-drive the real operation — or delete the appliance outright if
    the node is gone for good.

    A k3s join legitimately takes minutes, so clearing a transition younger
    than ``_CLUSTER_TRANSITION_STUCK_AFTER`` is refused unless ``force`` is
    set: blanking the desired-state out from under a RUNNING join would let
    the joiner come up as a live control-plane member that this row — and
    therefore cp-size scaling, MetalLB and quorum math — accounts for as
    nothing. (The reported-``ready`` settle is self-healing for exactly that
    case, but the operator shouldn't have to rely on it.)
    """
    _require_superadmin(current_user)

    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Appliance {appliance_id} not found.")

    before = {
        "cluster_join_state": row.cluster_join_state,
        "cluster_join_reason": row.cluster_join_reason,
        "desired_cluster_role": row.desired_cluster_role,
        "evict_requested": row.evict_requested,
    }
    # Only in-flight bookkeeping is clearable. A settled row (``ready`` /
    # ``left`` / ``failed`` with nothing pending) has nothing stuck, and
    # blanking its state would just destroy the operator's audit trail of
    # how it got there. Read the pre-image so the guard and the audit row
    # can never disagree about what "in flight" meant.
    in_flight = (
        before["cluster_join_state"] not in (None, *CLUSTER_JOIN_STATES_TERMINAL)
        or before["desired_cluster_role"] is not None
        or bool(before["evict_requested"])
    )
    if not in_flight:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Appliance {row.hostname!r} has no in-flight cluster transition to clear "
            f"(cluster_join_state={row.cluster_join_state!r}).",
        )

    force = bool(body.force) if body is not None else False
    started_at = row.cluster_join_state_at
    if not force and started_at is not None:
        age = datetime.now(UTC) - started_at
        if age < _CLUSTER_TRANSITION_STUCK_AFTER:
            remaining = int((_CLUSTER_TRANSITION_STUCK_AFTER - age).total_seconds())
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"Appliance {row.hostname!r} entered {row.cluster_join_state!r} only "
                f"{int(age.total_seconds())}s ago — a k3s join legitimately takes minutes. "
                f"Wait {remaining}s for it to converge, or re-send with force=true if you "
                "know the node is never coming back.",
            )

    row.cluster_join_state = None
    row.cluster_join_state_at = None
    row.cluster_join_reason = None
    row.desired_cluster_role = None
    row.desired_k3s_server_url = None
    row.desired_k3s_join_token_encrypted = None
    row.evict_requested = False

    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.control_plane_state_cleared",
            resource_type="appliance",
            resource_id=str(row.id),
            resource_display=row.hostname,
            result="success",
            old_value=before,
            new_value={"cluster_role": row.cluster_role, "forced": force},
        )
    )
    await db.commit()
    await db.refresh(row)
    logger.warning(
        "control_plane_state_cleared",
        appliance_id=str(row.id),
        hostname=row.hostname,
        cleared=before,
        user=current_user.username,
    )
    return _row_to_schema(row)


# ── Admin: etcd snapshot list + guided restore (#272 Phase 9b) ───────


class EtcdSnapshotRow(BaseModel):
    """One recoverable etcd snapshot, mapped from a k3s
    ``ETCDSnapshotFile`` CR. All fields tolerant of a partial wire shape
    (a future k3s schema change shouldn't 500 the panel)."""

    name: str = ""
    location: str = ""
    node_name: str = ""
    size: int | None = None
    created_at: str | None = None


class EtcdSnapshotsResponse(BaseModel):
    """Cluster etcd snapshot inventory + in-flight restore state.

    ``available`` is False on a docker / k8s control plane (no appliance
    seed row) — the Fleet panel then shows a "not an appliance" note
    instead of an empty table that reads as broken.
    """

    available: bool = False
    seed_id: uuid.UUID | None = None
    seed_hostname: str | None = None
    reported_at: datetime | None = None
    snapshots: list[EtcdSnapshotRow] = Field(default_factory=list)
    # In-flight guided restore (#272 Phase 9b).
    desired_restore_snapshot: str | None = None
    restore_state: str | None = None
    restore_reason: str | None = None


class ClusterRestoreRequest(BaseModel):
    """POST body for a guided etcd restore. ``confirm_hostname`` must
    match the seed's hostname exactly — a typed-confirmation guardrail
    on top of the superadmin gate, because the restore is a single-node
    cluster-reset (every other control-plane node is orphaned)."""

    snapshot_name: str
    confirm_hostname: str


async def _find_seed_row(db: DB) -> Appliance | None:
    """Resolve the etcd seed appliance row — the control-plane node that
    holds the snapshots + drives a guided restore.

    Multi-node: the row with ``cluster_role == 'primary'``. Single-node
    (pre-promote, cluster_role still NULL): the lone control-plane-variant
    appliance. None on a docker / k8s control plane (no appliance rows)."""
    primary = (
        (
            await db.execute(
                select(Appliance).where(
                    Appliance.state == APPLIANCE_STATE_APPROVED,
                    Appliance.cluster_role == CLUSTER_ROLE_PRIMARY,
                )
            )
        )
        .scalars()
        .first()
    )
    if primary is not None:
        return primary
    return (
        (
            await db.execute(
                select(Appliance)
                .where(
                    Appliance.state == APPLIANCE_STATE_APPROVED,
                    Appliance.appliance_variant.in_(tuple(_SELF_BOOTSTRAP_VARIANTS)),
                    Appliance.last_seen_at.is_not(None),
                )
                .order_by(Appliance.created_at.asc())
            )
        )
        .scalars()
        .first()
    )


def _etcd_snapshots_response(seed: Appliance | None) -> EtcdSnapshotsResponse:
    if seed is None:
        return EtcdSnapshotsResponse(available=False)
    rows: list[EtcdSnapshotRow] = []
    for s in seed.etcd_snapshots or []:
        if isinstance(s, dict):
            rows.append(EtcdSnapshotRow(**s))
    return EtcdSnapshotsResponse(
        available=True,
        seed_id=seed.id,
        seed_hostname=seed.hostname,
        reported_at=seed.last_seen_at,
        snapshots=rows,
        desired_restore_snapshot=seed.desired_restore_snapshot,
        restore_state=seed.restore_state,
        restore_reason=seed.restore_reason,
    )


@router.get(
    "/fleet/control-plane/etcd-snapshots",
    response_model=EtcdSnapshotsResponse,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="List recoverable etcd snapshots from the cluster seed (superadmin)",
)
async def list_etcd_snapshots(
    current_user: CurrentUser,
    db: DB,
) -> EtcdSnapshotsResponse:
    """Read the seed's reported ``k3s etcd-snapshot list`` + any in-flight
    restore state. Read-only — the seed reports its local snapshots on
    every heartbeat, so this is just the last-reported inventory."""
    _require_superadmin(current_user)
    return _etcd_snapshots_response(await _find_seed_row(db))


@router.post(
    "/fleet/control-plane/restore",
    response_model=EtcdSnapshotsResponse,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Guided etcd restore — stamp the seed to cluster-reset-restore (superadmin)",
)
async def restore_etcd_snapshot(
    body: ClusterRestoreRequest,
    current_user: CurrentUser,
    db: DB,
) -> EtcdSnapshotsResponse:
    """Stamp the seed row to perform a guided etcd restore.

    ⚠️ DESTRUCTIVE — single-node cluster-reset. The seed supervisor reads
    ``desired_restore_snapshot`` on its next heartbeat and fires the
    host-side ``spatium-cluster-restore`` trigger (guarded by a confirm
    marker): k3s stops, resets etcd to a 1-member cluster from the
    snapshot, and restarts. Every OTHER control-plane node is orphaned
    and must be re-paired (Replace flow). Disaster recovery only.

    Guardrails: superadmin + the snapshot must exist in the seed's
    last-reported inventory + ``confirm_hostname`` must match the seed's
    hostname exactly. Refuses a second restore while one is in flight."""
    _require_superadmin(current_user)
    seed = await _find_seed_row(db)
    if seed is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "No appliance control-plane seed found — etcd restore is appliance-only "
            "(a docker / k8s control plane manages its own database).",
        )
    if (body.confirm_hostname or "").strip() != (seed.hostname or ""):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Type the seed hostname ({seed.hostname!r}) exactly to confirm this "
            "destructive cluster-reset restore.",
        )
    known = {
        s.get("name") for s in (seed.etcd_snapshots or []) if isinstance(s, dict) and s.get("name")
    }
    if body.snapshot_name not in known:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Snapshot {body.snapshot_name!r} is not in the seed's reported inventory.",
        )
    if seed.desired_restore_snapshot is not None and seed.restore_state != "failed":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"A restore is already in flight ({seed.desired_restore_snapshot!r}, "
            f"state={seed.restore_state or 'pending'}). Wait for it to settle.",
        )
    seed.desired_restore_snapshot = body.snapshot_name
    seed.restore_state = None
    seed.restore_reason = None
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.control_plane_etcd_restore_requested",
            resource_type="appliance",
            resource_id=str(seed.id),
            resource_display=seed.hostname,
            result="success",
            new_value={"snapshot_name": body.snapshot_name},
        )
    )
    await db.commit()
    await db.refresh(seed)
    logger.warning(
        "control_plane_etcd_restore_requested",
        appliance_id=str(seed.id),
        hostname=seed.hostname,
        snapshot=body.snapshot_name,
        user=current_user.username,
    )
    return _etcd_snapshots_response(seed)


# ── Admin: MetalLB control-plane VIP (#272 Phase 7c) ─────────────


def _parse_pool_entry(raw: str) -> tuple[int, int, int]:
    """Normalise one MetalLB pool entry to ``(version, first_int, last_int)``.

    Accepts a CIDR (``192.0.2.0/28``), a hyphen range
    (``192.0.2.10-192.0.2.20``), or a single host (``192.0.2.5``).
    Raises ``ValueError`` on anything malformed (so the field
    validator can surface a 422 with the offending entry).
    """
    s = raw.strip()
    if "-" in s and "/" not in s:
        lo_s, _, hi_s = s.partition("-")
        lo = ipaddress.ip_address(lo_s.strip())
        hi = ipaddress.ip_address(hi_s.strip())
        if lo.version != hi.version:
            raise ValueError(f"range {raw!r} mixes IPv4 and IPv6")
        if int(lo) > int(hi):
            raise ValueError(f"range {raw!r} is reversed (start > end)")
        return (lo.version, int(lo), int(hi))
    if "/" in s:
        net = ipaddress.ip_network(s, strict=False)
        return (net.version, int(net.network_address), int(net.broadcast_address))
    host = ipaddress.ip_address(s)
    return (host.version, int(host), int(host))


def _vip_in_pool(vip: str, pool: list[str]) -> bool:
    """True when ``vip`` falls inside any entry of ``pool``."""
    addr = ipaddress.ip_address(vip.strip())
    for entry in pool:
        try:
            version, lo, hi = _parse_pool_entry(entry)
        except ValueError:
            continue
        if version == addr.version and lo <= int(addr) <= hi:
            return True
    return False


# issue #566 decision D1 — BGP mode. ``_ASN_MIN``/``_ASN_MAX`` mirror
# ``looking_glass/schemas.py``'s local copy (kept separate rather than
# imported — zero code coupling between the two BGP surfaces per
# docs/features/LOOKING_GLASS.md's "share only the UI concept" framing).
_ASN_MIN, _ASN_MAX = 1, 4_294_967_295


class MetalLBBgpPeer(BaseModel):
    """One BGPPeer CR — a router SpatiumDDI advertises the VIP to."""

    my_asn: int
    peer_asn: int
    peer_address: str
    peer_port: int | None = None
    hold_time: str | None = None  # e.g. "90s" — passed through verbatim to the CR

    @field_validator("my_asn", "peer_asn")
    @classmethod
    def _v_asn(cls, v: int) -> int:
        if not (_ASN_MIN <= v <= _ASN_MAX):
            raise ValueError(f"AS number must be between {_ASN_MIN} and {_ASN_MAX}")
        return v

    @field_validator("peer_address")
    @classmethod
    def _v_addr(cls, v: str) -> str:
        ipaddress.ip_address(v.strip())  # raises ValueError -> 422
        return v.strip()


class MetalLBBgpAdvertisement(BaseModel):
    """One BGPAdvertisement CR — the pool(s)/attributes advertised."""

    ip_address_pools: list[str] = Field(default_factory=lambda: ["spatium-control-plane"])
    communities: list[str] = Field(default_factory=list)
    aggregation_length: int | None = None


class MetalLBConfigResponse(BaseModel):
    """Cluster-wide MetalLB / control-plane-VIP config + live status."""

    enabled: bool = False
    pool_addresses: list[str] = Field(default_factory=list)
    control_plane_vip: str = ""
    # #272 Phase 10 — data-plane resolver VIPs (same pool). Empty = the
    # hostNetwork data plane (no VIP). ``dns_vip`` fronts bind9/powerdns
    # :53; ``dhcp_relay_vip`` fronts the Kea relay→server :67 forward.
    dns_vip: str = ""
    dhcp_relay_vip: str = ""
    # issue #566 decision D1 — BGP mode (export path: advertise the VIP
    # to upstream routers). Layered on top of the same MetalLB install;
    # requires ``enabled=True``.
    bgp_enabled: bool = False
    bgp_peers: list[MetalLBBgpPeer] = Field(default_factory=list)
    bgp_advertisements: list[MetalLBBgpAdvertisement] = Field(default_factory=list)
    # #272 — live readiness, best-effort from the spatium-namespace pod
    # list (reuses the api's existing pod-read RBAC). All zero/false when
    # kubeapi is unreachable (docker/k8s control plane) or MetalLB is off.
    controller_ready: bool = False
    speakers_ready: int = 0
    speakers_total: int = 0


def _metallb_pod_status() -> tuple[bool, int, int]:
    """Return ``(controller_ready, speakers_ready, speakers_total)`` from
    the live MetalLB pods in the metallb-system namespace.

    Best-effort: degrades to ``(False, 0, 0)`` on any error (no
    ServiceAccount on a docker/k8s control plane, a kubeapi blip, or
    MetalLB simply disabled so no pods exist). MetalLB moved to its own
    metallb-system namespace (#286), so this needs the api SA's
    cross-namespace pod-read Role there — provided by the
    spatiumddi-metallb chart's api-reader-rbac.yaml, not the appliance
    chart. Without that grant the read 403s and status shows "starting".
    """
    from app.services.appliance import k8s  # noqa: PLC0415

    def _ready(pod: dict[str, Any]) -> bool:
        conds = (pod.get("status") or {}).get("conditions") or []
        return any(c.get("type") == "Ready" and c.get("status") == "True" for c in conds)

    try:
        # #272 / #286 — MetalLB lives in its own metallb-system namespace
        # now, not spatium. Best-effort: needs the api SA's metallb-system
        # pod-read Role (spatiumddi-metallb chart's api-reader-rbac.yaml);
        # degrades to (False,0,0) if the grant isn't present (status just
        # shows "starting").
        pods = k8s.list_pods("metallb-system")
    except Exception:  # noqa: BLE001
        return (False, 0, 0)
    controller_ready = False
    speakers_ready = 0
    speakers_total = 0
    for pod in pods:
        name = ((pod.get("metadata") or {}).get("name")) or ""
        if "metallb-controller" in name:
            controller_ready = controller_ready or _ready(pod)
        elif "metallb-speaker" in name:
            speakers_total += 1
            if _ready(pod):
                speakers_ready += 1
    return (controller_ready, speakers_ready, speakers_total)


def _metallb_response(row: PlatformSettings) -> MetalLBConfigResponse:
    controller_ready, speakers_ready, speakers_total = _metallb_pod_status()
    return MetalLBConfigResponse(
        enabled=row.metallb_enabled,
        pool_addresses=list(row.metallb_pool_addresses or []),
        control_plane_vip=row.control_plane_vip or "",
        dns_vip=row.dns_vip or "",
        dhcp_relay_vip=row.dhcp_relay_vip or "",
        bgp_enabled=row.metallb_bgp_enabled,
        bgp_peers=row.metallb_bgp_peers or [],
        bgp_advertisements=row.metallb_bgp_advertisements or [],
        controller_ready=controller_ready,
        speakers_ready=speakers_ready,
        speakers_total=speakers_total,
    )


class MetalLBConfigUpdate(BaseModel):
    """PUT body for the MetalLB / control-plane-VIP config.

    All-or-nothing replace (not a partial merge) — the Fleet card
    always submits the full state. Validators canonicalise pool
    entries + enforce the VIP-in-pool / enabled-needs-pool invariants
    so a half-configured state can never reach the chart.
    """

    enabled: bool = False
    pool_addresses: list[str] = Field(default_factory=list)
    control_plane_vip: str = ""
    # #272 Phase 10 — data-plane resolver VIPs (optional; same pool).
    dns_vip: str = ""
    dhcp_relay_vip: str = ""
    # issue #566 decision D1 — BGP mode (optional; export path).
    bgp_enabled: bool = False
    bgp_peers: list[MetalLBBgpPeer] = Field(default_factory=list)
    bgp_advertisements: list[MetalLBBgpAdvertisement] = Field(default_factory=list)

    @field_validator("pool_addresses")
    @classmethod
    def _valid_pool(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for raw in v:
            s = raw.strip()
            if not s:
                continue
            try:
                _parse_pool_entry(s)
            except ValueError as exc:
                raise ValueError(f"invalid pool entry {raw!r}: {exc}") from exc
            out.append(s)
        return out

    @field_validator("control_plane_vip", "dns_vip", "dhcp_relay_vip")
    @classmethod
    def _valid_vip(cls, v: str, info: ValidationInfo) -> str:
        s = v.strip()
        if not s:
            return ""
        try:
            ipaddress.ip_address(s)
        except ValueError as exc:
            raise ValueError(f"{info.field_name} must be a single IP: {exc}") from exc
        return s

    @model_validator(mode="after")
    def _cross_field(self) -> MetalLBConfigUpdate:
        if self.enabled:
            if not self.control_plane_vip:
                raise ValueError("a control-plane VIP is required when MetalLB is enabled")
            # #272 — auto-derive a single-address pool from the VIP when
            # no explicit pool is given. This is the common case: the
            # operator just wants one floating IP for the Web UI and
            # shouldn't have to hand-craft a MetalLB pool + keep it in
            # sync with the VIP. A /32 (v4) or /128 (v6) pool holding
            # exactly the VIP is all MetalLB needs. Operators who want a
            # range (headroom, future data-plane VIPs, BGP) can still
            # supply one explicitly, and the VIP-in-pool check below
            # applies to it.
            if not self.pool_addresses:
                prefix = 32 if ipaddress.ip_address(self.control_plane_vip).version == 4 else 128
                self.pool_addresses = [f"{self.control_plane_vip}/{prefix}"]
        # #272 Phase 10 — data-plane VIPs require MetalLB on (no VIP path
        # exists without it) and can't reuse the control-plane VIP or each
        # other — MetalLB hands a given address to exactly one Service, so
        # two services sharing one VIP would leave one perpetually Pending.
        dp_vips = {
            "DNS resolver VIP": self.dns_vip,
            "DHCP relay VIP": self.dhcp_relay_vip,
        }
        for label, vip in dp_vips.items():
            if vip and not self.enabled:
                raise ValueError(f"{label} requires MetalLB to be enabled")
        if self.dns_vip and self.dns_vip == self.control_plane_vip:
            raise ValueError("DNS resolver VIP must differ from the control-plane VIP")
        if self.dhcp_relay_vip and self.dhcp_relay_vip == self.control_plane_vip:
            raise ValueError("DHCP relay VIP must differ from the control-plane VIP")
        if self.dns_vip and self.dns_vip == self.dhcp_relay_vip:
            raise ValueError("DNS resolver VIP and DHCP relay VIP must differ")
        # Every configured VIP must fall inside the pool.
        for label, vip in {
            "control-plane VIP": self.control_plane_vip,
            **dp_vips,
        }.items():
            if vip and self.pool_addresses and not _vip_in_pool(vip, self.pool_addresses):
                raise ValueError(
                    f"{label} {vip} is not inside the address pool "
                    "(widen metallb_pool_addresses to include every VIP)"
                )
        # issue #566 decision D1 — BGP mode. An "export" path layered on
        # top of the same MetalLB install: requires MetalLB itself on +
        # at least one peer, since there's nothing to advertise-to
        # otherwise. Activates the GPL-v2 FRRouting image via MetalLB's
        # frr-k8s backend once applied — see NOTICE.
        if self.bgp_enabled:
            if not self.enabled:
                raise ValueError("BGP mode requires MetalLB to be enabled")
            if not self.bgp_peers:
                raise ValueError("at least one BGP peer is required when bgp_enabled")
            if not self.bgp_advertisements:
                # Auto-derive the same "advertise the control-plane VIP
                # pool" default the plain-VIP path already assumes, so a
                # v1 operator only has to type peer info — mirrors the
                # auto-derived /32 pool convenience above.
                self.bgp_advertisements = [
                    MetalLBBgpAdvertisement(ip_address_pools=["spatium-control-plane"])
                ]
        return self


async def _get_or_create_settings(db: DB) -> PlatformSettings:
    row = (
        await db.execute(select(PlatformSettings).where(PlatformSettings.id == 1))
    ).scalar_one_or_none()
    if row is None:
        row = PlatformSettings(id=1)
        db.add(row)
        await db.flush()
    return row


@router.get(
    "/fleet/control-plane/metallb",
    response_model=MetalLBConfigResponse,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Read the cluster MetalLB / control-plane-VIP config (superadmin)",
)
async def get_metallb_config(
    current_user: CurrentUser,
    db: DB,
) -> MetalLBConfigResponse:
    _require_superadmin(current_user)
    row = await _get_or_create_settings(db)
    return _metallb_response(row)


@router.put(
    "/fleet/control-plane/metallb",
    response_model=MetalLBConfigResponse,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Set the cluster MetalLB / control-plane-VIP config (superadmin)",
)
async def put_metallb_config(
    body: MetalLBConfigUpdate,
    current_user: CurrentUser,
    db: DB,
) -> MetalLBConfigResponse:
    """Persist the cluster-wide MetalLB pool + control-plane VIP.

    Validated all-or-nothing (VIP must fall inside the pool; enabling
    requires both). The seed supervisor picks the new values up on its
    next heartbeat (``desired_metallb_*`` in the response) and patches
    the spatium-bootstrap + spatium-control HelmCharts; helm-controller
    then renders the IPAddressPool / L2Advertisement + flips the
    frontend Service to a LoadBalancer on the VIP. Idempotent.
    """
    _require_superadmin(current_user)
    row = await _get_or_create_settings(db)
    old = {
        "enabled": row.metallb_enabled,
        "pool_addresses": list(row.metallb_pool_addresses or []),
        "control_plane_vip": row.control_plane_vip or "",
        "dns_vip": row.dns_vip or "",
        "dhcp_relay_vip": row.dhcp_relay_vip or "",
        "bgp_enabled": row.metallb_bgp_enabled,
        "bgp_peers": list(row.metallb_bgp_peers or []),
        "bgp_advertisements": list(row.metallb_bgp_advertisements or []),
    }
    row.metallb_enabled = body.enabled
    row.metallb_pool_addresses = body.pool_addresses
    row.control_plane_vip = body.control_plane_vip
    row.dns_vip = body.dns_vip
    row.dhcp_relay_vip = body.dhcp_relay_vip
    row.metallb_bgp_enabled = body.bgp_enabled
    row.metallb_bgp_peers = [p.model_dump() for p in body.bgp_peers]
    row.metallb_bgp_advertisements = [a.model_dump() for a in body.bgp_advertisements]
    new = {
        "enabled": body.enabled,
        "pool_addresses": body.pool_addresses,
        "control_plane_vip": body.control_plane_vip,
        "dns_vip": body.dns_vip,
        "dhcp_relay_vip": body.dhcp_relay_vip,
        "bgp_enabled": body.bgp_enabled,
        "bgp_peers": row.metallb_bgp_peers,
        "bgp_advertisements": row.metallb_bgp_advertisements,
    }
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.metallb_config_updated",
            resource_type="platform_settings",
            resource_id="1",
            resource_display="MetalLB control-plane VIP",
            result="success",
            old_value=old,
            new_value=new,
        )
    )
    await db.commit()
    logger.info(
        "metallb_config_updated",
        enabled=body.enabled,
        pool=body.pool_addresses,
        vip=body.control_plane_vip,
        user=current_user.username,
    )
    return _metallb_response(row)


# ── Admin: OS upgrade + reboot (#170 Wave D1) ────────────────────


class ApplianceUpgradeRequest(BaseModel):
    """Stamp the operator's target OS version on an appliance row.

    The supervisor's heartbeat picks this up + writes the
    slot-upgrade trigger on the host. The trigger file's presence
    is the marker the host's systemd ``.path`` unit watches to fire
    ``spatium-upgrade-slot apply``. Idempotent — the supervisor
    skips firing when the trigger already exists or installed
    matches desired.

    Two source modes for the image:

    * **External URL** — pass ``desired_slot_image_url`` directly.
      Used when the appliance can reach github.com or a private
      mirror. The supervisor downloads via the URL on the host.
    * **Uploaded image** — pass ``slot_image_id`` (an
      ``appliance_slot_image`` row id from the air-gap upload
      endpoint). The control plane composes the authenticated
      internal URL the supervisor pulls from. Air-gap-friendly.

    Exactly one of the two must be supplied. The version label is
    always required so the auto-clear logic can detect "installed
    matches desired" without inspecting the binary.
    """

    desired_appliance_version: str = Field(min_length=1, max_length=64)
    desired_slot_image_url: str | None = Field(default=None, min_length=1)
    slot_image_id: uuid.UUID | None = Field(default=None)


@router.post(
    "/appliances/{appliance_id}/upgrade",
    response_model=ApplianceRow,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Schedule an OS slot upgrade on an Application appliance",
)
async def schedule_appliance_upgrade(
    appliance_id: uuid.UUID,
    body: ApplianceUpgradeRequest,
    request: Request,
    current_user: CurrentUser,
    db: DB,
) -> ApplianceRow:
    """Stamps ``desired_appliance_version`` + ``desired_slot_image_url``
    on the appliance row. The supervisor's next heartbeat picks them up
    and fires the slot-upgrade trigger; the host runner downloads + dd's
    the raw.xz to the inactive slot + reboots into it. Per-row reboot is
    optional — operators who want to defer can clear desired_* via
    ``/clear-upgrade`` before the supervisor's next heartbeat.

    For air-gapped fleets, pass ``slot_image_id`` (an
    ``appliance_slot_image`` row from the upload endpoint) instead of
    ``desired_slot_image_url``. The control plane composes the
    authenticated internal URL the supervisor pulls from."""
    _require_superadmin(current_user)
    if (body.desired_slot_image_url is None) == (body.slot_image_id is None):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Pass exactly one of desired_slot_image_url or slot_image_id.",
        )
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    if row.state != APPLIANCE_STATE_APPROVED:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Cannot schedule upgrade on appliance in state {row.state!r}.",
        )
    if row.deployment_kind not in (None, "appliance"):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            (
                f"Appliance reports deployment_kind={row.deployment_kind!r}; "
                "OS slot upgrades are only available on the SpatiumDDI "
                "appliance OS. Use the manual docker / helm upgrade flow "
                "for docker / k8s deployments."
            ),
        )

    # Resolve slot_image_id → internal URL + integrity/transport hints,
    # then stamp all four desired-state columns. Both live in
    # ``services.appliance.slot_image_target`` so this surface and the
    # multi-node rolling orchestrator cannot drift apart on what the host
    # is told to fetch (#787) — the drift that re-introduced #386 there.
    #
    # The URL is composed against ``request.base_url``: the operator-facing
    # scheme + host the frontend reached us on (X-Forwarded-Host / -Proto
    # when nginx is in front), which is necessarily reachable from the
    # appliance subnet because that is where the supervisor already
    # heartbeats.
    try:
        target = await resolve_slot_image_target(
            db,
            base_url=str(request.base_url),
            slot_image_id=body.slot_image_id,
            slot_image_url=body.desired_slot_image_url,
        )
        # A fresh nonce per click: re-applying the SAME image from the Fleet
        # button is an explicit retry and must re-fire the host trigger.
        target = replace(target, nonce=new_refire_nonce())
        # #1026 — INSIDE the try. The architecture refusal is raised by
        # ``stamp``, not by ``resolve``: resolve knows the image, stamp is
        # the first place that also knows the node. Left outside, the
        # mismatch escaped as a 500 while every surface — the design, the
        # docs and the Fleet picker's own comment — promised a 422 naming
        # both architectures.
        stamp_desired_slot_image(row, target, desired_version=body.desired_appliance_version)
    except SlotImageResolutionError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    resolved_url = row.desired_slot_image_url or target.url
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.upgrade_scheduled",
            resource_type="appliance",
            resource_id=str(row.id),
            resource_display=row.hostname,
            result="success",
            new_value={
                "desired_appliance_version": body.desired_appliance_version,
                "desired_slot_image_url": resolved_url,
                "slot_image_id": (str(body.slot_image_id) if body.slot_image_id else None),
            },
        )
    )
    await db.commit()
    logger.info(
        "appliance_upgrade_scheduled",
        appliance_id=str(row.id),
        hostname=row.hostname,
        desired_version=body.desired_appliance_version,
        user=current_user.username,
    )
    # #358 Phase 1 — wake the supervisor heartbeat long-poll so the upgrade
    # trigger fires in ~0 s instead of waiting for the next heartbeat.
    await publish_wake(appliance_channel(row.id))
    return _row_to_schema(row)


@router.post(
    "/appliances/{appliance_id}/clear-upgrade",
    response_model=ApplianceRow,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Clear a pending OS upgrade stamp",
)
async def clear_appliance_upgrade(
    appliance_id: uuid.UUID, current_user: CurrentUser, db: DB
) -> ApplianceRow:
    """Cancel a pending upgrade and dismiss a failed one.

    Clears the desired slot-image state AND the ``last_upgrade_*`` columns
    the Fleet failure card renders from, then raises a one-shot host
    command (``clear_upgrade_requested``) that makes the supervisor reset
    its own sidecars and drop a stranded ``slot-upgrade-pending`` trigger.

    Clearing our copy alone is not enough: the host re-publishes those
    columns verbatim on every heartbeat, so without the command the next
    heartbeat restores the failure — and rebooting does not help, because
    those sidecars live on the persistent /var (#786).
    """
    _require_superadmin(current_user)
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    # Raising a host command on a row that can never consume it would strand
    # the flag set — which permanently suppresses that appliance's heartbeat
    # long-poll. Same gate the other host-command mutators apply.
    _check_appliance_slot_action_allowed(row)
    row.desired_appliance_version = None
    row.desired_slot_image_url = None
    row.desired_slot_image_sha256 = None
    row.desired_slot_image_tls_insecure = False
    # #786 — clearing the desired state alone left the appliance sitting in
    # the red "Upgrade failed" card forever. That card renders from the
    # ``last_upgrade_*`` columns, which the heartbeat re-publishes verbatim
    # from host sidecars every ~30 s, so the host has to be told to forget
    # too. Clear our copy for an immediate UI response AND raise the
    # command that makes the host reset its own state; without the second
    # half the next heartbeat simply restores what we just cleared.
    row.last_upgrade_state = None
    row.last_upgrade_state_at = None
    row.last_upgrade_progress = None
    row.last_upgrade_log_tail = None
    row.clear_upgrade_requested = True
    row.clear_upgrade_requested_at = datetime.now(UTC)
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.upgrade_cleared",
            resource_type="appliance",
            resource_id=str(row.id),
            resource_display=row.hostname,
            result="success",
        )
    )
    await db.commit()
    # #358 Phase 1 — wake so a mistaken upgrade is dropped promptly.
    await publish_wake(appliance_channel(row.id))
    return _row_to_schema(row)


class ApplianceSlotActionRequest(BaseModel):
    """Pick which A/B slot the operator wants to act on.

    Used by both ``/set-next-boot`` (one-shot, ``grub-reboot``) and
    ``/set-default-slot`` (durable, ``grub-set-default``). The
    supervisor's next heartbeat picks the desired field up and writes
    the matching trigger file the host runner watches.
    """

    slot: Literal["slot_a", "slot_b"]


def _check_appliance_slot_action_allowed(row: Appliance) -> None:
    """Shared guards for both ``/set-next-boot`` + ``/set-default-slot``.

    A slot action only makes sense on an approved appliance host: a
    docker / k8s row has no A/B partition layout, and a pending /
    revoked / rejected row is offline to the supervisor heartbeat
    cycle that delivers the intent.
    """
    if row.state != APPLIANCE_STATE_APPROVED:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Cannot change boot slot on appliance in state {row.state!r}.",
        )
    if row.deployment_kind not in (None, "appliance"):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            (
                f"Appliance reports deployment_kind={row.deployment_kind!r}; "
                "A/B slot operations are only available on the SpatiumDDI "
                "appliance OS."
            ),
        )


@router.post(
    "/appliances/{appliance_id}/set-next-boot",
    response_model=ApplianceRow,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Boot a specific A/B slot on the next reboot (one-shot)",
)
async def schedule_appliance_set_next_boot(
    appliance_id: uuid.UUID,
    body: ApplianceSlotActionRequest,
    current_user: CurrentUser,
    db: DB,
) -> ApplianceRow:
    """Stamps ``desired_next_boot_slot`` on the appliance row. The
    supervisor's heartbeat picks it up + writes the
    ``slot-set-next-boot-pending`` trigger; the host runner invokes
    ``spatium-upgrade-slot set-next-boot <slot>`` (``grub-reboot``).

    Semantics: one-shot. The slot is set for exactly the next boot.
    If the operator doesn't commit (via ``/set-default-slot``) before
    the boot AFTER that, grub auto-reverts to the previous durable
    default — that's the safety net behind trial-boot upgrades.

    The actual reboot is NOT triggered by this call. Operator
    either reboots manually (``/reboot`` endpoint) or waits for the
    next planned reboot window."""
    _require_superadmin(current_user)
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    _check_appliance_slot_action_allowed(row)
    row.desired_next_boot_slot = body.slot
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.set_next_boot_scheduled",
            resource_type="appliance",
            resource_id=str(row.id),
            resource_display=row.hostname,
            result="success",
            new_value={"desired_next_boot_slot": body.slot},
        )
    )
    await db.commit()
    logger.info(
        "appliance_set_next_boot_scheduled",
        appliance_id=str(row.id),
        hostname=row.hostname,
        slot=body.slot,
        user=current_user.username,
    )
    # #358 Phase 1 — wake the supervisor heartbeat so the slot-boot intent
    # is picked up in ~0 s instead of waiting for the next heartbeat.
    await publish_wake(appliance_channel(row.id))
    return _row_to_schema(row)


@router.post(
    "/appliances/{appliance_id}/set-default-slot",
    response_model=ApplianceRow,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Durably set the default A/B boot slot (commit / revert)",
)
async def schedule_appliance_set_default_slot(
    appliance_id: uuid.UUID,
    body: ApplianceSlotActionRequest,
    current_user: CurrentUser,
    db: DB,
) -> ApplianceRow:
    """Stamps ``desired_default_slot`` on the appliance row. The
    supervisor's heartbeat picks it up + writes the
    ``slot-set-default-pending`` trigger; the host runner invokes
    ``spatium-upgrade-slot set-default <slot>``
    (``grub-set-default``).

    Semantics: durable. The grub default flips and survives subsequent
    reboots. Two common uses:

    * **Commit a trial boot** — operator booted the trial slot via
      ``/set-next-boot``, validated it, calls this against the
      currently-running slot to make it durable. (``firstboot.service``
      also does this automatically when ``/health/live`` passes; this
      endpoint exists for the explicit operator-action case.)
    * **Durable revert** — operator wants to go back to the previous
      slot for good (not just one boot). Calls this against the
      previous slot."""
    _require_superadmin(current_user)
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    _check_appliance_slot_action_allowed(row)
    row.desired_default_slot = body.slot
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.set_default_slot_scheduled",
            resource_type="appliance",
            resource_id=str(row.id),
            resource_display=row.hostname,
            result="success",
            new_value={"desired_default_slot": body.slot},
        )
    )
    await db.commit()
    logger.info(
        "appliance_set_default_slot_scheduled",
        appliance_id=str(row.id),
        hostname=row.hostname,
        slot=body.slot,
        user=current_user.username,
    )
    # #358 Phase 1 — wake the supervisor heartbeat so the durable-slot
    # change is picked up in ~0 s instead of waiting for the next heartbeat.
    await publish_wake(appliance_channel(row.id))
    return _row_to_schema(row)


@router.post(
    "/appliances/{appliance_id}/reboot",
    response_model=ApplianceRow,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Stamp a reboot request on an Application appliance",
)
async def schedule_appliance_reboot(
    appliance_id: uuid.UUID, current_user: CurrentUser, db: DB
) -> ApplianceRow:
    """Stamps ``reboot_requested=True``. The supervisor's next
    heartbeat returns this; the supervisor writes the host-side
    ``reboot-pending`` trigger; the host runner ``systemctl reboot``s
    after a 5s grace.

    Strict appliance-only — docker / k8s deployments return 409 since
    there's no host to reboot from the supervisor."""
    _require_superadmin(current_user)
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    if row.state != APPLIANCE_STATE_APPROVED:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Cannot reboot appliance in state {row.state!r}.",
        )
    if row.deployment_kind not in (None, "appliance"):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            (
                f"Appliance reports deployment_kind={row.deployment_kind!r}; "
                "host-level reboot is only available on the SpatiumDDI "
                "appliance OS."
            ),
        )
    row.reboot_requested = True
    row.reboot_requested_at = datetime.now(UTC)
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.reboot_scheduled",
            resource_type="appliance",
            resource_id=str(row.id),
            resource_display=row.hostname,
            result="success",
        )
    )
    await db.commit()
    logger.info(
        "appliance_reboot_scheduled",
        appliance_id=str(row.id),
        hostname=row.hostname,
        user=current_user.username,
    )
    # #358 Phase 1 — wake the supervisor heartbeat long-poll so the reboot
    # starts in ~0 s instead of waiting up to one heartbeat interval.
    await publish_wake(appliance_channel(row.id))
    return _row_to_schema(row)


# ── Issue #183 Phase 4 — kubeapi proxy + restart-deployment action ──


class K8sProxyPollResponse(BaseModel):
    """Long-poll result. ``request_id`` is empty + ``method`` is empty
    when the poll timed out without a request — the supervisor handles
    that as "no work, poll again". Otherwise the supervisor decodes
    ``body_b64`` and POSTs against its local kubeapi."""

    request_id: str
    method: str
    path: str
    headers: dict[str, str]
    body_b64: str


class K8sProxyReplyRequest(BaseModel):
    """Supervisor-sent reply after executing the proxied request
    against the local kubeapi. ``status`` is the kubeapi's HTTP
    status; ``body_b64`` carries the response body verbatim."""

    request_id: str
    status: int
    headers: dict[str, str] = Field(default_factory=dict)
    body_b64: str = ""


async def _require_cert_auth(request: Request, db: DB) -> Appliance:
    """Shared cert-auth gate for the proxy endpoints. Returns the
    authenticated appliance row. Raises 403 on failure — no fallback
    to session-token here since the proxy channel only exists for
    approved appliances with mTLS certs.
    """
    from app.services.appliance.cert_auth import (  # noqa: PLC0415
        CertAuthFailed,
        authenticate_cert,
    )

    try:
        principal = await authenticate_cert(request, db)
    except CertAuthFailed as exc:
        logger.warning("appliance.k8s_proxy.cert_auth_failed", reason=exc.reason)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid appliance client cert.") from exc
    if principal is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Cert headers required for kubeapi proxy.",
        )
    if principal.appliance.state != APPLIANCE_STATE_APPROVED:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"Appliance in state {principal.appliance.state!r}; proxy disabled.",
        )
    return principal.appliance


@router.post(
    "/supervisor/k8s-proxy/poll",
    response_model=K8sProxyPollResponse,
    summary="Long-poll for the next queued kubeapi request",
)
async def k8s_proxy_poll(request: Request, db: DB) -> K8sProxyPollResponse:
    """Supervisor-only endpoint. The supervisor's ``k8s_proxy.py``
    background thread holds an outbound long-poll here; when an
    operator action enqueues a request bound for this appliance, the
    poll returns immediately. Otherwise the request times out after
    30 s and the supervisor re-issues.

    Cert auth required — anonymous callers can't intercept queued
    requests. Cert subject must match an approved appliance row
    (the proxy queue is keyed by appliance_id, so a misbehaving cert
    would only see its own queue anyway).
    """
    from app.services.appliance import k8s_proxy as _proxy  # noqa: PLC0415

    appliance = await _require_cert_auth(request, db)
    queued = await _proxy.pop_request(appliance.id, timeout=30.0)
    if queued is None:
        # No request within the timeout — return an empty shape so
        # the supervisor loop just re-polls. 200 (not 204) so the
        # supervisor doesn't have to special-case "no body".
        return K8sProxyPollResponse(request_id="", method="", path="", headers={}, body_b64="")
    return K8sProxyPollResponse(
        request_id=queued.request_id,
        method=queued.method,
        path=queued.path,
        headers=queued.headers,
        body_b64=queued.body_b64,
    )


@router.post(
    "/supervisor/k8s-proxy/reply/{request_id}",
    summary="Return a kubeapi response to the awaiting operator action",
)
async def k8s_proxy_reply(
    request_id: str,
    body: K8sProxyReplyRequest,
    request: Request,
    db: DB,
) -> dict[str, str]:
    """Supervisor-only endpoint. Once the supervisor has executed the
    proxied request against the local kubeapi, it POSTs the response
    here. The backend's in-memory future map matches the request_id
    + resolves the operator action's pending future.

    Returns 200 either way — late replies (operator already timed
    out + the future was GC'd) are logged + discarded server-side
    so the supervisor's loop stays simple.
    """
    from app.services.appliance import k8s_proxy as _proxy  # noqa: PLC0415

    appliance = await _require_cert_auth(request, db)
    if body.request_id != request_id:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "request_id path/body mismatch",
        )
    response = _proxy.K8sProxyResponse(
        request_id=request_id,
        status=body.status,
        headers=body.headers,
        body_b64=body.body_b64,
    )
    delivered = _proxy.deliver_response(response)
    logger.info(
        "appliance.k8s_proxy.reply",
        appliance_id=str(appliance.id),
        request_id=request_id,
        status=body.status,
        delivered=delivered,
    )
    return {"delivered": "true" if delivered else "stale"}


# ── Agent-perspective network tools (dashboard-and-remote-nettools) ──
#
# Generalizes the k8s-proxy poll/reply pattern above to carry an
# *already-validated* nettool job instead of a raw kubeapi request. The
# control plane enqueues a reachability tool (ping / traceroute / dig /
# port-test / tls-cert) bound for this appliance via
# ``app.services.appliance.agent_cmd``; the supervisor long-polls here,
# runs the tool against its local vantage, and POSTs the structured
# result back. Cert-authed exactly like the k8s-proxy channel.
#
# The supervisor-agent side that consumes these endpoints (the poll
# thread + the local nettool runner) is a separate follow-up; this
# lands only the backend surface.


class NetToolPollResponse(BaseModel):
    """Long-poll result for the supervisor's nettool channel.

    ``request_id`` + ``tool`` are empty when the poll timed out without
    a queued command — the supervisor handles that as "no work, poll
    again". Otherwise the supervisor maps ``tool`` + ``params`` to its
    local nettool runner (re-validating every field) and posts the
    result back via ``/supervisor/nettool/reply/{request_id}``.

    ``params`` is the server-validated structured request — NEVER a raw
    shell string or a pre-joined argv. The supervisor rebuilds the argv
    from these fields with the same allowlist validators the control
    plane uses.
    """

    request_id: str
    tool: str
    params: dict[str, Any] = Field(default_factory=dict)


class NetToolReplyRequest(BaseModel):
    """Supervisor-sent reply after running the dispatched tool locally.

    ``result`` is the JSON body of the matching nettool result model
    (CommandResult / PortTestResult / TlsCertResult). ``error`` is set
    instead when the supervisor couldn't run the tool at all (unknown
    tool / local validation failure) so the control plane surfaces a
    clean message rather than a malformed body.
    """

    request_id: str
    result: dict[str, Any] | None = None
    error: str | None = None


@router.post(
    "/supervisor/nettool/poll",
    response_model=NetToolPollResponse,
    summary="Long-poll for the next queued network-tool command",
)
async def nettool_poll(request: Request, db: DB) -> NetToolPollResponse:
    """Supervisor-only endpoint. The supervisor's nettool poll thread
    holds an outbound long-poll here; when an operator dispatches a
    reachability tool bound for this appliance, the poll returns
    immediately. Otherwise it times out after 30 s and the supervisor
    re-issues.

    Cert auth required — anonymous callers can't intercept queued
    commands. The queue is keyed by appliance_id, so a misbehaving cert
    only ever sees its own queue.
    """
    from app.services.appliance import agent_cmd as _cmd  # noqa: PLC0415

    appliance = await _require_cert_auth(request, db)
    queued = await _cmd.pop_command(appliance.id, timeout=30.0)
    if queued is None:
        # No command within the timeout — empty shape so the supervisor
        # loop just re-polls. 200 (not 204) so the supervisor doesn't
        # special-case "no body".
        return NetToolPollResponse(request_id="", tool="", params={})
    return NetToolPollResponse(
        request_id=queued.request_id,
        tool=queued.tool,
        params=queued.params,
    )


@router.post(
    "/supervisor/nettool/reply/{request_id}",
    summary="Return a network-tool result to the awaiting operator action",
)
async def nettool_reply(
    request_id: str,
    body: NetToolReplyRequest,
    request: Request,
    db: DB,
) -> dict[str, str]:
    """Supervisor-only endpoint. Once the supervisor has run the
    dispatched tool against its local vantage, it POSTs the structured
    result here. The backend's in-memory future map matches the
    request_id + resolves the operator action's pending future.

    Returns 200 either way — late replies (operator already timed out +
    the future was evicted) are logged + discarded server-side so the
    supervisor's loop stays simple.
    """
    from app.services.appliance import agent_cmd as _cmd  # noqa: PLC0415

    appliance = await _require_cert_auth(request, db)
    if body.request_id != request_id:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "request_id path/body mismatch",
        )
    result = _cmd.NetToolResult(
        request_id=request_id,
        result=body.result,
        error=body.error,
    )
    delivered = _cmd.deliver_result(result)
    logger.info(
        "appliance.nettool.reply",
        appliance_id=str(appliance.id),
        request_id=request_id,
        has_error=body.error is not None,
        delivered=delivered,
    )
    return {"delivered": "true" if delivered else "stale"}


# ── Storage management (md / multipath, #999 Part B) ─────────────────────
#
# Same transport as the nettool channel above (per-appliance queue +
# per-request future) on its OWN queue, because a nettool is a read-only
# reachability probe and ``mdadm --add`` overwrites a disk. Separate
# queues mean a long-running topology dump cannot sit in front of a ping,
# and neither endpoint's name lies about what it moves.
#
# The supervisor does not run mdadm itself — it writes a request file for
# the host-side ``spatiumddi-storage-action`` runner and relays the
# result, so the root binaries stay out of the container.


class StoragePollResponse(BaseModel):
    """Long-poll result for the supervisor's storage channel.

    ``request_id`` is empty when the poll timed out with nothing queued.
    ``params`` is the server-validated structured action — never a shell
    string; the host runner re-validates every field against its own
    allowlist and builds the argv itself.
    """

    request_id: str
    params: dict[str, Any] = Field(default_factory=dict)


class StorageReplyRequest(BaseModel):
    """Supervisor-sent reply carrying the host runner's verdict."""

    request_id: str
    result: dict[str, Any] | None = None
    error: str | None = None


class StorageReplyAck(BaseModel):
    """Whether the reply matched a still-waiting operator request.

    ``stale`` is a normal outcome, not an error: the operator's request
    may have timed out and had its future evicted while the host runner
    was still working.
    """

    delivered: Literal["true", "stale"]


@router.post(
    "/supervisor/storage/poll",
    response_model=StoragePollResponse,
    summary="Long-poll for the next queued storage-management action",
)
async def storage_poll(request: Request, db: DB) -> StoragePollResponse:
    """Supervisor-only endpoint (cert-authed). The queue is keyed by
    appliance_id, so a cert only ever sees its own actions."""
    from app.services.appliance import agent_cmd as _cmd  # noqa: PLC0415

    appliance = await _require_cert_auth(request, db)
    queued = await _cmd.pop_command(appliance.id, timeout=30.0, channel=_cmd.CHANNEL_STORAGE)
    if queued is None:
        return StoragePollResponse(request_id="", params={})
    return StoragePollResponse(request_id=queued.request_id, params=queued.params)


@router.post(
    "/supervisor/storage/reply/{request_id}",
    response_model=StorageReplyAck,
    summary="Return a storage-action result to the awaiting operator action",
)
async def storage_reply(
    request_id: str,
    body: StorageReplyRequest,
    request: Request,
    db: DB,
) -> StorageReplyAck:
    """Supervisor-only endpoint (cert-authed)."""
    from app.services.appliance import agent_cmd as _cmd  # noqa: PLC0415

    appliance = await _require_cert_auth(request, db)
    if body.request_id != request_id:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "request_id path/body mismatch",
        )
    delivered = _cmd.deliver_result(
        _cmd.NetToolResult(request_id=request_id, result=body.result, error=body.error),
        channel=_cmd.CHANNEL_STORAGE,
    )
    logger.info(
        "appliance.storage.reply",
        appliance_id=str(appliance.id),
        request_id=request_id,
        has_error=body.error is not None,
        delivered=delivered,
    )
    return StorageReplyAck(delivered="true" if delivered else "stale")


class StorageActionRequest(BaseModel):
    """An operator's md / multipath management request."""

    action: str
    array: str | None = None
    device: str | None = None
    #: Destructive actions require the DEVICE path typed back — a typed
    #: confirmation that is not the thing being destroyed is a
    #: click-through with extra steps.
    confirm: str | None = None


class StorageActionResponse(BaseModel):
    ok: bool
    action: str
    detail: str
    output: str | None = None


@router.post(
    "/appliances/{appliance_id}/storage/action",
    response_model=StorageActionResponse,
    summary="Run an md / multipath management action on an appliance (#999 Part B)",
)
async def appliance_storage_action(
    appliance_id: uuid.UUID,
    body: StorageActionRequest,
    request: Request,
    db: DB,
    user: CurrentUser,
) -> StorageActionResponse:
    """Superadmin only, audited, and refused rather than confirmed where
    the operator could not inspect the consequence afterwards.

    The control plane decides what may be ASKED for (this is the side
    that knows who the operator is); the host runner decides what is
    safe to do at the moment of the action, re-counting the array's
    in-sync members from the kernel — because this side's view is up to
    one heartbeat old and a member can have failed since.
    """
    from app.services.appliance import agent_cmd as _cmd  # noqa: PLC0415
    from app.services.appliance.storage_actions import (  # noqa: PLC0415
        ActionRefused,
        summarize,
        validate_action,
    )

    _require_superadmin(user)
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")

    try:
        params = validate_action(
            body.action, array=body.array, device=body.device, confirm=body.confirm
        )
    except ActionRefused as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    summary = summarize(body.action, body.array, body.device)
    # Recorded BEFORE dispatch, and committed either way: an action that
    # was attempted and failed is exactly as interesting to an auditor as
    # one that succeeded, and more interesting than one that was never
    # recorded because the supervisor happened to be offline.
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name or user.username,
            auth_source=user.auth_source or "local",
            source_ip=_client_ip(request),
            action="appliance.storage.action",
            resource_type="appliance",
            resource_id=str(row.id),
            resource_display=row.hostname,
            result="ok",
            new_value={
                "action": body.action,
                "array": body.array,
                "device": body.device,
                "summary": summary,
            },
        )
    )
    await db.commit()

    ready = _cmd.appliance_ready(state=row.state, last_seen_at=row.last_seen_at)
    try:
        outcome = await _cmd.enqueue_command(
            row.id,
            body.action,
            params,
            ready=ready,
            timeout=90.0,
            channel=_cmd.CHANNEL_STORAGE,
        )
    except _cmd.ApplianceOffline as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"appliance {row.hostname} is offline or not approved",
        ) from exc
    except TimeoutError as exc:
        raise HTTPException(
            status.HTTP_504_GATEWAY_TIMEOUT,
            f"{row.hostname} did not answer the storage action in time",
        ) from exc

    if outcome.error:
        return StorageActionResponse(
            ok=False, action=body.action, detail=outcome.error, output=None
        )
    result = outcome.result or {}
    return StorageActionResponse(
        ok=bool(result.get("ok")),
        action=body.action,
        detail=str(result.get("detail") or ""),
        output=(str(result["output"]) if result.get("output") else None),
    )


# ── Removable (USB) backup disks (#989 item 3) ───────────────────────
#
# Read the candidates this node can see, mount one, eject one. The
# mount is desired state on the appliance row, applied by the
# supervisor's host runner over the same trigger-file plane as every
# other host-config plane — so these endpoints stamp and wake, they
# never wait for the disk.


class RemovableDisk(BaseModel):
    """One USB filesystem the node reported.

    ``usable`` + ``reason`` rather than filtering: a disk that does not
    appear at all reads as a broken feature, and the operator cannot
    tell that from "SpatiumDDI has not noticed it yet".
    """

    device: str = ""
    by_id: str = ""
    fs_uuid: str = ""
    fstype: str = ""
    label: str = ""
    model: str = ""
    vendor: str = ""
    serial: str = ""
    size_bytes: int | None = None
    mounted_at: str | None = None
    usable: bool = False
    reason: str | None = None


class RemovableMount(BaseModel):
    name: str
    fs_uuid: str
    fstype: str
    label: str | None = None
    added_at: str | None = None
    #: ``mounted`` / ``waiting`` / ``present`` / ``blind`` /
    #: ``unreported`` — see ``merge_state``. ``waiting`` is NOT a fault
    #: (a rotated off-site disk); ``present`` is (the disk is in the
    #: port and the mount did not take).
    state: str = "unreported"
    #: Where a backup target should point. Not the mountpoint: ext4
    #: carries real ownership and the api runs as uid 1000, so archives
    #: go in a subdirectory the host runner chowns.
    path: str
    mountpoint: str
    total_bytes: int | None = None
    free_bytes: int | None = None
    present: bool = False


class RemovableResponse(BaseModel):
    #: False when the node has not reported a removable block at all —
    #: a supervisor too old to look, or one that has not heartbeated.
    #: NOT the same as "no disks", and the UI must not render it as one.
    reported: bool = False
    #: The node the disks are plugged into, for the backup target's
    #: ``node_name``. None until the node reports one.
    node_name: str | None = None
    disks: list[RemovableDisk] = Field(default_factory=list)
    mounts: list[RemovableMount] = Field(default_factory=list)
    #: Reported by the node when the last apply failed or is retrying,
    #: so a mount that never lands says so instead of sitting in
    #: ``waiting`` forever looking like an unplugged disk.
    apply_state: str | None = None
    #: The host runner's own reason for the last failure, when it had
    #: one. Without this the operator is told only "not applied" and
    #: sent to read ``journalctl`` — the concrete cause is written to a
    #: sidecar and would otherwise be discarded (the #882 deferred item).
    apply_error: str | None = None
    #: False = the node CAN see its disks but cannot read the removable
    #: root (the hostPath bind is missing, or its propagation was lost).
    #: Distinct from ``reported``: /run/udev is a separate mount, so the
    #: disk list can be full while every mount reads as absent, and
    #: rendering that as "your disk is not plugged in" sends the
    #: operator to check a cable for no reason.
    root_readable: bool = True
    #: The destination path a backup target should use, with ``{name}``
    #: left to substitute. Served rather than re-derived in the UI so
    #: the one screen whose job is telling the operator what to paste
    #: cannot drift from ``archive_path`` — the #878 two-renderers rule.
    path_template: str = ""


class RemovableMountRequest(BaseModel):
    fs_uuid: str
    name: str


def _removable_apply_error(row: Appliance) -> str | None:
    """The host runner's own reason for its last failed apply.

    Only surfaced while the failure is still current: once the runner
    succeeds it writes ``applied``, and reporting a stale reason beside
    a healthy plane is worse than reporting none.
    """
    block = removable_report(row.cluster_health)
    status = (block or {}).get("apply_status")
    if not isinstance(status, dict) or status.get("state") != "failed":
        return None
    error = status.get("error")
    return str(error)[:500] if error else None


def _removable_response(row: Appliance) -> RemovableResponse:
    block = removable_report(row.cluster_health)
    disks = [RemovableDisk(**removable_disk_fields(e)) for e in (block or {}).get("disks") or []]
    health = row.host_config_health if isinstance(row.host_config_health, dict) else {}
    plane = health.get("removable") if isinstance(health.get("removable"), dict) else None
    return RemovableResponse(
        reported=block is not None,
        # ``_s`` and not ``str(...) or None``: ``str(None)`` is the
        # string "None", which is TRUTHY, so the ``or`` never fires and
        # the UI renders "Disks here are on node None" — which an
        # operator then copies into a destination's node field, refusing
        # every backup thereafter.
        node_name=_s(block.get("node_name")) if block else None,
        root_readable=(bool(block.get("supported", True)) if block else True),
        disks=disks,
        mounts=[
            RemovableMount(**m)
            for m in merge_state(row.desired_removable_mounts, row.cluster_health)
        ],
        apply_state=_s(plane.get("state")) if plane else None,
        apply_error=_removable_apply_error(row),
        path_template=archive_path("{name}"),
    )


@router.get(
    "/appliances/{appliance_id}/removable",
    response_model=RemovableResponse,
    summary="Removable (USB) disks this appliance can see (#989)",
)
async def list_removable(appliance_id: uuid.UUID, db: DB, user: CurrentUser) -> RemovableResponse:
    """Read-only. The listing comes from the node's last heartbeat, so it
    is at most one heartbeat interval old — a disk plugged in a moment
    ago appears on the next tick, and the UI says how long ago the node
    last reported rather than implying the reading is live.
    """
    _require_superadmin(user)
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    return _removable_response(row)


@router.post(
    "/appliances/{appliance_id}/removable/mount",
    response_model=RemovableResponse,
    summary="Mount a removable disk on an appliance for backups (#989)",
)
async def mount_removable(
    appliance_id: uuid.UUID,
    body: RemovableMountRequest,
    request: Request,
    db: DB,
    user: CurrentUser,
) -> RemovableResponse:
    """Superadmin only, audited.

    **The reported disk list is the allowlist** (the #890 rule): the
    request names a disk from the listing and is resolved against a
    FRESH one here, so there is no second list to keep in sync and a
    UUID the node is not currently reporting is refused rather than
    written into a mount unit. That also means a disk the node marked
    unusable — its own root partition, a filesystem we cannot mount, one
    already in use — cannot be mounted by crafting the request by hand.
    """
    _require_superadmin(user)
    # FOR UPDATE, unlike this file's siblings, and the difference is the
    # operation shape rather than a change of house style: role
    # assignment and firewall are whole-value REPLACEs, where
    # last-writer-wins is a defined outcome. This is the first
    # per-appliance list built by read-modify-APPEND, so an unlocked
    # lost update silently drops an operator's action instead of
    # overwriting it — and the duplicate-name / duplicate-UUID refusals
    # run against each session's own stale copy, so they cannot see a
    # concurrent peer either.
    row = await db.get(Appliance, appliance_id, with_for_update=True)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")

    block = removable_report(row.cluster_health)
    if block is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{row.hostname} has not reported its removable disks yet. It may be "
            "offline, or running a supervisor that predates this feature.",
        )
    candidates = {
        str(d.get("fs_uuid")): d
        for d in (block.get("disks") or [])
        if isinstance(d, dict) and d.get("fs_uuid")
    }
    disk = candidates.get(body.fs_uuid.strip())
    if disk is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"{row.hostname} is not reporting a disk with UUID "
            f"{body.fs_uuid!r}. If you have just plugged it in, wait for the "
            "next heartbeat and refresh.",
        )
    if not disk.get("usable"):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            str(disk.get("reason") or "this disk cannot be used for backups"),
        )

    try:
        name = validate_name(body.name)
        desired = normalise_desired(
            [
                *(row.desired_removable_mounts or []),
                {
                    "name": name,
                    "fs_uuid": str(disk.get("fs_uuid")),
                    "fstype": str(disk.get("fstype")),
                    "label": disk.get("label"),
                    "added_at": datetime.now(UTC).isoformat(),
                },
            ]
        )
    except RemovableError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    row.desired_removable_mounts = desired
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name or user.username,
            auth_source=user.auth_source or "local",
            source_ip=_client_ip(request),
            action="appliance.removable.mount",
            resource_type="appliance",
            resource_id=str(row.id),
            resource_display=row.hostname,
            result="ok",
            new_value={
                "name": name,
                "fs_uuid": disk.get("fs_uuid"),
                "fstype": disk.get("fstype"),
                "label": disk.get("label"),
                "path": archive_path(name),
            },
        )
    )
    await db.commit()
    await db.refresh(row)
    # #358 Phase 1 — wake the heartbeat long-poll so the disk is mounted
    # in ~0 s rather than on the next tick. Advisory; the tick is the
    # fallback, so a Redis outage delays the mount, never loses it.
    await publish_wake(appliance_channel(row.id))
    return _removable_response(row)


@router.delete(
    "/appliances/{appliance_id}/removable/{name}",
    response_model=RemovableResponse,
    summary="Eject a removable disk from an appliance (#989)",
)
async def eject_removable(
    appliance_id: uuid.UUID,
    name: str,
    request: Request,
    db: DB,
    user: CurrentUser,
) -> RemovableResponse:
    """Flush and unmount, so the disk is safe to pull when this returns.

    Deliberately **not** blocked by a backup target still pointing at
    the mount. The operator wants their disk back, and refusing here
    would leave them pulling it anyway with the filesystem un-flushed —
    strictly worse. A run against an ejected disk then fails loudly:
    the path stops being a mountpoint, the driver refuses, and nothing
    is written to the appliance's own /var.
    """
    _require_superadmin(user)
    # See ``mount_removable`` — a mount racing an eject would otherwise
    # re-append the just-ejected entry from its stale copy, resurrecting
    # a disk the operator was told was ejected.
    row = await db.get(Appliance, appliance_id, with_for_update=True)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    try:
        wanted = validate_name(name)
    except RemovableError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    current = list(row.desired_removable_mounts or [])
    remaining = [m for m in current if str(m.get("name")) != wanted]
    if len(remaining) == len(current):
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, f"{row.hostname} has no removable mount named {wanted!r}."
        )
    row.desired_removable_mounts = remaining
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name or user.username,
            auth_source=user.auth_source or "local",
            source_ip=_client_ip(request),
            action="appliance.removable.eject",
            resource_type="appliance",
            resource_id=str(row.id),
            resource_display=row.hostname,
            result="ok",
            new_value={"name": wanted},
        )
    )
    await db.commit()
    await db.refresh(row)
    await publish_wake(appliance_channel(row.id))
    return _removable_response(row)


# ── Packet capture (appliance-host vantage, #59 Phase 2) ─────────────────

#
# The supervisor's pcap_proxy thread drives these. Unlike the nettool /
# k8s-proxy in-memory queues, the authority is the packet_capture DB row
# (claimed via a guarded UPDATE), so any api replica can serve the poll.


class PcapPollResponse(BaseModel):
    """A claimed appliance-vantage capture command, or empty (capture_id
    == "") when nothing is queued. Structured fields only — the
    supervisor + host runner rebuild the tcpdump argv from these."""

    capture_id: str = ""
    interface: str | None = None
    bpf_filter: str | None = None
    snaplen: int = 256
    promiscuous: bool = False
    max_packets: int | None = None
    max_duration_s: int | None = None
    max_bytes: int | None = None


class PcapProgressRequest(BaseModel):
    packets: int | None = None
    bytes_captured: int | None = None
    elapsed_s: float | None = None


async def _pcap_capture_for_appliance(db: DB, capture_id: uuid.UUID, appliance: Appliance) -> Any:
    from app.models.pcap import PacketCapture  # noqa: PLC0415

    row = await db.get(PacketCapture, capture_id)
    if row is None or row.appliance_id != appliance.id:
        # Don't leak existence of another appliance's capture.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "capture not found for this appliance")
    return row


@router.post(
    "/supervisor/pcap/poll",
    response_model=PcapPollResponse,
    summary="Long-poll for the next queued appliance-host packet capture",
)
async def pcap_poll(request: Request, db: DB) -> PcapPollResponse:
    """Cert-authed. Claims (guarded UPDATE → running) the oldest queued
    appliance-vantage capture for the caller's appliance, or returns an
    empty shape after ~30 s so the supervisor re-polls."""
    import asyncio as _asyncio  # noqa: PLC0415

    from app.services.appliance import pcap_capture as _pc  # noqa: PLC0415

    appliance = await _require_cert_auth(request, db)
    deadline = _asyncio.get_running_loop().time() + 30.0
    while True:
        cmd = await _pc.claim_next(db, appliance.id)
        if cmd is not None:
            return PcapPollResponse(**cmd)
        if _asyncio.get_running_loop().time() >= deadline:
            return PcapPollResponse()
        await _asyncio.sleep(2.0)


@router.post(
    "/supervisor/pcap/progress/{capture_id}",
    summary="Report live capture progress; returns the operator cancel flag",
)
async def pcap_progress(
    capture_id: uuid.UUID, body: PcapProgressRequest, request: Request, db: DB
) -> dict[str, bool]:
    from app.services.appliance import pcap_capture as _pc  # noqa: PLC0415

    appliance = await _require_cert_auth(request, db)
    await _pcap_capture_for_appliance(db, capture_id, appliance)
    cancel = await _pc.record_progress(
        db,
        capture_id,
        packets=body.packets,
        bytes_captured=body.bytes_captured,
        elapsed_s=body.elapsed_s,
    )
    return {"cancel": cancel}


@router.post(
    "/supervisor/pcap/upload/{capture_id}",
    summary="Stream the finished .pcap back (or finalize as failed via ?error=)",
)
async def pcap_upload(capture_id: uuid.UUID, request: Request, db: DB) -> dict[str, str]:
    """Cert-authed. Streams the host-captured ``.pcap`` to the shared
    PCAP_DIR (``.partial`` → atomic rename + sha256), capped at
    ``max_bytes`` + margin. ``?error=`` (empty body) finalizes a failed
    capture. A cancelled row keeps its uploaded bytes (valid partial
    ``.pcap`` up to the last flushed packet) so Stop-early stays
    downloadable; it just stays terminal-cancelled (#59 follow-up)."""
    import hashlib as _hashlib  # noqa: PLC0415
    import os as _os  # noqa: PLC0415

    from app.services.appliance import pcap_capture as _pc  # noqa: PLC0415
    from app.services.pcap.runner import HARD_MAX_BYTES, pcap_dir  # noqa: PLC0415

    appliance = await _require_cert_auth(request, db)
    row = await _pcap_capture_for_appliance(db, capture_id, appliance)

    error = request.query_params.get("error")
    if error:
        await _pc.finalize_capture(
            db,
            capture_id,
            pcap_path=None,
            pcap_size_bytes=None,
            pcap_sha256=None,
            packet_count=None,
            metadata={"stop_reason": "error"},
            error=error,
        )
        return {"status": "failed"}

    packets_q = request.query_params.get("packets")
    packet_count = int(packets_q) if packets_q and packets_q.isdigit() else None
    # Generous transfer ceiling: the configured byte cap + 16 MiB headroom
    # (pcap framing), never above the hard ceiling + headroom.
    cap = min((row.max_bytes or HARD_MAX_BYTES), HARD_MAX_BYTES) + 16 * 1024 * 1024

    # ``capture_id`` is a FastAPI-coerced uuid.UUID (path separators are
    # impossible), but resolve + assert the path stays inside PCAP_DIR
    # anyway — defence-in-depth + it clears the CodeQL path-injection taint
    # from the HTTP path param.
    pcap_root = pcap_dir().resolve()
    dest = (pcap_root / f"{capture_id}.pcap").resolve()
    if dest.parent != pcap_root:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid capture id")
    partial = dest.with_name(f"{dest.stem}.pcap.partial")
    h = _hashlib.sha256()
    size = 0
    over_cap = False
    try:
        with open(partial, "wb") as fh:
            async for chunk in request.stream():
                if not chunk:
                    continue
                size += len(chunk)
                if size > cap:
                    over_cap = True
                    break
                fh.write(chunk)
                h.update(chunk)
    except Exception as exc:  # noqa: BLE001
        partial.unlink(missing_ok=True)
        return {
            "status": await _pc.finalize_capture(
                db,
                capture_id,
                pcap_path=None,
                pcap_size_bytes=None,
                pcap_sha256=None,
                packet_count=None,
                metadata={"stop_reason": "upload_error"},
                error=f"upload failed: {exc}",
            )
        }

    if over_cap:
        # The savefile exceeds the capture's own byte cap + margin — the host
        # runner caps tcpdump at max_bytes, so this shouldn't happen. Finalize
        # as failed (don't leave the row dangling for the reaper) and drop the
        # oversized partial. A prior cancel still wins. Over-cap is the one
        # case we can't honour the keep-partial promise for.
        partial.unlink(missing_ok=True)
        await _pc.finalize_capture(
            db,
            capture_id,
            pcap_path=None,
            pcap_size_bytes=None,
            pcap_sha256=None,
            packet_count=packet_count,
            metadata={"stop_reason": "over_cap"},
            error="uploaded pcap exceeds the capture's byte cap",
        )
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            "uploaded pcap exceeds the capture's byte cap",
        )

    if size == 0:
        # Stopped before the first packet flushed. Never leave a 0-byte file
        # orphaned in PCAP_DIR (no row would reference it, so prune/delete —
        # which key on pcap_path — could never reclaim it).
        partial.unlink(missing_ok=True)
        final_status = await _pc.finalize_capture(
            db,
            capture_id,
            pcap_path=None,
            pcap_size_bytes=0,
            pcap_sha256=None,
            packet_count=packet_count,
            metadata={"packet_count": packet_count, "byte_count": 0, "stop_reason": "empty"},
            error=None,
        )
        logger.info(
            "appliance.pcap.upload",
            appliance_id=str(appliance.id),
            capture_id=str(capture_id),
            bytes=0,
            status=final_status,
        )
        return {"status": final_status}

    _os.replace(partial, dest)
    final_status = await _pc.finalize_capture(
        db,
        capture_id,
        pcap_path=str(dest),
        pcap_size_bytes=size,
        pcap_sha256=h.hexdigest(),
        packet_count=packet_count,
        metadata={
            "packet_count": packet_count,
            "byte_count": size,
            "stop_reason": "completed",
        },
        error=None,
    )
    # NOTE: a cancelled capture KEEPS its uploaded bytes (#59 follow-up) —
    # the savefile is a valid partial .pcap up to the last flushed packet,
    # so the operator can still download what was captured before Stop.
    logger.info(
        "appliance.pcap.upload",
        appliance_id=str(appliance.id),
        capture_id=str(capture_id),
        bytes=size,
        status=final_status,
    )
    return {"status": final_status}


class ApplianceWorkloadRow(BaseModel):
    """One restartable workload on an appliance's k3s."""

    kind: str
    name: str
    namespace: str
    component: str
    image: str
    desired: int
    ready: int
    state: str
    last_restarted_at: str | None = None


class ApplianceWorkloadsResponse(BaseModel):
    workloads: list[ApplianceWorkloadRow]
    #: Per-kind failures. Reported rather than raised so a cluster with an
    #: RBAC gap on one kind still lists the others.
    errors: list[str]


@router.get(
    "/appliances/{appliance_id}/k8s/workloads",
    response_model=ApplianceWorkloadsResponse,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="List restartable Deployments / DaemonSets / StatefulSets on an appliance",
)
async def k8s_list_workloads(
    appliance_id: uuid.UUID,
    current_user: CurrentUser,
    db: DB,
    namespace: str = "spatium",
) -> ApplianceWorkloadsResponse:
    """Inventory for the Fleet restart picker (#890).

    Before this the Fleet UI had exactly one restart button and it was
    hardcoded to ``deploy/dns-bind9``, so a node running PowerDNS,
    Technitium or Kea had no restart at all. Listing the workloads the
    appliance actually runs replaces the guess.

    Read-only, and filtered to workloads labelled as ours — an operator's
    own Deployment in the same namespace is neither listed here nor
    restartable through the sibling endpoint, which resolves its target
    against this same label set.
    """
    import json as _json  # noqa: PLC0415 — lazy; only on this path.

    from app.services.appliance import k8s_proxy as _proxy  # noqa: PLC0415
    from app.services.service_control import kube as _kube  # noqa: PLC0415

    _require_superadmin(current_user)
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    if row.state != APPLIANCE_STATE_APPROVED:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Appliance in state {row.state!r}; kubeapi proxy unavailable.",
        )

    workloads: list[dict[str, object]] = []
    errors: list[str] = []
    for kind, plural in _kube.WORKLOAD_KINDS:
        api_path = f"/apis/apps/v1/namespaces/{namespace}/{plural}"
        try:
            status_code, body = await _proxy.k8s_call(row.id, "GET", api_path, timeout=20.0)
        except TimeoutError:
            raise HTTPException(
                status.HTTP_504_GATEWAY_TIMEOUT,
                "Supervisor didn't reply in 20s. Is the appliance heartbeating?",
            ) from None
        if not 200 <= status_code < 300:
            # Report per-kind rather than failing the whole call: a
            # cluster with no StatefulSets and an RBAC gap on them should
            # still list the Deployments the operator came here to restart.
            errors.append(f"{plural}: kubeapi {status_code}")
            continue
        try:
            items = (_json.loads(body.decode("utf-8")) or {}).get("items") or []
        except (ValueError, UnicodeDecodeError) as exc:
            errors.append(f"{plural}: unparseable response ({exc})")
            continue
        workloads.extend(
            {**_kube.summarise_workload(kind, obj), "namespace": namespace}
            for obj in items
            if _kube.is_spatium_workload(obj)
        )

    workloads.sort(key=lambda w: (str(w["kind"]), str(w["name"])))
    return ApplianceWorkloadsResponse(
        workloads=[ApplianceWorkloadRow(**w) for w in workloads],  # type: ignore[arg-type]
        errors=errors,
    )


class ApplianceRestartDeploymentRequest(BaseModel):
    """Operator-driven Deployment / DaemonSet rollout-restart.

    Same effect as ``kubectl rollout restart <kind>/<name> -n
    <namespace>``. Bumps the pod template's
    ``kubectl.kubernetes.io/restartedAt`` annotation, which makes the
    controller spin up new pods and reap the old ones one at a time.
    """

    # StatefulSet joined the union in #890: the Fleet picker lists every
    # workload kind the appliance runs, so restricting the restart to two
    # of the three would leave rows in the picker that error on click.
    kind: Literal["Deployment", "DaemonSet", "StatefulSet"]
    namespace: str = Field(default="spatium", min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=253)


@router.post(
    "/appliances/{appliance_id}/k8s/restart",
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Rollout-restart a Deployment/DaemonSet on the appliance's k3s",
)
async def k8s_rollout_restart(
    appliance_id: uuid.UUID,
    body: ApplianceRestartDeploymentRequest,
    current_user: CurrentUser,
    db: DB,
) -> dict[str, object]:
    """First operator-facing direct-kubeapi action (#183 Phase 4
    proof-of-concept). Enqueues a kubeapi PATCH against the local
    cluster via the supervisor proxy + waits up to 30 s for the
    response.

    Returns ``{"ok": true, "status": <kubeapi-status>}`` on success;
    surfaces a 504 if the supervisor doesn't reply in time, 502 if
    the kubeapi itself returned an error.
    """
    from app.services.appliance import k8s_proxy as _proxy  # noqa: PLC0415

    _require_superadmin(current_user)
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    if row.state != APPLIANCE_STATE_APPROVED:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Appliance in state {row.state!r}; kubeapi proxy unavailable.",
        )

    # Strategic-merge patch that bumps the pod template's
    # ``restartedAt`` annotation. Standard kubectl rollout-restart
    # shape — same JSON kubectl sends.
    api_path = f"/apis/apps/v1/namespaces/{body.namespace}/" f"{body.kind.lower()}s/{body.name}"
    patch_body = {
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "kubectl.kubernetes.io/restartedAt": datetime.now(UTC).isoformat()
                    }
                }
            }
        }
    }
    try:
        status_code, response_body = await _proxy.k8s_call(
            row.id,
            "PATCH",
            api_path,
            body=patch_body,
            content_type="application/strategic-merge-patch+json",
            timeout=20.0,
        )
    except TimeoutError as exc:
        raise HTTPException(
            status.HTTP_504_GATEWAY_TIMEOUT,
            "Supervisor didn't reply in 20s. Is the appliance heartbeating?",
        ) from exc

    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.k8s_rollout_restart",
            resource_type="appliance",
            resource_id=str(row.id),
            resource_display=row.hostname,
            result="success" if 200 <= status_code < 300 else "failed",
            new_value={
                "kind": body.kind,
                "namespace": body.namespace,
                "name": body.name,
                "kubeapi_status": status_code,
            },
        )
    )
    await db.commit()

    if not 200 <= status_code < 300:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"kubeapi returned {status_code}: {response_body[:200]!r}",
        )

    logger.info(
        "appliance.k8s_rollout_restart",
        appliance_id=str(row.id),
        kind=body.kind,
        namespace=body.namespace,
        name=body.name,
        kubeapi_status=status_code,
        user=current_user.username,
    )
    return {"ok": True, "status": status_code, "kind": body.kind, "name": body.name}


# ── Issue #183 Phase 5 — kubeconfig reveal ──


class RevealKubeconfigRequest(BaseModel):
    """Operator re-confirmation before we hand back the cleartext
    kubeconfig. Same gate the SNMP-community and agent-bootstrap-key
    reveals use: local users supply ``password``, external-auth users
    (no local password, #408) supply ``totp_code``."""

    password: str | None = None
    totp_code: str | None = None


class RevealKubeconfigResponse(BaseModel):
    """Payload of a successful reveal. ``hostname`` is the operator-
    visible name we surface in the suggested download filename
    (``<hostname>.kubeconfig``)."""

    configured: bool
    kubeconfig: str | None
    hostname: str


@router.post(
    "/appliances/{appliance_id}/k8s/kubeconfig/reveal",
    response_model=RevealKubeconfigResponse,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Reveal an appliance's k3s admin kubeconfig (superadmin + password)",
)
async def reveal_appliance_kubeconfig(
    appliance_id: uuid.UUID,
    body: RevealKubeconfigRequest,
    current_user: CurrentUser,
    db: DB,
) -> RevealKubeconfigResponse:
    """Return the appliance's stored kubeconfig after password
    re-verification. Same shape as ``POST /admin/agent-keys/reveal``
    and ``POST /settings/snmp/reveal-community``:

    * Superadmin gate
    * Local-auth gate (external-auth users have no password to
      re-confirm)
    * Password re-verification
    * Every denial path emits an audit row + a 100 ms friction sleep

    The kubeconfig's ``server:`` field has already been rewritten to
    the appliance's last-seen IP on the way in (see the heartbeat
    handler). Operators on the appliance's network can use the
    downloaded file directly; operators on a different network may
    need to edit the server line to a reachable address.
    """
    from app.core.crypto import decrypt_str  # noqa: PLC0415
    from app.services.reauth import (  # noqa: PLC0415
        ReauthOutcome,
        reverify_operator,
    )

    def _audit_denied(reason: str, *, row: Appliance | None = None) -> None:
        db.add(
            AuditLog(
                user_id=current_user.id,
                user_display_name=current_user.display_name,
                auth_source=current_user.auth_source,
                action="appliance_kubeconfig_reveal_denied",
                resource_type="appliance",
                resource_id=str(appliance_id),
                resource_display=row.hostname if row else str(appliance_id),
                result="forbidden",
                new_value={"reason": reason},
            )
        )

    if not is_effective_superadmin(current_user):
        _audit_denied("non_superadmin")
        await db.commit()
        await asyncio.sleep(0.1)
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Only superadmins can reveal an appliance kubeconfig.",
        )
    # #408 — local users re-confirm with password or TOTP; external-auth
    # users with TOTP (enrol under Settings → Security if not yet enrolled).
    outcome = reverify_operator(current_user, password=body.password, totp_code=body.totp_code)
    if outcome is not ReauthOutcome.OK:
        await asyncio.sleep(0.1)
        if outcome is ReauthOutcome.MFA_REQUIRED:
            _audit_denied("mfa_required")
            await db.commit()
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Re-confirmation requires MFA. Your account has no local "
                "password — enrol TOTP under Settings → Security, then retry.",
            )
        _audit_denied("bad_credential")
        await db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Password or TOTP code is incorrect.")

    row = await db.get(Appliance, appliance_id)
    if row is None:
        _audit_denied("appliance_not_found")
        await db.commit()
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    if row.kubeconfig_encrypted is None:
        # Clean "nothing to reveal" — supervisor hasn't shipped a
        # kubeconfig yet (legacy compose / pre-Phase-5 / k3s not
        # started). Surface as a friendly state, not an error.
        return RevealKubeconfigResponse(configured=False, kubeconfig=None, hostname=row.hostname)

    try:
        plaintext = decrypt_str(row.kubeconfig_encrypted)
    except Exception:  # noqa: BLE001
        _audit_denied("decrypt_failed", row=row)
        await db.commit()
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Stored kubeconfig could not be decrypted (key mismatch?). "
            "The supervisor will re-ship it on the next heartbeat.",
        ) from None

    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance_kubeconfig_revealed",
            resource_type="appliance",
            resource_id=str(row.id),
            resource_display=row.hostname,
            result="success",
        )
    )
    await db.commit()
    logger.info(
        "appliance_kubeconfig_revealed",
        appliance_id=str(row.id),
        hostname=row.hostname,
        user=current_user.username,
    )
    return RevealKubeconfigResponse(configured=True, kubeconfig=plaintext, hostname=row.hostname)


# ── Issue #183 Phase 6 — kubeapi-expose CIDR editor ──


class ApplianceKubeapiCidrsRequest(BaseModel):
    """Operator-supplied list of CIDRs allowed to reach this
    appliance's kubeapi on tcp/6443. Validated as a list of strings;
    empty list = proxy-only (the default, recommended posture)."""

    cidrs: list[str] = Field(default_factory=list, max_length=32)


def _validate_cidr(value: str) -> str:
    """Light CIDR validation — operator may type ``10.0.0.0/8`` or
    a bare host ``192.168.1.50`` (which nftables accepts inline).
    Strips whitespace, refuses anything that doesn't parse as an
    ip_network or ip_address. Returns the normalised string the
    nft renderer will emit verbatim."""
    import ipaddress  # noqa: PLC0415

    text = value.strip()
    if not text:
        raise ValueError("empty CIDR")
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        # Bare host — nft accepts a single-IP rule the same way.
        try:
            return str(ipaddress.ip_address(text))
        except ValueError as exc:
            raise ValueError(f"{text!r} isn't a valid CIDR or IP address") from exc


@router.put(
    "/appliances/{appliance_id}/kubeapi-cidrs",
    response_model=ApplianceRow,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Set the kubeapi-direct-access CIDR allowlist on an appliance",
)
async def update_appliance_kubeapi_cidrs(
    appliance_id: uuid.UUID,
    body: ApplianceKubeapiCidrsRequest,
    current_user: CurrentUser,
    db: DB,
) -> ApplianceRow:
    """Update the operator-controlled CIDR allowlist for direct
    kubeapi access. The supervisor's firewall renderer reads this
    list on every heartbeat + emits ``ip saddr { ... } tcp dport
    6443 accept`` rules.

    Empty list = proxy-only (the recommended default): kubeapi stays
    on 127.0.0.1 and the only path into it is the supervisor's
    outbound proxy channel (Phase 4). Non-empty list = direct
    access for operators who want sub-millisecond local-network
    ops; the supervisor's mTLS proxy still works alongside.
    """
    _require_superadmin(current_user)
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")

    normalised: list[str] = []
    for value in body.cidrs:
        try:
            normalised.append(_validate_cidr(value))
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                str(exc),
            ) from exc

    row.kubeapi_expose_cidrs = normalised
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="appliance.kubeapi_cidrs_updated",
            resource_type="appliance",
            resource_id=str(row.id),
            resource_display=row.hostname,
            result="success",
            new_value={"kubeapi_expose_cidrs": normalised},
        )
    )
    await db.commit()
    logger.info(
        "appliance.kubeapi_cidrs_updated",
        appliance_id=str(row.id),
        hostname=row.hostname,
        cidr_count=len(normalised),
        user=current_user.username,
    )
    return _row_to_schema(row)


# ── Issue #183 Phase 8 — pod list + log viewer (via Phase 4 proxy) ──


class K8sPodSummary(BaseModel):
    """Trimmed shape of a kubeapi Pod for the operator's log-picker
    dropdown. We don't surface the full PodSpec — operators only
    need to pick (pod, container) for the log fetch."""

    name: str
    namespace: str
    phase: str
    ready: bool
    containers: list[str]
    labels: dict[str, str]


class K8sPodListResponse(BaseModel):
    pods: list[K8sPodSummary]


@router.get(
    "/appliances/{appliance_id}/k8s/pods",
    response_model=K8sPodListResponse,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="List pods on the appliance's local k3s (via the supervisor proxy)",
)
async def k8s_list_pods(
    appliance_id: uuid.UUID,
    current_user: CurrentUser,
    db: DB,
    namespace: str = "spatium",
) -> K8sPodListResponse:
    """List pods in the named namespace via the kubeapi proxy.

    Default namespace ``spatium`` covers every chart-deployed pod.
    Operators who want kube-system / default visibility pass the
    namespace explicitly — same kubeapi surface as ``kubectl get
    pods``.
    """
    from app.services.appliance import k8s_proxy as _proxy  # noqa: PLC0415

    _require_superadmin(current_user)
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    if row.state != APPLIANCE_STATE_APPROVED:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Appliance in state {row.state!r}; kubeapi proxy unavailable.",
        )

    path = f"/api/v1/namespaces/{namespace}/pods"
    try:
        status_code, body = await _proxy.k8s_call(row.id, "GET", path, timeout=15.0)
    except TimeoutError as exc:
        raise HTTPException(
            status.HTTP_504_GATEWAY_TIMEOUT,
            "Supervisor didn't reply in 15s. Is the appliance heartbeating?",
        ) from exc
    if not 200 <= status_code < 300:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"kubeapi returned {status_code}: {body[:200]!r}",
        )

    try:
        import json  # noqa: PLC0415

        data = json.loads(body)
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"kubeapi returned non-JSON body: {exc}",
        ) from exc

    pods: list[K8sPodSummary] = []
    for item in data.get("items") or []:
        meta = item.get("metadata") or {}
        spec = item.get("spec") or {}
        st = item.get("status") or {}
        container_statuses = st.get("containerStatuses") or []
        ready = bool(container_statuses) and all(cs.get("ready") for cs in container_statuses)
        pods.append(
            K8sPodSummary(
                name=meta.get("name") or "",
                namespace=meta.get("namespace") or namespace,
                phase=st.get("phase") or "Unknown",
                ready=ready,
                containers=[
                    c.get("name") or "" for c in (spec.get("containers") or []) if c.get("name")
                ],
                labels=dict(meta.get("labels") or {}),
            )
        )
    return K8sPodListResponse(pods=pods)


@router.get(
    "/appliances/{appliance_id}/k8s/logs",
    # ``response_class`` REPLACES the documented application/json (#921);
    # a ``responses={200: {"content": ...}}`` entry merges with it instead,
    # leaving the route declaring a JSON body it never produces.
    response_class=PlainTextStreamResponse,
    responses={200: {"description": "Pod logs as plain text"}},
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Fetch recent pod logs from the appliance's local k3s",
)
async def k8s_get_pod_logs(
    appliance_id: uuid.UUID,
    pod: str,
    current_user: CurrentUser,
    db: DB,
    namespace: str = "spatium",
    container: str | None = None,
    tail_lines: int = 1000,
):
    """Return the last ``tail_lines`` lines of the named pod's log
    via the kubeapi proxy.

    Snapshot-mode rather than ``--follow``: the Phase 4 proxy is
    request/response. For true ``kubectl logs -f``-style streaming
    the operator can ssh to the appliance + run the kubectl directly
    (kubeconfig revealed via the Fleet UI). A future Phase 8b
    follow-up extends the proxy with a streaming-response channel.

    Returns ``text/plain`` so the Fleet UI's textarea can render it
    verbatim. Up to 1 MiB per call — k3s tail-line cap by default.
    """
    from fastapi.responses import PlainTextResponse  # noqa: PLC0415

    from app.services.appliance import k8s_proxy as _proxy  # noqa: PLC0415

    _require_superadmin(current_user)
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    if row.state != APPLIANCE_STATE_APPROVED:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Appliance in state {row.state!r}; kubeapi proxy unavailable.",
        )

    # Reject obvious path-injection on operator-supplied strings —
    # the proxy concatenates them into the kubeapi URL.
    if "/" in pod or "/" in namespace or (container and "/" in container):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid identifier")
    tail = max(1, min(10_000, tail_lines))

    path = f"/api/v1/namespaces/{namespace}/pods/{pod}/log?tailLines={tail}"
    if container:
        path += f"&container={container}"

    try:
        status_code, body = await _proxy.k8s_call(
            row.id, "GET", path, accept="text/plain", timeout=20.0
        )
    except TimeoutError as exc:
        raise HTTPException(
            status.HTTP_504_GATEWAY_TIMEOUT,
            "Supervisor didn't reply in 20s.",
        ) from exc
    if not 200 <= status_code < 300:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"kubeapi returned {status_code}: {body[:200]!r}",
        )
    return PlainTextResponse(body.decode("utf-8", errors="replace"))
