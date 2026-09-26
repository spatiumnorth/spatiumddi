"""SpatiumDDI OS appliance management models — Phase 4 (issue #134).

Three persistence surfaces live here:

* ``ApplianceCertificate`` (Phase 4b.1) — Web UI TLS cert with a
  Fernet-encrypted private key.
* ``PairingCode`` (#169) — short-lived, single-use 8-digit codes that
  swap for the real agent bootstrap key. See the model docstring.
* ``Appliance`` (#170 Wave A2) — one row per supervisor that's claimed
  a pairing code. Carries the supervisor's Ed25519 public key +
  identity metadata. See the model docstring.

The broader management surface (releases, container state, host
network config, maintenance mode) doesn't need DB persistence — those
endpoints read from / write to systemd, docker, nftables directly.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

# Certificate sources — also the operator-facing label on each
# certificate card. "uploaded" is Phase 4b.1; the other three land
# in 4b.3 / 4b.4 / 4b.5 respectively, but we put the column in now
# so we don't need a follow-up migration for an enum widening.
CERT_SOURCE_UPLOADED = "uploaded"  # operator pasted/uploaded PEM
CERT_SOURCE_CSR = "csr"  # generated locally, signed by external CA
CERT_SOURCE_LETSENCRYPT = "letsencrypt"  # issued via ACME
CERT_SOURCE_SELF_SIGNED = "self-signed"  # auto-generated on first boot


class ApplianceCertificate(Base):
    """TLS certificate for the appliance's HTTPS frontend.

    Multiple certificates can live in the table (old + new during a
    rotation, or a self-signed fallback alongside the real one). The
    ``is_active`` flag picks which one nginx serves. The activation
    endpoint enforces the invariant that at most one row carries
    ``is_active=True``; we don't use a partial unique index because
    the swap-old-for-new flow temporarily has neither/both flagged
    inside the same transaction.
    """

    __tablename__ = "appliance_certificate"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Operator-chosen label. Unique so audit log lines + UI cards can
    # refer to "letsencrypt-2026.05" without ambiguity. Distinct from
    # the certificate's subject CN — the cert might be `*.spatiumddi.io`
    # but the operator names the row "wildcard-prod" for their own
    # bookkeeping.
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)

    # How this row arrived (see the CERT_SOURCE_* constants above).
    # Stored as a plain string rather than an Enum so adding sources
    # later doesn't require a migration to widen the type.
    source: Mapped[str] = mapped_column(String(32), nullable=False)

    # PEM-encoded certificate chain. Operators paste the full chain
    # (leaf + intermediates); we don't split because nginx wants the
    # concatenated file anyway. Plain text — public material.
    #
    # NULLable since Phase 4b.3 — a CSR-pending row carries a stored
    # private key + the generated CSR but no cert yet. cert_pem stays
    # NULL until the operator pastes back the signed cert. Treat
    # ``cert_pem IS NULL`` as the canonical "CSR pending" sentinel.
    cert_pem: Mapped[str | None] = mapped_column(Text, nullable=True)

    # PEM-encoded private key, Fernet-encrypted at rest. NEVER returned
    # in any API response — only written to /etc/nginx/certs/active.key
    # on the appliance when this row becomes active. Stored separately
    # from cert_pem so we can encrypt without affecting how the cert
    # body is rendered in the UI.
    key_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # Pointer to "the one nginx serves". At most one row may have
    # is_active=True; the /tls/{id}/activate endpoint clears every
    # other row's flag before setting this one. activated_at remembers
    # the most recent activation timestamp so the UI can show "active
    # since X" without consulting the audit log.
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Identity extracted from the cert at upload time (so listing
    # doesn't need to re-parse every PEM on every request). subject_cn
    # is the leaf's CN; sans_json is the full SubjectAlternativeName
    # list (DNS names + IP addresses). issuer_cn is the CN of the
    # immediate issuer in the chain.
    #
    # For CSR-pending rows (Phase 4b.3) subject_cn + sans come from the
    # operator's CSR form (they're known up-front); issuer_cn /
    # fingerprint / validity dates aren't known until the signed cert
    # comes back, so those three are nullable.
    subject_cn: Mapped[str] = mapped_column(String(255), nullable=False)
    sans_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    issuer_cn: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # SHA-256 fingerprint of the leaf DER, hex-encoded with colons
    # (matches `openssl x509 -fingerprint -sha256` output). NULL on
    # CSR-pending rows.
    fingerprint_sha256: Mapped[str | None] = mapped_column(String(95), nullable=True)

    # NotBefore / NotAfter from the leaf cert. Used by the UI to
    # render "expires in N days" badges and by a future renewal task
    # (Phase 4b.4) to schedule Let's Encrypt rotations. NULL on
    # CSR-pending rows.
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Operator notes — purely descriptive. UI shows them on the card
    # for context ("Let's Encrypt prod cert — renew script in cron").
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Audit metadata.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    # CSR-pending state (Phase 4b.3) — when the operator clicks
    # "Generate CSR" we create a row with cert_pem and these CSR fields
    # populated, no fingerprint yet, is_active false. Once they paste
    # back the signed cert we move it into cert_pem and null the CSR
    # fields. Wired into the model now so 4b.3 doesn't need a second
    # migration; ignored by 4b.1's upload flow.
    csr_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    csr_subject: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)


class PairingCode(Base):
    """Pairing code minted by an admin so a new supervisor appliance
    can join the fleet (#169 + #170 Wave A3 reshape).

    Two flavours:

    * **Ephemeral** (``persistent=False``, today's behaviour). Single-
      use, short expiry (default 15 min). Operator mints one per
      install. Consumed via ``POST /api/v1/appliance/supervisor/
      register`` — the consume side writes a ``pairing_claim`` row
      against the new ``appliance`` and the code is dead.
    * **Persistent** (``persistent=True``). Re-usable across N
      appliances (think "the staging-fleet code"). Default no expiry;
      admin can set one. ``enabled`` toggles whether new claims are
      accepted without revoking the code. ``max_claims`` optionally
      caps the number of claims; NULL = unlimited.

    Security model:

    * Code is stored as sha256 — the cleartext is shown exactly once
      on creation and persisted nowhere. Persistent codes can be
      *re-displayed* via a password-gated reveal endpoint that rotates
      the code (mint a new cleartext + replace code_hash atomically;
      existing claims are unaffected since FKs live on ``id``).
      Ephemeral codes are NOT re-displayable — losing the cleartext
      means minting a new ephemeral code.
    * ``revoked_at`` permanently kills a code. ``enabled=False`` on
      a persistent code temporarily pauses new claims without
      losing the row.
    * Claim accounting lives in the ``pairing_claim`` child table —
      one row per (code, supervisor) successful claim. The presence
      of any claim against an ephemeral code disqualifies it from
      future claims.
    """

    __tablename__ = "pairing_code"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # sha256 hex digest of the cleartext code. UNIQUE so the consume
    # endpoint can look up by hash in O(log n) without collision risk.
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)

    # Last two digits of the cleartext code. Surfaced in the list
    # endpoint for visual correlation ("which row is the code I just
    # wrote down?"). Two digits is trivial entropy — security comes
    # from the full 8 digits + expiry + single-use, not from this.
    code_last_two: Mapped[str] = mapped_column(String(2), nullable=False)

    # Wall-clock expiry. NULL = no expiry (persistent codes default
    # to this; admin can override). Ephemeral codes always carry an
    # expiry — validated at the API layer.
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )

    # When True the code can be claimed by N appliances; when False
    # it's single-use (today's #169 default). A claim sweep at the
    # supervisor-register endpoint enforces single-use by checking
    # for any existing pairing_claim row.
    persistent: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Only meaningful for persistent=True. Admin can pause new claims
    # without deleting the code (e.g. "freeze the staging fleet code
    # until the migration finishes"). Already-claimed appliances are
    # unaffected — their cert lives on its own track.
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Optional ceiling on claims for persistent codes. NULL = unlimited.
    # Lets an operator hand out a "this code admits up to 50 boxes"
    # token without re-issuing.
    max_claims: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Fernet-encrypted cleartext of the 8-digit code. Populated ONLY
    # for persistent codes — the /reveal endpoint decrypts it after a
    # password re-check. Ephemeral codes leave this NULL (cleartext is
    # shown once on create and gone forever, matching #169 semantics).
    code_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    # #272 Phase 1 — self-bootstrap codes auto-approve on register.
    # The endpoint that mints the code (``/self-register-bootstrap``,
    # gated to the local supervisor on full-stack / frontend-core)
    # flips this to True; ``/supervisor/register`` reads it and runs
    # the cert-signing + state-flip path inline so the operator
    # doesn't have to manually approve their own local supervisor.
    # Stays False for every operator-typed pairing code minted via
    # the Fleet → Pairing tab (those keep the manual-approve flow).
    auto_approve: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa.text("false")
    )

    # Operator-driven cancellation. Independent of enabled —
    # revoking a code is permanent ("dead row"), disabling is
    # reversible ("paused"). Revoking a claimed code is a no-op for
    # already-issued certs but still useful audit signal.
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )

    # Free-form operator note, e.g. "for dns-west-2". Surfaced in the
    # codes list + audit log.
    note: Mapped[str | None] = mapped_column(String(255), nullable=True)

    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class PairingClaim(Base):
    """One row per (pairing_code, supervisor) successful claim.

    Ephemeral codes: at most one row (subsequent claim attempts hit
    the single-use gate). Persistent codes: many rows, one per
    registered supervisor. The UNIQUE(pairing_code_id, appliance_id)
    constraint makes the re-register-from-cache idempotent path
    (supervisor restarts mid-claim, retries with same pubkey) safe:
    the second call hits the existing row instead of writing a
    duplicate.

    ON DELETE CASCADE both ways — deleting a pairing code drops its
    claim audit; deleting an approved appliance drops its claim row.
    The permanent audit-log row carries the durable history.
    """

    __tablename__ = "pairing_claim"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    pairing_code_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("pairing_code.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    appliance_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("appliance.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    claimed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    claimed_from_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)


# Supervisor lifecycle states (#170 Wave A2). State machine:
#
#   pending_approval ──(admin Approve in B1)──▶ approved
#         │                                        │
#         └────────(admin Reject)─────────────┐    │
#                                             ▼    ▼
#                                          (row DELETEd, supervisor
#                                           re-bootstraps on next poll)
#
# ``rejected`` is reserved for an optional intermediate state in B1
# where admin "rejects but retains audit trail" — A2 never writes it.
APPLIANCE_STATE_PENDING_APPROVAL = "pending_approval"
APPLIANCE_STATE_APPROVED = "approved"
APPLIANCE_STATE_REJECTED = "rejected"
# #170 Wave E follow-up — soft-delete state. Heartbeats from a
# ``revoked`` row return 403, which trips the supervisor's three-
# strike revocation detector and tears down its service containers.
# Admin can Re-authorize (back to ``approved``) or Permanently
# delete (hard DELETE).
APPLIANCE_STATE_REVOKED = "revoked"
APPLIANCE_STATES = (
    APPLIANCE_STATE_PENDING_APPROVAL,
    APPLIANCE_STATE_APPROVED,
    APPLIANCE_STATE_REJECTED,
    APPLIANCE_STATE_REVOKED,
)

# #272 Phase 7 — k3s control-plane cluster membership.
CLUSTER_ROLE_PRIMARY = "primary"  # etcd seed (cluster-init); runs the control plane
CLUSTER_ROLE_MEMBER = "member"  # server node that joined the seed
CLUSTER_ROLES = (CLUSTER_ROLE_PRIMARY, CLUSTER_ROLE_MEMBER)

CLUSTER_JOIN_STATE_JOINING = "joining"  # promote in progress
CLUSTER_JOIN_STATE_READY = "ready"  # promote complete — node is a member
CLUSTER_JOIN_STATE_LEAVING = "leaving"  # demote in progress
CLUSTER_JOIN_STATE_LEFT = "left"  # demote complete — node left the cluster
CLUSTER_JOIN_STATE_FAILED = "failed"
# #590 — dead-node replace: the row awaits the seed deleting its k8s Node,
# and converges to LEFT when the seed reports the eviction. The replace
# endpoint used to stamp this as a bare "evicting" string outside the
# vocabulary, which made it invisible to anything reasoning over the set.
CLUSTER_JOIN_STATE_EVICTING = "evicting"
# Terminal states — no supervisor report will move the row on its own.
CLUSTER_JOIN_STATES_TERMINAL = (
    CLUSTER_JOIN_STATE_READY,
    CLUSTER_JOIN_STATE_LEFT,
    CLUSTER_JOIN_STATE_FAILED,
)

# Sentinel desired_cluster_role values handed to the supervisor:
# "member" → join the seed; "none" → leave the cluster + revert to a
# plain application appliance.
DESIRED_CLUSTER_ROLE_MEMBER = "member"
DESIRED_CLUSTER_ROLE_NONE = "none"


class Appliance(Base):
    """One row per supervisor that's claimed a pairing code (#170).

    The supervisor generates an Ed25519 keypair on first boot, posts
    its public key + a pairing code to
    ``POST /api/v1/appliance/supervisor/register``, and the control
    plane lands an ``Appliance`` row in ``pending_approval`` state.
    Wave B1 wires admin approval + cert signing on top.

    Identity model:

    * ``public_key_der`` is the supervisor's Ed25519 pubkey, DER-
      encoded. Stored verbatim so the B1 cert signer can re-derive
      identity material without re-parsing.
    * ``public_key_fingerprint`` is sha256(public_key_der) hex-encoded.
      UNIQUE — a supervisor that resubmits the same pubkey (typical
      restart-after-crash) hits the same row and the register endpoint
      replies "already registered" idempotently. A NEW pubkey from the
      same hostname creates a NEW row (admin sees two pending entries
      and approves the real one).

    Reject / delete semantics:

    * The state column carries ``pending_approval`` → ``approved`` /
      ``rejected``, but in practice admins drop pending or approved
      rows by DELETE — the supervisor sees its ``appliance_id`` 404
      on next poll and falls back into "waiting for pairing code"
      state. We keep the column for audit-trail-style states the B1
      / Wave-D fleet UI may want.

    No FK to ``pairing_code`` is enforced beyond ON DELETE SET NULL,
    so Wave A3's pairing-code reaper sweeping terminal codes doesn't
    take down the appliances those codes provisioned.
    """

    __tablename__ = "appliance"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    hostname: Mapped[str] = mapped_column(String(255), nullable=False)

    # Raw Ed25519 public key, DER-encoded.
    public_key_der: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # sha256(public_key_der) hex-encoded — 64 chars. Globally unique
    # across the fleet; a duplicate submission = re-register-from-cache
    # and short-circuits to "you already exist".
    public_key_fingerprint: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )

    # Version string the supervisor reports at registration and in every
    # heartbeat, e.g. "2026.09.04-1" ("dev" for an unstamped build). Used
    # by the fleet UI's needs-upgrade banner, and as the fallback when
    # ``installed_appliance_version`` is unknown (#1183).
    supervisor_version: Mapped[str | None] = mapped_column(String(64), nullable=True)

    paired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    paired_from_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Pointer at the pairing_code row that admitted this register. ON
    # DELETE SET NULL — Wave A3's pairing-code reaper sweeps old
    # terminal codes; we don't want those sweeps to take down the
    # appliances they provisioned.
    paired_via_code_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("pairing_code.id", ondelete="SET NULL"),
        nullable=True,
    )

    state: Mapped[str] = mapped_column(
        String(32), nullable=False, default=APPLIANCE_STATE_PENDING_APPROVAL
    )
    # #170 Wave E follow-up — soft-delete timestamp. Set when an
    # operator hits the Fleet UI's Delete button; the row stays so
    # an admin can Re-authorize (clear ``revoked_at`` + state back
    # to ``approved``). A retention cron hard-deletes after
    # ``platform_settings.appliance_revoked_retention_days``.
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Updated by Wave A2+'s supervisor heartbeat path. Stays NULL
    # until the supervisor's first post-register check-in.
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Wave B1 — supervisor-reported capabilities (can_run_dns_bind9,
    # has_baked_images, cpu_count, host_nics, …). Populated on
    # register + every heartbeat; the fleet UI's role picker filters
    # against this column. Free-form JSONB (no DB-side validation) so
    # additive supervisor versions don't need a migration each time
    # a new fact gets reported.
    capabilities: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )

    # sha256 of the unauth session token the supervisor uses between
    # register and approval. The register response returns the
    # cleartext once; subsequent /supervisor/poll calls present it
    # for constant-time verification. Cleared after cert issuance —
    # all post-approval calls authenticate via mTLS.
    session_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Cert lifecycle (#170 B1). Populated by the approve endpoint:
    # CA signs an X.509 cert binding the supervisor's Ed25519 pubkey
    # to the appliance_id (subject CN). 90-day default validity; the
    # supervisor auto-renews 30 days before expiry (Wave C polish).
    cert_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    cert_serial: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cert_issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cert_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Approval audit columns (the canonical state is still `state` —
    # these timestamps are for UI relative-time chips).
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejected_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )

    # Slot telemetry — #170 Wave C1 moves this off dns_server /
    # dhcp_server (the per-service agents used to report it
    # independently in #138 Phase 8f-2). The supervisor's heartbeat
    # is now the single producer; the fleet UI reads these columns
    # to drive the Upgrade affordance, slot chips, and reboot button.
    deployment_kind: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # #272 — installer role baked into ``/etc/spatiumddi/
    # role-config:ROLE``. One of ``control-plane`` / ``appliance``
    # (matches the installer wizard's two choices; legacy
    # ``full-stack`` / ``frontend-core`` / ``application`` strings from
    # pre-#272 installs are still accepted as aliases). The supervisor
    # reads the file on startup + reports the value here so the Fleet
    # UI's two-table split (Control plane vs Service agents) can
    # categorise each appliance, and the variant-aware label reconciler
    # can apply the correct per-role labels on the node. NULL on the
    # pre-#272 supervisor heartbeat
    # shape — the handler leaves the column untouched when the field
    # is missing so a stale supervisor doesn't null out its variant.
    appliance_variant: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # #1026 — the node's CPU architecture (``amd64`` / ``arm64``), from
    # the supervisor's ``uname -m``. NULL on a supervisor too old to
    # report it, and the handler leaves the column untouched when the
    # field is absent so a stale supervisor doesn't null out a value a
    # newer one already reported.
    #
    # Load-bearing rather than informational: it is one half of the gate
    # that refuses to hand this node an upgrade image built for the
    # other architecture. NULL is UNKNOWN and never matches — see
    # ``services.appliance.architecture.architecture_conflict``.
    architecture: Mapped[str | None] = mapped_column(String(16), nullable=True)
    installed_appliance_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    current_slot: Mapped[str | None] = mapped_column(String(16), nullable=True)
    durable_default: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Per-slot installed version — supervisor reads the
    # ``/var/lib/spatiumddi/release-state/slot-versions.json`` sidecar
    # maintained by ``spatium-upgrade-slot sync-versions`` (called by
    # spatiumddi-firstboot at every boot + after every apply) and ships
    # both values on every heartbeat. Lets the Fleet UI render two
    # per-slot version cards in the drilldown without falling back to
    # only knowing the currently-running slot's version.
    slot_a_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    slot_b_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_trial_boot: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa.text("false")
    )
    last_upgrade_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    last_upgrade_state_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Issue #386 Part C — tail of the host-side ``slot-upgrade.log`` the
    # supervisor ships while a slot apply is in-flight or has failed, so
    # the Fleet drilldown can show what the upgrade is actually doing
    # (download → decompress → dd → grub-patch) and the failure reason —
    # previously only the coarse ``last_upgrade_state`` chip was visible,
    # which made a failing upgrade indistinguishable from a pending one.
    # The supervisor ships ``""`` once state is ready/done so a stale tail
    # doesn't linger; NULL on non-appliance / never-reported rows.
    last_upgrade_log_tail: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Issue #386 Part C — structured per-phase progress the host runner
    # emits so the Fleet UI can render a real step-by-step status (not
    # just a log dump): ``{"step": "downloading"|"verifying"|"writing"|
    # "bootloader"|"arming"|"reboot-pending"|"done"|"failed",
    # "pct": <int|null>, "detail": "<human line>", "at": "<iso8601>"}``.
    # NULL on non-appliance / never-reported rows; the supervisor ships
    # ``{}`` once an upgrade is no longer in-flight to clear it.
    last_upgrade_progress: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    snmpd_running: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    # Issue #347 / #430 — whether the host lldpd daemon is running. Companion
    # to the lldp_neighbours set (an empty set means "no neighbours" only when
    # lldpd is up; "lldpd down" otherwise). NULL on non-appliance / pre-#430
    # rows; the heartbeat handler only overwrites on a non-None value.
    lldpd_running: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    ntp_sync_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Issue #156 — best-effort rsyslog-forwarding status the supervisor
    # reports from ``systemctl is-active rsyslog`` + config-applied
    # state. ``forwarding`` (rsyslog active + config applied) /
    # ``unreachable`` (enabled but the rsyslog unit failed/inactive) /
    # ``disabled`` (off). NULL on non-appliance / pre-#156 rows; the
    # heartbeat handler only overwrites when the supervisor sends a
    # non-None value. Fine-grained per-target omfwd reachability is
    # deferred — this is a daemon-level health signal, not a
    # destination-level probe.
    syslog_forwarding: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Issue #157 — best-effort count of authorized_keys lines the
    # supervisor's host runner actually applied to ``~admin/.ssh/
    # authorized_keys``. PER-HOST (not a global len() of the settings
    # list), like ``snmpd_running`` — surfaces in the Fleet view so an
    # operator can confirm a key push actually landed on each box. NULL
    # on non-appliance / pre-#157 rows; the heartbeat handler only
    # overwrites when the supervisor sends a non-None value.
    ssh_key_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Issue #158 — best-effort systemd-resolved state the supervisor
    # reports after applying the resolver config. ``override`` (the
    # spatiumddi.conf drop-in is applied) / ``automatic`` (no drop-in —
    # per-link NetworkManager/DHCP DNS) / ``failed`` (apply error). NULL
    # on non-appliance / pre-#158 rows; the heartbeat handler only
    # overwrites when the supervisor sends a non-None value. Per-host,
    # like ``ssh_key_count`` / ``syslog_forwarding``.
    resolver_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Issue #155 — best-effort APT host-config state the supervisor
    # reports from the host runner's .state sidecar after a validate +
    # swap: ``synced`` (config applied + apt-get update OK) /
    # ``proxy-failed`` / ``mirror-unreachable`` / ``signature-mismatch``
    # / ``no-sources`` / ``unmanaged`` (apt_managed off) / ``unknown``.
    # NULL on non-appliance / pre-#155 rows; the heartbeat handler only
    # overwrites when the supervisor sends a non-None value.
    apt_state: Mapped[str | None] = mapped_column(String(24), nullable=True)

    # Operator-driven desired state. Set via the fleet UI / API;
    # supervisor's heartbeat poll picks them up + writes the matching
    # trigger files on the appliance host. Heartbeat handler auto-
    # clears once installed catches up (upgrade) or a fresh heartbeat
    # arrives post-reboot.
    desired_appliance_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    desired_slot_image_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Issue #386 Part A — integrity + transport hints for the host-side
    # ``spatium-upgrade-slot`` runner. When the scheduler points
    # ``desired_slot_image_url`` at the appliance's OWN control-plane API
    # (an imported/uploaded upgrade image served behind the self-signed
    # web cert), the runner's bare ``urllib.urlopen`` fails TLS verify and
    # the upgrade never applies. We stamp the image's stored sha256 here +
    # set ``tls_insecure`` so the runner verifies bytes against the hash
    # (the real integrity guarantee) and skips cert-verify ONLY for that
    # self-served URL. External (public-CA) URLs leave both NULL/false and
    # stay fully verified. ``tls_insecure`` is refused host-side unless an
    # expected sha256 is present.
    desired_slot_image_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    desired_slot_image_tls_insecure: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa.text("false")
    )
    reboot_requested: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa.text("false")
    )
    reboot_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # #786 — operator asked to clear a failed upgrade. The visible failure
    # state (the ``last_upgrade_*`` columns above) is re-published from
    # host sidecar files on every heartbeat, so clearing the DB alone does
    # nothing: the next heartbeat restores it, and rebooting doesn't help
    # because those files live on the persistent /var. This flag is the
    # command that makes the *host* forget — the supervisor deletes any
    # stranded slot-upgrade trigger and resets its state/progress sidecars.
    #
    # Unlike ``reboot_requested`` this is retired by ACKNOWLEDGEMENT rather
    # than a timer: the command rides every heartbeat response until the
    # host reports a non-``failed`` state, which is exactly what a
    # successful reset produces. ``_at`` exists only for the give-up
    # backstop, not as a delivery window.
    clear_upgrade_requested: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa.text("false")
    )
    clear_upgrade_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Per-slot boot control. Operator sets one of these via the Fleet
    # UI; supervisor reads from the heartbeat response + writes the
    # matching trigger file the host runners watch.
    #
    # ``desired_next_boot_slot`` is the *one-shot* "boot this slot
    # next" intent (``grub-reboot``) — auto-reverts on the boot AFTER
    # the trial. Use to test an inactive slot or swap to it temporarily.
    # ``desired_default_slot`` is the *durable* "make this slot the
    # default" intent (``grub-set-default``) — survives subsequent
    # reboots. Use to commit a trial boot, or to durably revert.
    #
    # Both auto-clear in the heartbeat handler once the supervisor's
    # reported state matches what was requested.
    desired_next_boot_slot: Mapped[str | None] = mapped_column(String(16), nullable=True)
    desired_default_slot: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # Role assignment — #170 Wave C2. Operator picks a subset of
    # ``dns-bind9`` / ``dns-powerdns`` / ``dns-technitium`` / ``dhcp`` /
    # ``observer`` / ``custom``. The dns-* roles are mutually exclusive
    # (one DNS engine per box), enforced at the role-assignment endpoint,
    # not via a CHECK constraint (operator intent should be a one-line
    # API error, not a Postgres exception).
    assigned_roles: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa.text("'[]'::jsonb")
    )
    assigned_dns_group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_server_group.id", ondelete="SET NULL"),
        nullable=True,
    )
    assigned_dhcp_group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server_group.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Operator-defined free-form key:value (string) pairs for fleet
    # targeting. ``{"site": "prod-east", "tier": "edge"}``. No
    # semantic interpretation; consumed by future fleet-UI filters +
    # MCP `tags_match` query arg.
    tags: Mapped[dict[str, str]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=sa.text("'{}'::jsonb")
    )

    # #170 Wave C3 — free-form nftables fragment the supervisor
    # renders **after** the role-driven block in
    # /etc/nftables.d/spatium-role.nft. Empty / NULL → role-driven
    # rules only. Operator typo-rejected via ``nft -c -f`` dry-run
    # on the supervisor before live-swap; rejection never opens or
    # closes the firewall mid-render.
    firewall_extra: Mapped[str | None] = mapped_column(Text, nullable=True)

    # #170 Phase E2 — supervisor-reported host-side port conflicts.
    # Shape: ``{"udp_67": "<users-from-ss>", ...}``. Surfaces a red
    # banner on the Fleet drilldown's role-assignment section when
    # the operator's chosen DHCP server-group is in bridged mode AND
    # udp_67 is non-empty.
    port_conflicts: Mapped[dict[str, str]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=sa.text("'{}'::jsonb"),
    )

    # #989 item 3 — removable (USB) disks this node should keep mounted
    # for backups. Shape: ``[{"name": "usb1", "fs_uuid": "1234-ABCD",
    # "fstype": "exfat", "label": "BACKUP", "added_at": "<iso>"}, ...]``;
    # ``[]`` means nothing is mounted, which is also how an EJECT is
    # expressed.
    #
    # PER-APPLIANCE, unlike every other host-config plane, and that is
    # not an inconsistency: snmp / ntp / ssh / apt render from
    # ``platform_settings`` because they describe the fleet, and a USB
    # disk is plugged into exactly one node. A fleet-wide list would ask
    # every other node to mount a disk it cannot see.
    #
    # The DESIRED set only. What is actually mounted is reported back
    # inside ``cluster_health["removable"]`` (#402 pattern — stored
    # verbatim, no schema for it), because those two disagreeing is the
    # normal case whenever a disk is unplugged, and a single column
    # could not say so.
    desired_removable_mounts: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=sa.text("'[]'::jsonb"),
    )

    # #593 — the supervisor refused a firewall drop-in that would have closed
    # etcd's peer port on this node while k3s still considers it an etcd member
    # (a stale/diverged appliance row). Shape:
    # ``{"state": "refused_self_partition", "source": "control-plane"|"in-pod",
    #    "reason": "..."}``; ``{}`` when healthy.
    #
    # Detecting the divergence and only logging it would leave the node silently
    # diverged forever — the control plane keeps re-rendering the same wrong
    # body from the same row. Surfaced as a Fleet chip, like port_conflicts.
    firewall_state: Mapped[dict[str, str]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=sa.text("'{}'::jsonb"),
    )

    # #170 Wave D follow-up — outcome of the supervisor's last
    # docker-compose apply against the assigned roles. ``idle`` /
    # ``ready`` / ``failed``. ``role_switch_reason`` carries the
    # first stderr line on failures so the Fleet UI can render it
    # in the red banner.
    role_switch_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    role_switch_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # #170 Wave E — service-container watchdog payload from the
    # supervisor. Free-form ``{<compose-service>: {role, status,
    # since, container_id}}``; keyed by compose service name so a
    # mixed-role appliance can report independently for each. Empty
    # dict on observer-only / idle appliances. The Fleet drilldown
    # surfaces per-service status chips alongside the role-assignment
    # section; ``status=missing`` + a long ``since`` is the signal
    # that the watchdog's auto-heal failed.
    role_health: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )

    # #59 — host NICs the supervisor enumerated from /run/udev/data
    # (e.g. ens18, cni0; ephemeral veth* filtered out). Surfaced as the
    # appliance-vantage interface picker for packet capture so operators
    # don't have to guess the host NIC name. Reported on every
    # appliance-mode heartbeat; None until the first one lands.
    host_interfaces: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)

    # #387 — per-plane host-config apply health from the supervisor's
    # bounded-retry fire-guard. ``{<plane>: {state, attempts, at}}`` for
    # the hash-keyed host-config runners (snmp / ntp / lldp / syslog /
    # ssh / resolver / firewall / timezone), keyed by plane name; only
    # planes whose desired config is NOT yet applied appear. ``state`` is
    # ``retrying`` (transient) or ``failing`` (apply keeps failing).
    # Empty dict when every plane is applied — the Fleet drilldown shows
    # an amber/red banner only when non-empty, so a stuck apply is
    # visible instead of looping silently (the pre-#387 NTP bug).
    host_config_health: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )

    # #395 — host-migration reconcile health from the supervisor's read
    # of the ``host-patches-applied.json`` ledger. ``{<patch-id>:
    # {state, attempts, at, error?}}`` where only patches whose ``ok``
    # field is False appear; an all-applied (or pre-#395) box reports
    # ``{}``. ``state`` is always ``"failing"`` (patches are run-once-
    # per-boot — no continuous retry loop). Empty dict clears stale
    # entries once the reconcile succeeds; ``None`` (pre-#395 supervisor)
    # leaves the column untouched.
    host_migration_health: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )

    # Issue #183 Phase 4 — local k3s cluster health summary, supplied
    # by the supervisor on every heartbeat. Shape:
    # ``{"kubeapi_ready": bool, "nodes_total": int, "nodes_ready":
    # int, "pods_total": int, "pods_by_phase": {"Running": N, ...}}``.
    # Empty dict on legacy compose appliances (or k3s probe failure)
    # so the Fleet UI knows the difference between "not running k3s"
    # vs "k3s here but kubeapi wedged".
    cluster_health: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default="{}",
    )

    # Issue #183 Phase 5 — operator-facing k3s metadata.
    # ``k3s_version`` is the upstream release tag the slot was baked
    # against (e.g. ``v1.36.4+k3s1``); Fleet UI shows it on the row.
    # ``kubeconfig_encrypted`` is the supervisor-supplied admin
    # kubeconfig, Fernet-encrypted at rest. NULL until the supervisor
    # ships one (legacy compose / pre-#183 supervisors / k3s not yet
    # started).
    k3s_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    kubeconfig_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    # Issue #183 Phase 6 — k3s server-cert expiry + direct-kubeapi
    # firewall allowlist.
    #
    # ``k3s_api_cert_expires_at`` is the supervisor-reported ``Not
    # After`` of the local k3s serving cert. Drives the
    # ``k3s_api_cert_expiring`` alert rule (30 / 7 day thresholds).
    #
    # ``kubeapi_expose_cidrs`` is the operator-controlled list of
    # CIDRs allowed to reach the appliance's kubeapi on tcp/6443.
    # Empty list (the default) = proxy-only mode: kubeapi binds to
    # 127.0.0.1 + only the supervisor's outbound proxy channel can
    # drive it. Non-empty list = additional direct-network access
    # for operators who want sub-millisecond local-network ops.
    # The supervisor's firewall renderer emits one
    # ``ip saddr { ... } tcp dport 6443 accept`` rule per heartbeat.
    k3s_api_cert_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    kubeapi_expose_cidrs: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=sa.text("'[]'::jsonb"),
    )

    # ── #272 Phase 7 — control-plane cluster membership ──────────────
    # ``cluster_role`` is the appliance's settled role in the k3s
    # control-plane cluster:
    #   * ``primary``   — the etcd seed (booted ``cluster-init: true``);
    #                     also where the SpatiumDDI control plane runs.
    #   * ``member``    — a server node that joined the seed via
    #                     ``--server <url> --token <token>``.
    #   * NULL          — not a control-plane cluster member (a plain
    #                     ``application`` data-plane appliance, or a
    #                     single-node install that hasn't been promoted).
    # The promote/demote endpoints stamp ``desired_cluster_role`` +
    # the join coordinates below; the supervisor's host-side runner
    # (Phase 7b) reconfigures k3s and reports ``cluster_join_state``.
    cluster_role: Mapped[str | None] = mapped_column(String(16), nullable=True)
    desired_cluster_role: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Join coordinates handed to a node being promoted to ``member``:
    # the seed's kubeapi URL (``https://<seed-ip>:6443``) + the cluster
    # join token. Token is Fernet-encrypted at rest (it grants full
    # server join). Both NULL except while a promote is in flight; the
    # heartbeat handler clears them once the node reports ``ready``.
    desired_k3s_server_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    desired_k3s_join_token_encrypted: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True
    )
    # The seed's own join token, reported by the PRIMARY's supervisor on
    # heartbeat (read from ``/var/lib/rancher/k3s/server/token``), Fernet-
    # encrypted at rest. The promote endpoint reads this off the primary
    # row to populate ``desired_k3s_join_token_encrypted`` on each joiner.
    k3s_join_token_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Supervisor-reported progress of the in-flight join/leave:
    # ``joining`` | ``ready`` | ``leaving`` | ``failed`` | ``evicting`` |
    # NULL (idle).
    cluster_join_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cluster_join_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # #590 — when ``cluster_join_state`` last CHANGED. No cluster transition
    # has a timeout (each converges only on a supervisor report), so this is
    # the only way to tell a healthy multi-minute k3s join from one that will
    # never converge. Both the Fleet UI's "Clear stuck state" affordance and
    # the clear-cluster-state endpoint's own guard key off its age, so an
    # impatient click seconds into a normal promote can't blank the
    # desired-state out from under a running join.
    cluster_join_state_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # The node's k3s-registered InternalIP, reported by the supervisor on
    # heartbeat (``kubectl get node <self> -o …InternalIP``). This is the
    # appliance's REAL routable host IP — distinct from ``last_seen_ip``,
    # which is the supervisor POD's source IP (10.42.x.x) since it
    # heartbeats from inside the cluster. The promote endpoint builds the
    # join URL (``https://<node_ip>:6443``) from the seed's ``node_ip``; a
    # pod/service IP there is unreachable by joiners. Also the source for
    # the cross-node firewall peer set + the operator kubeconfig rewrite.
    node_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Issue #285 Phase 1 — fleet-firewall prerequisites. The supervisor
    # reports these on every heartbeat so the (future) server-side
    # firewall compiler can scope the k3s data-plane + apiserver rules
    # correctly BEFORE the LAN-wide base accept is removed. All follow
    # "only update when not None" so a legacy / pre-#285 supervisor never
    # blanks them.
    #
    # ``node_ips`` is every k3s-registered InternalIP (both families on a
    # dual-stack cluster) — distinct from the single ``node_ip`` above,
    # which stays the join-URL source. Family-split peer scoping derives
    # /32 (v4) + /128 (v6) from this list, fixing the v6-garbage-/32 bug.
    node_ips: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa.text("'[]'::jsonb")
    )
    # Pod + service CIDR the operator chose at install (#302), read from
    # the k3s ``spatium-cidrs.yaml`` drop-in. May be a comma-joined
    # dual-stack pair. The 6443 rule must accept from the pod/service CIDR
    # — in-cluster apiserver access traverses INPUT via the service-IP
    # DNAT with ``saddr=pod-IP``.
    pod_cidr: Mapped[str | None] = mapped_column(String(128), nullable=True)
    service_cidr: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # k3s data-plane backend (``vxlan`` default / ``wireguard-native`` /
    # ``host-gw`` / …). Selects the inter-node data-plane port that must
    # be peer-opened on every pod-running node before the base accept is
    # cut (vxlan → 8472/udp; wireguard-native → 51820+51821/udp).
    dataplane_backend: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Which baked ``/etc/nftables.conf`` is live on this node: a sha256
    # marker (generic change detection) + a self-describing flag for
    # whether the legacy LAN-wide ``k3s-ha`` accept is still present. Lets
    # the control plane tell a half-A/B-upgraded fleet apart from a
    # hardened one, and gates the UI "hardened" claim + compliance verdict.
    base_conf_marker: Mapped[str | None] = mapped_column(String(64), nullable=True)
    base_lanwide_k3s: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    # #272 Phase 9 — dead-node replacement. Set True by the
    # ``/control-plane/{id}/replace`` endpoint on a member that has gone
    # away ungracefully (its own supervisor can't run a leave — it's
    # dead). The SEED supervisor reads the eviction list off its
    # heartbeat response and deletes the k8s Node (k3s removes the etcd
    # member with it), then reports the hostname back so the backend
    # clears this flag + settles the row to ``left``. Distinct from a
    # graceful demote, which the leaving node drives itself.
    evict_requested: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa.text("false")
    )

    # ── #272 Phase 9b — etcd snapshot inventory + guided restore ─────
    # The SEED (primary) reports its local ``k3s etcd-snapshot list`` on
    # every heartbeat so the Fleet tab can show recoverable snapshots
    # without an operator SSH. Each entry:
    #   {"name", "location", "size" (bytes, int|null), "created_at" (ISO)}.
    # Populated only on the primary row; member / application rows stay [].
    etcd_snapshots: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa.text("'[]'::jsonb")
    )
    # The snapshot the operator asked to restore (its ``name`` from the
    # inventory). Stamped by ``POST …/control-plane/restore`` on the seed
    # row; the seed supervisor reads it on heartbeat and fires the
    # destructive host-side ``spatium-cluster-restore`` trigger (guarded
    # by a confirm marker). NULL except while a restore is in flight; the
    # heartbeat handler clears it once the runner reports ``done``.
    #
    # ⚠️ A restore is a single-node cluster-reset: k3s collapses to a
    # 1-member etcd from the snapshot and every OTHER control-plane node
    # is orphaned and must be re-paired (Replace flow). Disaster recovery
    # only — never a routine op.
    desired_restore_snapshot: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Supervisor-reported progress of the in-flight restore:
    # ``restoring`` | ``done`` | ``failed`` | NULL (idle), read from the
    # host runner's ``.state`` sidecar (mirrors ``cluster_join_state``).
    restore_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    restore_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ApplianceCA(Base):
    """Internal CA singleton (#170 Wave B1).

    One row, id=1. Carries the RSA-2048 root cert + Fernet-encrypted
    private key that signs every supervisor's identity cert. Generated
    lazily on first need (first approve attempt) so a fresh-install
    control plane that never approves a supervisor doesn't pay the
    cost.

    Lifetime: 10 years by default. The CA's own rotation is a Wave-D
    polish — not in scope here. Operators wanting to migrate to a
    new CA today would re-key every approved supervisor manually.
    """

    __tablename__ = "appliance_ca"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    subject_cn: Mapped[str] = mapped_column(String(255), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    cert_pem: Mapped[str] = mapped_column(Text, nullable=False)
    key_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ApplianceUpgradeImage(Base):
    """Upgrade image (.raw.xz) an operator makes available for an
    air-gapped appliance OS upgrade (#170 follow-up; renamed from
    ``ApplianceSlotImage`` / ``appliance_slot_image`` in #199 — the
    operator-facing concept is an "upgrade image", while "slot" stays
    the name of the lower-level A/B dd mechanism the bytes land on).

    The image arrives one of two ways: uploaded out-of-band by the
    operator (air-gap), or imported by the control plane from a GitHub
    release (connected installs — #199). Either way the bytes live on
    disk under ``/var/lib/spatiumddi/slot-images/{id}.raw.xz`` (the
    on-disk path keeps the historical ``slot-images`` name — it's pure
    storage plumbing, not operator-facing). This row carries metadata +
    SHA-256 verification + audit linkage. The supervisor downloads via
    the internal authenticated URL
    ``GET /api/v1/appliance/upgrade-images/{id}/raw.xz`` once an operator
    schedules an upgrade pointing at this row.

    SHA-256 is computed server-side on the uploaded/imported byte stream
    + verified against the expected value before the row commits —
    mismatches raise 422 and the partial file is deleted from disk. The
    hash also acts as a uniqueness anchor (UNIQUE index) so a duplicate
    upload/import short-circuits to the existing row rather than wasting
    disk.
    """

    __tablename__ = "appliance_upgrade_image"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    size_bytes: Mapped[int] = mapped_column(sa.BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    appliance_version: Mapped[str] = mapped_column(String(64), nullable=False)
    # #1026 — which architecture this image's rootfs is built for
    # (``amd64`` / ``arm64``). NULL means UNKNOWN, which every image
    # uploaded before this column existed necessarily is.
    #
    # **Not derived from the filename.** On the import path it comes from
    # the GitHub release asset we published; on the upload path the
    # operator declares it alongside ``appliance_version``, which is
    # already declared the same way. Neither is byte-level proof, and it
    # deliberately is not the last word: ``spatium-upgrade-slot``
    # re-checks the decompressed image against the node's own ``uname
    # -m`` before it commits to writing, because the control plane must
    # not be the only gate on an operation that bricks a node.
    #
    # Why not read it out of the bytes here: a slot image is a bare ext4
    # filesystem (``build-slot-image.sh`` extracts the root partition,
    # so there is no GPT to read a type GUID from) inside a
    # non-seekable xz stream. Finding ``/etc/spatiumddi/appliance-release``
    # in it means either an ext4 traversal or decompressing ~8 GiB — on
    # an upload request, for a check the host repeats anyway.
    architecture: Mapped[str | None] = mapped_column(String(16), nullable=True)
    uploaded_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="SET NULL"),
        nullable=True,
    )
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
