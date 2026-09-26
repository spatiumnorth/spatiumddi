"""Multi-node rolling-upgrade state (issue #296 Phase A).

One row per upgrade attempt — Phase A only ships the **shape** so the
table exists when Phases C/D start writing. Phase A's preflight
endpoint is read-only and does not write here; the first row gets
inserted when the operator clicks "Start upgrade" in Phase D's UI
(or POSTs the equivalent endpoint), and the row's lifecycle walks
running → succeeded | failed | halted | aborted as the orchestrator
drives per-node through cordon → drain → apply → reboot →
health-gate → uncordon.

Persisted in Postgres rather than etcd because:

* CNPG already gives us HA + backups for free — no second
  state-store to operate.
* The orchestrator's resumability story is "the next-elected api pod
  reads the row + the k8s Lease and picks up where the last one left
  off"; Postgres being read-write from every api replica matches that
  model exactly.
* Pre-flight history is operator-visible (audit + UI surfacing of
  past runs) — a row in `system_upgrade_run` shows up in the same
  list views as any other audited operation.

The cluster-wide single-upgrader mutex is **NOT** in this table —
it lives in a ``coordination.k8s.io/v1/Lease`` so it survives DB
unreachability + leases naturally to whichever api pod can renew it.
This row records *which* lease holder started the run for audit; the
lease itself is the lock.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDPrimaryKeyMixin

# Lifecycle. Phase D's ``plan_upgrade`` is the only path that creates
# a row — it runs preflight (read-only, no writes) then persists a
# ``planned`` row with the node order + the preflight findings as
# audit context. Subsequent transitions through running → succeeded |
# failed | halted | aborted are driven by the orchestrator's
# ``_transition`` helper. The preflight HTTP endpoint
# (``GET /api/v1/upgrades/preflight``) is purely read-only + never
# touches this table.
#
# Kept as a plain string column (not a pg enum) so future states
# (e.g. a ``dry_run`` for Phase G's UI preview) slot in without an
# enum-migration round-trip.
LIFECYCLE_STATES = (
    "planned",  # plan_upgrade has run; awaiting operator /start
    "running",  # at least one node has started its per-node primitive
    "succeeded",  # every node committed the new slot durably
    "failed",  # a node hit a non-recoverable error (auto-revert, DB,
    # quorum loss); orchestrator halted the rollout
    "halted",  # operator clicked Pause; resumable
    "aborted",  # operator clicked Abort; not resumable
)

# Kinds. Phase C upgrades a single node manually (operator-initiated
# rolling-equivalent for testing); Phase D is the cluster-wide rolling
# orchestrator that walks every server in order.
RUN_KINDS = (
    "cluster_rolling",
    "single_node",
)


class SystemUpgradeRun(Base, UUIDPrimaryKeyMixin):
    """One row per upgrade attempt.

    The full plan + per-node progress live in ``plan`` (JSONB) so we
    don't have to migrate the row shape every time the orchestrator
    grows a new step. ``plan`` is the single source of truth for what
    the operator approved at preflight time; ``progress`` is the
    orchestrator's running log of where it actually got. Both stay
    queryable via JSONB containment operators if we ever want to
    answer "show me every upgrade that touched node-2" cheaply.
    """

    __tablename__ = "system_upgrade_run"

    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    state: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="planned",
        index=True,
    )

    # Target version the operator is moving the cluster to. Free-form
    # release tag (``2026.06.01-1``, or SemVer from 1.0.0); the preflight
    # check validates it with ``app.core.versions``, not the column.
    target_version: Mapped[str] = mapped_column(String(64), nullable=False)

    # What's running today, captured at preflight time. We capture per-
    # node because a rolling upgrade can take 15-30 min and a node may
    # be off-cycle (slot trial-boot, recent restart) — the per-node
    # before/after picture is what we audit against.
    source_versions: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )

    # The plan + per-node progress + the structured preflight finding
    # list. See docs/SHIPPED.md (once Phase D ships) for the exact
    # shape; Phase A only writes the ``preflight`` sub-key plus an
    # empty ``per_node`` array.
    plan: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    progress: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )

    # The api pod / process that holds the upgrade Lease right now.
    # Updated by Phases C/D as the orchestrator renews. Null on a
    # ``planned`` row that hasn't started yet; null again on a
    # terminal row whose lease was released.
    lease_holder: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_acquired_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Last user-actionable error message. Free-form; the structured
    # detail lives under ``progress.last_failure``. Surfaced on the
    # Fleet UI so the operator can read it without drilling into the
    # JSONB blob.
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Who started this run. Nullable because the orchestrator may
    # re-write a row in a beat task without a user context (e.g. an
    # autoresume after the orchestrator's pod reschedule).
    started_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="SET NULL"),
        nullable=True,
    )

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    def __repr__(self) -> str:  # pragma: no cover — debug only
        return (
            f"<SystemUpgradeRun id={self.id} kind={self.kind} "
            f"state={self.state} target={self.target_version}>"
        )
