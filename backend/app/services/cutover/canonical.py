"""Canonical dataclasses shared across the cutover workflow (issue #756).

One module so parity, readiness, shadow, pre-flight, lease-handover, and the
router all agree on the same shapes — the same reason the importers keep a
``canonical.py``. Everything here is a plain dataclass with an ``as_dict()``
so it can be persisted straight into the JSONB columns on ``cutover_item``
and handed back over the API without a second translation layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

# ── Parity ─────────────────────────────────────────────────────────────

#: How a single difference between SpatiumDDI and the live Windows server is
#: explained to the operator. The distinction that matters for a migration is
#: *why* the two sides differ, not merely that they do:
#:
#: ``drifted_since_import``
#:     Windows has it, SpatiumDDI doesn't, and the SpatiumDDI object carries
#:     import provenance — so it was imported once and Windows has moved on.
#:     These are the ones a re-import (or a manual add) has to catch up.
#: ``never_imported``
#:     Windows has it, SpatiumDDI doesn't, and there is no import provenance —
#:     the object was created here by hand, or imported from somewhere else.
#:     Nothing "drifted"; it was simply never brought across.
#: ``intentionally_diverged``
#:     SpatiumDDI has it, Windows doesn't. Almost always an operator addition
#:     made after the import. Surfaced, never auto-reconciled.
#: ``value_mismatch``
#:     Both sides have the name+type, with different data. Reported as one
#:     difference rather than the missing+extra pair #61's drift report would
#:     produce, because during a migration "the value changed" is a different
#:     decision from "a record appeared".
DiffClass = Literal[
    "in_sync",
    "drifted_since_import",
    "never_imported",
    "intentionally_diverged",
    "value_mismatch",
]

#: Every non-``in_sync`` classification, in the order the UI should rank them.
DIFF_CLASSES: tuple[DiffClass, ...] = (
    "value_mismatch",
    "drifted_since_import",
    "never_imported",
    "intentionally_diverged",
)


@dataclass
class ParityDifference:
    """One explained difference between the two sides."""

    classification: DiffClass
    #: Relative record label for DNS ("@" = apex); for DHCP, the facet that
    #: differs ("lease_time", "pool", a reservation MAC, an option name).
    name: str
    #: Human-readable one-liner. Rendered verbatim in the UI.
    detail: str
    source_value: str | None = None
    target_value: str | None = None
    #: DNS record type, when the difference is about a record.
    record_type: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "name": self.name,
            "detail": self.detail,
            "source_value": self.source_value,
            "target_value": self.target_value,
            "record_type": self.record_type,
        }


@dataclass
class ParityReport:
    """Result of comparing one SpatiumDDI object to its live Windows original.

    ``status``:
        ``ok``         — the pull succeeded and the diff below is meaningful.
        ``unmatched``  — the object exists on one side only, so there is
                         nothing to diff. ``error`` says which side is missing.
        ``error``      — the pull failed (WinRM / auth / PowerShell). Never
                         raises: a failed parity check must not take down a
                         whole-plan run.
        ``unverified`` — the pull *returned*, but its result cannot be trusted
                         as an answer. The case that forces this to exist:
                         ``WindowsDNSDriver._parse_records`` logs a warning and
                         returns ``[]`` when the PowerShell output does not
                         parse, which is byte-identical to a genuinely empty
                         zone. Calling that "every record diverged" would be
                         actively misleading, and calling it "in parity" would
                         be dangerous, so it gets its own status.

    ``not_compared`` counts records the source's read path physically cannot
    report (see ``parity._comparable_record``). They are excluded from both
    ``in_sync`` and ``differences`` because a difference there says something
    about the reader, not about the two servers.
    """

    kind: str  # "dns_zone" | "dhcp_scope"
    source_ref: str
    status: str = "ok"
    error: str | None = None
    in_sync: int = 0
    not_compared: int = 0
    differences: list[ParityDifference] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def difference_count(self) -> int:
        return len(self.differences)

    @property
    def is_parity(self) -> bool:
        """True only when the pull worked *and* found nothing to reconcile.

        A failed or unmatched pull is emphatically not parity — treating
        "we couldn't check" as "it's fine" is how a migration breaks
        resolution at 2am.
        """
        return self.status == "ok" and not self.differences

    def counts_by_class(self) -> dict[str, int]:
        out: dict[str, int] = {c: 0 for c in DIFF_CLASSES}
        for d in self.differences:
            if d.classification in out:
                out[d.classification] += 1
        return out

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "source_ref": self.source_ref,
            "status": self.status,
            "error": self.error,
            "in_sync": self.in_sync,
            "not_compared": self.not_compared,
            "difference_count": self.difference_count,
            "is_parity": self.is_parity,
            "counts_by_class": self.counts_by_class(),
            "differences": [d.as_dict() for d in self.differences],
            "warnings": list(self.warnings),
        }


# ── Readiness / blockers ───────────────────────────────────────────────

#: ``"block"`` refuses the cutover outright and cannot be forced.
#: ``"warn"`` is surfaced, and can be acknowledged with ``force=true``.
BlockerSeverity = Literal["block", "warn"]

# Stable machine-readable blocker codes. The UI keys help text off these, so
# renaming one is a breaking change — add a new code instead.
BLOCKER_AD_SECURE_DDNS = "ad_secure_dynamic_update"
BLOCKER_NO_TARGET_ZONE = "no_target_zone"
BLOCKER_NO_TARGET_SCOPE = "no_target_scope"
BLOCKER_NO_SOURCE_SERVER = "no_source_server"
BLOCKER_SOURCE_ZONE_MISSING = "source_zone_missing"
BLOCKER_SOURCE_SCOPE_MISSING = "source_scope_missing"
BLOCKER_TARGET_GROUP_NO_SERVERS = "target_group_has_no_servers"
BLOCKER_MANAGED_SCOPE_ACTIVE = "managed_scope_active"
BLOCKER_PARITY_NOT_VERIFIED = "parity_not_verified"
BLOCKER_PARITY_DIFFERENCES = "parity_differences"
BLOCKER_MISSING_REVERSE_ZONE = "missing_reverse_zone"
BLOCKER_AD_NONSECURE_DDNS = "ad_nonsecure_dynamic_update"
BLOCKER_ZONE_IS_AD_INTEGRATED = "zone_is_ad_integrated"
BLOCKER_TARGET_ZONE_VIEW_SCOPED = "target_zone_view_scoped"
BLOCKER_SOURCE_SCOPE_INACTIVE = "source_scope_inactive"
BLOCKER_LEASE_HANDOVER_PENDING = "lease_handover_pending"
BLOCKER_POOL_CLASS_UNAVAILABLE = "pool_class_unavailable"


@dataclass
class Blocker:
    """One reason an item is not ready to be cut over.

    ``message`` is operator-facing and should always state the fix, not just
    the symptom — it is the only thing shown next to a refused cutover.
    """

    code: str
    severity: BlockerSeverity
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "severity": self.severity, "message": self.message}


def blocking(blockers: list[Blocker]) -> list[Blocker]:
    """Only the entries that refuse a cutover outright."""
    return [b for b in blockers if b.severity == "block"]


# ── Shadow-query comparison ────────────────────────────────────────────


@dataclass
class ShadowSample:
    """One name+type asked of both sides."""

    name: str
    qtype: str
    #: Rendered rdata, sorted + normalised, per side.
    source_answers: list[str] = field(default_factory=list)
    target_answers: dict[str, list[str]] = field(default_factory=dict)
    #: "match" | "mismatch" | "source_error" | "target_error"
    verdict: str = "match"
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "qtype": self.qtype,
            "source_answers": list(self.source_answers),
            "target_answers": {k: list(v) for k, v in self.target_answers.items()},
            "verdict": self.verdict,
            "error": self.error,
        }


@dataclass
class ShadowReport:
    zone_name: str
    source: str  # display label for the Windows server
    targets: list[str] = field(default_factory=list)
    #: Where the sampled names came from — "query_log" (real traffic) or
    #: "zone_records" (fallback). Worth surfacing: parity demonstrated against
    #: production traffic is a stronger claim than parity against our own rows.
    sample_source: str = "zone_records"
    sampled: int = 0
    matched: int = 0
    mismatched: int = 0
    errors: int = 0
    samples: list[ShadowSample] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "zone_name": self.zone_name,
            "source": self.source,
            "targets": list(self.targets),
            "sample_source": self.sample_source,
            "sampled": self.sampled,
            "matched": self.matched,
            "mismatched": self.mismatched,
            "errors": self.errors,
            "samples": [s.as_dict() for s in self.samples],
            "warnings": list(self.warnings),
        }


# ── TTL pre-flight ─────────────────────────────────────────────────────


@dataclass
class TTLRecordChange:
    record_id: str
    name: str
    record_type: str
    current_ttl: int | None
    new_ttl: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "name": self.name,
            "record_type": self.record_type,
            "current_ttl": self.current_ttl,
            "new_ttl": self.new_ttl,
        }


@dataclass
class TTLPreflightPlan:
    target_ttl: int
    zone_current: dict[str, int] = field(default_factory=dict)
    zone_after: dict[str, int] = field(default_factory=dict)
    records: list[TTLRecordChange] = field(default_factory=list)
    #: Records already at or below ``target_ttl`` — left alone.
    unchanged: int = 0
    warnings: list[str] = field(default_factory=list)
    #: What the operator must do on the Windows side, which we deliberately
    #: do not do for them. See :mod:`app.services.cutover.preflight`.
    source_side_instructions: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_ttl": self.target_ttl,
            "zone_current": dict(self.zone_current),
            "zone_after": dict(self.zone_after),
            "records": [r.as_dict() for r in self.records],
            "changed": len(self.records),
            "unchanged": self.unchanged,
            "warnings": list(self.warnings),
            "source_side_instructions": self.source_side_instructions,
        }


# ── DHCP lease handover ────────────────────────────────────────────────

#: ``create``   — will become a reservation on the managed scope.
#: ``skip``     — deliberately not carried over; ``reason`` says why.
#: ``conflict`` — carrying it over would contradict an existing reservation.
LeaseAction = Literal["create", "skip", "conflict"]


@dataclass
class LeaseHandoverEntry:
    ip_address: str
    mac_address: str
    hostname: str = ""
    action: LeaseAction = "create"
    reason: str = ""
    #: Set on commit: "created" | "skipped" | "failed".
    result: str | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "action": self.action,
            "reason": self.reason,
            "result": self.result,
            "error": self.error,
        }


@dataclass
class LeaseHandoverPlan:
    scope_cidr: str
    source_scope_id: str
    entries: list[LeaseHandoverEntry] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    #: Populated on commit.
    created: int = 0
    skipped: int = 0
    failed: int = 0

    @property
    def create_count(self) -> int:
        return sum(1 for e in self.entries if e.action == "create")

    @property
    def skip_count(self) -> int:
        return sum(1 for e in self.entries if e.action == "skip")

    @property
    def conflict_count(self) -> int:
        return sum(1 for e in self.entries if e.action == "conflict")

    def as_dict(self) -> dict[str, Any]:
        return {
            "scope_cidr": self.scope_cidr,
            "source_scope_id": self.source_scope_id,
            "entries": [e.as_dict() for e in self.entries],
            "create_count": self.create_count,
            "skip_count": self.skip_count,
            "conflict_count": self.conflict_count,
            "created": self.created,
            "skipped": self.skipped,
            "failed": self.failed,
            "warnings": list(self.warnings),
        }
