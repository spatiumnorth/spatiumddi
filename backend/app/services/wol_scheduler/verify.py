"""Post-wake liveness verify + stagger auto-tune for Scheduled Wake-on-LAN
— Phase 3 (issue #586), multi-source liveness (issue #596).

After a run dispatches magic packets (:mod:`app.services.wol_scheduler.dispatch`)
an optional chained Celery task
(:func:`app.tasks.wol_scheduler.verify_wol_run`) probes each SENT host for
liveness and re-wakes the non-responders up to a bound. This module holds the
pure-ish building blocks that task orchestrates:

* :func:`probe_liveness` — is a host up, per an **active** probe (``ping`` or
  ``tcp``)? Returns ``(up, method_used)``. Never raises: a probe error / missing
  binary / timeout is a ``down`` verdict, never an aborted verify pass.
* :func:`seen_since` — the **passive** check. Which of these hosts were observed
  on the network *since the wake fired*? Reads ``IPAddress.last_seen_at`` — the
  column the SNMP ARP/FDB cross-reference, DHCP lease pulls, nmap, ping/ARP
  discovery and passive L2 fingerprinting all already stamp. Emits no traffic.
  Batched (one query per pass); the ``wol_wake_failed`` alert matcher reuses it.
* :func:`verify_run_targets` — probe the still-unverified SENT targets of a run
  under the schedule's ``verify_method``, stamp their ``wol_run_target`` verify
  columns, stamp the Seen infra (``IPAddress.last_seen_at`` /
  ``last_seen_method``) on **active** responders, and return the down set (the
  re-wake candidates). Does **not** commit — the caller owns the transaction.
  Idempotent: only touches not-yet-UP rows, so a double-fire re-probes the same
  rows to the same verdict without side effects.
* :func:`auto_stagger_ms` — the stagger auto-tune: turns a resolved target count
  into a suggested inter-host gap so a large fleet doesn't inrush /
  PXE-thundering-herd. An explicit operator ``stagger_ms`` always wins.

**The four methods** (``wol_schedule.verify_method``):

===========  ========  ==================================================
method       class     semantics
===========  ========  ==================================================
``ping``     active    ICMP echo. The v1 behaviour; ICMP-blocked hosts
                       (Windows default firewall) read as down.
``tcp``      active    connect-or-RST on a small port set. A refused
                       connection proves the host is up.
``seen``     passive   ``last_seen_at >= run.started_at``. Emits nothing;
                       works from a worker with no route to the segment.
``auto``     both      ``ping`` → ``tcp`` → ``seen``, first UP wins and
                       short-circuits. Costs one ping on a live host.
===========  ========  ==================================================

**Active and passive are deliberately asymmetric.** An active probe may return
either verdict. A passive probe may only ever *confirm* liveness — it never
asserts "down", because "no sighting" is equally consistent with "the SNMP
poller hasn't run yet". This is what makes ``auto`` safe to default to: a
passive source can shrink the down set but never grow it.

**The wake anchor kills the stale-cache false-up.** The passive check compares
``last_seen_at`` against ``run.started_at``, so a sighting recorded *before* the magic packet
went out — a week-old ARP entry, a lease from yesterday — can never be mistaken
for evidence that *this wake* worked. Only a sighting strictly after the wake
counts, and it is precisely that sighting the operator would have looked for by
hand.

**A passive confirm never re-stamps Seen.** The sighting was already recorded by
whichever subsystem actually observed the host; claiming "we pinged it just now"
would be a lie. Only an active UP verdict writes ``last_seen_at``.

**Vantage decision (active probes are server-vantage ONLY).**
``probe_liveness`` takes a ``vantage`` for signature/forward-compat but always
probes from the control-plane server, *regardless of the wake vantage*.
Appliance-vantage active verify is deferred:
:mod:`app.services.appliance.agent_cmd` is an in-memory, per-replica dispatch —
the supervisor long-polls the **api** process while the verify task runs in the
**worker**, so there is no worker→supervisor result-return path today. For an
appliance-vantage *wake*, an active probe still runs from the server; that is
correct when the api/worker can reach the target segment (routed ICMP /
directed broadcast) and, when it can't, yields a false-negative (unverified) —
never a false wake. **``seen`` sidesteps the vantage problem entirely**: it is a
pure DB read, so it works for a host on a segment the worker cannot reach at
all, as long as some other subsystem (an SNMP poll of the local switch, a DHCP
lease) observed it. A worker→supervisor result channel remains the named
follow-up for active appliance-vantage probes.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import structlog
from sqlalchemy import select, update

from app.models.ipam import IPAddress
from app.models.wol_schedule import WolRunTarget

# Same connect/RST probe + port set the IPAM discovery sweep uses, so a host that
# reads as alive to a discovery scan reads as alive to a wake verify.
from app.services.ipam.discovery import _TCP_PROBE_PORTS, _tcp_alive
from app.services.ipam.probe_policy import check_probe_target
from app.services.nettools.runner import run_ping

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession

    from app.models.wol_schedule import WolRun

logger = structlog.get_logger(__name__)

# Probe methods. These are the accepted values of ``wol_schedule.verify_method``
# (String(16)) and of the per-target ``wol_run_target.verify_method``, which
# records the source that actually settled the verdict — never the ``auto``
# keyword, so the History chip stays honest about *how* a host was confirmed.
VERIFY_METHOD_PING = "ping"
VERIFY_METHOD_TCP = "tcp"
VERIFY_METHOD_SEEN = "seen"
VERIFY_METHOD_AUTO = "auto"

# Active probes emit traffic and may return either verdict. Passive probes read
# a sighting some other subsystem already recorded and may ONLY confirm — see
# the module docstring's asymmetry note.
ACTIVE_METHODS = (VERIFY_METHOD_PING, VERIFY_METHOD_TCP)
PASSIVE_METHODS = (VERIFY_METHOD_SEEN,)

# What each schedule-level method expands to, in evaluation order. The first
# source returning UP wins and short-circuits the remainder, so ``auto`` costs a
# single ping against a live ICMP-responsive host and only pays for the extra
# sources on hosts that would otherwise have been re-woken for nothing.
_METHOD_CHAINS: dict[str, tuple[str, ...]] = {
    VERIFY_METHOD_PING: (VERIFY_METHOD_PING,),
    VERIFY_METHOD_TCP: (VERIFY_METHOD_TCP,),
    VERIFY_METHOD_SEEN: (VERIFY_METHOD_SEEN,),
    VERIFY_METHOD_AUTO: (VERIFY_METHOD_PING, VERIFY_METHOD_TCP, VERIFY_METHOD_SEEN),
}
VERIFY_METHODS = tuple(_METHOD_CHAINS)

# Packets per probe. Two keeps each probe fast (``run_ping`` caps it with a 15 s
# ``-w`` deadline) while papering over a single dropped reply — a freshly-woken
# host that answers the 2nd packet still reads as up.
_PING_COUNT = 2

# Per-port connect timeout for the TCP probe. ``_tcp_alive`` walks the port list
# sequentially and returns early on the first connect-or-RST, so a live host is
# fast; a fully-filtered host pays ``len(_TCP_PROBE_PORTS) × this`` in the worst
# case, which is why the probes fan out under ``_PROBE_CONCURRENCY``.
_TCP_PROBE_TIMEOUT = 1.0

# Bound on concurrent in-flight probes. The probe pass is network-bound ICMP, so
# fanning out the pings (then serialising the DB writes after) collapses the
# wall-clock of a large fleet verify from N × seconds to ~ceil(N/concurrency) ×
# seconds while staying well within the worker's resources. Idempotency is
# order-independent (each row's verdict is self-contained), so concurrency is
# safe here.
_PROBE_CONCURRENCY = 32

# Human-readable ``detail`` for each active source's evidence entry, keyed
# [method][up]. The operator's question on a down host is "down according to
# what?", and these are the answers.
_ACTIVE_DETAIL: dict[str, dict[bool, str]] = {
    VERIFY_METHOD_PING: {True: "ICMP reply received", False: "no ICMP reply"},
    VERIFY_METHOD_TCP: {
        True: "TCP connected or refused (host answered)",
        False: "no TCP port connected or refused",
    },
}


def _active_detail(method: str, up: bool) -> str:
    """Detail string for an active probe's evidence entry — never raises.

    A method absent from :data:`_ACTIVE_DETAIL` (a new active source added to
    ``_METHOD_CHAINS`` without a matching entry) falls back to a generic phrasing
    rather than a ``KeyError`` inside the gathered probe coroutine, which — being
    outside ``verify_run_targets``'s error handling — would otherwise wedge the
    run pending↔verifying until the retry bound.
    """
    return _ACTIVE_DETAIL.get(method, {}).get(up, "host answered" if up else "no response")


def _evidence(source: str, up: bool, detail: str, observed_at: datetime) -> dict[str, Any]:
    """One entry in a target's ``verify_evidence`` trail.

    ``observed_at`` is when the evidence was observed: for an active probe, when
    *we* checked; for a passive ``seen`` confirmation, the sighting time itself
    (the observation *is* the sighting). Kept structured so the UI can format /
    localize it — the ``detail`` string never embeds a timestamp.
    """
    return {
        "source": source,
        "up": up,
        "detail": detail,
        "observed_at": observed_at.isoformat(),
    }


def auto_stagger_ms(target_count: int, override: int = 0) -> int:
    """Suggested inter-host stagger (ms) for a resolved wake of ``target_count``.

    ``override`` is the schedule's stored ``stagger_ms``:

    * ``override > 0`` — an explicit operator value; returned verbatim (the
      operator's ramp always wins, we never override an override).
    * ``override == 0`` — "auto": ramp large fleets to cap the power-inrush +
      DHCP/PXE thundering-herd a same-second all-at-once fire would create. A
      small set still fires immediately (returns 0).

    Bands (host count → ms gap), tuned against the resolver's 512 fan-out cap:

    ======================  =========  ==================
    resolved target count   stagger    approx wakes/sec
    ======================  =========  ==================
    ≤ 20                    0          all-at-once
    21 – 100                50         ~20/s
    101 – 256               100        ~10/s
    > 256 (up to 512)       150        ~6–7/s
    ======================  =========  ==================

    Pure + side-effect-free — the same helper feeds the beat runner's dispatch,
    the verify re-wake pass, and the ``preview-targets`` surface's
    ``suggested_stagger_ms`` (call with ``override=0`` for the raw suggestion).
    """
    if override > 0:
        return override
    if target_count <= 20:
        return 0
    if target_count <= 100:
        return 50
    if target_count <= 256:
        return 100
    return 150


async def probe_liveness(
    address: str | None,
    vantage: dict[str, Any] | None = None,
    *,
    method: str = VERIFY_METHOD_PING,
) -> tuple[bool, str]:
    """Run one **active** probe against ``address``, returning ``(up, method_used)``.

    ``method`` selects the probe:

    * ``ping`` (default) — server-vantage ICMP via :func:`run_ping`; ``up`` is
      ``exit_code == 0`` (ping exits 0 iff ≥1 reply).
    * ``tcp`` — connect-or-RST across :data:`_TCP_PROBE_PORTS` via
      :func:`app.services.ipam.discovery._tcp_alive`. A ``ConnectionRefusedError``
      counts as UP: the host answered, it just isn't listening there. This is what
      makes ``tcp`` resilient to an ICMP-blocking host firewall.

    A passive method (or any unknown value) falls back to ``ping`` rather than
    raising — passive sources are not probed here, they go through
    :func:`seen_since`. A missing binary, a timeout, or *any* exception is a
    ``down`` verdict: this function NEVER raises, so one un-probeable host can't
    abort a verify pass over a fleet.

    ``vantage`` is accepted for signature/forward-compat but ignored (active
    probes are server-vantage only — see the module docstring). The returned
    method is the probe that actually ran, so the persisted
    ``wol_run_target.verify_method`` is an honest record of *how* the host was
    checked, independent of the wake vantage.
    """
    probe_method = method if method in ACTIVE_METHODS else VERIFY_METHOD_PING
    if not address:
        return False, probe_method
    try:
        if probe_method == VERIFY_METHOD_TCP:
            up = await _tcp_alive(address, _TCP_PROBE_PORTS, _TCP_PROBE_TIMEOUT)
        else:
            result = await run_ping(address, count=_PING_COUNT)
            up = result.exit_code == 0 and not result.timed_out
    except Exception as exc:  # noqa: BLE001 — a probe error is a "down" verdict.
        logger.debug("wol_verify_probe_error", address=address, method=probe_method, error=str(exc))
        return False, probe_method
    return up, probe_method


async def _seen_map(
    db: AsyncSession,
    ip_address_ids: list[uuid.UUID],
    since: datetime,
) -> dict[uuid.UUID, datetime]:
    """``{ip_address_id: last_seen_at}`` for those observed at/after ``since``.

    One batched query for a whole verify pass — never a per-row ``db.get``. Rows
    whose ``last_seen_at`` is NULL (never observed) or older than the wake are
    simply absent. The timestamps feed the per-target evidence trail; callers who
    only need membership use :func:`seen_since`.
    """
    if not ip_address_ids:
        return {}
    rows = await db.execute(
        select(IPAddress.id, IPAddress.last_seen_at).where(
            IPAddress.id.in_(ip_address_ids),
            IPAddress.last_seen_at.is_not(None),
            IPAddress.last_seen_at >= since,
        )
    )
    # ``last_seen_at IS NOT NULL`` is in the WHERE; the filter is for mypy.
    return {row[0]: row[1] for row in rows.all() if row[1] is not None}


async def seen_since(
    db: AsyncSession,
    ip_address_ids: list[uuid.UUID],
    since: datetime,
) -> set[uuid.UUID]:
    """The subset of ``ip_address_ids`` observed on the network at/after ``since``.

    Public because the ``wol_wake_failed`` alert matcher re-runs this same passive
    check on every evaluator tick, so an alert auto-resolves as stragglers boot and
    some other subsystem records the sighting.
    """
    return set(await _seen_map(db, ip_address_ids, since))


async def verify_run_targets(
    db: AsyncSession,
    run: WolRun,
    attempt: int,
    *,
    method: str = VERIFY_METHOD_PING,
) -> list[WolRunTarget]:
    """Probe the still-unverified SENT targets of ``run`` and stamp the result.

    One verify pass:

    1. Select ``wol_run_target`` rows for this run that were ``sent`` and are
       not yet UP (``verified IS NULL`` — never probed — OR ``verified IS
       FALSE`` — probed down on a previous pass, a re-wake candidate). Rows that
       were skipped/failed at dispatch (``sent = false``) are never probed and
       keep ``verified = NULL``.
    2. Expand ``method`` into its source chain (:data:`_METHOD_CHAINS`) and walk
       it per row, first-UP-wins:

       * **Active** sources (``ping`` / ``tcp``) need ``row.address`` and run
         concurrently, bounded by :data:`_PROBE_CONCURRENCY`. A row's whole
         active chain holds one slot, so ``auto`` doesn't double-book the pool.
       * The **passive** source (``seen``) needs ``row.ip_address_id`` and is
         resolved from a single batched query issued *after* the fan-out, over
         only the rows no active probe confirmed — never a per-row read inside a
         gathered coroutine (asyncpg sessions are not concurrency-safe). A pass
         where every host answered actively touches the DB not at all.

    3. Stamp each row a source could actually run against: ``verified``,
       ``verified_at = now``, and ``verify_method`` = the source that settled it
       (never the ``auto`` keyword). A row **no source could run against** — no
       address under an active-only method, no IPAM row under ``seen`` — is left
       ``verified = NULL``: honestly "not checked", neither UP nor a re-wake
       candidate, exactly as an address-less row behaved before multi-source.
    4. On an **active** UP verdict, stamp the Seen infra on the linked
       ``IPAddress`` (``last_seen_at = now``, ``last_seen_method`` = the winning
       active method) — mirroring
       :func:`app.services.ipam.discovery.reconcile_subnet`. A **passive** UP
       never re-stamps (the sighting is already recorded by its real source), and
       a DOWN verdict proves nothing about liveness, so neither touches Seen.
    5. Record ``verify_evidence`` — the ordered trail of every source consulted
       on this pass, with each source's verdict and a human-readable detail. It
       answers the operator's real question about a down host: *down according to
       what?* A pass that re-probes a row overwrites the trail, so it always
       describes the most recent verdict.

    Returns the down set (``verified = False`` this pass) — the caller's re-wake
    candidates. Because the chain is first-UP-wins, a richer ``method`` can only
    ever *shrink* the down set relative to ``ping``; it can never manufacture a
    re-wake. Does **not** commit or bump ``wake_attempts`` (the orchestrating
    task owns the transaction, the re-wake, and the attempt bookkeeping).
    Idempotent: only not-yet-UP rows are touched, so a re-run re-probes to the
    same verdict without double-counting.
    """
    chain = _METHOD_CHAINS.get(method, _METHOD_CHAINS[VERIFY_METHOD_PING])
    active_chain = [m for m in chain if m in ACTIVE_METHODS]
    passive = VERIFY_METHOD_SEEN in chain

    rows = list(
        (
            await db.execute(
                select(WolRunTarget)
                .where(WolRunTarget.run_id == run.id)
                .where(WolRunTarget.sent.is_(True))
                .where((WolRunTarget.verified.is_(None)) | (WolRunTarget.verified.is_(False)))
            )
        )
        .scalars()
        .all()
    )
    # A row is actionable if SOME source in the chain can run against it: an
    # address for the active probes, an IPAM row for the passive one.
    probeable = [
        r for r in rows if (active_chain and r.address) or (passive and r.ip_address_id is not None)
    ]
    if not probeable:
        logger.info(
            "wol_verify_pass_noop",
            run_id=str(run.id),
            attempt=attempt,
            method=method,
            candidate_rows=len(rows),
        )
        return []

    # Fragile-device suppression (#722). Resolved up front, before the
    # fan-out, because the gather is deliberately DB-free — and it has to
    # be a *set of addresses* rather than a per-row check for the same
    # reason. Only the ACTIVE chain is suppressed: the passive path below
    # reads sightings that already happened, so a suppressed host can
    # still be verified without a packet being sent at it. Waking a
    # fragile device is fine; poking it to confirm is not.
    suppressed_addresses: set[str] = set()
    if active_chain:
        for row in probeable:
            if not row.address:
                continue
            address = str(row.address)
            if address in suppressed_addresses:
                continue
            if (await check_probe_target(db, address)).blocked:
                suppressed_addresses.add(address)
    if suppressed_addresses:
        logger.info(
            "wol_verify_active_suppressed",
            run_id=str(run.id),
            attempt=attempt,
            suppressed=len(suppressed_addresses),
        )

    # Fan out the active probes (network-bound); no DB access inside the gather.
    sem = asyncio.Semaphore(_PROBE_CONCURRENCY)

    async def _probe_active(
        row: WolRunTarget,
    ) -> tuple[WolRunTarget, bool, str | None, list[dict[str, Any]]]:
        """Walk the row's active chain, short-circuiting on the first UP.

        Returns ``(row, up, last_source_tried, evidence_trail)``. The trail holds
        one entry per source actually consulted — so a short-circuit on ping
        records only ping, and the operator can tell "we never needed TCP" apart
        from "TCP said nothing".
        """
        trail: list[dict[str, Any]] = []
        if not row.address or not active_chain:
            return row, False, None, trail
        if str(row.address) in suppressed_addresses:
            # Not "down" — unprobed. Falls through to the passive read
            # with an empty trail, which is the honest record: we never
            # asked, so we have no active evidence either way.
            return row, False, None, trail
        async with sem:
            for m in active_chain:
                up, used = await probe_liveness(row.address, run_vantage_of(row), method=m)
                # Stamp each entry with when THIS probe ran, not the pass start —
                # a large fleet's fan-out spans minutes, so a shared pass-start
                # time would misdate the trail.
                trail.append(_evidence(used, up, _active_detail(used, up), datetime.now(UTC)))
                if up:
                    return row, True, used, trail
        return row, False, active_chain[-1], trail

    results = await asyncio.gather(*(_probe_active(r) for r in probeable))
    # Verdict time — captured AFTER the fan-out, so verified_at, the passive
    # "no sighting" observed_at, and the Seen re-stamp all reflect when we
    # actually finished checking rather than a pass-start instant minutes stale.
    now = datetime.now(UTC)

    # The passive read runs AFTER the fan-out: safe (no coroutines are in flight,
    # so the session is single-threaded again) and genuinely short-circuiting —
    # if every host answered an active probe we never issue the query at all. One
    # batched statement for the whole down set, never a per-row read. Anchored to
    # the wake instant so a pre-wake sighting can't confirm this run (seen_since).
    seen_at: dict[Any, datetime] = {}
    if passive:
        unconfirmed = [
            row.ip_address_id
            for row, up, _tried, _trail in results
            if not up and row.ip_address_id is not None
        ]
        if unconfirmed:
            seen_at = await _seen_map(db, unconfirmed, run.started_at)

    non_responders: list[WolRunTarget] = []
    # ip_address_id → winning ACTIVE method, for the Seen re-stamp below.
    active_up: dict[Any, str] = {}
    for row, up, tried, trail in results:
        if up and tried is not None:
            row.verified = True
            row.verified_at = now
            row.verify_method = tried
            row.verify_evidence = trail or None
            if row.ip_address_id is not None:
                active_up[row.ip_address_id] = tried
            continue

        # No active source confirmed. The passive source may still confirm — but
        # never condemn: an abstention (no IPAM row) falls through to whatever the
        # active chain already concluded.
        if passive and row.ip_address_id is not None:
            sighting = seen_at.get(row.ip_address_id)
            row.verified = sighting is not None
            row.verified_at = now
            row.verify_method = VERIFY_METHOD_SEEN
            # For a confirmed sighting the observation IS the sighting, so
            # ``observed_at`` carries the real last-seen time (structured, so the
            # UI can format it); a miss records the verdict time (when we ran the
            # passive check, after the fan-out).
            trail.append(
                _evidence(
                    VERIFY_METHOD_SEEN,
                    sighting is not None,
                    (
                        "seen on the network since the wake"
                        if sighting is not None
                        else "no sighting since the wake"
                    ),
                    sighting if sighting is not None else now,
                )
            )
            row.verify_evidence = trail
            if not row.verified:
                non_responders.append(row)
            continue

        if tried is not None:
            # An active source ran and said down.
            row.verified = False
            row.verified_at = now
            row.verify_method = tried
            row.verify_evidence = trail or None
            non_responders.append(row)
        # else: nothing could run against this row — leave verified = NULL and
        # verify_evidence untouched (no source ran, so there is nothing to record).

    # Batch-stamp the Seen infra on every ACTIVE responder's IPAddress. Passive
    # confirmations are excluded by construction: their sighting is already on the
    # row. Two guards against a stale write:
    #   * ``now`` is the post-fan-out verdict time (not a pass-start instant), so
    #     it reflects when the host actually answered rather than when the pass
    #     began.
    #   * the UPDATE only ADVANCES last_seen_at (``last_seen_at IS NULL OR <
    #     now``), so a fresher sighting a concurrent poller committed mid-fan-out
    #     is never clobbered backwards. Guarding in SQL (not on loaded rows) keeps
    #     it correct against a commit that landed after our SELECT snapshot.
    # Grouped by winning method (≤ 2: ping / tcp) so last_seen_method stays
    # consistent with the timestamp it's written beside.
    if active_up:
        by_method: dict[str, list[Any]] = {}
        for ip_id, m in active_up.items():
            by_method.setdefault(m, []).append(ip_id)
        for m, ip_ids in by_method.items():
            await db.execute(
                update(IPAddress)
                .where(
                    IPAddress.id.in_(ip_ids),
                    (IPAddress.last_seen_at.is_(None)) | (IPAddress.last_seen_at < now),
                )
                .values(last_seen_at=now, last_seen_method=m)
            )

    logger.info(
        "wol_verify_pass",
        run_id=str(run.id),
        attempt=attempt,
        method=method,
        probed=len(probeable),
        up=len(probeable) - len(non_responders),
        down=len(non_responders),
    )
    return non_responders


def run_vantage_of(row: WolRunTarget) -> dict[str, Any] | None:
    """The ``{kind, id}`` a target was woken from (per-row snapshot).

    Passed to :func:`probe_liveness` for forward-compat only — v1 probes
    server-vantage regardless. Kept as a tiny helper so the appliance-vantage
    verify follow-up has a single, obvious seam to thread a real per-segment
    probe vantage through.
    """
    return row.vantage


__all__ = [
    "ACTIVE_METHODS",
    "PASSIVE_METHODS",
    "VERIFY_METHODS",
    "VERIFY_METHOD_AUTO",
    "VERIFY_METHOD_PING",
    "VERIFY_METHOD_SEEN",
    "VERIFY_METHOD_TCP",
    "auto_stagger_ms",
    "probe_liveness",
    "seen_since",
    "verify_run_targets",
    "run_vantage_of",
]
