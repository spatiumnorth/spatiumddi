"""Operator runbook generator for a cutover plan (issue #756).

:func:`render_runbook` turns a plan and its items into markdown that gets
pasted straight into a change ticket. It is deliberately not a summary of
what SpatiumDDI already did — it is the document the operator works from
during the window, so it carries the Windows-side PowerShell we deliberately
do **not** run for them, the exact order of operations, and a rollback with a
number attached.

Two things here are load-bearing rather than decorative:

* **The Windows-side TTL block.** SpatiumDDI lowers TTLs on its own copy of a
  zone during pre-flight, but the currently-authoritative TTLs — the ones
  resolvers are actually caching — belong to the Windows server. Lowering only
  our side is worse than lowering neither, because it produces a runbook that
  claims a five-minute rollback while the world still holds hour-long answers.
  So the block is emitted, with the item's real target TTL baked in.
* **The stated recovery time.** Every rollback section names a concrete number
  derived from that item's actual pre-flight TTL (or lease time), and says so
  when no pre-flight has been run — an unquantified "roll back if it goes
  wrong" is what turns a bad cutover into a long one.

Nothing is escaped: the output is markdown for humans, and zone names / scope
ids are DNS labels and IP addresses.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, NamedTuple

from app.drivers._winrm import ps_one_line, ps_single_quote
from app.models.cutover import CutoverItem, CutoverPlan
from app.services.cutover.canonical import ParityReport
from app.services.cutover.preflight import windows_ttl_powershell

#: Used when an item has no TTL evidence at all — matches ``DNSZone.ttl``'s
#: model default, so it is the value a freshly-created zone really carries.
#: Always rendered with an explicit "assumed" caveat.
_ASSUMED_ZONE_TTL = 3600

#: What to tell an operator to lower to when no pre-flight has run yet. Inside
#: the pre-flight's documented 30..86400 bound, and the conventional migration
#: value: short enough that a rollback lands in minutes, long enough that the
#: authoritative servers aren't answering every query twice.
_RECOMMENDED_TARGET_TTL = 300

#: Same idea for DHCP: ``DHCPScope`` leases default to a day in every driver we
#: ship, and clients first attempt renewal at T1 (half the lease).
_ASSUMED_LEASE_SECONDS = 86400

_PLACEHOLDER_DNS_HOST = "WINDOWS-DNS-SERVER"
_PLACEHOLDER_DHCP_HOST = "WINDOWS-DHCP-SERVER"


def _humanise(seconds: int) -> str:
    """``300`` → ``"5 minutes"``. Whole units only; this is prose, not a clock."""
    if seconds < 60:
        return f"{seconds} second{'s' if seconds != 1 else ''}"
    if seconds < 3600:
        minutes = seconds // 60
        rest = seconds % 60
        head = f"{minutes} minute{'s' if minutes != 1 else ''}"
        return head if rest == 0 else f"{head} {rest}s"
    if seconds < 86400:
        hours = seconds // 3600
        rest = (seconds % 3600) // 60
        head = f"{hours} hour{'s' if hours != 1 else ''}"
        return head if rest == 0 else f"{head} {rest}m"
    days = seconds // 86400
    rest = (seconds % 86400) // 3600
    head = f"{days} day{'s' if days != 1 else ''}"
    return head if rest == 0 else f"{head} {rest}h"


def _as_int(value: Any) -> int | None:
    """Coerce a JSONB-sourced number to ``int``, or ``None`` if it isn't one."""
    if isinstance(value, bool):  # bool is an int subclass; not a TTL
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _sort_key(item: CutoverItem) -> tuple[int, str]:
    """DNS first, then DHCP, each alphabetical.

    DNS leads because it is the half with a multi-hour lead time: TTLs have to
    be dropped and then *waited out* before the window opens, while a DHCP
    scope switch is instant.
    """
    return (0 if item.kind == "dns_zone" else 1, item.source_ref)


# ── evidence extraction ────────────────────────────────────────────────


def _parity_facts(
    item: CutoverItem, reports: Mapping[str, ParityReport] | None
) -> dict[str, Any] | None:
    """Best available parity evidence for an item, as a flat dict.

    A freshly-run :class:`ParityReport` passed by the caller wins; otherwise
    the persisted ``item.last_parity`` blob is used, so a runbook generated
    without re-running the checks still reports the last known state rather
    than silently claiming nothing is known.
    """
    if reports is not None:
        report = reports.get(str(item.id))
        if report is not None:
            return {
                "status": report.status,
                "error": report.error,
                "in_sync": report.in_sync,
                "difference_count": report.difference_count,
                "counts_by_class": report.counts_by_class(),
                "fresh": True,
            }
    stored = item.last_parity
    if isinstance(stored, dict):
        return {
            "status": stored.get("status"),
            "error": stored.get("error"),
            "in_sync": stored.get("in_sync"),
            "difference_count": stored.get("difference_count"),
            "counts_by_class": stored.get("counts_by_class") or {},
            "fresh": False,
        }
    return None


class _DnsTtls(NamedTuple):
    """The two different TTLs a DNS item's section needs.

    They are only the same number once the pre-flight has run: before that,
    ``target`` is what the operator is being told to lower *to* and ``recovery``
    is the long value still governing a rollback. Conflating them produces the
    two worst possible instructions — "lower this zone to 3600s" (it already is)
    and "recovery is ~5 minutes" (it is an hour).
    """

    #: What the TTL pre-flight lowers records to.
    target: int
    #: What actually governs rollback convergence right now.
    recovery: int
    lowered: bool
    #: Where ``recovery`` came from, in prose.
    provenance: str


def _dns_ttl(item: CutoverItem, propagation_seconds: Mapping[str, int] | None) -> _DnsTtls:
    """Resolve a DNS item's pre-flight target and current recovery TTL.

    Evidence, most authoritative first: an explicit ``propagation_seconds``
    entry (the caller read the live ``DNSZone.ttl``, i.e. what records are
    genuinely being served with); ``ttl_snapshot["target_ttl"]``, stamped by
    the pre-flight apply; ``ttl_snapshot["zone"]["ttl"]``, the original
    pre-lowering value; then the zone-model default, labelled as an assumption.
    """
    override = (propagation_seconds or {}).get(str(item.id))
    snapshot = item.ttl_snapshot if isinstance(item.ttl_snapshot, dict) else {}
    applied = _as_int(snapshot.get("target_ttl"))
    zone_before = snapshot.get("zone")
    original = _as_int(zone_before.get("ttl")) if isinstance(zone_before, dict) else None

    if item.ttl_lowered_at is not None:
        # Pre-flight applied: records are being served with the lowered value,
        # so target and recovery are the same number.
        if applied is not None:
            return _DnsTtls(applied, applied, True, "the TTL applied by the pre-flight")
        if override is not None:
            return _DnsTtls(override, override, True, "the zone's current TTL")
        return _DnsTtls(
            _RECOMMENDED_TARGET_TTL,
            _RECOMMENDED_TARGET_TTL,
            True,
            "an assumed value (the pre-flight recorded no target TTL)",
        )

    # No pre-flight: recovery is still governed by the long, current TTL.
    if override is not None:
        return _DnsTtls(_RECOMMENDED_TARGET_TTL, override, False, "the zone's current TTL")
    if original is not None:
        return _DnsTtls(_RECOMMENDED_TARGET_TTL, original, False, "the zone's pre-migration TTL")
    return _DnsTtls(
        _RECOMMENDED_TARGET_TTL,
        _ASSUMED_ZONE_TTL,
        False,
        "an assumed zone default, because nothing recorded the real one",
    )


def _dhcp_lease(
    item: CutoverItem, propagation_seconds: Mapping[str, int] | None
) -> tuple[int, str]:
    """``(lease_seconds, provenance)`` for a DHCP item's recovery time."""
    override = (propagation_seconds or {}).get(str(item.id))
    if override is not None:
        return override, "the scope's configured lease time"
    return _ASSUMED_LEASE_SECONDS, "an assumed 24-hour lease (supply the real one to sharpen this)"


# ── document sections ──────────────────────────────────────────────────


def _header(plan: CutoverPlan, items: Sequence[CutoverItem]) -> list[str]:
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    dns_count = sum(1 for i in items if i.kind == "dns_zone")
    dhcp_count = len(items) - dns_count
    out = [
        f"# Cutover runbook — {plan.name}",
        "",
        (
            f"Generated {generated} · plan status `{plan.status}` · "
            f"{dns_count} DNS zone(s), {dhcp_count} DHCP scope(s)"
        ),
        "",
    ]
    if plan.description.strip():
        out += [plan.description.strip(), ""]
    out += [
        "Read this end to end before the change window opens. Each item below is",
        "independent: they can be cut over one at a time, on different days, and each",
        "one rolls back on its own. There is no big-bang step anywhere in this plan.",
        "",
    ]
    if plan.notes.strip():
        out += ["**Plan notes**", "", plan.notes.strip(), ""]
    return out


def _summary_table(items: Sequence[CutoverItem]) -> list[str]:
    out = [
        "## Items",
        "",
        "| # | Kind | Windows source | Stage | Blockers |",
        "|---|---|---|---|---|",
    ]
    for n, item in enumerate(items, start=1):
        blockers = item.blockers if isinstance(item.blockers, list) else []
        blocking = sum(1 for b in blockers if isinstance(b, dict) and b.get("severity") == "block")
        warns = len(blockers) - blocking
        if blocking:
            verdict = f"**{blocking} blocking**" + (f", {warns} warning" if warns else "")
        elif warns:
            verdict = f"{warns} warning(s)"
        else:
            verdict = "none"
        kind = "DNS zone" if item.kind == "dns_zone" else "DHCP scope"
        out.append(f"| {n} | {kind} | `{item.source_ref}` | `{item.stage}` | {verdict} |")
    out.append("")
    return out


def _blocker_block(item: CutoverItem) -> list[str]:
    blockers = item.blockers if isinstance(item.blockers, list) else []
    if not blockers:
        return ["**Readiness** — no blockers recorded at generation time.", ""]
    out = ["**Readiness**", ""]
    has_block = False
    for raw in blockers:
        if not isinstance(raw, dict):
            continue
        severity = str(raw.get("severity") or "warn")
        has_block = has_block or severity == "block"
        marker = "⛔ BLOCK" if severity == "block" else "⚠️ warn"
        out.append(f"- {marker} `{raw.get('code')}` — {raw.get('message')}")
    if has_block:
        out += [
            "",
            (
                "The `BLOCK` entries above are refused by the API and cannot be forced. "
                "Clear them before the window; `force` only acknowledges warnings."
            ),
        ]
    else:
        out += [
            "",
            (
                "Warnings do not stop the cutover, but the API asks you to acknowledge "
                "them with `force`. Read each one first — that is the entire point of "
                "making you pass the flag."
            ),
        ]
    out.append("")
    return out


def _parity_block(facts: dict[str, Any] | None) -> list[str]:
    if facts is None:
        return [
            (
                "**Parity** — never checked. Run the parity check before the window; a "
                "cutover from an unverified copy is a guess."
            ),
            "",
        ]
    status = facts.get("status")
    if status == "error":
        return [f"**Parity** — last check failed: {facts.get('error')}", ""]
    if status == "unmatched":
        return [
            f"**Parity** — the object exists on one side only ({facts.get('error')}).",
            "",
        ]
    diffs = facts.get("difference_count") or 0
    freshness = "checked for this runbook" if facts.get("fresh") else "last recorded check"
    if not diffs:
        return [f"**Parity** — in sync ({facts.get('in_sync')} objects matched, {freshness}).", ""]
    counts = facts.get("counts_by_class") or {}
    detail = ", ".join(f"{v} {k}" for k, v in counts.items() if v)
    out = [f"**Parity** — {diffs} difference(s) ({freshness}).", ""]
    if detail:
        out += [f"Breakdown: {detail}.", ""]
    out += [
        (
            "Reconcile these before cutting over, or accept them explicitly — each one is "
            "an answer that changes the moment traffic moves."
        ),
        "",
    ]
    return out


def _ps_lower_ttls(host: str, zone: str, ttl: int, current_ttl: int) -> list[str]:
    """Fence the canonical Windows-side TTL script for the runbook.

    The script itself lives in :func:`app.services.cutover.preflight.windows_ttl_powershell`
    and is *not* duplicated here: the same commands are also returned inline on
    every pre-flight preview and apply, and handing an operator two subtly
    different versions of the same step is how one of them ends up wrong.
    """
    block = windows_ttl_powershell(zone, ttl, current_ttl, computer_name=host)
    return ["```powershell", *block.rstrip("\n").split("\n"), "```", ""]


def _ps_disable_scavenging(host: str, zone: str) -> list[str]:
    host, zone = ps_one_line(host), ps_one_line(zone)
    return [
        "```powershell",
        "# Scavenging deletes 'stale' dynamically-registered records. Once clients",
        "# start registering against SpatiumDDI instead, Windows sees its own copies",
        "# stop refreshing and begins deleting them — during a parallel run that",
        "# silently empties the zone you are still falling back to. Turn it off",
        "# BEFORE the parallel run starts, not after.",
        f"$Server = {ps_single_quote(host)}",
        "",
        "Set-DnsServerScavenging -ComputerName $Server -ScavengingState $false -ApplyOnAllZones",
        f"Set-DnsServerZoneAging -ComputerName $Server -Name {ps_single_quote(zone)} -Aging $false",
        "",
        "# Verify",
        "Get-DnsServerScavenging -ComputerName $Server",
        f"Get-DnsServerZoneAging -ComputerName $Server -Name {ps_single_quote(zone)}",
        "```",
        "",
    ]


def _ps_scope_state(host: str, scope_id: str, *, active: bool) -> list[str]:
    host, scope_id = ps_one_line(host), ps_one_line(scope_id)
    state = "Active" if active else "InActive"
    return [
        "```powershell",
        "# Manual equivalent of what SpatiumDDI does for you. The Windows enum value",
        "# is 'InActive' — one word, capital A.",
        f"Set-DhcpServerv4Scope -ComputerName {ps_single_quote(host)} -ScopeId {ps_single_quote(scope_id)} -State {state}",
        f"Get-DhcpServerv4Scope -ComputerName {ps_single_quote(host)} -ScopeId {ps_single_quote(scope_id)} |",
        "    Select-Object ScopeId, Name, State, LeaseDuration",
        "```",
        "",
    ]


def _ps_deauthorize_dhcp(host: str) -> list[str]:
    host = ps_one_line(host)
    return [
        "```powershell",
        "# Deauthorize the Windows DHCP server in Active Directory. Until this runs,",
        "# the server is still an authorized DHCP source in the forest and will",
        "# happily start serving again after a reboot or a service restart.",
        "# Needs Enterprise Admins, or delegated rights on the NetServices container.",
        "",
        "Get-DhcpServerInDC      # what AD authorizes today — note the exact DnsName/IPAddress",
        "",
        f"Remove-DhcpServerInDC -DnsName {ps_single_quote(host)} -IPAddress '<the IP listed above>'",
        "",
        "Get-DhcpServerInDC      # confirm it is gone",
        "```",
        "",
    ]


# ── per-item sections ──────────────────────────────────────────────────


def _dns_section(
    n: int,
    item: CutoverItem,
    *,
    facts: dict[str, Any] | None,
    host: str,
    ttls: _DnsTtls,
) -> list[str]:
    zone = item.source_ref
    out = [f"### {n}. DNS zone `{zone}`", ""]
    out += _parity_block(facts)
    out += _blocker_block(item)

    applied_note = (
        " (already applied — re-running is a no-op for records at or below the target)"
        if ttls.lowered
        else ""
    )
    out += [
        "#### Pre-flight",
        "",
        "1. Confirm parity (above). Reconcile or consciously accept every difference.",
        "2. Turn off scavenging and aging on the Windows side, if it is on.",
        "",
    ]
    out += _ps_disable_scavenging(host, zone)
    out += [
        f"3. Run the TTL pre-flight in SpatiumDDI to lower this zone to {ttls.target}s"
        f"{applied_note}. The original values are snapshotted, so the restore is exact.",
        f"4. Lower the **Windows-side** TTLs to the same {ttls.target}s. SpatiumDDI does "
        "not do this for you — the Windows copy is the one resolvers are caching right "
        "now, and lowering only our side buys nothing.",
        "",
    ]
    out += _ps_lower_ttls(host, zone, ttls.target, ttls.recovery)
    if ttls.lowered:
        step5 = (
            "5. Confirm the short TTL is actually being served before you rely on it — "
            f"`dig +noall +answer {zone} SOA` against both sides should show {ttls.target}. "
            "A cache that fetched an answer just before step 4 still holds the old value "
            "until that older TTL elapses."
        )
    else:
        step5 = (
            f"5. Wait out the **old** TTL ({_humanise(ttls.recovery)}) before continuing. "
            "Caches that fetched an answer just before step 4 keep it for the old "
            f"duration; until that has elapsed, the {_humanise(ttls.target)} recovery "
            "time below is not real yet."
        )
    out += [
        step5,
        (
            "6. Run the shadow comparison and confirm the managed servers answer identically "
            "to Windows for real production query names."
        ),
        "",
        "#### The switch",
        "",
        (
            "SpatiumDDI owns no server-side switch for DNS — the switch is the delegation "
            "or forwarder change, and it lives on the parent zone or on the resolvers."
        ),
        "",
        (
            "1. Point the delegation (parent-zone NS records) or the resolver forwarders at "
            "the SpatiumDDI servers for this zone."
        ),
        (
            "2. Record the transition in SpatiumDDI (the item's **Cut over** action). It "
            "stamps the item, writes the audit + timeline rows, and refuses if any blocking "
            "readiness issue is still present."
        ),
        "3. Verify from a client subnet, not just from the DNS host:",
        "",
        "```bash",
        f"dig +norecurse @<spatiumddi-server-ip> {zone} SOA",
        f"dig {zone} NS      # resolved through the production resolver path",
        "```",
        "",
        "#### Rollback",
        "",
        "1. Revert the delegation / forwarder change made in step 1 of the switch.",
        "2. Restore the TTLs from the snapshot (the item's **Restore TTLs** action).",
        "",
    ]
    if ttls.lowered:
        applied_at = (
            item.ttl_lowered_at.strftime("%Y-%m-%d %H:%M UTC")
            if item.ttl_lowered_at is not None
            else "an unrecorded time"
        )
        out += [
            f"**Recovery time: ~{_humanise(ttls.recovery)} ({ttls.recovery}s)** once the "
            f"delegation is reverted — that is {ttls.provenance}, and the pre-flight was "
            f"applied at {applied_at}. Every resolver holding an answer from the "
            "SpatiumDDI servers drops it within that window and re-queries.",
            "",
        ]
    else:
        out += [
            f"**Recovery time: up to {_humanise(ttls.recovery)} ({ttls.recovery}s)** — the "
            "TTL pre-flight has NOT been run for this item, so recovery is governed by "
            f"{ttls.provenance}. That number is the real length of a bad cutover. Run the "
            f"pre-flight (step 3) and wait out the old TTL, and it drops to "
            f"~{_humanise(ttls.target)}.",
            "",
        ]
    return out


def _dhcp_section(
    n: int,
    item: CutoverItem,
    *,
    facts: dict[str, Any] | None,
    host: str,
    lease_seconds: int,
    lease_provenance: str,
) -> list[str]:
    scope = item.source_ref
    t1 = max(lease_seconds // 2, 1)
    out = [f"### {n}. DHCP scope `{scope}`", ""]
    out += _parity_block(facts)
    out += _blocker_block(item)

    handover = item.lease_handover if isinstance(item.lease_handover, dict) else None
    out += ["#### Pre-flight", ""]
    out += [
        (
            "1. Confirm parity (above): pools, exclusions, reservations, lease time and "
            "options must all match before any client is asked to renew against Kea."
        ),
        (
            "2. Confirm the managed scope is still **inactive**. During the parallel run the "
            "SpatiumDDI scope must be structurally unreachable — two DHCP servers answering "
            "on one broadcast domain is a coin flip, not a migration."
        ),
        (
            "3. Run the **lease handover**. It turns every live Windows lease into a "
            "reservation on the managed scope, so a client renewing against Kea gets back the "
            "address it already holds instead of a fresh one from an empty pool."
        ),
        "",
    ]
    if handover:
        out += [
            (
                f"   Last handover: {handover.get('created', 0)} created, "
                f"{handover.get('skipped', 0)} skipped, {handover.get('failed', 0)} failed "
                f"({handover.get('at', 'time not recorded')})."
            ),
            "",
        ]
    else:
        out += ["   Not run yet for this item.", ""]

    out += [
        "#### The switch",
        "",
        "This one SpatiumDDI performs, atomically and in this order:",
        "",
        f"1. Deactivate the scope on the Windows server (`{host}`).",
        "2. Activate the managed scope and wake the DHCP agents.",
        "",
        (
            "The order is the whole point — the old server stops answering before the new one "
            "starts, so the two never race. If step 2 fails, step 1 is reversed automatically."
        ),
        "",
    ]
    out += _ps_scope_state(host, scope, active=False)
    out += [
        (
            "Verify by watching a real client renew (`ipconfig /renew`, or `dhclient -v`), and "
            "confirm the offered address matches the reservation carried over in pre-flight."
        ),
        "",
        "#### Rollback",
        "",
        "1. Deactivate the managed scope.",
        f"2. Reactivate the Windows scope on `{host}`.",
        "",
    ]
    out += _ps_scope_state(host, scope, active=True)
    out += [
        f"**Recovery time: ~{_humanise(t1)} ({t1}s), up to {_humanise(lease_seconds)} "
        f"({lease_seconds}s)** — derived from {lease_provenance}. Clients first try to "
        "renew at T1, half the lease, and a client that renewed moments before the "
        "rollback waits until then. Nothing breaks in the meantime: an already-issued "
        "lease stays valid for its full duration regardless of which server issued it, "
        "which is why the lease handover in pre-flight matters so much — the addresses "
        "are identical on both sides, so a rollback is invisible to the client.",
        "",
    ]
    return out


def _decommission_section(dns_host: str, dhcp_host: str, *, has_dhcp: bool) -> list[str]:
    out = [
        "## After the window — decommission",
        "",
        (
            "Work the plan's decommission checklist in the UI; it tracks the ticks and notes "
            "per plan. Two steps are worth having the exact command for."
        ),
        "",
        "### Deauthorize the Windows DHCP server in AD",
        "",
    ]
    if has_dhcp:
        out += _ps_deauthorize_dhcp(dhcp_host)
    else:
        out += ["This plan migrates no DHCP scopes; nothing to deauthorize.", ""]
    out += [
        "### Stop the Windows services (only after a full soak)",
        "",
        "```powershell",
        "# Stop and disable rather than uninstall — the role, its zone data and its",
        "# scope database stay on disk, which is what makes a late rollback possible.",
        "Stop-Service -Name DNS -Force ; Set-Service -Name DNS -StartupType Disabled",
        (
            "Stop-Service -Name DHCPServer -Force ; Set-Service -Name DHCPServer "
            "-StartupType Disabled"
        ),
        "```",
        "",
        f"Run those on `{dns_host}` / `{dhcp_host}` respectively. Do not uninstall the "
        "roles until the checklist is complete and the plan has soaked for at least one "
        "full DHCP lease cycle.",
        "",
    ]
    return out


# ── public entry point ─────────────────────────────────────────────────


def render_runbook(
    plan: CutoverPlan,
    items: Sequence[CutoverItem],
    reports: Mapping[str, ParityReport] | None = None,
    *,
    source_dns_host: str | None = None,
    source_dhcp_host: str | None = None,
    propagation_seconds: Mapping[str, int] | None = None,
) -> str:
    """Render the operator runbook for ``plan`` as markdown.

    ``reports`` maps ``str(item.id)`` to a freshly-computed
    :class:`~app.services.cutover.canonical.ParityReport`. It is optional: any
    item without a fresh report falls back to its persisted ``last_parity``
    blob, so a runbook generated without re-running the checks still states the
    last known parity rather than claiming nothing is known.

    ``source_dns_host`` / ``source_dhcp_host`` are interpolated into the
    PowerShell blocks. When omitted, an obvious placeholder is emitted instead
    — the plan row carries only FK ids, so the caller is the one that knows the
    hostnames.

    ``propagation_seconds`` maps ``str(item.id)`` to the item's real
    propagation constant: the zone's currently-served TTL for a DNS item, the
    scope's lease time for a DHCP item. Supplying it is what makes the stated
    recovery time exact rather than derived from the pre-flight snapshot.
    """
    ordered = sorted(items, key=_sort_key)
    dns_host = source_dns_host or _PLACEHOLDER_DNS_HOST
    dhcp_host = source_dhcp_host or _PLACEHOLDER_DHCP_HOST

    lines: list[str] = []
    lines += _header(plan, ordered)

    if not ordered:
        lines += [
            (
                "This plan has no items yet. Run **Discover** against the source Windows "
                "servers and add the zones / scopes you intend to migrate, then regenerate "
                "this runbook."
            ),
            "",
        ]
        return "\n".join(lines).rstrip() + "\n"

    lines += _summary_table(ordered)

    blocked = [
        i
        for i in ordered
        if any(
            isinstance(b, dict) and b.get("severity") == "block"
            for b in (i.blockers if isinstance(i.blockers, list) else [])
        )
    ]
    if blocked:
        lines += [
            "> **Do not open the change window yet.** "
            f"{len(blocked)} item(s) carry a blocking readiness issue and the cutover "
            "endpoint will refuse them. See the Readiness list under each item.",
            "",
        ]

    lines += ["## Per-item procedure", ""]
    for n, item in enumerate(ordered, start=1):
        facts = _parity_facts(item, reports)
        if item.kind == "dns_zone":
            lines += _dns_section(
                n,
                item,
                facts=facts,
                host=dns_host,
                ttls=_dns_ttl(item, propagation_seconds),
            )
        else:
            lease_seconds, lease_provenance = _dhcp_lease(item, propagation_seconds)
            lines += _dhcp_section(
                n,
                item,
                facts=facts,
                host=dhcp_host,
                lease_seconds=lease_seconds,
                lease_provenance=lease_provenance,
            )

    lines += _decommission_section(
        dns_host, dhcp_host, has_dhcp=any(i.kind == "dhcp_scope" for i in ordered)
    )
    return "\n".join(lines).rstrip() + "\n"
