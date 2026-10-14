"""Phase 4 decommission checklist for the Windows cutover (issue #756).

The switch is the visible part of a migration; the decommission is the part
that bites weeks later. A Windows DNS server left running with scavenging on
quietly deletes the fallback copy of the zone. A DHCP server left *authorized
in Active Directory* starts answering again the first time it is patched and
rebooted, racing the managed scope for the same subnet. A conditional
forwarder on one resolver in one branch office keeps a whole site resolving
from a box everybody believes is retired.

None of that is discoverable from the cutover state, so it is a checklist: a
static catalog of the things that have to be true before the Windows side is
switched off, with per-plan state so an operator's ticks and notes persist.

Two rules shape the module:

* **The catalog is versioned code, the ticks are data.** :func:`read_checklist`
  merges the two at read time and writes nothing; a row appears only when the
  operator first ticks or annotates a line
  (:func:`upsert_checklist_row`). So a plan created three releases ago picks up
  items added since — with their current wording — without losing a tick, and
  without a page load turning into a database write.
* **Auto-checks never tick a box.** :func:`evaluate_auto_checks` returns
  advisory state next to each item. Some of the catalog is genuinely
  answerable from the database, and surfacing that saves real work, but the
  operator is the one who decides an item is done. A checklist that ticks
  itself is a checklist nobody reads.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cutover import CutoverChecklistItem, CutoverItem, CutoverPlan
from app.models.dns import DNSRecord, DNSServerOptions, DNSZone

__all__ = [
    "CHECK_STATES",
    "DECOMMISSION_CHECKLIST",
    "ChecklistSpec",
    "evaluate_auto_checks",
    "ChecklistView",
    "read_checklist",
    "upsert_checklist_row",
]


@dataclass(frozen=True)
class ChecklistSpec:
    """One catalog entry. ``key`` is the stable identity — never rename one."""

    key: str
    category: str  # dns | dhcp | ad | general
    label: str
    description: str
    applies_to: str  # dns_zone | dhcp_scope | general
    sort_order: int


#: Advisory states :func:`evaluate_auto_checks` reports.
#:
#: ``ok``             — evaluated, and nothing needs attention.
#: ``attention``      — evaluated, and something does. The detail says what.
#: ``not_applicable`` — the plan has nothing of the kind this item checks.
#: ``manual``         — not machine-answerable; the operator has to look.
STATE_OK = "ok"
STATE_ATTENTION = "attention"
STATE_NOT_APPLICABLE = "not_applicable"
STATE_MANUAL = "manual"

CHECK_STATES: frozenset[str] = frozenset(
    {STATE_OK, STATE_ATTENTION, STATE_NOT_APPLICABLE, STATE_MANUAL}
)


DECOMMISSION_CHECKLIST: tuple[ChecklistSpec, ...] = (
    # ── Active Directory ──────────────────────────────────────────────
    ChecklistSpec(
        key="dc_srv_registration",
        category="ad",
        label="Domain controllers re-registered their SRV records",
        description=(
            "Confirm every domain controller's _ldap._tcp / _kerberos._tcp / _gc._tcp SRV "
            "records resolve from the SpatiumDDI servers. This is the loudest failure mode of "
            "a DNS migration: clients locate a DC purely by SRV lookup, so if those records "
            "are missing or stale, domain logon, Group Policy and Kerberos all fail at once — "
            "and the error users see says nothing about DNS."
        ),
        applies_to="dns_zone",
        sort_order=10,
    ),
    ChecklistSpec(
        key="netlogon_dns_registration",
        category="ad",
        label="Netlogon re-registration forced on each DC",
        description=(
            "Run 'nltest /dsregdns' (or restart the Netlogon service) on every domain "
            "controller after the delegation moves, and confirm the records land. DCs "
            "otherwise only re-register on their own schedule — roughly hourly — so anything "
            "the migration did not carry across can be absent for an hour with no warning."
        ),
        applies_to="dns_zone",
        sort_order=20,
    ),
    ChecklistSpec(
        key="ad_dns_scavenging",
        category="ad",
        label="Scavenging disabled on the retired Windows zones",
        description=(
            "Turn DNS scavenging off on the Windows copies of the migrated zones. While the "
            "delegation points at SpatiumDDI the Windows zone is your rollback target, and "
            "scavenging keeps quietly deleting its aged dynamic records — so a rollback three "
            "days later restores a zone that has lost every dynamically-registered host."
        ),
        applies_to="dns_zone",
        sort_order=30,
    ),
    ChecklistSpec(
        key="ad_dynamic_update_permissions",
        category="ad",
        label="Dynamic-update sources repointed and permitted",
        description=(
            "Work out what still sends RFC 2136 / AD dynamic updates to the Windows zone and "
            "repoint it, then grant it on the SpatiumDDI zone (per-zone update ACL, by TSIG "
            "key or source address). Note the hard limit: SpatiumDDI does not implement "
            "GSS-TSIG, so a zone set to 'Secure only' on Windows cannot have its secure "
            "updates accepted here — that is why the cutover refuses such zones outright."
        ),
        applies_to="dns_zone",
        sort_order=40,
    ),
    ChecklistSpec(
        key="dhcp_ad_authorization",
        category="ad",
        label="Windows DHCP server deauthorized in Active Directory",
        description=(
            "Run 'Remove-DhcpServerInDC' for the retired server. Deactivating its scopes is "
            "not enough: an authorized Windows DHCP server that is merely idle will start "
            "answering again the first time the service restarts — a patch Tuesday reboot is "
            "all it takes — and then two servers are leasing the same subnet. "
            "Deauthorization is what makes that structurally impossible."
        ),
        applies_to="dhcp_scope",
        sort_order=50,
    ),
    # ── DNS ───────────────────────────────────────────────────────────
    ChecklistSpec(
        key="conditional_forwarders",
        category="dns",
        label="Conditional forwarders and stub zones repointed",
        description=(
            "Find every resolver holding a conditional forwarder or stub zone aimed at the "
            "Windows server and repoint it. These are configured per resolver and are "
            "invisible from the zone itself, so one missed appliance in one branch office "
            "keeps that whole site resolving from the old server — and the symptom is the "
            "worst kind: 'it works for me'."
        ),
        applies_to="dns_zone",
        sort_order=60,
    ),
    ChecklistSpec(
        key="reverse_zone_ownership",
        category="dns",
        label="Reverse zones migrated alongside their forward zones",
        description=(
            "Check that the in-addr.arpa / ip6.arpa zones covering the migrated address space "
            "moved too. A forward zone that migrates without its reverse looks completely "
            "healthy until something does a PTR lookup — mail servers, log pipelines, SSH "
            "reverse checks and some access-control lists all do, and they fail long after "
            "the change window has closed."
        ),
        applies_to="dns_zone",
        sort_order=70,
    ),
    ChecklistSpec(
        key="zone_transfer_acls",
        category="dns",
        label="Zone-transfer ACLs reviewed on the migrated zones",
        description=(
            "Review allow-transfer on each migrated zone and revoke anything that was opened "
            "for the migration itself. An imported zone can end up inheriting a permissive "
            "group default, and a zone open to AXFR from anywhere hands an attacker a "
            "complete map of the estate in one query."
        ),
        applies_to="dns_zone",
        sort_order=80,
    ),
    ChecklistSpec(
        key="wins_and_globalnames",
        category="dns",
        label="WINS / GlobalNames dependencies accounted for",
        description=(
            "Check the retired zones for WINS forward-lookup, WINS-R and GlobalNames-zone "
            "configuration. These are Windows-specific single-label resolution paths with no "
            "equivalent in BIND9, so anything still relying on them keeps working right up "
            "until the Windows server stops — and then breaks in a way that does not look "
            "like DNS at all."
        ),
        applies_to="general",
        sort_order=90,
    ),
    # ── DHCP ──────────────────────────────────────────────────────────
    ChecklistSpec(
        key="dhcp_failover_peer",
        category="dhcp",
        label="Windows DHCP failover relationship removed",
        description=(
            "Delete the failover relationship covering the migrated scopes before retiring "
            "the server. Deactivating one half of a Windows failover pair does not stop the "
            "partner: it keeps serving the subnet and keeps trying to sync scope state, so "
            "the subnet still has a second DHCP server handing out addresses."
        ),
        applies_to="dhcp_scope",
        sort_order=100,
    ),
    ChecklistSpec(
        key="resolver_dhcp_option",
        category="dhcp",
        label="DHCP option 6 (dns-servers) updated everywhere",
        description=(
            "Update every place that still hands clients the Windows resolver's address — "
            "including scopes that are not part of this plan, and any statically-configured "
            "hosts. This is the change with the longest tail: a client keeps the resolver "
            "list it was given until its lease expires, so the last stragglers can be a full "
            "lease time behind the switch."
        ),
        applies_to="general",
        sort_order=110,
    ),
    # ── General decommission ──────────────────────────────────────────
    ChecklistSpec(
        key="monitoring_alerting",
        category="general",
        label="Monitoring and alerting moved to the SpatiumDDI servers",
        description=(
            "Repoint DNS/DHCP checks, dashboards and on-call alerts at the managed servers. "
            "Until you do, the monitors keep going green against a box nobody uses while the "
            "service that actually matters is unmonitored — the outage is invisible precisely "
            "because the dashboard looks fine."
        ),
        applies_to="general",
        sort_order=120,
    ),
    ChecklistSpec(
        key="backup_retention",
        category="general",
        label="Final Windows DNS / DHCP export taken and retained",
        description=(
            "Export the Windows zones and the DHCP scope configuration one last time and "
            "store it with your change record. Once the role is removed, that export is the "
            "only remaining description of what Windows was serving; keep it at least as long "
            "as your rollback horizon."
        ),
        applies_to="general",
        sort_order=130,
    ),
    ChecklistSpec(
        key="windows_dns_service_stop",
        category="general",
        label="Windows DNS Server service stopped (not uninstalled)",
        description=(
            "Once every zone in the plan is cut over and the old TTLs have expired, stop the "
            "DNS Server service — and stop there. Stopping is the real test that nothing "
            "still depends on it, and it is reversible in seconds; removing the role is not. "
            "Leave the removal to a separate change once the zones have been quiet for a "
            "full business cycle."
        ),
        applies_to="dns_zone",
        sort_order=140,
    ),
    ChecklistSpec(
        key="windows_dhcp_service_stop",
        category="general",
        label="Windows DHCP Server service stopped after the longest lease",
        description=(
            "Wait out the longest lease time on the migrated scopes before stopping the "
            "service. A client that has not renewed still holds an address Windows issued; "
            "stopping sooner leaves it with an address, no way to renew it, and no record of "
            "it on the managed server."
        ),
        applies_to="dhcp_scope",
        sort_order=150,
    ),
)


@dataclass
class ChecklistView:
    """One checklist line as the API renders it.

    The catalog supplies the presentation (label / description / category /
    ``applies_to`` / ordering); the optional stored row supplies the operator's
    state (``is_done`` / ``done_at`` / ``notes``). Merging them at read time is
    what lets a plan created before a catalog entry existed pick it up with no
    migration and no write.
    """

    key: str
    category: str
    label: str
    description: str
    applies_to: str
    sort_order: int
    is_done: bool = False
    done_at: datetime | None = None
    notes: str = ""


def _view(spec: ChecklistSpec, row: CutoverChecklistItem | None) -> ChecklistView:
    return ChecklistView(
        key=spec.key,
        category=spec.category,
        label=spec.label,
        description=spec.description,
        applies_to=spec.applies_to,
        sort_order=spec.sort_order,
        is_done=bool(row.is_done) if row is not None else False,
        done_at=row.done_at if row is not None else None,
        notes=(row.notes or "") if row is not None else "",
    )


async def read_checklist(db: AsyncSession, *, plan: CutoverPlan) -> list[ChecklistView]:
    """The plan's checklist, merged from the catalog and any stored state.

    **Read-only.** Rows are created lazily by :func:`upsert_checklist_row` when
    the operator first ticks or annotates a line — a plan with an untouched
    checklist has no rows at all. That is deliberate: a GET that writes would
    need an ``audit_log`` entry per non-negotiable #4, and would slip a database
    write past the maintenance-mode middleware (#57), which gates on the HTTP
    method. Neither is a thing a page load should be doing.

    Keys stored on the plan but no longer in the catalog are appended at the
    end rather than dropped: they carry an operator's tick and notes, and
    silently discarding those to tidy up a list is how someone loses an audit
    finding.
    """
    rows = (
        (
            await db.execute(
                select(CutoverChecklistItem).where(CutoverChecklistItem.plan_id == plan.id)
            )
        )
        .scalars()
        .all()
    )
    by_key: dict[str, CutoverChecklistItem] = {row.key: row for row in rows}
    catalog_keys = {spec.key for spec in DECOMMISSION_CHECKLIST}

    out = [_view(spec, by_key.get(spec.key)) for spec in DECOMMISSION_CHECKLIST]
    out.extend(
        ChecklistView(
            key=row.key,
            category=row.category,
            label=row.label,
            description=row.description,
            applies_to=row.applies_to,
            sort_order=row.sort_order,
            is_done=row.is_done,
            done_at=row.done_at,
            notes=row.notes or "",
        )
        for key, row in sorted(by_key.items())
        if key not in catalog_keys
    )
    return sorted(out, key=lambda v: (v.sort_order, v.key))


async def upsert_checklist_row(
    db: AsyncSession, *, plan: CutoverPlan, key: str
) -> CutoverChecklistItem | None:
    """Return the stored row for ``key``, creating it from the catalog if needed.

    ``None`` when ``key`` is neither in the catalog nor already stored — the
    router turns that into a 404 rather than minting a row for a typo.

    Presentation fields are refreshed from the catalog on every call so improved
    wording lands without touching ``is_done`` / ``done_at`` / ``notes``.
    Flushes but does not commit; the caller owns the transaction.
    """
    row = (
        await db.execute(
            select(CutoverChecklistItem).where(
                CutoverChecklistItem.plan_id == plan.id, CutoverChecklistItem.key == key
            )
        )
    ).scalar_one_or_none()

    spec = next((s for s in DECOMMISSION_CHECKLIST if s.key == key), None)
    if spec is None:
        return row  # stored-but-retired key, or nothing at all

    if row is None:
        row = CutoverChecklistItem(
            plan_id=plan.id,
            key=spec.key,
            category=spec.category,
            label=spec.label,
            description=spec.description,
            applies_to=spec.applies_to,
            sort_order=spec.sort_order,
            is_done=False,
            notes="",
        )
        db.add(row)
    else:
        row.category = spec.category
        row.label = spec.label
        row.description = spec.description
        row.applies_to = spec.applies_to
        row.sort_order = spec.sort_order

    await db.flush()
    return row


# ── advisory auto-checks ──────────────────────────────────────────────


async def _plan_zones(db: AsyncSession, plan: CutoverPlan) -> list[DNSZone]:
    """The live DNS zones this plan's ``dns_zone`` items point at."""
    zone_ids = [
        zid
        for (zid,) in (
            await db.execute(
                select(CutoverItem.zone_id).where(
                    CutoverItem.plan_id == plan.id,
                    CutoverItem.kind == "dns_zone",
                    CutoverItem.zone_id.is_not(None),
                )
            )
        ).all()
        if zid is not None
    ]
    if not zone_ids:
        return []
    return list((await db.execute(select(DNSZone).where(DNSZone.id.in_(zone_ids)))).scalars().all())


# SRV owner prefixes a domain controller registers. Matched as a substring of
# the record's relative name, because a DC registers them both at the zone apex
# (``_ldap._tcp``) and under ``_msdcs`` / per-site labels.
_AD_SRV_MARKERS: tuple[str, ...] = ("_ldap._tcp", "_kerberos._tcp", "_gc._tcp", "_kpasswd._tcp")


async def _check_dc_srv(db: AsyncSession, zones: list[DNSZone]) -> dict[str, str]:
    """Do any of the plan's zones still carry AD service records?"""
    if not zones:
        return {"state": STATE_NOT_APPLICABLE, "detail": "This plan contains no DNS zones."}

    by_id = {z.id: z for z in zones}
    rows = (
        await db.execute(
            select(DNSRecord.zone_id, DNSRecord.name).where(
                DNSRecord.zone_id.in_(list(by_id)),
                DNSRecord.record_type == "SRV",
            )
        )
    ).all()

    hits: dict[str, int] = {}
    for zone_id, name in rows:
        label = (name or "").lower()
        if any(marker in label for marker in _AD_SRV_MARKERS):
            zone = by_id.get(zone_id)
            if zone is not None:
                hits[zone.name] = hits.get(zone.name, 0) + 1

    if not hits:
        return {
            "state": STATE_OK,
            "detail": (
                "No _ldap._tcp / _kerberos._tcp / _gc._tcp SRV records were found in this "
                "plan's zones, so no domain controller appears to locate itself through them. "
                "Confirm that matches your estate before ticking."
            ),
        }
    listed = ", ".join(f"{name} ({count})" for name, count in sorted(hits.items()))
    return {
        "state": STATE_ATTENTION,
        "detail": (
            f"AD service records live in: {listed}. Verify every domain controller has "
            "re-registered them against the SpatiumDDI servers before retiring Windows DNS."
        ),
    }


def _reverse_zone_names_for(values: list[str]) -> set[str]:
    """Map A-record values to the ``/24`` in-addr.arpa zone names covering them.

    IPv6 is intentionally not derived: an AAAA record's reverse zone boundary
    is a site convention (there is no ``/24`` equivalent), so guessing it would
    report companions that were never supposed to exist.
    """
    out: set[str] = set()
    for raw in values:
        try:
            addr = ipaddress.ip_address(str(raw).strip())
        except ValueError:
            continue
        if not isinstance(addr, ipaddress.IPv4Address):
            continue
        # "3.2.1.10.in-addr.arpa" → drop the host octet → the /24's zone name.
        pointer = addr.reverse_pointer.split(".", 1)[1]
        out.add(f"{pointer}.".lower())
    return out


def _covering(name: str, zone_names: set[str]) -> str | None:
    """The most specific of ``zone_names`` that ``name`` is equal to or under."""
    best: str | None = None
    for z in zone_names:
        if (name == z or name.endswith("." + z)) and (best is None or len(z) > len(best)):
            best = z
    return best


async def _check_reverse_zones(db: AsyncSession, zones: list[DNSZone]) -> dict[str, str]:
    """Is every reverse companion of the plan's forward zones also migrating?"""
    forward = [z for z in zones if z.kind != "reverse"]
    if not forward:
        return {
            "state": STATE_NOT_APPLICABLE,
            "detail": "This plan contains no forward DNS zones.",
        }

    in_plan = {z.name.lower() for z in zones}
    values = [
        str(v)
        for (v,) in (
            await db.execute(
                select(DNSRecord.value)
                .where(
                    DNSRecord.zone_id.in_([z.id for z in forward]),
                    DNSRecord.record_type == "A",
                )
                .limit(2000)
            )
        ).all()
    ]
    # A /24 is covered by the zone of its own name or by any wider reverse
    # zone above it: SpatiumDDI gives a /16 subnet one /16 zone (#1840), so a
    # name-equality test would report every /24 of it missing.
    wanted = {w for w in _reverse_zone_names_for(values) if _covering(w, in_plan) is None}
    if not wanted:
        return {
            "state": STATE_OK,
            "detail": (
                "Every /24 reverse zone implied by the plan's A records is already part of "
                "the plan."
            ),
        }

    # Scoped to the groups this plan's own zones live in. An unscoped lookup
    # would count a same-named reverse zone in an unrelated group (a lab, or
    # the other half of a split-horizon deployment) as "managed", and tell the
    # operator to add an existing zone to the plan when what they actually need
    # is to create one — leaving the PTR gap this check exists to catch open.
    group_ids = {z.group_id for z in zones}
    group_reverse = {
        name.lower()
        for (name,) in (
            await db.execute(
                select(DNSZone.name).where(
                    DNSZone.name.ilike("%in-addr.arpa%"),
                    DNSZone.group_id.in_(group_ids),
                )
            )
        ).all()
    }
    # Name the zone to add to the plan — the covering one, which for a /16
    # subnet is not the /24 the address implies.
    known: set[str] = set()
    unmanaged: list[str] = []
    for w in sorted(wanted):
        cover = _covering(w, group_reverse)
        if cover is None:
            unmanaged.append(w)
        else:
            known.add(cover)
    missing_from_plan = sorted(known)

    parts: list[str] = []
    if missing_from_plan:
        parts.append(
            "managed in SpatiumDDI but not in this plan: " + ", ".join(missing_from_plan[:10])
        )
    if unmanaged:
        parts.append("not present in SpatiumDDI at all: " + ", ".join(unmanaged[:10]))
    return {
        "state": STATE_ATTENTION,
        "detail": (
            "Reverse zones covering addresses in this plan's forward zones — "
            + "; ".join(parts)
            + ". PTR lookups for those addresses will not follow the cutover."
        ),
    }


async def _check_transfer_acls(db: AsyncSession, zones: list[DNSZone]) -> dict[str, str]:
    """Does any migrated zone end up transferable by anyone?

    The effective ACL is the zone's own ``allow_transfer`` when set, otherwise
    the server group's default — the same precedence the renderer uses — so a
    zone that inherits a permissive group default is caught too.
    """
    if not zones:
        return {"state": STATE_NOT_APPLICABLE, "detail": "This plan contains no DNS zones."}

    group_ids = {z.group_id for z in zones}
    group_default: dict[uuid.UUID, list] = {
        opts.group_id: list(opts.allow_transfer or [])
        for opts in (
            (
                await db.execute(
                    select(DNSServerOptions).where(DNSServerOptions.group_id.in_(group_ids))
                )
            )
            .scalars()
            .all()
        )
    }

    open_zones: list[str] = []
    for zone in zones:
        effective = zone.allow_transfer
        if effective is None:
            effective = group_default.get(zone.group_id, ["none"])
        if any(str(entry).strip().lower() == "any" for entry in effective):
            open_zones.append(zone.name)

    if not open_zones:
        return {
            "state": STATE_OK,
            "detail": "No migrated zone allows AXFR from 'any'.",
        }
    return {
        "state": STATE_ATTENTION,
        "detail": (
            "allow-transfer resolves to 'any' for: "
            + ", ".join(sorted(open_zones)[:10])
            + ". Restrict these to the secondaries that actually need AXFR."
        ),
    }


async def evaluate_auto_checks(db: AsyncSession, *, plan: CutoverPlan) -> dict[str, dict[str, str]]:
    """Advisory state for each checklist item. **Never sets ``is_done``.**

    Returns ``{key: {"state", "detail"}}`` for every catalog key, so the UI can
    render one uniform column. Most entries come back ``manual`` — they are
    about the state of a Windows box, a resolver in a branch office, or a
    monitoring system, none of which SpatiumDDI can see. The three that *are*
    answerable from our own data are evaluated properly, because they are also
    the three an operator is most likely to get wrong.
    """
    out: dict[str, dict[str, str]] = {
        spec.key: {"state": STATE_MANUAL, "detail": ""} for spec in DECOMMISSION_CHECKLIST
    }
    zones = await _plan_zones(db, plan)
    out["dc_srv_registration"] = await _check_dc_srv(db, zones)
    out["reverse_zone_ownership"] = await _check_reverse_zones(db, zones)
    out["zone_transfer_acls"] = await _check_transfer_acls(db, zones)
    return out
