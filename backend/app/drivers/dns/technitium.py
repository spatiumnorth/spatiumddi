"""Technitium DNS Server driver.

Technitium is the third authoritative DNS driver SpatiumDDI ships,
alongside BIND9 and PowerDNS. Each ``DNSServerGroup`` is single-driver;
mixed installs work via multiple groups (see ``docs/drivers/DNS_DRIVERS.md``
§5.1).

Technitium is entirely HTTP-API driven (``/api/zones/*``,
``/api/zones/records/*``) with bearer-token auth — closer in shape to
PowerDNS than to BIND9's config-file-plus-RFC2136 model, but with an even
thinner control-plane footprint: Technitium has no equivalent of
``pdns.conf`` for zone/record state at all (zones live entirely in its own
internal store, managed exclusively through the API), so this driver's
``render_zone_config``/``render_zone_file`` produce previews only — the
real reconcile-against-API logic lives in the agent-side driver under
``agent/dns/spatium_dns_agent/drivers/technitium.py``.

Scope (this driver):

* Primary / secondary / stub / forward zones, standard record CRUD, and
  catalog-zone membership via the Technitium REST API. The agent
  generates a permanent API token on first boot
  (``POST /api/user/createToken``) and is the only caller — the control
  plane formulates ``RecordChange`` ops and the agent translates them to
  ``/api/zones/records/{add,update,delete}`` calls.
* Validate the bundle (zone names end with ".", record types from the
  supported set, zone types from ``_SUPPORTED_ZONE_TYPES``, secondary /
  stub zones carry primaries to transfer from, no views).

Landed after the v1 cut, so the sections below are no longer "deferred":
online DNSSEC signing (#740), native DNS-over-TLS/HTTPS/QUIC listeners plus
encrypted *upstream* forwarding over all three (#741 — a real differentiator
over both PowerDNS, which needs a dnsdist sidecar and cannot forward at all,
and BIND9, which forwards over DoT only), secondary / stub / catalog zones
and TSIG transfer (#743), and the ``dns_import`` live-pull + native blocklist
wiring (#744).

Still outstanding (tracked in the roadmap, not this driver):

* Query-log shipping — issue #742. Technitium's query log is API/DB-backed
  (``/api/logs/query*``) rather than a tailable file, so it needs a
  poll-and-diff shipper instead of the file-tailing ``QueryLogShipper``.
* ANAME / APP / FWD record types (Technitium-proprietary, different shape
  than PowerDNS's ALIAS/LUA — not a drop-in equivalent).

CLAUDE.md non-negotiable #10: this driver speaks only neutral
``ConfigBundle`` / ``RecordChange`` types. Technitium specifics live inside
``render_server_config`` / ``apply_record_change`` and the agent-side driver.
"""

from __future__ import annotations

from typing import Any

import structlog

from app.core.dns_names import strip_control_chars
from app.drivers.dns.base import (
    ConfigBundle,
    DNSDriver,
    DynamicUpdateCaps,
    EffectiveBlocklistData,
    RecordChange,
    RecordData,
    ServerOptions,
    TsigKey,
    ZoneData,
)

logger = structlog.get_logger(__name__)


# Zone types the driver can create (issue #743). Technitium's own names
# are Primary / Secondary / Stub / Forwarder; the mapping lives agent-side
# in ``_ZONE_TYPE_MAP``. Catalog zones are handled out-of-band via the
# group's catalog block, not as a per-zone type an operator picks.
_SUPPORTED_ZONE_TYPES = frozenset({"primary", "secondary", "stub", "forward"})

# Record types the Technitium driver supports in v1, taken from Technitium's
# documented `/api/zones/records/add` type list. ANAME / FWD / APP are
# Technitium-proprietary and deliberately excluded — they aren't a drop-in
# equivalent of PowerDNS's ALIAS/LUA and need their own design pass.
# DNSSEC-adjacent types (DS, DNSKEY, RRSIG, NSEC*) stay out until online
# signing (fast-follow) lands, except DS which operators may set by hand for
# manual parent-side delegation independent of signing — held back anyway
# for v1 simplicity and revisited alongside DNSSEC.
_SUPPORTED_RECORD_TYPES = frozenset(
    {
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "TXT",
        "NS",
        "PTR",
        "SRV",
        "CAA",
        "TLSA",
        "SSHFP",
        "NAPTR",
        "URI",
        "SOA",
        "SVCB",
        "HTTPS",
        "DNAME",
    }
)


def _record_payload(zone: ZoneData, rr: RecordData) -> dict[str, Any]:
    """Compose the neutral JSON projection of one record for the preview /
    hash-stable rendering. Field names mirror Technitium's
    ``/api/zones/records/add`` parameters (``ipAddress``, ``cname``,
    ``exchange``/``preference``, ``priority``/``weight``/``port``/``target``,
    ``text``) so the agent-side reconciler can consume this shape directly.
    """
    rtype = rr.record_type.upper()
    value = strip_control_chars(rr.value).rstrip(".")
    payload: dict[str, Any] = {"ttl": rr.ttl or zone.ttl}
    if rtype in ("A", "AAAA"):
        payload["ipAddress"] = value
    elif rtype == "CNAME":
        payload["cname"] = value
    elif rtype == "MX":
        payload["exchange"] = value
        payload["preference"] = rr.priority if rr.priority is not None else 10
    elif rtype == "SRV":
        payload["target"] = value
        payload["priority"] = rr.priority if rr.priority is not None else 0
        payload["weight"] = rr.weight if rr.weight is not None else 0
        payload["port"] = rr.port if rr.port is not None else 0
    elif rtype == "TXT":
        payload["text"] = strip_control_chars(rr.value)
    elif rtype == "NS":
        payload["nameServer"] = value
    elif rtype == "PTR":
        payload["ptrName"] = value
    else:
        payload["value"] = strip_control_chars(rr.value)
    return payload


def _qualified_record_name(zone: ZoneData, rr: RecordData) -> str:
    """Return the FQDN (no trailing dot — Technitium's own convention) for
    the record's ``domain`` field."""
    zone_name = zone.name.rstrip(".")
    name = strip_control_chars(rr.name)
    if name in ("", "@") or name == zone_name:
        return zone_name
    return f"{name}.{zone_name}"


class TechnitiumDriver(DNSDriver):
    """Technitium DNS Server driver (v1 — primary zones + record CRUD).

    Daemon lifecycle + apply runs inside the agent; the control-plane apply
    path is a no-op (agent-based driver, like BIND9 / PowerDNS).
    """

    name = "technitium"

    # ── Rendering ─────────────────────────────────────────────────────────

    def render_server_config(
        self,
        server: Any,
        options: ServerOptions,
        *,
        bundle: ConfigBundle | None = None,
    ) -> str:
        """Render a preview of the settings the agent pushes via
        ``POST /api/settings/set`` on first boot.

        Technitium has no on-disk config file equivalent to ``named.conf``/
        ``pdns.conf`` for this driver's v1 scope — the daemon is configured
        entirely through its API. This preview exists so
        ``GET /servers/{id}/config`` has something representative to show;
        the agent's bearer token never reaches the control plane.
        """
        import json

        return json.dumps(
            {
                "dnsServer": "technitium",
                "api_token": "<agent-generated>",
                "recursion": "disabled",
                "listen_port": 53,
            },
            indent=2,
        )

    def render_zone_config(self, zone: ZoneData) -> str:
        """Technitium stores zones in its own internal store, not as
        per-zone config stanzas. Zones are managed via the REST API.
        Return an empty string so the bundle hash stays stable across
        drivers.
        """
        return ""

    def render_zone_file(self, zone: ZoneData, records: list[RecordData]) -> str:
        """Render a JSON projection of the zone the agent uses to drive the
        Technitium REST API (``/api/zones/records/add`` et al.).

        Deliberately not an RFC 1035 zone file — Technitium wants
        record-by-record API calls. Returns a stable, sorted JSON string so
        the bundle ETag is deterministic.
        """
        import json

        zone_name = zone.name.rstrip(".")

        entries: list[dict[str, Any]] = []
        for r in records:
            entries.append(
                {
                    "domain": _qualified_record_name(zone, r),
                    "type": r.record_type.upper(),
                    **_record_payload(zone, r),
                }
            )
        entries.sort(key=lambda e: (e["domain"], e["type"]))

        return json.dumps(
            {
                "zone": zone_name,
                "type": "Primary",
                "records": entries,
            },
            sort_keys=True,
            indent=2,
        )

    def render_rpz_zone(self, blocklist: EffectiveBlocklistData) -> str:
        """Technitium has its own native blocklist/ad-blocking apps, but
        wiring SpatiumDDI's blocklist model to them is deferred. Returns an
        empty string so groups with blocklists still hash deterministically;
        the agent skips applying blocklist data on Technitium hosts.
        """
        return ""

    # ── Runtime (agent-side; control plane only formulates) ──────────────

    async def apply_record_change(self, server: Any, change: RecordChange) -> None:
        """Control-plane no-op. The agent runs the actual
        ``/api/zones/records/{add,update,delete}`` call."""
        logger.info(
            "technitium.apply_record_change.formulated",
            server=str(getattr(server, "id", "")),
            zone=change.zone_name,
            op=change.op,
            name=change.record.name,
            type=change.record.record_type,
        )

    async def reload_config(self, server: Any) -> None:
        """Technitium has no global config reload — settings changes apply
        live via the API. Control-plane no-op."""
        logger.info("technitium.reload_config", server=str(getattr(server, "id", "")))

    async def reload_zone(self, server: Any, zone_name: str) -> None:
        """Zone state is always current via the API — no explicit reload
        step. Control-plane no-op."""
        logger.info(
            "technitium.reload_zone",
            server=str(getattr(server, "id", "")),
            zone=zone_name,
        )

    async def pull_zone_records(
        self, server: Any, zone_name: str, *, tsig: TsigKey | None = None
    ) -> list[RecordData]:
        """AXFR the zone off the Technitium host, for the #61 drift report.

        Technitium's own REST API would be the more natural source — it is
        exactly what the live-pull importer reads — but that API listens on
        loopback :5380 inside the agent's container and is reachable only
        by the co-located agent. The control plane can only talk to the
        server over DNS, so drift goes over AXFR, the same path BIND9 uses.

        **This requires the zone to permit transfer to the control plane.**
        Since #734 the agent grants a signed transfer whenever the group has
        a TSIG key — ``zoneTransfer="Allow"`` plus ``zoneTransferTsigKeyNames``,
        which Technitium reads as "any source, but the transfer must be
        signed by one of these keys". So ``tsig`` must carry that key. The
        operator's own ``allow_transfer`` ACL still applies on top when they
        set one.

        Without a key the AXFR is REFUSED, and the drift row surfaces that
        rather than silently reporting "no drift" — an empty diff from a
        refused transfer would be far worse than an error, because it reads
        as "in sync".
        """
        from app.drivers.dns._axfr import axfr_zone_records  # noqa: PLC0415

        host = getattr(server, "host", None)
        if not host:
            raise RuntimeError("TechnitiumDriver.pull_zone_records: server.host is required")
        port = getattr(server, "port", None) or 53
        try:
            return await axfr_zone_records(
                host=host,
                port=port,
                zone_name=zone_name,
                log_driver="technitium",
                server_id=str(getattr(server, "id", "")),
                tsig=tsig,
            )
        except Exception as exc:
            # A bare "REFUSED" tells the operator nothing about what to do.
            # Name the setting that governs it, and distinguish the two very
            # different reasons a Technitium transfer gets declined.
            #
            # Only for the DNS answer, though (#1470). A TCP "Connection
            # refused" carries the same word, and ``axfr_zone_records``
            # already reports it as unreachable with the right hint — read
            # as a refused transfer it sent the operator to the TSIG key on
            # a server nobody could open a socket to (an appliance whose
            # Technitium answers only on the DNS VIP, not the node address).
            if isinstance(exc.__cause__, OSError):
                raise
            if "REFUSED" in str(exc).upper():
                if tsig is None:
                    raise RuntimeError(
                        f"{host} refused the zone transfer for {zone_name!r}. Drift "
                        "reads the live zone over AXFR, which the agent permits only "
                        "for a TSIG-signed transfer — and this server's group has no "
                        "TSIG key, so the control plane had nothing to sign with. "
                        "Create a TSIG key on the group, or set the group's 'allow "
                        "transfer' to permit the control plane by address."
                    ) from exc
                raise RuntimeError(
                    f"{host} refused the zone transfer for {zone_name!r} despite "
                    f"signing it with the group key {tsig.name!r}. Check that the "
                    "agent has applied the current config bundle — the key must "
                    "exist on the Technitium server and be named in the zone's "
                    "transfer settings."
                ) from exc
            raise

    # ── Validation / capabilities ─────────────────────────────────────────

    def validate_config(self, bundle: ConfigBundle) -> tuple[bool, list[str]]:
        errors: list[str] = []
        seen: set[tuple[str | None, str]] = set()
        for z in bundle.zones:
            if not z.name.endswith("."):
                errors.append(f"zone {z.name!r}: name must end with '.'")
            key = (z.view_name, z.name)
            if key in seen:
                errors.append(f"duplicate zone {z.name!r} in view {z.view_name!r}")
            seen.add(key)
            if z.zone_type not in _SUPPORTED_ZONE_TYPES:
                errors.append(
                    f"zone {z.name!r}: zone_type {z.zone_type!r} not supported by "
                    f"the Technitium driver (supported: "
                    f"{', '.join(sorted(_SUPPORTED_ZONE_TYPES))})"
                )
            # A secondary/stub with nowhere to transfer from cannot be
            # created at all — Technitium resolves SOA against the primaries
            # at create time. Catch it here so the operator gets a 422 on
            # save rather than a zone that silently never appears.
            if z.zone_type in ("secondary", "stub") and not z.masters:
                errors.append(
                    f"zone {z.name!r}: zone_type {z.zone_type!r} requires at least "
                    "one primary name-server address to transfer from"
                )
            if z.zone_type == "forward" and not z.forwarders:
                errors.append(f"zone {z.name!r}: forward zones require at least one forwarder")
            for r in z.records:
                rtype = r.record_type.upper()
                if rtype not in _SUPPORTED_RECORD_TYPES:
                    errors.append(
                        f"zone {z.name!r}: record type {rtype!r} not supported "
                        f"by the Technitium driver"
                    )
        if bundle.views:
            errors.append(
                "Technitium driver does not support views — create a "
                "separate group per view (issue #24)"
            )
        if bundle.blocklists:
            # Not an error — just a notice. Agent will skip blocklist apply.
            logger.info(
                "technitium.bundle_has_blocklists_skipping",
                count=len(bundle.blocklists),
            )
        return (not errors, errors)

    def capabilities(self) -> dict[str, Any]:
        return {
            "name": "technitium",
            "views": False,
            "rpz": False,
            "dnssec_inline_signing": True,  # issue #740 — online signing
            "incremental_updates": "rest_api",
            "zone_types": sorted(_SUPPORTED_ZONE_TYPES),
            "record_types": sorted(_SUPPORTED_RECORD_TYPES),
            "alias_records": False,
            "lua_records": False,
            "catalog_zones": True,
        }

    @property
    def dynamic_update_caps(self) -> DynamicUpdateCaps:
        # v1: no dynamic-update (RFC 2136) surface wired for Technitium —
        # all record mutation flows through the agent's queued record-op
        # reconciler, not a client-facing UPDATE listener. Revisit if
        # Technitium's own RFC 2136 support (it has one) gets wired up.
        return DynamicUpdateCaps()


__all__ = ["TechnitiumDriver"]
