"""PowerDNS Authoritative driver.

PowerDNS-Authoritative is the second authoritative driver SpatiumDDI
ships, alongside BIND9 and (since issue #746) Technitium. They run
side-by-side: each ``DNSServerGroup`` is single-driver, mixed installs
work via multiple groups (issue #127).

Phase 1 scope (this driver):

* Render ``pdns.conf`` for the agent — backend selection (LMDB by
  default), API-key auth, listen addresses, log level. The agent
  generates the API key on first boot and shares it between
  ``pdns_server`` and the agent process.
* Apply zone + record state via the PowerDNS REST API
  (``http://127.0.0.1:8081/api/v1/servers/localhost/...``). The agent
  is the only caller; the control plane formulates ``RecordChange``
  ops and the agent translates them to PATCH calls.
* Validate the bundle (zone names end with ".", record types from
  the supported set, no duplicate (view, name) pairs).

Out of scope until Phase 2/3:

* Views (PowerDNS does split-horizon via tags / different zones, the
  mapping needs cross-design with the BIND views work in #24).
* RPZ blocklists (RPZ is a Recursor feature; PowerDNS-Authoritative
  doesn't consume it).
* Catalog zones (PowerDNS 4.8+ supports them; covered in Phase 3).
* DNSSEC online signing (covered in Phase 3 — much simpler API
  than BIND's manual key dance).
* ALIAS / LUA records (PowerDNS-only record types — Phase 3).

CLAUDE.md non-negotiable #10: this driver speaks only neutral
``ConfigBundle`` / ``RecordChange`` types. PowerDNS specifics live
inside ``render_server_config`` / ``apply_record_change`` and the
agent-side driver under ``agent/dns/spatium_dns_agent/drivers/
powerdns.py``.
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
    ZoneData,
)

logger = structlog.get_logger(__name__)


# Record types the PowerDNS driver supports. ALIAS (Phase 3a) gives
# operators CNAME-at-apex by having pdns resolve the target at query
# time; LUA (Phase 3b) lets operators write computed-response snippets
# (geo-routing, weighted random, ifportup health-checked failover).
# Online DNSSEC + catalog zones (Phase 3c+) and synthesised record
# families remain out of scope; surfacing them here would let
# operators create records the rest of SpatiumDDI can't yet handle.
_SUPPORTED_RECORD_TYPES = frozenset(
    {
        "A",
        "AAAA",
        "ALIAS",
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
        "LOC",
        "LUA",
        "SOA",
        "SVCB",
        "HTTPS",
        "DNAME",
    }
)


def _parse_quoted_txt(s: str) -> str | None:
    """Unescape a fully-quoted TXT presentation form, or None if ``s``
    is not exactly one or more quoted character-strings."""
    parts: list[str] = []
    i, n = 0, len(s)
    while i < n:
        if s[i].isspace():
            i += 1
            continue
        if s[i] != '"':
            return None
        i += 1
        buf: list[str] = []
        closed = False
        while i < n:
            ch = s[i]
            if ch == "\\" and i + 1 < n:
                digits = s[i + 1 : i + 4]
                if len(digits) == 3 and digits.isdigit():
                    buf.append(chr(int(digits)))
                    i += 4
                    continue
                buf.append(s[i + 1])
                i += 2
                continue
            if ch == '"':
                closed = True
                i += 1
                break
            buf.append(ch)
            i += 1
        if not closed:
            return None
        parts.append("".join(buf))
        if i < n and not s[i].isspace():
            return None
    return "".join(parts) if parts else None


def _quote_txt(value: str) -> str:
    """Quote a TXT record value per RFC 1035 (split long strings into chunks ≤255).

    Keeps in step with the copies in ``drivers/dns/powerdns.py`` and the
    DNS agent's BIND9/PowerDNS drivers (issue #1514) — the packages are
    deployed separately, so the helper is duplicated on purpose.

    Control characters are stripped. An already-quoted value is parsed
    back to its raw text first, so quoting it again changes nothing.
    Chunking walks the *unescaped* value one code point at a time and
    budgets each chunk by its escaped UTF-8 octet length, so a chunk
    can neither split an escape sequence (or a multi-byte character)
    nor exceed the 255-octet character-string limit once escaped.
    """
    s = "".join(ch for ch in value if ord(ch) >= 0x20 and ord(ch) != 0x7F)
    stripped = s.strip()
    raw = s
    if stripped.startswith('"'):
        parsed = _parse_quoted_txt(stripped)
        if parsed is not None:
            raw = parsed
    chunks: list[str] = []
    cur = ""
    cur_len = 0
    for ch in raw:
        esc = '\\"' if ch == '"' else "\\\\" if ch == "\\" else ch
        cost = len(esc.encode("utf-8"))
        if cur and cur_len + cost > 255:
            chunks.append(cur)
            cur, cur_len = "", 0
        cur += ch
        cur_len += cost
    chunks.append(cur)
    escaped_chunks = [c.replace("\\", "\\\\").replace('"', '\\"') for c in chunks]
    return " ".join(f'"{c}"' for c in escaped_chunks)


def _record_content(rr: RecordData) -> str:
    """Compose the wire-format ``content`` field for the PowerDNS API.

    PowerDNS expects MX / SRV records to carry priority / weight / port
    inline in the ``content`` string; we receive them as separate
    columns from the control plane and stitch them together here.
    """
    rtype = rr.record_type.upper()
    # Strip control chars from the value first (issue #597) — defense in
    # depth so a legacy/imported row can't push a raw newline into the
    # PowerDNS API content.
    value = strip_control_chars(rr.value)
    if rtype == "TXT":
        return _quote_txt(value)
    if rtype == "MX":
        prio = rr.priority if rr.priority is not None else 10
        return f"{prio} {value}"
    if rtype == "SRV":
        prio = rr.priority if rr.priority is not None else 0
        weight = rr.weight if rr.weight is not None else 0
        port = rr.port if rr.port is not None else 0
        return f"{prio} {weight} {port} {value}"
    return value


def _qualified_record_name(zone: ZoneData, rr: RecordData) -> str:
    """Return the FQDN PowerDNS expects in the rrset ``name`` field.

    PowerDNS API takes absolute names with a trailing dot. Apex records
    in our model are stored as ``@``, ``""``, or the bare zone name —
    all three resolve to the zone's apex.
    """
    zone_name = zone.name if zone.name.endswith(".") else zone.name + "."
    name = strip_control_chars(rr.name)
    if name in ("", "@") or name == zone_name.rstrip("."):
        return zone_name
    return f"{name}.{zone_name}"


def render_pdns_conf(
    *,
    api_key: str,
    backend: str = "lmdb",
    lmdb_path: str = "/var/lib/powerdns/pdns.lmdb",
    listen_address: str = "0.0.0.0",
    listen_port: int = 53,
    api_listen_address: str = "127.0.0.1",
    api_listen_port: int = 8081,
    log_level: int = 4,
) -> str:
    """Render the ``pdns.conf`` file the agent writes alongside the
    PowerDNS daemon.

    Pulled out of the driver as a module-level helper so the agent
    can import + call it directly when generating the conf at first
    boot, without instantiating a ``PowerDNSDriver``.

    The default ``backend="lmdb"`` matches the Phase 1 image —
    PowerDNS LMDB is the modern embedded backend and avoids any
    cross-process database dependency. Switching to gpgsql is a
    Phase 4 concern.
    """
    if backend != "lmdb":
        # Phase 1: only LMDB. gpgsql / gsqlite3 / etc. are deferred.
        # Don't silently accept; raising surfaces the misconfiguration
        # on the agent side where the operator can react.
        raise ValueError(f"Phase 1 only supports backend='lmdb' (got {backend!r})")

    return "\n".join(
        [
            "# pdns.conf — generated by SpatiumDDI DNS agent",
            "# Do not edit by hand; the agent rewrites this file on every config sync.",
            "",
            "launch=lmdb",
            f"lmdb-filename={lmdb_path}",
            "lmdb-shards=64",
            "lmdb-sync-mode=sync",
            "",
            f"local-address={listen_address}",
            f"local-port={listen_port}",
            "",
            "# REST API — agent-only via loopback. The API key is generated",
            "# by the entrypoint on first boot and shared with the agent",
            "# through the same on-disk file.",
            "api=yes",
            f"api-key={api_key}",
            "webserver=yes",
            f"webserver-address={api_listen_address}",
            f"webserver-port={api_listen_port}",
            "webserver-allow-from=127.0.0.1,::1",
            "",
            f"loglevel={log_level}",
            "log-dns-details=no",
            "log-dns-queries=no",
            "",
            "# Disable features Phase 1 doesn't surface yet — operators",
            "# who turn these on will need the matching control-plane",
            "# wiring (Phase 2/3).",
            "expand-alias=no",
            # No security-status polling: it phones secpoll.powerdns.com
            # with the version, an outbound connection nobody configured
            # (non-negotiable #17, #1353). Mirrors the agent's renderer.
            "security-poll-suffix=",
            # RFC 2136 dynamic updates (issue #641). Enabled globally; per-zone
            # ``ALLOW-DNSUPDATE-FROM`` / ``TSIG-ALLOW-DNSUPDATE`` metadata gates
            # actual acceptance, so this is a no-op for zones without an ACL.
            "dnsupdate=yes",
            "",
        ]
    )


class PowerDNSDriver(DNSDriver):
    """PowerDNS-Authoritative driver (issue #127).

    Phase 1 — server-config rendering + zone/record introspection.
    Daemon lifecycle + apply runs inside the agent; the control-plane
    apply path is a no-op (agent-based driver, like BIND9).
    """

    name = "powerdns"

    # ── Rendering ─────────────────────────────────────────────────────────

    def render_server_config(
        self,
        server: Any,
        options: ServerOptions,
        *,
        bundle: ConfigBundle | None = None,
    ) -> str:
        """Render ``pdns.conf``.

        The control plane doesn't actually write this file — the agent
        does, on first boot, with the API key it generated locally.
        We render a representative copy for ``GET /servers/{id}/config``
        previews (operator can see what the agent will produce) and
        for tests; the agent regenerates with its own API key in
        practice.
        """
        # Placeholder API key in the rendered preview so secrets never
        # reach the control-plane response. Agent's real key is local.
        return render_pdns_conf(api_key="<agent-generated>")

    def render_zone_config(self, zone: ZoneData) -> str:
        """PowerDNS LMDB stores zones in the database, not as
        per-zone config stanzas. Zones are managed via the REST API.
        Return an empty string so the bundle hash stays stable
        across drivers.
        """
        return ""

    def render_zone_file(self, zone: ZoneData, records: list[RecordData]) -> str:
        """Render a JSON projection of the zone the agent uses to drive
        the PowerDNS REST API.

        We deliberately do not render an RFC 1035 zone file — PowerDNS
        wants record-by-record JSON via the API. This is the JSON
        payload the agent will PATCH after diffing against the live
        zone state.

        Returns a stable, sorted JSON string so the bundle ETag is
        deterministic.
        """
        import json

        zone_name = zone.name if zone.name.endswith(".") else zone.name + "."

        rrsets: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for r in records:
            qname = _qualified_record_name(zone, r)
            key = (qname, r.record_type.upper())
            rrsets.setdefault(key, []).append(
                {
                    "content": _record_content(r),
                    "disabled": False,
                }
            )

        rrsets_payload = [
            {
                "name": qname,
                "type": rtype,
                "ttl": records[0].ttl or zone.ttl,
                "records": rrs,
            }
            for (qname, rtype), rrs in sorted(rrsets.items())
        ]

        return json.dumps(
            {
                "name": zone_name,
                "kind": "Native",
                "serial": zone.serial,
                "rrsets": rrsets_payload,
            },
            sort_keys=True,
            indent=2,
        )

    def render_rpz_zone(self, blocklist: EffectiveBlocklistData) -> str:
        """RPZ is a PowerDNS-Recursor feature, not Authoritative. The
        Phase 1 PowerDNS driver returns an empty string so server
        groups with blocklists still hash deterministically; the
        agent skips applying RPZ data on PowerDNS hosts.
        """
        return ""

    # ── Runtime (agent-side; control plane only formulates) ──────────────

    async def apply_record_change(self, server: Any, change: RecordChange) -> None:
        """Control-plane no-op. The agent runs the actual PATCH against
        the local PowerDNS REST API.
        """
        logger.info(
            "powerdns.apply_record_change.formulated",
            server=str(getattr(server, "id", "")),
            zone=change.zone_name,
            op=change.op,
            name=change.record.name,
            type=change.record.record_type,
        )

    async def reload_config(self, server: Any) -> None:
        """PowerDNS reloads via API or ``pdns_control rediscover``;
        the agent handles both. Control-plane no-op."""
        logger.info("powerdns.reload_config", server=str(getattr(server, "id", "")))

    async def reload_zone(self, server: Any, zone_name: str) -> None:
        """PowerDNS reloads a single zone via the REST API
        (``PUT /zones/{zone}/notify`` and ``axfr-retrieve``).
        Control-plane no-op."""
        logger.info(
            "powerdns.reload_zone",
            server=str(getattr(server, "id", "")),
            zone=zone_name,
        )

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
            if z.zone_type not in ("primary", "secondary", "stub", "forward"):
                errors.append(f"zone {z.name!r}: invalid zone_type {z.zone_type!r}")
            for r in z.records:
                rtype = r.record_type.upper()
                if rtype not in _SUPPORTED_RECORD_TYPES:
                    errors.append(
                        f"zone {z.name!r}: record type {rtype!r} not supported "
                        f"by Phase 1 PowerDNS driver"
                    )
        if bundle.views:
            errors.append(
                "PowerDNS Phase 1 driver does not support views — "
                "create a separate group per view (issue #24)"
            )
        if bundle.blocklists:
            # Not an error — just a notice. Agent will skip RPZ apply.
            logger.info(
                "powerdns.bundle_has_blocklists_skipping",
                count=len(bundle.blocklists),
            )
        return (not errors, errors)

    def capabilities(self) -> dict[str, Any]:
        return {
            "name": "powerdns",
            "views": False,
            "rpz": False,
            "dnssec_inline_signing": True,  # Phase 3c — landed (agent-side)
            "incremental_updates": "rest_api",
            "zone_types": ["primary", "secondary"],
            "record_types": sorted(_SUPPORTED_RECORD_TYPES),
            "alias_records": True,  # Phase 3a — landed
            "lua_records": True,  # Phase 3b — landed
            "catalog_zones": "producer-only",  # Phase 3d — landed
        }

    @property
    def dynamic_update_caps(self) -> DynamicUpdateCaps:
        # PowerDNS dynamic updates (issue #641) are coarse only: per-zone
        # ``ALLOW-DNSUPDATE-FROM`` (IP) + ``TSIG-ALLOW-DNSUPDATE`` (key) zone
        # metadata. There's no per-name / per-type / deny surface, so those
        # fields are rejected by ``validate_update_acl``.
        return DynamicUpdateCaps(
            supports_ip_acl=True,
            supports_tsig_acl=True,
            supports_name_scoping=False,
            supports_per_type=False,
        )


__all__ = ["PowerDNSDriver", "render_pdns_conf"]
