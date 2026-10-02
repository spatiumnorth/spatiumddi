"""PowerDNS agent driver (issue #127, Phase 1).

Runs alongside ``pdns_server`` inside the dns-powerdns container. Where
the BIND9 driver renders ``named.conf`` + RFC 1035 zone files and reloads
via ``rndc``, this driver:

* Renders ``pdns.conf`` once at first boot using the API key the
  entrypoint generated and shared with us via ``/var/lib/spatium-dns-
  agent/pdns-api.key``. Subsequent renders only rewrite the file if
  the bundle changed materially (loglevel, listen address, etc.).
* Applies zones + records via the local PowerDNS REST API
  (``http://127.0.0.1:8081/api/v1/servers/localhost``). Each
  ``apply_record_op`` call becomes one PATCH to the relevant zone's
  rrsets endpoint; full-bundle config sync diffs zone state and
  reconciles per-zone via the same REST surface.
* Validates by smoke-testing the API on the agent's loopback before
  signalling the daemon to reload (``pdns_control reload``).

Backend storage in Phase 1 is LMDB (``launch=lmdb``), embedded under
``/var/lib/powerdns/pdns.lmdb``. The gpgsql-backed configuration that
shares Postgres with the control plane is deferred to Phase 4 — the
extra cross-process database coupling isn't worth the complexity for
the first ship.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx
import structlog

from ._process import (
    find_running_daemon,
    is_zombie,
    spawn_guard,
    wait_for_daemon,
)
from .base import RRSET_OP_KINDS, DriverBase
from ..secure_io import harden_mode, write_private

log = structlog.get_logger(__name__)


_PDNS_API_BASE = "http://127.0.0.1:8081/api/v1/servers/localhost"
_PDNS_API_TIMEOUT = 10.0
_API_KEY_FILE = "pdns-api.key"

# ``resolver=`` takes ``ip``, ``ip:port`` or ``[v6]:port``, comma-separated.
_ALIAS_RESOLVER_PORTED_RE = re.compile(
    r"^(?:\[([0-9A-Fa-f:.]+)\]|([0-9.]+)):([0-9]{1,5})$"
)


def _alias_resolver_entry_ok(entry: str) -> bool:
    """One ``resolver=`` element: an address, optionally with a port."""
    ported = _ALIAS_RESOLVER_PORTED_RE.fullmatch(entry)
    host = (ported.group(1) or ported.group(2)) if ported else entry
    if ported and not 1 <= int(ported.group(3)) <= 65535:
        return False
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    # A bracketed host must be v6 and an unbracketed ``ip:port`` must be v4;
    # a zone index (``%eth0``) is not something ``resolver=`` can parse.
    if ported and (addr.version == 6) != bool(ported.group(1)):
        return False
    return "%" not in entry


def _read_text_or_none(path: Path) -> str | None:
    try:
        return path.read_text()
    except OSError:
        return None


def _safe_alias_resolver(value: Any) -> str:
    """The ALIAS resolver list to write into pdns.conf, or "" for ALIAS off.

    The control plane builds the list from validated forwarders (#1353), but
    it lands in pdns.conf, where a newline would start a new directive and a
    value pdns cannot parse stops it starting, so every element is checked
    again here. Anything that is not an address list turns ALIAS off rather
    than reaching the file.
    """
    if not isinstance(value, str) or not value.strip():
        return ""
    entries = value.strip().split(",")
    if not all(_alias_resolver_entry_ok(e) for e in entries):
        log.warning("powerdns_alias_resolver_refused", value=value[:200])
        return ""
    return ",".join(entries)


def _quote_txt(value: str) -> str:
    """RFC 1035 TXT quoting — chunk into ≤255-byte strings."""
    s = value
    if s.startswith('"') and s.endswith('"') and len(s) >= 2:
        s = s[1:-1]
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    chunks = [s[i : i + 255] for i in range(0, len(s), 255)] or [""]
    return " ".join(f'"{c}"' for c in chunks)


def _record_content(rec: dict[str, Any]) -> str:
    """Stitch wire-format content for a single record dict."""
    rtype = rec["type"].upper()
    value = rec.get("value") or ""
    if rtype == "TXT":
        return _quote_txt(value)
    if rtype == "MX":
        prio = rec.get("priority")
        if prio is None:
            prio = 10
        # Operators sometimes paste the priority into value already.
        first = value.lstrip().split(" ", 1)[0]
        if first.isdigit():
            return value
        return f"{prio} {value}"
    if rtype == "SRV":
        prio = rec.get("priority", 0) or 0
        weight = rec.get("weight", 0) or 0
        port = rec.get("port", 0) or 0
        if len(value.split()) >= 4:
            return value
        return f"{prio} {weight} {port} {value}"
    return value


def _qualified_name(zone_name: str, name: str) -> str:
    """Compose the FQDN PowerDNS expects for an rrset name."""
    zone = zone_name.rstrip(".") + "."
    if name in ("", "@") or name.rstrip(".") == zone.rstrip("."):
        return zone
    return f"{name.rstrip('.')}.{zone}"


def _render_catalog_zone_payload(catalog: dict[str, Any]) -> dict[str, Any]:
    """Build the zones.json payload entry for an RFC 9432 catalog zone.

    PowerDNS accepts the canonical catalog-zone shape verbatim: SOA + NS
    + a ``version`` TXT pinned to ``"2"`` (the only schema PowerDNS
    accepts) + one PTR per member zone. The PTR label is the SHA-1 of
    the wire-format member zone name, exactly as BIND9's catalog-zone
    renderer produces (RFC 9432 §4.1) — keeping the format identical
    means a SpatiumDDI-managed catalog can be served by either driver
    without consumers needing to special-case the producer kind.

    Returns a dict in the same shape as the regular zones_payload
    entries so the existing reconciler creates / patches it through
    the same code path.
    """
    zname = (catalog.get("zone_name") or "").rstrip(".") + "."
    if not zname or zname == ".":
        return {"name": "invalid.", "kind": "Native", "rrsets": []}

    serial = int(time.time())
    rrsets: list[dict[str, Any]] = [
        {
            "name": zname,
            "type": "SOA",
            "ttl": 86400,
            "records": [
                {
                    "content": (f"invalid. invalid. {serial} 86400 3600 86400 86400"),
                    "disabled": False,
                }
            ],
        },
        {
            "name": zname,
            "type": "NS",
            "ttl": 86400,
            "records": [{"content": "invalid.", "disabled": False}],
        },
        {
            "name": f"version.{zname}",
            "type": "TXT",
            "ttl": 86400,
            "records": [{"content": '"2"', "disabled": False}],
        },
    ]

    for member in catalog.get("members") or []:
        member_name = (member.get("zone_name") or "").rstrip(".")
        if not member_name:
            continue
        # RFC 9432 §4.1 — SHA-1 over the wire-format zone name (each
        # label prefixed with its length byte, root null at the end).
        wire = (
            b"".join(
                bytes([len(label)]) + label.encode("ascii")
                for label in member_name.split(".")
                if label
            )
            + b"\x00"
        )
        digest = hashlib.sha1(wire).hexdigest()
        rrsets.append(
            {
                "name": f"{digest}.zones.{zname}",
                "type": "PTR",
                "ttl": 86400,
                "records": [{"content": f"{member_name}.", "disabled": False}],
            }
        )

    return {
        "name": zname,
        "kind": "Native",
        "serial": serial,
        "rrsets": rrsets,
    }


# ── Encrypted transports (issue #50) ────────────────────────────────────────
# The dnsdist front runs in its OWN container and mounts the PowerDNS agent's
# state dir read-only. So paths baked into the rendered rules must be
# dnsdist-side paths, not agent-side ones: the agent writes
# ``<state_dir>/tls/listener.crt``, dnsdist reads
# ``/agent-state/tls/listener.crt``. Both images create ``spatium`` as
# uid 101, so the 0600 key the agent writes is readable by dnsdist.
DNSDIST_STATE_MOUNT = os.environ.get("DNSDIST_STATE_MOUNT", "/agent-state")
TLS_DIR_NAME = "tls"
TLS_CERT_FILENAME = "listener.crt"
TLS_KEY_FILENAME = "listener.key"


def _dnsdist_cert_paths() -> tuple[str, str]:
    base = f"{DNSDIST_STATE_MOUNT.rstrip('/')}/{TLS_DIR_NAME}"
    return f"{base}/{TLS_CERT_FILENAME}", f"{base}/{TLS_KEY_FILENAME}"


# Files inside the rendered tree that embed a credential and therefore need
# 0600 + redaction before the snapshot pusher ships them (#869). Keep this in
# step with anything new that render() writes under ``rendered.new``.
_SECRET_RENDERED_FILES: tuple[str, ...] = ("pdns.conf", "zones.json")


def _harden_legacy_rendered_modes(state_dir: Path) -> None:
    """Fix 0644 secret files left by a pre-#869 agent build.

    Upgrading the agent does not re-mode what is already on disk: the live
    ``rendered/`` tree survives until the next structural render replaces it,
    and then lingers as ``rendered.prev/`` for one more cycle. Without this,
    a still-valid API key and TSIG secrets stay world-readable for two
    renders' worth of uptime after the fix ships — on a stable install, that
    could be indefinitely.
    """
    for tree in ("rendered", "rendered.prev"):
        for name in _SECRET_RENDERED_FILES:
            harden_mode(state_dir / tree / name)


def render_dnsdist_conf(opts: dict[str, Any], has_cert: bool = False) -> str:
    """Render the dnsdist RULES + encrypted listeners from bundle options.

    Two things ride this file, both composed by the dnsdist container's
    entrypoint onto its env-configured base (setLocal + newServer → pdns
    backend). It is fully decoupled from pdns.conf — pdns never moves port.
    Pure + unit-testable.

    * **Rate limiting** (issue #146 Phase 2) — PowerDNS Authoritative has no
      RRL, so MaxQPSIPRule → TC/Drop + optional exceedQRate dynamic block
      live here.
    * **DoT / DoH listeners** (issue #50) — pdns auth speaks neither, so the
      dnsdist front terminates TLS and forwards plaintext to pdns over the
      container network.

    Note there is deliberately no upstream-transport handling: PowerDNS
    Authoritative doesn't recurse or forward, so ``forward_transport`` is a
    BIND9-only concept. The only hop dnsdist makes is to the local pdns
    backend, where encryption buys nothing.

    Returns "" when nothing is configured → the front runs as a plain
    pass-through, which is a safe no-op.
    """
    dot = bool(opts.get("dot_enabled")) and has_cert
    doh = bool(opts.get("doh_enabled")) and has_cert
    if not opts.get("dnsdist_enabled") and not (dot or doh):
        return ""

    lines = ["-- generated by SpatiumDDI — do not edit by hand"]

    if dot or doh:
        cert_path, key_path = _dnsdist_cert_paths()
        lines.append("-- encrypted transports (issue #50)")
        if dot:
            port = int(opts.get("dot_port", 853))
            for bind in (f"0.0.0.0:{port}", f"[::]:{port}"):
                lines.append(f'addTLSLocal("{bind}", "{cert_path}", "{key_path}")')
        if doh:
            port = int(opts.get("doh_port", 443))
            path = (opts.get("doh_path") or "/dns-query").strip()
            for bind in (f"0.0.0.0:{port}", f"[::]:{port}"):
                lines.append(
                    f'addDOHLocal("{bind}", "{cert_path}", "{key_path}", {{"{path}"}})'
                )

    if opts.get("dnsdist_enabled"):
        lines.append("-- rate-limit rules (issue #146 Phase 2)")
        max_qps = opts.get("dnsdist_max_qps_per_client")
        if max_qps is not None:
            action = (
                "DropAction()" if opts.get("dnsdist_action") == "drop" else "TCAction()"
            )
            lines.append("-- per-source-IP QPS cap")
            lines.append(f"addAction(MaxQPSIPRule({int(max_qps)}), {action})")
        dyn = opts.get("dnsdist_dynblock_qps")
        if dyn is not None:
            secs = int(opts.get("dnsdist_dynblock_seconds", 60))
            lines.append("-- dynamic per-source blocking on sustained query rate")
            lines.append("local dbr = dynBlockRulesGroup()")
            lines.append(
                f'dbr:setQueryRate({int(dyn)}, 10, "exceeded query rate", {secs})'
            )
            lines.append("function maintenance() dbr:apply() end")

    return "\n".join(lines) + "\n"


class PowerDNSDriver(DriverBase):
    """PowerDNS agent driver — Phase 1."""

    # ── Render / validate / swap ────────────────────────────────────────────

    def render(self, bundle: dict[str, Any]) -> None:
        """Write ``pdns.conf`` + the desired-state JSON the agent uses
        to drive the API on the next sync.

        ``pdns.conf`` is largely static after first boot — listen
        addresses, the API key, and the LMDB filename don't change at
        runtime. We still rewrite it on every render so operators
        editing options through the UI (loglevel, query logging, the
        ALIAS resolver) see the change: ``swap_and_reload`` restarts
        pdns when the rendered file differs, since pdns reads it only
        at startup.
        """
        # Re-mode anything a pre-#869 build left world-readable before we
        # render over it — the old trees outlive the upgrade (see the helper).
        _harden_legacy_rendered_modes(self.state_dir)

        new_dir = self.state_dir / "rendered.new"
        if new_dir.exists():
            shutil.rmtree(new_dir)
        new_dir.mkdir(parents=True)

        api_key = self._load_or_generate_api_key()
        opts = bundle.get("options", {}) or {}
        # ``query_log_enabled`` toggles ``log-dns-queries=yes`` in the
        # rendered pdns.conf so the daemon emits one stderr line per
        # incoming query. The agent's ``QueryLogShipper`` thread tails
        # the captured stderr file and ships parsed lines to the
        # control plane (matching the BIND9 flow under the same
        # ``DNSServerOptions.query_log_enabled`` gate).
        query_log_enabled = bool(opts.get("query_log_enabled", False))
        # PowerDNS gates ``log-dns-queries`` output at ``loglevel=6``
        # (Info) — at the default 4 (Warning) the lines are filtered
        # out before they reach stderr. Bump to 6 only when query
        # logging is enabled so quiet operators don't get noisy logs
        # for free; otherwise stick with the configured level (or 4
        # default) so startup banners + errors still show through.
        log_level = int(opts.get("log_level", 4))
        if query_log_enabled and log_level < 6:
            log_level = 6

        # The ALIAS resolver is the group's own plain-DNS forwarders,
        # computed by the control plane (#1353); "" turns ALIAS expansion
        # off. There is no built-in fallback: the old ``1.1.1.1,8.8.8.8``
        # default sent every ALIAS target to Cloudflare and Google, an
        # outbound connection nobody configured. The value is written into
        # pdns.conf, so anything but an address list is refused here too.
        alias_resolver = _safe_alias_resolver(opts.get("alias_resolver"))
        conf_path = new_dir / "pdns.conf"
        # 0600, not write_text: this file embeds ``api-key=`` in cleartext,
        # and that key grants zone CRUD + DNSSEC over the pdns REST API
        # (#869). ``pdns_server`` and the dnsdist front both run as uid 101,
        # the same owner, so the owner bit is all either of them needs —
        # what 0600 removes is group/other, i.e. any OTHER uid that can see
        # this path (a differently-run sidecar, a host bind-mount, a future
        # image that stops running everything as 101).
        # ``atomic=False``: this lands in a freshly-created ``rendered.new``
        # that no reader can see; the directory rename in swap_and_reload is
        # the atomic step.
        write_private(
            conf_path,
            self._render_conf(
                api_key=api_key,
                log_level=log_level,
                query_log_enabled=query_log_enabled,
                alias_resolver=str(alias_resolver),
            ),
            atomic=False,
        )

        # dnsdist rate-limit RULES (issue #146 Phase 2). Written to a STABLE
        # path under state_dir that the (separate) dnsdist front container
        # mounts read-only + watches; its entrypoint composes these rules onto
        # an env-configured base (setLocal + newServer→pdns:53). This is
        # rules-ONLY and fully decoupled from pdns.conf: pdns never moves port,
        # so writing/removing this file can't affect pdns serving. Removed when
        # dnsdist is disabled → the front becomes a plain pass-through.
        #
        # Since #50 the same file also carries the DoT/DoH listeners, whose
        # cert material is written below — write the cert FIRST so the
        # dnsdist front can never see a rules file pointing at a PEM that
        # isn't on disk yet (it polls the rules mtime and restarts on
        # change; a missing cert fails --check-config and it would keep the
        # old instance until the next poll).
        tls_cert = bundle.get("tls_cert") or None
        has_cert = bool(
            isinstance(tls_cert, dict)
            and tls_cert.get("cert_pem")
            and tls_cert.get("key_pem")
        )
        if (opts.get("dot_enabled") or opts.get("doh_enabled")) and not has_cert:
            log.warning(
                "powerdns_encrypted_listener_skipped_no_cert",
                dot_enabled=bool(opts.get("dot_enabled")),
                doh_enabled=bool(opts.get("doh_enabled")),
            )
        self._write_listener_cert(tls_cert if has_cert else None)

        rules_path = self.state_dir / "dnsdist-rules.conf"
        rules = render_dnsdist_conf(opts, has_cert=has_cert)
        if rules:
            rules_path.write_text(rules)
        elif rules_path.exists():
            rules_path.unlink()

        # Stash the desired-state JSON for the API reconciler. The
        # supervisor calls ``apply_config`` (default impl) which calls
        # render → validate → swap_and_reload; the actual REST PATCH
        # work happens in ``swap_and_reload`` so the daemon is up
        # before we try to reach its API.
        # TSIG keys shipped in the bundle, indexed by name — the reconciler
        # imports the ones a zone's dynamic-update ACL references into pdns
        # (issue #641). Secrets stay agent-private (same as the api-key in
        # pdns.conf); they never leave the appliance.
        bundle_keys = {
            k.get("name"): k for k in (bundle.get("tsig_keys") or []) if k.get("name")
        }
        zones_payload = []
        for zone in bundle.get("zones", []) or []:
            zname = (zone.get("name") or "").rstrip(".") + "."
            if not zname or zname == ".":
                continue
            ztype = zone.get("type", "primary")
            if ztype == "forward":
                # Phase 1: skip forward zones on PowerDNS — they're a
                # recursor concept and the authoritative server doesn't
                # consume them. The control-plane validator will surface
                # this via the capabilities() dict in Phase 2.
                continue
            # Dynamic-update ACL (issue #641). PowerDNS is coarse-only:
            # ALLOW-DNSUPDATE-FROM (IP grants) + TSIG-ALLOW-DNSUPDATE (key
            # grants); name-scope / per-type / deny are rejected at the
            # control plane. Referenced keys ride along so the reconciler can
            # import them into pdns before setting the metadata.
            acl = (
                (zone.get("update_acl") or [])
                if zone.get("dynamic_update_enabled")
                else []
            )
            referenced_keys = [
                bundle_keys[e["tsig_key_name"]]
                for e in acl
                if e.get("match_kind") == "tsig_key"
                and e.get("tsig_key_name") in bundle_keys
            ]
            rrsets: dict[tuple[str, str], list[dict[str, Any]]] = {}
            for rec in zone.get("records") or []:
                qname = _qualified_name(zname, rec.get("name") or "@")
                rtype = rec["type"].upper()
                rrsets.setdefault((qname, rtype), []).append(
                    {
                        "content": _record_content(rec),
                        "disabled": False,
                    }
                )
            zones_payload.append(
                {
                    "name": zname,
                    "kind": "Native",
                    "serial": zone.get("serial") or 1,
                    "rrsets": [
                        {
                            "name": qname,
                            "type": rtype,
                            "ttl": zone.get("ttl", 3600),
                            "records": rrs,
                        }
                        for (qname, rtype), rrs in sorted(rrsets.items())
                    ],
                    # Dynamic-update ACL (issue #641) — applied as zone
                    # metadata by the reconciler. Empty list = disabled.
                    "update_acl": acl,
                    "update_tsig_keys": referenced_keys,
                }
            )

        # Catalog zones (RFC 9432, Phase 3d). Producer mode renders the
        # catalog itself as a regular zone with the canonical record
        # structure; PowerDNS authoritative serves it like any other
        # zone, and operators can stand up secondaries via AXFR
        # (PowerDNS-native catalog-consumer mode needs additional config
        # we'll add in a follow-up — see the warning branch below).
        catalog = bundle.get("catalog") or None
        if catalog and catalog.get("mode") == "producer":
            zones_payload.append(_render_catalog_zone_payload(catalog))
        elif catalog and catalog.get("mode") == "consumer":
            log.warning(
                "powerdns_catalog_consumer_unsupported",
                zone=catalog.get("zone_name"),
                hint=(
                    "This agent does not wire up PowerDNS catalog-consumer "
                    "mode. Use AXFR-based secondaries against the producer "
                    "instead."
                ),
            )

        # Issue #247 — blocklists. The BIND9 driver renders these as
        # RPZ zones + a `response-policy` directive in named.conf;
        # PowerDNS auth doesn't have an equivalent inline RPZ surface
        # (recursor has Lua hooks but the appliance ships pdns auth
        # only). For now, log a clear warning so operators on
        # PowerDNS see why their blocklist UI doesn't actually
        # block — pre-#247 the entries were silently dropped from
        # render() and pdns answered normally.
        blocklists = bundle.get("blocklists") or []
        if blocklists:
            log.warning(
                "powerdns_blocklists_unsupported",
                blocklist_count=len(blocklists),
                hint=(
                    "PowerDNS authoritative server does not support "
                    "RPZ-style blocklists; the appliance ships pdns "
                    "auth only (no recursor + Lua hooks). Use the "
                    "BIND9 driver if blocklist enforcement matters, "
                    "or move blocking upstream to a recursor / "
                    "dnsdist tier. See issue #247 for the roadmap."
                ),
            )

        # 0600 for the same reason as pdns.conf (#869), and this one is not
        # obvious: ``update_tsig_keys`` carries whole key dicts including
        # ``secret`` (see ``_ensure_tsigkey``), so zones.json holds the TSIG
        # material that authorises dynamic updates. CodeQL flagged only
        # pdns.conf; this file was the same defect one write call away.
        write_private(
            new_dir / "zones.json",
            json.dumps(zones_payload, indent=2),
            atomic=False,
        )

    def _write_listener_cert(self, tls_cert: dict[str, Any] | None) -> None:
        """Write (or remove) the DoT/DoH listener cert for the dnsdist front.

        Lives at a STABLE path outside the ``rendered.new`` swap — the
        dnsdist container mounts the state dir and polls the rules file, so
        the PEM has to be readable at a fixed location the whole time.

        Written 0600 via O_NOFOLLOW like the BIND9 driver's TSIG key: the
        private key must never exist world-readable, not even between
        create and chmod. Both images run ``spatium`` as uid 101, so 0600
        is still readable by the dnsdist process.

        Removing the pair when the listeners are off matters — a stale key
        on disk is exactly the kind of thing that outlives the feature that
        put it there.
        """
        tls_dir = self.state_dir / TLS_DIR_NAME
        if tls_cert is None:
            for filename in (TLS_CERT_FILENAME, TLS_KEY_FILENAME):
                stale = tls_dir / filename
                if stale.exists():
                    stale.unlink()
            return

        tls_dir.mkdir(parents=True, exist_ok=True)
        for filename, material in (
            (TLS_CERT_FILENAME, str(tls_cert.get("cert_pem") or "")),
            (TLS_KEY_FILENAME, str(tls_cert.get("key_pem") or "")),
        ):
            write_private(tls_dir / filename, material)

    def validate(self) -> None:
        """``pdns_server --config-check`` if the binary supports it.

        Recent PowerDNS versions carry a ``--no-config`` smoke. Falling
        back to "config file exists and parses as text" is acceptable
        — invalid LMDB-backend config is caught when the daemon
        actually starts (the supervisor exits non-zero and the
        orchestrator restarts us).
        """
        new_dir = self.state_dir / "rendered.new"
        conf = new_dir / "pdns.conf"
        if not conf.exists():
            raise RuntimeError("pdns.conf was not written")
        if shutil.which("pdns_server"):
            # pdns_server uses ``--option=value`` syntax (the binary
            # rejects space-separated form with "perhaps a
            # '--setting=123' statement missed the '='?"). ``--config=
            # check`` parses the config + exits; non-zero means a
            # parse error in our file. We pass ``--config-name=`` (no
            # name) so it reads ``pdns.conf`` directly out of the
            # config-dir rather than expecting a ``pdns-<name>.conf``
            # variant.
            res = subprocess.run(
                [
                    "pdns_server",
                    f"--config-dir={new_dir}",
                    "--config-name=",
                    "--config=check",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            if res.returncode != 0:
                stderr = (res.stderr or res.stdout).strip()
                raise RuntimeError(f"pdns_server config-check failed: {stderr}")

    def swap_and_reload(self) -> None:
        """Promote the new render into place and reconcile via REST.

        Cold-boot ordering: at first boot the supervisor calls
        ``start_daemon`` BEFORE ``apply_config`` runs, so pdns.conf
        doesn't exist yet and the daemon-start no-ops with
        ``pdns_conf_missing_startup_deferred``. Once we render the
        config here, kick the daemon explicitly + wait briefly for
        the REST API to come up before reconciling — otherwise the
        first PATCH dies on Connection refused, the reconcile silently
        gives up, and the structural_etag advances so the sync loop
        never retries.
        """
        new_dir = self.state_dir / "rendered.new"
        current = self.state_dir / "rendered"
        backup = self.state_dir / "rendered.prev"
        old_conf = _read_text_or_none(current / "pdns.conf")
        if current.exists():
            if backup.exists():
                shutil.rmtree(backup)
            current.rename(backup)
        new_dir.rename(current)

        # Cold-boot fix: kick start_daemon now that pdns.conf exists.
        # ``daemon_running`` is the simplest "is pdns alive?" probe.
        # On warm reload the daemon is already up; start_daemon's
        # already-running check (added in #704) makes this a no-op.
        # Before that check existed this comment was simply wrong —
        # start_daemon only verified the config file and the binary,
        # and would happily spawn a second daemon.
        if not self.daemon_running():
            log.info("powerdns_daemon_starting_after_first_render")
            self.start_daemon()
            self._wait_for_api_up()
        elif old_conf is not None and old_conf != _read_text_or_none(
            current / "pdns.conf"
        ):
            # pdns reads pdns.conf only when it starts, so a changed one
            # (the ALIAS resolver from the group's forwarders, #1353; the log
            # level; query logging) is otherwise ignored until the container
            # restarts. Zones live in LMDB and survive; the reconcile below
            # runs against the new daemon. Costs a sub-second gap in answers,
            # and only when an operator changes a server option.
            log.info("powerdns_conf_changed_restarting", pid=self.daemon_pid)
            self._restart_daemon()

        api_key = self._load_or_generate_api_key()
        zones_path = current / "zones.json"
        if not zones_path.exists():
            log.warning("powerdns_zones_payload_missing")
            return
        try:
            payload = json.loads(zones_path.read_text())
        except Exception as exc:  # noqa: BLE001
            log.error("powerdns_zones_payload_unreadable", error=str(exc))
            return

        # Let HTTPError propagate — the sync loop catches the
        # exception, logs ``sync_apply_failed``, and crucially does
        # NOT advance ``_current_structural_etag``, so the next
        # bundle (or the next 304 retry) re-runs the apply. Silent
        # failure here used to lose every record on cold-boot when
        # the timing race fired.
        self._reconcile_zones(api_key, payload)

    def _restart_daemon(self, *, stop_timeout_s: float = 15.0) -> None:
        """Stop ``pdns_server`` and start it from the current render."""
        pid = self.daemon_pid or find_running_daemon("pdns_server")
        if pid is not None:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pid = None
        deadline = time.monotonic() + stop_timeout_s
        while pid is not None and time.monotonic() < deadline:
            # We spawned it, so once it exits it is our zombie until reaped.
            try:
                if os.waitpid(pid, os.WNOHANG)[0] == pid:
                    break
            except ChildProcessError:
                # Not our child (adopted after an agent restart): poll instead.
                try:
                    os.kill(pid, 0)
                except OSError:
                    break
            time.sleep(0.1)
        else:
            if pid is not None:
                log.warning("pdns_server_stop_timed_out", pid=pid)
        self.daemon_pid = None
        self.start_daemon()
        self._wait_for_api_up()

    def _wait_for_api_up(self, *, timeout_s: float = 10.0) -> None:
        """Poll the local PowerDNS REST API until it answers (or
        we exceed ``timeout_s``). Used after ``start_daemon`` to
        avoid racing the daemon's UDP/53 + HTTP/8081 bring-up
        before the first reconcile. Best-effort: a still-down API
        after the timeout falls through to the reconcile attempt
        which then surfaces the real error to the sync loop.
        """
        api_key = self._load_or_generate_api_key()
        deadline = time.monotonic() + timeout_s
        with httpx.Client(timeout=1.0) as client:
            while time.monotonic() < deadline:
                try:
                    resp = client.get(
                        f"{_PDNS_API_BASE}/zones",
                        headers={"X-API-Key": api_key},
                    )
                    if resp.status_code < 500:
                        return
                except httpx.HTTPError:
                    pass
                time.sleep(0.2)
        log.warning("powerdns_api_wait_timeout", timeout_s=timeout_s)

    # ── Record ops (REST PATCH against loopback API) ───────────────────────

    def apply_record_op(self, op: dict[str, Any]) -> dict[str, Any] | None:
        """Apply a single record op via the PowerDNS REST API.

        Returns an optional result dict the sync loop can pipe back
        upstream — DNSSEC ops use this to ship the new DS rrset to
        the control plane in the same tick the agent signed the zone.
        ``None`` for ordinary record ops (the existing fire-and-forget
        contract).
        """
        api_key = self._load_or_generate_api_key()
        zone_raw = op["zone_name"]
        zone = zone_raw.rstrip(".") + "."
        op_kind = op["op"]

        # DNSSEC operations (Phase 3c) are zone-level, not rrset-
        # shaped. They flow through the same record-op queue but
        # branch off here rather than building a rrset PATCH.
        if op_kind == "dnssec_sign":
            ds_records = self._dnssec_sign(api_key, zone)
            return {
                "dnssec_state": {
                    "zone_name": zone,
                    "ds_records": ds_records,
                }
            }
        if op_kind == "dnssec_unsign":
            self._dnssec_unsign(api_key, zone)
            return {
                "dnssec_state": {
                    "zone_name": zone,
                    "ds_records": [],
                }
            }

        rec = op["record"]
        name = _qualified_name(zone, rec.get("name") or "@")
        rtype = rec["type"].upper()
        # Absence, not falsiness — a TTL of 0 is legal ("never cache this") and
        # ``or`` silently turned it into an hour. Matches bind9's driver, which
        # has always tested for None here.
        _op_ttl = rec.get("ttl")
        ttl = 3600 if _op_ttl is None else _op_ttl

        url = f"{_PDNS_API_BASE}/zones/{zone}"
        headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
        new_content = _record_content(rec) if op_kind != "delete" else None

        # PowerDNS rrset PATCH semantics: ``REPLACE`` swaps the entire
        # rrset contents and ``DELETE`` drops it. There is no
        # ``INSERT`` / ``REMOVE-MEMBER`` granularity. Multiple records
        # at the same (name, type) — round-robin A pools, multi-MX
        # priorities, multi-NS apex — therefore need the whole set in
        # hand before the PATCH.
        #
        # #773 — the control plane now ships that set on the op, because it
        # is the only place the complete desired state is known. When it is
        # present the write is one PATCH, no read: no zone GET, no merge, and
        # an ``update`` that CHANGES a value no longer strands the old one
        # (the fallback below could not remove it, and says so).
        #
        # Every member goes out as ``disabled: False``. The control plane has
        # no notion of a disabled record, so its desired set means "these
        # values, served" — a record an operator disabled in PowerDNS's own UI
        # is re-enabled by the next write to that name. The merge below used to
        # preserve the flag on members it did not touch; a full-zone reconcile
        # would have clobbered it regardless, so this makes the behaviour
        # consistent rather than introducing a new way to lose it.
        rrset_payload = rec.get("rrset") if isinstance(rec.get("rrset"), dict) else None
        rrset_members = (
            rrset_payload.get("members") if rrset_payload is not None else None
        )
        if (
            rrset_payload is not None
            and rrset_members is not None
            and op_kind in RRSET_OP_KINDS
        ):
            if rrset_members:
                # Absence, not falsiness — a TTL of 0 is legal and meaningful.
                _rrset_ttl = rrset_payload.get("ttl")
                desired: dict[str, Any] = {
                    "name": name,
                    "type": rtype,
                    "ttl": int(ttl if _rrset_ttl is None else _rrset_ttl),
                    "changetype": "REPLACE",
                    "records": [
                        {
                            "content": _record_content({**m, "type": rtype}),
                            "disabled": False,
                        }
                        for m in rrset_members
                    ],
                }
            else:
                desired = {"name": name, "type": rtype, "changetype": "DELETE"}
            with httpx.Client(timeout=_PDNS_API_TIMEOUT) as client:
                resp = client.patch(url, headers=headers, json={"rrsets": [desired]})
            if resp.status_code >= 400:
                raise RuntimeError(
                    f"PowerDNS PATCH {zone}/{name}/{rtype} returned "
                    f"{resp.status_code}: {resp.text[:200]}"
                )
            log.info(
                "powerdns_rrset_applied",
                zone=zone,
                name=name,
                type=rtype,
                op=op_kind,
                members=len(rrset_members),
            )
            return None

        # Fallback for an op enqueued by a control plane that predates the
        # ``rrset`` payload: read the current rrset, splice the new content in
        # (or out), and PATCH the merged set back. Without this, two
        # consecutive ``create www A`` calls collide (the second overwrites
        # the first), which broke GSLB pool fan-out among other things.
        with httpx.Client(timeout=_PDNS_API_TIMEOUT) as client:
            zone_resp = client.get(url, headers=headers)
            existing_records: list[dict[str, Any]] = []
            if zone_resp.status_code == 200:
                zone_doc = zone_resp.json()
                for rs in zone_doc.get("rrsets", []) or []:
                    if rs.get("name") == name and rs.get("type") == rtype:
                        for rec_entry in rs.get("records") or []:
                            content = rec_entry.get("content")
                            if isinstance(content, str):
                                existing_records.append(
                                    {
                                        "content": content,
                                        "disabled": bool(
                                            rec_entry.get("disabled", False)
                                        ),
                                    }
                                )
                        break
            # update = delete-the-old-content + add-the-new-content; we don't
            # know the previous value here so update is treated as "ensure the
            # new value is present + remove any duplicate of the same
            # content". A separate explicit remove for the OLD value would
            # need the op payload to carry it, so without ``rrset`` a value
            # *change* leaves the old IP in the rrset until a delete op fires
            # for the prior content.
            merged: list[dict[str, Any]] = []
            if op_kind == "delete":
                merged = [r for r in existing_records if r["content"] != new_content]
                if not merged:
                    rrset: dict[str, Any] = {
                        "name": name,
                        "type": rtype,
                        "changetype": "DELETE",
                    }
                else:
                    rrset = {
                        "name": name,
                        "type": rtype,
                        "ttl": ttl,
                        "changetype": "REPLACE",
                        "records": merged,
                    }
            else:  # create | update
                merged = [r for r in existing_records if r["content"] != new_content]
                merged.append({"content": new_content, "disabled": False})
                rrset = {
                    "name": name,
                    "type": rtype,
                    "ttl": ttl,
                    "changetype": "REPLACE",
                    "records": merged,
                }

            body = {"rrsets": [rrset]}
            resp = client.patch(url, headers=headers, json=body)
            if resp.status_code >= 400:
                raise RuntimeError(
                    f"PowerDNS PATCH {zone}/{name}/{rtype} returned "
                    f"{resp.status_code}: {resp.text[:200]}"
                )
        # LUA records: the global ``enable-lua-records=yes`` knob in
        # pdns.conf (set in ``_render_conf`` above) makes every LUA
        # rrset live at query time. We deliberately do NOT set the
        # per-zone ``ENABLE-LUA-RECORDS`` metadata here — the REST API
        # rejects that key as "Unsupported metadata kind" via its
        # ``isValidMetadataKind`` filter, even though the docs claim it
        # works. Re-verified against pdns 5.0.5 while bumping the image
        # in #638: still HTTP 422, so the global flag stays. It is
        # portable across versions and zero-cost for non-LUA zones.
        log.info(
            "powerdns_record_op_applied",
            zone=zone,
            name=name,
            type=rtype,
            op=op_kind,
        )

    # ── DNSSEC ops (Phase 3c) ──────────────────────────────────────────────

    def _dnssec_sign(self, api_key: str, zone: str) -> list[str]:
        """Generate KSK + ZSK, set PRESIGNED metadata, rectify zone.

        Returns the DS rrset string list so the caller can ship it to the
        control plane (operator pastes the DS into their parent registrar).
        Empty list means we couldn't extract DS — log-only, not fatal,
        operator can re-trigger sign to retry.

        Idempotent — if keys already exist for the zone, pdns refuses with
        a 409 / 422 and we treat that as success. Operators expect the
        result of repeated 'Sign zone' clicks to converge to "signed",
        not error out.
        """
        headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
        with httpx.Client(timeout=_PDNS_API_TIMEOUT) as client:
            existing = client.get(
                f"{_PDNS_API_BASE}/zones/{zone}/cryptokeys", headers=headers
            )
            if existing.status_code == 200 and existing.json():
                # Keys already there — nothing to create. Just rectify
                # (idempotent) so NSEC/NSEC3 chains stay current. This
                # covers the "operator clicked twice" case + the
                # "agent restart, redo state" case.
                self._rectify(client, headers, zone)
                log.info("powerdns_dnssec_already_signed", zone=zone)
                return self._extract_ds_records(existing.json())

            for kind, key_type in (("ksk", "ksk"), ("zsk", "zsk")):
                # PowerDNS 4.9 picks a sensible default algorithm for
                # KSK creation when ``algorithm`` is omitted, but the
                # ZSK default-picker resolves to algorithm -1
                # (Unallocated) and the API rejects with "Creating an
                # algorithm -1 (Unallocated/Reserved) key requires the
                # size (in bits) to be passed." Pin both keys to
                # ECDSAP256SHA256 (algorithm 13) — RFC 6605, the
                # current online-signing default in pdns docs — so the
                # call is portable across KSK/ZSK iterations.
                resp = client.post(
                    f"{_PDNS_API_BASE}/zones/{zone}/cryptokeys",
                    headers=headers,
                    json={
                        "keytype": key_type,
                        "active": True,
                        "published": True,
                        "algorithm": "ecdsa256",
                    },
                )
                if resp.status_code >= 400:
                    raise RuntimeError(
                        f"PowerDNS create {kind.upper()} for {zone} returned "
                        f"{resp.status_code}: {resp.text[:200]}"
                    )

            # Note: we deliberately do NOT set the ``PRESIGNED`` zone
            # metadata for online-signing zones. ``PRESIGNED`` is for
            # zones signed by an external signer (e.g. via
            # ``dnssec-signzone``) and loaded as already-signed; for
            # online signing pdns derives signing intent from the
            # presence of cryptokeys + active/published flags. Setting
            # it actually trips the API's metadata-kind filter
            # ("Unsupported metadata kind 'PRESIGNED'"), and the
            # resulting warning is misleading. Re-verified against pdns
            # 5.0.5 while bumping the image in #638: still HTTP 422.
            self._rectify(client, headers, zone)

            # Re-fetch after creation so we get the freshly-rendered DS
            # rrset (PowerDNS computes DS from the KSK we just made).
            after = client.get(
                f"{_PDNS_API_BASE}/zones/{zone}/cryptokeys", headers=headers
            )
            log.info("powerdns_dnssec_signed", zone=zone)
            if after.status_code == 200:
                return self._extract_ds_records(after.json())
            return []

    @staticmethod
    def _extract_ds_records(cryptokeys: list[dict[str, Any]]) -> list[str]:
        """Walk the PowerDNS cryptokeys response and pull out every DS
        rrset string.

        PowerDNS includes a ``ds`` field on each KSK entry (and not on
        ZSKs — DS records only attest the KSK to the parent zone).
        Each KSK typically yields one DS per supported digest algorithm
        (SHA-1 + SHA-256 + SHA-384 by default), all of which the
        operator should publish to cover validators of varying
        sophistication.
        """
        out: list[str] = []
        for k in cryptokeys or []:
            if k.get("keytype") != "ksk":
                continue
            for ds in k.get("ds") or []:
                if isinstance(ds, str) and ds.strip():
                    out.append(ds.strip())
        return out

    def _dnssec_unsign(self, api_key: str, zone: str) -> None:
        """Delete every cryptokey + clear PRESIGNED metadata.

        Idempotent — missing keys / metadata are a no-op. Same convergence
        semantic as ``_dnssec_sign``.
        """
        headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
        with httpx.Client(timeout=_PDNS_API_TIMEOUT) as client:
            existing = client.get(
                f"{_PDNS_API_BASE}/zones/{zone}/cryptokeys", headers=headers
            )
            if existing.status_code == 200:
                for key in existing.json() or []:
                    key_id = key.get("id")
                    if key_id is None:
                        continue
                    del_resp = client.delete(
                        f"{_PDNS_API_BASE}/zones/{zone}/cryptokeys/{key_id}",
                        headers=headers,
                    )
                    if del_resp.status_code >= 400 and del_resp.status_code != 404:
                        log.warning(
                            "powerdns_dnssec_key_delete_failed",
                            zone=zone,
                            key_id=key_id,
                            status=del_resp.status_code,
                            body=del_resp.text[:200],
                        )

            # Note: PRESIGNED metadata is intentionally NOT touched
            # here — see _dnssec_sign for the full reason. With keys
            # gone, pdns is back to serving unsigned answers
            # automatically.
        log.info("powerdns_dnssec_unsigned", zone=zone)

    def _rectify(
        self, client: httpx.Client, headers: dict[str, str], zone: str
    ) -> None:
        """Re-sign + re-NSEC3 the zone after a key change. PowerDNS requires
        an explicit rectify call after cryptokey changes; otherwise old
        signatures linger until the next zone PATCH.
        """
        resp = client.put(
            f"{_PDNS_API_BASE}/zones/{zone}/rectify",
            headers=headers,
        )
        if resp.status_code >= 400:
            log.warning(
                "powerdns_dnssec_rectify_failed",
                zone=zone,
                status=resp.status_code,
                body=resp.text[:200],
            )

    # ── Lifecycle ───────────────────────────────────────────────────────────

    def start_daemon(self) -> None:
        """Spawn ``pdns_server`` from the rendered config dir.

        The container entrypoint already created the LMDB directory
        and seeded the API key. We don't drop privileges further —
        the entrypoint dropped to the unprivileged ``spatium`` user
        before invoking the agent.
        """
        current = self.state_dir / "rendered"
        if not (current / "pdns.conf").exists():
            log.warning("pdns_conf_missing_startup_deferred")
            return
        if not shutil.which("pdns_server"):
            log.error("pdns_server_binary_missing")
            return
        # Idempotent against the SYSTEM, not this object's state (#704).
        # ``daemon_pid`` is per-instance and only ``daemon_running()``
        # guards the two ``start_daemon()`` call sites from racing into
        # a duplicate spawn. Unlike
        # BIND9 — which uses SO_REUSEPORT and quietly runs two servers —
        # pdns_server has no ``reuseport`` set, so the duplicate fails to
        # bind :53 and exits. The damage is subtler for it: the ``Popen``
        # handle is discarded, so the corpse is never reaped, and
        # ``daemon_pid`` is left pointing at a ZOMBIE. Because
        # ``os.kill(zombie, 0)`` succeeds, the driver then reports a
        # healthy daemon while tracking a dead process, and any signal it
        # sends goes nowhere.
        # The system look-up is necessary but not sufficient: it matches on
        # ``/proc/<pid>/comm``, and a forked-but-not-yet-``execve``'d child
        # still carries the parent's name, so a concurrent caller sees no
        # daemon and spawns a duplicate anyway. Serialise check-and-spawn on
        # an exclusive lock instead (see ``_process.spawn_guard``).
        with spawn_guard(self.state_dir, "pdns_server"):
            existing = find_running_daemon("pdns_server")
            if existing is not None:
                self.daemon_pid = existing
                log.info(
                    "pdns_already_running_adopted",
                    pid=existing,
                    note="did not spawn a second daemon",
                )
                return
            # ``--daemon=no`` + foreground; pdns logs to stderr.
            # All flags use ``--name=value`` form — pdns_server rejects
            # space-separated args with "perhaps a '--setting=123'
            # statement missed the '='?".
            #
            # We redirect pdns_server stderr into a file the agent's
            # ``QueryLogShipper`` thread can tail, gated on
            # ``log-dns-queries=yes`` being set in pdns.conf. The file
            # lives inside the agent's own state dir
            # (``/var/lib/spatium-dns-agent/pdns.log``) — the ``spatium``
            # user owns that path, which avoids the permission denied
            # we'd hit trying to write to ``/var/log/pdns/`` (owned by
            # root inside the container). The supervisor's
            # ``QueryLogShipper`` is configured against the same path
            # in ``supervisor.run``.
            log_path = self.state_dir / "pdns.log"
            # Open append-mode so log rotates are non-destructive and the
            # tail can resume across daemon restarts (the shipper handles
            # inode-change rotation separately).
            log_fh = log_path.open("ab", buffering=0)
            self.daemon_pid = subprocess.Popen(
                [
                    "pdns_server",
                    "--daemon=no",
                    "--guardian=no",
                    f"--config-dir={current}",
                    "--config-name=",
                ],
                stdout=log_fh,
                stderr=subprocess.STDOUT,
            ).pid
            wait_for_daemon("pdns_server", self.daemon_pid)
        # Track the path so a future health-check / observability
        # surface can find it without re-deriving.
        self._daemon_log_path = log_path
        log.info(
            "pdns_server_started",
            pid=self.daemon_pid,
            log_path=str(log_path),
        )

    def daemon_running(self) -> bool:
        # Falls back to a system-wide look-up when this object has no pid
        # of its own — another driver instance may legitimately own the
        # running daemon, and answering "not running" spawns a duplicate.
        # The shared helper skips zombies, so a corpse is never mistaken
        # for a live daemon (#704).
        if self.daemon_pid is None:
            found = find_running_daemon("pdns_server")
            if found is None:
                return False
            self.daemon_pid = found
            return True
        try:
            os.kill(self.daemon_pid, 0)
        except OSError:
            return False
        # ``os.kill(pid, 0)`` succeeds for a zombie, so liveness needs
        # the state check too — this is exactly how a dead pdns_server
        # was being reported as healthy.
        return not is_zombie(str(self.daemon_pid))

    def daemon_version(self) -> str | None:
        """Running ``pdns_server`` version, e.g. ``"5.0.5"``.

        Read off the binary rather than the REST API on purpose: the version
        matters most when the daemon is NOT healthy (a pdns that just refused
        to open a migrated LMDB answers no API calls, and that is exactly the
        situation #638's preflight is trying to warn about beforehand).

        The output format differs between majors — 4.9 prefixes a syslog-style
        timestamp, 5.0 does not — so match on the product string, not position:

            Jul 28 12:56:47 PowerDNS Authoritative Server 4.9.5 (C) …
            PowerDNS Authoritative Server 5.0.5 (C) …
        """
        exe = shutil.which("pdns_server")
        if exe is None:
            return None
        try:
            proc = subprocess.run(  # noqa: S603
                [exe, "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as e:
            log.debug("pdns_version_probe_failed", error=str(e))
            return None
        m = re.search(
            r"Authoritative Server\s+([0-9]+(?:\.[0-9]+)*)",
            f"{proc.stdout}\n{proc.stderr}",
        )
        return m.group(1) if m else None

    # ── Internals ───────────────────────────────────────────────────────────

    def _api_key_path(self) -> Path:
        return self.state_dir / _API_KEY_FILE

    def _load_or_generate_api_key(self) -> str:
        """Return the local PowerDNS REST API key.

        The container entrypoint usually pre-creates this file. If
        the agent boots in a fresh state dir (volume not mounted),
        we generate one ourselves so the first config sync has
        something to use — pdns will read the same file when the
        entrypoint copies it into place at startup.

        Issue #249 — atomic write via ``.new`` sibling + ``replace``
        so a crash between ``write_text`` and ``chmod`` doesn't
        leave a world-readable key on disk (or a 0-byte partial
        file if the crash lands mid-write).

        Issue #253 — refuse to overwrite an existing file we can't
        read. If the entrypoint wrote the key as root with mode 600
        before chown'ing to spatium, the agent's previous logic
        treated the unreadable file as "missing" and silently wrote
        its own value while ``pdns_server`` was already running
        with the original. New behaviour: if the path exists but
        is unreadable, raise rather than overwrite — the operator
        sees a clear error in the agent log + can fix permissions
        rather than chase a mismatched-key 401 storm.
        """
        path = self._api_key_path()
        if path.exists():
            try:
                return path.read_text().strip()
            except PermissionError as exc:
                raise RuntimeError(
                    f"PowerDNS API key file at {path} exists but is "
                    "unreadable by the agent. Fix ownership/perms "
                    "(should be spatium:spatium 0600) instead of "
                    "letting the agent overwrite — pdns may already "
                    "be running with the original value."
                ) from exc
        key = secrets.token_urlsafe(32)
        # Shared primitive (#869): 0600 at creation via O_NOFOLLOW, complete
        # write, atomic replace. Was open-coded here; the copies had drifted.
        write_private(path, key + "\n")
        return key

    def _render_conf(
        self,
        *,
        api_key: str,
        log_level: int,
        query_log_enabled: bool = False,
        alias_resolver: str = "",
    ) -> str:
        # Mirrors backend/app/drivers/dns/powerdns.py::render_pdns_conf.
        # Agent and control plane render the same shape; the agent
        # owns the API key while the control plane sees only the
        # placeholder.
        log_queries_value = "yes" if query_log_enabled else "no"
        return "\n".join(
            [
                "# pdns.conf — generated by SpatiumDDI DNS agent",
                "# Do not edit by hand; the agent rewrites this file on every config sync.",
                "",
                "launch=lmdb",
                "lmdb-filename=/var/lib/powerdns/pdns.lmdb",
                "lmdb-shards=64",
                "lmdb-sync-mode=sync",
                "",
                # pdns always listens on :53. The dnsdist front (#146 Phase 2)
                # is a SEPARATE container that forwards to this :53 over the
                # network — pdns never moves port, so there's no restart race
                # and toggling the front is decoupled from pdns's lifecycle.
                "local-address=0.0.0.0",
                "local-port=53",
                "",
                "api=yes",
                f"api-key={api_key}",
                "webserver=yes",
                "webserver-address=127.0.0.1",
                "webserver-port=8081",
                "webserver-allow-from=127.0.0.1,::1",
                "",
                f"loglevel={log_level}",
                # ``log-dns-details`` adds the question + answer detail
                # we need to parse client_ip / qname / qtype out of the
                # log; ``log-dns-queries`` is the toggle that emits one
                # line per incoming query. Both gate on the operator-
                # facing ``DNSServerOptions.query_log_enabled`` flag.
                f"log-dns-details={log_queries_value}",
                f"log-dns-queries={log_queries_value}",
                "",
                # PowerDNS polls a TXT record under secpoll.powerdns.com at
                # startup and periodically to learn whether its version has
                # a security advisory. That query leaves through ``resolver=``
                # (once hardcoded public resolvers, see below) or the system
                # resolver, naming the version; it is an outbound connection
                # nobody configured (non-negotiable #17). An empty suffix
                # turns it off (#1353). PowerDNS fixes arrive with
                # SpatiumDDI releases instead. A startup setting: takes effect on
                # pdns's next start, like ``dnsupdate`` below.
                "security-poll-suffix=",
                # ALIAS-record resolution requires both ``expand-alias=yes``
                # and a ``resolver=`` upstream. PowerDNS Authoritative
                # synthesises A/AAAA at query time by recursing through
                # the configured resolver: the group's forwarders, or none
                # and ALIAS off (#1353).
                *(
                    ["expand-alias=yes", f"resolver={alias_resolver}"]
                    if alias_resolver.strip()
                    else ["expand-alias=no"]
                ),
                # LUA records (PowerDNS-only computed responses —
                # ``pickrandom`` / ``ifportup`` / ``createReverse`` etc.)
                # are GLOBALLY enabled here rather than per-zone via
                # ENABLE-LUA-RECORDS metadata. The per-zone metadata
                # path is rejected by the pdns REST filter as an
                # "unsupported kind" (re-verified on 5.0.5 in #638);
                # enabling globally is portable
                # across versions and harmless for non-LUA zones (zones
                # with zero LUA records simply don't trigger the LUA
                # engine at query time).
                "enable-lua-records=yes",
                # RFC 2136 dynamic updates (issue #641). Enabled globally so
                # the feature is available; per-zone acceptance is gated by the
                # ``ALLOW-DNSUPDATE-FROM`` / ``TSIG-ALLOW-DNSUPDATE`` metadata
                # the reconciler sets — a zone with neither rejects every
                # update, so this is a no-op for zones without an ACL.
                # ``dnsupdate`` is a startup setting, like every line here;
                # ``swap_and_reload`` restarts pdns when this file changes.
                "dnsupdate=yes",
                "",
            ]
        )

    def _reconcile_zones(self, api_key: str, payload: list[dict[str, Any]]) -> None:
        """Idempotently bring the local PowerDNS zone set in line with
        ``payload``. Phase 1 reconciliation is per-zone create-or-update.
        Zones present in PowerDNS that aren't in the bundle are NOT
        deleted yet — that's a control-plane safety call (operators
        should explicitly delete a zone, not have it disappear because
        a sync glitched). Phase 2 wires the explicit-delete signal
        from the bundle.
        """
        headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
        with httpx.Client(timeout=_PDNS_API_TIMEOUT) as client:
            try:
                existing = client.get(f"{_PDNS_API_BASE}/zones", headers=headers).json()
            except (httpx.HTTPError, ValueError):
                existing = []
            existing_names = {z["name"] for z in existing if isinstance(z, dict)}

            for zone_payload in payload:
                zone_name = zone_payload["name"]
                if zone_name not in existing_names:
                    # Create — POST /zones with the full rrset list.
                    create_body = {
                        "name": zone_name,
                        "kind": zone_payload.get("kind", "Native"),
                        "rrsets": zone_payload.get("rrsets") or [],
                    }
                    resp = client.post(
                        f"{_PDNS_API_BASE}/zones",
                        headers=headers,
                        json=create_body,
                    )
                    if resp.status_code >= 400:
                        log.error(
                            "powerdns_zone_create_failed",
                            zone=zone_name,
                            status=resp.status_code,
                            body=resp.text[:200],
                        )
                        continue
                    log.info("powerdns_zone_created", zone=zone_name)
                else:
                    # Update — PATCH /zones/{zone} with REPLACE rrsets.
                    rrsets = []
                    for rs in zone_payload.get("rrsets") or []:
                        rrsets.append(
                            {
                                "name": rs["name"],
                                "type": rs["type"],
                                "ttl": rs.get("ttl", 3600),
                                "changetype": "REPLACE",
                                "records": rs.get("records") or [],
                            }
                        )
                    # An empty rrset list still falls through to the
                    # dynamic-update metadata below — a DDNS-only zone may
                    # have no control-plane-managed records yet (issue #641).
                    if rrsets:
                        resp = client.patch(
                            f"{_PDNS_API_BASE}/zones/{zone_name}",
                            headers=headers,
                            json={"rrsets": rrsets},
                        )
                        if resp.status_code >= 400:
                            log.error(
                                "powerdns_zone_patch_failed",
                                zone=zone_name,
                                status=resp.status_code,
                                body=resp.text[:200],
                            )
                            continue
                        log.info(
                            "powerdns_zone_reconciled",
                            zone=zone_name,
                            rrset_count=len(rrsets),
                        )

                # Dynamic-update (RFC 2136) ACL metadata (issue #641).
                self._apply_dynamic_update(client, headers, zone_payload)

                # LUA records are enabled globally via
                # ``enable-lua-records=yes`` in pdns.conf (see
                # ``_render_conf``). Earlier code attempted a per-zone
                # ``ENABLE-LUA-RECORDS`` metadata PUT here, but pdns
                # rejects that key via ``isValidMetadataKind`` as
                # "Unsupported metadata kind" (still true on 5.0.5,
                # re-verified in #638) — which spammed a
                # ``powerdns_lua_metadata_failed`` warning on every
                # bulk reconcile of a LUA-bearing zone. The global
                # knob makes the per-zone PUT unnecessary.

    # ── Dynamic-update ACLs (issue #641) ───────────────────────────────────

    def _apply_dynamic_update(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        zone_payload: dict[str, Any],
    ) -> None:
        """Set (or clear) a zone's RFC 2136 dynamic-update metadata.

        PowerDNS is coarse-only: ``ALLOW-DNSUPDATE-FROM`` (grant IP/CIDRs) +
        ``TSIG-ALLOW-DNSUPDATE`` (grant TSIG key names, imported first). An
        empty ACL clears both so a zone whose dynamic updates were turned off
        stops accepting them. Best-effort — a failed call logs and moves on,
        never aborting the reconcile.
        """
        zone = zone_payload["name"]
        acl = zone_payload.get("update_acl") or []
        ip_from = [
            e["ip_cidr"]
            for e in acl
            if e.get("action") == "grant"
            and e.get("match_kind") == "ip"
            and e.get("ip_cidr")
        ]
        key_names = [
            e["tsig_key_name"].rstrip(".")
            for e in acl
            if e.get("action") == "grant"
            and e.get("match_kind") == "tsig_key"
            and e.get("tsig_key_name")
        ]
        for k in zone_payload.get("update_tsig_keys") or []:
            self._ensure_tsigkey(client, headers, k)
        self._put_metadata(client, headers, zone, "ALLOW-DNSUPDATE-FROM", ip_from)
        self._put_metadata(client, headers, zone, "TSIG-ALLOW-DNSUPDATE", key_names)

    def _ensure_tsigkey(
        self, client: httpx.Client, headers: dict[str, str], key: dict[str, Any]
    ) -> None:
        """Import a TSIG key into pdns (idempotent)."""
        name = (key.get("name") or "").rstrip(".")
        secret = key.get("secret")
        if not name or not secret:
            return
        body = {
            "name": name,
            "algorithm": key.get("algorithm") or "hmac-sha256",
            "key": secret,
        }
        try:
            resp = client.post(f"{_PDNS_API_BASE}/tsigkeys", headers=headers, json=body)
            if resp.status_code in (409, 422):
                # Already present — PUT in case the secret rotated. pdns keys
                # the TSIG key by its (dot-stripped) name, so no trailing dot.
                client.put(
                    f"{_PDNS_API_BASE}/tsigkeys/{name}", headers=headers, json=body
                )
            elif resp.status_code >= 400:
                log.warning(
                    "powerdns_tsigkey_import_failed",
                    key=name,
                    status=resp.status_code,
                    body=resp.text[:200],
                )
        except httpx.HTTPError as exc:
            log.warning("powerdns_tsigkey_import_error", key=name, error=str(exc))

    def _put_metadata(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        zone: str,
        kind: str,
        values: list[str],
    ) -> None:
        """PUT (replace) or DELETE (when empty) a zone metadata kind."""
        try:
            if values:
                resp = client.put(
                    f"{_PDNS_API_BASE}/zones/{zone}/metadata/{kind}",
                    headers=headers,
                    json={"kind": kind, "metadata": values},
                )
            else:
                resp = client.delete(
                    f"{_PDNS_API_BASE}/zones/{zone}/metadata/{kind}", headers=headers
                )
            # 404 on DELETE (metadata absent) is a benign no-op.
            if resp.status_code >= 400 and resp.status_code != 404:
                log.warning(
                    "powerdns_metadata_failed",
                    zone=zone,
                    kind=kind,
                    status=resp.status_code,
                    body=resp.text[:200],
                )
        except httpx.HTTPError as exc:
            log.warning("powerdns_metadata_error", zone=zone, kind=kind, error=str(exc))

    # ── Reload (compatibility with bind9 daemon-pid signal pattern) ────────

    def _reload_via_api(self) -> None:
        """Optional — issue a notify on every zone after a bulk
        change. PowerDNS is master-only by default; this only matters
        when secondaries are configured. Currently unused but kept
        as a hook for Phase 2 supermaster wiring.
        """
        if self.daemon_pid:
            try:
                os.kill(self.daemon_pid, signal.SIGUSR1)
            except OSError as exc:
                log.warning("pdns_sigusr1_failed", error=str(exc))
