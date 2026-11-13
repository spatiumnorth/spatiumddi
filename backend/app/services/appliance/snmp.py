"""Issue #153 — appliance SNMP support.

Source-of-truth lives on ``platform_settings`` (singleton); this
module renders an ``/etc/snmp/snmpd.conf`` payload from those columns
and folds the rendered text into the DNS + DHCP ConfigBundle long-
poll so every appliance host (local + remote agents) picks it up
the same way Phase 8f-4 ships slot-upgrade triggers.

Design notes:

* snmpd runs at the OS level on the appliance image, NOT in a
  container — HOST-RESOURCES-MIB needs unfiltered ``/proc`` and
  ``/sys`` which a containerised snmpd can't see without making
  the container effectively privileged. The trigger-file → host
  systemd path-unit pattern lets the api container ship config
  without itself being on the host.
* v2c uses ``rocommunity`` per source CIDR — net-snmp's shorthand
  that expands to a ``com2sec`` / ``group`` / ``access`` triple
  with the source filter baked in. Cleaner config and snmpd does
  the source filtering itself rather than relying on nftables.
* v3 uses the ``createUser`` mechanism. snmpd reads createUser
  lines on first start, hashes the passwords against its
  ``engineID``, and rewrites the result into
  ``/var/lib/snmp/snmpd.conf``. The host-side runner wipes that
  file before reload so each rendered config gets a clean run-
  through; this rotates the engineID on every config change,
  which is acceptable for a first cut. A future iteration could
  persist the engineID and compute hashed ``usmUser`` lines
  server-side.
* Empty / disabled settings still produce a *valid* snmpd.conf
  body (just an inert daemon with no community / users) so the
  runner can compare it byte-for-byte against the on-disk file
  and skip the reload when nothing changed.
"""

from __future__ import annotations

import hashlib
from ipaddress import ip_network
from typing import Any

import structlog

from app.core.config_text import has_control_chars
from app.core.crypto import decrypt_str
from app.models.settings import PlatformSettings

logger = structlog.get_logger(__name__)

# Listeners on the standard SNMP UDP port. IPv4 is always on all
# addresses. IPv6 listens on all addresses only when an IPv6 source can
# query (see ``_agent_address_line``); otherwise it stays on loopback.
# The host firewall (scoped to snmp_allowed_sources) and the per-source
# community lines are what restrict who gets an answer (#3813).
_AGENT_ADDRESS_V4_ONLY = "agentAddress udp:161,udp6:[::1]:161"
_AGENT_ADDRESS_DUAL = "agentAddress udp:161,udp6:161"


def _agent_address_line(sources: list[Any]) -> str:
    """``udp6:161`` when an IPv6 source is listed, or the list is empty
    (any source may reach the port); an IPv4-only list keeps IPv6 on
    loopback, so nothing new is exposed."""
    canon = _valid_sources(list(sources))
    if canon and not any(":" in c for c in canon):
        return _AGENT_ADDRESS_V4_ONLY
    return _AGENT_ADDRESS_DUAL


# AgentX master socket (issue #2154). lldpd's "Expose via SNMP" toggle
# (#348) runs ``lldpd -x``, which registers LLDP-MIB as an AgentX
# *subagent* — and that only works when snmpd is an AgentX *master*.
# net-snmp does not take the master role unless ``master agentx`` is
# configured; Debian's stock snmpd.conf carries the line, but this
# renderer REPLACES that file, so it has to carry it too or the LLDP
# toggle silently does nothing.
#
# Emitted whenever SNMP is enabled, not only when the LLDP toggle is on:
# it is a local unix socket (no listener on the network, nothing for
# nftables to open) restricted to root by ``agentXPerms``, so it exposes
# nothing; and keeping it unconditional means the snmpd config does not
# depend on LLDP settings — flipping the LLDP toggle never has to
# restart snmpd, and a later subagent (the planned SPATIUMDDI-MIB) needs
# no second switch.
#
# ``/run/agentx`` is the directory Debian's snmpd.service already creates
# (``RuntimeDirectory=agentx``): tmpfs, so a stale socket never survives
# a reboot the way one under the persistent /var would. lldpd is pointed
# at the same path explicitly (``-X``, see ``lldp.render_lldpd_daemon_args``)
# rather than relying on both sides' compiled-in defaults agreeing.
#
# 0600 / 0700 root-only is enough for lldpd: its monitor process keeps
# CAP_DAC_OVERRIDE after dropping to ``_lldpd`` and connects fine —
# verified against Debian 13's snmpd 5.9.4 + lldpd 1.0.18, including the
# reconnect after an snmpd restart (lldpd's AgentX ping re-registers
# within ~15 s, so the reload runner does not need to bounce lldpd).
AGENTX_SOCKET = "/run/agentx/master"
_AGENTX_LINES = (
    "# AgentX master — lets local subagents (lldpd -x → LLDP-MIB) register.",
    "master agentx",
    f"agentXSocket {AGENTX_SOCKET}",
    "agentXPerms 0600 0700",
)

# net-snmp Debian ships a default that loads HOST-RESOURCES + DISMAN
# implicitly; we don't have to ``load`` them explicitly. The lines
# below are the minimum operator-meaningful config — sysContact /
# sysLocation / view / agentAddress + the community or user table.


def render_snmpd_conf(settings: PlatformSettings) -> str:
    """Return the full ``/etc/snmp/snmpd.conf`` body for these settings.

    Returns a stable, deterministic string — same settings → same
    bytes, so the host-side runner can compare against the on-disk
    file and skip the reload when nothing changed.
    """
    lines: list[str] = [
        "# Managed by SpatiumDDI — edits will be overwritten on next config push.",
        "# Source of truth: Appliance → Fleet → Services → SNMP in the SpatiumDDI UI.",
        "",
    ]

    # Common headers — these are safe to emit even when SNMP is
    # globally disabled. The runner won't reach this code in that
    # case (it skips activation when ``snmp_enabled`` is false), but
    # the renderer staying pure lets callers test the output shape.
    #
    # sysContact / sysLocation are free text, and snmpd.conf ends a
    # directive at the newline. The settings API rejects control characters
    # in both; this check covers rows stored before it did. A value that
    # fails it is left out with a comment rather than failing the whole
    # render: both lines are informational, so dropping one keeps snmpd
    # loading with every access line intact, where refusing to render would
    # take SNMP down over a contact string.
    #
    # snmpd reads the rest of a sysContact / sysLocation line LITERALLY
    # (verified against net-snmp 5.9.4, the Debian 13 package the appliance
    # ships): there is no quoting or escaping, so quotes and backslashes
    # become part of the served value and the value is written bare, not
    # via _quote() (#2773). Whitespace between the keyword and the value and
    # at the end of the line is dropped by the parser (hence the strip, which
    # loses nothing). A "#" in the middle of the value is kept; one at the
    # START makes the whole line a comment and snmpd logs "Blank line
    # following ... token" and serves its default, so that value is left out
    # with a note instead of emitting a line that never takes effect.
    for directive, column, raw in (
        ("sysContact", "snmp_sys_contact", settings.snmp_sys_contact),
        ("sysLocation", "snmp_sys_location", settings.snmp_sys_location),
    ):
        value = (raw or "").strip()
        if not value:
            continue
        if has_control_chars(value):
            logger.error("snmp_sys_text_omitted_control_chars", field=column)
            lines.append(
                f"# {directive} OMITTED — the stored {column} contains a newline or "
                "other control character, which snmpd.conf cannot hold on one line. "
                "Re-enter it in the UI."
            )
            continue
        if value.startswith("#"):
            lines.append(
                f"# {directive} OMITTED — a value starting with '#' is read by "
                "snmpd as a comment and cannot be expressed."
            )
            continue
        lines.append(f"{directive:<14} {value}")
    lines.append(_agent_address_line(list(settings.snmp_allowed_sources or [])))
    lines.append("")

    # Source scope for the host firewall rule (#2153), read by the host runner
    # (spatiumddi-snmp-reload) — it is part of the body, so the config_hash
    # covers it and a changed list re-fires the runner. Empty = any source.
    # A stored entry that does not parse is published as the sentinel
    # "!invalid", which the runner refuses, rather than being dropped (which
    # would widen the rule).
    lines.append(_sources_marker(list(settings.snmp_allowed_sources or [])))
    lines.append("")

    # View that exposes the whole MIB tree to authorised queries.
    # Per-OID restrictions are out of scope for the first cut.
    lines.append("view all included .1")
    lines.append("")

    lines.extend(_AGENTX_LINES)
    lines.append("")

    version = (settings.snmp_version or "v2c").strip()
    sources = list(settings.snmp_allowed_sources or [])

    if version == "v2c":
        lines.extend(_render_v2c(settings, sources))
    elif version == "v3":
        lines.extend(_render_v3(settings, sources))

    # Trailing newline so editors don't add a "no newline at end of
    # file" diff when an operator inspects the file directly.
    return "\n".join(lines) + "\n"


SOURCES_MARKER = "# spatium-snmp-sources:"


def _sources_marker(raw_sources: list[Any]) -> str:
    entries = [str(s).strip() for s in raw_sources if str(s).strip()]
    canon = _valid_sources(entries)
    if len(canon) != len(entries):
        return f"{SOURCES_MARKER} !invalid"
    return f"{SOURCES_MARKER} {','.join(canon)}".rstrip()


def _quote(s: str) -> str:
    """net-snmp doesn't have a formal quoting grammar; whitespace and
    single quotes are the practical breakers. Use double quotes and
    escape any double quote in the value.

    Quoting does not survive a newline: snmpd ends the directive there
    whatever the quotes say. Every caller checks for control characters
    first and leaves the value out; dropping them here as well means a
    caller that forgets can still never emit a second line."""
    s = "".join(c for c in s if not (ord(c) < 0x20 or ord(c) == 0x7F))
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _render_v2c(settings: PlatformSettings, sources: list[str]) -> list[str]:
    """Emit one ``rocommunity`` (and ``rocommunity6`` for v6 sources)
    line per allowed source CIDR. No allowed sources = no usable
    config (snmpd will be running but refuse every query); that's
    explicit by operator choice."""
    community = _decrypt_or_none(settings.snmp_community_encrypted)
    if not community:
        return ["# SNMP v2c enabled but no community configured — daemon will accept nothing."]
    # The community is an unquoted token: a newline would start a new
    # directive and a space would shift the next word into the source
    # position. The API rejects both; a stored value that has either is not
    # published at all (the daemon then accepts nothing, the safe side).
    if has_control_chars(community) or any(c.isspace() for c in community):
        logger.error("snmp_v2c_community_omitted_illegal_chars")
        return [
            "# SNMP v2c community OMITTED — the stored community contains whitespace "
            "or control characters, which snmpd.conf cannot express. Re-enter it in "
            "the UI; the daemon will accept nothing until then."
        ]
    sources = _valid_sources(sources)
    if not sources:
        return [
            f"# SNMP v2c community {_quote(community)} configured but no allowed",
            "# sources — daemon will accept nothing. Add at least one CIDR in",
            "# Appliance → Fleet → Services → SNMP.",
        ]

    out: list[str] = []
    for src in sources:
        # net-snmp distinguishes v4 vs v6 by directive name; we pick
        # based on whether the CIDR contains a colon. ``ip_network``
        # validation in the router already canonicalised the entry.
        directive = "rocommunity6" if ":" in src else "rocommunity"
        out.append(f"{directive} {community} {src}")
    return out


def _valid_sources(sources: list[Any]) -> list[str]:
    """Canonical CIDR strings for each source that parses as one; anything
    else is dropped. The settings API canonicalises on write, but each
    source is written bare into an ``rocommunity`` line, so a stored value
    is checked again before it gets there."""
    out: list[str] = []
    for raw in sources:
        try:
            net = ip_network(str(raw).strip(), strict=False)
        except ValueError:
            logger.error("snmp_allowed_source_dropped", source=repr(raw))
            continue
        out.append(str(net))
    return out


def _render_v3(settings: PlatformSettings, sources: list[str]) -> list[str]:
    """Emit one ``createUser`` line per configured v3 user plus a
    matching ``rouser`` granting read access to the full view.

    ``createUser`` is consumed by snmpd on first start; the host-side
    runner wipes ``/var/lib/snmp/snmpd.conf`` before reload so this
    pass runs fresh each time.
    """
    raw_users: list[dict[str, Any]] = list(settings.snmp_v3_users or [])
    if not raw_users:
        return ["# SNMP v3 enabled but no users configured — daemon will accept nothing."]

    # v3 source filters are implemented per-rouser via the OID arg's
    # source-filter sibling — net-snmp's ``rouser`` itself doesn't
    # carry a CIDR arg, but ``access`` does. snmpd gets no source filter
    # for v3; ``snmp_allowed_sources`` is enforced by the host firewall rule
    # the runner renders (#2153). If empty, v3 users are reachable from any
    # source.
    out: list[str] = []
    for u in raw_users:
        username = (u.get("username") or "").strip()
        if not username:
            continue

        # snmpd.conf is whitespace-delimited with no quoting for the
        # username token, so a username carrying internal whitespace
        # splits into extra arguments — and one carrying a NEWLINE ends
        # the directive and starts a new one. ``ops\nrwuser evil .1``
        # would inject a READ-WRITE user into the daemon's config.
        #
        # ``_validate_v3_username`` on the settings router now rejects
        # this at the API boundary, which is the right place. This check
        # is deliberately kept as well: rows written before that
        # validator existed are still in the database, and this renderer
        # is the last thing standing between stored state and the file
        # snmpd loads. Cheap, and the failure mode it prevents is a
        # config-injection rather than a bad-looking line.
        if any(c.isspace() for c in username) or any(ord(c) < 32 for c in username):
            logger.error(
                "snmp_v3_user_skipped_illegal_username",
                username=repr(username),
            )
            out.append(
                "# SNMPv3 user OMITTED — its username contains whitespace or "
                "control characters, which snmpd.conf cannot express and which "
                "could inject additional directives. Rename the user."
            )
            continue

        auth_proto = u.get("auth_protocol") or "none"
        priv_proto = u.get("priv_protocol") or "none"
        auth_pass = _decrypt_v3_pass(u.get("auth_pass_enc"))
        priv_pass = _decrypt_v3_pass(u.get("priv_pass_enc"))

        # A passphrase is quoted on the ``createUser`` line, but quoting does
        # not survive a newline. The API rejects control characters in both
        # passphrases; a stored one that has them omits the user rather
        # than publishing it with a different passphrase than configured.
        if any(p and has_control_chars(p) for p in (auth_pass, priv_pass)):
            logger.error("snmp_v3_user_skipped_control_chars_in_pass", username=username)
            out.append(
                f"# SNMPv3 user {username!r} OMITTED — a stored passphrase contains "
                "control characters, which snmpd.conf cannot hold on one line. "
                "Re-enter the passphrase."
            )
            continue

        # A user configured WITH an auth protocol whose passphrase we
        # cannot decrypt must not be emitted. Falling through to the
        # ``noauth`` branch below would publish an unauthenticated
        # read-only SNMPv3 user reachable by anyone the firewall lets in
        # — a silent security downgrade rather than the outage an
        # operator would notice. ``_decrypt_v3_pass`` returns None for
        # both "absent" and "undecryptable", and the latter is exactly
        # what a key rotation or a half-finished cross-install restore
        # produces (#781). Skip the user and say so in the config.
        if auth_proto != "none" and not auth_pass:
            logger.error(
                "snmp_v3_user_skipped_undecryptable_auth_pass",
                username=username,
                auth_protocol=auth_proto,
            )
            out.append(
                f"# SNMPv3 user {username!r} OMITTED — its {auth_proto} passphrase "
                "could not be decrypted (wrong key, or a restore that did not "
                "rewrap it). Re-enter the passphrase; the user is NOT published "
                "unauthenticated."
            )
            continue

        # Build the createUser line. Each arg is required-or-not
        # based on the security level the user expects.
        create_parts: list[str] = ["createUser", username]
        access_level = "noauth"
        if auth_proto != "none" and auth_pass:
            create_parts.extend([auth_proto, _quote(auth_pass)])
            access_level = "auth"
            # Same reasoning one level down: a user asking for authPriv
            # whose privacy passphrase won't decrypt gets published at
            # ``auth`` — authenticated but UNENCRYPTED on the wire.
            if priv_proto != "none" and not priv_pass:
                logger.error(
                    "snmp_v3_user_skipped_undecryptable_priv_pass",
                    username=username,
                    priv_protocol=priv_proto,
                )
                out.append(
                    f"# SNMPv3 user {username!r} OMITTED — its {priv_proto} privacy "
                    "passphrase could not be decrypted. Re-enter it; the user is "
                    "NOT published without encryption."
                )
                continue
            if priv_proto != "none" and priv_pass:
                create_parts.extend([priv_proto, _quote(priv_pass)])
                access_level = "priv"
        out.append(" ".join(create_parts))
        out.append(f"rouser {username} {access_level} .1")

    if sources:
        # snmpd's USM model authenticates by user+pass, not source IP, so
        # the source list is not rendered into any v3 line; the host
        # runner's UDP 161 firewall rule enforces it instead (#2153).
        out.append("")
        out.append("# Note: snmpd itself does not filter v3 by source (USM authenticates by")
        out.append("# user+password); snmp_allowed_sources is enforced by the host firewall")
        out.append("# rule that opens UDP 161.")

    return out


def _decrypt_or_none(blob: bytes | None) -> str | None:
    if not blob:
        return None
    try:
        return decrypt_str(blob)
    except Exception:  # noqa: BLE001 — bad ciphertext = treat as unset
        return None


def _decrypt_v3_pass(token: Any) -> str | None:
    """v3 passes are stored as the URL-safe-base64 string Fernet emits,
    so ``decrypt_str`` expects bytes — encode back before decrypting.
    Returns None if the token is missing or undecryptable."""
    if not token or not isinstance(token, str):
        return None
    try:
        return decrypt_str(token.encode("ascii"))
    except Exception:  # noqa: BLE001
        return None


def snmp_bundle(settings: PlatformSettings) -> dict[str, Any]:
    """Build the ``snmp_settings`` block that the DNS + DHCP
    ConfigBundle ships to agents.

    Includes the rendered ``snmpd.conf`` body and a config-hash the
    agent can short-circuit on (avoid writing the trigger file when
    the body hasn't changed since the last bundle).
    """
    body = render_snmpd_conf(settings) if settings.snmp_enabled else ""
    config_hash = hashlib.sha256(body.encode("utf-8")).hexdigest() if body else ""
    return {
        "enabled": bool(settings.snmp_enabled),
        "config_hash": config_hash,
        "snmpd_conf": body,
    }
