"""Technitium rdata translation, both directions.

Technitium's record **read** API (``/api/zones/records/get``) does not echo
back the parameters its record **write** API (``/api/zones/records/add``)
takes. For several types it renames the keys, and for TLSA / SSHFP it
renders the numeric rdata fields as enum *names*. Verified against a live
``technitium/dns-server:15.4.0``: adding a TLSA with
``tlsaCertificateUsage=3, tlsaSelector=1, tlsaMatchingType=1`` reads back as
``{"certificateUsage": "DANE-EE", "selector": "SPKI",
"matchingType": "SHA2-256"}``.

So there are two translations, and this module owns both:

``rdata_to_value``
    read direction — structured ``rData`` → the presentation-format string
    SpatiumDDI stores, plus the structured fields it keeps in their own
    columns (MX/SRV priority, weight, port).

``record_params``
    write direction — a stored value → the type-specific params
    ``/api/zones/records/{add,delete}`` wants. ``delete`` takes the same
    value params as ``add`` because that is how it identifies which member
    of an rrset to remove.

Two consumers, one source of truth: the #744 live-pull importer (read only)
and the #810 agentless ``technitium_api`` driver (both). They previously
would have carried a copy each, which is exactly how the SSHFP enum table
drifts.

**The agent-side driver keeps its own copy** and always will:
``agent/dns/spatium_dns_agent/drivers/technitium.py`` is a separate Python
package that ships in the agent image and cannot import from ``app``. Its
``_normalize_rdata`` / ``_record_params`` are the same translation written
for a different runtime. Do not delete either side thinking it is dead code.

Nothing mechanically enforces that the two agree — the agent package is not
importable from the backend test-suite, so a shared assertion is not
available. What exists instead is a shared corpus: the expectations in
``backend/tests/test_dns_import_technitium.py`` and
``agent/dns/tests/test_technitium_render.py`` were both captured from the
same live ``technitium/dns-server:15.4.0``. If you change an enum table
here, change it there and run both.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import shlex
from typing import Any

# Record types both directions model. Technitium-proprietary types
# (ANAME / APP / FWD) are deliberately absent: they are not drop-in
# equivalents of PowerDNS's ALIAS/LUA and need their own design pass.
SUPPORTED_RECORD_TYPES = frozenset(
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
        "DNAME",
        "URI",
        "SVCB",
        "HTTPS",
    }
)

# Signing artefacts. Never imported and never written by hand — the zone is
# re-signed at the destination instead of carrying signatures across.
DNSSEC_RECORD_TYPES = frozenset({"DNSKEY", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "DS"})

# Enum name → number. Technitium returns the name on read and takes the
# number on write, so these are read in one direction only.
_TLSA_USAGE = {"PKIX-TA": 0, "PKIX-EE": 1, "DANE-TA": 2, "DANE-EE": 3}
_TLSA_SELECTOR = {"Cert": 0, "SPKI": 1}
_TLSA_MATCHING = {"Full": 0, "SHA2-256": 1, "SHA2-512": 2}
# 5 is absent upstream: Technitium echoes an unmapped algorithm back as its
# own number-as-string, which the passthrough in ``_enum_num`` handles.
_SSHFP_ALGO = {"RSA": 1, "DSA": 2, "ECDSA": 3, "Ed25519": 4, "Ed448": 6}
_SSHFP_FP_TYPE = {"SHA1": 1, "SHA256": 2}


def _enum_num(table: dict[str, int], value: Any) -> str:
    """Map an enum name back to its number.

    An unrecognised value passes through unchanged, so a Technitium release
    that adds an enum member degrades to one odd-looking record rather than
    an exception that kills a whole import or reconcile.
    """
    return str(table.get(str(value), value))


def int_or(value: Any, default: int) -> int:
    """Coerce to int, falling back only on genuinely absent input.

    ``int(x or default)`` silently rewrites a legitimate **zero**, which
    matters here: SVCB/HTTPS priority 0 means AliasMode (not ServiceMode),
    MX preference 0 is the highest priority, and URI priority/weight 0 are
    both valid.
    """
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def canonical_ip(value: str) -> str:
    """Canonical form of an A/AAAA value via ``ipaddress`` (#1513).

    Technitium returns addresses in canonical form while a record may
    be stored exactly as typed (``2001:DB8:0:0::1``), so string compares
    in drift/pull see a difference that is not one. An unparseable value
    passes through unchanged.
    """
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return value


def strip_bare_authority_slash(uri: str) -> str:
    """Strip a single trailing slash ONLY when the URI has no path
    beyond the authority (#1513).

    ``https://host/`` → ``https://host`` (Technitium appends that slash
    itself when storing a bare-authority URI), while
    ``https://host/path/`` keeps its slash — it can change the resource
    the URI points to, and the old ``rstrip("/")`` removed it.
    """
    if not uri.endswith("/"):
        return uri
    after_authority_marker = uri.split("://", 1)[-1]
    if after_authority_marker.count("/") == 1:
        return uri[:-1]
    return uri


def normalize_fqdn(name: str) -> str:
    """Ensure a single trailing dot."""
    return name if name.endswith(".") else name + "."


def classify_zone(name: str) -> str:
    """``"reverse"`` for in-addr.arpa / ip6.arpa, else ``"forward"``."""
    bare = name.rstrip(".").lower()
    return "reverse" if bare.endswith((".in-addr.arpa", ".ip6.arpa")) else "forward"


def rel_name(record_name: str, zone_fqdn: str) -> str:
    """Relativise a record's full domain against its zone.

    Technitium reports each record's absolute domain; SpatiumDDI stores a
    label relative to the zone apex, with ``@`` for the apex itself.
    """
    rec = record_name.rstrip(".").lower()
    zone = zone_fqdn.rstrip(".").lower()
    if rec == zone or not rec:
        return "@"
    if rec.endswith("." + zone):
        return rec[: -(len(zone) + 1)]
    return rec


def qualified_name(zone_name: str, name: str) -> str:
    """Compose the bare (no trailing dot) FQDN Technitium's ``domain`` wants.

    The inverse of :func:`rel_name`. Technitium stores and addresses records
    by absolute name with no trailing dot — its own convention throughout
    the API and console.
    """
    zone = zone_name.rstrip(".")
    bare = (name or "@").strip().rstrip(".")
    if bare in ("", "@") or bare.lower() == zone.lower():
        return zone
    if bare.lower().endswith("." + zone.lower()):
        return bare
    return f"{bare}.{zone}"


# ── SVCB / HTTPS (RFC 9460) ────────────────────────────────────────────
#
# Three forms meet here, and every comparison reduces them to one:
#
# * PRESENTATION, what an operator stores and BIND renders verbatim:
#   ``1 svc alpn=h2,h3 port=443``. A target without a trailing dot is
#   RELATIVE to the zone (RFC 1035 §5.1), exactly as BIND reads it.
# * TECHNITIUM WIRE, what ``zones/records/{add,delete}`` parses
#   (``WebServiceZonesApi.cs``, 15.4.0): ``svcTargetName`` is trimmed of
#   dots and stored verbatim, so Technitium has no relative names at all —
#   ``svc`` is served as ``svc.``, never as ``svc.<zone>.``. ``svcParams``
#   is split on ``|`` and walked two tokens at a time (``alpn|h2,h3|port|443``),
#   or is the literal ``false`` for none — the parameter is required, so
#   omitting it is "Parameter 'svcParams' missing.". The key is
#   ``Enum.Parse<DnsSvcParamKey>`` on the name, so ``keyNNNNN`` must go as
#   its NUMBER; ``ech`` and every unnamed key fall through to
#   ``DnsSvcUnknownParamValue``, which parses HEX, not base64.
# * TECHNITIUM READ-BACK (``zones/records/get``): ``svcTargetName`` as
#   stored (no dot, ``""`` for the root), and ``svcParams`` as an object of
#   ``key -> ToString()`` in the order the record was added — ``null`` for
#   ``no-default-alpn``, ``61:62`` colon-hex for ``ech`` and unnamed keys,
#   and an unnamed key reported by its number (``"65000"``).
#
# Canonical form: params in key-NUMBER order, ``mandatory`` sorted, hint
# addresses canonical, ``ech`` as normalised base64, unnamed keys as
# ``keyN`` with an RFC 1035-escaped value, values unquoted unless they hold
# whitespace. ``alpn`` order is significant and kept.
#
# This block is duplicated byte-for-byte in
# ``agent/dns/spatium_dns_agent/drivers/technitium.py`` (the agent image
# cannot import ``app``). Keep the two identical.

_SVCB_KEY_NUM = {
    "mandatory": 0,
    "alpn": 1,
    "no-default-alpn": 2,
    "port": 3,
    "ipv4hint": 4,
    "ech": 5,
    "ipv6hint": 6,
    "dohpath": 7,
}
_SVCB_KEY_NAME = {num: name for name, num in _SVCB_KEY_NUM.items()}
# Technitium ignores the value it is given for ``no-default-alpn``
# (``DnsSvcParamValue.Parse`` returns an empty ALPN value) but its splitter
# still needs a token in the value slot, and an empty one is refused.
_SVCB_VALUELESS_PLACEHOLDER = "true"
# Technitium's own spelling of "no SvcParams" (AliasMode, or a bare
# ServiceMode record).
_SVCB_NO_PARAMS = "false"


def _svcb_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return value.strip()


def _svcb_norm_key(key: str) -> str:
    """``ALPN`` / ``key1`` / ``1`` -> ``alpn``; ``key065000`` / ``65000`` ->
    ``key65000``. Technitium reports an unnamed key by its bare number."""
    k = key.strip().lower().replace("_", "-")
    if k.isdigit():
        num = int(k)
    elif k.startswith("key") and k[3:].isdigit():
        num = int(k[3:])
    else:
        return k
    return _SVCB_KEY_NAME.get(num, f"key{num}")


def _svcb_key_num(key: str) -> int:
    if key in _SVCB_KEY_NUM:
        return _SVCB_KEY_NUM[key]
    if key.startswith("key") and key[3:].isdigit():
        return int(key[3:])
    return 65536


def _svcb_is_generic(key: str) -> bool:
    return key.startswith("key") and key[3:].isdigit()


def _svcb_split(value: str) -> list[str]:
    """Split presentation-format rdata on whitespace outside double quotes.

    Backslash escapes are kept verbatim (``alpn=h2\\,x`` keeps its escaped
    comma), unlike ``shlex.split``, which eats the backslash.
    """
    tokens: list[str] = []
    cur: list[str] = []
    in_quote = False
    it = iter(value)
    for ch in it:
        if ch == "\\":
            cur.append(ch)
            cur.append(next(it, ""))
        elif ch == '"':
            in_quote = not in_quote
            cur.append(ch)
        elif ch.isspace() and not in_quote:
            if cur:
                tokens.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        tokens.append("".join(cur))
    return tokens


def _svcb_unquote(raw: str) -> str:
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        return raw[1:-1]
    return raw


def _svcb_unescape(text: str) -> bytes:
    """RFC 1035 §5.1 character-string -> bytes (``\\DDD`` and ``\\X``)."""
    out = bytearray()
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            digits = text[i + 1 : i + 4]
            if len(digits) == 3 and digits.isdigit() and int(digits) < 256:
                out.append(int(digits))
                i += 4
                continue
            out.extend(text[i + 1].encode("utf-8"))
            i += 2
            continue
        out.extend(ch.encode("utf-8"))
        i += 1
    return bytes(out)


def _svcb_escape(data: bytes) -> str:
    """bytes -> an RFC 1035 character-string needing no quotes."""
    out: list[str] = []
    for b in data:
        if b in (0x22, 0x5C):
            out.append("\\" + chr(b))
        elif 0x21 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append(f"\\{b:03d}")
    return "".join(out)


def _svcb_hex_bytes(value: str) -> bytes | None:
    try:
        return bytes.fromhex(value.replace(":", "").replace("-", ""))
    except ValueError:
        return None


def _svcb_b64_bytes(value: str) -> bytes | None:
    try:
        return base64.b64decode(value.strip(), validate=True)
    except (ValueError, binascii.Error):
        return None


def _svcb_canon_value(key: str, val: str | None, from_daemon: bool) -> str | None:
    """One param value in canonical presentation form (``None`` = valueless).

    ``from_daemon`` says ``val`` is Technitium's read-back ``ToString()``
    (colon-hex for ``ech`` / unnamed keys) rather than presentation text.
    """
    if val is None or val == "":
        return None
    if key == "mandatory":
        names = {_svcb_norm_key(n) for n in val.split(",") if n.strip()}
        return ",".join(sorted(names, key=lambda n: (_svcb_key_num(n), n))) or None
    if key in ("ipv4hint", "ipv6hint"):
        return ",".join(_svcb_ip(a) for a in val.split(",") if a.strip())
    if key == "port":
        return str(int(val)) if val.strip().isdigit() else val
    if key == "ech":
        data = _svcb_hex_bytes(val) if from_daemon else _svcb_b64_bytes(val)
        return base64.b64encode(data).decode("ascii") if data is not None else val
    if _svcb_is_generic(key):
        data = _svcb_hex_bytes(val) if from_daemon else _svcb_unescape(val)
        if data is None:
            return val
        return _svcb_escape(data) or None
    return val


def _svcb_param_list(
    items: list[tuple[str, str | None]], from_daemon: bool
) -> list[tuple[str, str | None]]:
    """Canonical ``(key, value-or-None)`` list, in key-number order."""
    out: dict[str, str | None] = {}
    for raw_key, raw_val in items:
        key = _svcb_norm_key(raw_key)
        out[key] = _svcb_canon_value(key, raw_val, from_daemon)
    return sorted(out.items(), key=lambda kv: (_svcb_key_num(kv[0]), kv[0]))


def _svcb_wire_key(key: str) -> str:
    return key[3:] if _svcb_is_generic(key) else key


def _svcb_wire_value(key: str, val: str | None) -> str:
    if key == "mandatory" and val:
        return ",".join(_svcb_wire_key(n) for n in val.split(","))
    if key == "ech" and val:
        data = _svcb_b64_bytes(val)
        return data.hex().upper() if data is not None else val
    if _svcb_is_generic(key):
        return _svcb_unescape(val).hex().upper() if val else ""
    if val is None:
        # Only ``no-default-alpn`` is valueless by definition; anything else
        # sent empty is the operator's empty value, not a made-up one.
        return _SVCB_VALUELESS_PLACEHOLDER if key == "no-default-alpn" else ""
    return val


def _svcb_wire(params: list[tuple[str, str | None]]) -> str:
    """Technitium's ``svcParams`` for an already-canonical list."""
    if not params:
        return _SVCB_NO_PARAMS
    parts: list[str] = []
    for key, val in params:
        parts.append(_svcb_wire_key(key))
        parts.append(_svcb_wire_value(key, val))
    return "|".join(parts)


def _svcb_render(params: list[tuple[str, str | None]]) -> str:
    def _q(v: str) -> str:
        return f'"{v}"' if any(c.isspace() for c in v) else v

    return " ".join(k if v is None else f"{k}={_q(v)}" for k, v in params)


def _svcb_target(name: str, origin: str | None) -> str:
    """A presentation-format target -> Technitium's form: absolute, lower
    case, no trailing dot, ``.`` for the root.

    A trailing dot means absolute and is honoured whatever the label count
    (``localhost.`` stays ``localhost``). Without one the name is relative
    to ``origin`` (``svc`` in ``example.net`` is ``svc.example.net``), as in
    a zone file; with no origin it is left as written.
    """
    name = name.strip()
    if name in ("", "."):
        return "."
    if name.endswith("."):
        return name.rstrip(".").lower() or "."
    zone = (origin or "").strip().rstrip(".").lower()
    if name == "@":
        return zone or "."
    return f"{name}.{zone}".lower() if zone else name.lower()


def _svcb_daemon_target(name: Any) -> str:
    """Technitium's read-back target, which is always absolute, in the same
    form ``_svcb_target`` produces. ``""`` is the root."""
    bare = str(name or "").strip().rstrip(".").lower()
    return bare or "."


def _svcb_parse(value: str, origin: str | None) -> tuple[int, str, list[tuple[str, str | None]]]:
    tokens = _svcb_split(value)
    if len(tokens) < 2:
        return (1, ".", [])
    priority = int(tokens[0]) if tokens[0].isdigit() else 1
    items: list[tuple[str, str | None]] = []
    for tok in tokens[2:]:
        key, eq, raw = tok.partition("=")
        items.append((key, _svcb_unquote(raw) if eq else None))
    return (priority, _svcb_target(tokens[1], origin), _svcb_param_list(items, False))


def _svcb_daemon_params(raw: Any) -> list[tuple[str, str | None]]:
    """Technitium's read-back ``svcParams`` object, canonical."""
    if not isinstance(raw, dict):
        return []
    return _svcb_param_list(
        [(str(k), None if v in (None, "") else str(v)) for k, v in raw.items()], True
    )


# ── end of the block shared with the agent ──────────────────────────────


def svcb_target(name: str, origin: str | None) -> str:
    """Public alias of ``_svcb_target`` (presentation target -> Technitium)."""
    return _svcb_target(name, origin)


def svcb_wire(params: list[tuple[str, str | None]]) -> str:
    """Public alias of ``_svcb_wire`` (canonical params -> ``svcParams``)."""
    return _svcb_wire(params)


def svcb_params(value: str, origin: str | None = None) -> tuple[int, str, str]:
    """Parse presentation-format SVCB/HTTPS rdata into Technitium's params.

    Input shape is what SpatiumDDI stores and BIND9 renders, e.g.
    ``'1 . alpn="h2,h3"'``. Returns ``(priority, target, svcParams)``, the
    target relative to ``origin`` unless it ends in a dot, ``svcParams`` in
    key-number order and ``|``-separated (``alpn|h2,h3|port|443``) — the
    comma-joined pairs this sent before #1698 only ever parsed for one
    param — or ``false`` when there are none.
    """
    priority, target, params = _svcb_parse(value, origin)
    return (priority, target, _svcb_wire(params))


def svcb_canonical(value: str, zone_name: str) -> str:
    """One comparison form for a presentation-format SVCB/HTTPS value.

    ``1 . alpn=h2``, ``1 . alpn="h2"`` and ``1 . ALPN=h2`` are one record, as
    are ``svc`` and ``svc.<zone>.`` as a target in ``<zone>``; params compare
    in key-number order. A target is relative only when it has no trailing
    dot, so ``localhost.`` is never qualified. The drift / sync identity key
    (#1513) — never what is sent or stored.
    """
    priority, target, params = _svcb_parse(value, zone_name)
    rendered = _svcb_render(params)
    tgt = target if target == "." else f"{target}."
    return f"{priority} {tgt}" + (f" {rendered}" if rendered else "")


# ── Read direction: Technitium rData → stored value ────────────────────


def rdata_to_value(rtype: str, rdata: dict[str, Any]) -> tuple[str, dict[str, int]]:
    """Rebuild the presentation-format value from Technitium's rData.

    Returns ``(value, extra)`` where ``extra`` carries the fields
    SpatiumDDI stores in their own columns rather than in the value string
    (MX/SRV ``priority``, SRV ``weight`` / ``port``).
    """
    extra: dict[str, int] = {}

    if rtype in ("A", "AAAA"):
        return canonical_ip(str(rdata.get("ipAddress") or "")), extra
    if rtype == "CNAME":
        return str(rdata.get("cname") or ""), extra
    if rtype == "DNAME":
        return str(rdata.get("dname") or ""), extra
    if rtype == "NS":
        return str(rdata.get("nameServer") or ""), extra
    if rtype == "PTR":
        return str(rdata.get("ptrName") or ""), extra
    if rtype == "TXT":
        return str(rdata.get("text") or ""), extra
    if rtype == "MX":
        extra["priority"] = int_or(rdata.get("preference"), 10)
        return str(rdata.get("exchange") or ""), extra
    if rtype == "SRV":
        extra["priority"] = int_or(rdata.get("priority"), 0)
        extra["weight"] = int_or(rdata.get("weight"), 0)
        extra["port"] = int_or(rdata.get("port"), 0)
        return str(rdata.get("target") or ""), extra
    if rtype == "CAA":
        return (
            f"{int_or(rdata.get('flags'), 0)} {rdata.get('tag') or 'issue'} "
            f"\"{rdata.get('value') or ''}\"",
            extra,
        )
    if rtype == "TLSA":
        return (
            " ".join(
                [
                    _enum_num(_TLSA_USAGE, rdata.get("certificateUsage")),
                    _enum_num(_TLSA_SELECTOR, rdata.get("selector")),
                    _enum_num(_TLSA_MATCHING, rdata.get("matchingType")),
                    str(rdata.get("certificateAssociationData") or "").lower(),
                ]
            ),
            extra,
        )
    if rtype == "SSHFP":
        return (
            " ".join(
                [
                    _enum_num(_SSHFP_ALGO, rdata.get("algorithm")),
                    _enum_num(_SSHFP_FP_TYPE, rdata.get("fingerprintType")),
                    str(rdata.get("fingerprint") or "").lower(),
                ]
            ),
            extra,
        )
    if rtype == "NAPTR":
        return (
            f"{rdata.get('order') or 0} {rdata.get('preference') or 0} "
            f"\"{rdata.get('flags') or ''}\" \"{rdata.get('services') or ''}\" "
            f"\"{rdata.get('regexp') or ''}\" {rdata.get('replacement') or '.'}",
            extra,
        )
    if rtype == "URI":
        return (
            f"{int_or(rdata.get('priority'), 1)} "
            f"{int_or(rdata.get('weight'), 1)} "
            f"{strip_bare_authority_slash(str(rdata.get('uri') or ''))}",
            extra,
        )
    if rtype in ("SVCB", "HTTPS"):
        # Canonical presentation (#1513): Technitium's names are absolute,
        # so the target comes back with its trailing dot (``svc`` on the
        # daemon is served as ``svc.``, and is reported as such); params in
        # key-number order, unquoted, ``ech`` / unnamed keys decoded from
        # Technitium's colon-hex.
        target = _svcb_daemon_target(rdata.get("svcTargetName"))
        rendered = _svcb_render(_svcb_daemon_params(rdata.get("svcParams")))
        return (
            f"{int_or(rdata.get('svcPriority'), 1)} "
            + (target if target == "." else f"{target}.")
            + (f" {rendered}" if rendered else ""),
            extra,
        )
    # Unreachable for SUPPORTED_RECORD_TYPES, but keeps the function total.
    return str(rdata), extra


# ── Write direction: stored value → Technitium add/delete params ───────


def record_params(
    rtype: str,
    value: str,
    *,
    priority: int | None = None,
    weight: int | None = None,
    port: int | None = None,
    origin: str | None = None,
) -> dict[str, Any]:
    """Build the type-specific params for ``/api/zones/records/{add,delete}``.

    ``delete`` takes the same value params as ``add``: that is how
    Technitium identifies *which* member of an rrset to remove, which
    matters because SpatiumDDI keys records per value and supports
    round-robin A records and multi-value MX / NS / TXT.

    ``priority`` / ``weight`` / ``port`` come from SpatiumDDI's own columns.
    They are defaulted with ``if x is None`` rather than ``or`` because zero
    is legitimate for every one of them — MX preference 0 is the highest
    priority, and SRV weight/port 0 are both meaningful.
    """
    if rtype in ("SVCB", "HTTPS"):
        # Before the blanket rstrip below: a trailing dot on the TARGET is
        # what says it is absolute, and rstrip would take it off first.
        # ``svcParams`` is always sent: Technitium requires it, with
        # ``false`` meaning none (AliasMode / a param-less record).
        prio, target, params = svcb_params(value, origin)
        return {"svcPriority": prio, "svcTargetName": target, "svcParams": params}
    value = value.rstrip(".")
    if rtype in ("A", "AAAA"):
        return {"ipAddress": canonical_ip(value)}
    if rtype == "CNAME":
        return {"cname": value}
    if rtype == "DNAME":
        return {"dname": value}
    if rtype == "NS":
        return {"nameServer": value}
    if rtype == "PTR":
        return {"ptrName": value}
    if rtype == "MX":
        return {"exchange": value, "preference": 10 if priority is None else priority}
    if rtype == "SRV":
        return {
            "target": value,
            "priority": 0 if priority is None else priority,
            "weight": 0 if weight is None else weight,
            "port": 0 if port is None else port,
        }
    if rtype == "TXT":
        return {"text": value}
    if rtype == "CAA":
        # value shape: "<flags> <tag> <target>", e.g. '0 issue "letsencrypt.org"'
        tokens = shlex.split(value)
        flags = int(tokens[0]) if tokens and tokens[0].isdigit() else 0
        tag = tokens[1] if len(tokens) > 1 else "issue"
        target = tokens[2] if len(tokens) > 2 else ""
        return {"flags": flags, "tag": tag, "value": target}
    if rtype == "TLSA":
        tokens = shlex.split(value)
        return {
            "tlsaCertificateUsage": tokens[0] if len(tokens) > 0 else "0",
            "tlsaSelector": tokens[1] if len(tokens) > 1 else "0",
            "tlsaMatchingType": tokens[2] if len(tokens) > 2 else "0",
            # Lower-cased to match the read side — Technitium upper-cases
            # the stored hex, so comparing raw would churn every record.
            "tlsaCertificateAssociationData": (tokens[3].lower() if len(tokens) > 3 else ""),
        }
    if rtype == "SSHFP":
        tokens = shlex.split(value)
        return {
            "sshfpAlgorithm": tokens[0] if len(tokens) > 0 else "0",
            "sshfpFingerprintType": tokens[1] if len(tokens) > 1 else "0",
            "sshfpFingerprint": tokens[2].lower() if len(tokens) > 2 else "",
        }
    if rtype == "NAPTR":
        tokens = shlex.split(value)
        return {
            "naptrOrder": tokens[0] if len(tokens) > 0 else "0",
            "naptrPreference": tokens[1] if len(tokens) > 1 else "0",
            "naptrFlags": tokens[2] if len(tokens) > 2 else "",
            "naptrServices": tokens[3] if len(tokens) > 3 else "",
            "naptrRegexp": tokens[4] if len(tokens) > 4 else "",
            "naptrReplacement": tokens[5] if len(tokens) > 5 else ".",
        }
    if rtype == "URI":
        tokens = shlex.split(value)
        return {
            "uriPriority": tokens[0] if len(tokens) > 0 else "1",
            "uriWeight": tokens[1] if len(tokens) > 1 else "1",
            # Only a bare-authority trailing slash is stripped (#1513) —
            # Technitium appends one there when it stores the record,
            # but a path's trailing slash is part of the target.
            "uri": (strip_bare_authority_slash(tokens[2]) if len(tokens) > 2 else ""),
        }
    # Unrecognised type — pass the raw value through under a best-guess key
    # so the API's own error message says what's missing, rather than
    # silently dropping the record.
    return {"value": value}


__all__ = [
    "DNSSEC_RECORD_TYPES",
    "SUPPORTED_RECORD_TYPES",
    "canonical_ip",
    "classify_zone",
    "int_or",
    "normalize_fqdn",
    "qualified_name",
    "rdata_to_value",
    "record_params",
    "rel_name",
    "strip_bare_authority_slash",
    "svcb_canonical",
    "svcb_params",
    "svcb_target",
    "svcb_wire",
]
