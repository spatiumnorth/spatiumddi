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


# RFC 9460 §14.3 SvcParamKey numbers. Canonical order is by key NUMBER,
# not name: ``mandatory`` (0) < ``alpn`` (1) < ``no-default-alpn`` (2) <
# ``port`` (3) < ``ipv4hint`` (4) < ``ech`` (5) < ``ipv6hint`` (6) <
# ``dohpath`` (7); ``keyNNNNN`` is its own number.
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

#: Technitium ignores the value of ``no-default-alpn`` (its parser builds an
#: empty ALPN value) but its ``|`` splitter walks tokens two at a time, so a
#: valueless key still needs a token after it. Source: DnsSvcParamValue.Parse
#: in TechnitiumLibrary. Not verified against a live daemon.
_SVCB_VALUELESS_PLACEHOLDER = "true"


def _svcb_key_num(key: str) -> int:
    if key in _SVCB_KEY_NUM:
        return _SVCB_KEY_NUM[key]
    if key.startswith("key") and key[3:].isdigit():
        return int(key[3:])
    return 65536


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


def _svcb_quote(v: str) -> str:
    return f'"{v}"' if any(c.isspace() or c == '"' for c in v) else v


def _svcb_param_list(tokens: list[str]) -> list[tuple[str, str | None]]:
    """Params as ``(key, value-or-None)``, sorted by key number.

    ``None`` is a valueless param (``no-default-alpn``); an empty value is
    the same thing on the wire, so both fold to ``None``. ``mandatory`` is a
    set of keys and is sorted; ``alpn`` order is significant and kept.
    """
    out: list[tuple[str, str | None]] = []
    for tok in tokens:
        key, eq, raw = tok.partition("=")
        key = key.lower().replace("_", "-")
        val: str | None = _svcb_unquote(raw) if eq else None
        if key == "mandatory" and val:
            names = [n.strip().lower().replace("_", "-") for n in val.split(",") if n.strip()]
            val = ",".join(sorted(names, key=lambda n: (_svcb_key_num(n), n)))
        elif key in ("ipv4hint", "ipv6hint") and val:
            val = ",".join(canonical_ip(a.strip()) for a in val.split(",") if a.strip())
        out.append((key, val or None))
    out.sort(key=lambda kv: (_svcb_key_num(kv[0]), kv[0]))
    return out


def svcb_target(name: str, origin: str | None) -> str:
    """Absolute, lower-cased, dot-less SVCB target (``.`` stays ``.``).

    Presentation-format rules (RFC 9460 §2.2 / RFC 1035 §5.1): a trailing
    dot is absolute; anything else is relative to the zone origin, so
    ``svc`` in ``example.net`` is ``svc.example.net``. Without an origin a
    relative name is left alone.
    """
    name = name.strip()
    if name in ("", "."):
        return "."
    zone = (origin or "").strip().rstrip(".").lower()
    if name.endswith("."):
        return name.rstrip(".").lower()
    if name == "@":
        return zone or "."
    return f"{name}.{zone}".lower() if zone else name.lower()


def _svcb_parse(value: str, origin: str | None) -> tuple[int, str, list[tuple[str, str | None]]]:
    tokens = _svcb_split(value)
    if len(tokens) < 2:
        return (1, ".", [])
    priority = int(tokens[0]) if tokens[0].isdigit() else 1
    return (priority, svcb_target(tokens[1], origin), _svcb_param_list(tokens[2:]))


def svcb_wire(params: list[tuple[str, str | None]]) -> str:
    """Technitium's ``svcParams`` string for an already-canonical list."""
    parts: list[str] = []
    for key, val in params:
        parts.append(key)
        parts.append(val if val is not None else _SVCB_VALUELESS_PLACEHOLDER)
    return "|".join(parts)


def svcb_params(value: str, origin: str | None = None) -> tuple[int, str, str]:
    """Parse presentation-format SVCB/HTTPS rdata into Technitium's params.

    Input shape is what SpatiumDDI stores and BIND9 renders, e.g.
    ``'1 . alpn="h2,h3"'``: priority, target, then space-separated
    ``key=value`` params with optionally-quoted values. Returns
    ``(priority, target, svcParams)``.

    Technitium's ``svcParams`` wire format is ``key|value`` tokens ALL
    separated by ``|`` — ``alpn|h2,h3|port|53443`` per its API docs;
    ``WebServiceZonesApi`` splits on ``|`` and walks it two at a time.
    Joining pairs with commas (what this did before #1698) works for one
    param only: with two, ``h2,port`` is parsed as a value. A multi-value
    param keeps its commas inside the value (``alpn|h2,h3``).

    Params are emitted in key-number order so a record reads back the way
    it was sent; ``origin`` qualifies a relative target.
    """
    priority, target, params = _svcb_parse(value, origin)
    return (priority, target, svcb_wire(params))


def svcb_canonical(value: str, zone_name: str) -> str:
    """One comparison form for an SVCB/HTTPS value, whoever produced it.

    ``1 . alpn=h2``, ``1 . alpn="h2"`` and ``1 . ALPN=h2`` are one record,
    as are ``svc``, ``svc.zone`` and ``svc.zone.`` as a target in ``zone``;
    params compare in key-number order. The drift / sync identity key
    (#1513) — never what is sent or stored.
    """
    priority, target, params = _svcb_parse(value, zone_name)
    rendered = " ".join(k if v is None else f"{k}={v}" for k, v in params)
    return f"{priority} {target}" + (f" {rendered}" if rendered else "")


# ── Read direction: Technitium rData → stored value ────────────────────


def rdata_to_value(
    rtype: str, rdata: dict[str, Any], origin: str | None = None
) -> tuple[str, dict[str, int]]:
    """Rebuild the presentation-format value from Technitium's rData.

    Returns ``(value, extra)`` where ``extra`` carries the fields
    SpatiumDDI stores in their own columns rather than in the value string
    (MX/SRV ``priority``, SRV ``weight`` / ``port``).

    ``origin`` is the zone name; it lets an SVCB/HTTPS target reported as a
    single label come back absolute (``svc`` -> ``svc.zone.``).
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
        # Technitium reports each param as ``key: ToString()`` - a bare
        # string, with a valueless param (no-default-alpn) null or empty.
        # Rendered unquoted unless a value needs it (#1513).
        raw = rdata.get("svcParams") or {}
        plist = sorted(
            ((str(k).lower(), (None if v in (None, "") else str(v))) for k, v in raw.items()),
            key=lambda kv: (_svcb_key_num(kv[0]), kv[0]),
        )
        rendered = " ".join(k if v is None else f"{k}={_svcb_quote(v)}" for k, v in plist)
        bare = str(rdata.get("svcTargetName") or "").strip().rstrip(".")
        if not bare:
            target = "."
        elif "." in bare:
            target = bare.lower() + "."
        elif origin:
            # A single label is origin-relative, however it got that way.
            target = f"{bare}.{origin.strip().rstrip('.')}".lower() + "."
        else:
            target = bare.lower()
        return (
            f"{int_or(rdata.get('svcPriority'), 1)} {target}"
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
        prio, target, params = svcb_params(value, origin)
        out: dict[str, Any] = {"svcPriority": prio, "svcTargetName": target}
        if params:
            out["svcParams"] = params
        return out
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
