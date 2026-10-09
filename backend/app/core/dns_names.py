"""Shared validation + normalization for DNS-shaped names (issue #597).

One module, so the rule for "what is a legal name here" lives in exactly
one place. The rule is deliberately **per-context** — there is no single
"valid DNS name" regex, because the correct answer depends on the field's
role:

* **Host names** (``IPAddress.hostname``, a DHCP reservation hostname, the
  owner of an A/AAAA/MX record and the names BIND's check-names covers —
  ``bind_check_names_error``) follow RFC 952 + RFC 1123 §2.1 — the classic
  letters-digits-hyphen (LDH) rule: each label 1–63 chars, no leading or
  trailing hyphen, total ≤ 253. Internationalized input is normalized to
  its IDNA A-label (``xn--``) form rather than rejected.

* **DNS record owner labels** (``DNSRecord.name``) follow the looser
  RFC 2181 §11 rule: the DNS protocol permits an underscore, so this is
  what keeps ``_acme-challenge`` (our own ACME DNS-01 client, #438),
  ``_dmarc``, ``_443._tcp`` SRV/TLSA owners, and ``*`` wildcards legal.
  We still reject whitespace, control characters, and the handful of
  characters that are dangerous in a zone-file master line.

* **FQDNs** (``DNSZone.name``, a ``domain-name`` DHCP option, rdata
  targets) are a dotted series of RFC 2181 labels.

Every ``validate_*`` helper raises ``ValueError`` with an operator-facing
message on failure and returns the *normalized* value on success, so a
Pydantic ``field_validator`` can both reject and canonicalize in one step.

``sanitize_hostname`` is the non-raising counterpart used on the DHCP
lease path, where a client-supplied hostname arriving off the wire must be
folded into something safe rather than rejected (a bad hostname must not
drop a lease).
"""

from __future__ import annotations

import re
import unicodedata

import idna

# RFC 1035 §2.3.4 / RFC 2181 §11 — a label is ≤ 63 octets; a name is ≤ 255
# octets on the wire including the length prefixes, which works out to a
# 253-character textual cap for the dotted presentation form.
MAX_LABEL_LEN = 63
MAX_NAME_LEN = 253

# RFC 1123 host label: LDH, 1–63 chars, no leading/trailing hyphen. A
# single-character label is legal (the alternation's optional tail covers
# the ≥ 2 char case).
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

# RFC 2181 owner label as we choose to constrain it: LDH plus underscore.
# Underscore is what the DNS protocol allows and the LDH host rule forbids
# — it is load-bearing for _acme-challenge / _dmarc / _443._tcp owners.
# A leading/trailing hyphen is still rejected; a leading underscore is the
# whole point, so it is allowed.
_DNS_LABEL_RE = re.compile(r"^(?![-])[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")

# Characters that are unsafe inside a zone-file master-format line
# (RFC 1035 §5.1): whitespace splits tokens, a newline injects a new
# record, ``;`` starts a comment, ``$`` starts a directive ($ORIGIN /
# $TTL), ``()`` group across lines, ``"`` quotes, ``@`` means the origin,
# ``\`` escapes, and any C0/C1 control byte is never legitimate in a name.
_ZONEFILE_UNSAFE_RE = re.compile(r'[\s;$()"@\\]|[\x00-\x1f\x7f]')


_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


def contains_control_chars(value: str) -> bool:
    """True if *value* holds a C0/C1 control byte (incl. newline)."""
    return bool(_CONTROL_CHARS_RE.search(value))


def strip_control_chars(value: str) -> str:
    """Remove C0/C1 control characters (incl. newlines) from *value*.

    The render-boundary neutralizer (issue #597): a raw newline is the one
    character that can inject a *second* record into a zone-file line, and no
    legitimate owner name or rdata ever contains a control byte. Applied to
    every name + rdata field as it is written into a master-format line, so a
    value that slipped past the field validators (via an importer or a legacy
    row) still cannot break out of its own record. Unlike
    ``contains_zonefile_unsafe`` this leaves spaces and quotes intact, so
    structured rdata (CAA / LOC / NAPTR / SVCB) renders unharmed.
    """
    return _CONTROL_CHARS_RE.sub("", value)


def contains_zonefile_unsafe(value: str) -> bool:
    """True if *value* contains a character unsafe in a zone-file line.

    Defense-in-depth for the render boundary — a name or rdata string that
    trips this must never be interpolated into a master-format line
    unescaped, regardless of how it got past the field validators (e.g.
    via an importer or a future code path).
    """
    return bool(_ZONEFILE_UNSAFE_RE.search(value))


def _to_ascii_label(label: str) -> str:
    """Return the ASCII (A-label) form of a single label.

    Pure-ASCII labels pass through untouched so underscore / wildcard
    labels survive (the strict IDNA2008 codec would reject them). A label
    carrying non-ASCII is IDNA-encoded to its ``xn--`` form; anything the
    codec refuses raises ``ValueError``.
    """
    if label.isascii():
        return label
    try:
        return idna.encode(label, uts46=True).decode("ascii")
    except idna.IDNAError as exc:
        raise ValueError(f"'{label}' is not a valid internationalized label ({exc})") from exc


def _strip_root(name: str) -> tuple[str, bool]:
    """Split a single optional trailing root dot off *name*.

    Returns ``(name_without_root, had_root_dot)``. A bare ``"."`` (the DNS
    root) yields ``("", True)``.
    """
    if name.endswith("."):
        return name[:-1], True
    return name, False


def validate_host_label(label: str, *, field: str = "hostname") -> str:
    """Validate a single RFC 1123 host label; return it lower-cased.

    Non-ASCII input is normalized to its IDNA A-label first, so a unicode
    label is accepted and canonicalized rather than rejected.
    """
    if not label:
        raise ValueError(f"{field} contains an empty label")
    ascii_label = _to_ascii_label(label)
    if len(ascii_label) > MAX_LABEL_LEN:
        raise ValueError(f"{field} label '{ascii_label}' exceeds {MAX_LABEL_LEN} characters")
    if not _HOST_LABEL_RE.match(ascii_label):
        raise ValueError(
            f"{field} label '{ascii_label}' is not a valid host label "
            "(letters, digits and hyphens only; no leading or trailing hyphen)"
        )
    return ascii_label.lower()


def validate_hostname(name: str, *, field: str = "hostname") -> str:
    """Validate a dotted RFC 1123 host name; return the normalized form.

    Accepts a single label (``web01``) or a multi-label host name
    (``web01.corp.example.com``). Internationalized labels are converted to
    their ``xn--`` A-label form and the whole name is lower-cased. A single
    trailing root dot is tolerated on input but stripped from the result.
    Raises ``ValueError`` on anything that is not a legal host name.
    """
    raw = name.strip()
    if not raw:
        raise ValueError(f"{field} must not be empty")
    body, _ = _strip_root(raw)
    if not body:
        raise ValueError(f"{field} must not be the root domain")
    labels = [validate_host_label(lbl, field=field) for lbl in body.split(".")]
    normalized = ".".join(labels)
    if len(normalized) > MAX_NAME_LEN:
        raise ValueError(f"{field} '{normalized}' exceeds {MAX_NAME_LEN} characters")
    return normalized


def validate_dns_label(label: str, *, field: str = "name", allow_wildcard: bool = False) -> str:
    """Validate a single RFC 2181 owner label (permits ``_``; optional ``*``).

    Used for the label components of a DNS record owner name. A lone ``*``
    is accepted only when *allow_wildcard* is set (the leftmost label of a
    wildcard owner). Non-ASCII is IDNA-normalized. The result is
    lower-cased.
    """
    if not label:
        raise ValueError(f"{field} contains an empty label")
    if label == "*":
        if allow_wildcard:
            return "*"
        raise ValueError(f"{field}: a '*' wildcard is only valid as the leftmost label")
    ascii_label = _to_ascii_label(label)
    if len(ascii_label) > MAX_LABEL_LEN:
        raise ValueError(f"{field} label '{ascii_label}' exceeds {MAX_LABEL_LEN} characters")
    if not _DNS_LABEL_RE.match(ascii_label):
        raise ValueError(
            f"{field} label '{ascii_label}' is not a valid DNS label "
            "(letters, digits, hyphen and underscore only; no leading or trailing hyphen)"
        )
    return ascii_label.lower()


def validate_record_owner(name: str, *, field: str = "record name") -> str:
    """Validate a DNS record owner name (RFC 2181, keeps ``_`` and ``*``).

    This is the rule for ``DNSRecord.name``. It deliberately permits the
    cases strict host validation would break — ``_acme-challenge`` and
    other underscore owners, ``_443._tcp`` SRV/TLSA owners, and a leftmost
    ``*`` wildcard — while still rejecting whitespace, control characters,
    and zone-file-dangerous punctuation.

    ``@`` (the zone apex) and the empty string are both accepted as
    "the apex" and normalized to ``"@"``. A single trailing root dot is
    tolerated on input but *stripped* from the result — ``DNSRecord.name``
    is a relative owner that the handlers concatenate as ``f"{name}.{zone}"``,
    so returning ``www.`` would yield the double-dotted ``www..zone``.
    Returns the normalized, lower-cased owner.
    """
    raw = name.strip()
    if raw in ("", "@"):
        return "@"
    body, _ = _strip_root(raw)
    if not body:
        return "@"
    parts = body.split(".")
    out: list[str] = []
    for i, part in enumerate(parts):
        # A wildcard is only meaningful as the leftmost label.
        out.append(validate_dns_label(part, field=field, allow_wildcard=(i == 0)))
    normalized = ".".join(out)
    if len(normalized) > MAX_NAME_LEN:
        raise ValueError(f"{field} '{normalized}' exceeds {MAX_NAME_LEN} characters")
    return normalized


def validate_fqdn(name: str, *, field: str = "domain", allow_underscore: bool = True) -> str:
    """Validate a fully-qualified domain name; return the normalized form.

    For zone names, ``domain-name`` DHCP options, and rdata targets. A
    dotted series of labels, each validated with the RFC 2181 owner rule
    (``allow_underscore=True``, the default — some zones legitimately carry
    underscore labels, e.g. ``_msdcs.example.com``) or the strict host rule
    when *allow_underscore* is False. Wildcards are not permitted in an
    FQDN. A single trailing root dot is tolerated and stripped.
    """
    raw = name.strip()
    if not raw:
        raise ValueError(f"{field} must not be empty")
    body, _ = _strip_root(raw)
    if not body:
        raise ValueError(f"{field} must not be the root domain")
    if allow_underscore:
        labels = [validate_dns_label(lbl, field=field) for lbl in body.split(".")]
    else:
        labels = [validate_host_label(lbl, field=field) for lbl in body.split(".")]
    normalized = ".".join(labels)
    if len(normalized) > MAX_NAME_LEN:
        raise ValueError(f"{field} '{normalized}' exceeds {MAX_NAME_LEN} characters")
    return normalized


# ── What BIND's check-names refuses (issue #1378) ────────────────────────
# BIND loads a primary zone under ``check-names primary fail`` unless told
# otherwise, and the agent renders no check-names option, so named-checkzone
# (the agent's pre-swap zone check, run with ``-k fail``) refuses a zone file
# that breaks the rule below, and the agent then quarantines the server's
# whole config bundle. The RFC 2181 owner rule above allows ``_`` in any
# owner, so the record API used to store records the group's own BIND would
# not load. The rule, as BIND applies it (``dns_rdata_checkowner`` /
# ``dns_rdata_checknames``):
#
# * the OWNER of an A, AAAA or MX record must be a host name. The whole owner
#   name counts, the zone's own labels included; a leftmost ``*`` is allowed.
#   BIND's two exceptions: Active Directory's ``gc._msdcs.<host>`` (A and
#   AAAA), and an A owner with an SPF "exists" label — ``_spf``,
#   ``_spf_verify`` or ``_spf_rate`` — anywhere but its last label.
# * the TARGET of an MX, NS or SRV record must be a host name, and so must an
#   SVCB or HTTPS TargetName in ServiceMode (an AliasMode target is not
#   checked).
# * the TARGET of a PTR must be a host name when the owner is a reverse
#   mapping name (under in-addr.arpa, ip6.arpa or ip6.int), except DNS-SD's
#   browsing-domain records (``b._dns-sd._udp.<domain>`` and its kin).
#
# "Host name" is RFC 952 as relaxed by RFC 1123: every label is letters,
# digits and hyphens with no leading or trailing hyphen (``_HOST_LABEL_RE``).
# The root name (a null MX, an SRV "no service here" target) qualifies.
# Every case here was checked against named-checkzone 9.20.29 with the
# agent's own flags (``-i none -k fail``) on the appliance's dns-bind9 image.

BIND_HOST_OWNER_TYPES = frozenset({"A", "AAAA", "MX"})
BIND_HOST_TARGET_TYPES = frozenset({"MX", "NS", "SRV"})
BIND_SERVICE_BINDING_TYPES = frozenset({"SVCB", "HTTPS"})
_REVERSE_MAPPING_SUFFIXES = ("in-addr.arpa", "ip6.arpa", "ip6.int")
_DNSSD_BROWSE_PREFIXES = frozenset(
    (first, "_dns-sd", "_udp") for first in ("b", "db", "lb", "r", "dr")
)
_AD_GC_PREFIX = ("gc", "_msdcs")
_SPF_EXISTS_LABELS = frozenset({"_spf", "_spf_verify", "_spf_rate"})


def _first_non_host_label(name: str, *, wildcard: bool) -> str | None:
    """The first label of *name* that is not a host-name label, or None.

    *name* is a dotted presentation name; a trailing root dot is ignored and
    the root itself is a host name. With *wildcard*, a leftmost ``*`` label
    passes, as it does for an owner in BIND.
    """
    body = name.strip().rstrip(".")
    if not body:
        return None
    for i, label in enumerate(body.split(".")):
        if wildcard and i == 0 and label == "*":
            continue
        if not label.isascii() or not _HOST_LABEL_RE.match(label):
            return label
    return None


def _zone_absolute(name: str, origin: str) -> str:
    """*name* the way a zone file whose ``$ORIGIN`` is *origin* reads it.

    The agent writes record values into the zone file as they are stored, so a
    name without a trailing dot is relative to the zone, and ``@`` is the zone.
    """
    name = name.strip()
    origin = origin.strip().rstrip(".") + "."
    if name in ("", "@"):
        return origin
    if name.endswith("."):
        return name
    return f"{name}.{origin}" if origin != "." else f"{name}."


def _bind_owner_exempt(record_type: str, owner: str) -> bool:
    """BIND's own exceptions to the owner rule (``checkowner_in_a`` /
    ``checkowner_in_aaaa``): Active Directory's global-catalog name
    ``gc._msdcs.<host>`` for an A or AAAA, and for an A an owner carrying an
    SPF "exists" label (RFC 7208 section 5.7 and appendix D.1) in any label
    but the last.
    """
    labels = owner.strip().rstrip(".").split(".")
    lowered = [label.lower() for label in labels]
    if (
        record_type in ("A", "AAAA")
        and len(labels) >= 2
        and tuple(lowered[:2]) == _AD_GC_PREFIX
        and _first_non_host_label(".".join(labels[2:]), wildcard=False) is None
    ):
        return True
    return record_type == "A" and any(label in _SPF_EXISTS_LABELS for label in lowered[:-1])


def _is_reverse_mapping(owner: str) -> bool:
    labels = owner.strip().rstrip(".").lower().split(".")
    if tuple(labels[:3]) in _DNSSD_BROWSE_PREFIXES:
        return False
    body = ".".join(labels)
    return any(body == s or body.endswith("." + s) for s in _REVERSE_MAPPING_SUFFIXES)


def bind_check_names_error(
    record_type: str,
    owner: str,
    value: str | None,
    *,
    origin: str,
    check_owner: bool = True,
    check_target: bool = True,
) -> str | None:
    """Why BIND's default ``check-names`` would refuse this record, or None.

    *owner* is the record's full owner name (relative owner + zone), *value*
    its stored value and *origin* the zone's name. MX and SRV values may carry
    the priority (and weight and port) inline on some paths, so their target
    is the value's last token; an SVCB or HTTPS value is ``priority target
    params…``. *check_owner* / *check_target* let an edit check only what it
    changes, so a TTL edit on a row that predates the rule still goes
    through. The message is operator-facing.
    """
    rtype = record_type.strip().upper()
    if check_owner and rtype in BIND_HOST_OWNER_TYPES:
        owner_abs = _zone_absolute(owner, origin)
        bad = _first_non_host_label(owner_abs, wildcard=True)
        if bad is not None and not _bind_owner_exempt(rtype, owner_abs):
            return (
                f"{rtype} record name '{owner_abs.rstrip('.')}' is not a host name: "
                f"its label '{bad}' may only hold letters, digits and hyphens, "
                "with no leading or trailing hyphen (RFC 1123). BIND refuses a "
                "zone that holds it (check-names), which stops the server applying "
                "its configuration. An underscore name suits TXT, SRV and similar "
                "records, not an address or mail exchanger."
            )
    if not check_target or value is None:
        return None
    tokens = value.split()
    if not tokens:
        return None
    if rtype in BIND_HOST_TARGET_TYPES:
        target = tokens[-1]
    elif rtype in BIND_SERVICE_BINDING_TYPES:
        # ServiceMode only: an AliasMode (priority 0) target is not checked.
        if len(tokens) < 2 or not tokens[0].isdigit() or int(tokens[0]) == 0:
            return None
        target = tokens[1]
    elif rtype == "PTR" and _is_reverse_mapping(_zone_absolute(owner, origin)):
        target = tokens[-1]
    else:
        return None
    target_abs = _zone_absolute(target, origin)
    bad = _first_non_host_label(target_abs, wildcard=False)
    if bad is None:
        return None
    return (
        f"{rtype} record target '{target_abs.rstrip('.')}' is not a host name: its "
        f"label '{bad}' may only hold letters, digits and hyphens, with no leading "
        "or trailing hyphen (RFC 1123). BIND refuses a zone that holds it "
        "(check-names), which stops the server applying its configuration."
    )


# ── Non-raising sanitizer (DHCP lease path) ──────────────────────────────
# A client-supplied hostname arriving off the wire (a DHCP DISCOVER option
# 12, a lease event) must be folded into something safe rather than
# rejected — a malformed hostname must never drop the lease or 500 the
# ingest. Mirrors services/dns/ddns._sanitise but is multi-label aware so
# a client that sends "my pc.corp" becomes "my-pc.corp", not "my-pc-corp".

_SANITIZE_LABEL_RE = re.compile(r"[^a-z0-9-]+")


def sanitize_host_label(raw: str | None) -> str:
    """Fold a raw string into a single safe LDH label (``""`` if nothing left)."""
    if not raw:
        return ""
    s = raw.strip().strip('"').lower()
    s = _SANITIZE_LABEL_RE.sub("-", s)
    # Truncate FIRST, then strip hyphens — truncating at MAX_LABEL_LEN can land
    # on a hyphen and re-expose a trailing one, which ``validate_host_label``
    # (correctly) rejects and which breaks a BIND9 zone load. Stripping after
    # the cut keeps the sanitizer's output a valid label (issue #597 review).
    return s[:MAX_LABEL_LEN].strip("-")


def sanitize_hostname(raw: str | None) -> str:
    """Fold a raw client hostname into a safe LDH host name (``""`` if empty).

    Splits on dots and sanitizes each label independently, dropping labels
    that reduce to nothing, then caps the whole name at ``MAX_NAME_LEN``.
    Non-raising by contract — returns ``""`` when there is nothing usable,
    which callers treat as "no hostname".
    """
    if not raw:
        return ""
    labels = [lbl for lbl in (sanitize_host_label(p) for p in raw.split(".")) if lbl]
    if not labels:
        return ""
    name = ".".join(labels)
    if len(name) <= MAX_NAME_LEN:
        return name
    # Trim whole trailing labels until it fits, so we never emit a
    # truncated (and possibly hyphen-tailed) partial label.
    while labels and len(".".join(labels)) > MAX_NAME_LEN:
        labels.pop()
    return ".".join(labels)


# ── Integration-mirrored names (#1459) ────────────────────────────────────
# A read-only integration (UniFi, Docker, Proxmox, Meraki, the cloud
# providers, OPNsense, the firewall mirrors, ...) copies an upstream display
# name into ``IPAddress.hostname``, and IPAM's DNS sync publishes that as a
# record owner. Upstream names are free text ("Vitrinen Schalter",
# "John's iPhone", "compose_project.web"), so they are folded here before
# they reach IPAM.

# German umlauts read better spelled out than dropped ("buero", not "bro").
# Anything else non-ASCII loses its accents through NFKD below.
_TRANSLITERATE = str.maketrans(
    {"ä": "ae", "ö": "oe", "ü": "ue", "Ä": "Ae", "Ö": "Oe", "Ü": "Ue", "ß": "ss"}
)
_APOSTROPHES_RE = re.compile(r"['’`]")


def _is_host_name(name: str) -> bool:
    """Whether *name* is already a legal ASCII host name, exactly as written."""
    if not name or len(name) > MAX_NAME_LEN or not name.isascii():
        return False
    return all(_HOST_LABEL_RE.match(label) for label in name.split("."))


def sanitize_mirrored_hostname(raw: str | None) -> str:
    """Fold an integration's upstream name into a legal host name.

    A name that is already a legal host name is returned unchanged, case
    included, so mirrors that already publish good names don't see their
    records renamed. Anything else is transliterated (``Büro`` → ``buero``),
    stripped of apostrophes (``John's`` → ``johns``) and folded with
    :func:`sanitize_hostname`. Non-raising: ``""`` means nothing usable is
    left, which callers treat as "no hostname".
    """
    if not raw:
        return ""
    name = raw.strip()
    if _is_host_name(name):
        return name
    folded = unicodedata.normalize("NFKD", name.translate(_TRANSLITERATE))
    folded = "".join(ch for ch in folded if not unicodedata.combining(ch))
    return sanitize_hostname(_APOSTROPHES_RE.sub("", folded))
