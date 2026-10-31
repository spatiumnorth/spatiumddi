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

import ipaddress
import re
import unicodedata

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import idna

# RFC 1035 §2.3.4 / RFC 2181 §11 — a label is ≤ 63 octets; a name is ≤ 255
# octets on the wire including the length prefixes, which works out to a
# 253-character textual cap for the dotted presentation form.
MAX_LABEL_LEN = 63
MAX_NAME_LEN = 253

# RFC 1123 host label: LDH, 1–63 chars, no leading/trailing hyphen. A
# single-character label is legal (the alternation's optional tail covers
# the ≥ 2 char case). Anchored with ``\Z``, not ``$``: Python's ``$`` also
# matches before a trailing newline, so ``web1\n`` passed as a host label
# (#2071 — a bulk-allocate template ending in a newline stored one).
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")

# RFC 2181 owner label as we choose to constrain it: LDH plus underscore.
# Underscore is what the DNS protocol allows and the LDH host rule forbids
# — it is load-bearing for _acme-challenge / _dmarc / _443._tcp owners.
# A leading/trailing hyphen is still rejected; a leading underscore is the
# whole point, so it is allowed. ``\Z`` for the same reason as above.
_DNS_LABEL_RE = re.compile(r"^(?![-])[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\Z")

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


# ── Full-name length (issue #2072) ───────────────────────────────────────
# The per-field validators above cap a name on its own. A host name is
# published as ``<hostname>.<zone>``, and the limit that matters is on that
# whole name: RFC 1035 section 3.1 / 2.3.4 caps a name at 255 octets on the
# wire, each label costing its length plus one length octet, plus the one
# octet of the root label. For a dotted presentation name with no trailing dot
# that is ``len(name) + 2 <= 255``, i.e. 253 characters, and every label
# <= 63. A 243-character hostname is valid alone; inside a 33-character zone it
# is 277, which BIND refuses ("ran out of space") together with the zone that
# holds the record and the reverse zone that holds the PTR naming it.


def name_length_error(name: str, *, field: str = "name") -> str | None:
    """Why *name* cannot be a DNS name on the wire, or None.

    *name* is a dotted presentation name; one trailing root dot is ignored.
    Checks the whole name (<= ``MAX_NAME_LEN`` characters, i.e. 255 wire
    octets) and each label (<= ``MAX_LABEL_LEN``). Length only: character
    rules stay with the per-context validators. Never truncates.
    """
    body = name.strip().rstrip(".")
    if len(body) > MAX_NAME_LEN:
        return (
            f"{field} '{body}' is {len(body)} characters, over the "
            f"{MAX_NAME_LEN}-character limit of a DNS name (255 octets on the wire)"
        )
    for label in body.split("."):
        if len(label) > MAX_LABEL_LEN:
            return f"{field} label '{label}' exceeds {MAX_LABEL_LEN} characters"
    return None


def name_in_zone_error(hostname: str, zone_name: str, *, field: str = "hostname") -> str | None:
    """Why ``<hostname>.<zone_name>`` cannot be published, or None.

    The message names *field* and the length the name would reach, so the
    operator knows to shorten the hostname or pick another zone.
    """
    zone = zone_name.strip().rstrip(".")
    host = hostname.strip().rstrip(".")
    if not host or not zone:
        return None
    full = f"{host}.{zone}"
    err = name_length_error(full, field=field)
    if err is None:
        return None
    if len(full) > MAX_NAME_LEN:
        return (
            f"{field}: '{host}' in zone '{zone}' makes a {len(full)}-character name; a "
            f"DNS name holds at most {MAX_NAME_LEN} characters, and BIND refuses a "
            "zone that holds one longer. Shorten the hostname or choose another zone."
        )
    return err


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
# Types whose rdata ends in a domain name (the length check, #2072).
_TARGET_LENGTH_TYPES = frozenset({"MX", "NS", "SRV", "CNAME", "PTR", "DNAME"})
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


def primary_ns_error(value: str | None) -> str | None:
    """Why *value* cannot be a zone's Primary NS (the SOA MNAME), or None.

    The MNAME is a host name BIND checks (``check-names``): an underscore or a
    label over 63 characters makes it refuse the whole zone, so the group never
    serves it (#2075). It is stored in absolute form, with or without the
    trailing dot (the agent reads both as absolute), so a single label such as
    ``ns1`` would be served as a name at the root, not under the zone; that is
    refused rather than guessed at. Empty means "not set" and is allowed.
    """
    if value is None or value == "":
        return None
    body = value[:-1] if value.endswith(".") else value
    if not body or "." not in body:
        return (
            "must be a fully qualified host name such as ns1.example.com. "
            "(a single label such as 'ns1' would be served as a name at the "
            "root, not under the zone)"
        )
    if len(body) > MAX_NAME_LEN:
        return f"exceeds {MAX_NAME_LEN} characters"
    for label in body.split("."):
        if not label:
            return "contains an empty label"
        if len(label) > MAX_LABEL_LEN:
            return f"label '{label[:20]}…' exceeds {MAX_LABEL_LEN} characters"
        if not label.isascii() or not _HOST_LABEL_RE.match(label):
            return (
                f"label '{label}' is not a host name label: letters, digits and "
                "hyphens only, with no leading or trailing hyphen (RFC 1123). "
                "BIND refuses a zone whose SOA primary name is not a host name"
            )
    return None


# BIND's ``dns_name_ismailbox``: the first label of an SOA RNAME (the
# mailbox's local part) may hold any printable ASCII character but a space;
# only the labels after it are held to the host-name rule. Measured against
# named-checkzone 9.20: ``admin+dns``, ``dns_admin`` and ``a!b`` load, while
# ``hostmaster.under_score.example.com.`` is refused (check-names).
_MAILBOX_LOCAL_RE = re.compile(r"^[\x21-\x7e]+\Z")


def admin_email_error(value: str | None) -> str | None:
    """Why *value* cannot be a zone's Admin Email (the SOA RNAME), or None.

    The RNAME is a mailbox in domain-name form (``hostmaster.example.com.``,
    the first label being the local part). BIND's check-names reads it as a
    mailbox: the local part is any printable ASCII (``admin+dns``,
    ``dns_admin``), and every label after it must be a host name label. One
    that is not makes BIND refuse the whole zone, so the group never serves
    it (#2916). Like the Primary NS (:func:`primary_ns_error`), a single label
    would be read as a name at the root, so it is refused. Characters a
    master file cannot carry unescaped (``@``, ``\\``, ``;`` …) are refused
    by :func:`contains_zonefile_unsafe` too, so a local part holding a dot
    cannot be written. Empty means "not set" and is allowed.
    """
    if value is None or value == "":
        return None
    if contains_zonefile_unsafe(value):
        return (
            "must be a mailbox in domain-name form such as hostmaster.example.com. "
            "(no whitespace, control characters, or zone-file syntax such as '@')"
        )
    body = value[:-1] if value.endswith(".") else value
    if not body or "." not in body:
        return (
            "must be a mailbox in domain-name form such as hostmaster.example.com. "
            "(a single label such as 'hostmaster' would be read as a name at the root)"
        )
    if len(body) > MAX_NAME_LEN:
        return f"exceeds {MAX_NAME_LEN} characters"
    for i, label in enumerate(body.split(".")):
        if not label:
            return "contains an empty label"
        if len(label) > MAX_LABEL_LEN:
            return f"label '{label[:20]}…' exceeds {MAX_LABEL_LEN} characters"
        if not label.isascii():
            return (
                f"label '{label}' is not ASCII; write an internationalised domain "
                "in its xn-- form"
            )
        if i == 0:
            if not _MAILBOX_LOCAL_RE.match(label):
                return f"mailbox name '{label}' holds a character BIND does not accept"
        elif not _HOST_LABEL_RE.match(label):
            return (
                f"label '{label}' is not a host name label: letters, digits and "
                "hyphens only, with no leading or trailing hyphen (RFC 1123). "
                "BIND refuses a zone whose SOA mailbox domain is not a host name"
            )
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


def _owner_absolute(owner: str, origin: str) -> str:
    """*owner* (a full owner name, zone included) as an absolute name.

    Unlike :func:`_zone_absolute`, a dotless owner that already ends in the
    zone is taken as it stands, so the length check (#2072) measures the name
    once whether or not the zone row carries its root dot.
    """
    name = owner.strip()
    zone = origin.strip().rstrip(".").lower()
    body = name.rstrip(".").lower()
    if zone and (body == zone or body.endswith("." + zone)):
        return name.rstrip(".") + "."
    return _zone_absolute(name, origin)


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
    if check_owner:
        # #2072 — the whole owner name, zone included, must fit a DNS name.
        # *owner* already carries the zone; a zone stored without its root
        # dot (synthesised and imported zones) would make _zone_absolute
        # append it a second time and refuse a name that fits.
        too_long = name_length_error(_owner_absolute(owner, origin), field=f"{rtype} record name")
        if too_long is not None:
            return too_long + "; BIND refuses a zone that holds it."
    if check_target and value is not None and rtype in _TARGET_LENGTH_TYPES:
        tokens_ = value.split()
        if tokens_:
            too_long = name_length_error(
                _zone_absolute(tokens_[-1], origin), field=f"{rtype} record target"
            )
            if too_long is not None:
                return too_long + "; BIND refuses a zone that holds it."
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
        if (
            len(tokens) < 2
            or not (tokens[0].isascii() and tokens[0].isdigit())
            or int(tokens[0]) == 0
        ):
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


# Types whose value is not zone-file rdata dnspython can read: TXT / SPF are
# quoted at render, ALIAS / LUA are PowerDNS-only syntax.
_RDATA_UNCHECKED_TYPES = frozenset({"TXT", "SPF", "ALIAS", "LUA"})


def structured_rdata_error(
    record_type: str,
    value: str,
    *,
    priority: int | None = None,
    weight: int | None = None,
    port: int | None = None,
    origin: str | None = None,
) -> str | None:
    """Why dnspython cannot read this record's rdata, or None if it can (#2502).

    The BIND9 agent writes ``value`` into the zone file verbatim, after
    prefixing the MX priority / SRV priority+weight+port exactly as composed
    here, and ``named-checkzone`` then refuses the whole zone. A / AAAA and the
    bare-name targets are checked elsewhere; a type dnspython does not know is
    not judged.
    """
    rtype = record_type.upper()
    if rtype in _RDATA_UNCHECKED_TYPES:
        return None
    try:
        rdtype = dns.rdatatype.from_text(rtype)
    except dns.rdatatype.UnknownRdatatype:
        return None
    wire = value
    if rtype == "MX" and priority is not None:
        if not wire.lstrip().split(" ", 1)[0].isdigit():
            wire = f"{priority} {wire}"
    elif (
        rtype == "SRV"
        and priority is not None
        and weight is not None
        and port is not None
        and len(wire.split()) < 4
    ):
        wire = f"{priority} {weight} {port} {wire}"
    try:
        org = dns.name.from_text(origin) if origin else None
        dns.rdata.from_text(dns.rdataclass.IN, rdtype, wire, origin=org)
    except Exception as exc:  # noqa: BLE001 — from_text raises a different type per rdata class
        return f"{rtype} record value {value!r} is not valid {rtype} rdata: {exc}"
    return None


def validate_optional_hostname(v: str | None, *, field: str = "hostname") -> str | None:
    """An optional host name: ``None`` stays ``None``, blank becomes ``""``.

    A whitespace-only value is "no hostname", not a hostname of spaces: kept
    verbatim it reached the IPAM mirror as a truthy name and was published as
    a record owner of blanks. A non-blank value must be a legal RFC 1123 host
    name and is returned normalized (see :func:`validate_hostname`).
    """
    if v is None:
        return None
    if v.strip() == "":
        return ""
    return validate_hostname(v, field=field)


def host_in_zone_error(hostname: str, zone_name: str, *, field: str = "hostname") -> str | None:
    """Why an address's host record ``<hostname>.<zone_name>`` cannot be published.

    The IPAM -> DNS publish path's one rule for the full owner name: the
    253-character limit (``name_in_zone_error``) and the record API's own
    check-names rule for an A / AAAA owner (``bind_check_names_error``), which
    walks the zone's labels as well as the host's. A zone named with an
    underscore label takes TXT / SRV but no host record, and BIND refuses the
    zone whole if one is written (#2918). The rule holds for the default-gateway
    placeholder (``gateway``) too: it publishes no forward record, but its PTR
    names ``gateway.<zone>``, and BIND's check-names refuses a reverse zone
    whose PTR target is not a host name just as it refuses the forward zone.
    """
    err = name_in_zone_error(hostname, zone_name, field=field)
    if err is not None:
        return err
    host = hostname.strip().rstrip(".")
    zone = zone_name.strip().rstrip(".")
    if not host or not zone:
        return None
    # The owner absolute (root dot): a relative one has the origin appended
    # again, which the message would then quote doubled.
    return bind_check_names_error("A", f"{host}.{zone}.", None, origin=zone, check_target=False)


def publishable_host_owner_error(hostname: str | None) -> str | None:
    """Why *hostname* cannot be published as a record owner, or None.

    The IPAM → DNS sync writes ``hostname`` verbatim as the owner of the
    address's A / AAAA record. The request models validate it, but a row can
    reach the sync by other paths (importers, integration mirrors, rows stored
    before a validator existed), so the sync checks it once more. Refused:
    a blank or whitespace-only name, surrounding whitespace, any control
    character, the apex (``@``), and anything the RFC 2181 owner rule rejects.
    """
    if hostname is None or hostname.strip() == "":
        return "hostname is blank"
    if hostname != hostname.strip() or contains_control_chars(hostname):
        return "hostname contains whitespace or a control character"
    try:
        owner = validate_record_owner(hostname, field="hostname")
    except ValueError as exc:
        return str(exc)
    if owner == "@":
        return "hostname cannot name the zone apex"
    return None


# Record types whose rdata is a single bare target *name*, validated as an
# FQDN (issue #597). MX / SRV are deliberately excluded: their value may carry
# the priority / weight / port inline (``10 mail.example.com``) on some client
# and driver paths, so an FQDN check would reject a legitimate value — the
# control-character guard still protects them. TXT (freeform, quoted at
# render), the structured types and A / AAAA are checked their own way.
HOSTNAME_TARGET_RECORD_TYPES = frozenset({"CNAME", "NS", "PTR", "DNAME", "ALIAS"})


def record_value_error(
    record_type: str,
    value: str,
    *,
    priority: int | None = None,
    weight: int | None = None,
    port: int | None = None,
    origin: str | None = None,
) -> str | None:
    """Why *value* is not acceptable record data for *record_type*, or None.

    The one rule the REST record endpoints and the operation layer (requests
    portal, Copilot) share, so the two cannot accept different values:

    * a control character or newline is refused for every type — it is the
      one thing that ends a zone-file line early and starts another record;
    * A / AAAA must be a single address of the matching family;
    * a bare-name target type must be a valid FQDN;
    * any other type must be rdata dnspython can read
      (:func:`structured_rdata_error`).
    """
    rtype = record_type.upper()
    if contains_control_chars(value):
        return (
            f"{rtype} record value contains a control character or newline, "
            "which is not allowed in DNS record data."
        )
    if rtype in HOSTNAME_TARGET_RECORD_TYPES:
        try:
            validate_fqdn(value, field=f"{rtype} record target")
        except ValueError as exc:
            return str(exc)
        return None
    if rtype not in ("A", "AAAA"):
        return structured_rdata_error(
            rtype, value, priority=priority, weight=weight, port=port, origin=origin
        )
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError:
        parsed = None
    if parsed is not None and (
        (rtype == "A" and parsed.version == 4) or (rtype == "AAAA" and parsed.version == 6)
    ):
        return None
    fam = "IPv4" if rtype == "A" else "IPv6"
    return (
        f"{rtype} record value must be a single {fam} address. To point one "
        "name at several IPs, add one record per address (round-robin) or "
        "use a DNS Pool for health-checked failover — not a comma-separated "
        "list in one record."
    )
