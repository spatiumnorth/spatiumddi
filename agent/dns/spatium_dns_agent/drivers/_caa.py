"""CAA value parsing and presentation (#2943).

One helper shared by this package's DNS drivers, so the copies cannot drift.
The control plane (``backend/app/drivers/dns/_caa.py``) and the DNS agent
(``agent/dns/spatium_dns_agent/drivers/_caa.py``) are deployed separately and
each carry an identical copy of this module — change both together
(``backend/tests/test_caa_helper_parity.py`` fails when they differ).

A stored CAA value is ``<flags> <tag> <value>`` and the value part comes in
two spellings, which are ONE record:

* **bare**: ``0 issue letsencrypt.org``. The value is the rest of the text
  exactly as written, so ``ca.org; account=1`` is all one value. A zone-file
  reader would take the ``;`` as a comment; a provider that takes the value
  as given (Azure) serves all of it.
* **quoted**: ``0 issue "letsencrypt.org"``, one quoted character-string whose
  ``\\"``, ``\\\\`` and ``\\DDD`` escapes are undone.

This is the same reading as ``caa_canonical`` in
``app/services/dns/pull_from_server.py`` (#2925), without its dnspython
dependency, because the agent image carries the same copy of this file.
:func:`caa_presentation` prints the form dnspython prints for the same rdata,
so a value written through it keys identically to one read back off a server.
"""

from __future__ import annotations

import re

_FIELDS = re.compile(r"^(\d+)\s+(\S+)\s+(.*)$", re.S)


def _unquote(rest: str) -> bytes | None:
    """The octets of ``rest`` when it is exactly one quoted string, else None."""
    if len(rest) < 2 or rest[0] != '"':
        return None
    out = bytearray()
    i, n = 1, len(rest)
    while i < n:
        ch = rest[i]
        if ch == "\\":
            digits = rest[i + 1 : i + 4]
            if len(digits) == 3 and digits.isdigit() and digits.isascii():
                n_octet = int(digits)
                if n_octet > 255:
                    return None
                out.append(n_octet)
                i += 4
                continue
            if i + 1 >= n:
                return None
            out.extend(rest[i + 1].encode("utf-8"))
            i += 2
            continue
        if ch == '"':
            # Only whitespace may follow the closing quote.
            return bytes(out) if not rest[i + 1 :].strip() else None
        out.extend(ch.encode("utf-8"))
        i += 1
    return None  # unterminated


def parse_caa(value: str) -> tuple[int, str, bytes] | None:
    """``(flags, tag, value octets)`` of a stored CAA value, or None when it
    is not ``<flags> <tag> <value>`` (or its quoted value is malformed)."""
    m = _FIELDS.match((value or "").strip())
    if m is None:
        return None
    flags, tag, rest = m.groups()
    raw = _unquote(rest) if rest.startswith('"') else rest.encode("utf-8")
    if raw is None:
        return None
    return int(flags), tag, raw


def _escape(raw: bytes) -> str:
    out: list[str] = []
    for b in raw:
        if b in (0x22, 0x5C):
            out.append("\\" + chr(b))
        elif 0x20 <= b < 0x7F:
            out.append(chr(b))
        else:
            out.append(f"\\{b:03d}")
    return "".join(out)


def caa_text(flags: int, tag: str, raw: bytes | str) -> str:
    """``<flags> <tag> "<escaped value>"``: the quoted presentation form."""
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    return f'{int(flags)} {tag} "{_escape(data)}"'


def caa_presentation(value: str) -> str:
    """The quoted presentation form of a stored value (what a zone file,
    Route 53, Google Cloud DNS and PowerDNS take). Unparseable: unchanged."""
    parsed = parse_caa(value)
    if parsed is None:
        return value
    flags, tag, raw = parsed
    return caa_text(flags, tag, raw)


def caa_unquoted_value(value: str) -> str | None:
    """The value part as the text a structured provider API takes (Azure's
    ``value``, Technitium's ``value``): no surrounding quotes, no escapes.
    None when the stored value does not parse."""
    parsed = parse_caa(value)
    if parsed is None:
        return None
    return parsed[2].decode("utf-8", errors="replace")


def caa_key(value: str) -> str:
    """A comparison key: the presentation form with the tag lower-cased
    (RFC 8659 §4.1). Unparseable values key as their whitespace-folded text."""
    parsed = parse_caa(value)
    if parsed is None:
        return " ".join((value or "").split())
    flags, tag, raw = parsed
    return caa_text(flags, tag.lower(), raw)
