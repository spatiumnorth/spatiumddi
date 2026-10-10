"""TXT record presentation-form quoting (issues #1514, #1609, #1694).

One helper shared by this package's DNS drivers so the copies cannot
drift. The control plane (``backend/app/drivers/dns/_txt.py``) and the
DNS agent (``agent/dns/spatium_dns_agent/drivers/_txt.py``) are
deployed separately and each carry an identical copy of this module —
change both together.

TXT values are stored either unquoted (zone templates, most API
clients) or already in presentation form (one or more quoted
character-strings, possibly with ``\\DDD`` escapes). Both must reach
the server as the operator meant them:

* An **unquoted** value is ONE logical string. It is quoted, escaped,
  and split into character-strings of at most 255 octets, never inside
  a UTF-8 character.
* An **already-quoted** value round-trips exactly: each quoted
  character-string stays a separate character-string (DNS-SD TXT
  records carry one ``key=value`` per string, so joining them changes
  the record), and ``\\DDD`` is ONE octet (RFC 1035 §5.1), not a code
  point. Only a string over the 255-octet limit is split further.

All work is done in bytes. On output, printable ASCII is emitted as
itself (``"`` and ``\\`` escaped), a valid printable UTF-8 character as
the character itself (BIND9 and PowerDNS both store the raw UTF-8
octets), and every other octet as ``\\DDD``, which both engines read as
that single octet.
"""

from __future__ import annotations

_MAX_STRING_OCTETS = 255


def _strip_control(value: str) -> str:
    return "".join(ch for ch in value if ord(ch) >= 0x20 and ord(ch) != 0x7F)


def _parse_quoted_txt(s: str) -> list[bytes] | None:
    """Decode a fully-quoted TXT presentation form into its
    character-strings (as octets), or None if ``s`` is not exactly one
    or more quoted character-strings separated by whitespace."""
    parts: list[bytes] = []
    i, n = 0, len(s)
    while i < n:
        if s[i].isspace():
            i += 1
            continue
        if s[i] != '"':
            return None
        i += 1
        buf = bytearray()
        closed = False
        while i < n:
            ch = s[i]
            if ch == "\\":
                if i + 1 >= n:
                    return None
                digits = s[i + 1 : i + 4]
                if len(digits) == 3 and digits.isdigit() and digits.isascii():
                    octet = int(digits)
                    if octet > 255:
                        return None
                    buf.append(octet)
                    i += 4
                    continue
                buf += s[i + 1].encode("utf-8")
                i += 2
                continue
            if ch == '"':
                closed = True
                i += 1
                break
            buf += ch.encode("utf-8")
            i += 1
        if not closed:
            return None
        parts.append(bytes(buf))
        if i < n and not s[i].isspace():
            return None
    return parts or None


def _chunk_octets(data: bytes) -> list[bytes]:
    """Split ``data`` into pieces of at most 255 octets, cutting before
    a UTF-8 lead byte rather than inside a multi-byte character where
    the data allows it."""
    if not data:
        return [b""]
    chunks: list[bytes] = []
    pos, n = 0, len(data)
    while pos < n:
        end = min(pos + _MAX_STRING_OCTETS, n)
        if end < n and (data[end] & 0xC0) == 0x80:
            # ``end`` lands on a continuation byte — back up to the lead
            # byte of that character (at most 3 octets back).
            k = end
            while k > pos and end - k < 3 and (data[k] & 0xC0) == 0x80:
                k -= 1
            if k > pos and (data[k] & 0xC0) == 0xC0:
                end = k
        chunks.append(data[pos:end])
        pos = end
    return chunks


def _utf8_seq_len(lead: int) -> int:
    if 0xC2 <= lead <= 0xDF:
        return 2
    if 0xE0 <= lead <= 0xEF:
        return 3
    if 0xF0 <= lead <= 0xF4:
        return 4
    return 0


def _escape_octets(data: bytes) -> str:
    out: list[str] = []
    i, n = 0, len(data)
    while i < n:
        c = data[i]
        if c == 0x22:
            out.append('\\"')
        elif c == 0x5C:
            out.append("\\\\")
        elif 0x20 <= c < 0x7F:
            out.append(chr(c))
        else:
            seq = _utf8_seq_len(c)
            if seq and i + seq <= n:
                try:
                    char = data[i : i + seq].decode("utf-8")
                except UnicodeDecodeError:
                    char = ""
                if char and char.isprintable():
                    out.append(char)
                    i += seq
                    continue
            out.append(f"\\{c:03d}")
        i += 1
    return "".join(out)


def txt_strings(value: str) -> list[bytes]:
    """The character-strings a stored TXT value stands for, as octets,
    each at most 255 of them: what ``quote_txt`` renders, before it
    escapes them. For a server that takes the strings themselves rather
    than presentation form (Technitium, #1694).

    Control characters are stripped from the stored value first. See
    the module docstring for how unquoted vs already-quoted values are
    treated.
    """
    s = _strip_control(value)
    strings: list[bytes] | None = None
    stripped = s.strip()
    if stripped.startswith('"'):
        strings = _parse_quoted_txt(stripped)
    if strings is None:
        strings = [s.encode("utf-8")]
    return [chunk for string in strings for chunk in _chunk_octets(string)]


def quote_txt(value: str) -> str:
    """Render a stored TXT value as RFC 1035 presentation form.

    Control characters are stripped from the stored value first. See
    the module docstring for how unquoted vs already-quoted values are
    treated.
    """
    return " ".join(f'"{_escape_octets(c)}"' for c in txt_strings(value))
