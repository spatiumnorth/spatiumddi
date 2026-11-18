"""PowerDNS Authoritative query-log line parser.

PowerDNS writes one stderr line per incoming query when both
``log-dns-queries=yes`` and ``log-dns-details=yes`` are set in
``pdns.conf``. The agent's stderr capture redirects that output
into ``/var/log/pdns/pdns.log`` and the QueryLogShipper tails the
file. This parser converts each line into the same
:class:`~app.services.logs.bind9_parser.ParsedQueryLine` shape so
the ingest endpoint can dispatch by ``server.driver`` without the
storage layer caring which DNS daemon emitted the line.

Sample line shapes pdns 4.9 emits::

    May 08 02:11:22 Remote 192.0.2.5:54321 wants 'www.example.com|A', do = 0, bufsize = 4096: 1 RR(s)
    May 08 02:11:22 Remote 127.0.0.1:54321 wants 'foo.example.com|AAAA', do = 1, bufsize = 4096: packetcache HIT

PowerDNS does not stamp a year on its timestamps (it uses syslog-
style ``Month DD HH:MM:SS`` derived from the C runtime). We treat
the line as occurring in the current UTC year — if a line crosses
into a new year while the agent is mid-batch, we may stamp it with
the wrong year by ~1 day. That's the same approximation the syslog
collector ecosystem makes; for query logs (24h retention) it's
inconsequential.

Lines that the regex can't match still come back as a
``ParsedQueryLine`` with most fields ``None`` and the raw text
preserved, so the operator can still see "something happened" in
the UI.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Final

from app.services.logs.bind9_parser import ParsedQueryLine

# ── Regex bits ───────────────────────────────────────────────────────

# pdns timestamp prefix: ``May 08 02:11:22`` or ``Apr  5 02:11:22``
# (single-digit days are right-padded with one extra space). No year.
_PDNS_TS_RE: Final = re.compile(
    r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+" r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})\s+"
)

# Hard separator. pdns emits ``... wants '<qname>|<qtype>'`` on every
# query line; the literal `` wants '`` substring can't appear inside
# an IP literal, port number, or any of the free-text bits in the
# source-IP block, so splitting on it first gives us two halves that
# each parse independently and at linear cost.
#
# Implementation history (CodeQL ``py/polynomial-redos`` alerts #40
# + #41):
#
# * Alert #40 — the original one-shot ``re.search`` pattern combined
#   a greedy ``[^\]]+``, an alternation fallback, and a lazy
#   ``[0-9a-fA-F.:]+?`` — polynomial-time backtracking on inputs
#   shaped like ``Remote [\\\\…\\\\``. Fixed by switching to a
#   split-on-hard-separator structure.
#
# * Alert #41 — the *separator regex* itself
#   (``r"\s+wants\s+'"``) had two ``\s+`` quantifiers around a
#   literal token. On adversarial input with many leading+trailing
#   spaces the two ``\s+`` groups can split a whitespace run in
#   O(n²) ways before the trailing ``'`` mismatch finally fails.
#   Fix: drop the regex entirely. Real pdns log lines always have a
#   single literal space around ``wants`` (the daemon's format
#   string is ``"Remote %s wants '%s|%s'"`` — see pdns 4.9 source),
#   so ``str.split(" wants '", 1)`` is exact, fast, and trivially
#   linear in the string length. Same fix the bind9 parser landed
#   for alerts #16 + #18.
_PDNS_SEP: Final = " wants '"

# Body — anchored at the start of the right half (i.e. just after
# the `` wants '`` separator we split on). qname is bounded by RFC
# 1035 (255 chars max in presentation form); qtype is short ASCII.
# Anything past the closing quote is discarded.
_PDNS_BODY_RE: Final = re.compile(r"^(?P<qname>[^|']{1,255})\|(?P<qtype>[A-Za-z0-9\-]{1,16})'")


def _parse_pdns_addr_port(token: str) -> tuple[str | None, int | None]:
    """Split a source-IP token into ``(addr, port)``.

    pdns 4.9 emits the source as one whitespace-delimited token after
    ``Remote``. Five shapes:

        ``192.0.2.5:54321``        IPv4 with port
        ``192.0.2.5``              IPv4 no port
        ``[2001:db8::1]:54321``    bracketed IPv6 with port
        ``[2001:db8::1]``          bracketed IPv6 no port
        ``2001:db8::1``            bare IPv6 (any pdns build that
                                   omits the port)

    Disambiguation is by colon-count + leading-bracket: bracketed
    forms are unambiguous; for the unbracketed variant a single
    colon is "address:port", anything else (zero or two-plus
    colons) is the address itself. Implemented in plain Python
    rather than regex to avoid the IPv4-port-vs-IPv6-colons
    ambiguity that even bounded regex alternations can't resolve
    cleanly. Cost is linear in ``len(token)``.
    """
    if not token:
        return None, None
    if token.startswith("["):
        end = token.find("]")
        if end <= 1:
            return None, None
        addr = token[1:end] or None
        port: int | None = None
        if end + 1 < len(token) and token[end + 1] == ":":
            try:
                port = int(token[end + 2 :])
            except ValueError:
                port = None
        return addr, port
    n_colons = token.count(":")
    if n_colons == 0:
        return token, None
    if n_colons == 1:
        addr, _, port_str = token.partition(":")
        try:
            return (addr or None), int(port_str)
        except ValueError:
            return (token or None), None
    # >= 2 colons → bare IPv6 with no port (pdns brackets when port
    # is present).
    return token, None


_MONTH_MAP: Final[dict[str, int]] = {
    m: i + 1
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    )
}

_MAX_LINE_LEN: Final = 4096

# CHAOS-class server-identification probes (id.server / version.bind /
# version.server / hostname.bind / authors.bind). Monitoring tools
# poll these every few seconds against any DNS server they discover,
# so an idle homelab daemon's query log is mostly noise from them.
# We never want them in the operator-facing /logs UI; drop at parse
# time so they don't even hit the DB. The names are case-insensitive
# in DNS but PowerDNS preserves whatever the client sent — match
# lower-cased so a client probing ``ID.SERVER`` is also caught.
_CHAOS_PROBE_QNAMES: Final[frozenset[str]] = frozenset(
    {
        "id.server",
        "version.bind",
        "version.server",
        "hostname.bind",
        "authors.bind",
    }
)


def _parse_pdns_ts(
    mon_name: str,
    day_str: str,
    h_str: str,
    m_str: str,
    s_str: str,
    *,
    now: datetime,
) -> datetime | None:
    """``May 08 02:11:22`` → tz-aware UTC datetime stamped with the
    current year. The agent and pdns share the container's UTC TZ.
    """
    mon = _MONTH_MAP.get(mon_name.title())
    if mon is None:
        return None
    try:
        return datetime(now.year, mon, int(day_str), int(h_str), int(m_str), int(s_str), tzinfo=UTC)
    except ValueError:
        return None


_PDNS_RR_RE: Final = re.compile(r"^(?P<n>\d{1,5}) RR\(s\)$")


def _answer_source(tail: str) -> str | None:
    """What the line's trailing verdict says about where the answer came from (#4251).

    ``tail`` is everything after the quoted ``qname|qtype`` — e.g.
    ``, do = 0, bufsize = 4096: packetcache HIT``. Only two verdicts
    are claimed:

    * ``packetcache HIT`` -> ``cache``: pdns says so itself.
    * ``N RR(s)`` with N >= 1 -> ``authoritative``: the Authoritative
      daemon built a non-empty answer from its own backend. ``0 RR(s)``
      is NXDOMAIN / NODATA / REFUSED and says nothing about which, so it
      stays ``None`` rather than being called authoritative.

    Anything else, including a missing verdict, is ``None`` (unknown).
    """
    verdict = tail.rsplit(":", 1)[-1].strip()
    if verdict == "packetcache HIT":
        return "cache"
    m = _PDNS_RR_RE.match(verdict)
    if m and int(m.group("n")) >= 1:
        return "authoritative"
    return None


def parse_query_line(line: str, *, fallback_ts: datetime | None = None) -> ParsedQueryLine | None:
    """Parse one PowerDNS query log line into the shared
    :class:`ParsedQueryLine` shape.

    Returns ``None`` only when the line is empty / whitespace-only.
    Lines that don't match the ``Remote ... wants '...'`` shape
    (start-up banners, "ready to distribute questions", etc.) come
    back with ``qname`` / ``qtype`` ``None`` so the storage layer
    skips them at insert time. Lines longer than ``_MAX_LINE_LEN``
    are truncated to bound regex cost.
    """
    line = line.rstrip("\r\n")
    if not line.strip():
        return None
    if len(line) > _MAX_LINE_LEN:
        line = line[:_MAX_LINE_LEN]

    now = fallback_ts or datetime.now(UTC)

    ts: datetime | None = None
    rest = line
    m_ts = _PDNS_TS_RE.match(rest)
    if m_ts:
        ts = _parse_pdns_ts(
            m_ts.group("mon"),
            m_ts.group("day"),
            m_ts.group("h"),
            m_ts.group("m"),
            m_ts.group("s"),
            now=now,
        )
        rest = rest[m_ts.end() :]

    if ts is None:
        ts = now

    # Split first on the hard `` wants '`` separator. The split is
    # bounded (maxsplit=1) and the literal substring can't appear in
    # any of the structured fields, so each side parses at linear
    # cost — the head with a Python-level token walk, the body with
    # a small anchored regex. ``str.split`` (not ``re.split``) so
    # there's no regex backtracking surface; see _PDNS_SEP comment
    # above for the alert #41 history.
    parts = rest.split(_PDNS_SEP, 1)
    if len(parts) != 2:
        # Non-query log line (banner, status, error). Surface the raw
        # text without parsed fields so the storage filter can drop it.
        return ParsedQueryLine(
            ts=ts,
            client_ip=None,
            client_port=None,
            qname=None,
            qclass=None,
            qtype=None,
            flags=None,
            view=None,
            raw=line,
        )
    head, body = parts

    # Head: ``[<prefix>] Remote <addr-token>``. Tokenise on whitespace
    # and pull the token after ``Remote`` — that one token carries
    # the IP plus optional port. ``str.split`` is linear.
    head_tokens = head.split()
    addr_token: str | None = None
    for i, tok in enumerate(head_tokens):
        if tok == "Remote" and i + 1 < len(head_tokens):
            addr_token = head_tokens[i + 1]
            break
    client_ip, client_port = _parse_pdns_addr_port(addr_token) if addr_token else (None, None)

    m_b = _PDNS_BODY_RE.match(body)
    if not addr_token or m_b is None:
        return ParsedQueryLine(
            ts=ts,
            client_ip=None,
            client_port=None,
            qname=None,
            qclass=None,
            qtype=None,
            flags=None,
            view=None,
            raw=line,
        )

    qname = (m_b.group("qname") or "").strip() or None
    qtype = (m_b.group("qtype") or "").strip().upper() or None

    # Drop CHAOS-class probes — see ``_CHAOS_PROBE_QNAMES`` above.
    if qname and qname.rstrip(".").lower() in _CHAOS_PROBE_QNAMES:
        return None

    answer_source = _answer_source(body[m_b.end() :])

    return ParsedQueryLine(
        ts=ts,
        client_ip=client_ip,
        client_port=client_port,
        qname=qname,
        # PowerDNS doesn't emit qclass in its query log shape; default
        # to "IN" since 99.9% of queries are class IN and the operator
        # filter UI defaults there too.
        qclass="IN" if qname else None,
        qtype=qtype,
        flags=None,
        view=None,
        raw=line,
        answer_source=answer_source,
    )


__all__ = ["parse_query_line"]
