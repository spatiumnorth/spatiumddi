"""BIND9 query log line parser.

A typical BIND9 query log line looks like::

    25-Apr-2026 16:30:01.123 client @0x7f... 192.0.2.5#54321 (example.com): query: example.com IN A +E(0)K (10.0.0.1)

The leading timestamp is present when the channel sets
``print-time yes`` (we always render it that way — see
``backend/app/drivers/dns/templates/bind9/named.conf.j2``). The
``client @0x... <ip>#<port>`` block carries the resolver address and
the ephemeral source port; ``(<question>):`` is BIND's polite echo
of the query name. The ``query:`` body itself follows: ``<qname>
<qclass> <qtype> <flags>``. The trailing ``(<server>)`` is the
listening interface BIND received the query on (often the host's
LAN address) and is mostly noise for the UI.

This parser is deliberately liberal — every regex group is optional
because BIND configurations vary (no ``print-time``, no
``print-category``, IPv6 clients, view names, etc). When a field
can't be extracted we leave it as ``None`` and the caller stores the
raw line untouched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

# ── Regex bits ───────────────────────────────────────────────────────

# BIND9's default time format with print-time yes:
#   ``25-Apr-2026 16:30:01.123``
_BIND_TS_RE: Final = re.compile(
    r"^(?P<ts>\d{1,2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)\s+"
)

# ISO-8601 fallback (some operators reconfigure BIND to emit iso):
#   ``2026-04-25T16:30:01.123Z`` or ``2026-04-25 16:30:01.123``
_ISO_TS_RE: Final = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+\-]\d{2}:?\d{2})?)\s+"
)

# Optional ``[severity]``-style category prefix BIND prepends when
# ``print-severity`` / ``print-category`` are on. We tolerate both.
# ``responses`` is listed because response logging (issue #914) rides
# the same channel too, and an unstripped category prefix would push the
# ``client`` head out of reach of the ``^``-anchored ``_HEAD_RE``.
# ``rpz`` is listed alongside ``queries`` because RPZ policy hits ride
# the same channel (issue #699) and carry their own category name — a
# prefix left unstripped would push the client/qname head out of reach
# of ``_HEAD_RE`` and cost us the attribution the feature exists for.
# ``rpz-passthru`` is listed before ``rpz`` — alternation is ordered,
# and ``rpz`` would otherwise match the prefix of ``rpz-passthru:``
# and leave ``-passthru: `` in front of the ``client`` head, which is
# ``^``-anchored and would then fail to parse.
_CAT_SEV_RE: Final = re.compile(r"^(?:(?:queries|responses|rpz-passthru|rpz):\s+)?(?:info:\s+)?")

# BIND9 query lines are split on the hard ``: query: `` separator
# rather than matched by one big regex. The combined pattern (client
# + optional view block + optional bare view + qname/qclass/qtype +
# optional flags) had three independent ``\s+``-anchored optional
# groups that gave the regex engine room to try multiple alignments
# of whitespace runs on adversarial input — see CodeQL
# py/polynomial-redos alert #16. Splitting on ``: query: `` first
# disambiguates the structure: nothing on either side can contain
# the literal ``: query: ``, and each side gets a small, linear
# regex.
#
# Examples:
#   client @0x7f8b1c001234 192.0.2.5#54321 (example.com): query: example.com IN A +E(0)K (10.0.0.1)
#   client @0x... 2001:db8::1#34567 (foo.bar): query: foo.bar IN AAAA + (2001:db8::dead)
_QUERY_SEP_RE: Final = re.compile(r":\s+query:\s+", re.IGNORECASE)

# Head: everything between ``client`` and the ``: query: `` separator.
# Captures client IP + port up front; the parenthesised echo / view
# block and the bare ``view <name>`` form are extracted with a
# follow-up regex against the *remainder* — no two ``\s+``-anchored
# optionals competing for the same whitespace run.
_HEAD_RE: Final = re.compile(
    r"^client\s+" r"(?:@\S+\s+)?" r"(?P<client_ip>\S+?)" r"#(?P<client_port>\d+)" r"(?P<rest>.*)$",
    re.DOTALL,
)

# Pulls a view name out of the head's remainder. Either
# ``(view <name>)`` or bare ``view <name>``. Run with ``search`` so
# leading whitespace / parenthesised echo blocks are skipped over.
#
# CodeQL alert #18 (polynomial ReDoS): the previous shape was
# ``\(\s*view\s+(?P<view_paren>[^)]+?)\s*\)`` — and even the
# intermediate ``\(view\s+(?P<view_paren>[^)]*)\)`` is quadratic
# because ``\s+`` and ``[^)]*`` both consume whitespace and the
# engine enumerates every split between them when the trailing
# ``\)`` fails to match. Real BIND9 view names are single tokens
# (DNS-name-like — no embedded whitespace), so the safe shape is
# to constrain the inner capture to non-whitespace-non-paren
# (``[^)\s]+``). ``\s+`` matches whitespace exclusively, the
# capture matches non-whitespace exclusively, and the optional
# trailing ``\s*`` before ``\)`` doesn't overlap with the capture
# either — every segment has a disjoint character class, so the
# total time is linear in the input length.
_VIEW_RE: Final = re.compile(
    r"\(view\s+(?P<view_paren>[^)\s]+)\s*\)" r"|" r"\bview\s+(?P<view_bare>\S+)",
)

# Body: ``<qname> <qclass> <qtype> [<flags>]`` — what follows
# ``: query: ``. Anchored at the start so we don't search; bounded
# by ``\S+`` runs separated by single ``\s+`` matches that can't
# overlap thanks to the anchor.
_BODY_RE: Final = re.compile(
    r"^(?P<qname>\S+)\s+(?P<qclass>\S+)\s+(?P<qtype>\S+)" r"(?:\s+(?P<flags>\S+))?",
)

_MONTH_MAP: Final[dict[str, int]] = {
    m: i + 1
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    )
}


#: Closed set stored in ``dns_query_log_entry.answer_source`` (#4251).
#: ``forwarded`` / ``recursion`` carry the upstream in ``answer_upstream``
#: when the reporting flavor names it. NULL (never a member) means the
#: server did not say; there is deliberately no "unknown" value.
ANSWER_SOURCES: Final = ("authoritative", "cache", "forwarded", "recursion")


@dataclass(frozen=True)
class ParsedQueryLine:
    ts: datetime
    client_ip: str | None
    client_port: int | None
    qname: str | None
    qclass: str | None
    qtype: str | None
    flags: str | None
    view: str | None
    raw: str
    # How the server says it produced the answer (#4251) — one of
    # :data:`ANSWER_SOURCES`, or ``None`` when the daemon's log does not
    # say. BIND's ``queries`` / ``responses`` categories never do, so the
    # BIND9 parser always leaves these ``None`` rather than guessing.
    answer_source: str | None = None
    answer_upstream: str | None = None


def _parse_bind_ts(value: str) -> datetime | None:
    """``25-Apr-2026 16:30:01.123`` → tz-aware UTC datetime.

    BIND9 doesn't stamp a timezone; we treat it as UTC since the
    agent and named are running in the same container and we always
    set the container TZ to UTC.
    """
    try:
        date_part, time_part = value.split(maxsplit=1)
        d, mon_name, y = date_part.split("-")
        mon = _MONTH_MAP.get(mon_name)
        if mon is None:
            return None
        if "." in time_part:
            time_main, frac = time_part.split(".", 1)
            micro = int(frac.ljust(6, "0")[:6])
        else:
            time_main, micro = time_part, 0
        h, m, s = (int(x) for x in time_main.split(":"))
        return datetime(int(y), mon, int(d), h, m, s, micro, tzinfo=UTC)
    except (ValueError, KeyError):
        return None


def _parse_iso_ts(value: str) -> datetime | None:
    try:
        v = value.replace("Z", "+00:00")
        if " " in v and "T" not in v:
            v = v.replace(" ", "T", 1)
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except ValueError:
        return None


_MAX_LINE_LEN: Final = 4096

# CHAOS-class server-identification probes (id.server / version.bind /
# version.server / hostname.bind / authors.bind). Monitoring tools
# poll these every few seconds against any DNS server they discover —
# pure noise in the operator-facing /logs UI. Drop at parse time so
# they don't even hit the DB. Match lower-cased and trailing-dot-
# stripped so case / FQDN variants ($qname or $qname.) are caught.
_CHAOS_PROBE_QNAMES: Final[frozenset[str]] = frozenset(
    {
        "id.server",
        "version.bind",
        "version.server",
        "hostname.bind",
        "authors.bind",
    }
)


def parse_query_line(line: str, *, fallback_ts: datetime | None = None) -> ParsedQueryLine | None:
    """Parse one BIND9 query log line.

    Returns ``None`` only when the line is empty / whitespace-only.
    Lines that the regex can't match still come back as
    ``ParsedQueryLine`` with most fields ``None`` and the raw text
    preserved, so the UI can still surface them.

    ``fallback_ts`` is used when the line has no leading timestamp
    (e.g. ``print-time no`` in named.conf). The shipper passes the
    receive-time so we don't drop the line.

    Lines are truncated to ``_MAX_LINE_LEN`` before regex matching to
    bound the cost of the polynomial-backtracking patterns
    (``\\s+`` repetitions + optional view groups). A real BIND9
    query line is bounded by the qname (≤ 255 chars per RFC 1035)
    plus the timestamp / client / view metadata, so 4 KiB is well
    above any legitimate line. Truncation preserves the raw text
    on the resulting ParsedQueryLine for forensic inspection.
    """
    line = line.rstrip("\r\n")
    if not line.strip():
        return None
    if len(line) > _MAX_LINE_LEN:
        line = line[:_MAX_LINE_LEN]

    ts: datetime | None = None
    rest = line

    m = _BIND_TS_RE.match(rest)
    if m:
        ts = _parse_bind_ts(m.group("ts"))
        rest = rest[m.end() :]
    else:
        m_iso = _ISO_TS_RE.match(rest)
        if m_iso:
            ts = _parse_iso_ts(m_iso.group("ts"))
            rest = rest[m_iso.end() :]

    if ts is None:
        ts = fallback_ts or datetime.now(UTC)

    rest = _CAT_SEV_RE.sub("", rest, count=1)

    # Split on the hard ``: query: `` separator so each side gets a
    # small, linear regex. The split itself is bounded — at most one
    # cut, and ``: query: `` can't appear inside a qname or view name.
    parts = _QUERY_SEP_RE.split(rest, maxsplit=1)
    if len(parts) != 2:
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

    head_m = _HEAD_RE.search(head)
    body_m = _BODY_RE.match(body)
    if head_m is None or body_m is None:
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

    # Strip the trailing ``)`` parenthesised echo (e.g. ``(example.com)``)
    # before scanning for a view marker so the search bound is short.
    remainder = head_m.group("rest") or ""
    view: str | None = None
    vm = _VIEW_RE.search(remainder)
    if vm:
        view = (vm.group("view_paren") or vm.group("view_bare") or "").strip() or None

    try:
        client_port = int(head_m.group("client_port"))
    except (TypeError, ValueError):
        client_port = None

    qname = body_m.group("qname") or None
    # Drop CHAOS-class probes — see ``_CHAOS_PROBE_QNAMES`` above.
    if qname and qname.rstrip(".").lower() in _CHAOS_PROBE_QNAMES:
        return None

    return ParsedQueryLine(
        ts=ts,
        client_ip=head_m.group("client_ip") or None,
        client_port=client_port,
        qname=qname,
        qclass=body_m.group("qclass") or None,
        qtype=body_m.group("qtype") or None,
        flags=body_m.group("flags") or None,
        view=view,
        raw=line,
    )


__all__ = [
    "ParsedQueryLine",
    "ParsedRPZLine",
    "ParsedResponseLine",
    "parse_query_line",
    "parse_response_line",
    "parse_rpz_line",
]


# ── RPZ policy hits (issue #699) ──────────────────────────────────────
#
# named logs response-policy rewrites to its own ``rpz`` logging
# category, never to ``queries``. That is why "which machine keeps
# slamming blocked domains" — the question that actually identifies an
# infected host — was unanswerable from data we already had: we serve
# the blocklists and then discarded every hit.
#
# The line shape, with print-category on:
#
#   27-Jul-2026 22:15:03.123 rpz: info: client @0x7f8 192.0.2.5#54321 \
#       (ads.tracker.example): view default: rpz QNAME NXDOMAIN \
#       rewrite ads.tracker.example via ads.tracker.example.rpz-ads
#
# These arrive interleaved with query lines on the same channel, so the
# ingest tries this parser first and falls through to the query parser.
# The discriminator is the ``rpz <TRIGGER> <POLICY>`` clause, which
# cannot appear in a query line — a qname could contain the substring
# "rpz", but not followed by a known trigger keyword.

# Trigger types and policy actions are closed sets in named's source
# (``rpz_type_str`` / ``dns_rpz_policy_to_text``), so they are matched
# as alternations rather than ``\S+``. That keeps a malformed line from
# being mistaken for an RPZ hit, and every segment's character class is
# disjoint from its neighbours' so matching stays linear.
_RPZ_TRIGGERS: Final = "QNAME|CLIENT-IP|IP|NSDNAME|NSIP"
# ``TCP_ONLY`` carries an UNDERSCORE: the hyphenated ``tcp-only`` is
# the named.conf keyword, but dns_rpz_policy2str() emits the
# underscore form to the log. Both are accepted so a config-shaped
# line from a future named release still parses.
_RPZ_POLICIES: Final = "NXDOMAIN|NODATA|PASSTHRU|DROP|TCP_ONLY|TCP-ONLY|CNAME|Local-Data"

_RPZ_RE: Final = re.compile(
    r"\brpz\s+(?P<trigger>" + _RPZ_TRIGGERS + r")"
    r"\s+(?P<policy>" + _RPZ_POLICIES + r")"
    # ``rewrite <qname>/<qtype>/<qclass>`` — note the operand carries the
    # type and class, so it is NOT a bare name (verified against BIND
    # 9.20: ``rewrite bad.example/A/IN``). Both halves stay optional to
    # tolerate format drift across releases rather than because any
    # current policy omits them — BIND 9.20 emits ``rewrite``/``via`` for
    # every policy including DROP, contrary to a common reading of the
    # docs.
    r"(?:\s+rewrite\s+(?P<rewritten>[^\s]+))?"
    r"(?:\s+via\s+(?P<via>[^\s]+))?",
)


@dataclass(frozen=True)
class ParsedRPZLine:
    ts: datetime
    client_ip: str | None
    qname: str | None
    trigger: str
    policy: str
    # The RPZ zone that matched, recovered from the ``via`` clause. This
    # is what attributes a hit to a specific blocklist feed, which is
    # the difference between "blocked" and "blocked by the malware feed
    # rather than the ad feed".
    rpz_zone: str | None
    raw: str


def parse_rpz_line(line: str, *, fallback_ts: datetime | None = None) -> ParsedRPZLine | None:
    """Parse one BIND9 ``rpz`` category line, or ``None`` if it isn't one.

    Returning ``None`` for non-RPZ input is the contract the ingest
    relies on to tell the two line shapes apart on a shared channel —
    it tries this first and falls through to :func:`parse_query_line`.

    The client IP and queried name are recovered from the same
    ``client <ip>#<port> (<qname>)`` head that query lines carry, so
    the existing head regex does that work. When the head is missing or
    unparseable the hit is still returned with ``client_ip=None``: a
    blocked lookup we cannot attribute is worth counting (it proves the
    blocklist is doing something) even though it cannot be pinned to a
    host.
    """
    line = line.rstrip("\r\n")
    if not line.strip():
        return None
    if len(line) > _MAX_LINE_LEN:
        line = line[:_MAX_LINE_LEN]

    # Cheap reject before the regex. Every ingested query-log line pays
    # this probe, and ``_RPZ_RE`` requires a literal ``rpz`` token, so the
    # substring test is behaviour-preserving and ~50x cheaper on the miss
    # path (which is almost every line).
    if "rpz" not in line:
        return None

    rpz_m = _RPZ_RE.search(line)
    if rpz_m is None:
        return None
    # named prefixes the message with ``disabled `` when the policy zone
    # is running with ``policy disabled`` — the standard way to trial a
    # new feed in log-only mode. Nothing was actually blocked, so
    # counting it would fabricate hits for an operator who is explicitly
    # evaluating rather than enforcing.
    if line[: rpz_m.start()].rstrip().endswith("disabled"):
        return None

    ts: datetime | None = None
    rest = line
    m = _BIND_TS_RE.match(rest)
    if m:
        ts = _parse_bind_ts(m.group("ts"))
        rest = rest[m.end() :]
    else:
        m_iso = _ISO_TS_RE.match(rest)
        if m_iso:
            ts = _parse_iso_ts(m_iso.group("ts"))
            rest = rest[m_iso.end() :]
    if ts is None:
        ts = fallback_ts or datetime.now(UTC)

    head_m = _HEAD_RE.search(_CAT_SEV_RE.sub("", rest, count=1))
    client_ip = head_m.group("client_ip") if head_m else None
    # ``_HEAD_RE`` deliberately stops at the port and hands the tail back
    # as ``rest`` — the query path takes its qname from the body after
    # ``: query: ``, which an RPZ line does not have. So the name is
    # recovered from the parenthesised ``(<qname>)`` BIND puts in the
    # head, falling back to the ``rewrite`` clause. Both carry the same
    # name; the fallback matters because a DROP policy logs no
    # ``rewrite``, and the paren form matters because a head that failed
    # to parse leaves only the clause.
    qname = _rpz_qname_from_head(head_m.group("rest") if head_m else None) or _bare_qname(
        rpz_m.group("rewritten")
    )

    return ParsedRPZLine(
        ts=ts,
        client_ip=client_ip,
        qname=qname.rstrip(".").lower() if qname else None,
        trigger=rpz_m.group("trigger"),
        policy=rpz_m.group("policy"),
        rpz_zone=_rpz_zone_from_via(rpz_m.group("via")),
        raw=line,
    )


def _rpz_zone_from_via(via: str | None) -> str | None:
    """Recover the RPZ zone name from named's ``via`` clause.

    named logs ``via <trigger-entry>.<rpz-zone>`` — the matched entry
    prefixed onto the zone it came from, so the two have to be split
    apart before a hit can be attributed to a feed.

    SpatiumDDI renders its RPZ zones as ``spatium-blocklist.rpz.`` and
    ``spatium-blocklist-<view>.rpz.`` (see ``dns/agent_config.py``), so
    the zone is the final ``rpz`` label plus the one before it. Taking
    everything from the first ``.rpz`` rightwards would be wrong for a
    zone whose own name contains ``rpz``, and taking everything from the
    LAST ``.rpz`` yields the bare ``rpz`` label — both were tried.

    Falls back to the whole string when no ``rpz`` label is present,
    which keeps a hand-rolled RPZ zone attributable rather than dropping
    the hit on the floor.
    """
    if not via:
        return None
    cleaned = via.rstrip(".").lower()
    labels = cleaned.split(".")
    # SpatiumDDI's own zones are the case that must be exact, so match
    # the rendered prefix directly rather than inferring from label
    # position. Guessing by position mis-sliced any zone with a
    # non-terminal ``rpz`` label — ``bad.example.rpz.local`` yielded
    # ``example.rpz.local``, gluing the blocked name onto the zone and
    # turning every distinct name into its own phantom "feed".
    for i, label in enumerate(labels):
        if label.startswith(_RENDERED_RPZ_PREFIX):
            return ".".join(labels[i:])[:_RPZ_ZONE_MAX_LEN]
    # Hand-rolled / imported zone. Take the last two labels as a
    # best-effort feed identity; returning the whole ``via`` (as an
    # earlier cut did) made the value vary per blocked name AND could
    # exceed the String(255) column, which aborts the entire ingest
    # batch on commit — losing every query-log row in the same POST.
    return ".".join(labels[-2:])[:_RPZ_ZONE_MAX_LEN] if len(labels) >= 2 else cleaned


# The ``(<qname>)`` BIND puts between the client address and the colon.
#
# CodeQL py/polynomial-redos, same family as alerts #16 and #18 on this
# file: the first cut used ``[^)\s]+``, which still admits ``(``. Run
# under ``search``, input like ``((((((`` makes the engine consume every
# ``(`` at each candidate start position, fail the closing ``\)``, and
# backtrack one character at a time — O(n) work at O(n) offsets. Adding
# ``(`` to the excluded set makes the inner run unable to cross a paren
# in either direction, so a failing start position fails immediately and
# the total stays linear. It is also strictly more correct: a DNS name
# can contain neither parenthesis, so nothing legitimate is excluded.
_RPZ_HEAD_QNAME_RE: Final = re.compile(r"\((?P<qname>[^()\s]+)\)")

# ``dns_rpz_hit.rpz_zone`` is String(255). The ``via`` token is
# unbounded, and one overlong value fails the single commit that covers
# the whole ingest batch, so clamp here rather than at the call site.
_RPZ_ZONE_MAX_LEN: Final = 255

# What ``dns/agent_config.py`` renders: ``spatium-blocklist.rpz.`` and
# ``spatium-blocklist-<view>.rpz.``.
_RENDERED_RPZ_PREFIX: Final = "spatium-blocklist"


def _rpz_qname_from_head(rest: str | None) -> str | None:
    r"""Pull the queried name out of an RPZ line's head.

    ``rest`` is everything ``_HEAD_RE`` left after the client port; the
    first parenthesised token there is the qname. The ``(view <name>)``
    form cannot be confused with it — that contains a space, which
    ``_RPZ_HEAD_QNAME_RE``'s ``[^)\s]+`` excludes by construction.
    """
    if not rest:
        return None
    m = _RPZ_HEAD_QNAME_RE.search(rest)
    return m.group("qname") if m else None


def _bare_qname(operand: str | None) -> str | None:
    """Strip the ``/<qtype>/<qclass>`` suffix off a ``rewrite`` operand.

    BIND logs ``rewrite bad.example/A/IN``, not a bare name. Storing the
    raw operand put ``bad.example/a/in`` in ``dns_rpz_hit.qname``, which
    matches no real domain — it would group as its own row in
    ``top_blocked_names`` and render that way in the UI and in copilot
    answers.
    """
    if not operand:
        return None
    return operand.split("/", 1)[0] or None


# ── Response lines (issue #914) ───────────────────────────────────────
#
# BIND's ``queries`` category is request-side by design — it logs the
# question as it arrives and never mentions the answer. BIND 9.20's
# ``responselog yes;`` adds a second category, ``responses``, carrying
# the RCODE and the section counts:
#
#   23-Aug-2026 13:20:09.490 responses: info: client @0x7f83 127.0.0.1#57018 \
#       (www.example.com): view internal: response: www.example.com IN A \
#       NOERROR 1 1 2 +E(0)K (127.0.0.1)
#
# Verified against BIND 9.20.26 across NOERROR / NXDOMAIN / REFUSED, a
# NODATA (``NOERROR 0``), DNSSEC (``+E(0)DK``) and TCP (``+E(0)TK``) —
# the three counts are always present and always in the order
# answer / authority / additional.
#
# The line is routed to the same channel as ``queries`` (see the BIND9
# renderer), so it arrives interleaved with query lines in the same
# shipper batch and the ingest tells the shapes apart by separator:
# ``: response: `` here, ``: query: `` there. Neither substring can
# appear inside a DNS name, a view name or an address literal, so the
# split is exact — the same argument :data:`_QUERY_SEP_RE` rests on.
_RESPONSE_SEP_RE: Final = re.compile(r":\s+response:\s+", re.IGNORECASE)

# ``<qname> <qclass> <qtype> <RCODE> <an> <au> <ad> [<flags>]``. Every
# segment is a ``\S+`` run separated by a single ``\s+`` match and the
# whole thing is anchored, so no two quantifiers compete for the same
# whitespace — the property the rest of this module's regexes were
# rewritten for (CodeQL py/polynomial-redos, alerts #16 / #18 / #40).
_RESPONSE_BODY_RE: Final = re.compile(
    r"^(?P<qname>\S+)\s+(?P<qclass>\S+)\s+(?P<qtype>\S+)\s+(?P<rcode>\S+)"
    r"\s+(?P<answers>\d+)\s+(?P<authority>\d+)\s+(?P<additional>\d+)"
    r"(?:\s+(?P<flags>\S+))?",
)

#: ``dns_query_log_entry.rcode`` is ``String(16)``. named prints an
#: unassigned rcode numerically rather than symbolically, so the token is
#: not drawn from a closed set; clamp here rather than at the call site,
#: because one overlong value fails the single commit covering the whole
#: ingest batch and would lose every other row in the same POST — the
#: failure mode ``_RPZ_ZONE_MAX_LEN`` exists for.
_RCODE_MAX_LEN: Final = 16


@dataclass(frozen=True)
class ParsedResponseLine:
    """The answer half of one query, to be stamped onto its query row.

    Carries the full correlation key rather than just the outcome: named
    logs the response as an independent line, so matching it back to the
    question is the caller's job and everything needed to do it has to
    survive parsing.
    """

    ts: datetime
    client_ip: str | None
    client_port: int | None
    qname: str | None
    qclass: str | None
    qtype: str | None
    rcode: str
    answer_count: int
    authority_count: int
    additional_count: int
    flags: str | None
    view: str | None
    raw: str


def parse_response_line(
    line: str, *, fallback_ts: datetime | None = None
) -> ParsedResponseLine | None:
    """Parse one BIND9 ``responses`` category line, or ``None`` if it isn't one.

    Returning ``None`` for non-response input is the contract the ingest
    relies on to tell the three line shapes apart on a shared channel: it
    tries RPZ, then this, then falls through to :func:`parse_query_line`.

    Unlike the query parser, a line whose *head* fails to parse is
    rejected outright rather than returned with ``None`` fields. A
    response is only useful once it can be attributed to the question it
    answers, and a response with no client address can be attributed to
    nothing — keeping it would mean either dropping it later anyway or,
    worse, stamping an outcome onto the wrong query.
    """
    line = line.rstrip("\r\n")
    if not line.strip():
        return None
    if len(line) > _MAX_LINE_LEN:
        line = line[:_MAX_LINE_LEN]

    # Cheap reject before any regex work. Every ingested line pays this
    # probe and almost all of them are query lines, which cannot contain
    # the literal ``response:``.
    if "response:" not in line:
        return None

    ts: datetime | None = None
    rest = line
    m = _BIND_TS_RE.match(rest)
    if m:
        ts = _parse_bind_ts(m.group("ts"))
        rest = rest[m.end() :]
    else:
        m_iso = _ISO_TS_RE.match(rest)
        if m_iso:
            ts = _parse_iso_ts(m_iso.group("ts"))
            rest = rest[m_iso.end() :]
    if ts is None:
        ts = fallback_ts or datetime.now(UTC)

    rest = _CAT_SEV_RE.sub("", rest, count=1)

    parts = _RESPONSE_SEP_RE.split(rest, maxsplit=1)
    if len(parts) != 2:
        return None
    head, body = parts

    head_m = _HEAD_RE.search(head)
    body_m = _RESPONSE_BODY_RE.match(body)
    if head_m is None or body_m is None:
        return None

    qname = body_m.group("qname") or None
    # Same CHAOS-probe suppression the query side applies. Without it the
    # query row is dropped at parse time and its response line survives,
    # so the correlator would scan for a row that was never inserted on
    # every monitoring poll.
    if qname and qname.rstrip(".").lower() in _CHAOS_PROBE_QNAMES:
        return None

    view: str | None = None
    vm = _VIEW_RE.search(head_m.group("rest") or "")
    if vm:
        view = (vm.group("view_paren") or vm.group("view_bare") or "").strip() or None

    try:
        client_port: int | None = int(head_m.group("client_port"))
    except (TypeError, ValueError):
        client_port = None

    return ParsedResponseLine(
        ts=ts,
        client_ip=head_m.group("client_ip") or None,
        client_port=client_port,
        qname=qname,
        qclass=body_m.group("qclass") or None,
        qtype=body_m.group("qtype") or None,
        rcode=body_m.group("rcode").upper()[:_RCODE_MAX_LEN],
        answer_count=int(body_m.group("answers")),
        authority_count=int(body_m.group("authority")),
        additional_count=int(body_m.group("additional")),
        flags=body_m.group("flags") or None,
        view=view,
        raw=line,
    )
