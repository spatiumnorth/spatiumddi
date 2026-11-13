"""Feed parsing for DNS blocking lists (hosts / domains / adblock).

Pure functions with no imports beyond the standard library, split out of
:mod:`app.services.dns_blocklist` (#3522) so that the monthly catalog check
(``scripts/check_blocklist_catalog.py``) can load the exact parser a refresh
runs without the app, SQLAlchemy or the ORM. Keep it that way: the script
loads this file on its own, and an import of anything outside the standard
library makes that check fail (loudly, exit 2) rather than run.

:mod:`app.services.dns_blocklist` re-exports every public name here, so
callers keep importing from there.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class FeedSkipCounts:
    """Rules an adblock-format feed carried that did not become entries (#2123).

    Each is a rule the feed's author wrote and this list does not enforce,
    so the operator is told how many rather than left to assume the list
    is the whole feed:

    * ``regex`` — ``/…/`` and ``@@/…/`` rules. RPZ matches names, not
      patterns.
    * ``modifier`` — a rule carrying a modifier DNS cannot express
      (``$domain=``, ``$third-party``, ``$client=``, ``$dnstype=``, …).
      Most of them NARROW a rule, so dropping the modifier and keeping the
      name would block more than the feed asked for; the rule is skipped
      instead. ``$important`` is the one exception: it only changes
      precedence, so the rule is kept as a plain block.
    * ``badfilter`` — ``$badfilter`` rules. Each disables the rule it
      names, which is dropped with it; neither becomes an entry.
    * ``malformed`` — anything else this parser cannot turn into a name. It
      is the SUM of the reason buckets below (#3519), so a reader that only
      knows the four original keys still adds up; it is derived, never set:

      * ``star_in_name`` — ``||reachableads-av.*.amazonaws.com^``; RPZ
        has no mid-name wildcard.
      * ``no_anchor`` — ``-tracker.example.net^``, ``.n.2.1.js^``; no ``||``
        (and no ``*``), so adblock reads it as a substring match, which a
        name cannot say. (A dot-led rule that IS a plain name,
        ``.bbelements.com^``, is NOT skipped: it blocks that name's
        subdomains, see :class:`ParsedFeed`.)
      * ``trailing_dot`` — ``||adserver1.``; a prefix match on a label.
      * ``start_anchor`` — ``|piwik.``, ``|load.gtm.``; a single ``|``
        anchors the start of the URL, not a domain. (``|a.example.com^``,
        a full name between the anchor and the ``^``, is NOT skipped: it is
        an exact-name block, see :class:`ParsedFeed`.)
      * ``bare_star`` — ``*ad.example.net^``, ``-adx-*.example.com^``; a
        ``*`` anywhere in a rule with no ``||``.
      * ``dotless`` — ``||countly-``; a single label, not a hostname.
      * ``other`` — anything that fits none of the above (a path such as
        ``||host/ads``, a character a hostname cannot carry).

    * ``invalid_name`` — hosts / domains feeds only (#3531): a token that is
      not a DNS name (an adblock rule such as ``||ads.example.com^``, a path,
      a backslash). Counted separately from ``malformed``, which is
      adblock's. An IP literal, like a dotless name, is skipped uncounted.
    """

    regex: int = 0
    modifier: int = 0
    badfilter: int = 0
    star_in_name: int = 0
    no_anchor: int = 0
    trailing_dot: int = 0
    start_anchor: int = 0
    bare_star: int = 0
    dotless: int = 0
    other: int = 0
    # hosts / domains feeds only (#3531): a token that is not a DNS name.
    invalid_name: int = 0

    @property
    def malformed(self) -> int:
        return (
            self.star_in_name
            + self.no_anchor
            + self.trailing_dot
            + self.start_anchor
            + self.bare_star
            + self.dotless
            + self.other
        )

    @property
    def total(self) -> int:
        """Every rule skipped, each counted once."""
        return self.regex + self.modifier + self.badfilter + self.malformed + self.invalid_name

    def as_dict(self) -> dict[str, int]:
        out = {
            "regex": self.regex,
            "modifier": self.modifier,
            "badfilter": self.badfilter,
            "malformed": self.malformed,
            "star_in_name": self.star_in_name,
            "no_anchor": self.no_anchor,
            "trailing_dot": self.trailing_dot,
            "start_anchor": self.start_anchor,
            "bare_star": self.bare_star,
            "dotless": self.dotless,
            "other": self.other,
        }
        # Only hosts / domains feeds can set it; an adblock row keeps its shape.
        if self.invalid_name:
            out["invalid_name"] = self.invalid_name
        return out


@dataclass(frozen=True)
class ParsedFeed:
    """A parsed feed plus what its syntax said about subdomains.

    ``wildcard_count`` is how many lines declared "this name and every
    subdomain": ``*.``-prefixed lines, and in an adblock feed every
    ``||name^`` rule, since that is what ``||`` means. The caller needs it
    because a list configured apex-only (``feed_entries_are_wildcard=False``,
    #894) against such a feed is overriding a stated intent, which is worth
    saying out loud rather than doing silently.

    ``exceptions`` are the feed's own allow rules (adblock ``@@||name^``,
    #2123), stored as the list's exceptions. ``skipped`` counts the rules
    a feed carried that became neither: adblock rules DNS cannot express, or
    (hosts / domains, #3531) tokens that are not DNS names; None for a
    hosts / domains feed with none.
    """

    domains: list[str]
    wildcard_count: int
    exceptions: list[str] = field(default_factory=list)
    skipped: FeedSkipCounts | None = None
    #: Adblock entries whose reach is NOT the list's subdomain setting (#4037),
    #: stored verbatim and always with ``is_wildcard=False``: ``name`` for an
    #: exact-name rule (``|name^``, the name and nothing under it) and
    #: ``*.name`` for a dot-led rule (``.name^``, the subdomains and NOT the
    #: apex; the RPZ renderers emit ``*.name`` as written). Disjoint from
    #: ``domains`` and from the exceptions.
    literal_domains: list[str] = field(default_factory=list)
    #: Set when the content looks like a different format than the one asked
    #: for (#3531), e.g. ``"adblock"`` for an adblock file read as hosts. The
    #: caller should refuse the refresh rather than store the result.
    format_mismatch: str | None = None


def looks_like_html(content: str) -> bool:
    """True when a body starts like an HTML document (#3607).

    A captive portal, login page, or a 404 page served with status 200
    parses as a feed with zero (or a few junk) rules; the caller refuses it
    rather than emptying the list.
    """
    head = content.lstrip("\ufeff \t\r\n")[:64].lower()
    return head.startswith(("<!doctype html", "<html"))


def parse_feed(content: str, feed_format: str) -> list[str]:
    """Parse raw feed text into a deduped list of domains.

    Thin wrapper over :func:`parse_feed_detailed` for the many callers
    (and tests) that only want the names.
    """
    return parse_feed_detailed(content, feed_format).domains


#: A hostname as an adblock ``||`` rule may name it: labels of letters,
#: digits, ``-`` and ``_``, at least two of them, optionally ``*.``-led.
_ADBLOCK_HOST_RE = re.compile(r"^(?:\*\.)?[a-z0-9_-]+(?:\.[a-z0-9_-]+)+\.?$")

#: One DNS label as a hosts / domains feed may carry it: letters, digits,
#: ``-`` and ``_``, 1-63 characters, no leading or trailing hyphen. This is
#: the RFC 2181 owner rule ``app.core.dns_names.validate_fqdn`` applies; it is
#: restated here because this module must stay stdlib-only. One deliberate
#: difference: ``validate_fqdn`` IDNA-encodes a non-ASCII name, while a feed
#: line carrying one is counted as ``invalid_name`` (feeds publish punycode,
#: ``xn--…``, which the rule accepts).
_FEED_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
#: A whole name: at least two labels (a dotless token is skipped silently
#: before this is reached). Total length is checked separately.
_FEED_NAME_RE = re.compile(rf"^(?:{_FEED_LABEL}\.)+{_FEED_LABEL}$")

#: An adblock rule line: ``||name^`` or ``@@||name^`` (with optional modifiers).
_ADBLOCK_LINE_RE = re.compile(r"^(?:@@)?\|\|[^\s]*\^")


def _is_ip_literal(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return False
    return True


def _is_feed_name(name: str) -> bool:
    """True when ``name`` is a DNS name by the ``validate_fqdn`` rule."""
    return len(name) <= 253 and _FEED_NAME_RE.match(name) is not None


def _rule_lines(content: str) -> list[str]:
    """The lines that carry a rule: not blank, not a comment or header."""
    out = []
    for raw in content.splitlines():
        line = raw.strip()
        if line and not line.startswith(("#", "!", "[")):
            out.append(line)
    return out


def _looks_like_hosts(content: str) -> bool:
    """True when most rule lines are hosts lines (``<address> <name>``)."""
    lines = _rule_lines(content)
    hosts = 0
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and _is_ip_literal(parts[0]):
            hosts += 1
    return hosts > 0 and hosts * 2 > len(lines)


def _looks_like_adblock(content: str) -> bool:
    """True when most rule lines are adblock ``||name^`` / ``@@||name^`` rules."""
    lines = _rule_lines(content)
    adblock = sum(1 for line in lines if _ADBLOCK_LINE_RE.match(line))
    return adblock > 0 and adblock * 2 > len(lines)


def _looks_like_domains(content: str) -> bool:
    """True when most rule lines are one bare domain each (``*.`` allowed)."""
    lines = _rule_lines(content)
    names = 0
    for line in lines:
        parts = line.split("#", 1)[0].split()
        if len(parts) != 1:
            continue
        name = parts[0].lower().strip(".")
        if name.startswith("*."):
            name = name[2:]
        if "." in name and not _is_ip_literal(name) and _is_feed_name(name):
            names += 1
    return names > 0 and names * 2 > len(lines)


#: Modifiers that leave a rule's DNS meaning intact. ``important`` only
#: raises a rule's precedence over exceptions in the same engine.
_ADBLOCK_HARMLESS_MODIFIERS = frozenset({"important"})

#: Element-hiding / scriptlet separators. Those rules are for browsers, never
#: for DNS, so they are ignored rather than counted as lost.
_ADBLOCK_COSMETIC_MARKERS = ("##", "#@#", "#?#", "#$#", "#%#", "#@$#", "#@%#", "#@?#")


#: (is_exception, pattern, modifiers without badfilter) identifies a rule for
#: ``$badfilter``, which cancels the rule that is otherwise identical.
_RuleKey = tuple[bool, str, frozenset[str]]


#: Last labels that are file extensions, not top-level domains. AdGuard lists
#: carry dot-led filename fragments (``.n.2.1.js^``) that look like a name.
_NOT_A_TLD = frozenset(
    "js css png jpg jpeg gif svg ico webp html htm php asp aspx swf json xml txt "
    "woff woff2 ttf mp4 webm map".split()
)


def _plain_name_rule(pattern: str) -> tuple[str, str] | None:
    """``(kind, name)`` for a non-``||`` rule that is a complete DNS name (#4037).

    ``kind`` is ``"subdomains"`` for a dot-led ``.name^`` and ``"exact"`` for
    ``|name^``. Both must end in ``^`` (an optional end ``|`` after it is
    allowed): without the separator adblock reads the text as a substring
    (``.stape.net`` also matches ``stape.net.evil.example``), which a name
    cannot say.

    The name must satisfy :func:`_is_feed_name` plus a sanity rule, because
    a dot-led pattern is just as often a filename fragment as a domain
    (``.n.2.1.js^``, ``.1.1.1.l80.js^``): no label may be all digits, and
    the last label must be letters (or ``xn--`` punycode) and not a file
    extension. A legitimate name with a numeric label (``1.example.com``) is
    skipped by that rule, the safe direction.
    """
    body = pattern[:-1] if pattern.endswith("^|") else pattern
    if not body.endswith("^"):
        return None
    body = body[:-1]
    if body.startswith("."):
        kind, name = "subdomains", body[1:]
    elif body.startswith("|") and not body.startswith("||"):
        kind, name = "exact", body[1:]
    else:
        return None
    if not _is_feed_name(name):
        return None
    labels = name.split(".")
    if len(labels) < 2 or any(label.isdigit() for label in labels):
        return None
    tld = labels[-1]
    if tld in _NOT_A_TLD or not (tld.isalpha() or tld.startswith("xn--")):
        return None
    return kind, name


def _malformed_reason(pattern: str, host: str | None) -> str:
    """Why a rule that is not a plain ``||name^`` was skipped (#3519).

    ``pattern`` is the lowercased rule body without ``@@`` / modifiers;
    ``host`` is the part after ``||`` with its ``|`` / ``^`` terminators
    removed, or None when the rule has no ``||`` anchor.
    """
    if host is None:
        if pattern.startswith("|"):
            return "start_anchor"
        # Any ``*`` without ``||``, not only a leading one: ``-adx-*.x.com^``
        # is a wildcard rule first and a substring rule second, and the
        # AdGuard DNS Filter counts in #3519 file it here.
        if "*" in pattern:
            return "bare_star"
        return "no_anchor"
    if "/" in host:
        return "other"
    if "*" in host:
        return "star_in_name"
    if host.endswith("."):
        return "trailing_dot"
    if "." not in host:
        return "dotless"
    return "other"


def _parse_adblock(content: str) -> ParsedFeed:
    """The ``adblock`` branch of :func:`parse_feed_detailed` (#2123).

    The old parser read only ``||`` lines and cut each at the first ``^``,
    ``$`` or ``/``. So ``@@`` exceptions vanished (over-blocking whatever
    another rule covered), ``||x^$badfilter`` — "disable the rule for x" —
    became a block of x, and a ``$domain=`` rule, which narrows a block to
    requests from one site, became an unconditional block. Each is now
    handled for what it says, and every rule that cannot be honoured is
    counted rather than silently dropped.
    """
    blocks: list[tuple[_RuleKey, str]] = []
    literal_blocks: list[tuple[_RuleKey, str]] = []
    allows: list[tuple[_RuleKey, str]] = []
    cancelled: set[_RuleKey] = set()
    regex = modifier = badfilter = 0
    malformed: dict[str, int] = {}
    wildcard_count = 0

    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith(("!", "#", "[")):
            continue  # comment, or an ``[Adblock Plus 2.0]`` header
        if any(marker in line for marker in _ADBLOCK_COSMETIC_MARKERS):
            continue

        is_exception = line.startswith("@@")
        body = line[2:] if is_exception else line
        if body.startswith("/"):
            regex += 1
            continue

        pattern, sep, mod_text = body.partition("$")
        mods = (
            frozenset(m.strip().lower() for m in mod_text.split(",") if m.strip())
            if sep
            else frozenset()
        )
        pattern = pattern.lower()
        if "badfilter" in mods:
            badfilter += 1
            cancelled.add((is_exception, pattern, mods - {"badfilter"}))
            continue
        if any(m.split("=", 1)[0] not in _ADBLOCK_HARMLESS_MODIFIERS for m in mods):
            modifier += 1
            continue

        if not pattern.startswith("||"):
            plain = _plain_name_rule(pattern)
            if plain is not None:
                kind, name = plain
                plain_key: _RuleKey = (is_exception, pattern, mods)
                if not is_exception:
                    literal_blocks.append((plain_key, name if kind == "exact" else f"*.{name}"))
                    continue
                if kind == "exact":
                    # Every renderer's exception means "this name and what is
                    # under it", so ``@@|name^`` over-allows the subtree; the
                    # rule's whole point is a carve-out, so it is kept.
                    allows.append((plain_key, name))
                    continue
                # ``@@.name^`` (subdomains only, apex stays blocked) has no
                # exception to map to: skipped and counted, as before.
            reason = _malformed_reason(pattern, None)
            malformed[reason] = malformed.get(reason, 0) + 1
            continue
        host = pattern[2:]
        if host.endswith("|"):
            host = host[:-1]
        if host.endswith("^"):
            host = host[:-1]
        if not _ADBLOCK_HOST_RE.match(host):
            reason = _malformed_reason(pattern, host)
            malformed[reason] = malformed.get(reason, 0) + 1
            continue
        host = host.strip(".")
        if host.startswith("*."):
            host = host[2:]
        key: _RuleKey = (is_exception, pattern, mods)
        (allows if is_exception else blocks).append((key, host))

    # ``$important`` raises a block over every exception that is not itself
    # ``$important`` — that is the modifier's whole meaning. So a plain
    # ``@@`` for a name an important block names is overruled, and is not
    # stored: a stored exception would unblock the name for every list on
    # the group, inverting the feed's intent.
    important_blocks = {
        host
        for key, host in (*blocks, *literal_blocks)
        if key not in cancelled and "important" in key[2]
    }
    exceptions: list[str] = []
    excepted: set[str] = set()
    for key, host in allows:
        if key in cancelled or host in excepted:
            continue
        if host in important_blocks and "important" not in key[2]:
            continue
        excepted.add(host)
        exceptions.append(host)

    domains: list[str] = []
    seen: set[str] = set()
    for key, host in blocks:
        if key in cancelled:
            continue
        # ``||name^`` is adblock's "name and every subdomain" (#894).
        wildcard_count += 1
        # A name the feed also excepts never renders (the RPZ renderers skip
        # an entry equal to an exception), so storing it would only inflate
        # ``entry_count`` past what the list enforces.
        if host in seen or host in excepted:
            continue
        seen.add(host)
        domains.append(host)

    literals: list[str] = []
    literal_seen: set[str] = set()
    for key, host in literal_blocks:
        if key in cancelled:
            continue
        # A ``*.name`` entry beside an exception for ``name`` would put two
        # CNAMEs on one RPZ owner (the exception emits ``*.name`` too), which
        # BIND rejects for the whole zone.
        apex = host[2:] if host.startswith("*.") else host
        # An exact ``name`` already covered by a ``||name^`` entry adds nothing
        # (and the table is unique on the name).
        if apex in excepted or host in literal_seen or host in seen:
            continue
        literal_seen.add(host)
        literals.append(host)

    return ParsedFeed(
        domains=domains,
        wildcard_count=wildcard_count,
        exceptions=exceptions,
        skipped=FeedSkipCounts(regex=regex, modifier=modifier, badfilter=badfilter, **malformed),
        literal_domains=literals,
    )


def parse_feed_detailed(content: str, feed_format: str) -> ParsedFeed:
    """Parse raw feed text into deduped domains + wildcard-syntax count.

    Accepts:
      - `hosts`: `0.0.0.0 ads.example.com` (or `127.0.0.1`)
      - `domains`: one domain per line, optionally `*.`-prefixed
      - `adblock`: `||ads.example.com^`, with `@@` exceptions and
        `$important` / `$badfilter`; see :func:`_parse_adblock`

    Ignores blank lines and comments (`#`, `!`). A leading `*.` is
    stripped rather than kept — see the comment at the strip site.
    """
    if feed_format == "adblock":
        # The reverse of the check below (#3597): a hosts or domains file
        # matches no ``||name^`` rule, so the adblock parser would count
        # every line malformed, return no domains, and the refresh would
        # empty the list. A real adblock feed with a few plain-name lines
        # stays below the majority threshold and parses as before.
        if _looks_like_hosts(content):
            return ParsedFeed(domains=[], wildcard_count=0, format_mismatch="hosts")
        if _looks_like_domains(content):
            return ParsedFeed(domains=[], wildcard_count=0, format_mismatch="domains")
        return _parse_adblock(content)

    if _looks_like_adblock(content):
        # Hosts / domains parsers would store every ``||name^`` rule as a
        # "name" that never matches anything (#3531). Report it instead.
        return ParsedFeed(domains=[], wildcard_count=0, format_mismatch="adblock")
    if feed_format == "domains" and _looks_like_hosts(content):
        # The domains parser takes a hosts line's address as its name, so
        # every entry would be skipped and the refresh would empty the list.
        return ParsedFeed(domains=[], wildcard_count=0, format_mismatch="hosts")

    out: list[str] = []
    seen: set[str] = set()
    wildcard_count = 0
    invalid = 0

    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue

        domain: str | None = None

        if feed_format == "hosts":
            # Strip inline comment
            line = line.split("#", 1)[0].strip()
            parts = line.split()
            if len(parts) >= 2:
                domain = parts[1]
            elif len(parts) == 1:
                domain = parts[0]
        else:  # "domains"
            line = line.split("#", 1)[0].strip()
            if line:
                domain = line.split()[0]

        if not domain:
            continue
        domain = domain.lower().strip(".")
        # Several feeds publish wildcard syntax (`*.example.com` — OISD's
        # `domainswild`, Hagezi's `wildcard/`). The star is how the feed
        # says "and every subdomain", which is what a blocklist entry
        # means here anyway, so it is stripped rather than stored: kept
        # literally it produces an RPZ rule matching subdomains ONLY,
        # leaving the apex resolving normally.
        if domain.startswith("*."):
            domain = domain[2:]
            wildcard_count += 1
        if not domain or "." not in domain:
            continue
        # An address in the name position (StevenBlack's ``0.0.0.0 0.0.0.0``
        # header line) is hosts-file boilerplate, not a name the feed meant
        # to block: skipped silently, like ``localhost``.
        if _is_ip_literal(domain):
            continue
        if not _is_feed_name(domain):
            invalid += 1
            continue
        if domain in seen:
            continue
        seen.add(domain)
        out.append(domain)

    return ParsedFeed(
        domains=out,
        wildcard_count=wildcard_count,
        skipped=FeedSkipCounts(invalid_name=invalid) if invalid else None,
    )


def dedupe_domains(domains: list[str]) -> list[str]:
    """Return a deduped, lowercased, sorted-by-input-order list of valid domains."""
    seen: set[str] = set()
    out: list[str] = []
    for d in domains:
        dd = d.strip().lower().strip(".")
        if not dd or "." not in dd or dd in seen:
            continue
        seen.add(dd)
        out.append(dd)
    return out
