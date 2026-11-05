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
    * ``malformed`` — anything else this parser cannot turn into a name:
      a path (``||host/ads``), a ``*`` inside a name, a ``|`` anchor, a
      bare word.
    """

    regex: int = 0
    modifier: int = 0
    badfilter: int = 0
    malformed: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "regex": self.regex,
            "modifier": self.modifier,
            "badfilter": self.badfilter,
            "malformed": self.malformed,
        }


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
    an adblock feed carried that became neither; it is None for the other
    formats, which have no rule syntax to lose.
    """

    domains: list[str]
    wildcard_count: int
    exceptions: list[str] = field(default_factory=list)
    skipped: FeedSkipCounts | None = None


def parse_feed(content: str, feed_format: str) -> list[str]:
    """Parse raw feed text into a deduped list of domains.

    Thin wrapper over :func:`parse_feed_detailed` for the many callers
    (and tests) that only want the names.
    """
    return parse_feed_detailed(content, feed_format).domains


#: A hostname as an adblock ``||`` rule may name it: labels of letters,
#: digits, ``-`` and ``_``, at least two of them, optionally ``*.``-led.
_ADBLOCK_HOST_RE = re.compile(r"^(?:\*\.)?[a-z0-9_-]+(?:\.[a-z0-9_-]+)+\.?$")

#: Modifiers that leave a rule's DNS meaning intact. ``important`` only
#: raises a rule's precedence over exceptions in the same engine.
_ADBLOCK_HARMLESS_MODIFIERS = frozenset({"important"})

#: Element-hiding / scriptlet separators. Those rules are for browsers, never
#: for DNS, so they are ignored rather than counted as lost.
_ADBLOCK_COSMETIC_MARKERS = ("##", "#@#", "#?#", "#$#", "#%#", "#@$#", "#@%#", "#@?#")


#: (is_exception, pattern, modifiers without badfilter) identifies a rule for
#: ``$badfilter``, which cancels the rule that is otherwise identical.
_RuleKey = tuple[bool, str, frozenset[str]]


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
    allows: list[tuple[_RuleKey, str]] = []
    cancelled: set[_RuleKey] = set()
    regex = modifier = badfilter = malformed = 0
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
            malformed += 1
            continue
        host = pattern[2:]
        if host.endswith("|"):
            host = host[:-1]
        if host.endswith("^"):
            host = host[:-1]
        if not _ADBLOCK_HOST_RE.match(host):
            malformed += 1
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
        host for key, host in blocks if key not in cancelled and "important" in key[2]
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

    return ParsedFeed(
        domains=domains,
        wildcard_count=wildcard_count,
        exceptions=exceptions,
        skipped=FeedSkipCounts(
            regex=regex, modifier=modifier, badfilter=badfilter, malformed=malformed
        ),
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
        return _parse_adblock(content)

    out: list[str] = []
    seen: set[str] = set()
    wildcard_count = 0

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
        if domain in seen:
            continue
        seen.add(domain)
        out.append(domain)

    return ParsedFeed(domains=out, wildcard_count=wildcard_count)


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
