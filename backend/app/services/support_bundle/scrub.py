"""Scrubbing for the support bundle (issue #875).

A support bundle is meant to be attached to a **public** GitHub issue.
Attachments on a public repo's issues are effectively world-readable —
the JWT-signed `private-user-images.githubusercontent.com` URLs follow
repository visibility, so anyone who can read the issue can fetch the
file, and deleting the comment does not reliably purge it. So the plan
is scrubbing, not secrecy.

Two tiers, and the distinction is the whole design:

**Hard-exclude** — secrets. Fernet blobs, password hashes, PSKs, API
tokens, TSIG keys, private keys. These are never pseudonymised and never
appear in any mode, including the "unscrubbed" one: an unscrubbed bundle
is for an operator debugging their own install, and there is no version
of that which is improved by shipping the credential that decrypts
everything else. :func:`redact_secrets` and the safety net below enforce
that independently of any caller remembering to.

**Pseudonymise** — identifying-but-diagnostic values: IPs, hostnames,
domains, MACs, usernames. Replaced with stable synthetic values so the
bundle stays *useful* — you can still see that two log lines refer to
one host, that a set of addresses share a subnet, that a name is three
labels deep. This is the ``sos report --clean`` model, and like sos it
is explicitly **best-effort**: freeform text can carry an identifier in
a shape no regex anticipates. The docs say "review before sharing" for
the same reason theirs do.

Determinism: mappings are seeded from the install's ``SECRET_KEY`` via
HMAC, so a given value maps to the same token across runs on one install
(support can correlate two bundles) and is unguessable from outside it
(the seed is never in the bundle). The reverse mapping is returned
separately from the archive, never inside it.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from dataclasses import dataclass, field

from app.config import settings

# ── Address space for synthetic values ──────────────────────────────────
#
# 240.0.0.0/4 (RFC 1112 "reserved for future use") rather than sos's
# 100.64.0.0/10: SpatiumDDI *models* CGNAT space as a real, meaningful
# thing — #42 ships a CGNAT advisory badge — so obfuscating into it would
# make a scrubbed bundle look like it documents genuine CGNAT
# deployments. 240/4 is unroutable and unmistakably synthetic, so nobody
# reading a bundle can confuse it for real addressing.
_SYNTH_V4_BASE = int(ipaddress.IPv4Address("240.0.0.0"))
# Index width is capped so synthetic addresses stay inside 240.0.0.0/6
# (240.x–243.x). The wider /4 runs to 255.255.255.255, and emitting a
# 255.x address into a diagnostics file reads as broadcast space.
_SYNTH_V4_NETS = 1 << 18
# 2001:db8::/32 is RFC 3849 documentation space — the v6 equivalent of
# "obviously not real".
_SYNTH_V6_PREFIX = ipaddress.IPv6Address("2001:db8::")
# Locally-administered OUI (the 0x02 bit) so a synthetic MAC cannot
# collide with a real vendor assignment.
_SYNTH_MAC_OUI = "02:00:00"
# RFC 2606 reserves .invalid precisely so it can never resolve.
_SYNTH_TLD = "invalid"


_REDACTED = "[REDACTED]"


# ── Hard-exclude: secret shapes ─────────────────────────────────────────
#
# Matched on VALUE shape, not on the key name, so a secret that lands in
# an unexpected field is still caught. These are all high-signal prefixes
# with no plausible benign meaning in a diagnostics dump.
_SECRET_VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    # Fernet token — every encrypted column in this codebase.
    ("fernet", re.compile(r"\bgAAAAA[A-Za-z0-9_\-=]{16,}"), f"{_REDACTED}:fernet"),
    # bcrypt / argon2 password hashes.
    (
        "password-hash",
        re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"),
        f"{_REDACTED}:password-hash",
    ),
    (
        "password-hash",
        re.compile(r"\$argon2[a-z]{1,2}\$[^\s\"']{16,}"),
        f"{_REDACTED}:password-hash",
    ),
    # PEM private keys (and certificates' private halves).
    ("pem", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"), f"{_REDACTED}:pem"),
    # JWTs — session tokens, agent tokens, supervisor tokens.
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
        f"{_REDACTED}:jwt",
    ),
    # Credentials embedded in a URL's userinfo. Found by testing rather
    # than by reading: DATABASE_URL ships as
    # ``postgresql+asyncpg://user:password@host/db`` and no name-based
    # rule catches it, because the variable is called *_URL. Only the
    # userinfo is replaced — the scheme, host and path are topology and
    # the host is pseudonymised separately.
    # Square brackets are excluded from the userinfo class so the
    # replacement — "[REDACTED]:[REDACTED]" — cannot match the pattern
    # that produced it. Without that, redacting twice re-fires, and the
    # SAFETY NET then reports a hit on text a collector had already
    # cleaned: a false bug report, from the mechanism whose whole value
    # is that a hit means a real one.
    (
        "url-credentials",
        re.compile(r"(?<=://)[^:/@\s\[\]]+:[^@/\s\[\]]+(?=@)"),
        f"{_REDACTED}:{_REDACTED}",
    ),
    # Telegram Bot API token (``<bot id>:<secret>``). It travels in the
    # request PATH (``/bot<token>/sendMessage``), so any log line that
    # prints the request URL carries it. The audit-forward sender filters
    # it out of httpx's request log; this catches whatever else does.
    (
        "telegram-bot-token",
        re.compile(r"(?<!\d)\d{3,15}:[A-Za-z0-9_-]{30,}"),
        f"{_REDACTED}:telegram-bot-token",
    ),
    # Base64 TSIG secrets are indistinguishable from any other base64, so
    # they are excluded by key name at the collector instead; see
    # ``SECRET_KEY_NAME_RE``.
)

# Matched on KEY name, for structured data (env dumps, settings rows,
# JSON blobs) where the value alone carries no telltale shape. Deliberately
# broad: a false positive costs one redacted diagnostic field, a false
# negative ships a credential to a public issue.
SECRET_KEY_NAME_RE = re.compile(
    r"(password|passwd|passphrase|secret|token|apikey|credential|"
    r"_encrypted$|psk|tsig|hmac|salt|gpg|bearer|cookie|session[_-]?id"
    # ``audit_forward_webhook_auth_header`` holds a literal
    # "Bearer …" / "Basic …" in PLAINTEXT (see its column comment) and
    # matched none of the terms above, so the settings collector shipped
    # it verbatim into an archive destined for a public issue. An
    # incoming-webhook URL is a bearer credential in its own right — the
    # path segment IS the authentication — so both are matched by name.
    r"|auth[_-]?header|authorization|webhook[_-]?url"
    # Any name ENDING in "key" or "keys". Broad on purpose: the agent
    # PSKs ship as DNS_AGENT_KEY / DHCP_AGENT_KEY / LG_AGENT_KEY, whose
    # values are raw hex with no shape a value-matcher could recognise —
    # so the name is the only thing that can catch them, and an
    # `api[_-]?key`-style enumeration will always be one variant behind.
    r"|(^|[_-])keys?$)",
    re.IGNORECASE,
)


def looks_secret_key(name: str) -> bool:
    """True when a field name suggests its value is a credential."""
    return bool(SECRET_KEY_NAME_RE.search(name or ""))


def redact_secrets(text: str) -> tuple[str, list[str]]:
    """Strip secret-shaped substrings. Returns (clean_text, kinds_hit).

    Runs in **every** mode. The unscrubbed bundle exists so an operator
    can read their own hostnames and addresses; it is not a reason to
    hand out the key that decrypts their database.
    """
    hits: list[str] = []
    out = text
    for kind, pattern, replacement in _SECRET_VALUE_PATTERNS:
        out, n = pattern.subn(replacement, out)
        if n:
            hits.append(kind)
    return out, hits


# ── Pseudonymisation ────────────────────────────────────────────────────

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b(?:/\d{1,2})?")
# Candidate-then-validate rather than a precise IPv6 regex. A
# hand-written pattern gets the compressed forms wrong in a way that is
# worse than not matching: for "2001:db8:9::1" the greedy alternative
# matched the "2001:db8:9" PREFIX and stopped at the "::" word boundary,
# so the substitution replaced three groups and left "::1" sitting in the
# output. Grabbing any hex-and-colon run and asking ``ipaddress`` whether
# it is an address has no such edge: it either parses or it does not.
_IPV6_CANDIDATE_RE = re.compile(r"\b[0-9A-Fa-f:]*:[0-9A-Fa-f:]*\b(?:/\d{1,3})?")

_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
# A dotted name with a plausible TLD. Excludes bare numbers (caught as IPs
# first) and single labels (too ambiguous — "localhost", "api", a column
# name — to touch without wrecking the bundle's readability).
_HOSTNAME_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b"
)

# Names that carry no information about the install and whose replacement
# would make the bundle harder to read for zero privacy gain.
_HOSTNAME_ALLOWLIST = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "example.com",
        "example.org",
        "example.net",
        "spatiumddi.com",
        "www.spatiumddi.com",
        "github.com",
        "in-addr.arpa",
        "ip6.arpa",
        # Compose / k8s service names are topology, not identity, and are
        # identical on every install.
        "postgres",
        "redis",
        "api",
        "worker",
        "beat",
        "frontend",
    }
)

# Final labels that CANNOT be a TLD, so a dotted token ending in one
# cannot be a resolvable hostname and skipping it costs nothing in
# privacy. This is the whole test applied below: every entry here was
# checked against the IANA root zone, and deliberately absent are the
# extensions that ARE real TLDs — `.zone`, `.py`, `.sh`, `.md`, `.rs`,
# `.go`, `.dev` — because denying those would leak a genuine hostname to
# save a line of traceback.
_NON_TLD_SUFFIXES = frozenset(
    {
        "json",
        "jsonl",
        "txt",
        "log",
        "yml",
        "yaml",
        "conf",
        "ini",
        "toml",
        "cfg",
        "sql",
        "lock",
        "pyc",
        "pyo",
        "env",
        "pem",
        "crt",
        "csr",
        "bak",
        "tmp",
        "out",
        "err",
        "db",
        "sqlite",
        "whl",
        "tar",
        "gz",
    }
)


def _is_probably_code_not_a_hostname(name: str) -> bool:
    """Whether a dotted token is source code rather than a name.

    Tracebacks are among the most useful things in a bundle, and the
    hostname pattern happily eats them: ``sqlalchemy.exc.ProgrammingError``
    and ``versions.json`` are both "labels separated by dots ending in
    letters". Rewriting them to ``nA.nB.dC.invalid`` costs the reader the
    stack trace they opened the file for.

    Only STRICTLY SAFE rules are applied — each one identifies a token
    that could not be a resolvable hostname anyway, so nothing real is
    left exposed to buy the readability:

    * a final label with BOTH cases (``ProgrammingError``, ``PosixPath``)
      — no TLD is camel-case, while an all-caps ``EXAMPLE.COM`` is still
      pseudonymised because a shouted hostname is a real one;
    * a final label in :data:`_NON_TLD_SUFFIXES`.

    Not covered, and accepted: ``collect.py`` and ``app.services.scrub``
    are still pseudonymised — ``py`` is Paraguay's ccTLD and ``scrub``
    could be a gTLD for all this function knows. Sparing them would need
    a "preceded by a slash, so it is a path" heuristic, and that leaks
    the domain straight out of a DNS product's own
    ``/var/named/corp.example.com.zone`` log lines. What a reader keeps
    in a mangled traceback line is the directory, the line number, the
    function name and — the part that matters most — the exception's own
    dotted module path, since ``ProgrammingError`` is camel-case.
    Over-scrubbing is the correct direction to err in a file destined for
    a public issue.
    """
    last = name.rsplit(".", 1)[-1]
    if last.lower() in _NON_TLD_SUFFIXES:
        return True
    return any(c.isupper() for c in last) and any(c.islower() for c in last)


# Public suffixes we keep intact so `foo.co.uk` does not read as a
# two-label domain. Not the full PSL — that would be a dependency for a
# cosmetic gain — just the common multi-part ones.
_MULTI_PART_SUFFIXES = frozenset(
    {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp"}
)


@dataclass
class ScrubReport:
    """What the scrubber did, for the manifest and the UI preview."""

    ips_v4: int = 0
    ips_v6: int = 0
    macs: int = 0
    hostnames: int = 0
    usernames: int = 0
    secrets_redacted: dict[str, int] = field(default_factory=dict)
    # Files where the safety net fired — a non-empty list means a
    # collector shipped something it should have redacted itself, which
    # is a bug, not a routine event.
    safety_net_hits: list[str] = field(default_factory=list)


class Scrubber:
    """Stateful, deterministic pseudonymiser for one bundle.

    Not thread-safe and not meant to be: one instance per generation,
    which is also what makes the mapping self-consistent.
    """

    def __init__(self, *, enabled: bool = True, seed: str | None = None) -> None:
        self.enabled = enabled
        self._seed = (seed or settings.secret_key or "spatiumddi").encode()
        # real -> synthetic. The inverse is handed to the operator
        # separately and never written into the archive.
        self._ipv4: dict[str, str] = {}
        self._ipv4_nets: dict[str, int] = {}
        self._ipv6: dict[str, str] = {}
        self._macs: dict[str, str] = {}
        self._hosts: dict[str, str] = {}
        self._domains: dict[str, str] = {}
        self._users: dict[str, str] = {}
        self.report = ScrubReport()

    # ── deterministic index allocation ──────────────────────────────
    def _index(self, bucket: str, value: str, modulo: int) -> int:
        """Stable pseudo-random index for ``value`` within ``bucket``.

        HMAC over the install seed: same value → same index on this
        install, and not reproducible by anyone without the seed.
        """
        digest = hmac.new(self._seed, f"{bucket}:{value}".encode(), hashlib.sha256).digest()
        return int.from_bytes(digest[:4], "big") % modulo

    # ── IPv4 ────────────────────────────────────────────────────────
    def ipv4(self, raw: str) -> str:
        """Map an IPv4 address, preserving subnet grouping and host octet.

        Two addresses in one real /24 land in one synthetic /24, and the
        final octet survives — so "is .1 the gateway, .255 the broadcast"
        stays answerable, and "these hosts are on the same segment" stays
        visible. That is the property that makes a scrubbed bundle worth
        reading for a DDI product, where the addressing IS the subject.
        """
        if raw in self._ipv4:
            return self._ipv4[raw]
        try:
            addr = ipaddress.IPv4Address(raw)
        except ValueError:
            return raw
        # Loopback / unspecified / link-local carry no site information
        # and are load-bearing when reading logs.
        if addr.is_loopback or addr.is_unspecified or addr.is_link_local or addr.is_multicast:
            self._ipv4[raw] = raw
            return raw

        net_key = str(ipaddress.IPv4Network(f"{addr}/24", strict=False).network_address)
        if net_key not in self._ipv4_nets:
            # 2^18 distinct synthetic /24s; collisions across one
            # install's subnets are not a practical concern.
            self._ipv4_nets[net_key] = self._index("v4net", net_key, _SYNTH_V4_NETS)
        synth_net = _SYNTH_V4_BASE + (self._ipv4_nets[net_key] << 8)
        synth = str(ipaddress.IPv4Address(synth_net + int(addr) % 256))
        self._ipv4[raw] = synth
        self.report.ips_v4 += 1
        return synth

    # ── IPv6 ────────────────────────────────────────────────────────
    def ipv6(self, raw: str) -> str:
        """Map an IPv6 address, preserving /64 grouping.

        The interface ID is NOT preserved, unlike the v4 host octet: a
        SLAAC address embeds the MAC (RFC 4291 modified EUI-64), so
        carrying it through would leak hardware identity straight past
        the MAC scrubber.
        """
        if raw in self._ipv6:
            return self._ipv6[raw]
        try:
            addr = ipaddress.IPv6Address(raw)
        except ValueError:
            return raw
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local:
            self._ipv6[raw] = raw
            return raw

        net_key = str(ipaddress.IPv6Network(f"{addr}/64", strict=False).network_address)
        subnet = self._index("v6net", net_key, 1 << 16)
        iid = self._index("v6iid", raw, 1 << 32)
        synth = ipaddress.IPv6Address(int(_SYNTH_V6_PREFIX) + (subnet << 64) + iid)
        self._ipv6[raw] = str(synth)
        self.report.ips_v6 += 1
        return str(synth)

    # ── MAC ─────────────────────────────────────────────────────────
    def mac(self, raw: str) -> str:
        """Map a MAC to a locally-administered synthetic one.

        The real OUI is dropped rather than preserved. It names the
        hardware vendor, which is site-identifying in aggregate ("this
        estate is all one vendor"), and the diagnostic value of knowing
        the vendor is lower than that risk on a public attachment.
        """
        key = raw.lower().replace("-", ":")
        if key in self._macs:
            return self._macs[key]
        idx = self._index("mac", key, 1 << 24)
        synth = f"{_SYNTH_MAC_OUI}:{idx >> 16 & 0xFF:02x}:{idx >> 8 & 0xFF:02x}:{idx & 0xFF:02x}"
        self._macs[key] = synth
        self.report.macs += 1
        return synth

    # ── Hostnames / domains ─────────────────────────────────────────
    def hostname(self, raw: str) -> str:
        """Map a dotted name, preserving subdomain depth and zone grouping.

        ``a.corp.example.com`` and ``b.corp.example.com`` become
        ``nA.nB.dK.invalid`` sharing ``nB.dK`` — so "same zone" and "same
        subdomain" survive, which is most of what a DNS bug report is
        about, and the number of subdomain levels is unchanged.

        The registrable domain collapses to ONE synthetic label
        regardless of how many it had, so ``foo.co.uk`` and
        ``foo.example`` both yield ``dK.invalid``. Preserving that depth
        would say which public suffix the site uses, which is
        jurisdiction-adjacent information for no diagnostic gain.
        """
        name = raw.rstrip(".").lower()
        if not name or name in _HOSTNAME_ALLOWLIST:
            return raw
        # Reverse-DNS names are structure, not identity, and rewriting
        # them would destroy the one thing that makes a PTR log readable.
        if name.endswith(".in-addr.arpa") or name.endswith(".ip6.arpa"):
            return raw
        if _is_probably_code_not_a_hostname(raw):
            return raw
        if name in self._hosts:
            return self._hosts[name]

        labels = name.split(".")
        suffix_len = 2
        if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_PART_SUFFIXES:
            suffix_len = 3
        domain = ".".join(labels[-suffix_len:]) if len(labels) >= suffix_len else name
        if domain not in self._domains:
            self._domains[domain] = f"d{self._index('domain', domain, 100000)}.{_SYNTH_TLD}"
        parts = [self._domains[domain]]
        for label in reversed(labels[:-suffix_len]):
            parts.insert(0, f"n{self._index('label', f'{domain}:{label}', 100000)}")
        synth = ".".join(parts)
        self._hosts[name] = synth
        self.report.hostnames += 1
        return synth

    def username(self, raw: str) -> str:
        """Map an operator/account name.

        Unlike :meth:`mac` / :meth:`ipv4` / :meth:`hostname`, collectors
        call this DIRECTLY rather than through :meth:`text`, so it has to
        honour ``enabled`` itself. Without that check an unscrubbed
        bundle still came back with ``user41234`` in the audit tail —
        contradicting its own manifest ("contains real … usernames") and
        leaving no way to read it, since the UI only offers the decode
        map for a scrubbed bundle.
        """
        if not raw or not self.enabled:
            return raw
        key = raw.lower()
        if key not in self._users:
            self._users[key] = f"user{self._index('user', key, 100000)}"
            self.report.usernames += 1
        return self._users[key]

    # ── Text sweep ──────────────────────────────────────────────────
    def text(self, value: str) -> str:
        """Scrub a blob of freeform text (a log file, a traceback).

        Order matters. MACs first, because a colon-separated MAC is a
        near-miss for the IPv6 pattern. Then v6, then v4, then hostnames
        — by which point anything address-shaped is already a synthetic
        value and the hostname regex will not re-match it.
        """
        if not value:
            return value
        cleaned, kinds = redact_secrets(value)
        for kind in kinds:
            self.report.secrets_redacted[kind] = self.report.secrets_redacted.get(kind, 0) + 1
        if not self.enabled:
            return cleaned

        cleaned = _MAC_RE.sub(lambda m: self.mac(m.group(0)), cleaned)
        cleaned = _IPV6_CANDIDATE_RE.sub(self._maybe_ipv6, cleaned)
        cleaned = _IPV4_RE.sub(lambda m: self._sub_cidr(m.group(0), self.ipv4), cleaned)
        cleaned = _HOSTNAME_RE.sub(lambda m: self.hostname(m.group(0)), cleaned)
        return cleaned

    def _maybe_ipv6(self, match: re.Match[str]) -> str:
        """Map a hex-and-colon run, but only if it really is an address.

        The candidate pattern is deliberately loose, so this is where a
        timestamp fragment, a `key: value` pair or anything else with a
        colon gets handed back untouched.
        """
        token = match.group(0)
        addr = token.partition("/")[0]
        try:
            ipaddress.IPv6Address(addr)
        except ValueError:
            return token
        return self._sub_cidr(token, self.ipv6)

    @staticmethod
    def _sub_cidr(token: str, mapper) -> str:  # type: ignore[no-untyped-def]
        """Apply ``mapper`` to the address half of an optional CIDR.

        The prefix length is topology, not identity, and dropping it
        would turn every subnet in an IPAM bundle into a bare address.
        """
        if "/" in token:
            addr, _, prefix = token.partition("/")
            return f"{mapper(addr)}/{prefix}"
        return mapper(token)

    def value(self, key: str, value: object) -> object:
        """Scrub one structured field, using its name as a hint."""
        if looks_secret_key(key):
            return _REDACTED if value not in (None, "", [], {}) else value
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {k: self.value(k, v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.value(key, v) for v in value]
        return value

    # ── Reverse mapping ─────────────────────────────────────────────
    def decode_map(self) -> dict[str, dict[str, str]]:
        """Synthetic → real, for the operator only.

        Returned from a separate endpoint and never written into the
        archive: a bundle that carries its own decoder is not scrubbed,
        it is merely inconvenient to read.
        """
        return {
            "ipv4": {v: k for k, v in self._ipv4.items() if v != k},
            "ipv6": {v: k for k, v in self._ipv6.items() if v != k},
            "mac": {v: k for k, v in self._macs.items()},
            "hostname": {v: k for k, v in self._hosts.items()},
            "username": {v: k for k, v in self._users.items()},
        }


# ── Safety net ──────────────────────────────────────────────────────────


def safety_net(name: str, content: str, report: ScrubReport) -> str:
    """Last-chance sweep over an assembled section.

    Every collector is supposed to redact its own secrets. This runs
    anyway, because "a collector forgot" and "a new column got added"
    are ordinary events and the consequence — a credential on a public
    issue — is not recoverable.

    A hit is recorded in ``report.safety_net_hits`` and surfaced in the
    manifest rather than swallowed: the net firing means a collector has
    a bug, and hiding that would let the bug persist behind a net that
    might not catch the next variant.
    """
    cleaned, kinds = redact_secrets(content)
    if kinds:
        report.safety_net_hits.append(f"{name}: {', '.join(sorted(set(kinds)))}")
        for kind in kinds:
            report.secrets_redacted[kind] = report.secrets_redacted.get(kind, 0) + 1
    return cleaned
