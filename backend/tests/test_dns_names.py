"""Unit tests for the shared DNS-name validators (issue #597).

The acceptance criteria are encoded directly here: the eight malformed
hostnames from the live repro must be rejected, while legitimate DNS
owners that are *not* valid host names — ``_acme-challenge`` (our own ACME
DNS-01 client), ``_443._tcp`` SRV owners, ``*`` wildcards — must still
pass. These two facts pulling in opposite directions are the whole reason
the rule is per-context.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from app.core.dns_names import (
    MAX_NAME_LEN,
    contains_control_chars,
    contains_zonefile_unsafe,
    sanitize_hostname,
    validate_dns_label,
    validate_fqdn,
    validate_host_label,
    validate_hostname,
    validate_record_owner,
)

# ── Host names (RFC 1123, strict LDH) ────────────────────────────────────

# The eight malformed hostnames that returned HTTP 201 in the live repro.
MALFORMED_HOSTNAMES = [
    "has space",
    "under_score",  # underscore is illegal in a *host* name (fine in a record owner)
    "-leading-hyphen",
    "a..b",  # empty label
    "CAPS Host!",
    'evil\nMORE IN TXT "pwned"',
    "x" * 68,  # over the 63-char label limit
    "trailing-hyphen-",
]


@pytest.mark.parametrize("bad", MALFORMED_HOSTNAMES)
def test_validate_hostname_rejects_malformed(bad: str) -> None:
    with pytest.raises(ValueError):
        validate_hostname(bad)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("web01", "web01"),
        ("WEB01", "web01"),  # canonicalized to lowercase
        ("web01.corp.example.com", "web01.corp.example.com"),
        ("host-name-01", "host-name-01"),
        ("a", "a"),  # single-char label is legal
        ("web01.example.com.", "web01.example.com"),  # trailing root dot stripped
        ("  web01  ", "web01"),  # surrounding whitespace trimmed
        ("9host", "9host"),  # RFC 1123 relaxed the leading-digit ban
    ],
)
def test_validate_hostname_accepts_and_normalizes(raw: str, expected: str) -> None:
    assert validate_hostname(raw) == expected


def test_validate_hostname_idna_normalizes_unicode() -> None:
    # A unicode host name is accepted by converting to its A-label form,
    # which is what actually goes on the wire — not rejected outright.
    out = validate_hostname("Ünïcödé")
    assert out.startswith("xn--")
    assert out.isascii()


def test_validate_hostname_rejects_over_253() -> None:
    long_name = ".".join(["abcdefgh"] * 40)  # 40*8 + 39 dots = 359 chars
    with pytest.raises(ValueError):
        validate_hostname(long_name)


def test_validate_hostname_empty() -> None:
    with pytest.raises(ValueError):
        validate_hostname("   ")


# ── DNS record owners (RFC 2181, permits _ and *) ────────────────────────

# The load-bearing acceptance case: these are NOT valid host names but ARE
# valid DNS record owners and must keep working.
LEGITIMATE_OWNERS = [
    "_acme-challenge",
    "_acme-challenge.www",
    "_dmarc",
    "_443._tcp",
    "_sip._tls.example.com",
    "*",
    "*.example.com",
    "www",
    "@",  # apex
    "",  # apex (empty → @)
]


@pytest.mark.parametrize("owner", LEGITIMATE_OWNERS)
def test_validate_record_owner_accepts_legitimate(owner: str) -> None:
    # Must not raise; apex forms normalize to "@".
    out = validate_record_owner(owner)
    if owner in ("", "@"):
        assert out == "@"
    else:
        assert out == owner.lower()


def test_validate_record_owner_underscore_is_a_hostname_failure() -> None:
    # Same string: illegal as a host name, legal as a record owner. This
    # divergence is exactly why the rule is per-context.
    with pytest.raises(ValueError):
        validate_hostname("_acme-challenge")
    assert validate_record_owner("_acme-challenge") == "_acme-challenge"


@pytest.mark.parametrize(
    "bad",
    [
        "has space",
        "evil\nrecord",
        "semi;colon",  # ; starts a zone-file comment
        "dollar$sign",
        'quote"mark',
        "a..b",  # empty interior label
        "x" * 64,  # label too long
    ],
)
def test_validate_record_owner_rejects_dangerous(bad: str) -> None:
    with pytest.raises(ValueError):
        validate_record_owner(bad)


def test_validate_record_owner_wildcard_only_leftmost() -> None:
    assert validate_record_owner("*.example.com") == "*.example.com"
    with pytest.raises(ValueError):
        validate_record_owner("example.*.com")


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("www.", "www"),
        ("www.example.com.", "www.example.com"),
        ("_acme-challenge.", "_acme-challenge"),
    ],
)
def test_validate_record_owner_strips_trailing_dot(raw: str, expected: str) -> None:
    # A record owner is relative and the handlers build ``f"{name}.{zone}"``,
    # so a preserved trailing dot would yield a double-dotted FQDN (#597 review).
    assert validate_record_owner(raw) == expected


# ── FQDNs (zone names, domain-name option, rdata targets) ────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("example.com.", "example.com"),
        ("10.in-addr.arpa", "10.in-addr.arpa"),
        ("_msdcs.example.com", "_msdcs.example.com"),  # underscore zone label
    ],
)
def test_validate_fqdn_accepts(raw: str, expected: str) -> None:
    assert validate_fqdn(raw) == expected


@pytest.mark.parametrize("bad", ["bad domain", "under_score.com not", "a..b", "*.example.com"])
def test_validate_fqdn_rejects(bad: str) -> None:
    with pytest.raises(ValueError):
        validate_fqdn(bad)


def test_validate_fqdn_strict_host_mode_rejects_underscore() -> None:
    with pytest.raises(ValueError):
        validate_fqdn("_dmarc.example.com", allow_underscore=False)


# ── Zone-file safety guard (render boundary) ─────────────────────────────


@pytest.mark.parametrize(
    "value,unsafe",
    [
        ("web01", False),
        ("_acme-challenge.www", False),
        ("normal.example.com", False),
        ("evil\nrecord", True),
        ("has space", True),
        ("semi;colon", True),
        ("dollar$sign", True),
        ("null\x00byte", True),
        ("paren(group", True),
    ],
)
def test_contains_zonefile_unsafe(value: str, unsafe: bool) -> None:
    assert contains_zonefile_unsafe(value) is unsafe


@pytest.mark.parametrize(
    "value,has_ctrl",
    [
        # The narrow guard used at the rdata boundary: only control bytes.
        # Spaces and quotes must NOT trip it, or structured rdata breaks.
        ("web01", False),
        ('1 . alpn="h2,h3"', False),  # HTTPS/SVCB rdata — spaces + quotes
        ('0 issue "letsencrypt.org"', False),  # CAA rdata
        ("51 30 12.748 N 0 7 39.611 W 2m", False),  # LOC rdata
        ("evil\nrecord", True),
        ("tab\there", True),
        ("null\x00byte", True),
    ],
)
def test_contains_control_chars(value: str, has_ctrl: bool) -> None:
    assert contains_control_chars(value) is has_ctrl


# ── Non-raising sanitizer (DHCP lease path) ──────────────────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("my pc", "my-pc"),
        ("MyPC", "mypc"),
        ("my pc.corp", "my-pc.corp"),  # multi-label aware
        ("--weird--", "weird"),
        ('"quoted"', "quoted"),
        ("", ""),
        (None, ""),
        ("!!!", ""),  # nothing usable
        ("under_score", "under-score"),
    ],
)
def test_sanitize_hostname(raw: str | None, expected: str) -> None:
    assert sanitize_hostname(raw) == expected


def test_sanitize_hostname_output_is_valid() -> None:
    # Whatever the sanitizer emits (when non-empty) must itself pass strict
    # host validation — otherwise it just moves the problem downstream.
    # Includes truncation-boundary inputs (issue #597 review): a long run of
    # hyphens truncated at 63 must NOT leave a trailing hyphen.
    for raw in [
        "my pc",
        "Weird__Name",
        "café-01",
        "a.b.c",
        "printer" + "-" * 60 + "lobby",  # 63rd char lands on a hyphen
        "a" + "-" * 70 + "b",
        "conference room projector second floor east wing unit annex",
        "x" * 300,
    ]:
        out = sanitize_hostname(raw)
        if out:
            assert validate_hostname(out) == out, f"{raw!r} -> {out!r} is not a valid hostname"


def test_sanitize_hostname_respects_length_cap() -> None:
    out = sanitize_hostname(".".join(["label"] * 60))
    assert len(out) <= MAX_NAME_LEN
    assert not out.endswith(".")


# #2071 — Python's ``$`` matches before a trailing newline, so a label ending
# in one passed both label rules; an embedded label is not stripped by the
# whole-name validators, so ``web1\n.lab`` reached them too.
@pytest.mark.parametrize(
    ("validate", "value"),
    [
        (validate_host_label, "web1\n"),
        (validate_dns_label, "web1\n"),
        (validate_hostname, "web1\n.lab"),
        (validate_record_owner, "web1\n.lab"),
        (validate_fqdn, "web1\n.example.com"),
    ],
)
def test_a_label_ending_in_a_newline_is_refused(validate: Callable[..., str], value: str) -> None:
    with pytest.raises(ValueError):
        validate(value)
