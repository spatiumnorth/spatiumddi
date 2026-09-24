"""Canonical forms for the identity fields DHCP reconcilers compare on.

A MAC read back from a Windows DHCP server (``00-15-5D-01-02-03``) and the
same MAC as Postgres stores it (``00:15:5d:01:02:03``) are the same address
written two ways. Any code that diffs wire state against DB state has to fold
both to one form first, or a cosmetic reformat reads as a change — which for
``pull_leases._upsert_scope`` means deleting a reservation and re-creating it
under a new id on every poll.

These started life as ``_norm_mac`` / ``_norm_ip`` inside
``windows_writethrough`` (#426, for its change-detection). ``pull_leases``
needs exactly the same semantics, and two definitions that could drift apart
is the last thing a reconciler wants — so they live here and both import them.
"""

from __future__ import annotations

import ipaddress

from app.core.mac import canonicalize_mac

__all__ = ["canonical_duid", "canonicalize_mac", "norm_duid", "norm_ip", "norm_mac"]


def norm_mac(mac: str) -> str:
    """Fold a MAC to bare lowercase hex, so ``00-15-5D-…`` == ``00:15:5d:…``."""
    return "".join(c for c in mac.lower() if c in "0123456789abcdef")


def norm_ip(ip: str) -> str:
    """Canonicalise an IP for change-detection.

    Falls back to the stripped raw string when it doesn't parse, so a bad
    value still compares equal to itself rather than collapsing every
    unparseable value onto one key.
    """
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return ip.strip()


# RFC 8415 §11.1: a DUID is a 2-octet type code plus at most 128 octets.
_DUID_MIN_OCTETS = 3
_DUID_MAX_OCTETS = 130


def norm_duid(duid: str) -> str:
    """Fold a DUID to bare lowercase hex (#1141) — the comparison form, so
    ``00:01:00:01:…`` and ``000100…`` and ``00-01-00-01-…`` are one client."""
    return "".join(c for c in duid.lower() if c in "0123456789abcdef")


def canonical_duid(duid: str) -> str:
    """A DUID in the colon-separated lowercase hex form Kea reports and
    ``dhcp_lease.duid`` stores. Raises ``ValueError`` for anything that is
    not a whole number of octets within RFC 8415's bounds, or that carries
    characters other than hex digits and ``:`` / ``-`` / ``.`` separators —
    a lease identity is keyed on this, so it is refused rather than guessed.
    """
    text = duid.strip().lower()
    if not text or any(c not in "0123456789abcdef:-." for c in text):
        raise ValueError("DUID must be hex octets")
    hexdigits = norm_duid(text)
    if len(hexdigits) % 2:
        raise ValueError("DUID must be a whole number of octets")
    octets = len(hexdigits) // 2
    if not _DUID_MIN_OCTETS <= octets <= _DUID_MAX_OCTETS:
        raise ValueError(f"DUID must be {_DUID_MIN_OCTETS}-{_DUID_MAX_OCTETS} octets")
    return ":".join(hexdigits[i : i + 2] for i in range(0, len(hexdigits), 2))
