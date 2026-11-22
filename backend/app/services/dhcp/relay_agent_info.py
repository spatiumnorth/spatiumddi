"""Relay agent information (DHCP option 82) on a lease (#54).

The DHCP agent ships the option-82 body Kea stored for a lease (Kea's
``ISC.relay-agent-info.sub-options``) as ``relay_agent_info``: uppercase hex,
no ``0x``. This module is the one place that decodes it.

Everything is kept as hex. A circuit-id is bytes, often binary (a Cisco
switch sends ``00 04 <vlan> <module> <port>``), and decoding bytes to text
lossily is the ``U+FFFD`` mistake ``device_policy.text_to_hex`` documents. A
printable rendering is derived at read time, and only when every byte is
printable ASCII.

The body is a run of sub-options, each ``code (1 byte), length (1 byte),
value`` (RFC 3046 §2.0). Sub-option 1 is the circuit-id, 2 the remote-id.
"""

from __future__ import annotations

import re
from typing import Any

CIRCUIT_ID = 1
REMOTE_ID = 2

# An option-82 body is at most 255 bytes.
MAX_HEX = 510
_HEX_RE = re.compile(r"^[0-9A-F]+$")
# Separators an operator may paste a hex value with (``01:0a``, ``01-0a``).
_SEPARATORS_RE = re.compile(r"[\s:.\-]")


def normalize_relay_hex(value: Any) -> str | None:
    """Uppercase hex without ``0x``, or None if ``value`` is not an
    option-82 body (non-empty, even length, at most 255 bytes)."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if v[:2] in ("0x", "0X"):
        v = v[2:]
    v = v.upper()
    if not v or len(v) % 2 or len(v) > MAX_HEX or not _HEX_RE.match(v):
        return None
    return v


def parse_sub_options(raw_hex: str | None) -> list[tuple[int, str]] | None:
    """``[(code, value_hex), …]`` in wire order, or None when malformed.

    A length running past the end of the body, or a lone trailing byte, makes
    the whole body malformed: the sub-options before it parsed, but a body
    that does not end on a boundary is not one to draw conclusions from.
    Zero-length sub-options and repeated codes are kept as sent.
    """
    if not raw_hex:
        return None
    try:
        data = bytes.fromhex(raw_hex)
    except ValueError:
        return None
    out: list[tuple[int, str]] = []
    i = 0
    while i < len(data):
        if i + 2 > len(data):
            return None
        code, length = data[i], data[i + 1]
        end = i + 2 + length
        if end > len(data):
            return None
        out.append((code, data[i + 2 : end].hex().upper()))
        i = end
    return out


def circuit_and_remote(raw_hex: str | None) -> tuple[str | None, str | None]:
    """The circuit-id and remote-id of a body, as hex.

    The first occurrence of each code wins; RFC 3046 does not allow a code
    to repeat, so a body that repeats one is taken as the relay sent it. An
    empty value is None: there is nothing to search or show. A malformed
    body gives ``(None, None)``; its raw hex is still stored.
    """
    subs = parse_sub_options(raw_hex)
    if subs is None:
        return None, None
    found: dict[int, str] = {}
    for code, value in subs:
        found.setdefault(code, value)
    return found.get(CIRCUIT_ID) or None, found.get(REMOTE_ID) or None


def printable_text(value_hex: str | None) -> str | None:
    """``value_hex`` as text when every byte is printable ASCII, else None."""
    if not value_hex:
        return None
    try:
        data = bytes.fromhex(value_hex)
    except ValueError:
        return None
    if all(0x20 <= b <= 0x7E for b in data):
        return data.decode("ascii")
    return None


def decode_sub_options(raw_hex: str | None) -> list[dict[str, Any]]:
    """Every sub-option for display: ``[{code, hex, text}]``, empty when the
    body is absent or malformed."""
    return [
        {"code": code, "hex": value, "text": printable_text(value)}
        for code, value in (parse_sub_options(raw_hex) or [])
    ]


def relay_hex_filter(value: str) -> tuple[str, bool] | None:
    """Parse a hex filter value: ``(hex, is_prefix)``, or None if invalid.

    A trailing ``*`` makes it a prefix match. Separators and ``0x`` are
    dropped. An exact value must be whole bytes; a prefix may end mid-byte.
    """
    v = value.strip()
    prefix = v.endswith("*")
    if prefix:
        v = v[:-1]
    v = _SEPARATORS_RE.sub("", v)
    if v[:2] in ("0x", "0X"):
        v = v[2:]
    v = v.upper()
    if not v or len(v) > MAX_HEX or not _HEX_RE.match(v):
        return None
    if not prefix and len(v) % 2:
        return None
    return v, prefix


def relay_id_clause(column: Any, value: str) -> Any | None:
    """A WHERE clause matching ``column`` (a hex circuit-id / remote-id
    column) against a ``relay_hex_filter`` value, or None if it is invalid.

    Stored values are uppercase with no separators, and hex has no LIKE
    wildcard in it, so a plain prefix LIKE and an equality are both exact.
    """
    parsed = relay_hex_filter(value)
    if parsed is None:
        return None
    hex_value, prefix = parsed
    return column.like(f"{hex_value}%") if prefix else column == hex_value


def text_to_relay_hex(text: str) -> str:
    """Hex of a text value's UTF-8 bytes, to search for a typed circuit-id."""
    return text.encode("utf-8").hex().upper()


__all__ = [
    "CIRCUIT_ID",
    "REMOTE_ID",
    "circuit_and_remote",
    "decode_sub_options",
    "normalize_relay_hex",
    "parse_sub_options",
    "printable_text",
    "relay_hex_filter",
    "relay_id_clause",
    "text_to_relay_hex",
]
