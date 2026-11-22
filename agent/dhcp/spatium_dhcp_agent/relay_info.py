"""Relay agent information (DHCP option 82) from a Kea lease (#54).

With ``store-extended-info`` on (rendered for any group with an option-82
class), Kea keeps the option-82 payload the relay sent in the lease's user
context::

    {"ISC": {"relay-agent-info": {"sub-options": "0x010A65…", "remote-id": "…"}}}

``sub-options`` is the whole option-82 body (circuit-id, remote-id and every
other sub-option, TLV-encoded), so it is the one value the agent ships, as
``relay_agent_info``: uppercase hex, no ``0x``. The control plane splits it
into sub-options itself, so the agent never has to agree with it on how.

The lease file (``kea-leases4.csv``) holds the same JSON in its
``user_context`` column with Kea's CSV escaping applied: a comma is written
``&#x2c`` (``CSVFile::escapeCharacters`` in Kea's ``csv_file.cc`` writes
``&#x`` plus two hex digits). The ``lease4-get-page`` answer carries it as
real JSON under ``user-context``. Measured on kea-dhcp4 3.0.3; the
fixtures under ``tests/fixtures/kea303_relay_*`` are those captures.

Anything unexpected yields None: the lease event is always sent, with or
without the field — a lease must never be dropped over option 82.
"""

from __future__ import annotations

import json
import re
from typing import Any

# An option-82 body is at most 255 bytes.
_MAX_HEX = 510
_HEX_RE = re.compile(r"^[0-9A-F]+$")
_CSV_ESCAPE_RE = re.compile(r"&#x([0-9A-Fa-f]{2})")


def unescape_kea_csv(text: str) -> str:
    """Undo Kea's memfile CSV escaping (``&#xHH`` → the character)."""
    if "&#x" not in text:
        return text
    return _CSV_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)


def _normalise_hex(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip()
    if v[:2] in ("0x", "0X"):
        v = v[2:]
    v = v.upper()
    if not v or len(v) % 2 or len(v) > _MAX_HEX or not _HEX_RE.match(v):
        return None
    return v


def relay_agent_info_from_user_context(user_context: Any) -> str | None:
    """The option-82 payload in a lease user context, as hex, or None.

    Accepts the decoded dict (``lease4-get-page``) or the raw CSV column text
    (``kea-leases4.csv``, still escaped).
    """
    if isinstance(user_context, str):
        text = user_context.strip()
        if not text:
            return None
        try:
            user_context = json.loads(unescape_kea_csv(text))
        except ValueError:
            return None
    if not isinstance(user_context, dict):
        return None
    isc = user_context.get("ISC")
    rai = isc.get("relay-agent-info") if isinstance(isc, dict) else None
    if isinstance(rai, str):
        # Older Kea releases stored the payload itself here, not a map.
        return _normalise_hex(rai)
    if not isinstance(rai, dict):
        return None
    return _normalise_hex(rai.get("sub-options"))


__all__ = ["relay_agent_info_from_user_context", "unescape_kea_csv"]
