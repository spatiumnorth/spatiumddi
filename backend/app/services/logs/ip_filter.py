"""Free-text IP / MAC filters over the log tables (#3171).

The log tables keep ``client_ip`` / ``ip_address`` as ``inet`` and
``mac_address`` as ``macaddr``. Comparing either to a half-typed value
(``127``, ``192.168.0.``, ``08:00``) is a Postgres data error, so a filter box
that sends a request per keystroke answered a generic 422 until the operator
had typed a whole address. These helpers accept what an operator really types:

* a whole address -> exact match (compared as ``inet`` / ``macaddr``, so an
  index on the column can serve it);
* a CIDR (IP only) -> containment, ``col <<= cidr``;
* a partial address -> prefix match on the column's text form. This is
  "starts with" as typed, so ``10.1`` also matches ``10.10.x`` and
  ``10.100.x``; typing ``10.1.`` narrows it. It cannot use an index, so it
  relies on the callers' time window and row limit to stay bounded.

Anything that cannot be part of an address raises :class:`InvalidLogFilter`,
whose message names the field, so the caller answers a clear 422.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from sqlalchemy import String, cast, func
from sqlalchemy.dialects.postgresql import INET

from app.services.search.ranking import escape_like

_V4_PARTIAL = re.compile(r"^[0-9.]+$")
_V6_PARTIAL = re.compile(r"^[0-9a-fA-F:.]+$")
_HEX = re.compile(r"^[0-9a-fA-F]+$")


class InvalidLogFilter(ValueError):
    """A filter value that cannot be an address, a CIDR or an address prefix."""

    def __init__(self, field: str, expected: str) -> None:
        self.field = field
        self.detail = f"{field}: not {expected}"
        super().__init__(self.detail)


def ip_filter_clause(column: Any, value: str, *, field: str = "client_ip") -> Any:
    """SQL clause matching ``column`` (an ``inet``) against what was typed."""
    text = value.strip()
    expected = "an IP address, CIDR or address prefix"
    if text.endswith("/"):
        # ``10.0.0.0/`` is a CIDR half-typed; match the address part until
        # the prefix length arrives rather than refusing a keystroke.
        text = text[:-1].rstrip()
    if not text or "%" in text:
        # ``%`` is only legal in an IPv6 zone id (``fe80::1%eth0``), which
        # Python accepts and Postgres ``inet`` does not, so it would reach
        # the generic data-error 422 instead of this one.
        raise InvalidLogFilter(field, expected)
    if "/" in text:
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise InvalidLogFilter(field, expected) from exc
        return column.op("<<=")(cast(str(net), INET))
    try:
        return column == str(ipaddress.ip_address(text))
    except ValueError:
        pass
    if _V4_PARTIAL.match(text) or (":" in text and _V6_PARTIAL.match(text)):
        # host() drops the /len that text(inet) can append; lower-case both
        # sides so ``FD00:`` finds ``fd00::1``.
        return func.lower(func.host(column)).like(escape_like(text.lower()) + "%", escape="\\")
    if _HEX.match(text) and len(text) <= 4:
        # A bare ``fd`` / ``2001`` is the start of an IPv6 address.
        return func.lower(func.host(column)).like(escape_like(text.lower()) + "%", escape="\\")
    raise InvalidLogFilter(field, expected)


def mac_filter_clause(column: Any, value: str, *, field: str = "mac_address") -> Any:
    """SQL clause matching ``column`` (a ``macaddr``) against what was typed.

    Separators (``:``, ``-``, ``.``, spaces) are ignored, so ``AA-BB-CC``,
    ``aabb.cc`` and ``aabbcc`` all mean the same prefix.
    """
    expected = "a MAC address or MAC prefix"
    digits = re.sub(r"[:\-.\s]", "", value.strip())
    if not digits or len(digits) > 12 or not _HEX.match(digits):
        raise InvalidLogFilter(field, expected)
    digits = digits.lower()
    if len(digits) == 12:
        full = ":".join(digits[i : i + 2] for i in range(0, 12, 2))
        return column == full
    prefix = ":".join(digits[i : i + 2] for i in range(0, len(digits), 2))
    return cast(column, String).like(escape_like(prefix) + "%", escape="\\")
