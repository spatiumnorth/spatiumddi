"""Checks for operator text that is written into a host config file.

Several appliance host configs (``snmpd.conf``, ``chrony.conf``, apt's
``sources.list``, the nftables drop-in) are line-oriented: a directive ends
at the newline. A setting rendered into one of those files must therefore
never carry a newline, a carriage return or any other control character, or
the text after it is read as a directive of its own.

Two layers use these helpers:

* the API boundary rejects such a value with a 422 naming the field, so the
  operator's own request is where the problem shows up; and
* each renderer checks again before writing, because rows stored before the
  API check existed (or written by another path, such as a restore) are
  still in the database.
"""

from __future__ import annotations


def has_control_chars(value: str) -> bool:
    """True when ``value`` holds a C0 control character (newline, carriage
    return, NUL, tab, ...) or DEL."""
    return any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)


def reject_control_chars(value: str, field: str) -> str:
    """Return ``value`` unchanged, or raise ``ValueError`` naming ``field``
    when it holds a control character."""
    if has_control_chars(value):
        raise ValueError(
            f"{field} must not contain control characters "
            "(newline, carriage return, NUL, tab or other non-printing characters)"
        )
    return value


__all__ = ["has_control_chars", "reject_control_chars"]
