"""Refusals that carry a second, shorter text for a portal requester.

The approver and the audit row keep the full reason (``str(exc)`` / the HTTP
detail). The request portal's requester reads the failed request too, and may
hold no read on the other objects the full reason names (another DHCP scope,
a template, a record), so the approval spine stores ``requester_text`` on the
request instead when an exception carries one.
"""

from __future__ import annotations

from fastapi import HTTPException


class ValueRefusal(ValueError):
    def __init__(self, message: str, *, requester_text: str) -> None:
        super().__init__(message)
        self.requester_text = requester_text


class HTTPRefusal(HTTPException):
    def __init__(self, status_code: int, detail: str, *, requester_text: str) -> None:
        super().__init__(status_code=status_code, detail=detail)
        self.requester_text = requester_text
