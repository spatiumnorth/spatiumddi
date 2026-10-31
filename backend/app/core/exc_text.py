"""Operator-readable text for an exception whose ``str()`` may be empty.

Lives in ``app.core`` because backup destinations, the DNS / NetBox
importers and the integration test-connection routes all need it, and
``app.core`` has an empty ``__init__``: importing it from an importer must
not drag in the backup package (#3096).
"""

from __future__ import annotations


def describe_exc(exc: BaseException) -> str:
    """A non-empty, operator-readable reason for ``exc``.

    Many library exceptions carry no text at all — ``httpx.ReadTimeout``,
    ``httpx.ConnectTimeout``, ``asyncio.TimeoutError``, a bare
    ``TimeoutError`` — so ``f"...: {exc}"`` ended at the colon and told the
    operator nothing (#2402, #3096). Falls back to the exception's type, and
    says plainly when it was a timeout.

    Adds no text of its own beyond the type name, so it is exactly as safe
    as ``str(exc)``: a caller whose exception can echo a credentialed URL
    still runs ``scrub_url`` over the result.
    """
    text = str(exc).strip()
    if text:
        return text
    name = type(exc).__name__
    if isinstance(exc, TimeoutError) or "timeout" in name.lower():
        return f"{name} (the destination timed out)"
    return name
