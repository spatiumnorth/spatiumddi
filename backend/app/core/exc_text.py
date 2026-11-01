"""Operator-readable text for an exception whose ``str()`` may be empty.

Lives in ``app.core`` because backup destinations, the DNS / NetBox
importers and the integration test-connection routes all need it, and
``app.core`` has an empty ``__init__``: importing it from an importer must
not drag in the backup package (#3096).
"""

from __future__ import annotations

import re

import httpx


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


_QUERY_RE = re.compile(r"(://[^\s?#'\"]+)[?#][^\s'\"]*")
_USERINFO_RE = re.compile(r"(://)[^/@\s'\"]*@")
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _redact(text: str) -> str:
    """Drop URL userinfo and query strings from ``text``.

    A v1 InfluxDB write carries its password as ``?p=`` and other
    integrations pass tokens the same way, so a message built from an
    exception that echoes the request URL must not keep either.
    """
    return _USERINFO_RE.sub(r"\1", _QUERY_RE.sub(r"\1", text))


def _target(exc: BaseException) -> str | None:
    """``host:port`` of the request an httpx error belongs to, or None.

    Scheme, host and port only: never userinfo, path or query.
    """
    if not isinstance(exc, httpx.RequestError | httpx.HTTPStatusError):
        return None
    try:
        url = exc.request.url
    except RuntimeError:  # httpx raises when the error carries no request
        return None
    host = url.host
    if not host:
        return None
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    port = url.port or _DEFAULT_PORTS.get(url.scheme)
    return f"{host}:{port}" if port else host


def describe_http_exc(exc: BaseException, *, timeout: float | None = None) -> str:
    """Operator-readable reason for a failed httpx call (#3236).

    ``describe_exc`` alone gives ``ConnectTimeout (the destination timed
    out)`` — true, but it names neither the destination nor the limit.
    This says which address did not answer and, when the caller passes the
    ``timeout`` it configured, within how long. Only ``host:port`` is ever
    quoted from the request; the URL's userinfo and query (where a token
    or a v1 password may sit) are not. Anything that is not an httpx
    request error falls back to ``describe_exc``, with URLs in its text
    redacted the same way.
    """
    target = _target(exc)
    after = f" after {timeout:g}s" if timeout else ""
    if target and isinstance(exc, httpx.TimeoutException):
        if isinstance(exc, httpx.ConnectTimeout):
            return f"Connection to {target} timed out{after}"
        if isinstance(exc, httpx.ReadTimeout):
            return f"{target} accepted the connection but sent no response{after}"
        return f"Request to {target} timed out{after}"
    if target and isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code} from {target}"
    if target and isinstance(exc, httpx.ConnectError):
        cause = _redact(str(exc).strip())
        return f"Could not connect to {target}" + (f": {cause}" if cause else "")
    if target and isinstance(exc, httpx.RequestError):
        return f"Request to {target} failed: {_redact(describe_exc(exc))}"
    if isinstance(exc, httpx.InvalidURL):
        return f"Invalid URL: {_redact(describe_exc(exc))}"
    return _redact(describe_exc(exc))
