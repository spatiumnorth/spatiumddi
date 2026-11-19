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


# A URL anywhere in the text: an optional opening wrapper, the scheme, then
# EVERYTHING up to the next whitespace. Quotes, brackets, ``@``, ``/`` and
# ``#`` are all legal inside userinfo, paths and query values, so no
# character other than whitespace may end the match: stopping at one would
# leave the rest of a secret behind in the message (fail closed).
_URL_RE = re.compile(r"(?P<open>[(\[<'\"])?(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)(?P<rest>\S*)")
_CLOSERS = {"(": ")", "[": "]", "<": ">", "'": "'", '"': '"'}
_AUTHORITY_RE = re.compile(r"(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._~-]+)(:\d+)?")
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _reduce_url(match: re.Match[str]) -> str:
    scheme = match["scheme"]
    rest = match["rest"]
    opener = match["open"]
    # The authority ends at the first / ? # ; userinfo ends at the LAST @
    # inside it. Anything that is then not a plain host[:port] is redacted
    # whole rather than half-quoted.
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0].rsplit("@", 1)[-1]
    ok = _AUTHORITY_RE.fullmatch(authority)
    out = scheme + (authority if ok else "[redacted]")
    # Keep a wrapping closer only when it pairs with the opener right
    # before the URL; it is re-added from our own table, never copied
    # from the URL's text.
    if opener and rest.endswith(_CLOSERS[opener]):
        out += _CLOSERS[opener]
    return (opener or "") + out


def _redact(text: str) -> str:
    """Reduce every URL in ``text`` to ``scheme://host[:port]``.

    A v1 InfluxDB write carries its password as ``?p=``, other
    integrations pass tokens in the query or the userinfo, and a webhook
    URL (Slack, Teams, Discord) carries its secret in the PATH, so a
    message built from an exception that echoes a URL keeps none of them.
    A URL is consumed up to the next whitespace; if its authority is not
    a plain host it becomes ``scheme://[redacted]``.
    """
    return _URL_RE.sub(_reduce_url, text)


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
    quoted from the request; the URL's userinfo, path and query (where a
    token, a webhook secret or a v1 password may sit) are not, and neither
    is a header h11 refused. Anything that is not an httpx request error
    falls back to ``describe_exc``, with every URL in its text reduced to
    ``scheme://host[:port]``.
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
    if isinstance(exc, httpx.LocalProtocolError):
        # h11 quotes the offending header verbatim ("Illegal header value
        # b'Token <secret>\n'"), and the header is usually the credential.
        where = f" to {target}" if target else ""
        return (
            f"Request{where} could not be sent: a header holds a character "
            "HTTP does not allow (check the token or custom headers for a "
            "stray newline)"
        )
    if target and isinstance(exc, httpx.ConnectError):
        cause = _redact(str(exc).strip())
        return f"Could not connect to {target}" + (f": {cause}" if cause else "")
    if target and isinstance(exc, httpx.RequestError):
        return f"Request to {target} failed: {_redact(describe_exc(exc))}"
    if isinstance(exc, httpx.InvalidURL):
        return f"Invalid URL: {_redact(describe_exc(exc))}"
    return _redact(describe_exc(exc))
