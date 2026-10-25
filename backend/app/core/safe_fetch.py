"""Guarded HTTP(S) GET for operator-configured feed URLs.

The control plane pulls a few documents from URLs an operator typed in — DNS
blocklist feeds, WoL iCal calendars. Each of those is a server-side request,
so each one goes through the same three checks here instead of carrying its
own copy of them:

1. **Scheme.** Only ``http`` and ``https``. Anything else (``file``, ``ftp``,
   ``gopher``, …) is refused before a client is built.
2. **Target, before the request.** The host is resolved and checked by
   :func:`app.core.ssrf.assert_safe_target` with ``block=True`` — loopback,
   link-local (which covers the cloud-metadata address) and the unspecified
   address are refused. RFC 1918 / unique-local are deliberately allowed: an
   internal feed mirror on ``10.x`` is a normal deployment, and the shared
   guard draws the same line for every other integration.
3. **Target, at connect time.** A check that resolves the name and then lets
   the HTTP client resolve it again can be answered differently the second
   time. So the transport here does its own resolution, refuses the request
   if ANY answer is in a blocked range, and connects to the checked IP
   literal — the address that passed the check is the address dialled. TLS
   still verifies against (and sends SNI for) the hostname in the URL.

Redirects are followed by hand, at most ``max_redirects`` hops, and each hop
goes through checks 1–3 again: an origin-only check is undone by a 302 to an
internal address.

A refusal raises :class:`FetchRefusedError`, a ``ValueError`` with a fixed,
host-free message — callers store it where readers can see it, and a message
naming the resolved address would turn the error column into a way to map
the internal network. The detail is logged server-side by the ssrf guard.

A failed request (status, timeout, connect) raises :class:`FetchFailedError`
— still an ``httpx.HTTPError``, so a caller's ``autoretry_for`` keeps working —
whose message is the HTTP status or the kind of failure and nothing else.
httpx's own exceptions spell out the full request URL, credentials included,
and they travel further than the caller's ``except``: Celery writes the
exception into its retry and failure log lines and into the result backend.

A feed URL can carry credentials (``https://user:pass@host/…``,
``?token=…``). :func:`mask_url_credentials` is the one place that hides them
for display; the URL as stored is used only to make the request.

Environment proxy variables are not consulted (a custom transport disables
them in httpx); the request goes direct.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable, Iterable
from typing import Any
from urllib.parse import unquote_plus, urlsplit, urlunsplit

import anyio
import httpcore
import httpx
import structlog

from app.core.ssrf import SSRFBlockedError, assert_safe_target, classify_address

logger = structlog.get_logger(__name__)

ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_MAX_REDIRECTS = 5

TARGET_REFUSED_MESSAGE = "feed URL target is not permitted"
SCHEME_REFUSED_MESSAGE = "feed URL must use http or https"
REDIRECT_LIMIT_MESSAGE = "feed URL exceeded the redirect limit"

Resolver = Callable[[str, int], Awaitable[list[str]]]

# Shown in place of a credential in a feed URL. URL-safe in both the userinfo
# and a query value, so a masked URL still parses as a URL.
CREDENTIAL_MASK = "***"

# Query parameter names whose value is treated as a credential. Broad on
# purpose: masking a harmless value costs a retype on edit, while missing a
# real one shows it to every reader of the list.
_CREDENTIAL_PARAM_RE = re.compile(
    r"(token|secret|passw|apikey|api[_-]?key|credential|auth|sig|session"
    r"|(^|[_.-])(key|pass|pwd|pw|code|hash)$)",
    re.IGNORECASE,
)


class FetchRefusedError(ValueError):
    """A guarded fetch was refused before (or instead of) being dialled.

    The message is one of the fixed strings above — never a host or IP.
    Permanent: retrying the same URL gives the same answer.
    """


class FetchFailedError(httpx.HTTPError):
    """A guarded fetch reached the network and failed.

    ``description`` is the HTTP status (``"HTTP 404"``) or the kind of
    failure (``"timed out"``, ``"could not connect"``) — never the URL, a
    resolved address or a response body. Transient: the caller may retry.
    """

    def __init__(self, message: str, *, description: str = "", status_code: int | None = None):
        super().__init__(message)
        self.description = description or message
        self.status_code = status_code


def describe_fetch_error(exc: BaseException) -> str:
    """A reader-safe description of a failed fetch: the HTTP status, or the
    kind of failure — never the exception text."""

    if isinstance(exc, FetchFailedError):
        return exc.description
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code}"
    if isinstance(exc, httpx.TimeoutException):
        return "timed out"
    if isinstance(exc, (httpx.ConnectError, socket.gaierror)):
        return "could not connect"
    return "transport error"


def _is_credential_param(name: str) -> bool:
    return bool(_CREDENTIAL_PARAM_RE.search(name))


def mask_url_credentials(url: str) -> str:
    """``url`` with its credentials replaced by :data:`CREDENTIAL_MASK`.

    Masks the userinfo password (or a lone username, which is how a token is
    usually carried there) and the value of every query parameter whose name
    looks like a credential. Everything else is kept exactly as written, so
    a reader can still tell which feed it is. A URL that does not parse is
    masked whole.
    """

    if not url:
        return url
    try:
        parts = urlsplit(url)
        _ = parts.port  # raises on a malformed port, like the fetch would
    except ValueError:
        return CREDENTIAL_MASK
    netloc = parts.netloc
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)
        if ":" in userinfo:
            user = userinfo.split(":", 1)[0]
            netloc = f"{user}:{CREDENTIAL_MASK}@{hostport}"
        else:
            netloc = f"{CREDENTIAL_MASK}@{hostport}"
    query = parts.query
    if query:
        pieces = []
        for piece in query.split("&"):
            name, sep, value = piece.partition("=")
            if sep and value and _is_credential_param(unquote_plus(name)):
                piece = f"{name}={CREDENTIAL_MASK}"
            pieces.append(piece)
        query = "&".join(pieces)
    if netloc == parts.netloc and query == parts.query:
        return url
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))


def has_masked_credentials(url: str) -> bool:
    """True when ``url`` carries :data:`CREDENTIAL_MASK` where
    :func:`mask_url_credentials` would put it — i.e. it is (an edit of) a
    masked URL, not one with real credentials in it."""

    if not url:
        return False
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return False
    if "@" in parts.netloc:
        userinfo = parts.netloc.rsplit("@", 1)[0]
        if CREDENTIAL_MASK in userinfo.split(":"):
            return True
    for piece in parts.query.split("&") if parts.query else ():
        name, sep, value = piece.partition("=")
        if sep and value == CREDENTIAL_MASK and _is_credential_param(unquote_plus(name)):
            return True
    return False


def check_feed_url_shape(url: str) -> str:
    """Return ``url`` stripped, or raise ``ValueError`` unless it is an
    ``http(s)://host…`` URL. Shape only — no DNS. For API-side validation."""

    text = (url or "").strip()
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        raise ValueError(SCHEME_REFUSED_MESSAGE) from None
    if parts.scheme.lower() not in ALLOWED_SCHEMES or not host:
        raise ValueError(SCHEME_REFUSED_MESSAGE)
    return text


def guard_url(url: str, *, label: str) -> None:
    """Checks 1 and 2: scheme, then the pre-request address check.

    Raises :class:`FetchRefusedError` with a generic message.
    """

    try:
        check_feed_url_shape(url)
    except ValueError:
        raise FetchRefusedError(SCHEME_REFUSED_MESSAGE) from None
    try:
        assert_safe_target(url, label=label, block=True)
    except SSRFBlockedError as exc:
        logger.warning("safe_fetch_target_refused", label=label, detail=str(exc))
        raise FetchRefusedError(TARGET_REFUSED_MESSAGE) from None


async def _default_resolver(host: str, port: int) -> list[str]:
    infos = await anyio.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    out: list[str] = []
    for info in infos:
        addr = info[4][0]
        if isinstance(addr, str) and addr not in out:
            out.append(addr)
    return out


class GuardedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Check 3: resolve once, refuse a blocked answer, dial the checked IP."""

    def __init__(
        self,
        *,
        label: str,
        inner: httpcore.AsyncNetworkBackend | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        self._label = label
        self._inner = inner if inner is not None else httpcore.AnyIOBackend()
        self._resolve = resolver if resolver is not None else _default_resolver

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        try:
            literal = ipaddress.ip_address(host.strip("[]"))
            addresses = [str(literal)]
        except ValueError:
            try:
                with anyio.fail_after(timeout):
                    addresses = await self._resolve(host, port)
            except TimeoutError as exc:
                raise httpcore.ConnectTimeout("name resolution timed out") from exc
            except OSError as exc:
                raise httpcore.ConnectError("name resolution failed") from exc
        if not addresses:
            raise httpcore.ConnectError("name did not resolve")

        for addr in addresses:
            reason = classify_address(addr)
            if reason is not None:
                # One blocked answer refuses the whole name: a resolver that
                # returns [public, metadata] must not get a coin flip.
                logger.warning(
                    "safe_fetch_connect_refused",
                    label=self._label,
                    host=host,
                    resolved=addresses,
                    reason=reason,
                )
                raise SSRFBlockedError(f"{self._label}: connect target refused ({reason})")

        last_exc: Exception | None = None
        for addr in addresses:
            try:
                return await self._inner.connect_tcp(
                    addr,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_exc = exc
        if last_exc is None:  # pragma: no cover — addresses is non-empty
            raise httpcore.ConnectError("no address to connect to")
        raise last_exc

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise SSRFBlockedError(f"{self._label}: unix sockets are not a feed target")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class GuardedTransport(httpx.AsyncHTTPTransport):
    """``httpx.AsyncHTTPTransport`` whose connections go through
    :class:`GuardedNetworkBackend`."""

    def __init__(
        self,
        *,
        label: str,
        inner_backend: httpcore.AsyncNetworkBackend | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        super().__init__()
        # AsyncHTTPTransport does not take a network backend, so swap the
        # pool it built for one that uses ours. Same defaults otherwise.
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(),
            network_backend=GuardedNetworkBackend(
                label=label, inner=inner_backend, resolver=resolver
            ),
        )


async def safe_get_text(
    url: str,
    *,
    label: str,
    timeout: float = 60.0,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    transport: httpx.AsyncBaseTransport | None = None,
) -> str:
    """GET ``url`` through all three checks and return the body text.

    Raises :class:`FetchRefusedError` (permanent, generic message) when a
    check refuses the URL or a redirect hop, or the hop limit is exceeded;
    :class:`FetchFailedError` (an ``httpx.HTTPError`` whose message names
    only the status or the kind of failure) on a transport or status
    failure — transient, the caller may retry.
    """

    current = url.strip()
    guard_url(current, label=label)

    client = httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        transport=transport if transport is not None else GuardedTransport(label=label),
    )
    try:
        async with client:
            for _hop in range(max_redirects + 1):
                resp = await client.get(current)
                if resp.is_redirect:
                    location = resp.headers.get("location")
                    if not location:
                        # A 3xx with nowhere to go: report it as the status
                        # failure it is.
                        resp.raise_for_status()
                    current = str(resp.url.join(location))
                    guard_url(current, label=label)
                    continue
                resp.raise_for_status()
                return resp.text
    except SSRFBlockedError as exc:
        # Raised by the connect-time check inside the transport.
        logger.warning("safe_fetch_target_refused", label=label, detail=str(exc))
        raise FetchRefusedError(TARGET_REFUSED_MESSAGE) from None
    except httpx.HTTPError as exc:
        # httpx's message names the request URL with its credentials (and a
        # redirect hop's URL, which the operator never typed). Replace it,
        # unchained, so neither the message nor a traceback carries it.
        description = describe_fetch_error(exc)
        status_code = exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None
        raise FetchFailedError(
            f"feed fetch failed: {description}",
            description=description,
            status_code=status_code,
        ) from None
    raise FetchRefusedError(REDIRECT_LIMIT_MESSAGE)


__all__ = [
    "ALLOWED_SCHEMES",
    "CREDENTIAL_MASK",
    "FetchFailedError",
    "FetchRefusedError",
    "GuardedNetworkBackend",
    "GuardedTransport",
    "REDIRECT_LIMIT_MESSAGE",
    "SCHEME_REFUSED_MESSAGE",
    "TARGET_REFUSED_MESSAGE",
    "check_feed_url_shape",
    "describe_fetch_error",
    "guard_url",
    "has_masked_credentials",
    "mask_url_credentials",
    "safe_get_text",
]
