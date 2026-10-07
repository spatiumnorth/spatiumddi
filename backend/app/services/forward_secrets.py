"""Write-only, encrypted-at-rest secrets on a forwarding target (#1502).

An incoming-webhook URL for Slack, Discord or Teams *is* the credential:
whoever has it can post into the channel. A generic webhook's
``Authorization`` header is a bearer token for the collector. Both are
therefore stored Fernet-encrypted (``*_encrypted`` columns), accepted by
the API but never returned, and kept out of log lines and error details.

The helpers here are deliberately small and column-agnostic, so any other
secret on a forwarding target can use the same contract:

* :func:`apply_write_only` is the API's three-way write: ``None`` keeps the
  stored value, ``""`` clears it, anything else is encrypted and replaces it
  (the ``smtp_password`` contract).
* :func:`reveal` decrypts for the send path only.
* :func:`url_display` is the non-secret label the API returns instead of
  the URL: scheme and host, never the path, query or userinfo.
* :func:`redact` strips a secret from text that is about to be logged or
  returned, such as an exception message.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlsplit

import httpx
import structlog

from app.core.crypto import decrypt_str, encrypt_str

logger = structlog.get_logger(__name__)

REDACTED = "[redacted]"


def apply_write_only(current: bytes | None, incoming: str | None) -> bytes | None:
    """The stored ciphertext after a write of ``incoming``.

    ``None`` means the field was not sent: keep what is stored. ``""``
    clears it. Anything else is encrypted.
    """
    if incoming is None:
        return current
    if incoming == "":
        return None
    return encrypt_str(incoming)


def reveal(token: bytes | None, *, field: str, target: str | None = None) -> str:
    """The secret in clear, or ``""`` when there is none or it won't decrypt.

    A value that does not decrypt (the install's key changed without a
    rewrap) is logged by name only and treated as unset, so the target is
    skipped rather than posting somewhere it shouldn't.
    """
    if not token:
        return ""
    try:
        return decrypt_str(bytes(token))
    except ValueError:
        logger.warning("forward_secret_undecryptable", field=field, target=target)
        return ""


def url_display(url: str) -> str:
    """``https://hooks.slack.com/…``: enough to tell targets apart.

    Only the scheme, host and an explicit port survive. The path and query
    are where incoming-webhook credentials live, and userinfo is a password,
    so all three are replaced by an ellipsis.
    """
    if not url:
        return ""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return "…"
    if not parts.scheme or not host:
        return "…"
    if ":" in host:
        host = f"[{host}]"
    shown = f"{parts.scheme}://{host}"
    if port is not None:
        shown += f":{port}"
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username:
        shown += "/…"
    return shown


def redact(text: str, *secrets: str) -> str:
    """``text`` with every non-empty secret in it replaced by ``[redacted]``.

    For a URL, the path and query are redacted on their own as well, since a
    library may render the URL differently (normalised, re-quoted) from the
    string that was stored. A collector that echoes only part of a secret
    must not leak the rest (GHSA-5qf8-pqm4-58mj), so this also redacts:

    * the bare credential of a header value — the part after its scheme
      word (``Bearer <token>`` → ``<token>`` on its own);
    * each URL path segment and each query key/value longer than a few
      characters, raw and percent-decoded; and
    * every needle above in its JSON-escaped (``\\/``) and percent-encoded
      forms, which defeat an exact match the same way a truncation does.

    Callers must redact *before* truncating: a secret straddling a cut is
    no longer an exact match, so its leading part would survive.
    """
    base: list[str] = []
    for secret in secrets:
        if not secret:
            continue
        base.append(secret)
        # Bare token: a header such as "Bearer <token>" echoed without its
        # scheme word. Only a two-part value — a URL has no space, and a
        # one-word secret is already a needle above.
        split = secret.split(None, 1)
        if len(split) == 2 and split[1].strip():
            base.append(split[1].strip())
        try:
            parts = urlsplit(secret)
        except ValueError:
            continue
        if parts.scheme and parts.netloc:
            if len(parts.path) > 1:
                base.append(parts.path)
                for segment in parts.path.split("/"):
                    if len(segment) >= 4:
                        base.append(segment)
                        decoded_seg = unquote(segment)
                        if decoded_seg != segment and len(decoded_seg) >= 4:
                            base.append(decoded_seg)
            if parts.query:
                base.append(parts.query)
                # Raw pieces keep percent-encoded values; parse_qsl gives
                # the decoded forms. Both can be echoed back.
                for pair in parts.query.split("&"):
                    for piece in pair.split("=", 1):
                        if len(piece) >= 4:
                            base.append(piece)
                for key, value in parse_qsl(parts.query, keep_blank_values=True):
                    for piece in (key, value):
                        if len(piece) >= 4:
                            base.append(piece)
                            for segment in piece.split("/"):
                                if len(segment) >= 4:
                                    base.append(segment)
            if parts.fragment and len(parts.fragment) >= 4:
                base.append(parts.fragment)
            for userinfo in (parts.username, parts.password):
                if userinfo and len(userinfo) >= 4:
                    base.append(userinfo)
    needles: set[str] = set()
    for needle in base:
        if not needle:
            continue
        needles.add(needle)
        decoded = unquote(needle)
        if decoded != needle:
            needles.add(decoded)
        for variant in (needle, decoded):
            if "/" in variant:
                needles.add(variant.replace("/", r"\/"))
            # Percent-encoded echoes: fully encoded, and encoded with the
            # path separator kept (the two common re-quoting styles).
            needles.add(quote(variant, safe=""))
            needles.add(quote(variant, safe="/"))
    out = text
    # Longest first, so a full URL is replaced before its own path is.
    for needle in sorted(needles, key=len, reverse=True):
        if needle:
            out = out.replace(needle, REDACTED)
    return out


# ── httpx request log line ─────────────────────────────────────────────────
#
# httpx logs ``HTTP Request: POST <full URL> "HTTP/1.1 200 OK"`` at INFO on
# every request, and ``configure_logging`` renders stdlib INFO records, so
# every webhook delivery used to write the incoming-webhook URL into the api
# and worker logs. The filter below rewrites the URL argument of records
# emitted while a secret-bearing request is in flight; every other httpx
# line is left alone. Any sender whose URL carries a credential can wrap
# its request in ``secret_url_in_flight``. Other filters on the httpx
# logger (a token-shape filter, say) compose with this one in any order:
# each only rewrites record arguments.

_IN_FLIGHT: ContextVar[str | None] = ContextVar("forward_secret_url_in_flight", default=None)


class _HttpxUrlRedactor(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        url = _IN_FLIGHT.get()
        if url and isinstance(record.args, tuple):
            shown = url_display(url)
            record.args = tuple(
                shown if _is_url_arg(arg, url) else _redact_arg(arg, url) for arg in record.args
            )
        return True


def _is_url_arg(arg: Any, url: str) -> bool:
    # httpx passes ``request.url``, an ``httpx.URL``. Only the secret-bearing
    # request is in flight in this context, so any URL argument is that one.
    return isinstance(arg, httpx.URL) or (isinstance(arg, str) and arg == url)


def _redact_arg(arg: Any, url: str) -> Any:
    return redact(arg, url) if isinstance(arg, str) else arg


_REDACTOR = _HttpxUrlRedactor()
logging.getLogger("httpx").addFilter(_REDACTOR)


@contextmanager
def secret_url_in_flight(url: str) -> Iterator[None]:
    """Redact ``url`` from httpx's own log lines for the duration."""
    token = _IN_FLIGHT.set(url)
    try:
        yield
    finally:
        _IN_FLIGHT.reset(token)


__all__ = [
    "REDACTED",
    "apply_write_only",
    "redact",
    "reveal",
    "secret_url_in_flight",
    "url_display",
]
