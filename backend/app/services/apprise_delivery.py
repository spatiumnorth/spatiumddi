"""Apprise delivery for webhook forward targets (#1503).

A webhook target with ``webhook_flavor="apprise"`` stores one Apprise
service URL (``tgram://…``, ``ntfys://…``, ``pover://…``, …) in the same
encrypted, write-only ``url_encrypted`` column every webhook URL uses
(#1502). Apprise does the per-service formatting and transport; this
module is the boundary around it. Three things about Apprise shape it:

* **It is synchronous.** Every plugin talks through ``requests``. Each
  call runs on a small dedicated thread pool (:data:`MAX_CONCURRENT`
  workers), never on the event loop, so a slow or dead service cannot
  stall the api or a worker's beat sweep. Each HTTP request has Apprise's
  own connect / read timeouts, the whole call has a deadline
  (:data:`CALL_TIMEOUT_SECONDS`) that Apprise enforces itself, and the
  await has one more on top in case the thread never comes back.
* **The URL is the credential**, and Apprise and the libraries under it
  log at several levels. The ``apprise`` logger does not propagate to
  ours: what Apprise says during a call is read from that call's own
  :class:`apprise.AppriseResult` (call-scoped, so concurrent sends never
  mix), redacted, and reported by us. ``urllib3`` logs the request path at
  DEBUG (for Telegram that path contains the bot token), and a few
  plugins go through ``requests-oauthlib``. A log-record factory scrubs
  every record created on a thread that is running an Apprise call, so
  whatever library writes the line, the URL's secret parts never reach a
  handler.
* **``notify()``'s result is the error report.** Apprise 2.x returns an
  ``AppriseResult`` with a status and the warning / error lines of that
  one call. Those lines are what the Test button shows ("Bad Request:
  chat not found"), after the URL's parts and anything URL-shaped are
  redacted. Nothing raw (the URL, a response body, a traceback) is
  surfaced; when nothing usable is left, a fixed message is.

Only service URLs are accepted: no Apprise configuration files or URLs,
no custom plugin paths, no attachments. Apprise's persistent store is
memory-only, and its default notification icons, which some services
would fetch from github.com, are switched off.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import re
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlsplit

import apprise

from app.services.forward_secrets import REDACTED

#: Seconds Apprise may spend on one notification, all requests included.
CALL_TIMEOUT_SECONDS = 20.0
#: How long the caller waits for the worker thread, on top of that.
_AWAIT_SLACK_SECONDS = 5.0
#: Apprise calls in flight at once, per process.
MAX_CONCURRENT = 4

_EXECUTOR = ThreadPoolExecutor(max_workers=MAX_CONCURRENT, thread_name_prefix="apprise")

#: Captured lines shown at most, and their length.
_MAX_REASONS = 3
_MAX_REASON_CHARS = 300

_SEVERITY_TO_NOTIFY_TYPE = {
    "info": apprise.NotifyType.INFO,
    "warn": apprise.NotifyType.WARNING,
    "warning": apprise.NotifyType.WARNING,
    "error": apprise.NotifyType.FAILURE,
    "denied": apprise.NotifyType.FAILURE,
    "critical": apprise.NotifyType.FAILURE,
}

# Anything that looks like ``scheme://…`` in text we are about to show. The
# needles below are the precise redaction; this is the catch-all for a URL
# Apprise rendered in a shape we did not predict.
_URL_IN_TEXT_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9+.-]{1,15})://[^\s'\"<>]+")
_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]{1,31})://")
# Separators inside an Apprise URL. Every piece between them is treated as
# possibly secret: tokens sit in the host (``tgram://<id>:<secret>``), the
# userinfo, path segments or query values, depending on the service.
_PIECE_SPLIT_RE = re.compile(r"[/:@?&=#,;\s]+")
_MIN_NEEDLE = 4


class AppriseDeliveryError(RuntimeError):
    """An Apprise send failed.

    The message is operator-facing and already redacted, so it is safe to
    log and to return from the Test endpoint.
    """


# ── URL handling ───────────────────────────────────────────────────────────


def url_display(url: str) -> str:
    """``tgram://…``: the service, never the token or credentials.

    Unlike a webhook URL, the host of an Apprise URL can itself be a
    secret (``tgram://<bot token>/…``, ``pover://<user>@<token>``), so only
    the scheme is shown.
    """
    if not url:
        return ""
    match = _SCHEME_RE.match(url.strip())
    return f"{match.group(1).lower()}://…" if match else "…"


def secret_needles(url: str) -> tuple[str, ...]:
    """Every part of ``url`` that has to be kept out of text, longest first.

    The whole URL, everything after the scheme, and each piece between
    separators (raw, unquoted and re-quoted, since a library may render
    either). A DNS name or IP address in the host position is left out:
    that is the server, not a credential, and keeping it makes an error
    readable.
    """
    if not url:
        return ()
    needles = {url}
    rest = url.split("://", 1)[1] if "://" in url else url
    needles.add(rest)
    keep: set[str] = set()
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if "." in host or ":" in host:
            keep.add(host)
        # Option names (``?priority=…&format=…``) are Apprise's vocabulary,
        # not secrets; their values are treated as possibly secret.
        keep.update(k.lower() for k, _ in parse_qsl(parts.query, keep_blank_values=True))
    except ValueError:
        pass
    for piece in _PIECE_SPLIT_RE.split(rest):
        for form in {piece, unquote(piece), quote(unquote(piece), safe="")}:
            if len(form) >= _MIN_NEEDLE and form.lower() not in keep:
                needles.add(form)
    return tuple(sorted(needles, key=len, reverse=True))


def _replace(text: str, needles: tuple[str, ...]) -> str:
    out = text
    for needle in needles:
        if needle in out:
            out = out.replace(needle, REDACTED)
    return out


def scrub(text: str, needles: tuple[str, ...]) -> str:
    """``text`` with every needle replaced, then any URL cut to its scheme.

    For text we show or log ourselves. Log records from libraries only get
    the needle replacement, so a DEBUG line keeps its host and path shape.
    """
    return _URL_IN_TEXT_RE.sub(lambda m: f"{m.group(1)}://…", _replace(text, needles))


# ── Log hygiene ────────────────────────────────────────────────────────────

# Apprise's own lines reach us through the per-call result only.
logging.getLogger("apprise").propagate = False

_IN_FLIGHT: ContextVar[tuple[str, ...] | None] = ContextVar(
    "apprise_secret_in_flight", default=None
)


def _scrub_record(record: logging.LogRecord, needles: tuple[str, ...]) -> None:
    try:
        message = record.getMessage()
    except Exception:  # noqa: BLE001 — a broken format is not ours to fix
        message = str(record.msg)
    cleaned = _replace(message, needles)
    if cleaned != message:
        record.msg = cleaned
        record.args = None
    if record.exc_info:
        # A requests / urllib3 exception can carry the URL in its text.
        formatted = logging.Formatter().formatException(record.exc_info)
        if _replace(formatted, needles) != formatted:
            record.exc_info = None
            record.exc_text = None
            record.msg = f"{record.msg} (traceback withheld: it quoted the target URL)"


def _install_record_factory() -> None:
    """Scrub every log record created while an Apprise call is in flight.

    A filter on a named logger only sees records created on that exact
    logger, not its children (``urllib3.connectionpool``,
    ``urllib3.util.retry``, ``oauthlib.*`` …), so the scrub sits in the
    record factory instead. It acts only in a context where
    :func:`_in_flight` is active, which ``asyncio`` and Apprise both copy
    into the threads they start.
    """
    previous = logging.getLogRecordFactory()
    if getattr(previous, "_spatium_apprise", False):
        return

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = previous(*args, **kwargs)
        needles = _IN_FLIGHT.get()
        if needles:
            _scrub_record(record, needles)
        return record

    factory._spatium_apprise = True  # type: ignore[attr-defined]
    logging.setLogRecordFactory(factory)


_install_record_factory()


@contextmanager
def _in_flight(url: str) -> Iterator[tuple[str, ...]]:
    needles = secret_needles(url)
    token = _IN_FLIGHT.set(needles)
    try:
        yield needles
    finally:
        _IN_FLIGHT.reset(token)


def _asset() -> apprise.AppriseAsset:
    return apprise.AppriseAsset(
        # Nothing written to disk; Telegram's owner auto-detection and the
        # like are remembered for one call only.
        storage_mode="memory",
        # The default icons are github.com URLs that a service such as
        # Discord or Slack would fetch. We send none.
        image_url_mask="",
        image_url_logo="",
        image_path_mask="",
    )


def _load(url: str) -> apprise.Apprise | None:
    """An Apprise object holding exactly ``url``, or None if it won't parse."""
    obj = apprise.Apprise(asset=_asset())
    if not obj.add(url) or len(obj) != 1:
        return None
    return obj


# ── Running off the event loop ─────────────────────────────────────────────


async def _off_loop(fn: Callable[..., Any], *args: Any) -> Any:
    loop = asyncio.get_running_loop()
    ctx = contextvars.copy_context()
    return await loop.run_in_executor(_EXECUTOR, lambda: ctx.run(fn, *args))


def _check_sync(url: str) -> str | None:
    with _in_flight(url):
        if _load(url) is None:
            return (
                "Apprise could not use this URL. Check the service prefix and the "
                "token / ID parts against the Apprise documentation for that service; "
                "one target holds exactly one URL."
            )
    return None


async def check_url(url: str) -> str | None:
    """None when Apprise can load ``url``; otherwise why not, without the URL.

    Parsing only: no request is made, nothing is sent. The first call in a
    process loads Apprise's plugin table (about a second), hence the thread.
    """
    return await _off_loop(_check_sync, url)  # type: ignore[no-any-return]


# ── Sending ────────────────────────────────────────────────────────────────


def _reason(result: apprise.AppriseResult, lines: list[str], needles: tuple[str, ...]) -> str:
    services = [r.name for r in result.results]
    service = services[0] if services else "Apprise"
    status = result.status
    if status == apprise.AppriseResultStatus.TIMEOUT:
        return f"{service} did not answer within {CALL_TIMEOUT_SECONDS:g} s."
    if status == apprise.AppriseResultStatus.NOMATCH:
        return "Apprise did not attempt a delivery: the URL matched no service."
    reasons: list[str] = []
    for line in lines:
        cleaned = scrub(line, needles).strip()[:_MAX_REASON_CHARS]
        if cleaned and cleaned not in reasons:
            reasons.append(cleaned)
        if len(reasons) >= _MAX_REASONS:
            break
    if not reasons:
        return f"{service} reported a failure without a reason."
    return f"{service}: " + " | ".join(reasons)


def _send_sync(url: str, title: str, body: str, notify_type: apprise.NotifyType) -> None:
    with _in_flight(url) as needles:
        obj = _load(url)
        if obj is None:
            raise AppriseDeliveryError("Apprise could not load the stored URL for this target.")
        lines: list[str] = []

        def _collect(entry: Any, _service: Any) -> None:
            # Bounded: only the first few lines are ever shown.
            if len(lines) < 4 * _MAX_REASONS:
                lines.append(str(entry.message))

        result = obj.notify(
            body=body,
            title=title,
            notify_type=notify_type,
            body_format=apprise.NotifyFormat.TEXT,
            timeout=CALL_TIMEOUT_SECONDS,
            log_callback=_collect,
            log_level=logging.WARNING,
        )
        with result:
            if result:
                return
            raise AppriseDeliveryError(_reason(result, lines, needles))


async def send(url: str, *, title: str, body: str, severity: str) -> None:
    """Deliver one notification through the Apprise URL ``url``.

    Raises :class:`AppriseDeliveryError` with a redacted, operator-facing
    reason on any failure, timeout included.
    """
    notify_type = _SEVERITY_TO_NOTIFY_TYPE.get(severity.lower(), apprise.NotifyType.INFO)
    if not body:
        title, body = "", title or "(no details)"
    try:
        await asyncio.wait_for(
            _off_loop(_send_sync, url, title, body, notify_type),
            timeout=CALL_TIMEOUT_SECONDS + _AWAIT_SLACK_SECONDS,
        )
    except AppriseDeliveryError:
        raise
    except TimeoutError:
        raise AppriseDeliveryError(
            f"The Apprise call did not return within {CALL_TIMEOUT_SECONDS + _AWAIT_SLACK_SECONDS:g} s."
        ) from None
    except Exception as exc:  # noqa: BLE001 — Apprise or a plugin raised
        raise AppriseDeliveryError(
            f"Apprise raised {type(exc).__name__}: {scrub(str(exc), secret_needles(url))[:200]}"
        ) from None


__all__ = [
    "CALL_TIMEOUT_SECONDS",
    "MAX_CONCURRENT",
    "AppriseDeliveryError",
    "check_url",
    "scrub",
    "secret_needles",
    "send",
    "url_display",
]
