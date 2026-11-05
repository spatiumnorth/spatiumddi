"""RPKI ROA pull — stream the global ROA dump from a public mirror and keep
only the ROAs of the ASNs that were asked for.

Two source backends today:

* **Cloudflare** — ``https://rpki.cloudflare.com/rpki.json``. Compact
  JSON shape: ``{"metadata": {...}, "roas": [{"asn": 13335, "prefix":
  "1.1.1.0/24", "maxLength": 24, "ta": "apnic", "expires": 1778336254},
  ...], "bgpsec_keys": [...], "aspas": [...]}``. ``expires`` is a Unix
  epoch (seconds) — that's the ``valid_to`` we surface. Cloudflare doesn't
  ship ``valid_from``; we leave it NULL. The dump itself is refreshed
  roughly every 20 minutes.
* **RIPE NCC RPKI Validator 3** —
  ``https://rpki-validator.ripe.net/api/export.json`` (the old
  ``/api/objects/validated.json`` answers 404 since RIPE retired it,
  spatiumddi#3557; the export was verified live on 2026-11-05). Same
  triple shape (``asn`` as ``"AS13335"`` / ``prefix`` / ``maxLength`` /
  ``ta``) with ``roas`` at the top level. The export carries no validity
  window, so ``valid_from`` / ``valid_to`` stay NULL for it; the parser
  still maps ``notBefore`` / ``notAfter`` should a payload carry them.

A failed fetch is NOT an empty answer (spatiumddi#3557). "The source
answered and this ASN has no ROAs" is an empty list; "we could not get an
answer" (transport error, non-200, malformed or truncated body, a 200 whose
document is far smaller than a full index, unknown source) raises :class:`RoaFetchError`. The refresh reconcile deletes ROA rows
that are absent from what it is given, so conflating the two wiped every
stored ROA the first time a mirror moved its URL, while reporting success.

Why the dump is STREAMED and never held whole (spatiumddi#1054). The global
dump is ~100 MB of JSON and a million entries (2026-09-15: 104,582,576
bytes, 1,004,107 ROAs over 62,494 ASNs). ``resp.json()`` of that body costs
~460 MB of Python objects on top of the ~100 MB body, and a CPython process
never hands that heap back to the kernel: the previous version parsed the
whole body and cached the list per process, and on the appliance every
celery prefork child that ever ran one ASN refresh grew by ~380 MB and kept
it, so two children plus the parent overran the supervisor's ``MemTotal/4``
limit on a 6 GB node and the worker was OOMKilled (measured live: one
``refresh_one_asn_by_id`` took a child from 266 MB to 646 MB resident in
41 s). The api process runs the same code on ``POST /asns/{id}/refresh-rpki``.

So the fetch is a streamed GET whose body is walked one JSON value at a time
by :func:`iter_roas` — an incremental parser over ``json.JSONDecoder``'s
``raw_decode`` that never materialises the ``roas`` array — and only the
entries of the ASNs asked for are kept. The per-process cache holds those
slices (kilobytes) for :data:`_CACHE_TTL_SECONDS`, keyed by source, so a
beat sweep that refreshes ROAs for 50 ASNs still makes ONE HTTP call: it
calls :func:`prime_roas` with the whole set first, and every
:func:`fetch_roas_for_asn` after that is a cache hit. An ASN the cache does
not index re-primes for the union, so the one-shot path (one ASN, one fetch)
and the sweep share one code path.
"""

from __future__ import annotations

import codecs
import json
import re
import time
from collections.abc import AsyncIterator, Iterable
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

# Per-call ceiling — the connect budget is capped so a dead mirror doesn't
# stall the worker for minutes; ``read`` is per chunk on a streamed body, so
# a slow mirror is bounded per 256 KiB rather than per 100 MB.
_PER_REQUEST_TIMEOUT = httpx.Timeout(30.0, connect=5.0, read=30.0)

# 5-minute cache TTL keyed by source. The Cloudflare mirror itself
# refreshes every ~20 minutes so we're not at risk of serving stale
# data; this is purely a worker-side optimisation so a beat sweep
# refreshing ROAs for 50 ASNs makes one HTTP call, not 50.
_CACHE_TTL_SECONDS = 300

_SOURCE_URLS = {
    "cloudflare": "https://rpki.cloudflare.com/rpki.json",
    "ripe": "https://rpki-validator.ripe.net/api/export.json",
}


class RoaFetchError(Exception):
    """The ROA source could not be read (transport error, non-200, malformed
    body, unknown source). Distinct from an empty answer: callers must keep
    what they have stored and report the failure, never treat it as "this AS
    has no ROAs"."""


_VALID_TRUST_ANCHORS = {"arin", "ripe", "apnic", "lacnic", "afrinic"}

# Streamed body chunk. Big enough that a 100 MB dump is a few hundred reads,
# small enough that the parse buffer stays a fraction of one ROA list page.
_CHUNK_BYTES = 256 * 1024
# Consumed text is dropped from the parse buffer once this much has been
# walked, so the buffer never grows past ~one chunk plus one JSON value.
_TRIM_AT = 64 * 1024

# A full-index source carries ~1M ROAs (2026-11-05: Cloudflare 1,031,225,
# RIPE's export 1,031,269). A 200 whose document parses but holds far fewer is
# an upstream outage or a truncated export, not the state of the world, and
# reading it as one would delete every stored ROA of every AS it no longer
# lists (spatiumddi#3557, the #986 TLD-download guard's reasoning). Well under
# a tenth of today's size so organic churn never trips it.
_MIN_INDEX_ENTRIES = 100_000

# Last failure reason per source, cleared by the next successful fetch.
_last_error: dict[str, str] = {}

# Module-level cache: { source: (fetched_at_epoch, asns indexed, {asn: [roa, ...]}) }
_cache: dict[str, tuple[float, frozenset[int], dict[int, list[dict[str, Any]]]]] = {}

_WS = re.compile(r"[ \t\r\n]*")
_decoder = json.JSONDecoder()


def _normalise_asn_field(value: Any) -> int | None:
    """Cloudflare emits ``"AS13335"``; RIPE sometimes emits the raw
    int. Accept both shapes; return ``None`` on anything we can't
    parse so the ROA gets skipped rather than crashing the load.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str):
        s = value.strip().upper()
        if s.startswith("AS"):
            s = s[2:]
        try:
            n = int(s)
        except ValueError:
            return None
        return n if n > 0 else None
    return None


def _normalise_trust_anchor(value: Any) -> str | None:
    """Both mirrors emit ``"arin"`` / ``"ripe"`` / ``"apnic"`` /
    ``"lacnic"`` / ``"afrinic"``; some payloads use the older
    ``"AfriNIC"`` casing. Lower-case + restrict to the known set,
    falling back to ``None`` (treated as ``"unknown"`` downstream).
    """
    if not isinstance(value, str):
        return None
    code = value.strip().lower()
    return code if code in _VALID_TRUST_ANCHORS else None


def _parse_validity(value: Any) -> datetime | None:
    """Coerce a ROA-validity field to ``datetime``.

    Cloudflare ships ``expires`` as a Unix epoch (seconds). RIPE's
    validator ships ``notBefore`` / ``notAfter`` as ISO 8601 strings.
    Accept both shapes and silently return ``None`` for anything we
    can't parse — a stray malformed row shouldn't poison the load.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(int(value), tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        # Numeric string → epoch.
        if s.isdigit():
            try:
                return datetime.fromtimestamp(int(s), tz=UTC)
            except (OverflowError, OSError, ValueError):
                return None
        # ISO 8601 — handle both ``...Z`` and ``...+00:00`` shapes.
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(s)
        except ValueError:
            return None
    return None


def _normalise_max_length(value: Any) -> int | None:
    """Coerce ``maxLength`` to int. Drop entries we can't parse —
    a malformed row shouldn't poison the whole load.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _normalise_entry(raw: Any) -> tuple[int, dict[str, Any]] | None:
    """One raw ROA object -> ``(asn, entry)`` in the shape
    :func:`fetch_roas_for_asn` returns, or ``None`` when the row is not a
    usable ROA (no ASN, no prefix, no maxLength)."""
    if not isinstance(raw, dict):
        return None
    # Both mirrors use ``asn``; RIPE older payloads use ``customerASN``.
    asn_field = raw.get("asn") if "asn" in raw else raw.get("customerASN")
    n = _normalise_asn_field(asn_field)
    if n is None:
        return None
    prefix = raw.get("prefix")
    if not isinstance(prefix, str) or not prefix.strip():
        return None
    max_length = _normalise_max_length(raw.get("maxLength") or raw.get("max_length"))
    if max_length is None:
        return None
    # ``ta`` is Cloudflare's key; ``trustAnchor`` / ``ta_name``
    # show up in some RIPE variants.
    ta_raw = raw.get("ta") or raw.get("trustAnchor") or raw.get("ta_name")
    ta = _normalise_trust_anchor(ta_raw)
    # Validity windows. Cloudflare ships ``expires`` (epoch);
    # RIPE ships ``notBefore`` / ``notAfter`` (ISO 8601). Accept
    # whichever the source provides; either may be absent.
    valid_from = _parse_validity(raw.get("notBefore"))
    valid_to = _parse_validity(raw.get("expires") or raw.get("notAfter"))
    return n, {
        "prefix": prefix.strip(),
        "max_length": int(max_length),
        "valid_from": valid_from,
        "valid_to": valid_to,
        "trust_anchor": ta,
    }


# ── The incremental parser ──────────────────────────────────────────────


class _Stream:
    """A text window over an async byte stream for ``raw_decode``.

    ``buf`` holds the not-yet-consumed text from ``pos`` on; ``more()`` pulls
    the next chunk (False at end of stream); ``trim()`` drops consumed text so
    the window stays about one chunk wide however large the document is.
    """

    def __init__(self, chunks: AsyncIterator[bytes]) -> None:
        self._chunks = chunks
        self._dec = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self.buf = ""
        self.pos = 0
        self.eof = False

    async def more(self) -> bool:
        if self.eof:
            return False
        try:
            chunk = await self._chunks.__anext__()
        except StopAsyncIteration:
            self.eof = True
            self.buf += self._dec.decode(b"", final=True)
            return False
        self.buf += self._dec.decode(chunk)
        return True

    def trim(self) -> None:
        if self.pos > _TRIM_AT:
            self.buf = self.buf[self.pos :]
            self.pos = 0

    async def skip_ws(self) -> None:
        """Advance past whitespace, reading on until a non-blank char or EOF."""
        while True:
            m = _WS.match(self.buf, self.pos)
            self.pos = m.end() if m is not None else self.pos
            if self.pos < len(self.buf):
                return
            if not await self.more():
                return

    async def peek(self) -> str:
        await self.skip_ws()
        return self.buf[self.pos] if self.pos < len(self.buf) else ""

    async def expect(self, ch: str) -> None:
        got = await self.peek()
        if got != ch:
            raise ValueError(f"expected {ch!r} at offset {self.pos}, got {got!r}")
        self.pos += 1

    async def value(self) -> Any:
        """One complete JSON value starting at ``pos`` (whitespace skipped),
        reading more of the stream until it decodes. A value the stream ends
        inside is malformed."""
        await self.skip_ws()
        while True:
            try:
                val, end = _decoder.raw_decode(self.buf, self.pos)
            except json.JSONDecodeError:
                if not await self.more():
                    raise ValueError("truncated or malformed JSON value") from None
                continue
            # A number at the very end of the window may continue in the next
            # chunk ("12" + "34"): read on until the window holds more than the
            # value, or the stream is over.
            if end == len(self.buf) and not self.eof and self.buf[self.pos] not in '"{[':
                if await self.more():
                    continue
            self.pos = end
            return val


async def iter_roas(chunks: AsyncIterator[bytes]) -> AsyncIterator[dict[str, Any]]:
    """Yield the objects of the document's ``roas`` array one at a time,
    from a streamed JSON body, without ever holding the array.

    Walks the top-level object member by member: keys are decoded with the
    real decoder (so a string VALUE that happens to contain ``"roas"`` cannot
    fool it), non-``roas`` values are decoded and dropped, ``data`` is
    descended into for the mirrors that nest the array, and the walk stops
    the moment the ``roas`` array closes — nothing after it is read. Raises
    ``ValueError`` on a malformed or truncated document, or one without a
    ``roas`` array.
    """
    s = _Stream(chunks)
    await s.expect("{")
    depth_data = False
    while True:
        ch = await s.peek()
        if ch == "}":
            s.pos += 1
            if depth_data:
                depth_data = False
                # Back at the top level: the rest of the top object.
                ch = await s.peek()
                if ch == ",":
                    s.pos += 1
                    continue
                if ch == "}":
                    break
                raise ValueError("expected ',' or '}' after data")
            break
        if ch == ",":
            s.pos += 1
            continue
        key = await s.value()
        if not isinstance(key, str):
            raise ValueError("object key is not a string")
        await s.expect(":")
        if key == "roas":
            await s.expect("[")
            while True:
                ch = await s.peek()
                if ch == "]":
                    s.pos += 1
                    return
                if ch == ",":
                    s.pos += 1
                    continue
                obj = await s.value()
                if isinstance(obj, dict):
                    yield obj
                s.trim()
        elif key == "data" and not depth_data and await s.peek() == "{":
            s.pos += 1
            depth_data = True
        else:
            await s.value()  # decoded and dropped — metadata, aspas, keys
            s.trim()
    raise ValueError("no roas array in the document")


async def _stream_dump(url: str) -> AsyncIterator[bytes]:
    """The body of ``url`` as a stream of byte chunks; raises
    ``httpx.HTTPError`` on transport failure and ``ValueError`` on a
    non-200 answer. Kept separate so tests can feed the parser a document
    without a network."""
    async with httpx.AsyncClient(timeout=_PER_REQUEST_TIMEOUT) as client:
        async with client.stream("GET", url) as resp:
            if resp.status_code != 200:
                raise ValueError(f"http {resp.status_code}")
            async for chunk in resp.aiter_bytes(_CHUNK_BYTES):
                yield chunk


async def _fetch_index(source: str, asns: frozenset[int]) -> dict[int, list[dict[str, Any]]]:
    """Stream the dump from ``source`` and index the ROAs of ``asns``.

    Raises :class:`RoaFetchError` on transport failure / non-200 / malformed
    JSON / unknown source, and on a document listing fewer than
    ``_MIN_INDEX_ENTRIES`` ROAs (a 200 that is not a full index). Every ASN asked for is a key of the result, an
    empty list meaning "the dump was read and has no ROAs for it".
    """
    url = _SOURCE_URLS.get(source)
    if url is None:
        logger.warning("rpki_roa_unknown_source", source=source)
        raise RoaFetchError(f"unknown ROA source {source!r}")
    index: dict[int, list[dict[str, Any]]] = {n: [] for n in asns}
    seen = 0
    try:
        async for raw in iter_roas(_stream_dump(url)):
            seen += 1
            n = _normalise_asn_field(raw.get("asn") if "asn" in raw else raw.get("customerASN"))
            if n is None or n not in index:
                continue
            norm = _normalise_entry(raw)
            if norm is not None:
                index[n].append(norm[1])
    except httpx.HTTPError as exc:
        reason = f"transport: {exc}"
    except ValueError as exc:
        reason = str(exc)
    except Exception as exc:  # noqa: BLE001 — never block the worker on a bad mirror
        reason = f"unexpected: {exc}"
    else:
        reason = ""
        if seen < _MIN_INDEX_ENTRIES:
            reason = (
                f"the document lists only {seen} ROAs, fewer than the "
                f"{_MIN_INDEX_ENTRIES} a full index carries; treated as an outage"
            )
    if reason:
        logger.info("rpki_roa_fetch_failed", source=source, error=reason)
        raise RoaFetchError(f"{source} ROA source: {reason}")
    logger.info("rpki_roa_dump_indexed", source=source, entries=seen, asns=len(asns))
    return index


def _fresh(source: str) -> tuple[frozenset[int], dict[int, list[dict[str, Any]]]] | None:
    cached = _cache.get(source)
    if cached is not None and (time.monotonic() - cached[0]) < _CACHE_TTL_SECONDS:
        return cached[1], cached[2]
    return None


async def _prime(wanted: frozenset[int], source: str) -> None:
    """Index ``wanted`` (plus whatever a still-fresh cache already indexes);
    raises :class:`RoaFetchError` when the source cannot be read."""
    fresh = _fresh(source)
    if fresh is not None and wanted <= fresh[0]:
        return
    if fresh is not None:
        wanted = wanted | fresh[0]
    try:
        index = await _fetch_index(source, wanted)
    except RoaFetchError as exc:
        _last_error[source] = str(exc)
        raise
    _last_error.pop(source, None)
    _cache[source] = (time.monotonic(), wanted, index)


async def prime_roas(asns: Iterable[int], source: str) -> bool:
    """Make one streamed fetch that indexes ``asns`` (plus whatever a still-
    fresh cache already indexes, so a sweep never narrows what the one-shot
    path just fetched). ``True`` when the index is usable; ``False`` when the
    fetch failed — the reason is in :func:`last_fetch_error`."""
    try:
        await _prime(frozenset(int(n) for n in asns if n), source)
    except RoaFetchError:
        return False
    return True


def last_fetch_error(source: str) -> str | None:
    """Reason the most recent fetch from ``source`` failed, or ``None``."""
    return _last_error.get(source)


async def fetch_roas_for_asn(asn_number: int, source: str) -> list[dict[str, Any]]:
    """The ROAs originated by ``asn_number`` from the cached slice of the
    dump, fetching (streamed, filtered) when the cache is stale or does not
    index this AS.

    Returned shape (one dict per ROA)::

        {
            "prefix": "1.1.1.0/24",
            "max_length": 24,
            "valid_from": datetime | None,  # ``notBefore`` when the source has it
            "valid_to": datetime | None,    # ``expires`` (CF) or ``notAfter``
            "trust_anchor": "apnic",        # may be None on malformed rows
        }

    An empty list means the source WAS read and has no ROAs for this AS.
    When the source cannot be read this raises :class:`RoaFetchError`, so the
    caller's reconcile never mistakes an outage for "no ROAs" and deletes the
    stored rows (spatiumddi#3557).
    """
    n = int(asn_number)
    fresh = _fresh(source)
    if fresh is None or n not in fresh[0]:
        await _prime(frozenset({n}), source)
    cached = _cache.get(source)
    if cached is None or n not in cached[1]:
        raise RoaFetchError(f"{source} ROA source: no index for AS{n}")
    return list(cached[2].get(n, []))


def _clear_cache_for_test() -> None:
    """Reset the module-level cache. Test-only; never call in prod."""
    _cache.clear()
    _last_error.clear()


__all__ = [
    "RoaFetchError",
    "fetch_roas_for_asn",
    "iter_roas",
    "last_fetch_error",
    "prime_roas",
    "_clear_cache_for_test",
]
