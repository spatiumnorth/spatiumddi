"""Fetching the config bundle without holding its body in memory (#2029)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx

from .cache import FETCH_SPOOL, parse_bundle_file

CONFIG_PATH = "/api/v1/dns/agents/config"


class _SpooledConfig:
    """A config reply whose body was streamed to disk instead of into memory.

    Offers what ``_poll_once`` reads off a response (``status_code``,
    ``headers``, ``json()``). The body is parsed from the spool file on the
    first ``json()`` and the file removed; a reply nobody parses (a 304, an
    error status) never had a body written.
    """

    def __init__(self, status_code: int, headers: httpx.Headers, spool: Path | None):
        self.status_code = status_code
        self.headers = headers
        self._spool = spool

    def json(self) -> Any:
        if self._spool is None:
            raise ValueError("config reply carried no body")
        try:
            return parse_bundle_file(self._spool)
        finally:
            self._spool.unlink(missing_ok=True)


def get_config(client: Any, headers: dict[str, str], state_dir: Path) -> Any:
    """GET the config bundle, streaming a 200's body to disk (#2029).

    ``Client.get`` reads the whole body into memory — chunk list and joined
    copy both, briefly — and the response then keeps it alive for the rest of
    the poll, apply included. With a catalog-sized blocklist that is a
    150 MB+ bytes object beside the parsed bundle. Spooling it to a file in
    the state dir and parsing from there means the body is never held as
    bytes while it is being parsed (see ``parse_bundle_file``).

    A client that offers only ``get`` (no httpx streaming) is asked the old
    way; its reply has the same three members ``_poll_once`` uses.
    """
    stream = getattr(client, "stream", None)
    if stream is None:
        return client.get(CONFIG_PATH, headers=headers)
    with stream("GET", CONFIG_PATH, headers=headers) as resp:
        if resp.status_code != 200:
            return _SpooledConfig(resp.status_code, resp.headers, None)
        spool = state_dir / FETCH_SPOOL
        spool.parent.mkdir(parents=True, exist_ok=True)
        try:
            with spool.open("wb") as fh:
                for chunk in resp.iter_bytes():
                    fh.write(chunk)
        except BaseException:
            # A body cut off mid-stream raises here (an httpx error the poll
            # already handles), as does a full disk (OSError, which the poll
            # treats as a failed fetch); leave no partial spool behind.
            spool.unlink(missing_ok=True)
            raise
        return _SpooledConfig(resp.status_code, resp.headers, spool)


BLOCKLIST_PATH = "/api/v1/dns/agents/blocklist"
BLOCKLIST_ETAG_HEADER = "X-Spatium-Blocklist-Etag"

# The blocklist stream the agent holds (#4041): the document as fetched, and
# the ETag it was served under. Kept apart from ``current.json`` (the merged
# bundle) so a record-only change never downloads it again.
BLOCKLIST_CACHE = "config/blocklist.json"
BLOCKLIST_CACHE_ETAG = "config/blocklist.etag"
_BLOCKLIST_SPOOL = "config/blocklist.json.part"


class BlocklistUnavailable(Exception):
    """The control plane answered the blocklist stream with something else
    than a document (a render still pending is a 503). Retried by the poll."""


def held_blocklist_etag(state_dir: Path) -> str | None:
    """The ETag of the stream on disk, ``None`` when there is none (or no
    document to go with it)."""
    try:
        if not (state_dir / BLOCKLIST_CACHE).is_file():
            return None
        return (state_dir / BLOCKLIST_CACHE_ETAG).read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def get_blocklist(client: Any, state_dir: Path) -> str:
    """GET the blocklist stream, spool it to disk and make it the held one.

    Returns the ETag it was served under (the document names itself, so a
    newer render than the one the poll saw is simply taken). The old document
    stays until the new one is complete: the ETag file is written last, so a
    torn download never reads as a held stream."""
    stream = getattr(client, "stream", None)
    spool = state_dir / _BLOCKLIST_SPOOL
    spool.parent.mkdir(parents=True, exist_ok=True)
    try:
        if stream is None:
            resp = client.get(BLOCKLIST_PATH)
            if resp.status_code != 200:
                raise BlocklistUnavailable(f"blocklist stream answered {resp.status_code}")
            spool.write_bytes(resp.content)
            etag = resp.headers.get("ETag")
        else:
            with stream("GET", BLOCKLIST_PATH) as resp:
                if resp.status_code != 200:
                    raise BlocklistUnavailable(f"blocklist stream answered {resp.status_code}")
                etag = resp.headers.get("ETag")
                with spool.open("wb") as fh:
                    for chunk in resp.iter_bytes():
                        fh.write(chunk)
        if not etag:
            raise BlocklistUnavailable("blocklist stream carried no ETag")
        etag = unquote_etag(etag)
        (state_dir / BLOCKLIST_CACHE_ETAG).unlink(missing_ok=True)
        os.replace(spool, state_dir / BLOCKLIST_CACHE)
        (state_dir / BLOCKLIST_CACHE_ETAG).write_text(etag, encoding="utf-8")
        return etag
    except BaseException:
        spool.unlink(missing_ok=True)
        raise


def unquote_etag(value: str) -> str:
    """``W/"sha256:..."`` as the header spells it, back to ``sha256:...``."""
    value = value.strip()
    if value.startswith("W/"):
        value = value[2:]
    return value.strip('"')


def merge_blocklist_stream(bundle: dict[str, Any], state_dir: Path, etag: str) -> None:
    """Fill the bundle's blocklist zones from the held stream, in place.

    Each zone the bundle names (an empty ``entries``) takes its entries, and
    in a BIND9 bundle its content hash, from the stream element of the same
    RPZ zone and view. The bundle then reads as one that embedded them, for
    the driver and for the cache, and ``blocklist_etag`` records which stream
    it holds. Its ``structural_etag`` folds in the stream's, so a change to
    entries alone is still a change the apply loop acts on (the control plane's
    own structural etag, which an entry edit no longer moves, is the part
    before the ``+``).

    Raises ``BlocklistUnavailable`` when the held stream lacks a zone the
    bundle names: the stream is from a render older than the bundle, and the
    poll fetches it again."""
    doc = parse_bundle_file(state_dir / BLOCKLIST_CACHE)
    by_key = {(z.get("rpz_zone_name"), z.get("view_name")): z for z in doc.get("blocklists") or []}
    for zone in bundle.get("blocklists") or []:
        held = by_key.get((zone.get("rpz_zone_name"), zone.get("view_name")))
        if held is None:
            raise BlocklistUnavailable(f"stream has no zone {zone.get('rpz_zone_name')!r}")
        zone["entries"] = held.get("entries") or []
        if "rpz_sha256" in held:
            zone["rpz_sha256"] = held["rpz_sha256"]
    bundle["blocklist_etag"] = etag
    bundle["structural_etag"] = f"{bundle.get('structural_etag')}+{etag}"
