"""Fetching the config bundle without holding its body in memory (#2029)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import httpx

from .cache import FETCH_SPOOL, parse_bundle_file

CONFIG_PATH = "/api/v1/dns/agents/config"

#: Sent on a poll by an agent that holds the body for the ``If-None-Match`` it
#: presents (#5025): the control plane may then answer the pending ops alone.
OPS_ONLY_HEADER = "X-Spatium-Ops-Only"

# The head the control plane puts in front of every body it serves:
# ``{"etag":..,"pending_record_ops":[..],"pending_ops_remaining":N,`` (see
# ``_bundle_prefix`` on the control plane). Its first three keys are in this
# order since #958; an older control plane that orders them otherwise is just
# not recognised, and its reply is read in full.
_HEAD_OPEN = '{"etag":'
_HEAD_OPS = ',"pending_record_ops":'
_HEAD_REMAINING = re.compile(r',"pending_ops_remaining":(\d+),')
# A head larger than this is not one: read the reply in full instead.
_HEAD_MAX_BYTES = 32 * 1024 * 1024

_MORE = object()


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


class _HeadReply:
    """A reply whose body was never read (#5025): ``json()`` is its head, the
    etag, the ops page and the count behind it, marked ``head_only``."""

    def __init__(self, status_code: int, headers: httpx.Headers, head: dict[str, Any]):
        self.status_code = status_code
        self.headers = headers
        self._head = head

    def json(self) -> Any:
        return self._head


def _parse_head(buf: bytes, hold_etag: str) -> dict[str, Any] | None | object:
    """The head of a reply that carries ``hold_etag``, ``None`` when this is
    not one (another ETag, another shape), ``_MORE`` while it is incomplete."""
    try:
        text = buf.decode("utf-8")
    except UnicodeDecodeError:
        return _MORE  # a multi-byte character cut by the chunk
    if len(text) < len(_HEAD_OPEN):
        return _MORE if _HEAD_OPEN.startswith(text) else None
    if not text.startswith(_HEAD_OPEN):
        return None
    dec = json.JSONDecoder()
    try:
        etag, at = dec.raw_decode(text, len(_HEAD_OPEN))
    except ValueError:
        return _MORE
    if etag != hold_etag:
        return None
    if not text.startswith(_HEAD_OPS, at):
        return _MORE if len(text) - at < len(_HEAD_OPS) else None
    try:
        ops, at = dec.raw_decode(text, at + len(_HEAD_OPS))
    except ValueError:
        return _MORE
    m = _HEAD_REMAINING.match(text, at)
    if m is None:
        return _MORE if len(text) - at < 48 else None
    if not isinstance(ops, list):
        return None
    return {
        "etag": etag,
        "pending_record_ops": ops,
        "pending_ops_remaining": int(m.group(1)),
        "head_only": True,
    }


def get_config(
    client: Any,
    headers: dict[str, str],
    state_dir: Path,
    hold_etag: str | None = None,
) -> Any:
    """GET the config bundle, streaming a 200's body to disk (#2029).

    ``Client.get`` reads the whole body into memory — chunk list and joined
    copy both, briefly — and the response then keeps it alive for the rest of
    the poll, apply included. With a catalog-sized blocklist that is a
    150 MB+ bytes object beside the parsed bundle. Spooling it to a file in
    the state dir and parsing from there means the body is never held as
    bytes while it is being parsed (see ``parse_bundle_file``).

    A client that offers only ``get`` (no httpx streaming) is asked the old
    way; its reply has the same three members ``_poll_once`` uses.

    ``hold_etag`` (#5025): the ETag of the bundle this agent already holds
    and has applied. A 200 that opens with that ETag has nothing in its body
    the agent does not have — only the ops page in front of it matters — so
    only the head is read, the connection is closed, and the reply's
    ``json()`` is the head marked ``head_only``. This is what lets an agent
    drain a long queue against a control plane that sends the body with every
    page (every release before #5025): no body spooled, parsed or re-saved.
    """
    stream = getattr(client, "stream", None)
    if stream is None:
        return client.get(CONFIG_PATH, headers=headers)
    with stream("GET", CONFIG_PATH, headers=headers) as resp:
        if resp.status_code != 200:
            return _SpooledConfig(resp.status_code, resp.headers, None)
        spool = state_dir / FETCH_SPOOL
        spool.parent.mkdir(parents=True, exist_ok=True)
        chunks = resp.iter_bytes()
        head = bytearray()
        if hold_etag:
            for chunk in chunks:
                head += chunk
                if len(head) >= len(_HEAD_OPEN) and not head.startswith(_HEAD_OPEN.encode()):
                    break  # not a head this agent recognises: read it in full
                if b'"pending_ops_remaining":' not in head:
                    if len(head) > _HEAD_MAX_BYTES:
                        break
                    continue
                parsed = _parse_head(bytes(head), hold_etag)
                if isinstance(parsed, dict):
                    return _HeadReply(resp.status_code, resp.headers, parsed)
                if parsed is None or len(head) > _HEAD_MAX_BYTES:
                    break
        try:
            with spool.open("wb") as fh:
                fh.write(head)
                for chunk in chunks:
                    fh.write(chunk)
        except BaseException:
            # A body cut off mid-stream raises here (an httpx error the poll
            # already handles), as does a full disk (OSError, which the poll
            # treats as a failed fetch); leave no partial spool behind.
            spool.unlink(missing_ok=True)
            raise
        return _SpooledConfig(resp.status_code, resp.headers, spool)
