"""Fetching the config bundle without holding its body in memory (#2029)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from .cache import parse_bundle_file

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
        spool = state_dir / "config" / "fetch.json.part"
        spool.parent.mkdir(parents=True, exist_ok=True)
        try:
            with spool.open("wb") as fh:
                for chunk in resp.iter_bytes():
                    fh.write(chunk)
        except BaseException:
            # A body cut off mid-stream raises here (an httpx error the poll
            # already handles); leave no partial spool behind.
            spool.unlink(missing_ok=True)
            raise
        return _SpooledConfig(resp.status_code, resp.headers, spool)
