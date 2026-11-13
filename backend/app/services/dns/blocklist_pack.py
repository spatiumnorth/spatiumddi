"""Packed blocklist entries for the DNS agent bundle (#4040).

A bundle carried every blocklist entry as its own JSON object, ~108 bytes
each, of which ~100 repeat the same four words: 69 MB for AdGuard + OISD +
Hagezi, parsed whole by the agent. An agent that sends ``packed-blocklists``
in ``X-Spatium-Agent-Features`` is sent a RUN of consecutive entries that
share every field but the domain as one element of ``entries``::

    {"packed": {"action": ..., "block_mode": ..., "target": null,
                "is_wildcard": ..., ["sinkhole_ip": ...]},
     "count": N, "domains_gz": "<base64 of gzip of the domains, one per line>"}

Runs are consecutive, never regrouped: the agent's renderer keeps the first
writer of an owner name (#878), so entry ORDER decides which of two
disagreeing lists wins and a reordered list would render a different zone.
Entries a run cannot carry (a ``target``, a domain with a newline, a run too
short to repay it) stay objects, in place. A feed's rows share everything, so
a catalogue list is one run per ``PACK_MAX_RUN`` domains.

The ETag is hashed over the bundle as it is sent, runs included, so it moves
whenever an entry does and differs between the two shapes. ``mtime=0`` makes
the gzip bytes a function of the domains (and the zlib release, so an upgrade
may move the ETag once).
"""

from __future__ import annotations

import base64
import gzip
from collections.abc import Iterable
from typing import Any

#: The feature token an agent sends to say it reads packed entries.
FEATURE_PACKED_BLOCKLISTS = "packed-blocklists"

#: Fewer than this many consecutive alike entries stay as objects.
PACK_MIN_RUN = 32
#: A run is cut at this many domains, so a decoder never holds a whole feed.
PACK_MAX_RUN = 100_000


def renders_packed_blocklists(header: str | None) -> bool:
    from app.services.dns.soa_timers import agent_features

    return FEATURE_PACKED_BLOCKLISTS in agent_features(header)


def _eligible(entry: dict[str, Any]) -> bool:
    domain = entry["domain"]
    return (
        bool(domain) and entry.get("target") is None and "\n" not in domain and "\r" not in domain
    )


def _key(entry: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(sorted((k, v) for k, v in entry.items() if k != "domain"))


def pack_run(attrs: dict[str, Any], domains: list[str]) -> dict[str, Any]:
    """One run as it is sent."""
    text = "\n".join(domains).encode("utf-8")
    blob = base64.b64encode(gzip.compress(text, compresslevel=6, mtime=0)).decode("ascii")
    return {"packed": attrs, "count": len(domains), "domains_gz": blob}


class EntryPacker:
    """Folds a stream of entry dicts into runs, a batch at a time.

    ``feed`` takes a batch and returns the items it completed; ``finish`` the
    last. Memory is one run's domains.
    """

    def __init__(self) -> None:
        self._key: tuple[Any, ...] | None = None
        self._attrs: dict[str, Any] = {}
        self._pending: list[dict[str, Any]] = []

    def _flush(self) -> list[dict[str, Any]]:
        pending, self._pending, self._key = self._pending, [], None
        if len(pending) < PACK_MIN_RUN:
            return pending
        return [pack_run(self._attrs, [e["domain"] for e in pending])]

    def feed(self, entries: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for e in entries:
            if not _eligible(e):
                out.extend(self._flush())
                out.append(e)
                continue
            key = _key(e)
            if key != self._key or len(self._pending) >= PACK_MAX_RUN:
                out.extend(self._flush())
                self._key = key
                self._attrs = {k: v for k, v in e.items() if k != "domain"}
            self._pending.append(e)
        return out

    def finish(self) -> list[dict[str, Any]]:
        return self._flush()


def pack_entries(entries: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """The wire form of a whole entry list (the materialised render)."""
    packer = EntryPacker()
    return packer.feed(entries) + packer.finish()
