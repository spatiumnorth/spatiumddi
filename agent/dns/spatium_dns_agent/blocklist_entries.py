"""Blocklist entries as a bundle carries them (#4040).

A bundle's ``entries`` list holds two kinds of element: an entry object
(``{"domain": ..., "action": ..., ...}``) and, for an agent that advertised
``packed-blocklists``, a RUN of consecutive entries sharing every field but
the domain::

    {"packed": {"action": ..., ...}, "count": N, "domains_gz": "<b64 gzip>"}

``iter_entries`` yields the entry objects in the order the control plane
sent them, one decompressed line at a time, so a run's domains are never
held as a list. Anything that reads ``entries`` goes through it, and the
rendered RPZ zone is the one a per-entry bundle gives. The bundle on disk
holds the runs as they came, so a restart with the control plane down
renders from the cache alone.
"""

from __future__ import annotations

import base64
import gzip
import io
from collections.abc import Iterator
from typing import Any


def _run_domains(run: dict[str, Any]) -> Iterator[str]:
    raw = gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(run["domains_gz"])))
    with io.TextIOWrapper(raw, encoding="utf-8", newline="\n") as text:
        for line in text:
            domain = line.rstrip("\n")
            if domain:
                yield domain


def iter_entries(blocklist: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Every entry of ``blocklist``, packed runs expanded, in order."""
    for item in blocklist.get("entries") or []:
        attrs = item.get("packed")
        if attrs is None:
            yield item
            continue
        for domain in _run_domains(item):
            yield {**attrs, "domain": domain}


def entry_count(blocklist: dict[str, Any]) -> int:
    """How many entries ``blocklist`` holds, without expanding a run."""
    return sum(
        int(item["count"]) if "packed" in item else 1 for item in blocklist.get("entries") or []
    )
