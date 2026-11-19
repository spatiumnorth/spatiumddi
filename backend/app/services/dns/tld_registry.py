"""The IANA root-zone TLD list: bundled snapshot + operator refresh (#986).

Two sources, one effective answer:

* **Bundled** — ``backend/app/data/iana_tlds.json``, regenerated at
  release-prep by ``scripts/refresh_iana_tlds.py``. Always present, so
  classification works on an air-gapped install that has never made an
  outbound call.
* **Snapshot** — a one-row ``tld_registry_snapshot`` table an operator
  fills with ``POST /api/v1/dns/tld-registry/refresh``. Postgres rather
  than a file on disk because a node-local file does not propagate across
  a multi-node control plane (the #886 logo reasoning).

The snapshot wins only when its ``version`` is *newer* than the bundled
one. That direction matters: a fresh release ships a newer bundled list
than a year-old snapshot, and silently preferring the stored copy would
make an upgrade lose TLDs.

**This module is deliberately stdlib-only at runtime.**
``scripts/refresh_iana_tlds.py`` imports :func:`parse_tld_payload` from
here so the download guard the script applies is byte-for-byte the one the
running control plane applies — two copies of a validator that are meant to
agree is the bug class this repo keeps finding (see #878). Keeping the
import cheap is what lets that script run under a bare ``python:3.12``
with no backend dependencies installed, so the SQLAlchemy import below is
``TYPE_CHECKING``-only and the model import is function-level.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from importlib.resources import files
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sqlalchemy.ext.asyncio import AsyncSession

_DATA_FILE = "iana_tlds.json"

# The one outbound host this module can reach, and only when an operator
# clicks Refresh. Documented in docs/PRIVACY.md §3.2 alongside the RDAP
# bootstrap, which already fetches from the same host (non-negotiable #17).
SOURCE_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
_FETCH_TIMEOUT_SECONDS = 20.0

# ── Download guard ───────────────────────────────────────────────────
# A truncated or wrong-shaped payload must be REJECTED, never stored: the
# effective list is what separates "public" from "undelegated", so storing
# a 3-line download would relabel every real zone in the estate as
# undelegated at once, in one action, with no error anywhere.
MIN_TLDS = 1000
SENTINEL_TLDS = ("com", "net", "org", "arpa")


class TldPayloadError(ValueError):
    """A downloaded TLD list failed the shape guard and must not be stored."""


class TldFetchError(RuntimeError):
    """The TLD list could not be downloaded at all."""


def parse_tld_payload(text: str) -> tuple[str, list[str]]:
    """Parse IANA's ``tlds-alpha-by-domain.txt`` → ``(version, tlds)``.

    The first line carries ``# Version YYYYMMDDNN``; the rest are uppercase
    A-labels, one per line. TLDs come back lowercased and de-duplicated so
    an ``xn--`` entry matches a ``validate_fqdn``-normalised zone name with
    a plain set lookup.

    Raises :class:`TldPayloadError` when the payload has no version header,
    is shorter than :data:`MIN_TLDS`, or is missing a sentinel TLD.
    """
    version = ""
    tlds: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            if not version and "version" in line.lower():
                parts = line.lstrip("#").strip().split()
                if len(parts) >= 2 and parts[0].lower() == "version":
                    version = parts[1].rstrip(",")
            continue
        tlds.append(line.lower())

    if not version:
        raise TldPayloadError("payload has no '# Version' header")
    unique = sorted(set(tlds))
    if len(unique) < MIN_TLDS:
        raise TldPayloadError(
            f"payload lists only {len(unique)} TLDs, expected at least {MIN_TLDS} — "
            "refusing to store a truncated download"
        )
    missing = [t for t in SENTINEL_TLDS if t not in unique]
    if missing:
        raise TldPayloadError(f"payload is missing sentinel TLD(s): {', '.join(missing)}")
    return version, unique


# ── Resolved registry ────────────────────────────────────────────────


@dataclass(frozen=True)
class TldRegistry:
    """The effective TLD list plus where it came from."""

    tlds: frozenset[str]
    version: str
    fetched_at: datetime | None
    source: str
    origin: str  # "bundled" | "snapshot"

    @property
    def count(self) -> int:
        return len(self.tlds)

    @property
    def age_days(self) -> int | None:
        """Whole days since ``fetched_at``; ``None`` when unknown."""
        if self.fetched_at is None:
            return None
        stamped = self.fetched_at
        if stamped.tzinfo is None:
            stamped = stamped.replace(tzinfo=UTC)
        return max(0, (datetime.now(UTC) - stamped).days)


def _parse_stamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None


@lru_cache(maxsize=1)
def _load_data_file() -> dict[str, Any]:
    raw = files("app.data").joinpath(_DATA_FILE).read_text()
    payload: dict[str, Any] = json.loads(raw)
    return payload


@lru_cache(maxsize=1)
def load_bundled() -> TldRegistry:
    """The TLD list shipped with this release. Never fails: an install with
    no outbound access still classifies zones."""
    payload = _load_data_file()
    return TldRegistry(
        tlds=frozenset(str(t).lower() for t in payload.get("tlds", [])),
        version=str(payload.get("version", "")),
        fetched_at=_parse_stamp(payload.get("fetched_at")),
        source=str(payload.get("source", "")),
        origin="bundled",
    )


def load_special_use() -> tuple[dict[str, Any], ...]:
    """The hand-curated special-use suffix table.

    Deliberately *not* overridable by a snapshot: these entries change by
    RFC and by ICANN action, not by anything in IANA's root-zone download.
    """
    payload = _load_data_file()
    entries = payload.get("special_use", [])
    return tuple(e for e in entries if isinstance(e, dict) and e.get("suffix"))


def _version_sort_key(version: str) -> tuple[int, int | str]:
    """IANA versions are ``YYYYMMDDNN``. Compare numerically when both
    sides parse, and fall back to a string compare otherwise — never
    crash on an unexpected shape, and never let an unparseable snapshot
    version silently outrank a numeric bundled one."""
    v = version.strip()
    if v.isascii() and v.isdigit():
        return (1, int(v))
    return (0, v)


def resolve_effective(bundled: TldRegistry, snapshot: TldRegistry | None) -> TldRegistry:
    """Pick the effective registry: the snapshot only when it is newer."""
    if snapshot is None or not snapshot.tlds:
        return bundled
    if _version_sort_key(snapshot.version) > _version_sort_key(bundled.version):
        return snapshot
    return bundled


# ── DB-backed effective registry, with a short TTL cache ─────────────
# The snapshot changes only when an operator clicks Refresh, and the
# payload is a ~1,400-entry array we would otherwise re-parse on every
# zone-list request. A 60 s TTL keeps that off the hot path; the node
# that performs the refresh invalidates locally so its own next read is
# immediate, and any other api / worker process converges within the TTL.

_CACHE_TTL_SECONDS = 60.0
# Two globals rather than one tuple, matching ``core.maintenance_mode`` and
# ``services.feature_modules`` — the codebase's other two TTL caches.
_cache_loaded_at: float = 0.0
_cached_registry: TldRegistry | None = None


def invalidate_effective_cache() -> None:
    """Drop the cached effective registry (called after a refresh, and by
    the test suite's global-cache reset).

    Clears the value rather than zeroing the timestamp: ``time.monotonic()``
    has an arbitrary epoch, so a "stale" sentinel of ``0.0`` would still
    look fresh for the first 60 s of whatever that epoch counts from.
    """
    global _cached_registry  # noqa: PLW0603
    _cached_registry = None


async def load_snapshot(db: AsyncSession) -> TldRegistry | None:
    """Read the stored snapshot row, or ``None`` when nothing is stored."""
    from sqlalchemy import select

    from app.models.dns import TLDRegistrySnapshot

    row = (await db.execute(select(TLDRegistrySnapshot).limit(1))).scalar_one_or_none()
    if row is None:
        return None
    return TldRegistry(
        tlds=frozenset(str(t).lower() for t in (row.tlds or [])),
        version=row.version or "",
        fetched_at=row.fetched_at,
        source=row.source or "",
        origin="snapshot",
    )


async def effective_registry(db: AsyncSession) -> TldRegistry:
    """The list zone classification should use right now.

    Always cached. A caller that needs the uncached truth — the registry
    card, which reports both candidates — reads ``load_bundled()`` and
    ``load_snapshot()`` directly instead.
    """
    global _cache_loaded_at, _cached_registry  # noqa: PLW0603

    now = time.monotonic()
    if _cached_registry is not None and now - _cache_loaded_at < _CACHE_TTL_SECONDS:
        return _cached_registry

    _cached_registry = resolve_effective(load_bundled(), await load_snapshot(db))
    _cache_loaded_at = now
    return _cached_registry


# ── Operator-triggered refresh ───────────────────────────────────────


async def fetch_remote_payload() -> tuple[str, list[str]]:
    """Download IANA's list and run it through the guard.

    ``httpx`` is imported inside the function on purpose: this module is
    loaded by file path from ``scripts/refresh_iana_tlds.py`` (see the
    module docstring), and a top-level third-party import would break that.

    Raises :class:`TldFetchError` when the host is unreachable or answers
    non-200, and :class:`TldPayloadError` when the body is the wrong shape.
    The caller writes nothing in either case, so the previous snapshot —
    and, failing that, the bundled list — stays in force.
    """
    import httpx

    from app.core.exc_text import describe_http_exc

    try:
        async with httpx.AsyncClient(timeout=_FETCH_TIMEOUT_SECONDS) as client:
            resp = await client.get(SOURCE_URL)
    except httpx.HTTPError as exc:
        raise TldFetchError(f"could not reach {SOURCE_URL}: {describe_http_exc(exc)}") from exc
    if resp.status_code != 200:
        raise TldFetchError(f"{SOURCE_URL} answered HTTP {resp.status_code}")
    return parse_tld_payload(resp.text)


async def store_snapshot(db: AsyncSession, version: str, tlds: list[str]) -> TldRegistry:
    """Upsert the singleton snapshot row. Does not commit — the caller
    writes the audit row and commits both together."""
    from app.models.dns import TLDRegistrySnapshot

    row = await db.get(TLDRegistrySnapshot, 1)
    fetched = datetime.now(UTC)
    if row is None:
        row = TLDRegistrySnapshot(id=1)
        db.add(row)
    row.source = SOURCE_URL
    row.version = version
    row.fetched_at = fetched
    row.tlds = tlds
    await db.flush()

    # NOTE: the cache is deliberately NOT invalidated here. This function
    # has only flushed — the caller still has to commit, and dropping the
    # cache before that opens a window where a concurrent request in this
    # same process misses the cache, reads the row as it was BEFORE the
    # refresh (the write is not visible to another session yet), and
    # re-caches the stale list for a further 60 s. The settings card would
    # then report the new version while every zone pill, importer preview
    # and MCP read still classified against the old one — including the
    # frontend's own refetch immediately after the button click.
    # ``refresh_tld_registry`` invalidates after ``db.commit()``.
    return TldRegistry(
        tlds=frozenset(tlds),
        version=version,
        fetched_at=fetched,
        source=SOURCE_URL,
        origin="snapshot",
    )
