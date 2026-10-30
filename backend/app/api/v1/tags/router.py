"""Tag autocomplete endpoints (issue #104 phase 2).

Powers the typeahead behind the upcoming UI tag-chip — the
frontend hits ``GET /tags/keys`` while the operator is typing a
key, and ``GET /tags/values?key=env`` once they've entered a key
and are picking the value side.

## Cross-table aggregation

Both endpoints UNION ALL across every model that carries a JSONB
``tags`` column:

* IPAM — ``ip_space``, ``ip_block``, ``subnet``, ``ip_address``
* Network modeling — ``asn``, ``vrf``, ``network_device``,
  ``domain``, ``circuit``, ``network_service``, ``overlay_network``

The list is intentionally hardcoded here (not derived) so a future
``tags`` column on a new model is an explicit one-line opt-in
rather than silently expanding the autocomplete surface — autocomplete
discoverability has compliance implications (operators see "what
tag keys exist on this platform"), so an explicit list is safer.

The same set is what :func:`app.services.tags.apply_tag_filter`'s
callers wire into their ``tag=`` query params, so the autocomplete
options always match what the filter can actually act on.

## Postgres mechanics

* ``jsonb_object_keys(tags)`` unrolls each row's keys to one row
  per key — set-returning function, runs against the JSONB GIN
  index on each table's ``tags`` column.
* ``tags ->> 'key'`` extracts the value as text (numbers /
  booleans collapse to their printable form; nested objects come
  back as JSON-stringified text — which is fine for autocomplete
  display but operators won't be able to match on nested
  structures from the UI chip; that limitation is by design for
  v1).
* Outer ``DISTINCT`` + ``ORDER BY`` produces a stable list. No
  pagination — autocomplete is single-shot, capped via ``limit``.

## Authorization

Each table contributes only for a caller who may read its rows through
that table's own router (``_TABLE_READ_TYPES``), so the autocomplete never
offers a tag the caller could not already see on a row. A caller who can
read none of them gets an empty list rather than a 403, so the chip simply
offers nothing.
"""

from __future__ import annotations

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.deps import DB, CurrentUser
from app.core.permissions import user_has_permission

router = APIRouter()


# Hardcoded — see module docstring for why this isn't derived.
# Order is alphabetical for readable EXPLAIN plans + matches the
# alphabetised router.include_router list.
_TAGGED_TABLES: tuple[str, ...] = (
    "asn",
    "circuit",
    "dhcp_scope",
    "dhcp_static_assignment",
    "dns_record",
    "dns_zone",
    "domain",
    "ip_address",
    "ip_block",
    "ip_space",
    "network_device",
    "network_service",
    "overlay_network",
    "subnet",
    "vrf",
)


# The resource types whose ``read`` opens each table's own router; any one
# of them is enough, as it is there. The IPAM router admits a reader of any
# of its four types; each DNS route needs its own type (#3073).
_IPAM = ("ip_space", "ip_block", "subnet", "ip_address")
_TABLE_READ_TYPES: dict[str, tuple[str, ...]] = {
    "asn": ("manage_asns",),
    "circuit": ("circuit",),
    "dhcp_scope": ("dhcp_scope",),
    "dhcp_static_assignment": ("dhcp_static",),
    "dns_record": ("dns_record",),
    "dns_zone": ("dns_zone",),
    "domain": ("manage_domains",),
    "ip_address": _IPAM,
    "ip_block": _IPAM,
    "ip_space": _IPAM,
    "network_device": ("manage_network_devices",),
    "network_service": ("network_service",),
    "overlay_network": ("overlay_network",),
    "subnet": _IPAM,
    "vrf": ("vrf",),
}


def _readable_tables(user: object) -> list[str]:
    return [
        t
        for t in _TAGGED_TABLES
        if any(user_has_permission(user, "read", rt) for rt in _TABLE_READ_TYPES[t])  # type: ignore[arg-type]
    ]


# ``tags`` is JSONB-typed and non-nullable on every model (default=dict on
# the column), but `jsonb_object_keys(NULL)` raises, so the IS NOT NULL
# guard costs nothing and keeps the query safe if a future migration ever
# loosens the column. Table names come from ``_TAGGED_TABLES`` only.
def _keys_union_sql(tables: list[str]) -> str:
    return " UNION ALL ".join(
        f"SELECT jsonb_object_keys(tags) AS key FROM {t} WHERE tags IS NOT NULL" for t in tables
    )


def _values_union_sql(tables: list[str]) -> str:
    return " UNION ALL ".join(
        f"SELECT tags ->> :key AS value FROM {t} WHERE tags ? :key" for t in tables
    )


class TagKeysResponse(BaseModel):
    keys: list[str] = Field(description="Sorted distinct list of tag keys.")


class TagValuesResponse(BaseModel):
    key: str
    values: list[str] = Field(description="Sorted distinct list of values for the requested key.")


@router.get("/keys", response_model=TagKeysResponse)
async def list_tag_keys(
    db: DB,
    current_user: CurrentUser,
    prefix: str | None = Query(
        None,
        description=(
            "Case-insensitive substring filter on the key name. Pass "
            "the operator's in-flight typeahead chars; empty / null "
            "returns the full set."
        ),
        max_length=200,
    ),
    limit: int = Query(200, ge=1, le=1000),
) -> TagKeysResponse:
    tables = _readable_tables(current_user)
    if not tables:
        return TagKeysResponse(keys=[])
    sql = f"SELECT DISTINCT key FROM ({_keys_union_sql(tables)}) AS sub"
    params: dict[str, object] = {"limit": limit}
    if prefix:
        sql += " WHERE key ILIKE :prefix"
        params["prefix"] = f"%{prefix}%"
    sql += " ORDER BY key LIMIT :limit"
    rows = (await db.execute(text(sql), params)).all()
    return TagKeysResponse(keys=[r.key for r in rows])


@router.get("/values", response_model=TagValuesResponse)
async def list_tag_values(
    db: DB,
    current_user: CurrentUser,
    key: str = Query(
        ...,
        min_length=1,
        max_length=255,
        description="Tag key whose values should be returned.",
    ),
    prefix: str | None = Query(
        None,
        description="Case-insensitive substring filter on the value side.",
        max_length=200,
    ),
    limit: int = Query(200, ge=1, le=1000),
) -> TagValuesResponse:
    # Outer DISTINCT lets duplicates from multiple tables collapse.
    # ``WHERE value IS NOT NULL`` drops rows where the key is
    # explicitly stored as JSON null — the frontend chip can't
    # represent "match the JSON null" anyway, so excluding them
    # keeps the autocomplete tidy.
    tables = _readable_tables(current_user)
    if not tables:
        return TagValuesResponse(key=key, values=[])
    sql = (
        f"SELECT DISTINCT value FROM ({_values_union_sql(tables)}) AS sub "
        "WHERE value IS NOT NULL"
    )
    params: dict[str, object] = {"key": key, "limit": limit}
    if prefix:
        sql += " AND value ILIKE :prefix"
        params["prefix"] = f"%{prefix}%"
    sql += " ORDER BY value LIMIT :limit"
    rows = (await db.execute(text(sql), params)).all()
    return TagValuesResponse(key=key, values=[r.value for r in rows])
