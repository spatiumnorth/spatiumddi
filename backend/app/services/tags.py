"""Shared tag-filter helper for REST list endpoints + the AI ``find_by_tag``
tool (issue #104).

Tags live on a JSONB ``tags`` column on every operator-managed model
(IPAM space / block / subnet / IP, DNS zones + records, DHCP scopes,
network devices, ASNs, VRFs, domains, circuits, services, overlays).
This module is the single place that translates the wire-level
``?tag=key:value`` query syntax into SQLAlchemy WHERE clauses against
those columns. Whatever Postgres-side semantics we change here (case
folding, operator choice, GIN-index hints) propagate to every caller
in one diff.

## Wire syntax

Every list endpoint that returns a tagged resource accepts a repeated
``tag`` query parameter:

* ``?tag=env`` — match rows where the ``env`` key is present, any
  value (``tags ? 'env'``).
* ``?tag=env:prod`` — match rows where ``tags['env'] == 'prod'``
  (case-sensitive, ``tags @> '{"env":"prod"}'``).
* ``?tag=env:prod&tag=team:platform`` — multiple ``tag`` params AND
  together; row must match every clause.
* Whitespace-only or empty entries are silently skipped so a
  trailing comma in the operator's URL doesn't 422.

The ``:`` is the *first* split — values containing ``:`` (e.g.
``rfc1918:10.0.0.0/8``) round-trip cleanly because we only split
once.

## Postgres-side mechanics

* Key-only uses the JSONB ``?`` operator (``has_key``).
* Key+value uses ``@>`` (``contains``). This is the form Postgres'
  default JSONB GIN index serves natively, so even on tables with
  10k+ rows the filter is cheap.
* Both expressions are emitted by SQLAlchemy's
  :class:`~sqlalchemy.dialects.postgresql.JSONB` comparator so the
  operator chain matches whatever the column type already is — no
  cast / unwrap dance needed.

The helper is **Postgres-only** — that's fine because SpatiumDDI
runs on Postgres everywhere (alembic migration target, dev
compose, k8s subchart). Don't bend it to SQLite for tests; the
test conftest stands up Postgres in CI.
"""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import Select


def parse_tag_param(raw: str) -> tuple[str, str | None]:
    """Split ``key:value`` into ``(key, value)``; bare ``key`` returns
    ``(key, None)``.

    ``rsplit`` is deliberately *not* used — the first ``:`` is the
    separator so values containing ``:`` (e.g. CIDR-shaped tags like
    ``rfc1918:10.0.0.0/8``) survive the round-trip into the dict
    contains check, where Postgres compares the value byte-for-byte.
    """
    stripped = raw.strip()
    if ":" not in stripped:
        return stripped, None
    key, _, value = stripped.partition(":")
    key = key.strip()
    value = value.strip()
    return key, value or None


def apply_tag_filter[*Ts](
    stmt: Select[*Ts],
    tags_column,
    tag_params: Iterable[str] | None,
) -> Select[*Ts]:
    """ANDs each ``tag=`` query param onto the select as a JSONB clause.

    ``tags_column`` is the actual ORM column (e.g. ``Subnet.tags``)
    rather than the model class — keeps the helper resource-agnostic
    and means the caller can pass either the unbound class attribute
    or any aliased version.

    Empty / whitespace-only entries are skipped so a stray ``&tag=``
    in the URL doesn't fail the request — matches the existing list
    endpoints' tolerance for empty filter params.
    """
    if not tag_params:
        return stmt
    for raw in tag_params:
        if not raw:
            continue
        key, value = parse_tag_param(raw)
        if not key:
            continue
        if value is None:
            stmt = stmt.where(tags_column.has_key(key))
        else:
            stmt = stmt.where(tags_column.contains({key: value}))
    return stmt
