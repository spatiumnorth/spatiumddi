"""Foreign-key graph helpers for the factory reset (#1835).

``TRUNCATE … CASCADE`` empties every table with a foreign key into a
truncated table, recursively, **whatever the key's ``ON DELETE``
rule** — so the Tools section's ``TRUNCATE nmap_scan CASCADE`` reached
``ip_address`` (``last_profile_scan_id``, ``ON DELETE SET NULL``) and,
through it, every DNS record and DHCP static in the install.

The reset now removes rows the way the schema says deletion works:

* a table nothing outside the wipe references is ``TRUNCATE``d (no
  ``CASCADE`` — Postgres refuses instead of reaching further), which
  keeps the multi-million-row log tables fast;
* everything else is ``DELETE``d, children first, so an
  ``ON DELETE SET NULL`` key is nulled and the referencing row
  survives. Only an ``ON DELETE CASCADE`` key removes a row outside
  the section, and each section declares those tables
  (``cascade_dependents``) so the preview names them.

Everything here is pure (edges in, tables out) so the live database
and the SQLAlchemy metadata share one implementation — see
``tests/test_factory_reset_fk_cascade.py``.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

# pg_constraint.confdeltype → the rule name SQLAlchemy uses.
_DELTYPE = {"a": "NO ACTION", "r": "RESTRICT", "c": "CASCADE", "n": "SET NULL", "d": "SET DEFAULT"}

# Every foreign key in the public schema: child, parent, delete rule,
# child columns. Partitions of a partitioned table inherit their
# parent's keys, so only ``conparentid = 0`` rows are listed.
FK_EDGES_SQL = """
SELECT cl.relname AS child,
       pl.relname AS parent,
       c.confdeltype::text AS deltype,
       ARRAY(
           SELECT a.attname::text
             FROM pg_attribute a
            WHERE a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
       ) AS cols
  FROM pg_constraint c
  JOIN pg_class cl ON cl.oid = c.conrelid
  JOIN pg_class pl ON pl.oid = c.confrelid
  JOIN pg_namespace n ON n.oid = cl.relnamespace
 WHERE c.contype = 'f' AND n.nspname = 'public' AND c.conparentid = 0
"""


@dataclass(frozen=True)
class FKEdge:
    child: str
    parent: str
    ondelete: str  # "CASCADE" | "SET NULL" | "RESTRICT" | "NO ACTION" | "SET DEFAULT"
    columns: tuple[str, ...]


def edges_from_rows(rows: Iterable[Any]) -> list[FKEdge]:
    """Build edges from ``FK_EDGES_SQL`` result rows."""
    return [
        FKEdge(
            child=r["child"],
            parent=r["parent"],
            ondelete=_DELTYPE.get(r["deltype"], "NO ACTION"),
            columns=tuple(r["cols"]),
        )
        for r in rows
    ]


def edges_from_metadata(metadata: Any) -> list[FKEdge]:
    """Build edges from SQLAlchemy ``MetaData`` (what the tests use)."""
    out: list[FKEdge] = []
    for table in metadata.tables.values():
        for fk in table.foreign_key_constraints:
            out.append(
                FKEdge(
                    child=table.name,
                    parent=fk.referred_table.name,
                    ondelete=(fk.ondelete or "NO ACTION").upper(),
                    columns=tuple(c.name for c in fk.columns),
                )
            )
    return out


def cascade_closure(edges: Iterable[FKEdge], tables: Iterable[str]) -> set[str]:
    """Tables OUTSIDE ``tables`` that a ``DELETE`` of every row in
    ``tables`` removes through ``ON DELETE CASCADE`` keys, transitively.
    """
    seed = set(tables)
    by_parent: dict[str, list[FKEdge]] = {}
    for e in edges:
        if e.ondelete == "CASCADE":
            by_parent.setdefault(e.parent, []).append(e)
    seen = set(seed)
    stack = list(seed)
    while stack:
        parent = stack.pop()
        for e in by_parent.get(parent, ()):
            if e.child not in seen:
                seen.add(e.child)
                stack.append(e.child)
    return seen - seed


def blocking_edges(edges: Iterable[FKEdge], tables: Iterable[str]) -> list[FKEdge]:
    """Keys that make a ``DELETE`` of ``tables`` fail: a table neither
    in ``tables`` nor removed by their cascade holds a
    ``RESTRICT`` / ``NO ACTION`` key into one of them."""
    edge_list = list(edges)
    members = set(tables)
    wiped = members | cascade_closure(edge_list, members)
    return [
        e
        for e in edge_list
        if e.ondelete in ("RESTRICT", "NO ACTION") and e.parent in members and e.child not in wiped
    ]


def truncatable(edges: Iterable[FKEdge], tables: Iterable[str]) -> set[str]:
    """The subset of ``tables`` that can be ``TRUNCATE``d without
    ``CASCADE``: no table outside the subset has a key into it (a
    plain TRUNCATE refuses even when the referencing table is empty).
    Computed as a greatest fixed point so a pair that only reference
    each other stays truncatable together."""
    keep = set(tables)
    edge_list = [e for e in edges if e.child != e.parent]
    changed = True
    while changed:
        changed = False
        for e in edge_list:
            if e.parent in keep and e.child not in keep:
                keep.discard(e.parent)
                changed = True
    return keep


def delete_order(edges: Iterable[FKEdge], tables: Iterable[str]) -> list[str]:
    """Order ``tables`` for ``DELETE`` so a table holding a
    ``RESTRICT`` / ``NO ACTION`` key into another goes first. Stable
    with respect to the input order; a cycle falls back to input order
    for the remainder (the database then reports the violation)."""
    ordered_in = list(dict.fromkeys(tables))
    members = set(ordered_in)
    # parent -> children that must be deleted before it
    before: dict[str, set[str]] = {t: set() for t in ordered_in}
    for e in edges:
        if (
            e.ondelete in ("RESTRICT", "NO ACTION")
            and e.child != e.parent
            and e.child in members
            and e.parent in members
        ):
            before[e.parent].add(e.child)
    out: list[str] = []
    done: set[str] = set()
    remaining = list(ordered_in)
    while remaining:
        progressed = False
        for t in list(remaining):
            if before[t] <= done:
                out.append(t)
                done.add(t)
                remaining.remove(t)
                progressed = True
        if not progressed:
            out.extend(remaining)
            break
    return out
