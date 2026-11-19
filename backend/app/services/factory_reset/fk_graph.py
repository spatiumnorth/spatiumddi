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
             FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord)
             JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
            ORDER BY k.ord
       ) AS cols,
       ARRAY(
           SELECT a.attname::text
             FROM unnest(c.confkey) WITH ORDINALITY AS k(attnum, ord)
             JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.attnum
            ORDER BY k.ord
       ) AS ref_cols
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
    # The referenced columns, positionally matching ``columns``.
    ref_columns: tuple[str, ...] = ()


def edges_from_rows(rows: Iterable[Any]) -> list[FKEdge]:
    """Build edges from ``FK_EDGES_SQL`` result rows."""
    return [
        FKEdge(
            child=r["child"],
            parent=r["parent"],
            ondelete=_DELTYPE.get(r["deltype"], "NO ACTION"),
            columns=tuple(r["cols"]),
            ref_columns=tuple(r["ref_cols"]),
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
                    columns=tuple(el.parent.name for el in fk.elements),
                    ref_columns=tuple(el.column.name for el in fk.elements),
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
    """Keys that CAN make a ``DELETE`` of ``tables`` fail: a
    ``RESTRICT`` / ``NO ACTION`` key into one of them **or into a table
    their cascade reaches** (a cascaded delete is refused exactly like
    a direct one), held by any table the wipe does not empty outright.
    That includes a table the cascade only partly removes: an
    operator's subnet under an integration-owned block survives the
    Integrations reset, and its ``RESTRICT`` key refuses the block's
    delete. Whether a key DOES refuse is a row question —
    :func:`blocking_count_queries` counts it."""
    edge_list = list(edges)
    members = set(tables)
    wiped = members | cascade_closure(edge_list, members)
    return [
        e
        for e in edge_list
        if e.ondelete in ("RESTRICT", "NO ACTION") and e.parent in wiped and e.child not in members
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


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


class _DeletedRows:
    """Builds SQL predicates selecting exactly the rows a ``DELETE`` of
    every row in ``tables`` removes from a table its ``ON DELETE
    CASCADE`` keys reach (or the table's rows, for ``tables`` itself).

    Exact, not an upper bound: a row two hops away goes only when the
    row it hangs off goes. A self-referencing cascade
    (``ip_block.parent_block_id``) is followed with a recursive CTE. A
    cascade cycle through two tables (none in the schema today) cannot
    be expressed this way; :meth:`pred` returns None for it and callers
    fall back to an over-count.
    """

    def __init__(self, edges: Iterable[FKEdge], tables: Iterable[str]) -> None:
        edge_list = list(edges)
        self.own = set(tables)
        self.reach = cascade_closure(edge_list, self.own)
        self.casc = [e for e in edge_list if e.ondelete == "CASCADE"]
        self._n = 0

    def fresh(self) -> str:
        self._n += 1
        return f"t{self._n}"

    @staticmethod
    def cols(alias: str, names: tuple[str, ...]) -> str:
        return "(" + ", ".join(f"{alias}.{_q(c)}" for c in names) + ")"

    def keys_removed(self, parent: str, ref_columns: tuple[str, ...]) -> str | None:
        """``SELECT <ref_columns> FROM parent`` restricted to the rows
        the wipe removes, or None when that cannot be expressed."""
        sub = self.fresh()
        inner = self.pred(parent, sub)
        if inner is None:
            return None
        return (
            "SELECT "
            + ", ".join(f"{sub}.{_q(c)}" for c in ref_columns)
            + f" FROM {_q(parent)} {sub} WHERE {inner}"
        )

    def key_removed(self, edge: FKEdge, alias: str) -> str | None:
        """Predicate on ``edge.child`` (as ``alias``): the row's key
        points at a row of ``edge.parent`` the wipe removes."""
        if edge.parent in self.own:
            return "(" + " AND ".join(f"{alias}.{_q(c)} IS NOT NULL" for c in edge.columns) + ")"
        sub = self.keys_removed(edge.parent, edge.ref_columns)
        if sub is None:
            return None
        return f"{self.cols(alias, edge.columns)} IN ({sub})"

    def _base(self, table: str, alias: str, stack: frozenset[str]) -> str | None:
        terms: list[str] = []
        for e in self.casc:
            if e.child != table or e.parent == table:
                continue
            if e.parent not in self.own and e.parent not in self.reach:
                continue
            if e.parent in stack | {table}:
                return None  # a cascade cycle through another table
            if e.parent in self.own:
                term = self.key_removed(e, alias)
            else:
                sub = self.fresh()
                inner = self.pred(e.parent, sub, stack | {table})
                term = (
                    None
                    if inner is None
                    else f"{self.cols(alias, e.columns)} IN (SELECT "
                    + ", ".join(f"{sub}.{_q(c)}" for c in e.ref_columns)
                    + f" FROM {_q(e.parent)} {sub} WHERE {inner})"
                )
            if term is None:
                return None
            terms.append(term)
        return " OR ".join(terms) if terms else "FALSE"

    def pred(self, table: str, alias: str, stack: frozenset[str] = frozenset()) -> str | None:
        if table in self.own:
            return "TRUE"
        selfs = [e for e in self.casc if e.child == table and e.parent == table]
        if not selfs:
            return self._base(table, alias, stack)
        # Rows removed directly, plus every descendant of one through a
        # self-referencing CASCADE key.
        keys = tuple(dict.fromkeys(c for e in selfs for c in e.ref_columns))
        seed_alias, step_alias, cte = self.fresh(), self.fresh(), self.fresh()
        seed = self._base(table, seed_alias, stack)
        if seed is None:
            return None
        # One recursive term joining on any of the self keys (Postgres
        # allows the CTE to be referenced only once in it).
        step_on = " OR ".join(
            "("
            + " AND ".join(
                f"{step_alias}.{_q(c)} = {cte}.{_q(r)}"
                for c, r in zip(e.columns, e.ref_columns, strict=True)
            )
            + ")"
            for e in selfs
        )
        key_list = ", ".join(_q(k) for k in keys)
        return (
            f"{self.cols(alias, keys)} IN (WITH RECURSIVE {cte}({key_list}) AS ("
            "SELECT "
            + ", ".join(f"{seed_alias}.{_q(k)}" for k in keys)
            + f" FROM {_q(table)} {seed_alias} WHERE {seed} UNION SELECT "
            + ", ".join(f"{step_alias}.{_q(k)}" for k in keys)
            + f" FROM {_q(table)} {step_alias} JOIN {cte} ON {step_on}"
            f") SELECT {key_list} FROM {cte})"
        )

    def overcount(self, table: str, alias: str) -> str:
        keyed = sorted(
            {
                c
                for e in self.casc
                if e.child == table and (e.parent in self.own or e.parent in self.reach)
                for c in e.columns
            }
        )
        return " OR ".join(f"{alias}.{_q(c)} IS NOT NULL" for c in keyed) or "FALSE"


def dependent_count_queries(edges: Iterable[FKEdge], tables: Iterable[str]) -> dict[str, str]:
    """Per table in ``cascade_closure(edges, tables)``, a ``SELECT
    COUNT(*)`` of exactly the rows a ``DELETE`` of every row in
    ``tables`` takes with it through ``ON DELETE CASCADE`` keys.

    Integrations shows why exact matters: an integration-owned zone
    takes its records, but counting every ``dns_record`` with a zone
    would put the operator's whole estate on the card.
    """
    rows = _DeletedRows(edges, tables)
    out: dict[str, str] = {}
    for dep in sorted(rows.reach):
        alias = rows.fresh()
        p = rows.pred(dep, alias)
        if p is None:
            p = rows.overcount(dep, alias)
        out[dep] = f"SELECT COUNT(*) FROM {_q(dep)} {alias} WHERE {p}"
    return out


def blocking_count_queries(
    edges: Iterable[FKEdge], tables: Iterable[str]
) -> list[tuple[FKEdge, str]]:
    """Per :func:`blocking_edges` key, a ``SELECT COUNT(*)`` of the
    referencing rows that would actually refuse the wipe: those whose
    key points at a row the wipe removes. A key into a table reached
    only through a cascade must not refuse the reset over a row whose
    parent survives."""
    edge_list = list(edges)
    rows = _DeletedRows(edge_list, tables)
    out: list[tuple[FKEdge, str]] = []
    for e in blocking_edges(edge_list, tables):
        alias = rows.fresh()
        p = rows.key_removed(e, alias)
        if p is None:
            p = " OR ".join(f"{alias}.{_q(c)} IS NOT NULL" for c in e.columns)
        if e.child in rows.reach:
            # Partly removed itself: only a SURVIVING row refuses.
            gone = rows.pred(e.child, alias)
            if gone is not None:
                p = f"({p}) AND NOT ({gone})"
        out.append((e, f"SELECT COUNT(*) FROM {_q(e.child)} {alias} WHERE {p}"))
    return out
