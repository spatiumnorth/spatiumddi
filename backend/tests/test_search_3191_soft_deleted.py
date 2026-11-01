"""Global search must not return soft-deleted rows (#3191)."""

from __future__ import annotations

import importlib
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import and_, or_, select, true
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased
from sqlalchemy.sql import operators, visitors
from sqlalchemy.sql.elements import BinaryExpression, BooleanClauseList, ColumnClause, Null
from sqlalchemy.sql.expression import Select
from sqlalchemy.sql.selectable import Alias, Join, TableClause

from app.core.security import create_access_token, hash_password
from app.db import _get_soft_delete_models
from app.models.auth import User
from app.models.base import Base, SoftDeleteMixin
from app.models.circuit import Circuit
from app.models.ipam import CustomFieldDefinition, IPBlock
from app.models.ownership import Provider, Site
from app.services.search.providers import PROVIDERS
from app.services.search.schemas import shape_of
from tests.test_search import _address, _space, _subnet, _zone_with_record

# Import for side effect: registers every mapper. importlib keeps it from
# binding an unused ``app`` name in this module.
importlib.import_module("app.models")

pytestmark = pytest.mark.asyncio


class _RecordingSession:
    """Delegates to a real session and records every statement it is sent.

    The guard needs real rows behind it: several providers only reach their
    follow-up statements (the subnet / zone breadcrumb, every custom-field
    search) once the first query returns something, so an empty stub would
    leave exactly those statements unchecked.
    """

    def __init__(self, inner: AsyncSession) -> None:
        self._inner = inner
        self.statements: list[Any] = []

    async def execute(self, stmt: Any, *a: Any, **kw: Any) -> Any:
        self.statements.append(stmt)
        return await self._inner.execute(stmt, *a, **kw)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def _soft_delete_mappers() -> list[type]:
    return [
        m.class_
        for m in Base.registry.mappers
        if issubclass(m.class_, SoftDeleteMixin) and hasattr(m.class_, "__tablename__")
    ]


def _uncovered_models() -> list[type]:
    """Soft-deletable models the global ORM filter in ``app.db`` does not
    cover: every read of one of these must carry its own clause."""
    covered = set(_get_soft_delete_models())
    return [m for m in _soft_delete_mappers() if m not in covered]


def _leaves(from_obj: Any) -> list[Any]:
    """The tables and aliases under a FROM item, joins flattened."""
    if isinstance(from_obj, Join):
        return _leaves(from_obj.left) + _leaves(from_obj.right)
    return [from_obj]


def _table_name(leaf: Any) -> str | None:
    """Underlying table of a FROM leaf (``None`` for a derived table)."""
    if isinstance(leaf, Alias):
        return _table_name(leaf.element)
    return leaf.name if isinstance(leaf, TableClause) else None


def _conjuncts(clause: Any) -> list[Any]:
    """Top-level AND terms of a WHERE clause: ``a AND (b AND c)`` is three,
    while ``a OR b`` is one."""
    if clause is None:
        return []
    if isinstance(clause, BooleanClauseList) and clause.operator is operators.and_:
        return [t for c in clause.clauses for t in _conjuncts(c)]
    return [clause]


def _is_live_only(term: Any, leaf: Any) -> bool:
    """``term`` is exactly ``<leaf>.deleted_at IS NULL``."""
    return (
        isinstance(term, BinaryExpression)
        and term.operator is operators.is_
        and isinstance(term.right, Null)
        and isinstance(term.left, ColumnClause)
        and term.left.name == "deleted_at"
        # Annotated ORM columns are copies, so match the FROM item by name
        # (an alias's name is unique to it).
        and getattr(term.left.table, "name", None) == getattr(leaf, "name", object())
    )


def _selects(stmt: Any) -> list[Select]:
    return [n for n in visitors.iterate(stmt) if isinstance(n, Select)]


def _reads(stmt: Any, tables: list[str]) -> list[str]:
    """Names from ``tables`` that some SELECT inside ``stmt`` reads."""
    return [
        t
        for sel in _selects(stmt)
        for leaf in (x for f in sel.get_final_froms() for x in _leaves(f))
        if (t := _table_name(leaf)) in tables
    ]


def _unfiltered_reads(stmt: Any, tables: list[str]) -> list[str]:
    """Reads of ``tables`` (FROM or JOIN, aliased or not, in the statement
    or any subquery) whose own SELECT does not AND ``deleted_at IS NULL`` for
    that very table or alias into its WHERE. A predicate under an OR, or in a
    different subquery, does not count: it does not exclude the row.

    This is deliberately about the statement tree, not its SQL text, so it
    does not depend on how the compiler spells anything. Stated limit: a
    clause carried in a JOIN's ON is not recognised, so a legitimate outer
    join written that way is a loud false positive rather than a silent miss.
    """
    leaks: list[str] = []
    for sel in _selects(stmt):
        terms = _conjuncts(sel.whereclause)
        for leaf in (x for f in sel.get_final_froms() for x in _leaves(f)):
            table = _table_name(leaf)
            if table in tables and not any(_is_live_only(t, leaf) for t in terms):
                leaks.append(table)
    return leaks


async def test_unfiltered_read_detector_flags_a_bare_read() -> None:
    """Negative controls for the guard below. For Circuit and every other
    uncovered model: a bare read, an aliased read, a join, a predicate under
    an OR, a predicate only in a sibling subquery, and a predicate on another
    table are all flagged; filtered reads (plain, ANDed with other terms,
    aliased, joined) are not."""
    for model in {Circuit, *_uncovered_models()}:
        table = model.__tablename__
        alias = aliased(model)
        live = model.deleted_at.is_(None)
        flagged = {
            "bare": select(model),
            "aliased": select(alias),
            "join": select(Provider).join(model, true()),
            "or": select(model).where(or_(live, model.id.is_not(None))),
            "or-in-and": select(model).where(model.id.is_not(None), or_(live, true())),
            "other-subquery": select(model).where(
                model.id.in_(select(model.id).where(model.deleted_at.is_(None)))
            ),
            "other-alias": select(model).where(aliased(model).deleted_at.is_(None)),
            "alias-filtered-by-base": select(alias).where(live),
        }
        for label, stmt in flagged.items():
            assert table in _unfiltered_reads(stmt, [table]), (table, label)
        clean = {
            "plain": select(model).where(live),
            "anded": select(model).where(model.id.is_not(None), live),
            "nested-and": select(model).where(and_(model.id.is_not(None), and_(live, true()))),
            "aliased": select(alias).where(alias.deleted_at.is_(None)),
            "joined": select(Provider).join(model, true()).where(live),
            "subquery": select(Provider).where(Provider.id.in_(select(model.id).where(live))),
        }
        for label, stmt in clean.items():
            assert _unfiltered_reads(stmt, [table]) == [], (table, label)


async def _seed(db: AsyncSession, tag: str) -> None:
    """One live row behind every provider that has a follow-up statement."""
    for rtype in ("ip_block", "subnet", "ip_address"):
        db.add(
            CustomFieldDefinition(
                resource_type=rtype,
                name=f"f{rtype}",
                label=rtype,
                field_type="text",
                is_searchable=True,
            )
        )
    space = await _space(db, tag)
    subnet = await _subnet(db, space, "10.91.0.0/24", name=tag, custom_fields={"fsubnet": tag})
    block = await db.get(IPBlock, subnet.block_id)
    block.name = tag
    block.custom_fields = {"fip_block": tag}
    await _address(
        db,
        subnet,
        "10.91.0.5",
        hostname=tag,
        mac_address="aa:bb:cc:dd:ee:ff",
        custom_fields={"fip_address": tag},
    )
    await _zone_with_record(db, f"{tag}.example.com", f"{tag}.example.com", "10.91.0.5")
    await db.flush()


async def test_every_provider_filters_soft_deletable_models(db_session: AsyncSession) -> None:
    """Structural guard over the provider registry.

    A soft-deletable model is safe in a search query only when the global
    ORM filter in ``app.db`` covers it, or the statement carries its own
    ``deleted_at IS NULL`` ANDed into the WHERE of the SELECT that reads it.
    Anything else leaks a deleted row into search. Providers run against
    real seeded rows, so their follow-up statements are sent and inspected
    too, and the checks at the end fail the test if one stops being sent.

    Why the statement tree and not a DB behaviour test per provider: a
    behavioural test needs a deleted row seeded for each of ~20 providers
    and says nothing about a provider added later, whereas this reads every
    statement a provider sends. The deleted-circuit behaviour tests below
    cover the end-to-end half for the model that was actually broken.
    """
    tag = "g3191"
    await _seed(db_session, tag)
    tables = [m.__tablename__ for m in _uncovered_models()]
    offenders: list[str] = []
    sent_by: dict[str, list[Any]] = {}
    for provider in PROVIDERS:
        sent = sent_by.setdefault(provider.type, [])
        for q in (tag, "10.91.0.5", "10.91.0.0/24", "aa:bb:cc:dd:ee:ff"):
            db = _RecordingSession(db_session)
            await provider.fn(db, shape_of(q), 5)  # type: ignore[arg-type]
            sent += db.statements
            for stmt in db.statements:
                for table in _unfiltered_reads(stmt, tables):
                    offenders.append(f"{provider.type} -> {table}")
        assert sent, f"provider {provider.type} sent no statement"
    assert not offenders, sorted(set(offenders))

    # Non-vacuity: the follow-up statements really ran.
    cf = ["ip_block", "subnet", "ip_address"]
    for provider_type, tables_read in {
        "custom_field": ["custom_field_definition", *cf],
        "ip_address": ["subnet", "ip_space"],
        "dns_record": ["dns_zone", "dns_server_group"],
    }.items():
        seen = {t for st in sent_by[provider_type] for t in _reads(st, tables_read)}
        assert seen == set(tables_read), (provider_type, seen)


async def test_search_hides_a_deleted_circuit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"a-{tag}",
        email=f"{tag}@t.io",
        display_name="a",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    prov = Provider(name=f"prov-{tag}", kind="carrier")
    db_session.add_all([user, prov])
    await db_session.flush()
    ckt = Circuit(name=f"wan-{tag}", ckt_id=f"CKT-{tag}", provider_id=prov.id)
    db_session.add(ckt)
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}

    for q in (f"wan-{tag}", f"CKT-{tag}"):
        r = await client.get("/api/v1/search", params={"q": q, "types": "circuit"}, headers=hdr)
        assert r.status_code == 200, r.text
        assert [x["id"] for x in r.json()["results"]] == [str(ckt.id)], q

    ckt.deleted_at = datetime.now(UTC)
    await db_session.commit()

    for q in (f"wan-{tag}", f"CKT-{tag}"):
        r = await client.get("/api/v1/search", params={"q": q, "types": "circuit"}, headers=hdr)
        assert r.status_code == 200, r.text
        assert r.json()["results"] == [], q


async def test_overlay_paths_ignore_a_deleted_circuit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The overlay site's preferred-circuit check and the simulation's name
    lookup read Circuit by id, so they need the live-only clause too."""
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"o-{tag}",
        email=f"o{tag}@t.io",
        display_name="o",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    prov = Provider(name=f"oprov-{tag}", kind="carrier")
    s1, s2 = Site(name=f"s1-{tag}"), Site(name=f"s2-{tag}")
    db_session.add_all([user, prov, s1, s2])
    await db_session.flush()
    ckt = Circuit(name=f"ockt-{tag}", provider_id=prov.id)
    db_session.add(ckt)
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}

    r = await client.post("/api/v1/overlays", json={"name": f"ovl-{tag}"}, headers=hdr)
    assert r.status_code == 201, r.text
    ovl = r.json()["id"]
    r = await client.post(
        f"/api/v1/overlays/{ovl}/sites",
        json={"site_id": str(s1.id), "preferred_circuits": [str(ckt.id)]},
        headers=hdr,
    )
    assert r.status_code == 201, r.text

    async def _primary_name() -> str | None:
        r = await client.post(f"/api/v1/overlays/{ovl}/simulate", json={}, headers=hdr)
        assert r.status_code == 200, r.text
        (site,) = r.json()["site_resolutions"]
        return site["primary_circuit_name"]

    assert await _primary_name() == ckt.name  # positive control

    r = await client.delete(f"/api/v1/circuits/{ckt.id}", headers=hdr)
    assert r.status_code == 204, r.text

    assert await _primary_name() is None
    r = await client.post(
        f"/api/v1/overlays/{ovl}/sites",
        json={"site_id": str(s2.id), "preferred_circuits": [str(ckt.id)]},
        headers=hdr,
    )
    assert r.status_code == 422, r.text
    assert str(ckt.id) in r.json()["detail"]


async def test_simulation_keeps_a_deleted_circuits_transport_class(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A deleted circuit is hidden by name but still counts for policy
    comparison: taking it down must still flag a ``steer_to_transport_class``
    policy as impacted, not report it unaffected while the site blackholes."""
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"p-{tag}",
        email=f"p{tag}@t.io",
        display_name="p",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    prov = Provider(name=f"pprov-{tag}", kind="carrier")
    site = Site(name=f"ps-{tag}")
    db_session.add_all([user, prov, site])
    await db_session.flush()
    ckt = Circuit(name=f"pckt-{tag}", provider_id=prov.id, transport_class="mpls")
    db_session.add(ckt)
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}

    r = await client.post("/api/v1/overlays", json={"name": f"povl-{tag}"}, headers=hdr)
    ovl = r.json()["id"]
    r = await client.post(
        f"/api/v1/overlays/{ovl}/sites",
        json={"site_id": str(site.id), "preferred_circuits": [str(ckt.id)]},
        headers=hdr,
    )
    assert r.status_code == 201, r.text
    r = await client.post(
        f"/api/v1/overlays/{ovl}/policies",
        json={
            "name": "voice",
            "match_kind": "dscp",
            "match_value": "EF",
            "action": "steer_to_transport_class",
            "action_target": "mpls",
        },
        headers=hdr,
    )
    assert r.status_code == 201, r.text

    async def _simulate() -> dict[str, Any]:
        r = await client.post(
            f"/api/v1/overlays/{ovl}/simulate",
            json={"down_circuits": [str(ckt.id)]},
            headers=hdr,
        )
        assert r.status_code == 200, r.text
        return r.json()

    before = await _simulate()
    assert before["policy_resolutions"][0]["impacted"] is True  # positive control

    r = await client.delete(f"/api/v1/circuits/{ckt.id}", headers=hdr)
    assert r.status_code == 204, r.text

    after = await _simulate()
    assert after["policy_resolutions"][0]["impacted"] is True
    (res,) = after["site_resolutions"]
    assert res["blackholed"] is True
    assert res["primary_circuit_name"] is None
