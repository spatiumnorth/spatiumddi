"""Named ACLs reach the agent, ordered and cycle-free (issue #899).

The agent-side rendering of these into ``acl {}`` stanzas is covered by
``agent/dns/tests/test_acl_render.py`` — the agent is a separate package
with its own test job, so it cannot be imported from here.

Before this, `DNSAcl` rows were stored, listed and editable on the ACLs
tab and applied to nothing: the bundle carried `{id, name}` with no
entries, and the agent's BIND9 renderer never emitted an `acl {}` stanza.
Naming one anywhere that reached `named.conf` left an undefined symbol —
`named-checkconf` fails, the agent declines the *whole* bundle, and the
group stops converging rather than just that statement.

So the assertions that matter are: the entries reach the bundle, they come
out in an order BIND can resolve, and a cycle is refused rather than
shipped.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSAcl, DNSAclEntry, DNSServerGroup
from app.services.dns.named_conf_validation import AclCycleError, order_acls_for_render


async def _admin(db: AsyncSession) -> str:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"a-{tag}",
        email=f"{tag}@example.com",
        display_name="A",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


async def _group(db: AsyncSession) -> DNSServerGroup:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(group)
    await db.flush()
    return group


def _hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _acl(name: str, *values: str) -> dict:
    return {"name": name, "entries": [{"value": v, "negate": False} for v in values]}


# ── dependency ordering ───────────────────────────────────────────────────


def test_a_referenced_acl_is_emitted_before_its_referrer():
    """BIND resolves ``acl`` statements where they are written.

    A reference to one declared later in the file is an error, not a
    forward declaration — so the order is load-bearing, not cosmetic.
    """
    ordered = order_acls_for_render(
        [_acl("outer", "inner", "10.0.0.0/8"), _acl("inner", "192.168.0.0/16")]
    )
    names = [a["name"] for a in ordered]
    assert names.index("inner") < names.index("outer")


def test_ordering_is_deterministic():
    """The bundle is hashed into a sha256 ETag. A set-iteration order would
    churn it and make every agent re-pull a config that did not change."""
    acls = [_acl("c"), _acl("a"), _acl("b")]
    assert [a["name"] for a in order_acls_for_render(acls)] == ["a", "b", "c"]
    assert [a["name"] for a in order_acls_for_render(list(reversed(acls)))] == [
        "a",
        "b",
        "c",
    ]


def test_a_negated_reference_still_counts_as_a_dependency():
    """``!inner`` cites ``inner`` just as much as ``inner`` does."""
    ordered = order_acls_for_render([_acl("outer", "!inner"), _acl("inner", "10.0.0.0/8")])
    names = [a["name"] for a in ordered]
    assert names.index("inner") < names.index("outer")


def test_a_transitive_chain_orders_correctly():
    ordered = order_acls_for_render([_acl("a", "b"), _acl("b", "c"), _acl("c", "10.0.0.0/8")])
    assert [x["name"] for x in ordered] == ["c", "b", "a"]


def test_a_direct_cycle_is_refused():
    with pytest.raises(AclCycleError):
        order_acls_for_render([_acl("a", "a")])


def test_an_indirect_cycle_is_refused():
    """A→B→A. Each edge is individually legal; only the pair is not, which
    is why per-field validation cannot catch this on its own."""
    with pytest.raises(AclCycleError) as exc:
        order_acls_for_render([_acl("a", "b"), _acl("b", "a")])
    assert "references itself" in str(exc.value)


def test_an_address_that_looks_like_a_name_is_not_a_dependency():
    """Only a bare name matching another ACL is a reference — an address,
    a prefix or a built-in never is."""
    ordered = order_acls_for_render([_acl("a", "any", "10.0.0.0/8", "key k")])
    assert [x["name"] for x in ordered] == ["a"]


# ── through the API ───────────────────────────────────────────────────────


async def test_acl_entries_are_validated(client: AsyncClient, db_session):
    """The values are interpolated verbatim into named.conf now, so they
    get the same gate a view's match_clients does."""
    token = await _admin(db_session)
    group = await _group(db_session)
    await db_session.flush()

    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/acls",
        headers=_hdr(token),
        json={"name": "office", "entries": [{"value": "10.0.0.0/33"}]},
    )
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["field"] == "entries"


async def test_acl_name_is_validated(client: AsyncClient, db_session):
    token = await _admin(db_session)
    group = await _group(db_session)
    await db_session.flush()

    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/acls",
        headers=_hdr(token),
        json={"name": 'evil"; }; //', "entries": [{"value": "10.0.0.0/8"}]},
    )
    assert r.status_code == 422
    assert r.json()["detail"]["field"] == "name"


async def test_acl_cannot_shadow_a_builtin(client: AsyncClient, db_session):
    """``acl "any" { … };`` is a redefinition BIND refuses."""
    token = await _admin(db_session)
    group = await _group(db_session)
    await db_session.flush()

    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/acls",
        headers=_hdr(token),
        json={"name": "any", "entries": [{"value": "10.0.0.0/8"}]},
    )
    assert r.status_code == 422


async def test_acl_may_reference_another_acl(client: AsyncClient, db_session):
    token = await _admin(db_session)
    group = await _group(db_session)
    await db_session.flush()

    inner = await client.post(
        f"/api/v1/dns/groups/{group.id}/acls",
        headers=_hdr(token),
        json={"name": "inner", "entries": [{"value": "10.0.0.0/8"}]},
    )
    assert inner.status_code == 201, inner.text

    outer = await client.post(
        f"/api/v1/dns/groups/{group.id}/acls",
        headers=_hdr(token),
        json={
            "name": "outer",
            "entries": [{"value": "inner"}, {"value": "172.16.0.0/12"}],
        },
    )
    assert outer.status_code == 201, outer.text


async def test_acl_self_reference_is_refused(client: AsyncClient, db_session):
    token = await _admin(db_session)
    group = await _group(db_session)
    await db_session.flush()

    created = await client.post(
        f"/api/v1/dns/groups/{group.id}/acls",
        headers=_hdr(token),
        json={"name": "loop", "entries": [{"value": "10.0.0.0/8"}]},
    )
    acl_id = created.json()["id"]

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/acls/{acl_id}",
        headers=_hdr(token),
        json={"entries": [{"value": "loop"}]},
    )
    assert r.status_code == 422, r.text


async def test_a_two_acl_cycle_is_refused_at_the_commit(client: AsyncClient, db_session):
    """A→B is legal, then B→A closes the loop. Per-field validation sees
    only one legal edge at a time; the graph check is what catches it."""
    token = await _admin(db_session)
    group = await _group(db_session)
    await db_session.flush()

    a = await client.post(
        f"/api/v1/dns/groups/{group.id}/acls",
        headers=_hdr(token),
        json={"name": "a", "entries": [{"value": "10.0.0.0/8"}]},
    )
    b = await client.post(
        f"/api/v1/dns/groups/{group.id}/acls",
        headers=_hdr(token),
        json={"name": "b", "entries": [{"value": "a"}]},
    )
    assert b.status_code == 201, b.text

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/acls/{a.json()['id']}",
        headers=_hdr(token),
        json={"entries": [{"value": "b"}]},
    )
    assert r.status_code == 422, r.text
    assert "references itself" in r.json()["detail"]["message"]


async def test_bundle_carries_acl_entries(client: AsyncClient, db_session):
    """The regression that started it all: entries reaching the agent."""
    from sqlalchemy import select

    from app.models.dns import DNSServer
    from app.services.dns.agent_config import build_config_bundle

    group = await _group(db_session)
    acl = DNSAcl(group_id=group.id, name="office", description="")
    db_session.add(acl)
    await db_session.flush()
    db_session.add(DNSAclEntry(acl_id=acl.id, value="10.0.0.0/8", negate=False, order=0))
    server = DNSServer(group_id=group.id, name="s1", driver="bind9", host="127.0.0.1", port=53)
    db_session.add(server)
    await db_session.flush()

    loaded = (
        await db_session.execute(select(DNSServer).where(DNSServer.id == server.id))
    ).scalar_one()
    bundle = await build_config_bundle(db_session, loaded)

    acls = bundle["acls"]
    assert [a["name"] for a in acls] == ["office"]
    assert acls[0]["entries"] == [{"value": "10.0.0.0/8", "negate": False}]


# ── referential integrity (review follow-up) ──────────────────────────────
#
# Write-time validation stops an operator CREATING a dangling reference. It
# does nothing about removing the target of one that already resolves — and
# the consequence is identical: named.conf carries an undefined symbol, so
# the group stops converging.


async def _create_acl(client: AsyncClient, token: str, group_id, name: str, *values: str) -> str:
    r = await client.post(
        f"/api/v1/dns/groups/{group_id}/acls",
        headers=_hdr(token),
        json={"name": name, "entries": [{"value": v, "order": i} for i, v in enumerate(values)]},
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def test_deleting_an_acl_cited_by_another_acl_is_refused(client: AsyncClient, db_session):
    token = await _admin(db_session)
    group = await _group(db_session)
    await db_session.flush()

    inner = await _create_acl(client, token, group.id, "inner", "10.0.0.0/8")
    await _create_acl(client, token, group.id, "outer", "inner")

    r = await client.delete(f"/api/v1/dns/groups/{group.id}/acls/{inner}", headers=_hdr(token))
    assert r.status_code == 409, r.text
    assert "outer" in r.json()["detail"]["message"]


async def test_deleting_an_acl_cited_by_a_view_is_refused(client: AsyncClient, db_session):
    token = await _admin(db_session)
    group = await _group(db_session)
    await db_session.flush()

    acl_id = await _create_acl(client, token, group.id, "office", "10.0.0.0/8")
    v = await client.post(
        f"/api/v1/dns/groups/{group.id}/views",
        headers=_hdr(token),
        json={"name": "corp", "match_clients": ["office"]},
    )
    assert v.status_code == 201, v.text

    r = await client.delete(f"/api/v1/dns/groups/{group.id}/acls/{acl_id}", headers=_hdr(token))
    assert r.status_code == 409
    assert "corp" in r.json()["detail"]["message"]


async def test_deleting_an_acl_cited_by_server_options_is_refused(client: AsyncClient, db_session):
    """#1786: ``allow_recursion`` now renders, so an ACL it names must stay."""
    token = await _admin(db_session)
    group = await _group(db_session)
    await db_session.flush()

    acl_id = await _create_acl(client, token, group.id, "office", "10.0.0.0/8")
    o = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        headers=_hdr(token),
        json={"allow_recursion": ["office"]},
    )
    assert o.status_code == 200, o.text

    r = await client.delete(f"/api/v1/dns/groups/{group.id}/acls/{acl_id}", headers=_hdr(token))
    assert r.status_code == 409, r.text
    assert "allow_recursion" in r.json()["detail"]["message"]


async def test_renaming_a_cited_acl_is_refused(client: AsyncClient, db_session):
    """A rename orphans every reference to the OLD name, exactly as a
    delete would — and is the easier mistake to make."""
    token = await _admin(db_session)
    group = await _group(db_session)
    await db_session.flush()

    inner = await _create_acl(client, token, group.id, "inner", "10.0.0.0/8")
    await _create_acl(client, token, group.id, "outer", "inner")

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/acls/{inner}",
        headers=_hdr(token),
        json={"name": "renamed"},
    )
    assert r.status_code == 409, r.text


async def test_an_uncited_acl_deletes_normally(client: AsyncClient, db_session):
    """The guard must not make ordinary cleanup impossible."""
    token = await _admin(db_session)
    group = await _group(db_session)
    await db_session.flush()

    acl_id = await _create_acl(client, token, group.id, "spare", "10.0.0.0/8")
    r = await client.delete(f"/api/v1/dns/groups/{group.id}/acls/{acl_id}", headers=_hdr(token))
    assert r.status_code == 204, r.text


# ── legacy rows the old, unvalidated endpoints allowed ────────────────────


async def test_bundle_drops_an_unrenderable_legacy_entry(client: AsyncClient, db_session):
    """Rows predating #899 were stored with no validation at all.

    The moment the agent started rendering them, a legacy bad CIDR would
    break named.conf on upgrade with nobody having touched anything — so
    the bundle drops what it cannot render rather than shipping it.
    """
    from sqlalchemy import select

    from app.models.dns import DNSServer
    from app.services.dns.agent_config import build_config_bundle

    group = await _group(db_session)
    acl = DNSAcl(group_id=group.id, name="legacy", description="")
    db_session.add(acl)
    await db_session.flush()
    # Written straight to the table, bypassing the API — exactly how these
    # rows exist today.
    db_session.add(DNSAclEntry(acl_id=acl.id, value="10.0.0.0/8", negate=False, order=0))
    db_session.add(DNSAclEntry(acl_id=acl.id, value="not-a-prefix/99", negate=False, order=1))
    server = DNSServer(group_id=group.id, name="s1", driver="bind9", host="127.0.0.1", port=53)
    db_session.add(server)
    await db_session.flush()

    loaded = (
        await db_session.execute(select(DNSServer).where(DNSServer.id == server.id))
    ).scalar_one()
    bundle = await build_config_bundle(db_session, loaded)

    entries = bundle["acls"][0]["entries"]
    assert [e["value"] for e in entries] == ["10.0.0.0/8"]


async def test_bundle_survives_a_legacy_cycle(client: AsyncClient, db_session):
    """A cyclic pair can only exist from before the graph check.

    ``build_config_bundle`` runs inside the agent's /config long-poll, so
    raising here is not a failed edit — it is every agent in the group
    getting a 500 on every poll, forever, with no way to fix it from the
    UI. Strictly worse than the bug being fixed.
    """
    from sqlalchemy import select

    from app.models.dns import DNSServer
    from app.services.dns.agent_config import build_config_bundle

    group = await _group(db_session)
    a = DNSAcl(group_id=group.id, name="a", description="")
    b = DNSAcl(group_id=group.id, name="b", description="")
    db_session.add_all([a, b])
    await db_session.flush()
    db_session.add(DNSAclEntry(acl_id=a.id, value="b", negate=False, order=0))
    db_session.add(DNSAclEntry(acl_id=b.id, value="a", negate=False, order=0))
    server = DNSServer(group_id=group.id, name="s1", driver="bind9", host="127.0.0.1", port=53)
    db_session.add(server)
    await db_session.flush()

    loaded = (
        await db_session.execute(select(DNSServer).where(DNSServer.id == server.id))
    ).scalar_one()
    bundle = await build_config_bundle(db_session, loaded)
    assert sorted(x["name"] for x in bundle["acls"]) == ["a", "b"]
