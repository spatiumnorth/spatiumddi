"""A prefix BIND 9 refuses never reaches a BIND9 server (#2695).

``10.0.0.5/24`` is not an address-match element BIND 9 loads:
``named-checkconf`` refuses the file ("'10.0.0.5/24': address/prefix length
mismatch '24'"), the agent keeps the config it had, and while the value
stands every later bundle for the group is refused the same way. The gate
parsed prefixes with ``strict=False`` on the belief that BIND accepts host
bits, so the API answered 200 for a value no BIND9 server could load. A
mask where the length goes (``10.0.0.0/255.255.255.0``) passed the same
parse and fails the same way ("expected prefix length").

What the tests pin:

* every address-match list the API writes (server options, named ACL
  entries, a view's match lists, a zone's clauses) refuses such a prefix
  with a 422 that names the entry and the network it would mean, and saves
  nothing; the network itself is accepted;
* a value saved before the fix stops blocking the group: a BIND9 server's
  bundle drops it, loudly, and an access list it empties (or that loses a
  negation) fails closed as ``none``, never open;
* a Technitium server's bundle keeps it: Technitium's translator applies
  the network, so a server that serves the value today keeps serving it.
"""

from __future__ import annotations

import gzip
import json
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import (
    DNSAcl,
    DNSAclEntry,
    DNSServer,
    DNSServerGroup,
    DNSServerOptions,
    DNSView,
    DNSZone,
)
from app.services.dns.agent_config import build_config_bundle, encode_bundle_body
from app.services.dns.named_conf_validation import (
    ADDRESS_MATCH_LIST_OPTIONS,
    ViewValidationError,
    validate_server_option,
)

HOST_BITS = "10.0.0.5/24"
MASK_FORM = "10.0.0.0/255.255.255.0"
NETWORK = "10.0.0.0/24"


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="sa",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    u.groups = []  # mark loaded: is_effective_superadmin walks .groups (#351)
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _group(db: AsyncSession) -> DNSServerGroup:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    return group


def _assert_names_the_network(detail: dict, field: str, value: str = HOST_BITS) -> None:
    assert detail["field"] == field
    assert detail["value"] == value
    assert NETWORK in detail["message"]


# ── the grammar ───────────────────────────────────────────────────────


@pytest.mark.parametrize("field", ADDRESS_MATCH_LIST_OPTIONS)
@pytest.mark.parametrize("element", [HOST_BITS, f"!{HOST_BITS}", "2001:db8::1/64", MASK_FORM])
def test_every_address_match_option_refuses_a_prefix_bind_refuses(field: str, element: str):
    """The server options, and a zone's ``allow_query`` / ``allow_transfer``,
    which go through the same function under the same names (#1316)."""
    with pytest.raises(ViewValidationError) as info:
        validate_server_option(field, ["any", element])
    assert info.value.field == field
    assert info.value.value == element


# ── through the API ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_options_refuse_a_host_bits_prefix_and_take_the_network(
    client: AsyncClient, db_session: AsyncSession
):
    """The reproduction: ``allow_query: ["10.0.0.5/24"]`` answered 200 and was
    saved, and every BIND9 server in the group then refused the bundle."""
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/options"
    before = (await client.get(url, headers=headers)).json()["allow_query"]

    r = await client.put(url, json={"allow_query": [HOST_BITS]}, headers=headers)
    assert r.status_code == 422, r.text
    _assert_names_the_network(r.json()["detail"], "allow_query")
    assert (await client.get(url, headers=headers)).json()["allow_query"] == before

    r = await client.put(url, json={"allow_query": [MASK_FORM]}, headers=headers)
    assert r.status_code == 422, r.text
    _assert_names_the_network(r.json()["detail"], "allow_query", MASK_FORM)
    assert (await client.get(url, headers=headers)).json()["allow_query"] == before

    r = await client.put(url, json={"allow_query": [NETWORK]}, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["allow_query"] == [NETWORK]


@pytest.mark.asyncio
async def test_acl_entries_refuse_a_host_bits_prefix_on_create_and_update(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/acls"

    r = await client.post(
        url, json={"name": "office", "entries": [{"value": HOST_BITS}]}, headers=headers
    )
    assert r.status_code == 422, r.text
    _assert_names_the_network(r.json()["detail"], "entries")

    r = await client.post(
        url, json={"name": "office", "entries": [{"value": NETWORK}]}, headers=headers
    )
    assert r.status_code == 201, r.text
    acl_id = r.json()["id"]

    r = await client.put(
        f"{url}/{acl_id}",
        json={"entries": [{"value": NETWORK}, {"value": HOST_BITS}]},
        headers=headers,
    )
    assert r.status_code == 422, r.text
    _assert_names_the_network(r.json()["detail"], "entries")
    (acl,) = (await client.get(url, headers=headers)).json()
    assert [e["value"] for e in acl["entries"]] == [NETWORK]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field", ["match_clients", "match_destinations", "allow_query", "allow_query_cache"]
)
async def test_view_match_lists_refuse_a_host_bits_prefix(
    client: AsyncClient, db_session: AsyncSession, field: str
):
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    await db_session.commit()

    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/views",
        json={"name": "inside", field: [HOST_BITS]},
        headers=headers,
    )
    assert r.status_code == 422, r.text
    _assert_names_the_network(r.json()["detail"], field)


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["allow_query", "allow_transfer"])
async def test_zone_clauses_refuse_a_host_bits_prefix(
    client: AsyncClient, db_session: AsyncSession, field: str
):
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    await db_session.commit()

    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones",
        json={"name": "example.com", field: [HOST_BITS]},
        headers=headers,
    )
    assert r.status_code == 422, r.text
    _assert_names_the_network(r.json()["detail"], field)


# ── rows saved before the fix ─────────────────────────────────────────


async def _rows_saved_before_the_fix(db: AsyncSession, group: DNSServerGroup) -> None:
    """Written straight to the tables, as a save before the fix left them."""
    acl = DNSAcl(group_id=group.id, name="office", description="")
    db.add(acl)
    await db.flush()
    db.add(DNSAclEntry(acl_id=acl.id, value="10.0.0.0/8", negate=False, order=0))
    db.add(DNSAclEntry(acl_id=acl.id, value=HOST_BITS, negate=False, order=1))
    db.add(DNSView(group_id=group.id, name="inside", match_clients=[HOST_BITS, "10.1.0.0/16"]))
    db.add(
        DNSServerOptions(
            group_id=group.id,
            allow_query=[HOST_BITS, "192.0.2.0/24", "10.9.9.9/32", MASK_FORM],
            allow_transfer=[HOST_BITS],
        )
    )
    db.add(
        DNSZone(
            group_id=group.id,
            name="example.test.",
            zone_type="primary",
            kind="forward",
            primary_ns="ns1.example.test.",
            admin_email="hostmaster.example.test.",
            allow_query=[HOST_BITS, "10.2.0.0/16"],
            allow_transfer=[f"!{HOST_BITS}", "10.3.0.0/16"],
        )
    )
    await db.flush()


async def _bundle_for(db: AsyncSession, group: DNSServerGroup, driver: str) -> dict:
    server = DNSServer(group_id=group.id, name="s1", driver=driver, host="127.0.0.1", port=53)
    db.add(server)
    await db.flush()
    loaded = (await db.execute(select(DNSServer).where(DNSServer.id == server.id))).scalar_one()
    return await build_config_bundle(db, loaded)


@pytest.mark.asyncio
async def test_a_bind9_bundle_drops_a_host_bits_prefix_saved_before_the_fix(db_session):
    """BIND refuses the element, so shipping it stops the whole group
    converging. It is dropped under the #2282 rule that a drop never widens
    access: an access list it empties, or one that loses a negation, ships
    ``none``. A host route (``/32``) and every clean prefix stay."""
    group = await _group(db_session)
    await _rows_saved_before_the_fix(db_session, group)
    bundle = await _bundle_for(db_session, group, "bind9")

    assert HOST_BITS not in str(bundle)
    assert MASK_FORM not in str(bundle)
    (acl,) = bundle["acls"]
    assert acl["entries"] == [{"value": "10.0.0.0/8", "negate": False}]
    (view,) = [v for v in bundle["views"] if v["name"] == "inside"]
    assert view["match_clients"] == ["10.1.0.0/16"]
    assert bundle["options"]["allow_query"] == ["192.0.2.0/24", "10.9.9.9/32"]
    assert bundle["options"]["allow_transfer"] == ["none"]
    zones = [z for z in bundle["zones"] if z["name"] == "example.test."]
    assert zones
    assert all(z["allow_query"] == ["10.2.0.0/16"] for z in zones)
    assert all(z["allow_transfer"] == ["none"] for z in zones)


@pytest.mark.asyncio
async def test_the_streamed_render_drops_it_too(db_session):
    """The worker stores the streamed render (#1662, #2227), which builds its
    zones apart from the whole render; it must drop the element the same way."""
    group = await _group(db_session)
    await _rows_saved_before_the_fix(db_session, group)
    server = DNSServer(group_id=group.id, name="s1", driver="bind9", host="127.0.0.1", port=53)
    db_session.add(server)
    await db_session.flush()
    server_id = server.id
    db_session.expunge_all()
    fresh = await db_session.get(DNSServer, server_id)
    assert fresh is not None
    body = json.loads(gzip.decompress((await encode_bundle_body(db_session, fresh)).body_gz))

    assert HOST_BITS not in json.dumps(body)
    assert MASK_FORM not in json.dumps(body)
    assert body["options"]["allow_query"] == ["192.0.2.0/24", "10.9.9.9/32"]
    assert body["options"]["allow_transfer"] == ["none"]
    zones = [z for z in body["zones"] if z["name"] == "example.test."]
    assert zones
    assert all(z["allow_transfer"] == ["none"] for z in zones)


@pytest.mark.asyncio
async def test_a_technitium_bundle_keeps_it_because_technitium_applies_the_network(
    db_session,
):
    """Technitium's translator masks a prefix to its network, so a server it
    runs applies ``10.0.0.0/24`` today. Dropping the element there would
    change what a working server applies; the API refusing it is enough."""
    group = await _group(db_session)
    await _rows_saved_before_the_fix(db_session, group)
    bundle = await _bundle_for(db_session, group, "technitium")

    (acl,) = bundle["acls"]
    assert [e["value"] for e in acl["entries"]] == ["10.0.0.0/8", HOST_BITS]
    assert bundle["options"]["allow_query"] == [
        HOST_BITS,
        "192.0.2.0/24",
        "10.9.9.9/32",
        MASK_FORM,
    ]
    assert bundle["options"]["allow_transfer"] == [HOST_BITS]
