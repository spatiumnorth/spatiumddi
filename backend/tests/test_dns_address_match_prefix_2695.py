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
  bundle carries the network it stands for, in its place, with its ``!``,
  and a warning names the stored value so it can be found and re-saved.
  Leaving it out instead would turn a list it was the only entry of into
  ``none``: ``allow_query: ["10.0.0.5/24"]`` would REFUSE every query with
  the apply reported ``ok``. ``also-notify``, which takes addresses only,
  still leaves it out;
* a Technitium or PowerDNS server's bundle carries the stored value: their
  agents apply the network themselves, so a server that serves the value
  today keeps serving it.
"""

from __future__ import annotations

import gzip
import json
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

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


def _zone(group: DNSServerGroup, name: str, **clauses: list[str]) -> DNSZone:
    return DNSZone(
        group_id=group.id,
        name=name,
        zone_type="primary",
        kind="forward",
        primary_ns=f"ns1.{name}",
        admin_email=f"hostmaster.{name}",
        **clauses,
    )


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
        _zone(
            group,
            "example.test.",
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


def _view(bundle: dict, name: str = "inside") -> dict:
    (view,) = [v for v in bundle["views"] if v["name"] == name]
    return view


def _zones(bundle: dict, name: str) -> list[dict]:
    zones = [z for z in bundle["zones"] if z["name"] == name]
    assert zones
    return zones


@pytest.mark.asyncio
async def test_a_bind9_bundle_ships_a_prefix_saved_before_the_fix_as_its_network(db_session):
    """BIND refuses the element, so shipping it as stored stops the whole
    group converging, and leaving it out can turn an access list into
    ``none``. A BIND9 server gets the network it stands for, in its place,
    with its ``!``: what the Technitium and PowerDNS agents apply for the
    same value. A host route (``/32``) and every clean prefix stay as stored."""
    group = await _group(db_session)
    await _rows_saved_before_the_fix(db_session, group)
    bundle = await _bundle_for(db_session, group, "bind9")

    assert HOST_BITS not in str(bundle)
    assert MASK_FORM not in str(bundle)
    (acl,) = bundle["acls"]
    assert acl["entries"] == [
        {"value": "10.0.0.0/8", "negate": False},
        {"value": NETWORK, "negate": False},
    ]
    assert _view(bundle)["match_clients"] == [NETWORK, "10.1.0.0/16"]
    assert bundle["options"]["allow_query"] == [NETWORK, "192.0.2.0/24", "10.9.9.9/32", NETWORK]
    assert bundle["options"]["allow_transfer"] == [NETWORK]
    for zone in _zones(bundle, "example.test."):
        assert zone["allow_query"] == [NETWORK, "10.2.0.0/16"]
        assert zone["allow_transfer"] == [f"!{NETWORK}", "10.3.0.0/16"]


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ADDRESS_MATCH_LIST_OPTIONS)
async def test_an_option_whose_only_entry_is_one_ships_its_network_not_none(db_session, field: str):
    """The review's case: ``allow_query: ["10.0.0.5/24"]``. As stored, BIND
    refuses the config and keeps serving its previous one; left out, the
    list would ship ``none`` and REFUSE every query with the apply reported
    ``ok``. Every address-match option ships the network, ``allow_recursion``
    and ``blackhole`` among them."""
    group = await _group(db_session)
    db_session.add(DNSServerOptions(group_id=group.id, **{field: [HOST_BITS]}))
    await db_session.flush()
    bundle = await _bundle_for(db_session, group, "bind9")

    assert bundle["options"][field] == [NETWORK]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stored", "shipped"),
    [
        (f"!{HOST_BITS}", f"!{NETWORK}"),
        ("2001:db8::1/64", "2001:db8::/64"),
        ("!2001:db8::1/64", "!2001:db8::/64"),
        (MASK_FORM, NETWORK),
        ("10.0.0.5/255.255.255.0", NETWORK),
        ("10.0.0.0/0.0.0.255", NETWORK),
        (f"!{MASK_FORM}", f"!{NETWORK}"),
        ("fe80::1%lo/64", "fe80::/64"),
    ],
)
async def test_each_form_ships_as_its_network_in_its_place_with_its_negation(
    db_session, stored: str, shipped: str
):
    """Host bits set or a mask where the length goes, IPv4 or IPv6, negated
    or not: the network the 422 names for new input, where the element was.
    A scope (``%lo``) is not carried, as in that network and in the one the
    Technitium agent applies."""
    group = await _group(db_session)
    db_session.add(
        DNSServerOptions(group_id=group.id, allow_query=["192.0.2.0/24", stored, "198.51.100.0/24"])
    )
    await db_session.flush()
    bundle = await _bundle_for(db_session, group, "bind9")

    assert bundle["options"]["allow_query"] == ["192.0.2.0/24", shipped, "198.51.100.0/24"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field", ["match_clients", "match_destinations", "allow_query", "allow_query_cache"]
)
async def test_a_view_list_whose_only_entry_is_one_ships_its_network(db_session, field: str):
    group = await _group(db_session)
    db_session.add(DNSView(group_id=group.id, name="inside", **{field: [HOST_BITS]}))
    await db_session.flush()
    bundle = await _bundle_for(db_session, group, "bind9")

    assert _view(bundle)[field] == [NETWORK]


@pytest.mark.asyncio
async def test_an_acl_whose_only_entry_is_one_ships_its_network_with_its_negation(db_session):
    """The ACL loop filters entries, so it must carry the rewritten value too.
    A negation travels as the entry's ``negate`` or, on an older row, as a
    leading ``!`` in its value; the BIND9 agent reads both."""
    group = await _group(db_session)
    for name, value, negate in [
        ("office", HOST_BITS, False),
        ("not-office", HOST_BITS, True),
        ("older", f"!{MASK_FORM}", False),
    ]:
        acl = DNSAcl(group_id=group.id, name=name, description="")
        db_session.add(acl)
        await db_session.flush()
        db_session.add(DNSAclEntry(acl_id=acl.id, value=value, negate=negate, order=0))
    await db_session.flush()
    bundle = await _bundle_for(db_session, group, "bind9")

    assert {a["name"]: a["entries"] for a in bundle["acls"]} == {
        "office": [{"value": NETWORK, "negate": False}],
        "not-office": [{"value": NETWORK, "negate": True}],
        "older": [{"value": f"!{NETWORK}", "negate": False}],
    }


@pytest.mark.asyncio
async def test_a_zone_clause_whose_only_entry_is_one_ships_its_network(db_session):
    group = await _group(db_session)
    db_session.add(_zone(group, "only.test.", allow_query=[HOST_BITS], allow_transfer=[MASK_FORM]))
    await db_session.flush()
    bundle = await _bundle_for(db_session, group, "bind9")

    for zone in _zones(bundle, "only.test."):
        assert zone["allow_query"] == [NETWORK]
        assert zone["allow_transfer"] == [NETWORK]


@pytest.mark.asyncio
async def test_the_streamed_render_ships_the_network_too(db_session):
    """The worker stores the streamed render (#1662, #2227), which builds its
    zones apart from the whole render; it must carry the network the same way."""
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
    (acl,) = body["acls"]
    assert acl["entries"] == [
        {"value": "10.0.0.0/8", "negate": False},
        {"value": NETWORK, "negate": False},
    ]
    assert _view(body)["match_clients"] == [NETWORK, "10.1.0.0/16"]
    assert body["options"]["allow_query"] == [NETWORK, "192.0.2.0/24", "10.9.9.9/32", NETWORK]
    assert body["options"]["allow_transfer"] == [NETWORK]
    for zone in _zones(body, "example.test."):
        assert zone["allow_query"] == [NETWORK, "10.2.0.0/16"]
        assert zone["allow_transfer"] == [f"!{NETWORK}", "10.3.0.0/16"]


@pytest.mark.asyncio
async def test_each_rewrite_is_logged_with_the_stored_value_and_what_shipped(db_session):
    """At warning, so a value saved before the fix can be found and re-saved."""
    group = await _group(db_session)
    await _rows_saved_before_the_fix(db_session, group)
    with capture_logs() as logs:
        await _bundle_for(db_session, group, "bind9")

    rewrites = [e for e in logs if e["event"] == "dns_bundle_entry_normalised_bind9_refused_prefix"]
    assert {e["log_level"] for e in rewrites} == {"warning"}
    assert {(e["where"], e["value"], e["rendered"]) for e in rewrites} == {
        ("acl:office", HOST_BITS, NETWORK),
        ("view:inside.match_clients", HOST_BITS, NETWORK),
        ("options.allow_query", HOST_BITS, NETWORK),
        ("options.allow_query", MASK_FORM, NETWORK),
        ("options.allow_transfer", HOST_BITS, NETWORK),
        ("zone:example.test..allow_query", HOST_BITS, NETWORK),
        ("zone:example.test..allow_transfer", f"!{HOST_BITS}", f"!{NETWORK}"),
    }
    assert not [e for e in logs if e["event"] == "dns_bundle_entry_dropped_bind9_refused_prefix"]


@pytest.mark.asyncio
async def test_beside_an_undefined_key_or_acl_the_prefix_still_ships_its_network(db_session):
    """Only the prefix is rewritten: an undefined ``key`` or ACL reference
    beside it is still dropped (#2282), and the list keeps the network."""
    group = await _group(db_session)
    db_session.add(
        DNSView(group_id=group.id, name="inside", match_clients=["no-such-acl", HOST_BITS])
    )
    db_session.add(DNSServerOptions(group_id=group.id, allow_query=["key no-such-key", HOST_BITS]))
    await db_session.flush()
    bundle = await _bundle_for(db_session, group, "bind9")

    assert bundle["options"]["allow_query"] == [NETWORK]
    assert _view(bundle)["match_clients"] == [NETWORK]


@pytest.mark.asyncio
async def test_a_lost_negation_or_an_emptied_list_still_ships_none(db_session):
    """#2282's rules hold beside a rewritten prefix: a list that loses a
    negated reference, or that a drop empties, ships ``none``, never wider."""
    group = await _group(db_session)
    db_session.add(
        DNSView(
            group_id=group.id,
            name="inside",
            match_destinations=["!no-such-acl", f"!{HOST_BITS}"],
        )
    )
    db_session.add(
        DNSServerOptions(
            group_id=group.id,
            allow_transfer=["!key no-such-key", HOST_BITS],
            allow_notify=["key no-such-key"],
        )
    )
    await db_session.flush()
    bundle = await _bundle_for(db_session, group, "bind9")

    assert bundle["options"]["allow_transfer"] == ["none"]
    assert bundle["options"]["allow_notify"] == ["none"]
    assert _view(bundle)["match_destinations"] == ["none"]


@pytest.mark.asyncio
async def test_also_notify_takes_addresses_so_a_bind9_bundle_leaves_one_out(db_session):
    """``also-notify`` names the servers to send NOTIFY to, and the API takes
    an address there, never a prefix (#1316). Neither the stored value nor its
    network loads in ``also-notify``, so a BIND9 bundle leaves it out, and
    never puts ``none`` there, which is not legal there either."""
    group = await _group(db_session)
    db_session.add(DNSServerOptions(group_id=group.id, also_notify=[HOST_BITS, "192.0.2.53"]))
    db_session.add(_zone(group, "notify.test.", also_notify=[HOST_BITS]))
    await db_session.flush()
    bundle = await _bundle_for(db_session, group, "bind9")

    assert bundle["options"]["also_notify"] == ["192.0.2.53"]
    for zone in _zones(bundle, "notify.test."):
        assert zone["also_notify"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", ["technitium", "powerdns"])
async def test_a_technitium_or_powerdns_bundle_ships_it_as_stored(db_session, driver: str):
    """Their agents mask a prefix to its network themselves (Technitium in
    each address-match list it applies, PowerDNS in ``allow-transfer``, the
    one it applies), so a server that serves the value today keeps serving
    it, and its bundle carries the value as stored."""
    group = await _group(db_session)
    await _rows_saved_before_the_fix(db_session, group)
    bundle = await _bundle_for(db_session, group, driver)

    (acl,) = bundle["acls"]
    assert [e["value"] for e in acl["entries"]] == ["10.0.0.0/8", HOST_BITS]
    assert bundle["options"]["allow_query"] == [
        HOST_BITS,
        "192.0.2.0/24",
        "10.9.9.9/32",
        MASK_FORM,
    ]
    assert bundle["options"]["allow_transfer"] == [HOST_BITS]
    for zone in _zones(bundle, "example.test."):
        assert zone["allow_transfer"] == [f"!{HOST_BITS}", "10.3.0.0/16"]
