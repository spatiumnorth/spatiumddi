"""Validation for the free-text that reaches ``named.conf`` (#876, #899).

View scoping shipped with #24 but was API-only, so these fields were
effectively unvalidated. #876 puts a form in front of them, and both are
interpolated **verbatim** into ``named.conf`` — the name additionally
becomes a directory on the DNS agent. So the tests that matter here are
the ones that prove a bad value is refused at the API rather than
discovered when the agent's ``named-checkconf`` rejects the bundle and the
whole group silently stops converging.
"""

from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSAcl, DNSServerGroup
from app.services import feature_modules
from app.services.dns.named_conf_validation import (
    MAX_VIEW_NAME_LEN,
    RESERVED_VIEW_NAMES,
    ViewValidationError,
    validate_address_match_list,
    validate_view_name,
)

# No module-level ``pytest.mark.asyncio`` — ``asyncio_mode = "auto"`` in
# pyproject already collects the async tests, and marking the sync ones
# emits a PytestWarning per test.


@pytest_asyncio.fixture(autouse=True)
async def _reset_module_cache():
    feature_modules.invalidate_cache()
    yield
    feature_modules.invalidate_cache()


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


# ── view names ────────────────────────────────────────────────────────────


def test_accepts_ordinary_view_names():
    for name in ("guest", "internal", "dmz-2", "vlan_50", "a", "A1"):
        assert validate_view_name(name) == name


def test_rejects_bind_reserved_names():
    for name in RESERVED_VIEW_NAMES:
        with pytest.raises(ViewValidationError):
            validate_view_name(name)
    # Case-insensitively — BIND's parser is not case-sensitive here.
    with pytest.raises(ViewValidationError):
        validate_view_name("_DEFAULT")


def test_rejects_names_that_would_escape_their_context():
    """The name lands in ``view "…" {`` and in a filesystem path.

    A quote or brace breaks out of the statement; a slash or ``..`` walks
    out of ``/var/cache/bind/rpz/<view>/``.
    """
    for name in (
        'guest"; };  //',
        "../../etc/bind",
        "a/b",
        "with space",
        "semi;colon",
        "brace}",
        "",
        "   ",
    ):
        with pytest.raises(ViewValidationError):
            validate_view_name(name)


def test_rejects_over_long_names():
    """The cap is the RPZ zone label, not the view statement.

    The agent names the per-view blocking zone
    ``spatium-blocklist-<view>.rpz.`` — an 18-character prefix on a label
    RFC 1035 caps at 63 octets. A longer view name renders a zone BIND
    refuses to load, which takes the whole group's config with it.
    """
    assert MAX_VIEW_NAME_LEN == 45
    assert validate_view_name("v" * MAX_VIEW_NAME_LEN)
    assert len(f"spatium-blocklist-{'v' * MAX_VIEW_NAME_LEN}") == 63
    with pytest.raises(ViewValidationError):
        validate_view_name("v" * (MAX_VIEW_NAME_LEN + 1))


# ── address-match-lists ───────────────────────────────────────────────────


def test_accepts_addresses_prefixes_and_builtins():
    ok = [
        "any",
        "none",
        "localhost",
        "localnets",
        "10.0.0.1",
        "2001:db8::1",
        "10.20.0.0/16",
        "2001:db8::/32",
        "!198.51.100.0/24",
    ]
    assert validate_address_match_list(ok, field="match_clients") == ok


@pytest.mark.parametrize(
    ("element", "network", "address"),
    [
        ("10.0.0.5/24", "10.0.0.0/24", "10.0.0.5"),
        ("!10.0.0.5/24", "10.0.0.0/24", "10.0.0.5"),
        ("192.168.1.1/16", "192.168.0.0/16", "192.168.1.1"),
        ("10.0.0.0/0", "0.0.0.0/0", "10.0.0.0"),
        ("2001:db8::1/64", "2001:db8::/64", "2001:db8::1"),
        ("10.0.0.5/255.255.255.0", "10.0.0.0/24", "10.0.0.5"),
    ],
)
def test_a_prefix_with_host_bits_set_is_refused_naming_the_network(
    element: str, network: str, address: str
):
    """BIND refuses ``10.0.0.5/24`` (#2695): ``named-checkconf`` fails with
    "address/prefix length mismatch", and the group stops loading new config.
    Refused rather than rewritten, because it may mean the network or the
    one host; the message offers both."""
    with pytest.raises(ViewValidationError) as exc:
        validate_address_match_list(["10.0.0.0/8", element], field="match_clients")
    assert exc.value.field == "match_clients"
    assert exc.value.value == element
    assert f"use {network} " in str(exc.value)
    assert f"or {address} " in str(exc.value)


@pytest.mark.parametrize(
    ("element", "network"),
    [
        ("10.0.0.0/255.255.255.0", "10.0.0.0/24"),
        ("!10.0.0.0/255.255.255.0", "10.0.0.0/24"),
        ("10.0.0.0/0.0.0.255", "10.0.0.0/24"),
        ("10.0.0.0/255.255.255.255", "10.0.0.0/32"),
    ],
)
def test_a_mask_where_the_length_goes_is_refused_naming_the_prefix(element: str, network: str):
    """BIND reads only a decimal length after the slash (#2695):
    ``named-checkconf`` refuses ``10.0.0.0/255.255.255.0`` with "expected
    prefix length", though ``ipaddress`` reads it as ``10.0.0.0/24``."""
    with pytest.raises(ViewValidationError) as exc:
        validate_address_match_list(["10.0.0.0/8", element], field="match_clients")
    assert exc.value.field == "match_clients"
    assert exc.value.value == element
    assert str(exc.value).endswith(f"write it as {network}.")


@pytest.mark.parametrize(
    "element",
    [
        "10.0.0.0/24",
        "10.0.0.5/32",
        "0.0.0.0/0",
        "10.0.0.0/024",
        "2001:db8::/64",
        "2001:db8::1/128",
        "::/0",
    ],
)
def test_a_prefix_bind_reads_is_accepted(element: str):
    """No host bits and a decimal length, the leading zero included: BIND 9's
    ``named-checkconf`` takes each of these."""
    assert validate_address_match_list([element], field="match_clients") == [element]


def test_the_bundle_builder_can_ask_about_syntax_alone():
    """How a prefix BIND 9 refuses ships depends on the driver (a BIND9
    server gets the network it stands for, the Technitium and PowerDNS agents
    apply that network themselves), so the bundle builder, deciding per
    server, asks the syntax question without that one."""
    lenient = ["10.0.0.5/24", "10.0.0.0/255.255.255.0"]
    assert (
        validate_address_match_list(
            lenient, field="entries", allow_unknown_names=True, allow_bind9_refused_prefixes=True
        )
        == lenient
    )
    with pytest.raises(ViewValidationError):
        validate_address_match_list(
            ["10.0.0.0/33"],
            field="entries",
            allow_unknown_names=True,
            allow_bind9_refused_prefixes=True,
        )


def test_rejects_a_malformed_prefix():
    with pytest.raises(ViewValidationError) as exc:
        validate_address_match_list(["10.0.0.0/33"], field="match_clients")
    assert exc.value.field == "match_clients"
    assert exc.value.value == "10.0.0.0/33"


def test_rejects_an_octet_out_of_range():
    with pytest.raises(ViewValidationError):
        validate_address_match_list(["10.0.0.300"], field="match_clients")


def test_rejects_config_injection():
    """The element is interpolated straight into ``match-clients { … };``."""
    with pytest.raises(ViewValidationError):
        validate_address_match_list(['any; }; zone "evil" {'], field="match_clients")


def test_rejects_an_empty_element():
    with pytest.raises(ViewValidationError):
        validate_address_match_list(["10.0.0.0/8", "  "], field="match_clients")


def test_bare_negation_is_rejected():
    with pytest.raises(ViewValidationError):
        validate_address_match_list(["!"], field="match_clients")


def test_an_undefined_name_is_rejected():
    with pytest.raises(ViewValidationError) as exc:
        validate_address_match_list(["office-clients"], field="match_clients")
    assert "not an ACL defined" in str(exc.value)


def test_a_defined_acl_name_is_accepted():
    """#899 — the agent now renders ``acl {}``, so a reference resolves.

    #876 rejected every ACL name because none of them could ever resolve;
    that was the accurate answer then and the wrong one now.
    """
    assert validate_address_match_list(
        ["office", "10.0.0.0/8"],
        field="match_clients",
        known_acls=frozenset({"office"}),
    ) == ["office", "10.0.0.0/8"]


def test_an_undefined_acl_name_is_still_rejected():
    """An undefined symbol fails the whole bundle, not just this view."""
    with pytest.raises(ViewValidationError) as exc:
        validate_address_match_list(
            ["marketing"], field="match_clients", known_acls=frozenset({"office"})
        )
    assert "not an ACL defined in this server group" in str(exc.value)


def test_unknown_tsig_key_is_rejected():
    """``key <name>`` is an undefined symbol unless the group ships the key.

    Same blast radius as an undefined ACL: named.conf fails to parse and the
    whole group stops converging, not just this view.
    """
    with pytest.raises(ViewValidationError) as exc:
        validate_address_match_list(["key transfer-key"], field="match_clients")
    assert "not a TSIG key" in str(exc.value)


def test_known_tsig_key_is_accepted():
    assert validate_address_match_list(
        ["key transfer-key", "!key other-key"],
        field="match_clients",
        known_keys=frozenset({"transfer-key", "other-key"}),
    ) == ["key transfer-key", "!key other-key"]


def test_elements_are_stripped():
    assert validate_address_match_list(["  10.0.0.0/8  "], field="match_clients") == ["10.0.0.0/8"]


# ── through the API ───────────────────────────────────────────────────────


async def test_create_view_rejects_a_bad_cidr(client: AsyncClient, db_session):
    token = await _admin(db_session)
    group = await _group(db_session)
    await db_session.flush()

    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/views",
        headers=_hdr(token),
        json={"name": "guest", "match_clients": ["10.0.0.0/33"]},
    )
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert detail["field"] == "match_clients"
    assert detail["value"] == "10.0.0.0/33"


async def test_create_view_rejects_a_traversing_name(client: AsyncClient, db_session):
    token = await _admin(db_session)
    group = await _group(db_session)
    await db_session.flush()

    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/views",
        headers=_hdr(token),
        json={"name": "../../etc/bind", "match_clients": ["any"]},
    )
    assert r.status_code == 422
    assert r.json()["detail"]["field"] == "name"


async def test_create_view_accepts_a_defined_acl_by_name(client: AsyncClient, db_session):
    """#899 — the whole point. A view may cite an ACL the group defines."""
    token = await _admin(db_session)
    group = await _group(db_session)
    db_session.add(DNSAcl(group_id=group.id, name="office", description=""))
    await db_session.flush()

    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/views",
        headers=_hdr(token),
        json={"name": "internal", "match_clients": ["office", "10.0.0.0/8"]},
    )
    assert r.status_code == 201, r.text
    assert r.json()["match_clients"] == ["office", "10.0.0.0/8"]


async def test_create_view_rejects_an_acl_from_another_group(client: AsyncClient, db_session):
    """ACL names are per-group, so one group's ACL is undefined in another —
    and the bundle is built per group, so it would never be rendered."""
    token = await _admin(db_session)
    owner = await _group(db_session)
    other = await _group(db_session)
    db_session.add(DNSAcl(group_id=owner.id, name="office", description=""))
    await db_session.flush()

    r = await client.post(
        f"/api/v1/dns/groups/{other.id}/views",
        headers=_hdr(token),
        json={"name": "internal", "match_clients": ["office"]},
    )
    assert r.status_code == 422
    assert r.json()["detail"]["field"] == "match_clients"


async def test_duplicate_name_is_caught_after_stripping(client: AsyncClient, db_session):
    """The validator strips, so the duplicate check has to run on the

    stripped name — otherwise ``" guest "`` sails past a pre-check that
    ``"guest"`` would have caught and the answer comes from the DB's unique
    violation instead of the handler's own message.
    """
    token = await _admin(db_session)
    group = await _group(db_session)
    await db_session.flush()

    first = await client.post(
        f"/api/v1/dns/groups/{group.id}/views",
        headers=_hdr(token),
        json={"name": "guest", "match_clients": ["any"]},
    )
    assert first.status_code == 201, first.text

    dupe = await client.post(
        f"/api/v1/dns/groups/{group.id}/views",
        headers=_hdr(token),
        json={"name": "  guest  ", "match_clients": ["any"]},
    )
    assert dupe.status_code == 409, dupe.text
    assert "already exists" in dupe.json()["detail"]


async def test_update_view_validates_too(client: AsyncClient, db_session):
    """The update path is the one an operator uses most, and it applied
    ``setattr`` straight from the body."""
    token = await _admin(db_session)
    group = await _group(db_session)
    await db_session.flush()

    created = await client.post(
        f"/api/v1/dns/groups/{group.id}/views",
        headers=_hdr(token),
        json={"name": "guest", "match_clients": ["10.20.0.0/16"]},
    )
    assert created.status_code == 201
    view_id = created.json()["id"]

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/views/{view_id}",
        headers=_hdr(token),
        json={"match_clients": ["not-an-address"]},
    )
    assert r.status_code == 422

    # The stored value is untouched by the rejected write.
    listed = await client.get(f"/api/v1/dns/groups/{group.id}/views", headers=_hdr(token))
    assert listed.json()[0]["match_clients"] == ["10.20.0.0/16"]


async def test_allow_query_overrides_are_validated(client: AsyncClient, db_session):
    """#430's per-view query ACLs render into the same kind of statement."""
    token = await _admin(db_session)
    group = await _group(db_session)
    await db_session.flush()

    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/views",
        headers=_hdr(token),
        json={
            "name": "guest",
            "match_clients": ["any"],
            "allow_query": ["10.0.0.0/8; }; //"],
        },
    )
    assert r.status_code == 422
    assert r.json()["detail"]["field"] == "allow_query"
