"""DNS server-group options are validated before they reach named.conf (#1244).

``PUT /dns/groups/{id}/options`` stored ``allow-query`` and friends, the
bare-token options and the query-log path with no checks, and the renderers
interpolate them verbatim. One bad element and ``named-checkconf`` refused
the whole bundle — reverted and alerted since #882, but only after the form
had reported the save as successful.

What the tests pin:

* each grammar accepts what BIND accepts and refuses the rest, naming the
  element;
* the API answers 422 with the field and value, and writes nothing;
* a value stored before the gate existed does not block an unrelated save,
  because the options form sends every field every time.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSAcl, DNSServerGroup, DNSServerOptions, DNSTSIGKey
from app.services.dns.named_conf_validation import (
    ADDRESS_MATCH_LIST_OPTIONS,
    ViewValidationError,
    validate_server_option,
)

_KEYS = frozenset({"xfer-key"})
_ACLS = frozenset({"office"})


def _ok(field: str, value: object) -> object:
    return validate_server_option(field, value, known_acls=_ACLS, known_keys=_KEYS)


def _bad(field: str, value: object) -> ViewValidationError:
    with pytest.raises(ViewValidationError) as info:
        _ok(field, value)
    assert info.value.field == field
    return info.value


# ── grammars ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("field", ADDRESS_MATCH_LIST_OPTIONS)
def test_address_match_lists_accept_what_bind_accepts(field: str):
    value = ["any", "!10.0.0.5", "192.0.2.0/24", "2001:db8::/32", "office", "key xfer-key"]
    assert _ok(field, value) == value


@pytest.mark.parametrize("field", ADDRESS_MATCH_LIST_OPTIONS)
@pytest.mark.parametrize(
    "element",
    ["10.0.0.300", "10.0.0.0/33", 'any; }; include "/etc/passwd', "undefined-acl", "key nokey", ""],
)
def test_address_match_lists_refuse_and_name_the_element(field: str, element: str):
    err = _bad(field, ["any", element])
    assert err.value == element


def test_forwarders_take_an_ip_with_an_optional_port():
    assert _ok("forwarders", ["1.1.1.1", "2606:4700:4700::1111", "9.9.9.9@853"]) == [
        "1.1.1.1",
        "2606:4700:4700::1111",
        "9.9.9.9@853",
    ]


@pytest.mark.parametrize("bad", ["dns.google", "1.1.1.1@", "1.1.1.1@99999", "1.1.1.1; }"])
def test_forwarders_refuse_anything_else(bad: str):
    assert _bad("forwarders", [bad]).value == bad


def test_also_notify_takes_ip_port_and_key():
    value = [
        "192.0.2.1",
        "192.0.2.2 port 5353",
        "2001:db8::1 key xfer-key",
        "192.0.2.3 port 53 key xfer-key",
    ]
    assert _ok("also_notify", value) == value


@pytest.mark.parametrize(
    "bad",
    [
        "office",
        "192.0.2.0/24",
        "!192.0.2.1",
        "192.0.2.1 port 0",
        "192.0.2.1 key nokey",
        "192.0.2.1 extra",
    ],
)
def test_also_notify_is_not_an_address_match_list(bad: str):
    # also-notify names servers to NOTIFY: an ACL name, a prefix or a
    # negation is a syntax error there, unlike in allow-notify.
    assert _bad("also_notify", [bad]).value == bad


@pytest.mark.parametrize(
    ("field", "good", "bad"),
    [
        ("forward_policy", "only", "sometimes"),
        ("dnssec_validation", "auto", "maybe"),
        ("notify_enabled", "explicit", "yes; recursion yes"),
        ("query_log_channel", "syslog", "file; stderr"),
        ("query_log_severity", "debug 3", "loud"),
    ],
)
def test_bare_token_options_take_only_their_grammar(field: str, good: str, bad: str):
    assert _ok(field, good) == good
    assert _bad(field, bad).value == bad


def test_query_log_path_must_be_a_plain_file_under_the_log_dir():
    assert _ok("query_log_file", "/var/log/named/queries.log") == "/var/log/named/queries.log"
    for bad in (
        "relative.log",
        "/var/log/named/../../etc/passwd",
        '/var/log/named/q.log" versions 99',
        "/var/log/named/q.log;",
        "/var/log/named/a b.log",
        "/tmp/queries.log",
        "/var/log/named/",
    ):
        assert _bad("query_log_file", bad).value == bad


def test_keytab_path_must_be_a_plain_file_under_etc_or_var_lib():
    assert _ok("gss_tsig_keytab_path", "/etc/bind/dns.keytab") == "/etc/bind/dns.keytab"
    assert _ok("gss_tsig_keytab_path", "/var/lib/bind/dns.keytab") == "/var/lib/bind/dns.keytab"
    for bad in ("/root/dns.keytab", "/etc/../root/k", '/etc/k"'):
        _bad("gss_tsig_keytab_path", bad)


def test_fields_without_a_grammar_pass_through():
    assert _ok("rrl_window", 15) == 15
    assert _ok("gss_tsig_realm", "EXAMPLE.COM") == "EXAMPLE.COM"


# ── API ───────────────────────────────────────────────────────────────


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="sa",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    u.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _group(db: AsyncSession) -> DNSServerGroup:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    return group


@pytest.mark.asyncio
async def test_a_bad_element_is_a_422_naming_it_and_nothing_is_saved(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/options"

    r = await client.put(
        url, json={"allow_query": ["any"], "blackhole": ["10.0.0.300"]}, headers=headers
    )
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["field"] == "blackhole"
    assert r.json()["detail"]["value"] == "10.0.0.300"

    got = (await client.get(url, headers=headers)).json()
    assert got["blackhole"] == []


@pytest.mark.asyncio
async def test_names_defined_in_the_group_are_accepted(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    db_session.add(DNSAcl(group_id=group.id, name="office"))
    db_session.add(
        DNSTSIGKey(
            group_id=group.id, name="xfer-key", algorithm="hmac-sha256", secret_encrypted=b"x"
        )
    )
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        json={
            "allow_recursion": ["office"],
            "allow_transfer": ["key xfer-key"],
            "also_notify": ["192.0.2.1 key xfer-key"],
        },
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["allow_recursion"] == ["office"]


@pytest.mark.asyncio
async def test_a_value_stored_before_the_gate_does_not_block_an_unrelated_save(
    client: AsyncClient, db_session: AsyncSession
):
    # The options form sends every field on every save. A legacy value the
    # gate would now refuse must not make the whole form unsavable.
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    db_session.add(DNSServerOptions(group_id=group.id, query_log_file="/srv/legacy/queries.log"))
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/options"

    r = await client.put(
        url,
        json={"query_log_file": "/srv/legacy/queries.log", "rrl_window": 20},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["rrl_window"] == 20

    # Changing it is checked like any other new value.
    r = await client.put(url, json={"query_log_file": "/srv/other.log"}, headers=headers)
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["field"] == "query_log_file"
