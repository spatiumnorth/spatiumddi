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
        ("query_log_channel", "file", "file; stderr"),
        ("query_log_severity", "debug 3", "loud"),
    ],
)
def test_bare_token_options_take_only_their_grammar(field: str, good: str, bad: str):
    assert _ok(field, good) == good
    assert _bad(field, bad).value == bad


@pytest.mark.parametrize("channel", ["syslog", "stderr"])
def test_query_log_channel_other_than_file_is_refused(channel: str):
    # #2265: the shipper tails the file channel; syslog / stderr would
    # leave the DNS Queries tab empty.
    assert _bad("query_log_channel", channel).value == channel


@pytest.mark.parametrize("severity", ["notice", "warning", "error", "critical"])
def test_query_log_severity_that_drops_every_query_is_refused(severity: str):
    # named logs queries at info; a channel threshold above it drops them.
    assert _bad("query_log_severity", severity).value == severity


@pytest.mark.parametrize("severity", ["info", "debug", "debug 2", "dynamic"])
def test_query_log_severity_that_keeps_queries_is_accepted(severity: str):
    assert _ok("query_log_severity", severity) == severity


def test_query_log_file_may_not_move_off_the_shipper_path():
    assert _bad("query_log_file", "/var/log/named/other.log").field == "query_log_file"


def test_query_log_print_time_may_not_be_turned_off():
    assert _bad("query_log_print_time", False).field == "query_log_print_time"
    assert _ok("query_log_print_time", True) is True


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
    r = await client.put(url, json={"query_log_file": "/var/log/named/other.log"}, headers=headers)
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["field"] == "query_log_file"


# ── Technitium cannot apply some options (#1763) ──────────────────────


async def _technitium_group(db: AsyncSession) -> DNSServerGroup:
    from app.models.dns import DNSServer

    group = await _group(db)
    db.add(DNSServer(group_id=group.id, name="t1", driver="technitium", host="t1", port=53))
    await db.flush()
    return group


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        {"minimal_responses": True},
        {"tcp_clients": 100},
        {"clients_per_query": 10},
        {"max_clients_per_query": 10},
        {"allow_query": ["localnets"]},
        {"allow_query": ["key xfer-key"]},
    ],
)
async def test_a_technitium_group_refuses_options_the_daemon_ignores(
    client: AsyncClient, db_session: AsyncSession, body: dict
):
    headers = await _superadmin(db_session)
    group = await _technitium_group(db_session)
    db_session.add(
        DNSTSIGKey(
            group_id=group.id, name="xfer-key", algorithm="hmac-sha256", secret_encrypted=b"x"
        )
    )
    await db_session.commit()
    r = await client.put(f"/api/v1/dns/groups/{group.id}/options", json=body, headers=headers)
    assert r.status_code == 422, r.text
    assert "Technitium" in str(r.json()["detail"])


@pytest.mark.asyncio
async def test_a_technitium_group_still_takes_what_the_daemon_applies(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _superadmin(db_session)
    group = await _technitium_group(db_session)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/options"
    body = {
        "dnssec_validation": "no",
        "allow_query": ["!10.1.0.0/16", "10.0.0.0/8", "2001:db8::/32"],
        # Defaults re-posted by the form on every save stay allowed.
        "minimal_responses": False,
        # 'only' is what Technitium does with forwarders (#1764).
        "forward_policy": "only",
        "forward_tls_verify": True,
    }
    r = await client.put(url, json=body, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["dnssec_validation"] == "no"
    assert r.json()["technitium_warnings"] == []


@pytest.mark.asyncio
async def test_a_non_technitium_group_keeps_every_option(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        json={"forward_policy": "only", "minimal_responses": True, "tcp_clients": 50},
        headers=headers,
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_a_stored_unsupported_value_does_not_block_resaving_it(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _superadmin(db_session)
    group = await _technitium_group(db_session)
    db_session.add(DNSServerOptions(group_id=group.id, minimal_responses=True, tcp_clients=7))
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        json={"minimal_responses": True, "tcp_clients": 7, "rrl_window": 20},
        headers=headers,
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_a_technitium_server_joining_a_group_with_stored_values_is_warned(
    client: AsyncClient, db_session: AsyncSession
):
    """A value stored before a Technitium server joined never passes the PUT
    gate (agent registration, a move or a Fleet assignment add the server),
    so the options response names it instead."""
    from app.models.dns import DNSServer

    headers = await _superadmin(db_session)
    group = await _group(db_session)
    db_session.add(DNSServerOptions(group_id=group.id, tcp_clients=50, allow_query=["localnets"]))
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/options"

    r = await client.get(url, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["technitium_warnings"] == []  # no Technitium server yet

    db_session.add(DNSServer(group_id=group.id, name="t1", driver="technitium", host="t1", port=53))
    await db_session.commit()
    r = await client.get(url, headers=headers)
    warnings = r.json()["technitium_warnings"]
    assert any(w.startswith("tcp_clients") for w in warnings), warnings
    assert any("localnets" in w for w in warnings), warnings

    # Clearing both clears the warning, and the clear itself is not refused.
    r = await client.put(url, json={"tcp_clients": None, "allow_query": ["any"]}, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["technitium_warnings"] == []


# ── Forwarding semantics on Technitium (#1764) ────────────────────────


@pytest.mark.asyncio
async def test_a_technitium_group_refuses_opportunistic_dot(
    client: AsyncClient, db_session: AsyncSession
):
    """Technitium validates every encrypted upstream's certificate; verify off
    was accepted, then refused by the agent on every apply."""
    headers = await _superadmin(db_session)
    group = await _technitium_group(db_session)
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        json={"forward_transport": "tls", "forward_tls_verify": False},
        headers=headers,
    )
    assert r.status_code == 422, r.text
    assert "forward_tls_verify" in str(r.json()["detail"])


@pytest.mark.asyncio
async def test_a_technitium_group_cannot_be_moved_back_to_forward_first(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _superadmin(db_session)
    group = await _technitium_group(db_session)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/options"
    # Re-posting the stored default is fine...
    r = await client.put(url, json={"forward_policy": "first"}, headers=headers)
    assert r.status_code == 200, r.text
    # ...'only' is accepted...
    r = await client.put(url, json={"forward_policy": "only"}, headers=headers)
    assert r.status_code == 200, r.text
    # ...and going back to 'first' is a change to something untrue.
    r = await client.put(url, json={"forward_policy": "first"}, headers=headers)
    assert r.status_code == 422, r.text
    assert "forward_policy" in str(r.json()["detail"])


@pytest.mark.asyncio
async def test_stored_forward_first_with_forwarders_is_warned_on_technitium(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _superadmin(db_session)
    group = await _technitium_group(db_session)
    db_session.add(DNSServerOptions(group_id=group.id, forwarders=["9.9.9.9"]))
    await db_session.commit()
    r = await client.get(f"/api/v1/dns/groups/{group.id}/options", headers=headers)
    assert any(w.startswith("forward_policy") for w in r.json()["technitium_warnings"])
    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options", json={"forward_policy": "only"}, headers=headers
    )
    assert not any(w.startswith("forward_policy") for w in r.json()["technitium_warnings"])


@pytest.mark.asyncio
async def test_a_technitium_group_needs_a_tls_name_even_with_stored_verify_off(
    client: AsyncClient, db_session: AsyncSession
):
    """A legacy row with verification off re-posts it (allowed, it is
    stored); tls with no name still has to be refused, because the agent
    will not send bare IPs over Tls (they fail wherever the certificate has
    no IP SAN), so the API would otherwise store forwarders that never
    apply (#1764)."""
    headers = await _superadmin(db_session)
    group = await _technitium_group(db_session)
    db_session.add(DNSServerOptions(group_id=group.id, forward_tls_verify=False))
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/options"
    r = await client.put(
        url,
        json={"forward_transport": "tls", "forward_tls_verify": False, "forwarders": ["9.9.9.9"]},
        headers=headers,
    )
    assert r.status_code == 422, r.text
    assert "forward_tls_hostname" in str(r.json()["detail"])
    r = await client.put(
        url,
        json={
            "forward_transport": "tls",
            "forward_tls_verify": False,
            "forward_tls_hostname": "dns.quad9.net",
            "forwarders": ["9.9.9.9"],
        },
        headers=headers,
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_stored_tls_without_name_is_warned_on_technitium(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _superadmin(db_session)
    group = await _technitium_group(db_session)
    db_session.add(
        DNSServerOptions(
            group_id=group.id,
            forward_transport="tls",
            forward_tls_verify=False,
            forward_policy="only",
            forwarders=["9.9.9.9"],
        )
    )
    await db_session.commit()
    r = await client.get(f"/api/v1/dns/groups/{group.id}/options", headers=headers)
    warnings = r.json()["technitium_warnings"]
    assert any(w.startswith("forward_transport 'tls'") for w in warnings), warnings
