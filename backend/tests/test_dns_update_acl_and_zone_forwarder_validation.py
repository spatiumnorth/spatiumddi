"""Update-ACL fields and BIND9 zone forwarders are validated (#1357).

The rest of the #876 / #899 / #1244 / #1316 class: a dynamic-update ACL
entry's ``name_pattern`` and ``record_types`` are interpolated verbatim into
the zone's ``update-policy`` rule, and a BIND9 forward zone's ``forwarders``
into its ``forwarders { … };``. One bad element makes BIND refuse the file
and the whole server group stops converging.

Each is checked on write (422 naming the element) and again at bundle
assembly, where a row stored before the check is dropped with a log line
instead of shipped.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.router import VALID_RECORD_TYPES
from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSTSIGKey, DNSZone, DNSZoneUpdateAcl
from app.services.dns.agent_config import build_config_bundle
from app.services.dns.named_conf_validation import (
    UPDATE_POLICY_RR_TYPES,
    ViewValidationError,
    validate_update_acl_entry,
    validate_zone_forwarders,
)

# ── Grammar (pure) ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("scope", "pattern", "expected"),
    [
        ("subdomain", "wks.example.com.", "wks.example.com."),
        ("name", "Host1.Example.com", "host1.example.com"),
        ("name", "_acme-challenge.example.com", "_acme-challenge.example.com"),
        ("wildcard", "*.dyn.example.com.", "*.dyn.example.com."),
        ("self", ".", "."),
        ("self", "*", "*"),
        ("self", "*.example.com", "*.example.com"),
        (None, "  ", None),
        (None, None, None),
    ],
)
def test_name_patterns_bind_accepts(scope: str | None, pattern: str | None, expected: str) -> None:
    assert validate_update_acl_entry(scope, pattern, None) == (expected, None)


@pytest.mark.parametrize(
    ("scope", "pattern"),
    [
        ("subdomain", "wks example.com"),
        ("name", "x.example.com; }; grant evil zonesub"),
        ("name", "*.example.com"),  # a leading '*.' only for wildcard / self
        ("subdomain", "."),
        ("wildcard", "*"),
        ("name", "bad..example.com"),
    ],
)
def test_name_patterns_bind_refuses(scope: str, pattern: str) -> None:
    with pytest.raises(ViewValidationError) as exc:
        validate_update_acl_entry(scope, pattern, None)
    assert exc.value.field == "name_pattern"
    assert exc.value.value == pattern


def test_record_types_are_normalised_not_refused_for_case() -> None:
    assert validate_update_acl_entry(
        "zonesub", None, [" a ", "aaaa", "PTR", "dhcid", "ANY", "TYPE65280", "a(5)", ""]
    ) == (None, ["A", "AAAA", "PTR", "DHCID", "ANY", "TYPE65280", "A(5)"])
    assert validate_update_acl_entry(None, None, ["", "  "]) == (None, None)


@pytest.mark.parametrize("bad", ["NOTATYPE", "A;", "A B", "TXT}", "TYPE0", "TYPE70000", "A(x)"])
def test_unknown_record_types_are_refused(bad: str) -> None:
    with pytest.raises(ViewValidationError) as exc:
        validate_update_acl_entry("zonesub", None, ["A", bad])
    assert exc.value.field == "record_types"
    assert exc.value.value == bad


def test_every_authorable_type_bind_serves_is_grantable() -> None:
    # ALIAS / LUA are PowerDNS-only: BIND does not know the mnemonic.
    assert VALID_RECORD_TYPES - {"ALIAS", "LUA"} <= UPDATE_POLICY_RR_TYPES


def test_zone_forwarders_grammar() -> None:
    assert validate_zone_forwarders(
        ["10.0.0.5", "2606:4700:4700::1111@853", " 9.9.9.9 port 5353 ", "1.1.1.1 @ 53"]
    ) == ["10.0.0.5", "2606:4700:4700::1111@853", "9.9.9.9@5353", "1.1.1.1@53"]
    for bad in ("dns.google", "https://dns.google/dns-query", "1.1.1.1@99999", "1.1.1.1; }"):
        with pytest.raises(ViewValidationError) as exc:
            validate_zone_forwarders(["10.0.0.5", bad])
        assert exc.value.field == "forwarders"


# ── API ─────────────────────────────────────────────────────────────────────


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


async def _group(db: AsyncSession, driver: str = "bind9") -> tuple[DNSServerGroup, DNSServer]:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    server = DNSServer(group_id=group.id, name="ns1", driver=driver, host="10.0.0.53", port=53)
    db.add(server)
    await db.flush()
    return group, server


async def _key(db: AsyncSession, group: DNSServerGroup) -> DNSTSIGKey:
    key = DNSTSIGKey(
        group_id=group.id,
        name="dc01-ddns.",
        algorithm="hmac-sha256",
        secret_encrypted=encrypt_str("c2VjcmV0"),
    )
    db.add(key)
    await db.flush()
    return key


@pytest.mark.parametrize(
    ("entry", "fragment"),
    [
        ({"name_scope": "subdomain", "name_pattern": "wks example.com"}, "name_pattern"),
        ({"name_scope": "zonesub", "record_types": ["A", "BOGUS"]}, "BOGUS"),
    ],
)
async def test_update_acl_put_refuses_a_bad_entry(
    client: AsyncClient, db_session: AsyncSession, entry: dict, fragment: str
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session)
    key = await _key(db_session, group)
    zone = DNSZone(group_id=group.id, name="dyn.example.com.", zone_type="primary", kind="forward")
    db_session.add(zone)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/zones/{zone.id}/update-acl"

    good = {"match_kind": "tsig_key", "tsig_key_id": str(key.id)}
    # First write (the ACL's "create") …
    r = await client.put(url, headers=headers, json={"entries": [{**good, **entry}]})
    assert r.status_code == 422, r.text
    assert fragment in r.text
    # … and a replace of an existing ACL (its "update").
    r = await client.put(url, headers=headers, json={"entries": [good]})
    assert r.status_code == 200, r.text
    r = await client.put(url, headers=headers, json={"entries": [good, {**good, **entry}]})
    assert r.status_code == 422, r.text
    assert fragment in r.text


async def test_update_acl_put_accepts_wildcards_and_type_lists(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session)
    key = await _key(db_session, group)
    zone = DNSZone(group_id=group.id, name="dyn.example.com.", zone_type="primary", kind="forward")
    db_session.add(zone)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/zones/{zone.id}/update-acl",
        headers=headers,
        json={
            "dynamic_update_enabled": True,
            "entries": [
                {
                    "match_kind": "tsig_key",
                    "tsig_key_id": str(key.id),
                    "name_scope": "wildcard",
                    "name_pattern": "*.wks.dyn.example.com.",
                    "record_types": ["a", "AAAA", "dhcid"],
                },
                {
                    "match_kind": "tsig_key",
                    "tsig_key_id": str(key.id),
                    "action": "deny",
                    "name_scope": "zonesub",
                    "record_types": ["ANY"],
                },
            ],
        },
    )
    assert r.status_code == 200, r.text
    first, second = r.json()["entries"]
    assert first["name_pattern"] == "*.wks.dyn.example.com."
    assert first["record_types"] == ["A", "AAAA", "DHCID"]
    assert second["record_types"] == ["ANY"]


async def test_bind9_zone_forwarders_are_checked_on_create_and_update(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/zones"

    r = await client.post(
        url,
        headers=headers,
        json={"name": "corp.example", "zone_type": "forward", "forwarders": ["dns.google"]},
    )
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["field"] == "forwarders"
    assert r.json()["detail"]["value"] == "dns.google"

    r = await client.post(
        url,
        headers=headers,
        json={
            "name": "corp.example",
            "zone_type": "forward",
            "forwarders": ["10.0.0.5", "2001:db8::53@5353", "10.0.0.6 port 53"],
        },
    )
    assert r.status_code == 201, r.text
    assert r.json()["forwarders"] == ["10.0.0.5", "2001:db8::53@5353", "10.0.0.6@53"]
    zone_id = r.json()["id"]

    r = await client.put(
        f"{url}/{zone_id}", headers=headers, json={"forwarders": ["10.0.0.5", "1.1.1.1@0"]}
    )
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["value"] == "1.1.1.1@0"


async def test_a_stored_bad_forwarder_does_not_block_an_unrelated_edit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session)
    zone = DNSZone(
        group_id=group.id,
        name="old.example.",
        zone_type="forward",
        kind="forward",
        forwarders=["resolver.internal"],
    )
    db_session.add(zone)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/zones/{zone.id}",
        headers=headers,
        json={"forwarders": ["resolver.internal"], "forward_only": False},
    )
    assert r.status_code == 200, r.text


async def test_technitium_zone_forwarders_may_still_be_hostnames(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, driver="technitium")
    await db_session.commit()

    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones",
        headers=headers,
        json={
            "name": "corp.example",
            "zone_type": "forward",
            "forwarders": ["dns.google", "https://cloudflare-dns.com/dns-query"],
        },
    )
    assert r.status_code == 201, r.text
    assert r.json()["forwarders"] == ["dns.google", "https://cloudflare-dns.com/dns-query"]


# ── Bundle: rows stored before the check ────────────────────────────────────


async def test_bundle_drops_unrenderable_rows_and_keeps_the_rest(
    db_session: AsyncSession,
) -> None:
    group, server = await _group(db_session)
    key = await _key(db_session, group)
    dyn = DNSZone(
        group_id=group.id,
        name="dyn.example.com.",
        zone_type="primary",
        kind="forward",
        dynamic_update_enabled=True,
    )
    fwd = DNSZone(
        group_id=group.id,
        name="corp.example.",
        zone_type="forward",
        kind="forward",
        forwarders=["10.0.0.5", "resolver.internal", "10.0.0.6 port 5353"],
    )
    db_session.add_all([dyn, fwd])
    await db_session.flush()

    def acl(seq: int, **kw: object) -> DNSZoneUpdateAcl:
        return DNSZoneUpdateAcl(
            zone_id=dyn.id, seq=seq, match_kind="tsig_key", tsig_key_id=key.id, **kw
        )

    db_session.add_all(
        [
            acl(0, action="grant", name_scope="subdomain", name_pattern="ok.dyn.example.com."),
            # A bad grant: dropped on its own (only ever removes permission).
            acl(1, action="grant", name_scope="name", name_pattern="x; }; grant evil zonesub"),
            acl(2, action="grant", name_scope="zonesub", record_types=["A", "PTR"]),
            # A bad deny: dropping it alone would let the grant below match
            # what it refused, so everything after it goes too.
            acl(3, action="deny", name_scope="zonesub", record_types=["NOPE"]),
            acl(4, action="grant", name_scope="zonesub"),
        ]
    )
    await db_session.commit()

    bundle = await build_config_bundle(db_session, server)
    zones = {z["name"]: z for z in bundle["zones"]}
    shipped = zones["dyn.example.com."]["update_acl"]
    assert [(e["action"], e["name_pattern"], e["record_types"]) for e in shipped] == [
        ("grant", "ok.dyn.example.com.", None),
        ("grant", None, ["A", "PTR"]),
    ]
    assert zones["corp.example."]["forwarders"] == ["10.0.0.5", "10.0.0.6@5353"]
    # The rest of the bundle is intact.
    assert zones["dyn.example.com."]["dynamic_update_enabled"] is True
    assert bundle["etag"]


async def test_a_technitium_bundle_keeps_hostname_forwarders(db_session: AsyncSession) -> None:
    group, server = await _group(db_session, driver="technitium")
    db_session.add(
        DNSZone(
            group_id=group.id,
            name="corp.example.",
            zone_type="forward",
            kind="forward",
            forwarders=["dns.google"],
        )
    )
    await db_session.commit()

    bundle = await build_config_bundle(db_session, server)
    (zone,) = [z for z in bundle["zones"] if z["name"] == "corp.example."]
    assert zone["forwarders"] == ["dns.google"]
