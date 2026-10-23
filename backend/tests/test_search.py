"""Global search v2 (issue #879) — ranking, RBAC, coverage, query shapes.

The load-bearing assertions here are the two things v1 got wrong:

* **Ranking happens before the limit.** A weak substring hit must never
  crowd out an exact match, including when the weak hits outnumber the
  per-type limit.
* **Results are permission-filtered server-side.** v1 checked nothing, so
  ``/api/v1/search`` returned DNS rows to an operator whose own
  ``GET /api/v1/dns/zones`` would 403.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services import feature_modules
from app.services.search import execute
from app.services.search.providers import PROVIDERS, _mac_normalized_sql
from app.services.search.ranking import EXACT, PREFIX, SUBSTRING, escape_like, pick_match
from app.services.search.schemas import shape_of

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture(autouse=True)
async def _reset_module_cache():
    feature_modules.invalidate_cache()
    yield
    feature_modules.invalidate_cache()


# ── helpers ───────────────────────────────────────────────────────────────


async def _user(
    db: AsyncSession, *, permissions: list[dict[str, Any]] | None = None, superadmin: bool = False
) -> tuple[User, str]:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"u-{tag}",
        email=f"{tag}@example.com",
        display_name="U",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    if permissions is not None:
        role = Role(name=f"r-{tag}", description="", is_builtin=False, permissions=permissions)
        group = Group(name=f"g-{tag}", description="")
        group.roles = [role]
        group.users = [user]
        db.add(group)
    db.add(user)
    await db.flush()
    return user, create_access_token(str(user.id))


def _hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _space(db: AsyncSession, name: str = "default") -> IPSpace:
    space = IPSpace(name=f"{name}-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    return space


async def _subnet(db: AsyncSession, space: IPSpace, network: str = "10.0.0.0/24", **kw) -> Subnet:
    net = ipaddress.ip_network(network)
    block = IPBlock(
        space_id=space.id,
        # A block wide enough to hold the subnet — ``subnet.block_id`` is
        # NOT NULL, so every subnet needs one.
        network=ipaddress.ip_network(
            f"{net.network_address}/{max(net.prefixlen - 8, 8)}", strict=False
        ),
        name=f"blk-{uuid.uuid4().hex[:6]}",
        description="",
    )
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network=net,
        name=kw.pop("name", "sn"),
        description=kw.pop("description", ""),
        status="active",
        **kw,
    )
    db.add(subnet)
    await db.flush()
    return subnet


async def _address(db: AsyncSession, subnet: Subnet, address: str, **kw) -> IPAddress:
    ip = IPAddress(
        subnet_id=subnet.id,
        address=ipaddress.ip_address(address),
        status=kw.pop("status", "allocated"),
        hostname=kw.pop("hostname", ""),
        description=kw.pop("description", ""),
        **kw,
    )
    db.add(ip)
    await db.flush()
    return ip


async def _zone_with_record(
    db: AsyncSession, zone_name: str, fqdn: str, value: str = "10.0.0.1"
) -> tuple[DNSServerGroup, DNSZone, DNSRecord]:
    group = DNSServerGroup(name=f"grp-{uuid.uuid4().hex[:6]}", description="")
    db.add(group)
    await db.flush()
    zone = DNSZone(group_id=group.id, name=zone_name, zone_type="master")
    db.add(zone)
    await db.flush()
    record = DNSRecord(
        zone_id=zone.id,
        name=fqdn.split(".")[0],
        fqdn=fqdn,
        record_type="A",
        value=value,
        ttl=300,
    )
    db.add(record)
    await db.flush()
    return group, zone, record


IPAM_READ = [
    {"action": "read", "resource_type": t} for t in ("ip_space", "ip_block", "subnet", "ip_address")
]
DNS_READ = [{"action": "read", "resource_type": t} for t in ("dns_group", "dns_zone", "dns_record")]


# ── ranking ───────────────────────────────────────────────────────────────


async def test_exact_match_outranks_substring_across_types(client: AsyncClient, db_session):
    """The headline v1 bug: type order decided the result order."""
    _, token = await _user(db_session, superadmin=True)
    space = await _space(db_session)
    # A space whose *description* merely contains the term...
    space.description = "hosts the widget cluster"
    space.name = "widget-adjacent-space"
    subnet = await _subnet(db_session, space)
    # ...and an address whose hostname IS the term.
    await _address(db_session, subnet, "10.0.0.5", hostname="widget")
    await db_session.flush()

    r = await client.get("/api/v1/search", headers=_hdr(token), params={"q": "widget"})
    assert r.status_code == 200, r.text
    results = r.json()["results"]
    assert results, "expected hits"
    assert results[0]["type"] == "ip_address"
    assert results[0]["display"] == "10.0.0.5"
    # And the ordering is explained by the score, not by luck.
    assert results[0]["score"] > results[-1]["score"]


async def test_exact_match_survives_a_flood_of_substring_matches(client: AsyncClient, db_session):
    """Ranking must be applied in SQL, before the per-type LIMIT.

    With 60 substring matches and a per-type limit of 25, an unordered
    query returns whichever rows the database felt like — and the exact
    match was routinely not among them. Sorting in Python afterwards
    cannot recover a row that was never fetched.
    """
    _, token = await _user(db_session, superadmin=True)
    space = await _space(db_session)
    subnet = await _subnet(db_session, space, "10.1.0.0/16")
    for i in range(60):
        await _address(
            db_session, subnet, f"10.1.{i // 254}.{i % 254 + 1}", hostname=f"pre-needle-{i}"
        )
    await _address(db_session, subnet, "10.1.250.250", hostname="needle")
    await db_session.flush()

    r = await client.get("/api/v1/search", headers=_hdr(token), params={"q": "needle", "limit": 5})
    results = r.json()["results"]
    assert results[0]["display"] == "10.1.250.250"
    assert results[0]["matched_field"] == "hostname"


async def test_prefix_beats_substring(client: AsyncClient, db_session):
    _, token = await _user(db_session, superadmin=True)
    space = await _space(db_session)
    subnet = await _subnet(db_session, space)
    await _address(db_session, subnet, "10.0.0.2", hostname="not-the-db-server")
    await _address(db_session, subnet, "10.0.0.3", hostname="db-server-primary")
    await db_session.flush()

    r = await client.get("/api/v1/search", headers=_hdr(token), params={"q": "db-server"})
    ordered = [x["display"] for x in r.json()["results"] if x["type"] == "ip_address"]
    assert ordered.index("10.0.0.3") < ordered.index("10.0.0.2")


def test_quality_buckets_dominate_type_weights():
    """An exact hit on the lowest-weighted type must still beat a substring
    hit on the highest. This is the property that makes ranking meaningful
    rather than a tiebreak, so it is pinned rather than left implicit."""
    from app.services.search.ranking import TYPE_WEIGHTS, total_score

    best, worst = max(TYPE_WEIGHTS.values()), min(TYPE_WEIGHTS.values())
    assert EXACT + worst > SUBSTRING + best
    assert PREFIX + worst > SUBSTRING + best
    assert total_score(EXACT, "user") > total_score(SUBSTRING, "ip_address")


def test_pick_match_reports_the_best_field_not_the_first():
    score, field = pick_match("alpha", [("description", "contains alpha here"), ("name", "alpha")])
    assert (score, field) == (EXACT, "name")


# ── LIKE metacharacters ───────────────────────────────────────────────────


def test_escape_like_neutralises_metacharacters():
    assert escape_like("50%") == "50\\%"
    assert escape_like("a_b") == "a\\_b"
    # Backslash first, or the escapes would themselves be escaped.
    assert escape_like("a\\b") == "a\\\\b"


async def test_wildcard_in_query_is_matched_literally(client: AsyncClient, db_session):
    """``%`` used to be interpolated straight into the LIKE pattern, so
    searching for it matched every row in every table."""
    _, token = await _user(db_session, superadmin=True)
    space = await _space(db_session)
    subnet = await _subnet(db_session, space)
    await _address(db_session, subnet, "10.0.0.7", hostname="load-50%-host")
    await _address(db_session, subnet, "10.0.0.8", hostname="unrelated")
    await db_session.flush()

    r = await client.get("/api/v1/search", headers=_hdr(token), params={"q": "50%"})
    hits = [x["display"] for x in r.json()["results"]]
    assert hits == ["10.0.0.7"]


async def test_underscore_is_not_a_single_character_wildcard(client: AsyncClient, db_session):
    _, token = await _user(db_session, superadmin=True)
    space = await _space(db_session)
    subnet = await _subnet(db_session, space)
    await _address(db_session, subnet, "10.0.0.9", hostname="axb")
    await db_session.flush()

    r = await client.get("/api/v1/search", headers=_hdr(token), params={"q": "a_b"})
    assert r.json()["results"] == []


# ── permission filtering ──────────────────────────────────────────────────


async def test_ipam_only_user_cannot_see_dns_rows(client: AsyncClient, db_session):
    """The v1 leak. ``/api/v1/dns/*`` requires read on a dns_* type; search
    returned the same rows to anyone with a session."""
    _, token = await _user(db_session, permissions=IPAM_READ)
    space = await _space(db_session)
    subnet = await _subnet(db_session, space, name="shared-name")
    await _address(db_session, subnet, "10.0.0.10", hostname="shared-name-host")
    await _zone_with_record(db_session, "shared-name.example.com.", "www.shared-name.example.com.")
    await db_session.flush()

    r = await client.get("/api/v1/search", headers=_hdr(token), params={"q": "shared-name"})
    types = {x["type"] for x in r.json()["results"]}
    assert types, "IPAM user should still get their own rows"
    assert types <= {"ip_address", "subnet", "block", "space"}
    assert not any(t.startswith("dns") for t in types)


async def test_dns_only_user_cannot_see_ipam_rows(client: AsyncClient, db_session):
    _, token = await _user(db_session, permissions=DNS_READ)
    space = await _space(db_session)
    subnet = await _subnet(db_session, space, name="shared-name")
    await _address(db_session, subnet, "10.0.0.11", hostname="shared-name-host")
    await _zone_with_record(db_session, "shared-name.example.com.", "www.shared-name.example.com.")
    await db_session.flush()

    r = await client.get("/api/v1/search", headers=_hdr(token), params={"q": "shared-name"})
    types = {x["type"] for x in r.json()["results"]}
    assert types
    assert types <= {"dns_group", "dns_zone", "dns_record"}


async def test_user_directory_is_superadmin_only(client: AsyncClient, db_session):
    """``/api/v1/users`` is superadmin-gated rather than permission-gated,
    so a wildcard ``read`` grant must not turn search into a staff
    directory."""
    target, _ = await _user(db_session)
    _, reader = await _user(db_session, permissions=[{"action": "read", "resource_type": "*"}])
    await db_session.flush()

    r = await client.get("/api/v1/search", headers=_hdr(reader), params={"q": target.username})
    assert not [x for x in r.json()["results"] if x["type"] == "user"]

    _, admin = await _user(db_session, superadmin=True)
    await db_session.flush()
    r = await client.get("/api/v1/search", headers=_hdr(admin), params={"q": target.username})
    assert [x for x in r.json()["results"] if x["type"] == "user"]


async def test_searched_types_reflects_the_callers_permissions(client: AsyncClient, db_session):
    _, token = await _user(db_session, permissions=IPAM_READ)
    await db_session.flush()

    r = await client.get("/api/v1/search/types", headers=_hdr(token))
    assert r.status_code == 200
    groups = {t["group"] for t in r.json()}
    assert groups == {"ipam"}

    r = await client.get("/api/v1/search", headers=_hdr(token), params={"q": "x"})
    assert {t["group"] for t in r.json()["searched_types"]} == {"ipam"}


async def test_requesting_a_forbidden_type_returns_nothing_not_an_error(
    client: AsyncClient, db_session
):
    """A stale scope chip in an open tab should come back empty, not 403 the
    whole search."""
    _, token = await _user(db_session, permissions=IPAM_READ)
    await _zone_with_record(db_session, "forbidden.example.com.", "www.forbidden.example.com.")
    await db_session.flush()

    r = await client.get(
        "/api/v1/search",
        headers=_hdr(token),
        params={"q": "forbidden", "types": "dns_zone,dns_record"},
    )
    assert r.status_code == 200
    assert r.json()["results"] == []


async def test_custom_field_pass_cannot_bypass_the_type_gate(client: AsyncClient, db_session):
    """The IPAM custom-field pass is one query emitting three row types.
    A caller who may read subnets but not addresses must not receive an
    address row through it."""
    from app.models.ipam import CustomFieldDefinition

    db_session.add(
        CustomFieldDefinition(
            resource_type="ip_address",
            name="owner",
            label="Owner",
            field_type="text",
            is_searchable=True,
        )
    )
    _, token = await _user(db_session, permissions=[{"action": "read", "resource_type": "subnet"}])
    space = await _space(db_session)
    subnet = await _subnet(db_session, space)
    await _address(db_session, subnet, "10.0.0.12", custom_fields={"owner": "zaphod"})
    await db_session.flush()

    r = await client.get("/api/v1/search", headers=_hdr(token), params={"q": "zaphod"})
    assert [x["type"] for x in r.json()["results"] if x["type"] == "ip_address"] == []


# ── feature-module gating ─────────────────────────────────────────────────


async def test_disabled_module_removes_its_type(client: AsyncClient, db_session):
    _, token = await _user(db_session, superadmin=True)
    await db_session.flush()

    r = await client.get("/api/v1/search/types", headers=_hdr(token))
    assert "vlan" in {t["type"] for t in r.json()}

    await feature_modules.set_module_enabled(db_session, "network.vlan", False, user_id=None)
    await db_session.flush()
    feature_modules.invalidate_cache()

    r = await client.get("/api/v1/search/types", headers=_hdr(token))
    assert "vlan" not in {t["type"] for t in r.json()}


# ── query shapes ──────────────────────────────────────────────────────────


def test_shape_detection():
    assert shape_of("10.0.0.1").kind == "ip"
    assert shape_of("10.0.0.0/24").kind == "cidr"
    assert shape_of("aa:bb:cc:dd:ee:ff").kind == "mac"
    assert shape_of("aabbccddeeff").kind == "mac"
    assert shape_of("aabb.ccdd.eeff").kind == "mac"
    assert shape_of("web-01").kind == "text"


def test_every_provider_declares_at_least_one_shape():
    for p in PROVIDERS:
        assert p.shapes, f"{p.type} would never run"
        assert p.shapes <= {"text", "ip", "cidr", "mac"}, p.type


def test_mac_shape_runs_only_the_providers_that_can_match_one():
    """A MAC substring-matched against a site's notes was never a result
    anybody wanted, and running twenty queries to prove it is waste."""
    runs = {p.type for p in PROVIDERS if "mac" in p.shapes}
    assert runs == {"ip_address", "dhcp_reservation"}


async def test_mac_lookup_is_separator_insensitive(client: AsyncClient, db_session):
    _, token = await _user(db_session, superadmin=True)
    space = await _space(db_session)
    subnet = await _subnet(db_session, space)
    await _address(
        db_session, subnet, "10.0.0.20", hostname="printer", mac_address="aa:bb:cc:dd:ee:ff"
    )
    await db_session.flush()

    for spelling in ("aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabbccddeeff", "aabb.ccdd.eeff"):
        r = await client.get("/api/v1/search", headers=_hdr(token), params={"q": spelling})
        hits = [x["display"] for x in r.json()["results"]]
        assert hits == ["10.0.0.20"], f"{spelling} found {hits}"


async def test_partial_mac_matches_via_the_normalised_form(client: AsyncClient, db_session):
    """An OUI prefix doesn't parse as a MAC, so it takes the text path —
    which now also normalises, meaning ``aa:bb:cc`` finds a row stored with
    any separator style."""
    _, token = await _user(db_session, superadmin=True)
    space = await _space(db_session)
    subnet = await _subnet(db_session, space)
    await _address(db_session, subnet, "10.0.0.21", mac_address="aa:bb:cc:11:22:33")
    await db_session.flush()

    r = await client.get("/api/v1/search", headers=_hdr(token), params={"q": "aa-bb-cc"})
    assert [x["display"] for x in r.json()["results"]] == ["10.0.0.21"]


async def test_ip_query_finds_the_address_and_its_containers(client: AsyncClient, db_session):
    _, token = await _user(db_session, superadmin=True)
    space = await _space(db_session)
    subnet = await _subnet(db_session, space, "10.5.0.0/24")
    await _address(db_session, subnet, "10.5.0.42", hostname="host42")
    await db_session.flush()

    r = await client.get("/api/v1/search", headers=_hdr(token), params={"q": "10.5.0.42"})
    by_type = {x["type"]: x for x in r.json()["results"]}
    assert by_type["ip_address"]["display"] == "10.5.0.42"
    assert by_type["subnet"]["display"] == "10.5.0.0/24"


async def test_ip_query_finds_dns_records_pointing_at_it(client: AsyncClient, db_session):
    """ "Which name resolves here?" is one of the most common lookups in a
    DDI tool, and v1 could not answer it — an IP query never reached the
    record *value* column."""
    _, token = await _user(db_session, superadmin=True)
    await _zone_with_record(db_session, "example.com.", "api.example.com.", value="10.9.9.9")
    await db_session.flush()

    r = await client.get("/api/v1/search", headers=_hdr(token), params={"q": "10.9.9.9"})
    records = [x for x in r.json()["results"] if x["type"] == "dns_record"]
    assert [x["display"] for x in records] == ["api.example.com."]


async def test_vlan_id_match_is_ranked_in_sql(client: AsyncClient, db_session):
    """A bare number matches ``vlan_id``, which is an integer equality — so
    it has to contribute to the SQL rank too. Ranked only in Python, the
    exact row scores 0 and the LIMIT drops it before Python runs."""
    from app.models.vlans import VLAN, Router

    _, token = await _user(db_session, superadmin=True)
    router = Router(name=f"rtr-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(router)
    await db_session.flush()
    # Enough decoys containing "42" in their names to exhaust a LIMIT.
    for i in range(30):
        db_session.add(
            VLAN(router_id=router.id, vlan_id=1000 + i, name=f"legacy-42-net-{i}", description="")
        )
    db_session.add(VLAN(router_id=router.id, vlan_id=42, name="the-real-one", description=""))
    await db_session.flush()

    r = await client.get("/api/v1/search", headers=_hdr(token), params={"q": "42", "limit": 5})
    vlans = [x for x in r.json()["results"] if x["type"] == "vlan"]
    assert vlans and vlans[0]["display"] == "VLAN 42"
    assert vlans[0]["matched_field"] == "vlan_id"


async def test_custom_field_exact_hit_survives_the_limit(client: AsyncClient, db_session):
    """The custom-field pass had ``.limit()`` with no ``ORDER BY`` — the same
    "database returns any N rows" flaw the rest of the module fixes."""
    from app.models.ipam import CustomFieldDefinition

    db_session.add(
        CustomFieldDefinition(
            resource_type="ip_address",
            name="owner",
            label="Owner",
            field_type="text",
            is_searchable=True,
        )
    )
    _, token = await _user(db_session, superadmin=True)
    space = await _space(db_session)
    subnet = await _subnet(db_session, space, "10.2.0.0/16")
    for i in range(40):
        await _address(
            db_session,
            subnet,
            f"10.2.{i // 254}.{i % 254 + 1}",
            custom_fields={"owner": f"team-ops-and-{i}"},
        )
    await _address(db_session, subnet, "10.2.250.250", custom_fields={"owner": "ops"})
    await db_session.flush()

    r = await client.get("/api/v1/search", headers=_hdr(token), params={"q": "ops", "limit": 5})
    hits = [x for x in r.json()["results"] if x["type"] == "ip_address"]
    assert hits and hits[0]["display"] == "10.2.250.250"
    assert hits[0]["matched_field"] == "custom_field:owner=ops"


def test_custom_field_scoring_uses_the_shared_ladder():
    """Inlined bucket values would silently desync from ``ranking.py``."""
    from app.services.search.providers import _custom_field_hit

    assert _custom_field_hit("ops", {"owner": "ops"}, ["owner"]) == (
        EXACT,
        "custom_field:owner=ops",
    )
    assert _custom_field_hit("ops", {"owner": "ops-team"}, ["owner"])[0] == PREFIX
    assert _custom_field_hit("ops", {"owner": "the-ops-team"}, ["owner"])[0] == SUBSTRING
    assert _custom_field_hit("ops", {"owner": "nothing"}, ["owner"]) == (0, None)


# ── coverage + shape of the response ──────────────────────────────────────


def test_provider_registry_is_internally_consistent():
    seen = set()
    for p in PROVIDERS:
        assert p.type not in seen, f"duplicate provider type {p.type}"
        seen.add(p.type)
        assert p.group in {"ipam", "dns", "dhcp", "network", "admin"}, p.type
        assert p.resource_types, p.type
        assert p.label


def test_every_emitted_type_has_a_ranking_weight():
    """A type with no weight silently ranks as if it were the least
    specific thing in the product."""
    from app.services.search.ranking import TYPE_WEIGHTS

    for p in PROVIDERS:
        for emitted in p.also_emits or (p.type,):
            assert emitted in TYPE_WEIGHTS, f"{emitted} has no type weight"


async def test_new_types_carry_a_route(client: AsyncClient, db_session):
    """Types added in v2 are navigated by path rather than by extending the
    client-side switch, so a missing route makes the row unclickable."""
    from app.models.dhcp import DHCPScope, DHCPServerGroup

    _, token = await _user(db_session, superadmin=True)
    space = await _space(db_session)
    subnet = await _subnet(db_session, space)
    grp = DHCPServerGroup(name=f"dg-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(grp)
    await db_session.flush()
    db_session.add(
        DHCPScope(group_id=grp.id, subnet_id=subnet.id, name="office-wifi", description="")
    )
    await db_session.flush()

    r = await client.get("/api/v1/search", headers=_hdr(token), params={"q": "office-wifi"})
    scopes = [x for x in r.json()["results"] if x["type"] == "dhcp_scope"]
    assert scopes and scopes[0]["route"].startswith("/dhcp?group=")


async def test_results_are_deduplicated_keeping_the_explained_hit(client: AsyncClient, db_session):
    """One row can match a direct column and a custom field. It should
    appear once, with the hint that explains why."""
    from app.models.ipam import CustomFieldDefinition

    db_session.add(
        CustomFieldDefinition(
            resource_type="ip_address",
            name="owner",
            label="Owner",
            field_type="text",
            is_searchable=True,
        )
    )
    _, token = await _user(db_session, superadmin=True)
    space = await _space(db_session)
    subnet = await _subnet(db_session, space)
    await _address(
        db_session, subnet, "10.0.0.30", hostname="marvin", custom_fields={"owner": "marvin"}
    )
    await db_session.flush()

    r = await client.get("/api/v1/search", headers=_hdr(token), params={"q": "marvin"})
    hits = [x for x in r.json()["results"] if x["type"] == "ip_address"]
    assert len(hits) == 1


async def test_soft_deleted_parent_hides_its_addresses(client: AsyncClient, db_session):
    """``IPAddress`` has no soft-delete column of its own — it is hidden by
    its subnet being hidden. The breadcrumb is a separate query now, so
    this is the assertion that keeps that split honest."""
    from datetime import UTC, datetime

    _, token = await _user(db_session, superadmin=True)
    space = await _space(db_session)
    subnet = await _subnet(db_session, space)
    await _address(db_session, subnet, "10.0.0.31", hostname="trashcan")
    await db_session.flush()

    r = await client.get("/api/v1/search", headers=_hdr(token), params={"q": "trashcan"})
    assert [x["display"] for x in r.json()["results"]] == ["10.0.0.31"]

    subnet.deleted_at = datetime.now(tz=UTC)
    await db_session.flush()

    r = await client.get("/api/v1/search", headers=_hdr(token), params={"q": "trashcan"})
    assert r.json()["results"] == []


# ── the MCP tool shares the engine ────────────────────────────────────────


async def test_mcp_global_search_is_permission_filtered(db_session):
    """The Copilot tool used to re-implement the fan-out over the router's
    private helpers, so it inherited neither new types nor any gating."""
    from app.services.ai.tools.observability import GlobalSearchArgs, global_search

    user, _ = await _user(db_session, permissions=IPAM_READ)
    space = await _space(db_session)
    subnet = await _subnet(db_session, space, name="tooltest")
    await _address(db_session, subnet, "10.0.0.40", hostname="tooltest-host")
    await _zone_with_record(db_session, "tooltest.example.com.", "www.tooltest.example.com.")
    await db_session.flush()

    rows = await global_search(db_session, user, GlobalSearchArgs(query="tooltest"))
    assert rows
    assert not any(r["type"].startswith("dns") for r in rows)


def _with_broken_provider(broken_type: str, fn):
    """Copy of the registry with one provider's query function replaced."""
    from app.services.search import providers as provider_module

    return tuple(
        provider_module.SearchProvider(
            type=p.type,
            label=p.label,
            group=p.group,
            resource_types=p.resource_types,
            fn=fn if p.type == broken_type else p.fn,
            module=p.module,
            superadmin_only=p.superadmin_only,
            also_emits=p.also_emits,
            shapes=p.shapes,
        )
        for p in PROVIDERS
    )


async def test_engine_survives_a_broken_provider(db_session, monkeypatch):
    """One failing type must not blank the whole palette."""
    user, _ = await _user(db_session, superadmin=True)
    space = await _space(db_session)
    subnet = await _subnet(db_session, space)
    await _address(db_session, subnet, "10.0.0.50", hostname="resilient")
    await db_session.flush()

    async def boom(*_args, **_kw):
        raise RuntimeError("provider exploded")

    monkeypatch.setattr(
        "app.services.search.engine.PROVIDERS", _with_broken_provider("subnet", boom)
    )

    response = await execute(db_session, user, "resilient")
    assert [r.display for r in response.results if r.type == "ip_address"] == ["10.0.0.50"]


async def test_a_failing_db_query_does_not_poison_the_later_providers(db_session, monkeypatch):
    """The isolation has to survive a **database** error, not just a Python one.

    Catching the exception is not enough on PostgreSQL: a failed statement
    leaves the session in "current transaction is aborted", so every later
    provider dies too and the caller gets ``200 {"results": []}``. The
    provider that fails here is ``ip_address``, which runs first — so
    without a SAVEPOINT per provider this blanks everything behind it.
    """
    from sqlalchemy import text as sqltext

    user, _ = await _user(db_session, superadmin=True)
    space = await _space(db_session)
    subnet = await _subnet(db_session, space, name="survivor")
    await _address(db_session, subnet, "10.0.0.51", hostname="survivor-host")
    await db_session.flush()

    async def bad_sql(db, *_args, **_kw):
        await db.execute(sqltext("SELECT * FROM a_table_that_does_not_exist"))
        return []

    monkeypatch.setattr(
        "app.services.search.engine.PROVIDERS", _with_broken_provider("ip_address", bad_sql)
    )

    response = await execute(db_session, user, "survivor")
    assert [r.display for r in response.results if r.type == "subnet"] == ["10.0.0.0/24"]


# ── index / query drift ───────────────────────────────────────────────────


def test_mac_index_expression_matches_the_query():
    """The trigram index on the normalised MAC is an *expression* index.

    PostgreSQL matches those by comparing the parsed expression, so a
    divergence between the migration and the live query costs the index
    silently — the search keeps working, just slowly, and nothing fails.
    The migration is a frozen historical record and must not import from
    the service, so the two spellings are compared here instead.
    """
    migration = (
        Path(__file__).resolve().parents[1]
        / "alembic"
        / "versions"
        / "f4b91d38a70c_search_trigram_indexes.py"
    ).read_text()
    # Tolerant of how black chooses to wrap the assignment.
    match = re.search(r'_MAC_NORMALIZE_SQL\s*=\s*\(?\s*"([^"]+)"', migration)
    assert match, "migration no longer declares _MAC_NORMALIZE_SQL as a single literal"
    indexed = match.group(1)

    # The migration spells the column bare (it is inside CREATE INDEX ON
    # ip_address); the query qualifies it with the table name.
    queried = _mac_normalized_sql("ip_address").replace("ip_address.mac_address", "mac_address")
    assert indexed == queried


async def test_a_grant_scoped_to_one_subnet_finds_that_subnet_and_no_other(
    client: AsyncClient, db_session
):
    """#2569: the holder of read on ONE subnet found it by neither CIDR nor
    name, because the provider gate asked for a type-level read."""
    space = await _space(db_session)
    mine = await _subnet(db_session, space, "10.77.1.0/24", name="team-lab")
    other = await _subnet(db_session, space, "10.77.2.0/24", name="team-lab-other")
    _, token = await _user(
        db_session,
        permissions=[{"action": "read", "resource_type": "subnet", "resource_id": str(mine.id)}],
    )
    await db_session.flush()

    for q in ("10.77.1.0/24", "team-lab"):
        r = await client.get("/api/v1/search", headers=_hdr(token), params={"q": q})
        assert r.status_code == 200
        subnets = {x["id"] for x in r.json()["results"] if x["type"] == "subnet"}
        assert subnets == {str(mine.id)}, q
        assert str(other.id) not in subnets
