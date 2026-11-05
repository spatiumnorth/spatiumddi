"""Every ``@read_only_post`` route is proven, at runtime, to write nothing and
call nothing out (#3356, part of #3302).

``@read_only_post`` is a claim: the route is a filter or a preview, so a
``read``-scoped API token may call it. The structural guard
(``test_token_read_only_post_3223.py``) only checks that the marker sits on
the reviewed set of routes. It cannot see a handler that quietly writes a row,
an audit entry, or opens a socket, and such a handler would let a ``read``
token change state or make SpatiumDDI contact another host.

This harness calls each marked route over HTTP with a valid body, as a
``read``-scoped token, against seeded data, while:

* any INSERT / UPDATE / DELETE / TRUNCATE reaching the database is recorded
  (an engine-level hook, so it also sees a handler's own short-lived session,
  plus a session ``before_flush`` hook that names the offending object), and
* every socket that is not the test database, Redis or loopback is refused,
  and so is every name lookup outside that set (a ``sendto`` datagram too).

The route set is imported from the structural guard, not copied: a route
added there without a case here (or an explicit exemption with a reason)
fails ``test_every_read_only_route_has_a_case_or_a_reason``.

The negative controls at the bottom drive a throwaway app through the same
guard to show that a read-only handler which writes, or which opens a socket,
fails it. Without them a guard that never fires would look exactly like a
clean tree.

HOW TO RUN:
    make test-one T=tests/test_read_only_post_runtime_3356.py
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import ipaddress
import os
import re
import socket
import tarfile
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event, text
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.config import settings
from app.core.security import generate_api_token, hash_password
from app.db import get_db
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.auth import APIToken, User
from app.models.dhcp import DHCPServerGroup
from app.models.dns import DNSServerGroup, DNSZone
from app.models.e911 import EmergencyResponseLocation, ERLBinding
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet, SubnetPlan
from app.models.wol_schedule import WolSchedule
from tests.test_token_read_only_post_3223 import EXPECTED_READ_ONLY_POSTS

# ── The guard ─────────────────────────────────────────────────────────────

_DML = re.compile(r"^\s*(INSERT|UPDATE|DELETE|TRUNCATE|COPY|MERGE)\b", re.IGNORECASE)
# ``WITH x AS (...) INSERT ...`` / a data-modifying CTE.
_CTE_DML = re.compile(r"\b(INSERT\s+INTO|DELETE\s+FROM|UPDATE\s+\"?\w+\"?\s+SET)\b", re.IGNORECASE)


def _is_dml(statement: str) -> bool:
    if _DML.match(statement):
        return True
    return bool(re.match(r"^\s*WITH\b", statement, re.IGNORECASE) and _CTE_DML.search(statement))


def _hosts_of(url: str) -> set[str]:
    """Every host a URL names (sentinel URLs list several, comma-separated)."""
    out: set[str] = set()
    netloc = url.split("://", 1)[-1].split("/", 1)[0].rsplit("@", 1)[-1]
    for part in netloc.split(","):
        host = part.strip().rsplit(":", 1)[0].strip("[]") if part.strip() else ""
        if host:
            out.add(host)
    return out


def _resolve(host: str) -> set[str]:
    try:
        return {ai[4][0] for ai in socket.getaddrinfo(host, None)}
    except OSError:
        return set()


def _allowed_hosts() -> tuple[set[str], set[str]]:
    """``(names, ip literals)`` the guard lets through: the test database and
    Redis. Resolved BEFORE the guard is armed, so resolving them is not
    itself a violation."""
    names: set[str] = set()
    for url in (
        os.environ.get("TEST_DATABASE_URL", ""),
        os.environ.get("DATABASE_URL", ""),
        getattr(settings, "redis_url", "") or "",
    ):
        names |= _hosts_of(url) if url else set()
    names |= {"localhost", "test", "testserver"}
    ips: set[str] = set()
    for n in names:
        ips |= _resolve(n)
    return names, ips


def _is_local(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_loopback
    except ValueError:
        return False


@dataclass
class Guard:
    """What a guarded request did that a read-only route must not."""

    writes: list[str] = field(default_factory=list)
    sockets: list[str] = field(default_factory=list)
    armed: bool = False

    @property
    def violations(self) -> list[str]:
        return [f"DML: {w}" for w in self.writes] + [f"NET: {s}" for s in self.sockets]


@contextlib.contextmanager
def forbid_writes_and_sockets(allowed_names: set[str], allowed_ips: set[str]) -> Iterator[Guard]:
    guard = Guard()

    def on_cursor(conn, cursor, statement, parameters, context, executemany):  # type: ignore[no-untyped-def]
        if guard.armed and _is_dml(statement):
            guard.writes.append(" ".join(statement.split())[:200])

    def on_flush(session, flush_context, instances):  # type: ignore[no-untyped-def]
        if not guard.armed:
            return
        for kind, objs in (
            ("new", session.new),
            ("dirty", [o for o in session.dirty if session.is_modified(o)]),
            ("deleted", session.deleted),
        ):
            for o in objs:
                guard.writes.append(f"flush {kind} {type(o).__name__}")

    def permitted(address: Any) -> bool:
        if isinstance(address, (str, bytes)):  # AF_UNIX
            return True
        host = str(address[0])
        return host in allowed_names or host in allowed_ips or _is_local(host)

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_sendto = socket.socket.sendto
    real_getaddrinfo = socket.getaddrinfo
    real_create_connection = socket.create_connection

    def refuse(what: str, address: Any) -> None:
        guard.sockets.append(f"{what} {address!r}")
        raise OSError(f"outbound network blocked by the #3356 harness: {what} {address!r}")

    def connect(self, address):  # type: ignore[no-untyped-def]
        if guard.armed and not permitted(address):
            refuse("connect", address)
        return real_connect(self, address)

    def connect_ex(self, address):  # type: ignore[no-untyped-def]
        if guard.armed and not permitted(address):
            refuse("connect_ex", address)
        return real_connect_ex(self, address)

    def sendto(self, data, *args):  # type: ignore[no-untyped-def]
        address = args[-1] if args else None
        if guard.armed and address is not None and not permitted(address):
            refuse("sendto", address)
        return real_sendto(self, data, *args)

    def create_connection(address, *a, **kw):  # type: ignore[no-untyped-def]
        if guard.armed and not permitted(address):
            refuse("create_connection", address)
        return real_create_connection(address, *a, **kw)

    def getaddrinfo(host, *a, **kw):  # type: ignore[no-untyped-def]
        if guard.armed and host not in (None, "") and not permitted((host,)):
            refuse("getaddrinfo", host)
        return real_getaddrinfo(host, *a, **kw)

    event.listen(Engine, "before_cursor_execute", on_cursor)
    event.listen(Session, "before_flush", on_flush)
    socket.socket.connect = connect  # type: ignore[method-assign]
    socket.socket.connect_ex = connect_ex  # type: ignore[method-assign]
    socket.socket.sendto = sendto  # type: ignore[method-assign]
    socket.create_connection = create_connection  # type: ignore[assignment]
    socket.getaddrinfo = getaddrinfo  # type: ignore[assignment]
    try:
        yield guard
    finally:
        guard.armed = False
        socket.socket.connect = real_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = real_connect_ex  # type: ignore[method-assign]
        socket.socket.sendto = real_sendto  # type: ignore[method-assign]
        socket.create_connection = real_create_connection  # type: ignore[assignment]
        socket.getaddrinfo = real_getaddrinfo  # type: ignore[assignment]
        event.remove(Engine, "before_cursor_execute", on_cursor)
        event.remove(Session, "before_flush", on_flush)


# ── Seeded data ───────────────────────────────────────────────────────────


@dataclass
class Seed:
    raw_token: str
    space_id: uuid.UUID
    other_space_id: uuid.UUID
    block_id: uuid.UUID
    resize_block_id: uuid.UUID
    subnet_id: uuid.UUID
    sibling_id: uuid.UUID
    resize_subnet_id: uuid.UUID
    dns_group_id: uuid.UUID
    other_dns_group_id: uuid.UUID
    zone_id: uuid.UUID
    dhcp_group_id: uuid.UUID
    plan_id: uuid.UUID
    appliance_id: uuid.UUID
    schedule_id: uuid.UUID
    subnet_ids_for_wake: list[uuid.UUID] = field(default_factory=list)


async def _seed(db: AsyncSession) -> Seed:
    owner = User(
        username=f"owner-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Owner",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(owner)
    await db.flush()
    raw, _prefix, token_hash = generate_api_token()
    # ``last_used_at`` is stamped "now" so the once-a-minute bookkeeping write
    # in ``_resolve_api_token`` (#1158) is not what this harness measures: it
    # is the token's own use-tracking, not a thing the route did. Nothing else
    # is allowlisted.
    db.add(
        APIToken(
            name="harness-read",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=["read"],
            user_id=owner.id,
            created_by_user_id=owner.id,
            last_used_at=datetime.now(UTC),
        )
    )

    space = IPSpace(name="h-space")
    other = IPSpace(name="h-other")
    db.add_all([space, other])
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.20.0.0/16", name="b1")
    resize_block = IPBlock(space_id=space.id, network="10.40.0.0/24", name="b2")
    block3 = IPBlock(space_id=space.id, network="10.50.0.0/16", name="b3")
    db.add_all([block, resize_block, block3])
    await db.flush()
    subnet = Subnet(
        space_id=space.id, block_id=block.id, network="10.20.0.0/24", name="s1", kind="unicast"
    )
    sibling = Subnet(
        space_id=space.id, block_id=block.id, network="10.20.1.0/24", name="s2", kind="unicast"
    )
    resize_subnet = Subnet(
        space_id=space.id, block_id=block3.id, network="10.50.0.0/24", name="s3", kind="unicast"
    )
    db.add_all([subnet, sibling, resize_subnet])
    await db.flush()
    # So POST /held answers 200 (a binding on the subnet) rather than locationUnknown.
    erl = EmergencyResponseLocation(name="harness-erl", country="US", a1="NY", room="1")
    db.add(erl)
    await db.flush()
    db.add(ERLBinding(erl_id=erl.id, rule_kind="subnet", subnet_id=subnet.id))
    await db.flush()
    for i in (5, 6):
        db.add(
            IPAddress(
                subnet_id=subnet.id,
                address=f"10.20.0.{i}",
                mac_address=f"aa:bb:cc:dd:ee:0{i}",
                hostname=f"host{i}",
                status="allocated",
                tags={"wake": "nightly"},
            )
        )
    for i in (10, 11):
        db.add(IPAddress(subnet_id=resize_subnet.id, address=f"10.50.0.{i}", status="allocated"))

    dns_group = DNSServerGroup(name="h-grp", description="")
    other_dns = DNSServerGroup(name="h-grp-2", description="")
    db.add_all([dns_group, other_dns])
    await db.flush()
    zone = DNSZone(
        group_id=dns_group.id,
        name="example.com.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.com.",
        admin_email="hostmaster.example.com.",
        last_serial=1,
    )
    dhcp_group = DHCPServerGroup(name="h-dhcp")
    plan = SubnetPlan(
        name="h-plan",
        space_id=space.id,
        tree={
            "id": "r",
            "network": "10.60.0.0/16",
            "kind": "block",
            "children": [{"id": "a", "network": "10.60.1.0/24", "kind": "subnet"}],
        },
    )
    der = hashlib.sha256(uuid.uuid4().bytes).digest()
    appliance = Appliance(
        id=uuid.uuid4(),
        hostname=f"n-{uuid.uuid4().hex[:6]}",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        appliance_variant="application",
    )
    schedule = WolSchedule(
        name="h-nightly",
        target_selector={"mode": "address_tags", "tags": ["wake:nightly"]},
        schedule_cron="0 7 * * *",
        timezone="UTC",
        vantage={"kind": "server", "id": None},
        created_by_user_id=owner.id,
        next_run_at=datetime(2030, 1, 1, 7, 0, tzinfo=UTC),
    )
    db.add_all([zone, dhcp_group, plan, appliance, schedule])
    await db.flush()
    seed = Seed(
        raw_token=raw,
        space_id=space.id,
        other_space_id=other.id,
        block_id=block.id,
        resize_block_id=resize_block.id,
        subnet_id=subnet.id,
        sibling_id=sibling.id,
        resize_subnet_id=resize_subnet.id,
        dns_group_id=dns_group.id,
        other_dns_group_id=other_dns.id,
        zone_id=zone.id,
        dhcp_group_id=dhcp_group.id,
        plan_id=plan.id,
        appliance_id=appliance.id,
        schedule_id=schedule.id,
    )
    await db.commit()
    return seed


# ── One valid request per route ───────────────────────────────────────────

_KEA = (
    b'{"Dhcp4": {"valid-lifetime": 4000, "subnet4": [{"subnet": "192.0.2.0/24",'
    b' "pools": [{"pool": "192.0.2.10 - 192.0.2.100"}]}]}}'
)
_ISC = b"subnet 10.5.5.0 netmask 255.255.255.0 { range 10.5.5.10 10.5.5.50; }\n"
_NAMED = (
    'options { directory "/var/named"; };\nzone "example.com" { type master; file "e.zone"; };\n'
)
_ZONE_FILE = (
    "$TTL 3600\n@ IN SOA ns1.example.com. hostmaster.example.com. ( 5 3600 600 86400 300 )\n"
    "@ IN NS ns1.example.com.\nwww IN A 192.0.2.5\n"
)
_ZONE_TEXT = (
    "$ORIGIN example.com.\n$TTL 3600\n"
    "@ IN SOA ns1.example.com. hostmaster.example.com. ( 1 86400 7200 3600000 3600 )\n"
    "@ IN NS ns1.example.com.\nwww IN A 192.0.2.10\n"
)


def _bind_archive() -> bytes:
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        for path, content in (("etc/named.conf", _NAMED), ("var/named/e.zone", _ZONE_FILE)):
            data = content.encode()
            info = tarfile.TarInfo(path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return bio.getvalue()


Req = dict[str, Any]


def _json(url: str, body: dict[str, Any] | None = None) -> Req:
    return {"url": url, "json": {} if body is None else body}


_DICOM_CSV = "AE Title,IP,Port\nCT1_RAD,10.20.0.5,104\n"
_OT_CSV = "IP address,Protocol,Device name\n10.20.0.6,PROFINET,plc-a\n"

# path template -> builder.  Keyed by the SAME strings the structural guard
# pins, so a path added there with no entry here fails the coverage test.
CASES: dict[str, Callable[[Seed], Req]] = {
    "/api/v1/appliance/acme/preview": lambda s: _json(
        "/api/v1/appliance/acme/preview", {"domains": ["ddi.example.com"]}
    ),
    "/api/v1/appliance/firewall/preview": lambda s: _json(
        "/api/v1/appliance/firewall/preview", {"appliance_id": str(s.appliance_id)}
    ),
    "/api/v1/av/allocation-preview": lambda s: _json(
        "/api/v1/av/allocation-preview",
        {"space_id": str(s.space_id), "address_or_cidr": "239.10.0.5", "av_protocol": "dante"},
    ),
    "/api/v1/dhcp/import/isc/preview": lambda s: {
        "url": "/api/v1/dhcp/import/isc/preview",
        "files": {"file": ("dhcpd.conf", _ISC, "text/plain")},
        "data": {"target_group_id": str(s.dhcp_group_id), "ipam_space_id": str(s.space_id)},
    },
    "/api/v1/dhcp/import/kea/preview": lambda s: {
        "url": "/api/v1/dhcp/import/kea/preview",
        "files": {"file": ("kea.conf", _KEA, "application/json")},
        "data": {"target_group_id": str(s.dhcp_group_id), "ipam_space_id": str(s.space_id)},
    },
    "/api/v1/dicom/aes/import/preview": lambda s: _json(
        "/api/v1/dicom/aes/import/preview",
        {
            "csv_text": _DICOM_CSV,
            "column_map": {"ae_title": "AE Title", "address": "IP", "port": "Port"},
        },
    ),
    "/api/v1/dns/groups/{group_id}/zones/{zone_id}/import/preview": lambda s: _json(
        f"/api/v1/dns/groups/{s.dns_group_id}/zones/{s.zone_id}/import/preview",
        {"zone_file": _ZONE_TEXT, "zone_name": "example.com."},
    ),
    "/api/v1/dns/groups/{group_id}/zones/{zone_id}/import/spreadsheet/preview": lambda s: {
        "url": f"/api/v1/dns/groups/{s.dns_group_id}/zones/{s.zone_id}/import/spreadsheet/preview",
        "files": {"file": ("records.csv", b"name,type,value\nwww,A,192.0.2.7\n", "text/csv")},
        "data": {"mode": "merge"},
    },
    "/api/v1/dns/groups/{group_id}/zones/{zone_id}/move/preview": lambda s: _json(
        f"/api/v1/dns/groups/{s.dns_group_id}/zones/{s.zone_id}/move/preview",
        {"target_group_id": str(s.other_dns_group_id)},
    ),
    "/api/v1/dns/import/bind9/preview": lambda s: {
        "url": "/api/v1/dns/import/bind9/preview",
        "files": {"file": ("bind.tar.gz", _bind_archive(), "application/gzip")},
        "data": {"target_group_id": str(s.dns_group_id)},
    },
    "/api/v1/ipam/blocks/{block_id}/move/preview": lambda s: _json(
        f"/api/v1/ipam/blocks/{s.resize_block_id}/move/preview",
        {"target_space_id": str(s.other_space_id)},
    ),
    "/api/v1/ipam/blocks/{block_id}/plan-allocation": lambda s: _json(
        f"/api/v1/ipam/blocks/{s.block_id}/plan-allocation",
        {"items": [{"count": 2, "prefix_len": 24}]},
    ),
    "/api/v1/ipam/blocks/{block_id}/resize/preview": lambda s: _json(
        f"/api/v1/ipam/blocks/{s.resize_block_id}/resize/preview", {"new_cidr": "10.40.0.0/23"}
    ),
    "/api/v1/ipam/import/addresses/preview": lambda s: {
        "url": "/api/v1/ipam/import/addresses/preview",
        "files": {"file": ("a.csv", b"address,hostname\n10.20.0.50,h50\n", "text/csv")},
        "data": {"subnet_id": str(s.subnet_id)},
    },
    "/api/v1/ipam/import/preview": lambda s: {
        "url": "/api/v1/ipam/import/preview",
        "files": {"file": ("x.csv", b"network,name\n10.20.9.0/24,new\n", "text/csv")},
        "data": {"space_id": str(s.space_id)},
    },
    "/api/v1/ipam/import/preview-json": lambda s: _json(
        "/api/v1/ipam/import/preview-json",
        {
            "space_id": str(s.space_id),
            "payload": {"subnets": [{"network": "10.20.9.0/24", "name": "new"}]},
        },
    ),
    "/api/v1/ipam/plans/validate-tree": lambda s: _json(
        "/api/v1/ipam/plans/validate-tree",
        {
            "name": "p",
            "space_id": str(s.space_id),
            "tree": {
                "id": "r",
                "network": "10.70.0.0/16",
                "kind": "block",
                "children": [{"id": "a", "network": "10.70.1.0/24", "kind": "subnet"}],
            },
        },
    ),
    "/api/v1/ipam/plans/{plan_id}/validate": lambda s: _json(
        f"/api/v1/ipam/plans/{s.plan_id}/validate"
    ),
    "/api/v1/ipam/spaces/{space_id}/find-free": lambda s: _json(
        f"/api/v1/ipam/spaces/{s.space_id}/find-free", {"prefix_length": 24}
    ),
    "/api/v1/ipam/subnets/{subnet_id}/bulk-allocate/preview": lambda s: _json(
        f"/api/v1/ipam/subnets/{s.subnet_id}/bulk-allocate/preview",
        {
            "range_start": "10.20.0.100",
            "range_end": "10.20.0.103",
            "hostname_template": "bulk-{n}",
        },
    ),
    "/api/v1/ipam/subnets/{subnet_id}/merge/preview": lambda s: _json(
        f"/api/v1/ipam/subnets/{s.subnet_id}/merge/preview",
        {"sibling_subnet_ids": [str(s.sibling_id)]},
    ),
    "/api/v1/ipam/subnets/{subnet_id}/resize/preview": lambda s: _json(
        f"/api/v1/ipam/subnets/{s.resize_subnet_id}/resize/preview", {"new_cidr": "10.50.0.0/23"}
    ),
    "/api/v1/ipam/subnets/{subnet_id}/split/preview": lambda s: _json(
        f"/api/v1/ipam/subnets/{s.resize_subnet_id}/split/preview", {"new_prefix_length": 25}
    ),
    "/api/v1/logs/dhcp-activity": lambda s: _json("/api/v1/logs/dhcp-activity"),
    "/api/v1/logs/dns-queries": lambda s: _json("/api/v1/logs/dns-queries"),
    "/api/v1/logs/dns-queries/analytics": lambda s: _json("/api/v1/logs/dns-queries/analytics"),
    "/api/v1/multicast/groups/bulk-allocate/preview": lambda s: _json(
        "/api/v1/multicast/groups/bulk-allocate/preview",
        {
            "space_id": str(s.space_id),
            "count": 3,
            "name_template": "cam-{n}",
            "start_address": "239.1.1.1",
        },
    ),
    "/api/v1/ot/devices/import/preview": lambda s: _json(
        "/api/v1/ot/devices/import/preview",
        {
            "csv_text": _OT_CSV,
            "column_map": {
                "address": "IP address",
                "ot_protocol": "Protocol",
                "profinet_device_name": "Device name",
            },
        },
    ),
    "/api/v1/tools/mac-vendor": lambda s: _json(
        "/api/v1/tools/mac-vendor", {"macs": ["00:11:22:33:44:55"]}
    ),
    "/api/v1/wake-scheduler/preview-targets": lambda s: _json(
        "/api/v1/wake-scheduler/preview-targets",
        {"target_selector": {"mode": "address_tags", "tags": ["wake:nightly"]}},
    ),
    "/api/v1/wake-scheduler/schedules/{schedule_id}/preview-targets": lambda s: _json(
        f"/api/v1/wake-scheduler/schedules/{s.schedule_id}/preview-targets"
    ),
    # Allowed writer: see ALLOWED_WRITES.
    "/held": lambda s: {
        "url": "/held",
        "content": (
            b'<locationRequest xmlns="urn:ietf:params:xml:ns:geopriv:held">'
            b'<device><ip xmlns="urn:ietf:params:xml:ns:geopriv:held:id">10.20.0.5</ip></device>'
            b"</locationRequest>"
        ),
        "headers": {"Content-Type": "application/held+xml"},
    },
}

# Routes that cannot be driven here, with why. Empty today: every route runs.
EXEMPT: dict[str, str] = {}

# Writes a read-only route is explicitly ALLOWED to make: path -> (reason, substring a
# violation must contain to be waived). Everything else is still a violation.
ALLOWED_WRITES: dict[str, tuple[str, str]] = {
    "/held": (
        "#3514: POST /held writes the e911_resolution_log lookup trail, kept on purpose. "
        "Bounded by a per-caller logging budget (past it the lookup is answered without a "
        "row) and the daily prune_e911_resolution_log retention sweep.",
        "e911_resolution_log",
    ),
}
# Routes the harness caught breaking the read-only claim and that are not yet fixed
# (kept xfail(strict=True)). Empty today.
KNOWN_VIOLATIONS: dict[str, str] = {}


def test_every_read_only_route_has_a_case_or_a_reason() -> None:
    covered = set(CASES) | set(EXEMPT)
    assert not (set(CASES) & set(EXEMPT)), "a route is both exercised and exempt"
    assert covered == set(EXPECTED_READ_ONLY_POSTS), (
        f"routes with no harness case: {sorted(set(EXPECTED_READ_ONLY_POSTS) - covered)}; "
        f"cases for routes no longer read-only: {sorted(covered - set(EXPECTED_READ_ONLY_POSTS))}"
    )
    assert all(EXEMPT.values()), "an exemption needs a reason"
    assert set(KNOWN_VIOLATIONS) <= set(CASES)
    assert set(ALLOWED_WRITES) <= set(CASES)


# ── The harness ───────────────────────────────────────────────────────────


async def _call(client: AsyncClient, req: Req, raw_token: str) -> Any:
    req = dict(req)
    url = req.pop("url")
    headers = {"Authorization": f"Bearer {raw_token}", **req.pop("headers", {})}
    return await client.post(url, headers=headers, **req)


@pytest.mark.parametrize("path", sorted(CASES))
async def test_read_only_post_writes_nothing_and_calls_nothing(
    path: str, client: AsyncClient, db_session: AsyncSession, request: pytest.FixtureRequest
) -> None:
    if path in KNOWN_VIOLATIONS:
        request.applymarker(pytest.mark.xfail(strict=True, reason=KNOWN_VIOLATIONS[path]))
    seed = await _seed(db_session)
    req = CASES[path](seed)
    names, ips = _allowed_hosts()
    with forbid_writes_and_sockets(names, ips) as guard:
        guard.armed = True
        resp = await _call(client, req, seed.raw_token)
        guard.armed = False
    waiver = ALLOWED_WRITES.get(path)
    # The waiver names the table; the ORM flush entry names the model class.
    waived = ("e911_resolution_log", "E911ResolutionLog") if waiver else ()
    violations = [v for v in guard.violations if not any(w in v for w in waived)]
    assert not violations, f"{path} broke the read-only claim: {violations}"
    # The route must actually have run: a 401 / 403 / 404 / 422 means the body or the seed
    # was wrong and the guard watched nothing.
    assert resp.status_code == 200, f"{path} -> {resp.status_code} {resp.text[:300]}"


# ── Negative controls ─────────────────────────────────────────────────────


def _control_app(db: AsyncSession) -> FastAPI:
    app = FastAPI()

    async def override() -> Any:
        yield db

    app.dependency_overrides[get_db] = override

    @app.post("/ok")
    async def ok() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/reads")
    async def reads() -> dict[str, int]:
        return {"n": int((await db.execute(text("SELECT 1"))).scalar_one())}

    @app.post("/writes-orm")
    async def writes_orm() -> dict[str, bool]:
        db.add(IPSpace(name=f"leak-{uuid.uuid4().hex[:6]}"))
        await db.commit()
        return {"ok": True}

    @app.post("/writes-sql")
    async def writes_sql() -> dict[str, bool]:
        await db.execute(text("UPDATE ip_space SET name = name"))
        return {"ok": True}

    @app.post("/writes-other-session")
    async def writes_other_session() -> dict[str, bool]:
        from app.db import AsyncSessionLocal  # noqa: PLC0415

        async with AsyncSessionLocal() as other:
            await other.execute(text("DELETE FROM ip_space WHERE false"))
            await other.commit()
        return {"ok": True}

    @app.post("/socket")
    async def sock() -> dict[str, bool]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        try:
            s.connect(("192.0.2.1", 9))
        except OSError:
            # The guard records the attempt before the connect fails; the
            # failure itself (refused, timed out) is not what is under test.
            pass
        finally:
            s.close()
        return {"ok": True}

    @app.post("/udp")
    async def udp() -> dict[str, bool]:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(b"x", ("192.0.2.1", 9))
        except OSError:
            # As above: the guard has already recorded the send attempt.
            pass
        finally:
            s.close()
        return {"ok": True}

    @app.post("/dns-lookup")
    async def dns_lookup() -> dict[str, bool]:
        with contextlib.suppress(OSError):
            socket.getaddrinfo("example.invalid", 80)
        return {"ok": True}

    return app


async def _drive(db: AsyncSession, path: str) -> list[str]:
    names, ips = _allowed_hosts()
    app = _control_app(db)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        with forbid_writes_and_sockets(names, ips) as guard:
            guard.armed = True
            resp = await c.post(path)
            guard.armed = False
    assert resp.status_code == 200, resp.text
    return guard.violations


async def test_control_a_clean_route_passes(db_session: AsyncSession) -> None:
    assert await _drive(db_session, "/ok") == []
    # The database stays reachable under the guard, or a pass proves nothing.
    assert await _drive(db_session, "/reads") == []


@pytest.mark.parametrize("path", ["/writes-orm", "/writes-sql", "/writes-other-session"])
async def test_control_a_route_that_writes_fails_the_guard(
    path: str, db_session: AsyncSession
) -> None:
    violations = await _drive(db_session, path)
    assert any(v.startswith("DML:") for v in violations), violations


@pytest.mark.parametrize("path", ["/socket", "/udp", "/dns-lookup"])
async def test_control_a_route_that_opens_a_socket_fails_the_guard(
    path: str, db_session: AsyncSession
) -> None:
    violations = await _drive(db_session, path)
    assert any(v.startswith("NET:") for v in violations), violations


def test_the_guard_is_fully_restored_after_use() -> None:
    before = (socket.socket.connect, socket.getaddrinfo, socket.create_connection)
    names, ips = _allowed_hosts()
    with forbid_writes_and_sockets(names, ips):
        pass
    assert before == (socket.socket.connect, socket.getaddrinfo, socket.create_connection)
