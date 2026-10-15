"""Drift / pull reach an appliance DNS daemon that answers only on the VIP (#1470).

With ``dns_vip`` set the appliance's DNS pods drop hostNetwork and sit behind a
MetalLB LoadBalancer, so the node address a ``DNSServer`` row carries refuses
TCP/53. These tests run a real AXFR responder on a loopback address and assert
on which address was actually dialled.
"""

from __future__ import annotations

import socket
import struct
import threading
from types import SimpleNamespace

import dns.message
import dns.rdatatype
import dns.rrset
import pytest

from app.drivers.dns._axfr import axfr_zone_records
from app.drivers.dns.bind9 import BIND9Driver
from app.drivers.dns.technitium import TechnitiumDriver

ZONE = "example.test."


class _Responder:
    """One-shot-per-connection AXFR server on 127.0.0.2; counts connections."""

    def __init__(self, keyring: dict | None = None) -> None:
        self.keyring = keyring
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.2", 0))
        self.sock.listen(8)
        self.port = int(self.sock.getsockname()[1])
        self.connections = 0
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.connections += 1
            with conn:
                try:
                    n = struct.unpack("!H", conn.recv(2))[0]
                    q = dns.message.from_wire(conn.recv(n), keyring=self.keyring)
                    r = dns.message.make_response(q)
                    soa = dns.rrset.from_text(
                        ZONE, 300, "IN", "SOA", "ns.example.test. h.example.test. 1 2 3 4 5"
                    )
                    a = dns.rrset.from_text("www." + ZONE, 300, "IN", "A", "192.0.2.7")
                    ns = dns.rrset.from_text(ZONE, 300, "IN", "NS", "ns.example.test.")
                    r.answer = [soa, ns, a, soa]
                    wire = r.to_wire()
                    conn.sendall(struct.pack("!H", len(wire)) + wire)
                except Exception:  # noqa: BLE001, S110 — a test responder
                    pass

    def close(self) -> None:
        self.sock.close()


@pytest.fixture
def daemon():
    d = _Responder()
    yield d
    d.close()


@pytest.mark.asyncio
async def test_refused_node_address_falls_back_to_the_vip(daemon: _Responder) -> None:
    # 127.0.0.1 is the "node address": up, nothing on this port. 127.0.0.2 is the VIP.
    recs = await axfr_zone_records(
        host="127.0.0.1", port=daemon.port, zone_name=ZONE, fallback_hosts=["127.0.0.2"]
    )
    assert daemon.connections == 1
    assert [r.name for r in recs] == ["www"]


@pytest.mark.asyncio
async def test_without_a_fallback_the_refusal_is_reported(daemon: _Responder) -> None:
    with pytest.raises(RuntimeError, match="127.0.0.1"):
        await axfr_zone_records(host="127.0.0.1", port=daemon.port, zone_name=ZONE)
    assert daemon.connections == 0


@pytest.mark.asyncio
async def test_an_answering_node_is_not_redirected(daemon: _Responder) -> None:
    # The node answers itself, so the VIP (a different, closed address) is never dialled.
    await axfr_zone_records(
        host="127.0.0.2", port=daemon.port, zone_name=ZONE, fallback_hosts=["127.0.0.1"]
    )
    assert daemon.connections == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("driver_cls", [TechnitiumDriver, BIND9Driver])
async def test_drivers_forward_the_fallback(driver_cls, daemon: _Responder) -> None:
    server = SimpleNamespace(host="127.0.0.1", port=daemon.port, id="s1")
    recs = await driver_cls().pull_zone_records(
        server, ZONE, tsig=None, fallback_hosts=["127.0.0.2"]
    )
    assert daemon.connections == 1
    assert recs


def test_only_agent_managed_servers_get_the_vip() -> None:
    from app.services.dns.tsig import transfer_fallback_hosts

    agent = SimpleNamespace(driver="technitium", agent_id="a1")
    windows = SimpleNamespace(driver="windows_dns", agent_id=None)
    own_bind = SimpleNamespace(driver="bind9", agent_id=None)
    assert transfer_fallback_hosts(agent, "192.0.2.53") == ["192.0.2.53"]
    assert transfer_fallback_hosts(agent, "") == []
    assert transfer_fallback_hosts(windows, "192.0.2.53") == []
    assert transfer_fallback_hosts(own_bind, "192.0.2.53") == []


async def test_drift_reaches_a_daemon_that_answers_only_on_the_vip(db_session) -> None:
    """Whole drift path: a real signed AXFR, the node address refusing."""
    import uuid

    import dns.name
    import dns.tsig

    from app.core.crypto import encrypt_str
    from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
    from app.models.settings import PlatformSettings
    from app.services.dns.drift import compute_zone_drift

    secret = "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MDE="
    keyname = dns.name.from_text("spatium-test")
    key = dns.tsig.Key(keyname, secret, algorithm=dns.name.from_text("hmac-sha256"))
    daemon = _Responder(keyring={keyname: key})
    try:
        ps = await db_session.get(PlatformSettings, 1)
        if ps is None:
            ps = PlatformSettings(id=1)
            db_session.add(ps)
        ps.dns_vip = "127.0.0.2"
        group = DNSServerGroup(
            name=f"g-{uuid.uuid4().hex[:6]}",
            tsig_key_name="spatium-test",
            tsig_key_secret_encrypted=encrypt_str(secret),
        )
        db_session.add(group)
        await db_session.flush()
        db_session.add(
            DNSServer(
                group_id=group.id,
                name="ddi03",
                driver="technitium",
                host="127.0.0.1",
                port=daemon.port,
                is_enabled=True,
                agent_id=uuid.uuid4(),
            )
        )
        zone = DNSZone(group_id=group.id, name=ZONE, zone_type="primary", kind="forward")
        db_session.add(zone)
        await db_session.flush()
        db_session.add(
            DNSRecord(zone_id=zone.id, name="www", record_type="A", value="192.0.2.7", ttl=300)
        )
        await db_session.commit()

        report = await compute_zone_drift(db_session, group_id=group.id, zone=zone)
    finally:
        daemon.close()

    entry = report.servers[0]
    assert entry.error is None, entry.error
    assert entry.status == "ok"
    assert entry.in_sync == 1
    assert daemon.connections == 1


async def test_pull_from_server_reaches_a_vip_only_daemon(db_session) -> None:
    import uuid

    import dns.name
    import dns.tsig

    from app.core.crypto import encrypt_str
    from app.models.dns import DNSServer, DNSServerGroup, DNSZone
    from app.models.settings import PlatformSettings
    from app.services.dns.pull_from_server import pull_zone_from_server

    secret = "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MDE="
    keyname = dns.name.from_text("spatium-test")
    key = dns.tsig.Key(keyname, secret, algorithm=dns.name.from_text("hmac-sha256"))
    daemon = _Responder(keyring={keyname: key})
    try:
        ps = await db_session.get(PlatformSettings, 1)
        if ps is None:
            ps = PlatformSettings(id=1)
            db_session.add(ps)
        ps.dns_vip = "127.0.0.2"
        group = DNSServerGroup(
            name=f"g-{uuid.uuid4().hex[:6]}",
            tsig_key_name="spatium-test",
            tsig_key_secret_encrypted=encrypt_str(secret),
        )
        db_session.add(group)
        await db_session.flush()
        db_session.add(
            DNSServer(
                group_id=group.id,
                name="ddi03",
                driver="technitium",
                host="127.0.0.1",
                port=daemon.port,
                is_enabled=True,
                is_primary=True,
                agent_id=uuid.uuid4(),
            )
        )
        zone = DNSZone(group_id=group.id, name=ZONE, zone_type="primary", kind="forward")
        db_session.add(zone)
        await db_session.commit()

        result = await pull_zone_from_server(db_session, zone, apply=False)
    finally:
        daemon.close()

    assert result.server_records == 1
    assert daemon.connections == 1
