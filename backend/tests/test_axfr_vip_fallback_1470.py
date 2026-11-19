"""Drift / pull reach an appliance DNS daemon that is behind the DNS VIP (#1470).

With ``dns_vip`` set the appliance's DNS pods drop hostNetwork and sit behind a
MetalLB LoadBalancer, so the node address a ``DNSServer`` row carries refuses
TCP/53. A refused transfer is retried at the member's OWN pod address (the
source of its heartbeats, ``last_seen_ip``) — never at the VIP, which reaches an
arbitrary member and would report that member's state as this one's.

These tests run real AXFR responders on loopback addresses and assert on which
addresses were actually dialled. 127.0.0.1 is the "node address" (up, nothing
on the port); 127.0.0.2 / .3 are pod addresses; 127.0.0.9 is the VIP.
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
    """One-shot-per-connection AXFR server on a loopback address; counts connections."""

    def __init__(
        self,
        keyring: dict | None = None,
        *,
        addr: str = "127.0.0.2",
        port: int = 0,
        a_value: str = "192.0.2.7",
    ) -> None:
        self.keyring = keyring
        self.a_value = a_value
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((addr, port))
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
                    a = dns.rrset.from_text("www." + ZONE, 300, "IN", "A", self.a_value)
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
async def test_refused_node_address_falls_back_to_the_pod_address(daemon: _Responder) -> None:
    # 127.0.0.1 is the "node address": up, nothing on this port. 127.0.0.2 is the pod.
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
    # The node answers itself, so the fallback (a different, closed address) is never dialled.
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


@pytest.mark.asyncio
async def test_a_refused_fallback_is_reported_naming_both_addresses(daemon: _Responder) -> None:
    # Pod address closed too: the error names the row's own address first.
    with pytest.raises(RuntimeError, match=r"127\.0\.0\.1:\d+ \(retried at 127\.0\.0\.3:"):
        await axfr_zone_records(
            host="127.0.0.1", port=daemon.port, zone_name=ZONE, fallback_hosts=["127.0.0.3"]
        )
    assert daemon.connections == 0


def test_fallback_is_the_members_own_address_never_the_vip() -> None:
    from app.services.dns.tsig import transfer_fallback_hosts

    def srv(driver: str, agent: bool, seen: str | None) -> SimpleNamespace:
        return SimpleNamespace(
            driver=driver, agent_id="a1" if agent else None, host="ddi03", last_seen_ip=seen
        )

    vip = "192.0.2.53"
    assert transfer_fallback_hosts(srv("technitium", True, "10.42.1.7"), vip) == ["10.42.1.7"]
    assert transfer_fallback_hosts(srv("bind9", True, "10.42.2.9"), vip) == ["10.42.2.9"]
    # No VIP: the node address is where the daemon listens; a refusal is real.
    assert transfer_fallback_hosts(srv("technitium", True, "10.42.1.7"), "") == []
    # Never heartbeated, or heartbeating from the row's own address / the VIP.
    assert transfer_fallback_hosts(srv("technitium", True, None), vip) == []
    assert transfer_fallback_hosts(srv("technitium", True, "ddi03"), vip) == []
    assert transfer_fallback_hosts(srv("technitium", True, vip), vip) == []
    # Not agent-managed: reached at its own address, never redirected.
    assert transfer_fallback_hosts(srv("windows_dns", False, "10.0.0.5"), vip) == []
    assert transfer_fallback_hosts(srv("bind9", False, "10.0.0.5"), vip) == []


SECRET = "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MDE="


def _keyring() -> dict:
    import dns.name
    import dns.tsig

    keyname = dns.name.from_text("spatium-test")
    return {keyname: dns.tsig.Key(keyname, SECRET, algorithm=dns.name.from_text("hmac-sha256"))}


async def _vip_group(db, *, vip: str, members: list[tuple[str, str | None, int]]):
    """A signed agent-managed Technitium group with ``dns_vip`` set.

    ``members`` is ``(name, last_seen_ip, port)``; every row's ``host`` is the
    refusing node address 127.0.0.1. Returns ``(group, zone)``.
    """
    import uuid

    from app.core.crypto import encrypt_str
    from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
    from app.models.settings import PlatformSettings

    ps = await db.get(PlatformSettings, 1)
    if ps is None:
        ps = PlatformSettings(id=1)
        db.add(ps)
    ps.dns_vip = vip
    group = DNSServerGroup(
        name=f"g-{uuid.uuid4().hex[:6]}",
        tsig_key_name="spatium-test",
        tsig_key_secret_encrypted=encrypt_str(SECRET),
    )
    db.add(group)
    await db.flush()
    for i, (name, seen, port) in enumerate(members):
        db.add(
            DNSServer(
                group_id=group.id,
                name=name,
                driver="technitium",
                host="127.0.0.1",
                port=port,
                is_enabled=True,
                is_primary=i == 0,
                agent_id=uuid.uuid4(),
                last_seen_ip=seen,
            )
        )
    zone = DNSZone(group_id=group.id, name=ZONE, zone_type="primary", kind="forward")
    db.add(zone)
    await db.flush()
    db.add(DNSRecord(zone_id=zone.id, name="www", record_type="A", value="192.0.2.7", ttl=300))
    await db.commit()
    return group, zone


async def test_drift_reaches_the_member_at_its_pod_address_not_the_vip(db_session) -> None:
    """Whole drift path: a real signed AXFR, the node address refusing."""
    from app.services.dns.drift import compute_zone_drift

    pod = _Responder(keyring=_keyring(), addr="127.0.0.2")
    # The VIP answers too, with different data: it must never be dialled.
    vip = _Responder(keyring=_keyring(), addr="127.0.0.9", port=pod.port, a_value="198.51.100.1")
    try:
        group, zone = await _vip_group(
            db_session, vip="127.0.0.9", members=[("ddi03", "127.0.0.2", pod.port)]
        )
        report = await compute_zone_drift(db_session, group_id=group.id, zone=zone)
    finally:
        pod.close()
        vip.close()

    entry = report.servers[0]
    assert entry.error is None, entry.error
    assert entry.status == "ok"
    assert entry.in_sync == 1
    assert pod.connections == 1
    assert vip.connections == 0


async def test_a_dead_member_is_not_reported_in_sync_through_another(db_session) -> None:
    """Multi-member group: each row reads its own member, so a dead one fails.

    ddi01's pod answers; ddi02's pod address has nothing listening (its daemon
    is down). Reading ddi02 through the VIP — which any live member answers —
    would have reported it in sync.
    """
    from app.services.dns.drift import compute_zone_drift

    pod1 = _Responder(keyring=_keyring(), addr="127.0.0.2")
    vip = _Responder(keyring=_keyring(), addr="127.0.0.9", port=pod1.port)
    try:
        group, zone = await _vip_group(
            db_session,
            vip="127.0.0.9",
            members=[("ddi01", "127.0.0.2", pod1.port), ("ddi02", "127.0.0.3", pod1.port)],
        )
        report = await compute_zone_drift(db_session, group_id=group.id, zone=zone)
    finally:
        pod1.close()
        vip.close()

    by_name = {e.server_name: e for e in report.servers}
    assert by_name["ddi01"].status == "ok", by_name["ddi01"].error
    assert by_name["ddi02"].status != "ok"
    assert "127.0.0.3" in (by_name["ddi02"].error or "")
    assert vip.connections == 0


async def test_pull_from_server_reads_the_primary_at_its_pod_address(db_session) -> None:
    from app.services.dns.pull_from_server import pull_zone_from_server

    pod = _Responder(keyring=_keyring(), addr="127.0.0.2")
    vip = _Responder(keyring=_keyring(), addr="127.0.0.9", port=pod.port, a_value="198.51.100.1")
    try:
        _group, zone = await _vip_group(
            db_session, vip="127.0.0.9", members=[("ddi03", "127.0.0.2", pod.port)]
        )
        result = await pull_zone_from_server(db_session, zone, apply=False)
    finally:
        pod.close()
        vip.close()

    assert result.server_records == 1
    assert pod.connections == 1
    assert vip.connections == 0


async def test_without_a_vip_a_refused_node_is_not_retried(db_session) -> None:
    """Non-appliance installs (no ``dns_vip``): behaviour is unchanged."""
    from app.services.dns.drift import compute_zone_drift

    pod = _Responder(keyring=_keyring(), addr="127.0.0.2")
    try:
        group, zone = await _vip_group(
            db_session, vip="", members=[("ddi03", "127.0.0.2", pod.port)]
        )
        report = await compute_zone_drift(db_session, group_id=group.id, zone=zone)
    finally:
        pod.close()

    assert report.servers[0].status != "ok"
    assert pod.connections == 0
