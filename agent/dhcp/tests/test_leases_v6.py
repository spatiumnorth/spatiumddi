"""DHCPv6 leases reach the control plane (#1141).

The agent tailed ``kea-leases4.csv`` only and snapshotted with
``lease4-get-page`` only, so no v6 lease was ever reported. The fixtures
below are what Kea 3.0.3 actually wrote and answered for the same two
IA_NA leases (captured 2026-09-24) — one with a hardware address, one
without, which is the common DHCPv6 case.
"""

from __future__ import annotations

import csv
import io
import types
from pathlib import Path
from typing import Any

from spatium_dhcp_agent import leases as leases_mod
from spatium_dhcp_agent.lease_snapshot import LeaseSnapshot, kea_lease6_to_event
from spatium_dhcp_agent.leases import _parse_row, _parse_row_v6

_CSV6 = """\
address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state,user_context,hwtype,hwaddr_source,pool_id
2001:db8:83::100,00:01:00:01:2c:5f:aa:bb:bc:24:11:41:b7:45,3600,1790263075,1,7200,0,1234,128,0,0,client1.example.com.,bc:24:11:41:b7:45,0,,1,0,0
2001:db8:83::101,00:03:00:01:aa:bb:cc:dd:ee:ff,3600,1790263075,1,7200,0,7,128,0,0,,,0,,,,0
2001:db8:ff00::,00:03:00:01:aa:bb:cc:dd:ee:ff,3600,1790263075,1,7200,2,9,56,0,0,,,0,,,,0
"""

# lease6-get-page entries for the same two leases, as Kea 3.0.3 returned them.
_PAGE6 = [
    {
        "cltt": 1790259475,
        "duid": "00:01:00:01:2c:5f:aa:bb:bc:24:11:41:b7:45",
        "fqdn-fwd": False,
        "fqdn-rev": False,
        "hostname": "client1.example.com.",
        "hw-address": "bc:24:11:41:b7:45",
        "iaid": 1234,
        "ip-address": "2001:db8:83::100",
        "preferred-lft": 7200,
        "state": 0,
        "subnet-id": 1,
        "type": "IA_NA",
        "valid-lft": 3600,
    },
    {
        "cltt": 1790259475,
        "duid": "00:03:00:01:aa:bb:cc:dd:ee:ff",
        "fqdn-fwd": False,
        "fqdn-rev": False,
        "hostname": "",
        "iaid": 7,
        "ip-address": "2001:db8:83::101",
        "preferred-lft": 7200,
        "state": 0,
        "subnet-id": 1,
        "type": "IA_NA",
        "valid-lft": 3600,
    },
]


def _rows() -> list[list[str]]:
    return list(csv.reader(io.StringIO(_CSV6)))


def test_csv_rows_key_on_duid_and_keep_the_mac_only_when_kea_has_one() -> None:
    header, with_mac, without_mac, pd = _rows()
    assert _parse_row_v6(header) is None
    a = _parse_row_v6(with_mac)
    assert a is not None
    assert a["ip_address"] == "2001:db8:83::100"
    assert a["duid"] == "00:01:00:01:2c:5f:aa:bb:bc:24:11:41:b7:45"
    assert a["iaid"] == 1234
    assert a["mac_address"] == "bc:24:11:41:b7:45"
    assert a["hostname"] == "client1.example.com."
    assert a["state"] == "active"
    assert a["expires_at"] == a["ends_at"] is not None
    b = _parse_row_v6(without_mac)
    assert b is not None
    assert b["mac_address"] is None and b["duid"] and b["iaid"] == 7
    # IA_PD delegates a PREFIX, not an address the control plane mirrors.
    assert _parse_row_v6(pd) is None


def test_a_v6_row_without_a_duid_is_skipped() -> None:
    row = _rows()[1]
    row[1] = ""
    assert _parse_row_v6(row) is None


def test_snapshot_entries_convert_to_the_same_events_as_the_csv() -> None:
    a, b = (kea_lease6_to_event(e) for e in _PAGE6)
    assert a is not None and b is not None
    assert (a["duid"], a["iaid"], a["mac_address"]) == (
        "00:01:00:01:2c:5f:aa:bb:bc:24:11:41:b7:45",
        1234,
        "bc:24:11:41:b7:45",
    )
    # hw-address is ABSENT from the entry when Kea never learned one.
    assert b["mac_address"] is None and b["hostname"] is None
    assert kea_lease6_to_event({**_PAGE6[0], "type": "IA_PD"}) is None
    assert kea_lease6_to_event({**_PAGE6[0], "duid": ""}) is None


def test_the_v6_snapshot_walks_lease6_get_page() -> None:
    commands: list[str] = []
    posted: list[dict[str, Any]] = []
    snap = LeaseSnapshot(
        Path("/nonexistent"), lambda p: posted.append(p) or 200, family=6
    )
    snap._fetch = lambda args: (  # type: ignore[method-assign]
        commands.append(snap._command) or {"result": 0, "arguments": {"leases": _PAGE6}}
    )
    snap.request("agent_start")
    snap.step()
    assert commands == ["lease6-get-page"]
    assert [e["duid"] for e in posted[0]["leases"]] == [
        "00:01:00:01:2c:5f:aa:bb:bc:24:11:41:b7:45",
        "00:03:00:01:aa:bb:cc:dd:ee:ff",
    ]


def test_v4_and_v6_events_never_share_a_batch(tmp_path: Path) -> None:
    """A control plane older than #1141 422s a batch holding a MAC-less event,
    and the spool drops a rejected batch whole — so a shared batch would take
    the v4 leases down with the v6 ones it cannot ingest."""
    v4 = tmp_path / "kea-leases4.csv"
    v6 = tmp_path / "kea-leases6.csv"
    v4.write_text(
        "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,"
        "fqdn_rev,hostname,state,user_context,pool_id\n"
        "10.0.0.50,aa:bb:cc:dd:ee:ff,,3600,2000000000,1,0,0,host1,0,,0\n"
    )
    v6.write_text(_CSV6)
    cfg = types.SimpleNamespace(
        control_plane_url="http://cp",
        httpx_verify=lambda: True,
        kea_lease_file=v4,
        kea_lease_file_v6=v6,
        kea_control_socket=tmp_path / "s4",
        kea_control_socket_v6=tmp_path / "s6",
    )
    hb = types.SimpleNamespace(lease_count_since_start=0)
    w = leases_mod.LeaseWatcher(cfg, ["tok"], hb)
    batches: list[list[dict[str, Any]]] = []
    w._shipper.ship = lambda payload: batches.append(list(payload["leases"])) or "sent"  # type: ignore[method-assign]
    w._last_flush = 0.0  # due now
    w.tick()

    families = [{("duid" in e) for e in batch} for batch in batches]
    assert families == [{False}, {True}], batches
    assert [e["ip_address"] for e in batches[1]] == [
        "2001:db8:83::100",
        "2001:db8:83::101",
    ]
    # And the v4 tailer is unchanged: still MAC-keyed.
    assert (
        _parse_row(next(csv.reader(io.StringIO("10.0.0.50,,x,3600,1,1,0,0,h,0"))))
        is None
    )
