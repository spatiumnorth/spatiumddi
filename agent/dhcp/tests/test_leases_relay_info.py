"""#54 — the agent ships each lease's relay agent information (option 82).

The fixtures are captures from kea-dhcp4 3.0.3 with ``store-extended-info``
and ``stash-agent-options`` on, after five relayed DORAs (four with option
82, one without): ``kea303_relay_leases4.csv`` is the memfile it wrote and
``kea303_relay_lease4_page.json`` the ``lease4-get-page`` answer for the
same leases. Before #54 neither path read the user context at all.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from spatium_dhcp_agent.lease_snapshot import kea_lease_to_event
from spatium_dhcp_agent.leases import _parse_row
from spatium_dhcp_agent.relay_info import (
    relay_agent_info_from_user_context,
    unescape_kea_csv,
)

FIXTURES = Path(__file__).parent / "fixtures"

# What the relay sent, by MAC (the rig's client.py).
EXPECTED = {
    # circuit-id "eth0/1:100", remote-id AABBCC010203
    "02:00:00:00:00:01": "010A657468302F313A3130300206AABBCC010203",
    # + sub-option 6 "sub-42"
    "02:00:00:00:00:02": "010A657468302F323A3130300206AABBCC01020306067375622D3432",
    # circuit-id "Gi1/0/7"
    "02:00:00:00:00:03": "01074769312F302F370206DDEEFF010203",
    # binary circuit-id, remote-id with a comma, quotes and a newline in it
    "02:00:00:00:00:05": "01060004006401070209697427732C2278220A",
}
NO_OPTION_82 = "02:00:00:00:00:04"


def _csv_rows() -> list[list[str]]:
    with (FIXTURES / "kea303_relay_leases4.csv").open(newline="") as fh:
        return list(csv.reader(fh))


def test_lease_file_rows_carry_the_option_82_payload() -> None:
    rows = _csv_rows()
    assert rows[0][10] == "user_context" and len(rows[0]) == 12
    events = {ev["mac_address"]: ev for ev in map(_parse_row, rows) if ev}
    assert set(events) == set(EXPECTED) | {NO_OPTION_82}
    for mac, rai in EXPECTED.items():
        assert events[mac]["relay_agent_info"] == rai
    # No option 82 → no key at all, so the batch is what an older agent sent.
    assert "relay_agent_info" not in events[NO_OPTION_82]


def test_lease_page_entries_carry_the_option_82_payload() -> None:
    page = json.loads((FIXTURES / "kea303_relay_lease4_page.json").read_text())
    events = {ev["mac_address"]: ev for ev in map(kea_lease_to_event, page) if ev}
    for mac, rai in EXPECTED.items():
        assert events[mac]["relay_agent_info"] == rai
    assert "relay_agent_info" not in events[NO_OPTION_82]


def test_the_two_paths_agree() -> None:
    page = json.loads((FIXTURES / "kea303_relay_lease4_page.json").read_text())
    from_page = {
        ev["mac_address"]: ev.get("relay_agent_info") for ev in map(kea_lease_to_event, page) if ev
    }
    from_csv = {
        ev["mac_address"]: ev.get("relay_agent_info") for ev in map(_parse_row, _csv_rows()) if ev
    }
    assert from_page == from_csv


def test_fourteen_column_header_layout() -> None:
    # Later Kea releases append hwtype, hwaddr_source and pool_id; user_context
    # stays column 10.
    uc = '{ "ISC": { "relay-agent-info": { "sub-options": "0x0103414243" } } }'
    row = [
        "10.0.0.9",
        "aa:bb:cc:dd:ee:01",
        "",
        "3600",
        "2000000000",
        "1",
        "0",
        "0",
        "",
        "0",
        uc,
        "1",
        "0",
        "0",
    ]
    ev = _parse_row(row)
    assert ev is not None and ev["relay_agent_info"] == "0103414243"


def test_unescape_kea_csv() -> None:
    assert unescape_kea_csv('"a"&#x2c "b"') == '"a", "b"'
    assert unescape_kea_csv("&#x2C&#x26") == ",&"
    assert unescape_kea_csv("no escapes") == "no escapes"
    # Not two hex digits after the tag: left alone, as Kea leaves it.
    assert unescape_kea_csv("&#xZZ") == "&#xZZ"


def test_unusable_user_context_never_drops_the_lease() -> None:
    base = ["10.0.0.9", "aa:bb:cc:dd:ee:01", "", "3600", "2000000000", "1", "0", "0", "", "0"]
    for uc in (
        "",
        "not json",
        '{"ISC": 5}',
        '{"ISC": {"relay-agent-info": {"sub-options": "0x"}}}',
        '{"ISC": {"relay-agent-info": {"sub-options": "0xABC"}}}',  # odd length
        '{"ISC": {"relay-agent-info": {"sub-options": "0xGG"}}}',
        '{"ISC": {"relay-agent-info": {"sub-options": 12}}}',
        '{"ISC": {"relay-agent-info": {"sub-options": "0x' + "AB" * 256 + '"}}}',  # > 255 bytes
        '{"other": "context"}',
    ):
        ev = _parse_row(base + [uc, "0"])
        assert ev is not None, uc
        assert "relay_agent_info" not in ev, uc


def test_user_context_forms() -> None:
    assert relay_agent_info_from_user_context(None) is None
    assert relay_agent_info_from_user_context({}) is None
    assert (
        relay_agent_info_from_user_context(
            {"ISC": {"relay-agent-info": {"sub-options": "0x0102aBcD"}}}
        )
        == "0102ABCD"
    )
    # The older flat form, payload directly under relay-agent-info.
    assert relay_agent_info_from_user_context({"ISC": {"relay-agent-info": "0x0101FF"}}) == "0101FF"
