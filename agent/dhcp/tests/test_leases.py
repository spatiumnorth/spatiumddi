"""#428 — Kea lease shipper emits the server's LeaseEventBatch shape.

The shipper previously posted ``{"events":[{"ip","mac","ends_at",…}]}``,
which the control plane's Pydantic ``LeaseEventBatch`` silently dropped
(``leases`` defaulted to ``[]`` → HTTP 200 → every Kea lease lost). These
tests lock the wire contract: the batch envelope key is ``leases`` and
each event carries ``ip_address`` / ``mac_address`` / ``expires_at``.
"""

from __future__ import annotations

from spatium_dhcp_agent.leases import _parse_row


def _row(ip="10.0.0.50", mac="aa:bb:cc:dd:ee:ff", expire="2000000000"):
    # Kea memfile CSV: address,hwaddr,client_id,valid_lifetime,expire,
    # subnet_id,fqdn_fwd,fqdn_rev,hostname,state,...
    return [ip, mac, "", "3600", expire, "1", "0", "0", "host1", "0"]


def test_parse_row_uses_server_field_names() -> None:
    ev = _parse_row(_row())
    assert ev is not None
    # Server LeaseEvent field names — NOT the old ip/mac.
    assert ev["ip_address"] == "10.0.0.50"
    assert ev["mac_address"] == "aa:bb:cc:dd:ee:ff"
    assert "ip" not in ev and "mac" not in ev


def test_parse_row_sets_expires_at() -> None:
    # expires_at must be non-null (== ends_at) so the server stores a
    # reapable lease (sweep_expired_leases filters expires_at IS NOT NULL).
    ev = _parse_row(_row())
    assert ev is not None
    assert ev["expires_at"] is not None
    assert ev["expires_at"] == ev["ends_at"]


def test_parse_row_skips_macless_lease() -> None:
    # mac_address is required server-side; a MAC-less row can't be mirrored
    # and must be dropped (not 422 the whole batch).
    assert _parse_row(_row(mac="")) is None


def test_parse_row_skips_header_and_short_rows() -> None:
    assert _parse_row(["address", "hwaddr"]) is None
    assert _parse_row(["10.0.0.1"]) is None


def test_flush_body_uses_leases_key(monkeypatch) -> None:
    # The POST envelope key must be ``leases`` (not ``events``).
    import types

    from spatium_dhcp_agent import leases as leases_mod

    captured: dict = {}

    class _Resp:
        status_code = 200

    class _Client:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, path, json, headers):
            import copy

            captured["path"] = path
            # Snapshot — _flush clears _pending after the post, and the body
            # holds a live reference to that same list.
            captured["json"] = copy.deepcopy(json)
            return _Resp()

    cfg = types.SimpleNamespace(
        control_plane_url="http://cp",
        httpx_verify=lambda: True,
        kea_lease_file="/tmp/x",
        kea_control_socket="/tmp/x-sock",
        kea_control_socket_v6="/tmp/x6-sock",
    )
    hb = types.SimpleNamespace(lease_count_since_start=0)
    w = leases_mod.LeaseWatcher(cfg, ["tok"], hb)
    w._client = lambda: _Client()  # type: ignore[method-assign]
    w._pending = [_parse_row(_row())]
    w._flush()

    assert captured["path"] == "/api/v1/dhcp/agents/lease-events"
    assert "leases" in captured["json"] and "events" not in captured["json"]
    assert captured["json"]["leases"][0]["ip_address"] == "10.0.0.50"
    # #1077 — every lease batch carries a batch_id the server dedupes on.
    assert len(captured["json"]["batch_id"]) == 32
    assert hb.lease_count_since_start == 1
