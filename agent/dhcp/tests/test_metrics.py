"""Tests for the Kea metrics poller.

Covers the interesting behaviors:
  • first tick after startup establishes a baseline, doesn't report;
  • second tick with a positive delta gets reported upstream;
  • counter-reset (Kea restart) is detected and the bucket is dropped;
  • the #980 loss counters ride the same delta, and ``socket_drop`` — which
    comes from procfs rather than from Kea — stays in lockstep with them.

We test ``_parse_snapshot`` + ``_compute_delta`` directly so the HTTP
client stays out of the test path.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from spatium_dhcp_agent.config import AgentConfig
from spatium_dhcp_agent.metrics import MetricsPoller, _parse_snapshot


def _snapshot(values: dict[str, int]) -> dict:
    """Build a fake ``statistic-get-all`` response."""
    args: dict = {}
    for stat, v in values.items():
        args[stat] = [[v, "2026-04-22 09:00:00.000"]]
    return {"arguments": args}


def test_parse_snapshot_picks_expected_columns():
    resp = _snapshot(
        {
            "pkt4-discover-received": 10,
            "pkt4-offer-sent": 9,
            "pkt4-request-received": 9,
            "pkt4-ack-sent": 8,
            "pkt4-nak-sent": 1,
            "pkt4-decline-received": 0,
            "pkt4-release-received": 2,
            "pkt4-inform-received": 0,
        }
    )
    assert _parse_snapshot(resp) == {
        "discover": 10,
        "offer": 9,
        "request": 9,
        "ack": 8,
        "nak": 1,
        "decline": 0,
        "release": 2,
        "inform": 0,
        # #980 — absent from this response, so 0. The column exists either
        # way; a Kea too old to publish it is not a Kea that dropped nothing.
        "receive_drop": 0,
    }


def test_parse_snapshot_missing_counter_defaults_zero():
    # Fresh Kea that hasn't seen traffic yet won't have every counter
    # in its response. We must still produce a full row.
    resp = _snapshot({"pkt4-ack-sent": 5})
    out = _parse_snapshot(resp)
    assert out["ack"] == 5
    assert out["discover"] == 0
    assert out["request"] == 0


def _poller(tmp_path) -> MetricsPoller:
    cfg = AgentConfig(
        control_plane_url="http://api.invalid",
        agent_key="unused",
        server_name="dhcp-test",
        state_dir=tmp_path,
        kea_config_path=tmp_path / "kea.conf",
        kea_control_socket=tmp_path / "sock",
        kea_lease_file=tmp_path / "leases.csv",
        kea_config_path_v6=tmp_path / "kea6.conf",
        kea_control_socket_v6=tmp_path / "sock6",
        group_name=None,
        roles=["primary"],
        tls_ca_path=None,
        insecure_skip_tls_verify=True,
    )
    return MetricsPoller(cfg, token_ref=["unused"])


def test_first_tick_establishes_baseline(tmp_path):
    p = _poller(tmp_path)
    # First snapshot — no previous baseline, poller should not emit.
    delta = p._compute_delta(
        {
            "discover": 5,
            "offer": 5,
            "request": 5,
            "ack": 5,
            "nak": 0,
            "decline": 0,
            "release": 0,
            "inform": 0,
        }
    )
    assert delta is None


def test_second_tick_emits_delta(tmp_path):
    p = _poller(tmp_path)
    p._compute_delta(
        {
            "discover": 5,
            "offer": 5,
            "request": 5,
            "ack": 5,
            "nak": 0,
            "decline": 0,
            "release": 0,
            "inform": 0,
        }
    )
    delta = p._compute_delta(
        {
            "discover": 8,
            "offer": 8,
            "request": 8,
            "ack": 8,
            "nak": 1,
            "decline": 0,
            "release": 1,
            "inform": 0,
        }
    )
    assert delta == {
        "discover": 3,
        "offer": 3,
        "request": 3,
        "ack": 3,
        "nak": 1,
        "decline": 0,
        "release": 1,
        "inform": 0,
        "receive_drop": 0,
    }


def test_counter_reset_drops_bucket(tmp_path):
    p = _poller(tmp_path)
    p._compute_delta(
        {
            "discover": 100,
            "offer": 100,
            "request": 100,
            "ack": 100,
            "nak": 0,
            "decline": 0,
            "release": 0,
            "inform": 0,
        }
    )
    # Kea restart: counters back to zero.
    delta = p._compute_delta(
        {
            "discover": 0,
            "offer": 0,
            "request": 0,
            "ack": 0,
            "nak": 0,
            "decline": 0,
            "release": 0,
            "inform": 0,
        }
    )
    assert delta is None
    # Next normal tick produces a delta against the restart baseline.
    delta2 = p._compute_delta(
        {
            "discover": 2,
            "offer": 2,
            "request": 2,
            "ack": 2,
            "nak": 0,
            "decline": 0,
            "release": 0,
            "inform": 0,
        }
    )
    assert delta2 == {
        "discover": 2,
        "offer": 2,
        "request": 2,
        "ack": 2,
        "nak": 0,
        "decline": 0,
        "release": 0,
        "inform": 0,
        "receive_drop": 0,
    }


# ── #980: the loss counters ─────────────────────────────────────────────────


def test_receive_drop_folds_both_address_families():
    """v4 and v6 are separate daemons sharing one row, like every other
    column here — so their drop counters sum rather than one overwriting
    the other."""
    resp = _snapshot({"pkt4-receive-drop": 4, "pkt6-receive-drop": 3})
    assert _parse_snapshot(resp)["receive_drop"] == 7


class _FakeResponse:
    status_code = 200


class _FakeClient:
    """Stands in for httpx.Client and records the JSON body actually posted."""

    def __init__(self, sink: list):
        self._sink = sink

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def post(self, url, json=None, headers=None):
        self._sink.append(json)
        return _FakeResponse()


def _posted_body(tmp_path, monkeypatch, socket_drop):
    """Run the REAL ``_report`` and return the body it put on the wire."""
    p = _poller(tmp_path)
    sink: list = []
    monkeypatch.setattr(p, "_client", lambda: _FakeClient(sink))
    p._report(datetime(2026, 9, 6, 12, 0, tzinfo=UTC), {"discover": 3}, socket_drop)
    assert len(sink) == 1
    return sink[0]


def test_wire_body_carries_socket_drop_zero_as_a_value(tmp_path, monkeypatch):
    """Zero is a measurement and has to appear in the payload as 0.

    The server stores an omitted field as NULL, and NULL means "nobody
    looked" — so a working agent that measured no loss must not be filed
    under the same label as an agent that cannot measure at all. Asserts on
    the posted body rather than on a stubbed ``_report``, or the test would
    pass for a ``_report`` that silently dropped the field.
    """
    body = _posted_body(tmp_path, monkeypatch, 0)
    assert "socket_drop" in body
    assert body["socket_drop"] == 0
    assert body["discover"] == 3


def test_wire_body_carries_none_when_unmeasurable(tmp_path, monkeypatch):
    """The other half: unknown travels as an explicit null, not as 0 and not
    by omission (omission would be indistinguishable, but being explicit is
    what makes an older control plane's 422 loud rather than silent)."""
    body = _posted_body(tmp_path, monkeypatch, None)
    assert "socket_drop" in body
    assert body["socket_drop"] is None


def test_one_run_iteration_samples_both_counters_together(tmp_path, monkeypatch):
    """Drive the REAL ``run()`` loop for two ticks.

    Both baselines must advance on the same ticks: a bucket that is thrown
    away (agent start, Kea restart) throws away both deltas, and a bucket
    that is reported carries two numbers covering the same interval. If only
    one advanced, "drops against DISCOVERs" — the first comparison anyone
    makes — would span different windows.
    """
    p = _poller(tmp_path)
    sink: list = []
    monkeypatch.setattr(p, "_client", lambda: _FakeClient(sink))

    kea = iter([{"discover": 0}, {"discover": 7}])
    monkeypatch.setattr(p, "_poll_kea", lambda: next(kea, None))

    samples = iter([11, 22])
    sock_calls: list = []

    def _sample():
        v = next(samples, None)
        sock_calls.append(v)
        return v

    monkeypatch.setattr(p._socket, "sample", _sample)
    # Stop after the second tick rather than sleeping 60 s.
    real_wait = p._stop.wait
    ticks = {"n": 0}

    def _wait(timeout=None):
        ticks["n"] += 1
        if ticks["n"] >= 2:
            p._stop.set()
        return real_wait(0)

    monkeypatch.setattr(p._stop, "wait", _wait)

    p.run()

    # Two ticks -> two socket samples; only the second tick had a Kea
    # baseline, so exactly one bucket was posted, carrying that tick's
    # socket sample and not the first one.
    assert sock_calls == [11, 22]
    assert len(sink) == 1
    assert sink[0]["discover"] == 7
    assert sink[0]["socket_drop"] == 22


def test_the_drop_counter_follows_the_rendered_socket_mode(tmp_path):
    """#1283: the poller tells the drop counter kea-dhcp4's socket mode from
    the config file this agent writes for kea (``kea_config_path``)."""
    p = _poller(tmp_path)
    assert p._socket._socket_type() is None  # nothing rendered yet: unknown
    doc = {"Dhcp4": {"interfaces-config": {"dhcp-socket-type": "udp"}}}
    (tmp_path / "kea.conf").write_text(json.dumps(doc))
    assert p._socket._socket_type() == "udp"
    doc["Dhcp4"]["interfaces-config"]["dhcp-socket-type"] = "raw"
    (tmp_path / "kea.conf").write_text(json.dumps(doc))
    assert p._socket._socket_type() == "raw"
