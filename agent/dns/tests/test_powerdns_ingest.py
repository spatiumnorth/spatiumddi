"""PowerDNS ingest-back (issue #1524).

#641 enabled RFC 2136 dynamic updates on PowerDNS zones, but the
ingest-back worker that mirrors externally written records into
SpatiumDDI ran only for BIND9: records an AD domain controller or DHCP
server wrote to a PowerDNS zone never appeared in SpatiumDDI, and an
external value sharing a (name, type) with a managed rrset was silently
REPLACEd away by the next reconcile. The PowerDNS worker reads dynamic
zones back over the loopback REST API and ships them to the same
``/api/v1/dns/agents/ingested-records`` endpoint.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Self

import pytest

from spatium_dns_agent import ingest as ingest_mod
from spatium_dns_agent.cache import ensure_layout, save_config
from spatium_dns_agent.config import AgentConfig
from spatium_dns_agent.ingest import PowerDNSIngestWorker, parse_pdns_zone


def _zone_doc() -> dict[str, Any]:
    return {
        "name": "example.com.",
        "kind": "Master",
        "rrsets": [
            {
                "name": "example.com.",
                "type": "SOA",
                "ttl": 3600,
                "records": [
                    {
                        "content": "ns1.example.com. admin.example.com. 42 3600 600 86400 300",
                        "disabled": False,
                    }
                ],
            },
            {
                "name": "example.com.",
                "type": "NS",
                "ttl": 3600,
                "records": [{"content": "ns1.example.com.", "disabled": False}],
            },
            {
                "name": "ws1.example.com.",
                "type": "A",
                "ttl": 300,
                "records": [{"content": "192.0.2.50", "disabled": False}],
            },
            {
                "name": "example.com.",
                "type": "MX",
                "ttl": 3600,
                "records": [{"content": "10 mail.example.com.", "disabled": False}],
            },
            {
                "name": "_sip._tcp.example.com.",
                "type": "SRV",
                "ttl": 300,
                "records": [
                    {"content": "10 5 5060 sip.example.com.", "disabled": False}
                ],
            },
            {
                "name": "example.com.",
                "type": "TXT",
                "ttl": 300,
                "records": [
                    {"content": '"v=spf1 " "-all"', "disabled": False},
                    {"content": '"plain"', "disabled": True},
                ],
            },
            {
                "name": "ws1.example.com.",
                "type": "RRSIG",
                "ttl": 300,
                "records": [{"content": "A 13 3 300 ...", "disabled": False}],
            },
        ],
    }


def test_parse_pdns_zone_mirrors_axfr_shape() -> None:
    recs = parse_pdns_zone(_zone_doc(), "example.com.")
    assert recs is not None
    by_key = {(r["name"], r["record_type"]): r for r in recs}
    # SOA / apex NS / RRSIG are the daemon's — never shipped.
    assert set(by_key) == {
        ("ws1", "A"),
        ("@", "MX"),
        ("_sip._tcp", "SRV"),
        ("@", "TXT"),
    }
    assert by_key[("ws1", "A")]["value"] == "192.0.2.50"
    assert by_key[("ws1", "A")]["ttl"] == 300
    assert by_key[("@", "MX")]["priority"] == 10
    assert by_key[("@", "MX")]["value"] == "mail.example.com."
    srv = by_key[("_sip._tcp", "SRV")]
    assert (srv["priority"], srv["weight"], srv["port"]) == (10, 5, 5060)
    assert srv["value"] == "sip.example.com."
    # TXT: quoted chunks rejoined to the stored plain value; the disabled
    # record is not served, so it is not shipped either.
    assert by_key[("@", "TXT")]["value"] == "v=spf1 -all"


def test_parse_pdns_zone_without_soa_returns_none() -> None:
    """No apex SOA ⇒ not a zone pdns holds; shipping would read as "the
    zone is empty" and delete every external mirror."""
    doc = _zone_doc()
    doc["rrsets"] = [r for r in doc["rrsets"] if r["type"] != "SOA"]
    assert parse_pdns_zone(doc, "example.com.") is None
    assert parse_pdns_zone({"rrsets": []}, "example.com.") is None


class _Resp:
    def __init__(self, status: int = 200, body: Any = None) -> None:
        self.status_code = status
        self._body = body if body is not None else {}

    def json(self) -> Any:
        return self._body


class _FakeClient:
    def __init__(self, resp: _Resp) -> None:
        self._resp = resp

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def get(self, url: str, headers: Any = None) -> _Resp:
        return self._resp


def _worker(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch, resp: _Resp
) -> PowerDNSIngestWorker:
    monkeypatch.setattr(
        ingest_mod,
        "httpx",
        SimpleNamespace(Client=lambda **kw: _FakeClient(resp), HTTPError=Exception),
    )
    return PowerDNSIngestWorker(agent_cfg, ["tok"])


def test_pdns_worker_reads_zone_over_api(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = _worker(agent_cfg, monkeypatch, _Resp(200, _zone_doc()))
    recs = worker._read_live_zone("example.com", None)
    assert recs is not None and len(recs) == 4


def test_pdns_worker_read_failure_ships_nothing(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = _worker(agent_cfg, monkeypatch, _Resp(404, {}))
    assert worker._read_live_zone("example.com", None) is None


def test_pdns_worker_sweep_ships_dynamic_zones(
    agent_cfg: AgentConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ensure_layout(tmp_path)
    save_config(
        tmp_path,
        {
            "zones": [
                {
                    "name": "example.com",
                    "type": "primary",
                    "dynamic_update_enabled": True,
                },
                {
                    "name": "static.example.com",
                    "type": "primary",
                    "dynamic_update_enabled": False,
                },
            ],
            "tsig_keys": [],
        },
        "etag-1",
    )
    worker = PowerDNSIngestWorker(agent_cfg, ["tok"])
    shipped: list[tuple[str, list]] = []
    monkeypatch.setattr(worker, "_read_live_zone", lambda zone, key: [{"name": "ws1"}])
    monkeypatch.setattr(
        worker, "_ship", lambda zone, records: shipped.append((zone, records))
    )
    worker._sweep()
    assert shipped == [("example.com", [{"name": "ws1"}])]
