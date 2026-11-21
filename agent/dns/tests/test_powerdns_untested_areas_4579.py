"""PowerDNS agent paths the audit (#4579, C4 / C7 / C9) found nothing testing.

All offline: the pdns REST API is an ``httpx.MockTransport`` and rendering is
read back from the ``zones.json`` the driver writes. What needs a live pdns
(RFC 2136 acceptance, a secondary taking a NOTIFY, dnsdist) is not here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from spatium_dns_agent.drivers import powerdns
from spatium_dns_agent.drivers.powerdns import PowerDNSDriver

# ── C4: the DNSSEC helpers ────────────────────────────────────────────────────


class CryptokeyApi:
    """Cryptokeys of one zone, as much of the pdns API as sign / unsign use."""

    def __init__(
        self, keys: list[dict[str, Any]] | None = None, post_status: int = 201
    ) -> None:
        self.keys = keys or []
        self.post_status = post_status
        self.posts: list[dict[str, Any]] = []
        self.deleted: list[int] = []
        self.rectified = 0
        self.metadata_puts = 0
        self.delete_status = 204

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/cryptokeys") and request.method == "GET":
            return httpx.Response(200, json=self.keys)
        if path.endswith("/cryptokeys") and request.method == "POST":
            body = json.loads(request.content)
            self.posts.append(body)
            if self.post_status >= 400:
                return httpx.Response(self.post_status, json={"error": "no"})
            n = len(self.keys) + 1
            key: dict[str, Any] = {"id": n, "keytype": body["keytype"], "active": True}
            if body["keytype"] == "ksk":
                key["ds"] = [f"{n} 13 2 {'ab' * 32}", f"{n} 13 4 {'cd' * 48}"]
            self.keys.append(key)
            return httpx.Response(201, json=key)
        if "/cryptokeys/" in path and request.method == "DELETE":
            self.deleted.append(int(path.rsplit("/", 1)[1]))
            return httpx.Response(self.delete_status)
        if path.endswith("/rectify"):
            self.rectified += 1
            return httpx.Response(200, json={"result": "Rectified"})
        if "/metadata" in path:
            self.metadata_puts += 1
            return httpx.Response(204)
        return httpx.Response(404)


@pytest.fixture
def keys_api(monkeypatch: pytest.MonkeyPatch) -> CryptokeyApi:
    api = CryptokeyApi()
    real_client = httpx.Client

    def client(*args: Any, **kwargs: Any) -> httpx.Client:
        kwargs.pop("transport", None)
        return real_client(*args, transport=httpx.MockTransport(api.handle), **kwargs)

    monkeypatch.setattr(powerdns.httpx, "Client", client)
    return api


def test_extract_ds_takes_the_ksk_digests_only() -> None:
    keys = [
        {"keytype": "zsk", "ds": ["9 13 2 ignored"]},
        {"keytype": "ksk", "ds": ["1 13 2 aa", "  1 13 4 bb  ", "", None, 7]},
        {"keytype": "csk", "ds": ["2 13 2 cc"]},
        {"keytype": "ksk"},
    ]
    assert PowerDNSDriver._extract_ds_records(keys) == ["1 13 2 aa", "1 13 4 bb"]
    assert PowerDNSDriver._extract_ds_records([]) == []
    assert PowerDNSDriver._extract_ds_records(None) == []  # type: ignore[arg-type]


def test_sign_creates_a_ksk_and_a_zsk_and_returns_the_ds(
    tmp_path: Path, keys_api: CryptokeyApi
) -> None:
    ds = PowerDNSDriver(state_dir=tmp_path)._dnssec_sign("k", "t1.example.")
    assert [(p["keytype"], p["algorithm"], p["active"]) for p in keys_api.posts] == [
        ("ksk", "ecdsa256", True),
        ("zsk", "ecdsa256", True),
    ]
    assert len(ds) == 2 and all(d.endswith(("ab" * 32, "cd" * 48)) for d in ds)
    assert keys_api.rectified == 1
    # PRESIGNED is for externally-signed zones; pdns 422s it (see _dnssec_sign).
    assert keys_api.metadata_puts == 0


def test_a_second_sign_creates_no_more_keys(
    tmp_path: Path, keys_api: CryptokeyApi
) -> None:
    drv = PowerDNSDriver(state_dir=tmp_path)
    first = drv._dnssec_sign("k", "t1.example.")
    again = drv._dnssec_sign("k", "t1.example.")
    assert len(keys_api.posts) == 2
    assert again == first


def test_a_refused_key_fails_the_sign(tmp_path: Path, keys_api: CryptokeyApi) -> None:
    keys_api.post_status = 422
    with pytest.raises(RuntimeError, match="KSK"):
        PowerDNSDriver(state_dir=tmp_path)._dnssec_sign("k", "t1.example.")


def test_unsign_deletes_every_key_and_tolerates_a_vanished_one(
    tmp_path: Path, keys_api: CryptokeyApi
) -> None:
    keys_api.keys = [
        {"id": 1, "keytype": "ksk"},
        {"id": 2, "keytype": "zsk"},
        {"keytype": "zsk"},
    ]
    keys_api.delete_status = 404
    PowerDNSDriver(state_dir=tmp_path)._dnssec_unsign("k", "t1.example.")
    assert keys_api.deleted == [1, 2]
    assert keys_api.metadata_puts == 0


def test_unsign_of_an_unsigned_zone_is_a_no_op(
    tmp_path: Path, keys_api: CryptokeyApi
) -> None:
    PowerDNSDriver(state_dir=tmp_path)._dnssec_unsign("k", "t1.example.")
    assert keys_api.deleted == []


# ── C7: record types the control plane stores that pdns must be sent intact ──


def _zones_json(tmp_path: Path, bundle: dict[str, Any]) -> list[dict[str, Any]]:
    PowerDNSDriver(state_dir=tmp_path).render(bundle)
    out: list[dict[str, Any]] = json.loads(
        (tmp_path / "rendered.new" / "zones.json").read_text()
    )
    return out


_TLSA = "3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
_SSHFP = "4 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


# LOC is sent in the form pdns accepts, its size and precisions with two
# decimals (#4572); BIND9's shorter spelling of the same position is rewritten.
@pytest.mark.parametrize(
    ("rtype", "value", "expected"),
    [
        ("TLSA", _TLSA, _TLSA),
        ("SSHFP", _SSHFP, _SSHFP),
        (
            "LOC",
            "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m",
            "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000.00m 10.00m",
        ),
    ],
)
def test_wire_only_types_reach_pdns_unchanged(
    tmp_path: Path, rtype: str, value: str, expected: str
) -> None:
    bundle = {
        "options": {},
        "zones": [
            {
                "name": "example.com",
                "type": "primary",
                "records": [{"name": "h", "type": rtype, "value": value, "ttl": 300}],
            }
        ],
    }
    rrsets = {
        (r["name"], r["type"]): r for r in _zones_json(tmp_path, bundle)[0]["rrsets"]
    }
    rs = rrsets[("h.example.com.", rtype)]
    assert rs["ttl"] == 300
    assert [r["content"] for r in rs["records"]] == [expected]


# ── C9: the catalog zone ──────────────────────────────────────────────────────

CATALOG = {
    "mode": "producer",
    "zone_name": "catalog.spatium.invalid.",
    "members": [{"zone_name": "example.com."}],
}


def test_a_producer_catalog_is_rendered_as_a_zone_with_the_transfer_policy(
    tmp_path: Path,
) -> None:
    bundle = {
        "options": {"allow_transfer": ["192.0.2.53"]},
        "catalog": CATALOG,
        "zones": [{"name": "example.com", "type": "primary", "records": []}],
    }
    zones = {z["name"]: z for z in _zones_json(tmp_path, bundle)}
    assert set(zones) == {"example.com.", "catalog.spatium.invalid."}
    cat = zones["catalog.spatium.invalid."]
    assert cat["kind"] == "Native"
    ptrs = [r for r in cat["rrsets"] if r["type"] == "PTR"]
    assert [p["records"][0]["content"] for p in ptrs] == ["example.com."]
    # Consumers transfer the catalog like any zone: the same transfer ACL as a member.
    assert cat["axfr_from"] == zones["example.com."]["axfr_from"] != []


def test_a_catalog_with_no_members_still_carries_the_schema_version(
    tmp_path: Path,
) -> None:
    bundle = {"options": {}, "catalog": {**CATALOG, "members": []}, "zones": []}
    (cat,) = _zones_json(tmp_path, bundle)
    kinds = {(r["name"], r["type"]) for r in cat["rrsets"]}
    assert ("version.catalog.spatium.invalid.", "TXT") in kinds
    assert not [r for r in cat["rrsets"] if r["type"] == "PTR"]


def test_a_consumer_catalog_renders_no_zone(tmp_path: Path) -> None:
    bundle = {
        "options": {},
        "catalog": {**CATALOG, "mode": "consumer"},
        "zones": [{"name": "example.com", "type": "primary", "records": []}],
    }
    assert [z["name"] for z in _zones_json(tmp_path, bundle)] == ["example.com."]
