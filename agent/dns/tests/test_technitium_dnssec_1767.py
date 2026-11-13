"""DNSSEC on Technitium is structural, policy-driven and reported (#1767).

The sign op used to be one-shot: a zone created fresh on a new server, after a
retire, or on an empty data volume came back unsigned under a DS the control
plane still showed; the policy was ignored (always ECDSA P256 / NSEC); key
state was never read again. These tests drive the real reconcile against a
fake daemon that keeps signing state the way Technitium does.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from spatium_dns_agent.drivers.technitium import TechnitiumDriver

from .test_technitium_reconcile_churn import FakeTechnitium, _z
from .test_technitium_render import _install_fake_request, _seed_token


class _DnssecFake(FakeTechnitium):
    def __init__(self, zones: list[str], signed: dict[str, dict[str, Any]] | None = None) -> None:
        super().__init__(zones)
        # zone -> {"algo": 13, "nsec3": False}
        self.signed: dict[str, dict[str, Any]] = dict(signed or {})
        self.signs: list[dict[str, Any]] = []
        self.rollovers: list[dict[str, Any]] = []

    def respond(self, path: str, params: dict[str, Any], n: int) -> dict[str, Any]:
        zone = params.get("zone")
        if path == "zones/dnssec/properties/get":
            st = self.signed.get(zone)
            keys = (
                []
                if st is None
                else [
                    {
                        "keyTag": 111,
                        "keyType": "KeySigningKey",
                        "algorithmNumber": st["algo"],
                        "state": "Active",
                    },
                    {
                        "keyTag": 222,
                        "keyType": "ZoneSigningKey",
                        "algorithmNumber": st["algo"],
                        "state": "Active",
                    },
                ]
            )
            status = "Unsigned" if st is None else ("SignedWithNSEC3" if st["nsec3"] else "SignedWithNSEC")
            return {"status": "ok", "response": {"dnssecStatus": status, "dnssecPrivateKeys": keys}}
        if path == "zones/dnssec/sign":
            if zone in self.signed:
                return {"status": "error", "errorMessage": "Cannot sign zone: the zone is already signed."}
            self.signs.append(dict(params))
            self.signed[zone] = {
                "algo": {"ECDSA": 13, "EDDSA": 15, "RSA": 8}[params["algorithm"]],
                "nsec3": params.get("nxProof") == "NSEC3",
            }
            return {"status": "ok"}
        if path == "zones/dnssec/properties/rolloverDnsKey":
            self.rollovers.append(dict(params))
            return {"status": "ok"}
        if path == "zones/records/get" and params.get("listZone") == "true" and zone in self.signed:
            return {
                "status": "ok",
                "response": {
                    "records": [
                        {
                            "type": "DNSKEY",
                            "rData": {
                                "computedKeyTag": 111,
                                "algorithmNumber": self.signed[zone]["algo"],
                                "computedDigests": [{"digestType": "SHA256", "digest": "AB12"}],
                            },
                        }
                    ]
                },
            }
        return super().respond(path, params, n)


def _driver(tmp_path: Path, fake: _DnssecFake) -> TechnitiumDriver:
    d = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(d)
    _install_fake_request(d, fake.respond)
    d._ensure_zone_exists = lambda *_a, **_k: None  # type: ignore[method-assign]
    d._apply_zone_options = lambda *_a, **_k: None  # type: ignore[method-assign]
    d._reconcile_zone_apex = lambda *_a, **_k: None  # type: ignore[method-assign]
    d._apply_failures = []
    return d


def _bundle(policy: dict[str, Any] | None = None, enabled: bool = True) -> dict[str, Any]:
    zone = _z("example.com.", [{"name": "www", "type": "A", "value": "10.0.0.1", "ttl": 300}])
    zone["dnssec_enabled"] = enabled
    zone["dnssec_policy_name"] = policy["name"] if policy else None
    return {"zones": [zone], "dnssec_policies": [policy] if policy else []}


def _payload(d: TechnitiumDriver, bundle: dict[str, Any]) -> list[dict[str, Any]]:
    d.render(bundle)
    return json.loads((d.state_dir / "rendered.new" / "zones.json").read_text())


def test_unsigned_zone_is_signed_by_the_structural_pass(tmp_path: Path) -> None:
    """A zone the bundle flags signed, found unsigned (new server, re-created
    zone, lost volume), is signed without any sign op."""
    fake = _DnssecFake(["example.com"])
    d = _driver(tmp_path, fake)
    d._reconcile_zones("tok-1", _payload(d, _bundle()))
    assert len(fake.signs) == 1
    assert fake.signs[0]["zone"] == "example.com"
    assert fake.signs[0]["algorithm"] == "ECDSA" and fake.signs[0]["curve"] == "P256"
    # A second pass finds it signed and does nothing.
    d._reconcile_zones("tok-1", _payload(d, _bundle()))
    assert len(fake.signs) == 1
    assert d._apply_failures == []


def test_policy_maps_onto_sign_parameters(tmp_path: Path) -> None:
    policy = {
        "name": "rsa-nsec3",
        "algorithm": "rsasha256",
        "zsk_lifetime_days": 60,
        "ksk_lifetime_days": 0,
        "nsec3": True,
        "nsec3_iterations": 5,
        "nsec3_salt_length": 8,
        "nsec3_optout": False,
    }
    fake = _DnssecFake(["example.com"])
    d = _driver(tmp_path, fake)
    d._reconcile_zones("tok-1", _payload(d, _bundle(policy)))
    sent = fake.signs[0]
    assert sent["algorithm"] == "RSA" and sent["hashAlgorithm"] == "SHA256"
    assert sent["kskKeySize"] == "2048" and sent["zskKeySize"] == "2048"
    assert sent["nxProof"] == "NSEC3" and sent["iterations"] == "5" and sent["saltLength"] == "8"
    assert sent["zskRolloverDays"] == "60"


def test_policy_change_on_signed_zone_is_reported_not_resigned(tmp_path: Path) -> None:
    fake = _DnssecFake(["example.com"], {"example.com": {"algo": 13, "nsec3": False}})
    d = _driver(tmp_path, fake)
    policy = {"name": "ed", "algorithm": "ed25519", "nsec3": False}
    d._reconcile_zones("tok-1", _payload(d, _bundle(policy)))
    assert fake.signs == []  # re-signing would change the DS
    assert any("DNSSEC policy" in f for f in d._apply_failures)


def test_unflagged_signed_zone_is_left_alone(tmp_path: Path) -> None:
    fake = _DnssecFake(["example.com"], {"example.com": {"algo": 13, "nsec3": False}})
    d = _driver(tmp_path, fake)
    d._reconcile_zones("tok-1", _payload(d, _bundle(enabled=False)))
    assert fake.signs == [] and d._apply_failures == []
    assert not [p for p in fake.__dict__.get("writes", []) if "unsign" in str(p)]


def test_public_collect_reports_key_state_for_signed_zones(tmp_path: Path) -> None:
    """The sync loop looks up ``collect_dnssec_state``; it must exist."""
    fake = _DnssecFake(["example.com"], {"example.com": {"algo": 13, "nsec3": False}})
    d = _driver(tmp_path, fake)
    out = d.collect_dnssec_state(_bundle())
    assert len(out) == 1
    assert out[0]["zone_name"] == "example.com"
    assert out[0]["ds_records"] == ["111 13 2 AB12"]
    assert {k["key_type"] for k in out[0]["keys"]} == {"ksk", "zsk"}
    assert d.dnssec_incomplete is False


def test_collect_marks_unsigned_zone_incomplete(tmp_path: Path) -> None:
    fake = _DnssecFake(["example.com"])
    d = _driver(tmp_path, fake)
    assert d.collect_dnssec_state(_bundle()) == []
    assert d.dnssec_incomplete is True


def test_rollover_op_calls_rollover_dnskey(tmp_path: Path) -> None:
    fake = _DnssecFake(["example.com"], {"example.com": {"algo": 13, "nsec3": False}})
    d = _driver(tmp_path, fake)
    res = d.apply_record_op(
        {
            "op": "dnssec_rollover",
            "zone_name": "example.com.",
            "record": {"name": "@", "type": "DNSSEC_OP", "key_tag": 111},
        }
    )
    assert fake.rollovers == [{"zone": "example.com", "keyTag": 111}]
    assert res and res["dnssec_state"]["zone_name"] == "example.com"
