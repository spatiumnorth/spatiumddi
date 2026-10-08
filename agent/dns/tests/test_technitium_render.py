"""Technitium agent driver unit tests. No live daemon required.

Two layers here:

* Pure helpers (param builders, name qualification, SVCB parsing) —
  straight assertions.
* The API-driven paths (``apply_record_op``, ``_reconcile_zones``,
  ``_call``'s auth recovery). Those are the ones carrying the real
  semantics — rrset REPLACE-vs-append, TTL convergence, stale-token
  re-provisioning — so they are exercised here against a fake
  ``_request`` rather than left to the manual docker-compose run. The
  wire shapes they assert against (``{"status": "ok"|"error"|
  "invalid-token"}`` at HTTP 200, ``rData`` on record GETs) were
  confirmed empirically against a real ``technitium/dns-server``
  container — see the driver module docstring.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from spatium_dns_agent.drivers.technitium import (
    TechnitiumDriver,
    _blocking_payload,
    _normalize_rdata,
    _qualified_name,
    _record_params,
    _svcb_params,
    _tsig_key_names,
    _zone_options_payload,
)


class _FakeResponse:
    """Stand-in for ``httpx.Response``. A dict body is a JSON answer; a str
    body is a plain-text one (``blocked/export``), whose ``.json()`` raises
    as httpx's does."""

    def __init__(self, body: dict[str, Any] | str) -> None:
        self._body = body
        self.status_code = 200
        self.text = body if isinstance(body, str) else ""

    def json(self) -> dict[str, Any]:
        if isinstance(self._body, str):
            raise ValueError("not JSON")
        return self._body


def _install_fake_request(
    driver: TechnitiumDriver,
    responder: Any,
) -> list[tuple[str, str, str, dict[str, Any]]]:
    """Replace ``_request`` with a recorder. Returns the call log as
    ``(token, method, path, params)`` tuples."""
    calls: list[tuple[str, str, str, dict[str, Any]]] = []

    def _fake(token: str, method: str, path: str, params: dict[str, Any]):
        calls.append((token, method, path, dict(params)))
        return _FakeResponse(responder(path, params, len(calls)))

    driver._request = _fake  # type: ignore[method-assign]
    return calls


def _seed_token(driver: TechnitiumDriver, token: str = "tok-1") -> None:
    driver._write_secret(driver._api_token_path(), token)


def test_qualified_name_apex() -> None:
    assert _qualified_name("example.com", "@") == "example.com"
    assert _qualified_name("example.com", "") == "example.com"
    assert _qualified_name("example.com.", "example.com.") == "example.com"


def test_qualified_name_subdomain() -> None:
    assert _qualified_name("example.com", "www") == "www.example.com"
    assert _qualified_name("example.com", "_sip._tcp") == "_sip._tcp.example.com"


def test_record_params_a_aaaa() -> None:
    assert _record_params("A", "10.0.0.1", {}) == {"ipAddress": "10.0.0.1"}
    assert _record_params("AAAA", "2001:db8::1", {}) == {"ipAddress": "2001:db8::1"}


def test_record_params_cname_dname_ns_ptr() -> None:
    assert _record_params("CNAME", "www.example.com.", {}) == {"cname": "www.example.com"}
    assert _record_params("DNAME", "other.example.net.", {}) == {"dname": "other.example.net"}
    assert _record_params("NS", "ns1.example.com.", {}) == {"nameServer": "ns1.example.com"}
    assert _record_params("PTR", "host.example.com.", {}) == {"ptrName": "host.example.com"}


def test_record_params_mx_uses_priority() -> None:
    rec = {"priority": 20}
    assert _record_params("MX", "mail.example.com.", rec) == {
        "exchange": "mail.example.com",
        "preference": 20,
    }


def test_record_params_mx_default_priority() -> None:
    assert _record_params("MX", "mail.example.com.", {})["preference"] == 10


def test_record_params_srv() -> None:
    rec = {"priority": 10, "weight": 20, "port": 5060}
    assert _record_params("SRV", "sip.example.com.", rec) == {
        "target": "sip.example.com",
        "priority": 10,
        "weight": 20,
        "port": 5060,
    }


def test_record_params_txt() -> None:
    assert _record_params("TXT", "v=spf1 -all", {}) == {"text": "v=spf1 -all"}


def test_record_params_caa() -> None:
    out = _record_params("CAA", '0 issue "letsencrypt.org"', {})
    assert out == {"flags": 0, "tag": "issue", "value": "letsencrypt.org"}


def test_record_params_tlsa() -> None:
    out = _record_params("TLSA", "3 1 1 abcd1234", {})
    assert out == {
        "tlsaCertificateUsage": "3",
        "tlsaSelector": "1",
        "tlsaMatchingType": "1",
        "tlsaCertificateAssociationData": "abcd1234",
    }


def test_record_params_sshfp() -> None:
    out = _record_params("SSHFP", "4 2 abcd1234", {})
    assert out == {
        "sshfpAlgorithm": "4",
        "sshfpFingerprintType": "2",
        "sshfpFingerprint": "abcd1234",
    }


def test_record_params_naptr() -> None:
    value = '100 10 U "E2U+sip" "!^.*$!sip:info@example.com!" .'
    out = _record_params("NAPTR", value, {})
    assert out["naptrOrder"] == "100"
    assert out["naptrPreference"] == "10"
    assert out["naptrFlags"] == "U"
    assert out["naptrServices"] == "E2U+sip"
    assert out["naptrReplacement"] == "."


def test_record_params_uri() -> None:
    out = _record_params("URI", "1 1 https://example.com", {})
    assert out == {"uriPriority": "1", "uriWeight": "1", "uri": "https://example.com"}


def test_svcb_params_single_value() -> None:
    priority, target, params = _svcb_params('1 . alpn="h2"')
    assert priority == 1
    assert target == "."
    assert params == "alpn|h2"


def test_svcb_params_no_params() -> None:
    priority, target, params = _svcb_params("1 svc.example.com.")
    assert priority == 1
    # Root dot stripped — the daemon stores the target un-dotted. See
    # test_svcb_target_root_dot_is_stripped.
    assert target == "svc.example.com"
    assert params == ""


def test_record_params_svcb() -> None:
    out = _record_params("SVCB", '1 . alpn="h2"', {})
    assert out == {"svcPriority": 1, "svcTargetName": ".", "svcParams": "alpn|h2"}


def test_record_params_https_no_params_omits_svcparams() -> None:
    out = _record_params("HTTPS", "1 .", {})
    assert out == {"svcPriority": 1, "svcTargetName": "."}


def test_admin_bootstrap_password_persists(tmp_path: Path) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    pw1 = d.admin_bootstrap_password()
    pw2 = d.admin_bootstrap_password()
    assert pw1 == pw2
    path = tmp_path / "technitium-admin-password"
    assert path.exists()
    assert oct(path.stat().st_mode)[-3:] == "600"


def test_render_skips_daemon_managed_apex_types(tmp_path: Path) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    bundle = {
        "zones": [
            {
                "name": "example.com.",
                "type": "primary",
                "ttl": 3600,
                "records": [
                    {"name": "@", "type": "SOA", "value": "ignored"},
                    {"name": "@", "type": "NS", "value": "ns1.example.com."},
                    {"name": "sub", "type": "NS", "value": "ns2.example.com."},
                    {"name": "www", "type": "A", "value": "10.0.0.1", "ttl": 300},
                ],
            }
        ]
    }
    d.render(bundle)
    import json

    payload = json.loads((tmp_path / "rendered.new" / "zones.json").read_text())
    zone = payload[0]
    types_by_domain = {(r["domain"], r["type"]) for r in zone["records"]}
    # Apex SOA + apex NS are daemon-managed — excluded.
    assert ("example.com", "SOA") not in types_by_domain
    assert ("example.com", "NS") not in types_by_domain
    # Off-apex NS (delegation) and ordinary records pass through.
    assert ("sub.example.com", "NS") in types_by_domain
    assert ("www.example.com", "A") in types_by_domain


# ── apply_record_op: rrset REPLACE vs append ────────────────────────────


def test_apply_record_op_update_replaces_rrset(tmp_path: Path) -> None:
    """A record edit must REPLACE the rrset, not append to it.

    Regression guard: with ``overwrite=false`` an edited A record leaves
    the daemon serving the OLD and NEW addresses side by side, and a
    TTL-only edit comes back "already exists" and is swallowed. Neither
    self-heals — record CRUD bumps the bundle ``etag`` but not
    ``structural_etag``, so the full-zone reconcile never fires on a
    record edit. Matches bind9's ``upd.replace`` / PowerDNS's rrset
    REPLACE.
    """
    d = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(d)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})

    d.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "update",
            "record": {"name": "www", "type": "A", "value": "10.0.0.2", "ttl": 300},
        }
    )

    _, method, path, params = calls[0]
    assert method == "POST"
    assert path == "zones/records/add"
    assert params["overwrite"] == "true"
    assert params["domain"] == "www.example.com"
    assert params["ipAddress"] == "10.0.0.2"
    assert params["ttl"] == 300


def test_apply_record_op_create_replaces_rrset(tmp_path: Path) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(d)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})

    d.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "create",
            "record": {"name": "www", "type": "A", "value": "10.0.0.1", "ttl": 300},
        }
    )
    assert calls[0][3]["overwrite"] == "true"


def test_apply_record_op_honours_rrset_action_add(tmp_path: Path) -> None:
    """DNS pools set ``rrset_action="add"`` because N A records share one
    name there — a REPLACE would clobber siblings on every member add.
    Same override bind9's driver honours."""
    d = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(d)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})

    d.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "create",
            "record": {
                "name": "pool",
                "type": "A",
                "value": "10.0.0.7",
                "ttl": 60,
                "rrset_action": "add",
            },
        }
    )
    assert calls[0][3]["overwrite"] == "false"


def test_apply_record_op_delete_sends_no_overwrite(tmp_path: Path) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(d)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})

    d.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "delete",
            "record": {"name": "www", "type": "A", "value": "10.0.0.1"},
        }
    )
    _, _, path, params = calls[0]
    assert path == "zones/records/delete"
    assert "overwrite" not in params
    assert "ttl" not in params


# ── _call: stale-token recovery ─────────────────────────────────────────


def test_call_reprovisions_on_invalid_token(tmp_path: Path) -> None:
    """The state dir (token) and /etc/dns (daemon admin account) are
    separate volumes and can desync. An ``invalid-token`` answer must
    re-provision and retry, not wedge the agent forever."""
    d = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(d, "stale-token")

    def _responder(path: str, params: dict[str, Any], n: int) -> dict[str, Any]:
        return {"status": "invalid-token"} if n == 1 else {"status": "ok"}

    calls = _install_fake_request(d, _responder)
    d._create_api_token = lambda: (  # type: ignore[method-assign]
        d._write_secret(d._api_token_path(), "fresh-token") or "fresh-token"
    )

    resp = d._call("stale-token", "POST", "zones/create", {"zone": "example.com"})

    assert resp.json()["status"] == "ok"
    assert [c[0] for c in calls] == ["stale-token", "fresh-token"]
    assert d._api_token_path().read_text().strip() == "fresh-token"


def test_reprovision_reuses_token_another_call_already_refreshed(
    tmp_path: Path,
) -> None:
    """Several calls in one reconcile pass hold the same stale token in a
    local. Only the first should mint a replacement — ``createToken`` is
    not idempotent, so the rest would orphan tokens server-side."""
    d = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(d, "already-fresh")
    minted: list[str] = []

    def _boom() -> str:
        minted.append("x")
        return "should-not-happen"

    d._create_api_token = _boom  # type: ignore[method-assign]

    assert d._reprovision_token("stale-token") == "already-fresh"
    assert minted == []


# ── _reconcile_zones: TTL convergence ───────────────────────────────────


def _reconcile_with(
    driver: TechnitiumDriver,
    existing: list[dict[str, Any]],
    desired: list[dict[str, Any]],
) -> list[tuple[str, str, str, dict[str, Any]]]:
    def _responder(path: str, params: dict[str, Any], n: int) -> dict[str, Any]:
        if path == "zones/records/get":
            return {"status": "ok", "response": {"records": existing}}
        return {"status": "ok"}

    calls = _install_fake_request(driver, _responder)
    driver._reconcile_zones(
        "tok-1", [{"zone": "example.com", "type": "Primary", "records": desired}]
    )
    return calls


def test_reconcile_converges_ttl_only_change(tmp_path: Path) -> None:
    """TTL participates in the record fingerprint — it is a real
    desired-state change and this is the only path that can converge it
    (the incremental op path never sees the old value)."""
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _reconcile_with(
        d,
        existing=[
            {"name": "www.example.com", "type": "A", "ttl": 3600,
             "rData": {"ipAddress": "10.0.0.1"}}
        ],
        desired=[
            {"domain": "www.example.com", "type": "A", "ttl": 300,
             "ipAddress": "10.0.0.1"}
        ],
    )
    paths = [c[2] for c in calls]
    assert "zones/records/delete" in paths
    added = [c[3] for c in calls if c[2] == "zones/records/add"]
    assert len(added) == 1
    assert added[0]["ttl"] == 300


def test_reconcile_is_a_noop_when_already_in_sync(tmp_path: Path) -> None:
    """No churn on an unchanged zone — the failure mode this guards is a
    delete+add of every record on every single pass."""
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _reconcile_with(
        d,
        existing=[
            {"name": "www.example.com", "type": "A", "ttl": 300,
             "rData": {"ipAddress": "10.0.0.1"}}
        ],
        desired=[
            {"domain": "www.example.com", "type": "A", "ttl": 300,
             "ipAddress": "10.0.0.1"}
        ],
    )
    assert [c[2] for c in calls if c[2] != "zones/create"] == ["zones/records/get"]


def test_reconcile_tolerates_numeric_vs_string_rdata(tmp_path: Path) -> None:
    """``_record_params`` renders SSHFP/TLSA/NAPTR/URI fields as strings
    while the daemon returns some of them as numbers. Without
    normalisation every such record reads as "changed" forever."""
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _reconcile_with(
        d,
        existing=[
            {"name": "example.com", "type": "MX", "ttl": 3600,
             "rData": {"exchange": "mail.example.com", "preference": 10}}
        ],
        desired=[
            {"domain": "example.com", "type": "MX", "ttl": 3600,
             "exchange": "mail.example.com", "preference": "10"}
        ],
    )
    assert [c[2] for c in calls if c[2] != "zones/create"] == ["zones/records/get"]


def test_reconcile_never_deletes_daemon_managed_apex(tmp_path: Path) -> None:
    """Technitium auto-creates SOA + one apex NS on zone create. Deleting
    them because the bundle doesn't list them would break the zone."""
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _reconcile_with(
        d,
        existing=[
            {"name": "example.com", "type": "SOA", "ttl": 3600, "rData": {}},
            {"name": "example.com", "type": "NS", "ttl": 3600,
             "rData": {"nameServer": "technitium.local"}},
        ],
        desired=[],
    )
    assert [c[2] for c in calls if c[2] == "zones/records/delete"] == []


# ── rData read-back normalisation ───────────────────────────────────────
#
# Technitium's record GET does not echo the params its record ADD takes:
# it renames keys for NAPTR/URI, translates TLSA/SSHFP numeric fields to
# enum NAMES, returns svcParams as a dict, and mutates a few values. Every
# expectation below was captured from a live technitium/dns-server:15.4.0.


def test_normalize_rdata_tlsa_enum_names() -> None:
    out = _normalize_rdata(
        "TLSA",
        {
            "certificateUsage": "DANE-EE",
            "selector": "SPKI",
            "matchingType": "SHA2-256",
            "certificateAssociationData": "ABCD",
        },
    )
    assert out == {
        "tlsaCertificateUsage": "3",
        "tlsaSelector": "1",
        "tlsaMatchingType": "1",
        "tlsaCertificateAssociationData": "abcd",
    }


def test_normalize_rdata_sshfp_enum_names() -> None:
    out = _normalize_rdata(
        "SSHFP",
        {"algorithm": "Ed25519", "fingerprintType": "SHA256", "fingerprint": "AB12"},
    )
    assert out == {
        "sshfpAlgorithm": "4",
        "sshfpFingerprintType": "2",
        "sshfpFingerprint": "ab12",
    }


def test_normalize_rdata_unknown_enum_passes_through() -> None:
    """Technitium echoes an algorithm it has no name for back as its own
    number. A future enum member must degrade to a comparison mismatch on
    one record, never a KeyError that kills the whole reconcile."""
    out = _normalize_rdata("SSHFP", {"algorithm": "5"})
    assert out == {"sshfpAlgorithm": "5"}


def test_normalize_rdata_naptr_and_uri_key_renames() -> None:
    assert _normalize_rdata(
        "NAPTR",
        {"order": 100, "preference": 10, "flags": "U", "services": "E2U+sip",
         "regexp": "!x!", "replacement": "."},
    ) == {
        "naptrOrder": 100, "naptrPreference": 10, "naptrFlags": "U",
        "naptrServices": "E2U+sip", "naptrRegexp": "!x!", "naptrReplacement": ".",
    }
    # Technitium appends "/" to a bare-authority URI when it stores it.
    assert _normalize_rdata(
        "URI", {"priority": 1, "weight": 1, "uri": "https://example.test/"}
    ) == {"uriPriority": 1, "uriWeight": 1, "uri": "https://example.test"}


def test_normalize_rdata_svcb_params_dict_and_apex_target() -> None:
    out = _normalize_rdata(
        "SVCB", {"svcPriority": 1, "svcTargetName": "", "svcParams": {"alpn": "h2,h3"}}
    )
    assert out == {"svcPriority": 1, "svcTargetName": ".", "svcParams": "alpn|h2,h3"}


def test_normalize_rdata_leaves_matching_types_alone() -> None:
    for rtype, rdata in [
        ("A", {"ipAddress": "10.0.0.1"}),
        ("MX", {"exchange": "mail.example.test", "preference": 10}),
        ("SRV", {"priority": 10, "weight": 20, "port": 5060, "target": "s.example.test"}),
        ("CAA", {"flags": 0, "tag": "issue", "value": "letsencrypt.org"}),
    ]:
        assert _normalize_rdata(rtype, rdata) == rdata


def test_reconcile_no_churn_on_enum_translated_types() -> None:
    """The bug this guards: desired TLSA params never equalled the
    daemon's enum-name rData, so every pass issued a delete built from
    key names the API rejects, then re-added the record. Forever."""
    desired = _record_params("TLSA", "3 1 1 " + "AB" * 32, {})
    from_daemon = _normalize_rdata(
        "TLSA",
        {
            "certificateUsage": "DANE-EE",
            "selector": "SPKI",
            "matchingType": "SHA2-256",
            "certificateAssociationData": ("AB" * 32).upper(),
        },
    )
    assert desired == from_daemon


# ── SVCB multi-value params (issue #745) ────────────────────────────────


def test_svcb_multivalue_param_is_preserved() -> None:
    """Technitium accepts a comma-joined value for a single param
    (`alpn|h2,h3`) — verified live. What it rejects is splitting into
    separate pairs. So nothing needs truncating."""
    _, _, params = _svcb_params('1 . alpn="h2,h3"')
    assert params == "alpn|h2,h3"


def test_svcb_target_root_dot_is_stripped() -> None:
    """The daemon stores the target un-dotted; leaving the root dot on
    made every SVCB/HTTPS record read as changed on every reconcile."""
    _, target, _ = _svcb_params('1 svc.example.test. alpn="h3"')
    assert target == "svc.example.test"
    # A bare apex target must survive as "." rather than becoming "".
    assert _svcb_params("1 .")[1] == "."


# ── Zone types, transfer options, TSIG, catalog (issue #743) ────────────


def _zone_bundle(**over):
    base = {
        "options": {"allow_transfer": ["none"]},
        "tsig_keys": [],
        "zones": [],
    }
    base.update(over)
    return base


def test_render_emits_every_supported_zone_type(tmp_path: Path) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    d.render(
        _zone_bundle(
            zones=[
                {"name": "p.test.", "type": "primary", "records": []},
                {"name": "s.test.", "type": "secondary", "masters": ["192.0.2.1"]},
                {"name": "st.test.", "type": "stub", "masters": ["192.0.2.1"]},
                {"name": "f.test.", "type": "forward", "forwarders": ["8.8.8.8"]},
            ]
        )
    )
    import json as _json

    payload = _json.loads((tmp_path / "rendered.new" / "zones.json").read_text())
    assert {z["zone"]: z["type"] for z in payload} == {
        "p.test": "Primary",
        "s.test": "Secondary",
        "st.test": "Stub",
        "f.test": "Forwarder",
    }


def test_render_skips_zones_that_cannot_be_created(tmp_path: Path) -> None:
    """A secondary/stub with no primary to transfer from, or a forward zone
    with no upstream, cannot be created at all — Technitium rejects the
    call. Skip them rather than fail the whole render."""
    d = TechnitiumDriver(state_dir=tmp_path)
    d.render(
        _zone_bundle(
            zones=[
                {"name": "nomaster.test.", "type": "secondary", "masters": []},
                {"name": "nofwd.test.", "type": "forward", "forwarders": []},
                {"name": "bogus.test.", "type": "not-a-zone-type"},
                {"name": "ok.test.", "type": "primary", "records": []},
            ]
        )
    )
    import json as _json

    payload = _json.loads((tmp_path / "rendered.new" / "zones.json").read_text())
    assert [z["zone"] for z in payload] == ["ok.test"]


def test_render_omits_records_for_non_primary_zones(tmp_path: Path) -> None:
    """A secondary fills itself from the transfer. Rendering records for it
    would make the reconciler delete what the daemon just pulled down."""
    d = TechnitiumDriver(state_dir=tmp_path)
    d.render(
        _zone_bundle(
            zones=[
                {
                    "name": "s.test.",
                    "type": "secondary",
                    "masters": ["192.0.2.1"],
                    "records": [{"name": "www", "type": "A", "value": "10.0.0.1"}],
                }
            ]
        )
    )
    import json as _json

    payload = _json.loads((tmp_path / "rendered.new" / "zones.json").read_text())
    assert payload[0]["records"] == []


def test_zone_options_transfer_policy_mapping() -> None:
    assert _zone_options_payload("Primary", _zone_bundle())["zoneTransfer"] == "Deny"
    assert (
        _zone_options_payload("Primary", _zone_bundle(options={"allow_transfer": []}))[
            "zoneTransfer"
        ]
        == "Deny"
    )
    assert (
        _zone_options_payload(
            "Primary", _zone_bundle(options={"allow_transfer": ["any"]})
        )["zoneTransfer"]
        == "Allow"
    )
    acl = _zone_options_payload(
        "Primary", _zone_bundle(options={"allow_transfer": ["10.0.0.0/8"]})
    )
    assert acl["zoneTransfer"] == "UseSpecifiedNetworkACL"
    assert acl["zoneTransferNetworkACL"] == ["10.0.0.0/8"]


def test_zone_options_only_for_primary() -> None:
    """A secondary transfers IN. Whether it re-serves is a separate
    decision we don't make on the operator's behalf."""
    for ztype in ("Secondary", "Stub", "Forwarder"):
        assert _zone_options_payload(ztype, _zone_bundle()) == {}


def test_tsig_key_names_track_the_bundle() -> None:
    """A Deny zone has no keys to name, and a permitted one names them all."""
    denied = _zone_options_payload("Primary", _zone_bundle())
    assert denied["zoneTransfer"] == "Deny"
    assert denied["zoneTransferTsigKeyNames"] == []

    keys = [{"name": "k1.", "secret": "s", "algorithm": "hmac-sha256"}]
    allowed = _zone_options_payload(
        "Primary", _zone_bundle(tsig_keys=keys, options={"allow_transfer": ["any"]})
    )
    assert allowed["zoneTransferTsigKeyNames"] == ["k1"]


# ── Signed-transfer fallback (issue #734) ───────────────────────────────
#
# ``allow_transfer`` defaults to ``["none"]``, so honouring it literally
# left the control plane unable to AXFR any zone — which is what the drift
# report and sync-with-servers both do. Both were broken on every install
# nobody had hand-configured.
#
# Technitium ANDs two independent gates (verified against DnsServer.cs:
# ``IsZoneTransferAllowed`` then ``IsTsigAuthenticated``), and the second
# returns "no auth needed" ONLY when the key-name set is empty. So
# ``Allow`` + non-empty ``zoneTransferTsigKeyNames`` means "any source, but
# the request MUST be signed by one of these keys" — the same posture BIND9
# renders as ``allow-transfer { key "…"; };``, and narrower than an address
# ACL rather than wider.


def test_deny_becomes_signed_allow_when_the_group_has_keys() -> None:
    """The fix: a stock ["none"] group with a key permits a SIGNED transfer."""
    keys = [{"name": "spatium-default", "secret": "s", "algorithm": "hmac-sha256"}]
    out = _zone_options_payload("Primary", _zone_bundle(tsig_keys=keys))
    assert out["zoneTransfer"] == "Allow"
    assert out["zoneTransferTsigKeyNames"] == ["spatium-default"]


def test_deny_stays_deny_without_keys() -> None:
    """No key means nothing can authenticate, so ``Allow`` would be a plain
    open-AXFR hole rather than a signed grant. Never widen without a key."""
    out = _zone_options_payload("Primary", _zone_bundle(tsig_keys=[]))
    assert out["zoneTransfer"] == "Deny"


def test_operator_network_acl_is_not_overridden_by_the_fallback() -> None:
    """An explicit ACL is a deliberate choice — keep it, and add the keys as
    the second gate rather than replacing the address restriction."""
    keys = [{"name": "k1.", "secret": "s", "algorithm": "hmac-sha256"}]
    out = _zone_options_payload(
        "Primary", _zone_bundle(tsig_keys=keys, options={"allow_transfer": ["10.0.0.0/8"]})
    )
    assert out["zoneTransfer"] == "UseSpecifiedNetworkACL"
    assert out["zoneTransferNetworkACL"] == ["10.0.0.0/8"]
    assert out["zoneTransferTsigKeyNames"] == ["k1"]


def test_removing_the_last_key_clears_the_pinned_names() -> None:
    """Technitium reads an ABSENT parameter as "leave unchanged" and an empty
    one as "clear" (upstream ``WebServiceZonesApi.cs``: ``Length == 0`` sets
    the set to null). Omitting it when the group's last key is deleted would
    strand the old names on the zone, and transfers from the permitted range
    would then fail forever, demanding a signature by a key that no longer
    exists. Always send it so the control plane stays the source of truth.
    """
    out = _zone_options_payload(
        "Primary", _zone_bundle(tsig_keys=[], options={"allow_transfer": ["10.0.0.0/8"]})
    )
    assert out["zoneTransfer"] == "UseSpecifiedNetworkACL"
    assert out["zoneTransferTsigKeyNames"] == []


def test_per_zone_allow_transfer_overrides_the_server_list() -> None:
    """``DNSZone.allow_transfer`` ships in the bundle since #734. The BIND9
    agent honours it; ignoring it here would leave it a silent no-op on
    Technitium — the same defect #734 exists to fix, one driver over."""
    out = _zone_options_payload(
        "Primary",
        _zone_bundle(options={"allow_transfer": ["any"]}),
        {"allow_transfer": ["10.0.0.0/8"]},
    )
    assert out["zoneTransfer"] == "UseSpecifiedNetworkACL"
    assert out["zoneTransferNetworkACL"] == ["10.0.0.0/8"]


def test_per_zone_none_narrows_a_permissive_server_default() -> None:
    """An override must be able to tighten, not just widen — otherwise
    "deny transfers of this one zone" is unexpressible."""
    out = _zone_options_payload(
        "Primary",
        _zone_bundle(options={"allow_transfer": ["any"]}),
        {"allow_transfer": ["none"]},
    )
    assert out["zoneTransfer"] == "Deny"


def test_null_per_zone_value_inherits_the_server_list() -> None:
    """None means inherit, matching the BIND9 agent. Treating it as an empty
    ACL would silently deny every zone that had no override."""
    out = _zone_options_payload(
        "Primary", _zone_bundle(options={"allow_transfer": ["any"]}), {"allow_transfer": None}
    )
    assert out["zoneTransfer"] == "Allow"


def test_combined_transfer_enum_matches_upstream_spelling() -> None:
    """Upstream spells the combined variant WITHOUT "Only" — unlike
    ``AllowOnlyZoneNameServers``. The set is an allow-list of values we will
    send, and Technitium silently ignores an unrecognised one, so a
    misspelling here is a value that can never be set and never reports why.
    """
    from spatium_dns_agent.drivers.technitium import _ZONE_TRANSFER_VALUES

    assert "AllowZoneNameServersAndUseSpecifiedNetworkACL" in _ZONE_TRANSFER_VALUES
    assert "AllowOnlyZoneNameServersAndUseSpecifiedNetworkACL" not in _ZONE_TRANSFER_VALUES


def test_tsig_key_names_strip_root_dot() -> None:
    """Technitium stores names un-dotted, so a dotted name would compare
    as different forever."""
    assert _tsig_key_names(
        {"tsig_keys": [{"name": "a."}, {"name": "b"}, {"name": ""}]}
    ) == ["a", "b"]


def test_ensure_zone_exists_sends_type_specific_params(tmp_path: Path) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})

    d._ensure_zone_exists("t", {"zone": "s.test", "type": "Secondary",
                                "masters": ["192.0.2.1", "192.0.2.2"]})
    assert calls[-1][3]["primaryNameServerAddresses"] == "192.0.2.1,192.0.2.2"

    d._ensure_zone_exists("t", {"zone": "f.test", "type": "Forwarder",
                                "forwarders": ["8.8.8.8", "9.9.9.9"]})
    # Technitium's Forwarder zone takes ONE upstream; extras are dropped
    # with a warning rather than silently.
    assert calls[-1][3]["forwarder"] == "8.8.8.8"
    assert "forwarders" not in calls[-1][3]


def test_apply_zone_options_refuses_unknown_transfer_value(tmp_path: Path) -> None:
    """zones/options/set answers ok for a value it doesn't recognise and
    keeps the OLD one — so an unvalidated typo silently leaves transfer at
    whatever it was, which for a zone meant to be locked down is a security
    regression no log line would report."""
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})
    d._apply_zone_options("t", "z.test", {"zoneTransfer": "Bogus"})
    assert calls == []


def test_apply_zone_options_joins_list_values(tmp_path: Path) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})
    d._apply_zone_options(
        "t",
        "z.test",
        {
            "zoneTransfer": "UseSpecifiedNetworkACL",
            "zoneTransferNetworkACL": ["10.0.0.0/8", "192.168.0.0/16"],
            "zoneTransferTsigKeyNames": ["k1"],
        },
    )
    params = calls[0][3]
    assert params["zoneTransferNetworkACL"] == "10.0.0.0/8,192.168.0.0/16"
    assert params["zoneTransferTsigKeyNames"] == "k1"


def test_sync_tsig_keys_wire_format(tmp_path: Path) -> None:
    """FLAT pipe-delimited token list read in triples — name|secret|alg|…
    Not JSON, not one pipe-joined record per key, and not name|alg|secret
    (that one fails with "TSIG algorithm is not supported", because it
    reads the secret as the algorithm)."""
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})
    d._sync_tsig_keys(
        "t",
        [
            {"name": "k1.", "secret": "s1", "algorithm": "hmac-sha256"},
            {"name": "k2", "secret": "s2", "algorithm": "HMAC-SHA512"},
        ],
    )
    assert calls[0][2] == "settings/set"
    assert calls[0][3]["tsigKeys"] == "k1|s1|hmac-sha256|k2|s2|hmac-sha512"


def test_sync_tsig_keys_drops_unsupported_algorithm(tmp_path: Path) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})
    d._sync_tsig_keys(
        "t",
        [
            {"name": "bad", "secret": "s", "algorithm": "hmac-sha3"},
            {"name": "good", "secret": "s", "algorithm": "hmac-sha256"},
        ],
    )
    assert calls[0][3]["tsigKeys"] == "good|s|hmac-sha256"


def test_get_zone_records_filters_daemon_managed_apex(tmp_path: Path) -> None:
    """Apex NS/SOA are stamped by the daemon at zone create. Left in, the
    apex NS lands in to_delete every pass, gets skipped, and is still
    counted — reporting a deletion that never happened."""
    d = TechnitiumDriver(state_dir=tmp_path)
    _install_fake_request(
        d,
        lambda *_: {
            "status": "ok",
            "response": {
                "records": [
                    {"name": "z.test", "type": "SOA", "ttl": 900, "rData": {}},
                    {"name": "z.test", "type": "NS", "ttl": 3600,
                     "rData": {"nameServer": "self."}},
                    {"name": "sub.z.test", "type": "NS", "ttl": 3600,
                     "rData": {"nameServer": "ns.other."}},
                    {"name": "www.z.test", "type": "A", "ttl": 300,
                     "rData": {"ipAddress": "10.0.0.1"}},
                ]
            },
        },
    )
    got = {(r["domain"], r["type"]) for r in d._get_zone_records("t", "z.test")}
    assert ("z.test", "SOA") not in got
    assert ("z.test", "NS") not in got
    # Off-apex NS is a real delegation and must survive.
    assert ("sub.z.test", "NS") in got
    assert ("www.z.test", "A") in got


# ── DNSSEC (issue #740) ─────────────────────────────────────────────────


_SIGNED_PROPS = {
    "status": "ok",
    "response": {
        "dnssecStatus": "SignedWithNSEC",
        "dnssecPrivateKeys": [
            {"keyTag": 34619, "keyType": "KeySigningKey", "algorithmNumber": 13,
             "state": "Published", "stateChangedOn": "2026-07-30T15:30:08Z",
             "stateReadyBy": "2026-07-30T20:05:08Z"},
            {"keyTag": 44648, "keyType": "ZoneSigningKey", "algorithmNumber": 13,
             "state": "Active", "stateChangedOn": "2026-07-30T15:30:08Z"},
        ],
    },
}
_SIGNED_RECORDS = {
    "status": "ok",
    "response": {
        "records": [
            {"name": "z.test", "type": "DNSKEY", "ttl": 3600, "rData": {
                "computedKeyTag": 34619, "algorithmNumber": 13,
                "computedDigests": [
                    {"digestType": "SHA256", "digest": "DD98"},
                    {"digestType": "SHA384", "digest": "309D"},
                ]}},
            # ZSK carries no computedDigests — a DS attests the KSK only.
            {"name": "z.test", "type": "DNSKEY", "ttl": 3600, "rData": {
                "computedKeyTag": 44648, "algorithmNumber": 13}},
        ]
    },
}


def _dnssec_responder(path, params, n):
    if path == "zones/dnssec/properties/get":
        return _SIGNED_PROPS
    if path == "zones/records/get":
        return _SIGNED_RECORDS
    return {"status": "ok"}


def test_collect_dnssec_state_builds_ds_presentation_format(tmp_path: Path) -> None:
    """DS presentation form is ``<keyTag> <algorithm> <digestType> <digest>``.
    Technitium reports the digest TYPE by name, so it has to be mapped back
    to its RFC 4034 number."""
    d = TechnitiumDriver(state_dir=tmp_path)
    _install_fake_request(d, _dnssec_responder)
    state = d._collect_dnssec_state("t", "z.test")
    assert state["ds_records"] == [
        "34619 13 2 DD98",
        "34619 13 4 309D",
    ]


def test_collect_dnssec_state_reports_per_key_state(tmp_path: Path) -> None:
    """Unlike the PowerDNS agent, Technitium exposes per-key state, and the
    control plane already models it (#49's DNSKey rows)."""
    d = TechnitiumDriver(state_dir=tmp_path)
    _install_fake_request(d, _dnssec_responder)
    keys = {k["key_tag"]: k for k in d._collect_dnssec_state("t", "z.test")["keys"]}
    assert keys[34619]["key_type"] == "ksk"
    assert keys[44648]["key_type"] == "zsk"
    assert keys[34619]["state"] == "published"
    assert keys[44648]["state"] == "active"
    assert keys[34619]["algorithm"] == 13
    assert keys[34619]["timing"]["state_ready_by"] == "2026-07-30T20:05:08Z"


def test_dnssec_sign_is_idempotent(tmp_path: Path) -> None:
    """Repeated 'Sign zone' clicks should converge on signed, not error."""
    d = TechnitiumDriver(state_dir=tmp_path)

    def responder(path, params, n):
        if path == "zones/dnssec/sign":
            return {"status": "error", "errorMessage":
                    "Cannot sign zone: the zone is already signed."}
        return _dnssec_responder(path, params, n)

    _install_fake_request(d, responder)
    state = d._dnssec_sign("t", "z.test")
    assert state["ds_records"]


def test_dnssec_sign_raises_on_real_failure(tmp_path: Path) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    _install_fake_request(
        d, lambda *_: {"status": "error", "errorMessage": "Access denied."}
    )
    try:
        d._dnssec_sign("t", "z.test")
    except RuntimeError as exc:
        assert "Access denied" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected RuntimeError")


def test_dnssec_unsign_clears_ds_and_keys(tmp_path: Path) -> None:
    """A stale DS left on display is one the parent zone no longer trusts."""
    d = TechnitiumDriver(state_dir=tmp_path)
    _install_fake_request(d, lambda *_: {"status": "ok"})
    state = d._dnssec_unsign("t", "z.test")
    assert state == {"zone_name": "z.test", "ds_records": [], "keys": []}


def test_apply_record_op_routes_dnssec_ops(tmp_path: Path) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(d)
    _install_fake_request(d, _dnssec_responder)
    out = d.apply_record_op(
        {"zone_name": "z.test.", "op": "dnssec_sign",
         "record": {"name": "@", "type": "DNSSEC_OP"}}
    )
    assert out is not None and out["dnssec_state"]["ds_records"]


def test_get_zone_records_filters_signing_artefacts(tmp_path: Path) -> None:
    """A signed zone serves DNSKEY/RRSIG/NSEC* that no bundle describes.
    Left unfiltered, the reconciler tries to delete the zone's own
    signatures on every pass."""
    d = TechnitiumDriver(state_dir=tmp_path)
    _install_fake_request(
        d,
        lambda *_: {
            "status": "ok",
            "response": {
                "records": [
                    {"name": "z.test", "type": "DNSKEY", "ttl": 3600, "rData": {}},
                    {"name": "z.test", "type": "RRSIG", "ttl": 3600, "rData": {}},
                    {"name": "z.test", "type": "NSEC", "ttl": 3600, "rData": {}},
                    {"name": "z.test", "type": "NSEC3PARAM", "ttl": 3600, "rData": {}},
                    {"name": "www.z.test", "type": "A", "ttl": 300,
                     "rData": {"ipAddress": "10.0.0.1"}},
                ]
            },
        },
    )
    got = d._get_zone_records("t", "z.test")
    assert [r["type"] for r in got] == ["A"]


# ── Encrypted transports (issue #741) ───────────────────────────────────


def _self_signed_pem() -> tuple[str, str]:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dns.test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2026, 1, 1))
        .not_valid_after(datetime.datetime(2027, 1, 1))
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )


def test_write_tls_cert_emits_loadable_pkcs12(tmp_path: Path) -> None:
    """Technitium takes the cert as a PKCS #12 file path; handing it PEM
    fails with "must be PKCS #12 formatted". The bundle ships PEM, so the
    conversion happens here."""
    from cryptography.hazmat.primitives.serialization import pkcs12

    cert_pem, key_pem = _self_signed_pem()
    d = TechnitiumDriver(state_dir=tmp_path)
    path = d._write_tls_cert({"name": "spatium", "cert_pem": cert_pem, "key_pem": key_pem})
    assert path is not None
    blob = Path(path).read_bytes()
    # Round-trips through a real PKCS#12 loader, so this is not just "some
    # bytes were written".
    key, cert, _ = pkcs12.load_key_and_certificates(blob, None)
    assert key is not None and cert is not None
    # Embeds a private key — must not be world-readable.
    assert oct(Path(path).stat().st_mode)[-3:] == "600"


def test_write_tls_cert_returns_none_on_garbage(tmp_path: Path) -> None:
    """An unreadable cert must degrade to Do53, never take the daemon
    down — the whole point of #50's 'every path degrades to Do53'."""
    d = TechnitiumDriver(state_dir=tmp_path)
    assert d._write_tls_cert({"cert_pem": "not a cert", "key_pem": "nope"}) is None
    assert d._write_tls_cert({"cert_pem": "", "key_pem": ""}) is None


def test_transport_settings_force_listeners_off_without_cert(tmp_path: Path) -> None:
    """Technitium accepts enableDnsOverTls=true even when the cert path in
    the SAME call is rejected, so a listener must never be enabled without
    a cert. Crucially it must also be actively turned OFF: bailing out
    would leave an already-enabled listener up on a stale certificate,
    which is the opposite of "every path degrades to Do53"."""
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})
    d._apply_transport_settings("t", {"dot_enabled": True, "dot_port": 853}, None)
    assert len(calls) == 1
    params = calls[0][3]
    assert params["enableDnsOverTls"] == "false"
    assert params["enableDnsOverHttps"] == "false"
    assert params["enableDnsOverQuic"] == "false"
    # No port is pinned for a listener being turned off.
    assert "dnsOverTlsPort" not in params


def test_transport_settings_send_cert_path_before_enabling(tmp_path: Path) -> None:
    cert_pem, key_pem = _self_signed_pem()
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})
    d._apply_transport_settings(
        "t",
        {"dot_enabled": True, "dot_port": 8853, "doq_enabled": True, "doq_port": 8853},
        {"name": "s", "cert_pem": cert_pem, "key_pem": key_pem},
    )
    assert "dnsTlsCertificatePath" in calls[0][3]
    enable = calls[1][3]
    assert enable["enableDnsOverTls"] == "true"
    assert enable["dnsOverTlsPort"] == 8853
    # DoT and DoQ may share a port number: one is TCP, the other UDP.
    assert enable["enableDnsOverQuic"] == "true"
    assert enable["dnsOverQuicPort"] == 8853
    assert enable["enableDnsOverHttps"] == "false"


def test_transport_settings_abort_when_cert_path_rejected(tmp_path: Path) -> None:
    cert_pem, key_pem = _self_signed_pem()
    d = TechnitiumDriver(state_dir=tmp_path)

    def responder(path, params, n):
        if "dnsTlsCertificatePath" in params:
            return {"status": "error", "errorMessage": "file does not exists"}
        return {"status": "ok"}

    calls = _install_fake_request(d, responder)
    d._apply_transport_settings(
        "t", {"dot_enabled": True}, {"cert_pem": cert_pem, "key_pem": key_pem}
    )
    # Cert attempt, then an explicit disable — not a bail-out that would
    # strand an already-running listener on a stale cert.
    assert [c[2] for c in calls] == ["settings/set", "settings/set"]
    assert calls[1][3]["enableDnsOverTls"] == "false"


def test_forwarders_and_protocol_are_sent_together(tmp_path: Path) -> None:
    """forwarderProtocol is silently ignored unless forwarders is set in
    the SAME call — verified live: setting it alone returns ok and leaves
    the protocol at Udp."""
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})
    d._apply_forwarders(
        "t", {"forwarders": ["8.8.8.8", "8.8.4.4"], "forward_transport": "do53"}
    )
    params = calls[0][3]
    assert params["forwarders"] == "8.8.8.8,8.8.4.4"
    assert params["forwarderProtocol"] == "Udp"


def test_forwarders_substitute_hostname_for_encrypted_transports(tmp_path: Path) -> None:
    """Technitium rejects an IP for DoT/DoH/DoQ ("Address must be a domain
    name") — there'd be no name to validate the upstream cert against. The
    neutral model carries IPs plus one hostname, so the hostname wins."""
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})
    d._apply_forwarders(
        "t",
        {
            "forwarders": ["1.1.1.1", "1.0.0.1"],
            "forward_transport": "tls",
            "forward_tls_hostname": "cloudflare-dns.com",
        },
    )
    assert calls[0][3]["forwarders"] == "cloudflare-dns.com"
    assert calls[0][3]["forwarderProtocol"] == "Tls"


def test_forwarders_refuse_encrypted_transport_without_hostname(tmp_path: Path) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})
    d._apply_forwarders("t", {"forwarders": ["1.1.1.1"], "forward_transport": "https"})
    assert calls == []


def test_forwarders_map_every_transport(tmp_path: Path) -> None:
    for transport, expected in [
        ("do53", "Udp"), ("tls", "Tls"), ("https", "Https"), ("quic", "Quic")
    ]:
        d = TechnitiumDriver(state_dir=tmp_path)
        calls = _install_fake_request(d, lambda *_: {"status": "ok"})
        d._apply_forwarders(
            "t",
            {"forwarders": ["1.1.1.1"], "forward_transport": transport,
             "forward_tls_hostname": "dns.example"},
        )
        assert calls[0][3]["forwarderProtocol"] == expected


# ── Code-review fixes ───────────────────────────────────────────────────


def test_reconcile_counts_only_real_deletes(tmp_path: Path) -> None:
    """"no such record" means it was already gone — a no-op, not a delete.
    Counting it reports churn that never happened, which is the same
    phantom the apex-NS filter exists to prevent."""
    d = TechnitiumDriver(state_dir=tmp_path)

    def responder(path, params, n):
        if path == "zones/records/get":
            return {"status": "ok", "response": {"records": [
                {"name": "gone.z.test", "type": "A", "ttl": 300,
                 "rData": {"ipAddress": "10.0.0.9"}}]}}
        if path == "zones/records/delete":
            return {"status": "error", "errorMessage": "No such record exists."}
        return {"status": "ok"}

    _install_fake_request(d, responder)
    import structlog

    cap = structlog.testing.LogCapture()
    structlog.configure(processors=[cap])
    try:
        d._reconcile_zones("t", [{"zone": "z.test", "type": "Primary", "records": []}])
    finally:
        structlog.reset_defaults()
    reconciled = [e for e in cap.entries if e["event"] == "technitium_zone_reconciled"]
    # The delete was a no-op, so there is nothing to report at all.
    assert reconciled == []


def test_reconcile_counts_only_real_adds(tmp_path: Path) -> None:
    """Same reasoning for "already exists" on the add side."""
    d = TechnitiumDriver(state_dir=tmp_path)

    def responder(path, params, n):
        if path == "zones/records/get":
            return {"status": "ok", "response": {"records": []}}
        if path == "zones/records/add":
            return {"status": "error", "errorMessage": "Record already exists."}
        return {"status": "ok"}

    _install_fake_request(d, responder)
    import structlog

    cap = structlog.testing.LogCapture()
    structlog.configure(processors=[cap])
    try:
        d._reconcile_zones(
            "t",
            [{"zone": "z.test", "type": "Primary", "records": [
                {"domain": "www.z.test", "type": "A", "ttl": 300,
                 "ipAddress": "10.0.0.1"}]}],
        )
    finally:
        structlog.reset_defaults()
    assert [e for e in cap.entries if e["event"] == "technitium_zone_reconciled"] == []


def test_forwarders_cleared_when_bundle_has_none(tmp_path: Path) -> None:
    """Removing every forwarder must actually clear them. An early return
    would leave the daemon resolving through the old upstreams forever,
    because nothing else touches the setting."""
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})
    d._apply_forwarders("t", {"forwarders": [], "forward_transport": "do53"})
    assert calls[0][3]["forwarders"] == ""
    assert calls[0][3]["forwarderProtocol"] == "Udp"


def test_catalog_consumer_creates_secondary_catalog_zone(tmp_path: Path) -> None:
    """The catalog zone is shipped as a catalog block, not a zone row, so
    a consumer that doesn't create it here does nothing at all."""
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})
    d._apply_catalog(
        "t",
        {"mode": "consumer", "zone_name": "cat.test.", "producer_addr": "192.0.2.9"},
        [{"zone": "p.test", "type": "Primary"}],
    )
    assert calls[0][2] == "zones/create"
    assert calls[0][3]["type"] == "SecondaryCatalog"
    assert calls[0][3]["primaryNameServerAddresses"] == "192.0.2.9"
    # A consumer must NOT stamp membership onto its own primaries.
    assert not [c for c in calls if c[2] == "zones/options/set"]


def test_catalog_membership_cleared_when_disabled(tmp_path: Path) -> None:
    """Turning catalog zones off has to un-enrol the members; nothing else
    ever touches the option."""
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})
    d._apply_catalog("t", None, [{"zone": "p.test", "type": "Primary"}])
    opt = [c for c in calls if c[2] == "zones/options/set"]
    assert opt and opt[0][3]["catalog"] == ""


# ── Blocklists (issue #744) ─────────────────────────────────────────────


def _bl(entries, exceptions=()):
    return {"blocklists": [{"exceptions": list(exceptions), "entries": entries}]}


def test_blocking_payload_splits_block_from_allow() -> None:
    """Technitium's allowed set is exactly an RPZ passthru, so passthru
    entries and each list's exceptions both land there."""
    out = _blocking_payload(
        _bl(
            [
                {"domain": "ads.example.test", "action": "block", "block_mode": "nxdomain"},
                {"domain": "pass.example.test", "action": "block", "block_mode": "passthru"},
                {"domain": "allow.example.test", "action": "allow", "block_mode": "nxdomain"},
            ],
            ["exc.example.test"],
        )
    )
    assert out["blocked"] == ["ads.example.test"]
    assert out["allowed"] == [
        "allow.example.test",
        "exc.example.test",
        "pass.example.test",
    ]
    assert out["enabled"] is True


def test_blocking_payload_disabled_when_nothing_blocked() -> None:
    assert _blocking_payload({"blocklists": []})["enabled"] is False
    passthru_only = _blocking_payload(
        _bl([{"domain": "a.test", "action": "block", "block_mode": "passthru"}])
    )
    assert passthru_only["enabled"] is False


def test_blocking_payload_prefers_custom_address_when_modes_disagree() -> None:
    """One server-wide blocking type has to cover every entry. NxDomain
    would silently drop an operator's sinkhole, so the address-answering
    mode wins."""
    out = _blocking_payload(
        _bl(
            [
                {"domain": "a.test", "action": "block", "block_mode": "nxdomain"},
                {"domain": "b.test", "action": "block", "block_mode": "sinkhole",
                 "target": "10.0.0.1"},
            ]
        )
    )
    assert out["blocking_type"] == "CustomAddress"
    assert out["custom_addresses"] == ["10.0.0.1"]


def test_blocking_payload_collapses_per_view_lists() -> None:
    """Technitium's native blocking is server-wide with no view concept,
    and the driver declines views outright — so collapsing is the honest
    reading rather than applying one view's list to every client."""
    out = _blocking_payload(
        {
            "blocklists": [
                {"view_name": "internal", "exceptions": [],
                 "entries": [{"domain": "a.test", "action": "block",
                              "block_mode": "nxdomain"}]},
                {"view_name": None, "exceptions": [],
                 "entries": [{"domain": "b.test", "action": "block",
                              "block_mode": "nxdomain"}]},
            ]
        }
    )
    assert out["blocked"] == ["a.test", "b.test"]


def _blocking_responder(live: dict[str, str] | None = None):
    """``{kind}/export`` answers the plain-text ``live`` set (empty by
    default); everything else answers ok."""
    live = live or {}

    def responder(path, params, n):
        kind, _, op = path.partition("/")
        if op == "export":
            return live.get(kind, "")
        return {"status": "ok"}

    return responder


def test_apply_blocking_flushes_before_rewriting(tmp_path: Path) -> None:
    """A set that differs is flushed, then imported."""
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(d, _blocking_responder())
    d._apply_blocking(
        "t",
        {"enabled": True, "blocked": ["a.test"], "allowed": ["b.test"],
         "blocking_type": "NxDomain", "custom_addresses": []},
    )
    paths = [c[2] for c in calls]
    assert paths[0] == "settings/set"
    assert paths.index("blocked/flush") < paths.index("blocked/import")
    assert paths.index("allowed/flush") < paths.index("allowed/import")
    # #1425: never one call per domain.
    assert "blocked/add" not in paths and "allowed/add" not in paths


def test_apply_blocking_imports_in_chunks_not_one_call_per_domain(tmp_path: Path) -> None:
    """``blocked/add`` rewrote Technitium's zone file on every call, so a 16k
    list took ~30 minutes (#1425). ``blocked/import`` takes a comma-separated
    list and saves once per call."""
    from spatium_dns_agent.drivers.technitium import _BLOCKING_IMPORT_CHUNK

    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(d, _blocking_responder())
    domains = [f"d{i:05d}.test" for i in range(12001)]
    d._apply_blocking(
        "t", {"enabled": True, "blocked": domains, "blocking_type": "NxDomain"}
    )
    imports = [c for c in calls if c[2] == "blocked/import"]
    assert len(imports) == -(-len(domains) // _BLOCKING_IMPORT_CHUNK)
    sent = [x for c in imports for x in c[3]["blockedZones"].split(",")]
    assert sorted(sent) == sorted(domains)
    assert all(c[1] == "POST" for c in imports)  # form body, not a URL


def test_apply_blocking_leaves_an_unchanged_set_alone(tmp_path: Path) -> None:
    """A structural apply that did not touch a blocklist rewrites nothing:
    no flush, so no window without blocking (#1425)."""
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(
        d, _blocking_responder({"blocked": "b.test\na.test\n", "allowed": "c.test\n"})
    )
    d._apply_blocking(
        "t",
        {"enabled": True, "blocked": ["a.test", "B.test."], "allowed": ["c.test"],
         "blocking_type": "NxDomain"},
    )
    paths = [c[2] for c in calls]
    assert not any(p.endswith(("/flush", "/import")) for p in paths)


def test_apply_blocking_rewrites_only_the_set_that_changed(tmp_path: Path) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(
        d, _blocking_responder({"blocked": "a.test\n", "allowed": "old.test\n"})
    )
    d._apply_blocking(
        "t",
        {"enabled": True, "blocked": ["a.test"], "allowed": ["new.test"],
         "blocking_type": "NxDomain"},
    )
    paths = [c[2] for c in calls]
    assert "blocked/flush" not in paths
    assert paths.index("allowed/flush") < paths.index("allowed/import")


def test_apply_blocking_rewrites_when_the_live_set_is_unreadable(tmp_path: Path) -> None:
    """An error answer to export is not trusted as "already matches"."""
    d = TechnitiumDriver(state_dir=tmp_path)

    def responder(path, params, n):
        if path.endswith("/export"):
            return {"status": "error", "errorMessage": "Access was denied."}
        return {"status": "ok"}

    calls = _install_fake_request(d, responder)
    d._apply_blocking("t", {"enabled": True, "blocked": ["a.test"], "blocking_type": "NxDomain"})
    assert "blocked/import" in [c[2] for c in calls]


def test_apply_blocking_empty_list_still_clears_the_daemon(tmp_path: Path) -> None:
    """An emptied list has to actually clear on the daemon."""
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(d, _blocking_responder({"blocked": "stale.test\n"}))
    d._apply_blocking("t", {"enabled": True, "blocked": [], "blocking_type": "NxDomain"})
    paths = [c[2] for c in calls]
    assert "blocked/flush" in paths
    assert "blocked/import" not in paths


def test_idn_entries_compare_in_their_ascii_form() -> None:
    """Technitium stores and exports the IDNA form, so comparing the Unicode
    spelling would read an IDN entry as changed on every apply."""
    from spatium_dns_agent.drivers.technitium import _ascii_domain

    assert _ascii_domain("Bücher.Test.") == "xn--bcher-kva.test"
    assert _ascii_domain("plain.test") == "plain.test"


def test_apply_blocking_rejects_unknown_blocking_type(tmp_path: Path) -> None:
    """blockingType silently ignores values it doesn't recognise — same
    trap as zoneTransfer — so it is validated before sending."""
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})
    d._apply_blocking("t", {"enabled": True, "blocked": [], "blocking_type": "Bogus"})
    assert calls == []


def test_apply_blocking_falls_back_when_custom_address_missing(tmp_path: Path) -> None:
    """CustomAddress with nothing to answer would blackhole the name in a
    way the operator never asked for."""
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})
    d._apply_blocking(
        "t",
        {"enabled": True, "blocked": ["a.test"], "blocking_type": "CustomAddress",
         "custom_addresses": []},
    )
    assert calls[0][3]["blockingType"] == "NxDomain"


# ── Second code-review pass ─────────────────────────────────────────────


def test_master_port_translated_to_technitium_form() -> None:
    """SpatiumDDI validates masters as BIND's ``ip@port``; Technitium
    rejects the ``@`` outright ("invalid character [64]") and wants
    ``ip:port``. Untranslated, the zone create fails every pass."""
    from spatium_dns_agent.drivers.technitium import _technitium_master

    assert _technitium_master("192.0.2.1") == "192.0.2.1"
    assert _technitium_master("192.0.2.1@5353") == "192.0.2.1:5353"
    assert _technitium_master(" 192.0.2.1 ") == "192.0.2.1"


def test_existing_zone_upstream_is_reapplied(tmp_path: Path) -> None:
    """zones/create is a no-op once the zone exists, and it is what
    carries the upstream — so retargeting a secondary would otherwise be
    a permanent silent no-op."""
    d = TechnitiumDriver(state_dir=tmp_path)

    def responder(path, params, n):
        if path == "zones/create":
            return {"status": "error", "errorMessage": "Zone already exists."}
        return {"status": "ok"}

    calls = _install_fake_request(d, responder)
    d._ensure_zone_exists(
        "t", {"zone": "s.test", "type": "Secondary", "masters": ["192.0.2.9@5353"]}
    )
    opts = [c for c in calls if c[2] == "zones/options/set"]
    assert opts and opts[0][3]["primaryNameServerAddresses"] == "192.0.2.9:5353"


def test_empty_tsig_key_set_is_pushed(tmp_path: Path) -> None:
    """A revoked key that is never cleared stays installed and signed
    transfers keep working — same bug class as the forwarders path."""
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})
    d._sync_tsig_keys("t", [])
    assert calls and calls[0][3]["tsigKeys"] == ""


def test_doh_path_override_warns_because_it_is_unsupported(tmp_path: Path) -> None:
    """Technitium serves DoH on a fixed path and exposes no setting for
    it, so an operator who changed doh_path would be handed a URL the
    daemon never answers on."""
    cert_pem, key_pem = _self_signed_pem()
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _install_fake_request(d, lambda *_: {"status": "ok"})
    d._apply_transport_settings(
        "t",
        {"doh_enabled": True, "doh_port": 8443, "doh_path": "/custom"},
        {"cert_pem": cert_pem, "key_pem": key_pem},
    )
    # The path is not sent — there is no parameter for it.
    assert not any("Path" in k and k != "dnsTlsCertificatePath"
                   for c in calls for k in c[3])


def test_blocking_payload_drops_redirects_instead_of_allowing_them() -> None:
    """Redirect entries used to fall through into the ALLOW set.

    ``action != "block"`` sent them to the allowed branch, so a
    SafeSearch rewrite for ``www.google.com`` became "never block
    www.google.com" — a silent inversion of the operator's intent.
    Technitium's native blocking has no per-domain rewrite (its custom
    address is server-wide), so the honest answer is to enforce nothing
    and say so. Issue #878.
    """
    out = _blocking_payload(
        _bl(
            [
                {"domain": "ads.example.test", "action": "block",
                 "block_mode": "nxdomain"},
                {"domain": "www.google.com", "action": "redirect",
                 "block_mode": "nxdomain",
                 "target": "forcesafesearch.google.com"},
            ]
        )
    )
    assert out["blocked"] == ["ads.example.test"]
    assert "www.google.com" not in out["allowed"]
    assert out["allowed"] == []
    # …and the rewrite target must not leak into the server-wide
    # custom-address setting, where it would apply to every blocked name.
    assert out["custom_addresses"] == []


# ── Zone apex: SOA + NS from the zone's own settings ───────────────────
#
# Technitium writes its own apex at zone create: one NS and an SOA MNAME
# naming the server's host name (the pod name, under the DNS VIP) and a
# placeholder RNAME. The SOA-update semantics below were checked against a
# live technitium/dns-server:15.4.0: ``zones/records/update`` for type SOA
# refuses a call without ``serial`` and stores current + 1, takes the RNAME
# in either SOA or address form and reads it back as an address, and
# ``zones/records/get`` without ``listZone`` returns the apex records only.


def _render_zone(tmp_path: Path, zone: dict[str, Any]) -> dict[str, Any]:
    import json as _json

    d = TechnitiumDriver(state_dir=tmp_path)
    d.render(_zone_bundle(zones=[zone]))
    return _json.loads((tmp_path / "rendered.new" / "zones.json").read_text())[0]


def test_render_apex_from_primary_ns_and_admin_email(tmp_path: Path) -> None:
    out = _render_zone(
        tmp_path,
        {
            "name": "home.example.test.",
            "type": "primary",
            "ttl": 300,
            "primary_ns": "ns.home.example.test.",
            "admin_email": "hostmaster.example.test.",
            "refresh": 3600,
            "retry": 600,
            "expire": 604800,
            "minimum": 300,
            "records": [{"name": "ns", "type": "A", "value": "192.0.2.53"}],
        },
    )
    assert out["apex"] == {
        "ns": ["ns.home.example.test"],
        "soa": {
            "primaryNameServer": "ns.home.example.test",
            "responsiblePerson": "hostmaster@example.test",
            "refresh": 3600,
            "retry": 600,
            "expire": 604800,
            "minimum": 300,
        },
        "ttl": 300,
    }


def test_render_apex_declared_ns_records_win(tmp_path: Path) -> None:
    """The zone's own apex NS records are the NS set (#1153's precedence);
    a relative target is relative to the zone, as in a zone file."""
    out = _render_zone(
        tmp_path,
        {
            "name": "example.test.",
            "type": "primary",
            "primary_ns": "ns0.elsewhere.test",
            "records": [
                {"name": "@", "type": "NS", "value": "ns1.example.test."},
                {"name": "@", "type": "NS", "value": "ns2"},
                {"name": "sub", "type": "NS", "value": "ns.sub.example.test."},
            ],
        },
    )
    assert out["apex"]["ns"] == ["ns1.example.test", "ns2.example.test"]
    # MNAME is still the Primary NS when one is set.
    assert out["apex"]["soa"]["primaryNameServer"] == "ns0.elsewhere.test"
    # The delegation stays an ordinary record.
    assert [r["domain"] for r in out["records"] if r["type"] == "NS"] == ["sub.example.test"]


def test_render_apex_absent_when_zone_sets_nothing(tmp_path: Path) -> None:
    """A zone with no Primary NS, Admin Email or timers keeps the daemon's
    apex untouched — the behaviour before the apex was managed."""
    out = _render_zone(
        tmp_path, {"name": "plain.test.", "type": "primary", "ttl": 3600, "records": []}
    )
    assert "apex" not in out


def test_render_apex_only_for_primary_zones(tmp_path: Path) -> None:
    """A secondary's apex comes from the transfer, so it is not ours."""
    out = _render_zone(
        tmp_path,
        {
            "name": "s.test.",
            "type": "secondary",
            "masters": ["192.0.2.1"],
            "primary_ns": "ns.s.test.",
        },
    )
    assert "apex" not in out


def test_render_apex_ignores_unusable_values(tmp_path: Path) -> None:
    out = _render_zone(
        tmp_path,
        {
            "name": "x.test.",
            "type": "primary",
            "primary_ns": "  ",
            "admin_email": "nodots",
            "minimum": True,  # a bool is not a timer
            "refresh": -1,
        },
    )
    assert "apex" not in out


def test_responsible_person_forms() -> None:
    from spatium_dns_agent.drivers.technitium import _responsible_person

    assert _responsible_person("hostmaster.example.test.") == "hostmaster@example.test"
    assert _responsible_person("first\\.last.example.test.") == "first.last@example.test"
    assert _responsible_person("Admin@Example.test") == "admin@example.test"
    assert _responsible_person("nodots") is None
    assert _responsible_person("") is None
    assert _responsible_person(None) is None


def _apex_reconcile(
    driver: TechnitiumDriver,
    apex_records: list[dict[str, Any]],
    apex: dict[str, Any],
    fail_paths: set[str] = frozenset(),  # type: ignore[assignment]
) -> list[tuple[str, str, str, dict[str, Any]]]:
    def _responder(path: str, params: dict[str, Any], n: int) -> dict[str, Any]:
        if path == "zones/records/get":
            if params.get("listZone") == "true":
                return {"status": "ok", "response": {"records": []}}
            return {"status": "ok", "response": {"records": apex_records}}
        if path in fail_paths:
            return {"status": "error", "errorMessage": "boom"}
        return {"status": "ok"}

    calls = _install_fake_request(driver, _responder)
    driver._reconcile_zones(
        "tok-1", [{"zone": "example.test", "type": "Primary", "records": [], "apex": apex}]
    )
    return calls


_DAEMON_APEX = [
    {"name": "example.test", "type": "NS", "ttl": 14400,
     "rData": {"nameServer": "dns-technitium-snw7c"}},
    {"name": "example.test", "type": "SOA", "ttl": 900,
     "rData": {"primaryNameServer": "dns-technitium-snw7c",
               "responsiblePerson": "hostadmin@example.test", "serial": 41,
               "refresh": 900, "retry": 300, "expire": 604800, "minimum": 900}},
]

_WANTED_APEX = {
    "ns": ["ns.example.test"],
    "soa": {"primaryNameServer": "ns.example.test",
            "responsiblePerson": "hostmaster@example.test",
            "refresh": 3600, "retry": 600, "expire": 604800, "minimum": 300},
    "ttl": 300,
}


def test_reconcile_apex_rewrites_daemon_soa_and_ns(tmp_path: Path) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _apex_reconcile(d, _DAEMON_APEX, _WANTED_APEX)
    writes = [(c[2], c[3]) for c in calls if c[2] != "zones/create" and c[2] != "zones/records/get"]

    soa = [p for path, p in writes if path == "zones/records/update"]
    assert len(soa) == 1
    assert soa[0]["type"] == "SOA"
    assert soa[0]["serial"] == 41  # the current serial, which the daemon requires
    assert soa[0]["primaryNameServer"] == "ns.example.test"
    assert soa[0]["responsiblePerson"] == "hostmaster@example.test"
    assert (soa[0]["refresh"], soa[0]["retry"], soa[0]["minimum"], soa[0]["ttl"]) == (
        3600, 600, 300, 300)

    ns_ops = [(path, p["nameServer"]) for path, p in writes if p.get("type") == "NS"]
    # The new name server goes in before the daemon's own comes out.
    assert ns_ops == [
        ("zones/records/add", "ns.example.test"),
        ("zones/records/delete", "dns-technitium-snw7c"),
    ]


def test_reconcile_apex_is_a_noop_when_converged(tmp_path: Path) -> None:
    """Every SOA write bumps the serial, so a converged apex must cost one
    read and nothing else."""
    d = TechnitiumDriver(state_dir=tmp_path)
    converged = [
        {"name": "example.test", "type": "NS", "ttl": 300,
         "rData": {"nameServer": "ns.example.test"}},
        {"name": "example.test", "type": "SOA", "ttl": 300,
         "rData": {"primaryNameServer": "ns.example.test",
                   "responsiblePerson": "hostmaster@example.test", "serial": 42,
                   "refresh": 3600, "retry": 600, "expire": 604800, "minimum": 300}},
    ]
    calls = _apex_reconcile(d, converged, _WANTED_APEX)
    assert [c[2] for c in calls if c[2] != "zones/create"] == [
        "zones/records/get",  # the zone's records
        "zones/records/get",  # its apex
    ]


def test_reconcile_apex_keeps_old_ns_when_the_add_fails(tmp_path: Path) -> None:
    """Never leave the zone without a name server."""
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _apex_reconcile(d, _DAEMON_APEX, _WANTED_APEX, fail_paths={"zones/records/add"})
    assert "zones/records/delete" not in [c[2] for c in calls]


def test_reconcile_apex_untouched_without_apex(tmp_path: Path) -> None:
    """No ``apex`` in the payload (an older render, or a zone that sets
    nothing): the daemon's own SOA and NS are not even read."""
    d = TechnitiumDriver(state_dir=tmp_path)
    calls = _apex_reconcile(d, _DAEMON_APEX, None)  # type: ignore[arg-type]
    assert [c[2] for c in calls if c[2] != "zones/create"] == ["zones/records/get"]
    assert [c[3].get("listZone") for c in calls if c[2] == "zones/records/get"] == ["true"]
