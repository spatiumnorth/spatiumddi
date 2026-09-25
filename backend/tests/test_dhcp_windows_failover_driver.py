"""#1110 — the Windows DHCP driver's failover reads and scope-presence guards.

The failover read and the live probe both hand their answers to code that
turns them into write decisions, so the parsers are held to one rule above
all: an answer that cannot be read must not become "no relationships" or
"the scope is not here". Both of those are answers the write-through acts
on — the first by refusing less than it should, the second by writing to
the wrong members.

The PowerShell shapes here are the ones ``ConvertTo-Json`` produces for the
envelopes the driver builds. They have NOT yet been captured from a live
Windows failover pair; the cases below are the documented shapes plus the
serialisation quirks Windows PowerShell 5.1 is known for.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from app.drivers._winrm import MAX_ENCODED_COMMAND, encoded_command_len
from app.drivers.dhcp import windows
from app.drivers.dhcp.windows import (
    _ABSENT_TOKEN,
    _PS_LIST_FAILOVER,
    _as_list,
    _parse_failover,
    _parse_probe,
    _ps_probe_scopes,
)


def _rel(**overrides: Any) -> dict[str, Any]:
    base = {
        "name": "dhcp1-dhcp2",
        "partner_server": "dhcp2.corp.example",
        "mode": "LoadBalance",
        "server_role": "",
        "state": "Normal",
        "load_balance_percent": 50,
        "reserve_percent": 0,
        "max_client_lead_time_seconds": 3600,
        "state_switch_interval_seconds": None,
        "auto_state_transition": False,
        "enable_auth": True,
        "scope_ids": ["10.1.2.0", "10.1.3.0"],
    }
    base.update(overrides)
    return base


def _failover(rels: Any, *, ok: bool = True, error: str | None = None, code: int | None = None):
    return {"ok": ok, "error": error, "error_code": code, "relationships": rels}


# ── failover read ─────────────────────────────────────────────────────


def test_failover_parse_shapes_a_relationship() -> None:
    out = _parse_failover(json.dumps(_failover([_rel()])))
    assert out["ok"] is True
    assert out["error"] is None
    (rel,) = out["relationships"]
    assert rel["name"] == "dhcp1-dhcp2"
    assert rel["partner_server"] == "dhcp2.corp.example"
    assert rel["mode"] == "LoadBalance"
    # ``[string]$null`` comes back as "" — that is "not reported", not a role.
    assert rel["server_role"] is None
    assert rel["load_balance_percent"] == 50
    assert rel["max_client_lead_time_seconds"] == 3600
    assert rel["state_switch_interval_seconds"] is None
    assert rel["enable_auth"] is True
    assert rel["scope_ids"] == ["10.1.2.0", "10.1.3.0"]


def test_failover_parse_hot_standby_role() -> None:
    out = _parse_failover(
        json.dumps(_failover([_rel(mode="HotStandby", server_role="Standby", reserve_percent=5)]))
    )
    (rel,) = out["relationships"]
    assert rel["mode"] == "HotStandby"
    assert rel["server_role"] == "Standby"
    assert rel["reserve_percent"] == 5


@pytest.mark.parametrize(
    "scope_ids",
    [
        "10.1.2.0",  # one element, unrolled to a bare scalar
        ["10.1.2.0"],
        {"value": ["10.1.2.0"], "Count": 1},  # PS 5.1 System.Array type-data wrapper
    ],
)
def test_failover_parse_accepts_every_collection_shape(scope_ids: Any) -> None:
    out = _parse_failover(json.dumps(_failover([_rel(scope_ids=scope_ids)])))
    assert out["relationships"][0]["scope_ids"] == ["10.1.2.0"]


def test_failover_parse_single_relationship_unrolled_to_an_object() -> None:
    out = _parse_failover(json.dumps(_failover(_rel())))
    assert [r["name"] for r in out["relationships"]] == ["dhcp1-dhcp2"]


def test_failover_parse_canonicalises_and_dedupes_scope_ids() -> None:
    out = _parse_failover(
        json.dumps(_failover([_rel(scope_ids=[" 10.1.2.0 ", "10.1.2.0", "junk", None])]))
    )
    assert out["relationships"][0]["scope_ids"] == ["10.1.2.0"]


def test_failover_parse_no_relationships_is_ok_and_empty() -> None:
    out = _parse_failover(json.dumps(_failover([])))
    assert out == {"ok": True, "error": None, "relationships": []}


@pytest.mark.parametrize("code", [259, 20115])
def test_failover_parse_none_reported_as_an_error_is_still_none(code: int) -> None:
    """Some enumerations report "there are none" through an error. That is
    an answer — the server has no relationships — not a failure to read."""
    out = _parse_failover(
        json.dumps(_failover([], ok=False, error="There are no more items.", code=code))
    )
    assert out == {"ok": True, "error": None, "relationships": []}


def test_failover_parse_access_denied_is_unknown_not_none() -> None:
    """The case that matters: a denied read must stay distinguishable from
    'this server has no relationships', or every scope looks uncovered."""
    out = _parse_failover(json.dumps(_failover([], ok=False, error="Access is denied.", code=5)))
    assert out["ok"] is False
    assert out["error"] == "Access is denied."
    assert out["relationships"] == []


@pytest.mark.parametrize("raw", ["", "   ", "not json", "[1, 2]", '"a string"'])
def test_failover_parse_refuses_what_it_cannot_read(raw: str) -> None:
    with pytest.raises(RuntimeError):
        _parse_failover(raw)


def test_failover_script_never_selects_the_shared_secret() -> None:
    assert "SharedSecret" not in _PS_LIST_FAILOVER
    assert "EnableAuth" in _PS_LIST_FAILOVER


# ── live probe ────────────────────────────────────────────────────────


def _probe_row(sid: str, *, present: bool = True, state: str = "Active", ex=None):
    if not present:
        return {
            "scope_id": sid,
            "present": False,
            "state": None,
            "start_range": None,
            "end_range": None,
            "exclusions": [],
        }
    return {
        "scope_id": sid,
        "present": True,
        "state": state,
        "start_range": "10.1.2.10",
        "end_range": "10.1.2.200",
        "exclusions": ex if ex is not None else [{"start_ip": "10.1.2.50", "end_ip": "10.1.2.60"}],
    }


def test_probe_parse_present_scope() -> None:
    raw = json.dumps({"scopes": [_probe_row("10.1.2.0")], "failover": _failover([_rel()])})
    out = _parse_probe(raw, ["10.1.2.0"])
    obs = out["scopes"]["10.1.2.0"]
    assert obs["present"] is True
    assert obs["is_active"] is True
    assert (obs["start_ip"], obs["end_ip"]) == ("10.1.2.10", "10.1.2.200")
    assert obs["exclusions"] == [("10.1.2.50", "10.1.2.60")]
    assert out["failover"]["relationships"][0]["name"] == "dhcp1-dhcp2"


def test_probe_parse_inactive_and_absent() -> None:
    raw = json.dumps(
        {
            "scopes": [
                _probe_row("10.1.2.0", state="InActive"),
                _probe_row("10.1.3.0", present=False),
            ],
            "failover": _failover([]),
        }
    )
    out = _parse_probe(raw, ["10.1.2.0", "10.1.3.0"])
    assert out["scopes"]["10.1.2.0"]["is_active"] is False
    assert out["scopes"]["10.1.3.0"] == {
        "present": False,
        "is_active": None,
        "start_ip": None,
        "end_ip": None,
        "exclusions": [],
    }


def test_probe_parse_missing_row_is_an_error_not_absent() -> None:
    """The script emits one row per requested id. A missing row means the
    output was mangled — reading it as 'absent' would let the planner write
    to the other members as if this one did not serve the scope."""
    raw = json.dumps({"scopes": [], "failover": _failover([])})
    with pytest.raises(RuntimeError, match="did not report"):
        _parse_probe(raw, ["10.1.2.0"])


def test_probe_parse_needs_a_failover_block() -> None:
    raw = json.dumps({"scopes": [_probe_row("10.1.2.0")]})
    with pytest.raises(RuntimeError):
        _parse_probe(raw, ["10.1.2.0"])


def test_probe_script_fits_the_winrm_budget_with_room() -> None:
    """One scope id is the only shape the write-through sends; it must fit
    with headroom, not squeak under the CMD.EXE line limit."""
    assert encoded_command_len(_ps_probe_scopes(["255.255.255.0"])) < MAX_ENCODED_COMMAND - 1000


def test_probe_script_enumerates_scopes_under_stop() -> None:
    """A per-id lookup under SilentlyContinue returns $null for a lookup
    that FAILED as well as for one that found nothing."""
    script = _ps_probe_scopes(["10.1.2.0"])
    assert "$ErrorActionPreference = 'Stop'" in script
    assert "Get-DhcpServerv4Scope -ScopeId" not in script
    assert "'10.1.2.0'" in script


def test_as_list_shapes() -> None:
    assert _as_list(None) == []
    assert _as_list("x") == ["x"]
    assert _as_list([1]) == [1]
    assert _as_list({"value": [1, 2], "Count": 2}) == [1, 2]
    # A real object that happens to have a "value" key is not the wrapper.
    assert _as_list({"value": 1, "name": "n"}) == [{"value": 1, "name": "n"}]


# ── scope-presence guards on the writes ───────────────────────────────


class _PS:
    """Captures the script a driver method sends and returns canned stdout."""

    def __init__(self, stdout: str) -> None:
        self.stdout = stdout
        self.scripts: list[str] = []

    def __call__(self, server: Any, creds: Any, script: str) -> str:
        self.scripts.append(script)
        return self.stdout


@pytest.fixture
def driver(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setattr(windows, "_load_credentials", lambda server: {})
    return windows.WindowsDHCPReadOnlyDriver()


_SERVER = SimpleNamespace(id="s1", name="dhcp1", host="dhcp1.corp.example")


def _apply_scope_kwargs(**overrides: Any) -> dict[str, Any]:
    kw: dict[str, Any] = {
        "scope_id": "10.1.2.0",
        "subnet_mask": "255.255.255.0",
        "start_range": "10.1.2.10",
        "end_range": "10.1.2.200",
        "name": "office",
        "description": "",
        "lease_seconds": 86400,
        "is_active": True,
        "options": {},
    }
    kw.update(overrides)
    return kw


@pytest.mark.asyncio
async def test_apply_scope_update_only_reports_absent(driver: Any, monkeypatch) -> None:
    ps = _PS(_ABSENT_TOKEN + "\r\n")
    monkeypatch.setattr(windows, "_run_ps", ps)
    applied = await driver.apply_scope(_SERVER, **_apply_scope_kwargs(), create_if_missing=False)
    assert applied is False
    script = ps.scripts[0]
    # The existence check and the refusal to create sit in the script itself.
    assert "-not $false" in script
    assert "Add-DhcpServerv4Scope" in script  # still present for the create path


@pytest.mark.asyncio
async def test_apply_scope_default_still_creates(driver: Any, monkeypatch) -> None:
    ps = _PS("OK\r\n")
    monkeypatch.setattr(windows, "_run_ps", ps)
    assert await driver.apply_scope(_SERVER, **_apply_scope_kwargs()) is True
    assert "-not $true" in ps.scripts[0]


@pytest.mark.asyncio
async def test_remove_scope_absent_is_a_noop(driver: Any, monkeypatch) -> None:
    ps = _PS(_ABSENT_TOKEN)
    monkeypatch.setattr(windows, "_run_ps", ps)
    assert await driver.remove_scope(_SERVER, "10.1.2.0") is False
    ps.stdout = "OK"
    assert await driver.remove_scope(_SERVER, "10.1.2.0") is True


@pytest.mark.asyncio
async def test_reservation_and_exclusion_skip_a_server_without_the_scope(
    driver: Any, monkeypatch
) -> None:
    ps = _PS(_ABSENT_TOKEN)
    monkeypatch.setattr(windows, "_run_ps", ps)
    assert (
        await driver.apply_reservation(
            _SERVER, scope_id="10.1.2.0", ip_address="10.1.2.5", mac_address="aa:bb:cc:dd:ee:ff"
        )
        is False
    )
    assert (
        await driver.apply_exclusion(
            _SERVER, scope_id="10.1.2.0", start_ip="10.1.2.50", end_ip="10.1.2.60"
        )
        is False
    )
    for script in ps.scripts:
        # Enumerated under Stop, never looked up by id under SilentlyContinue.
        assert "Get-DhcpServerv4Scope | Where-Object" in script
        assert "$ErrorActionPreference = 'Stop'" in script


@pytest.mark.asyncio
async def test_probe_scopes_round_trip(driver: Any, monkeypatch) -> None:
    raw = json.dumps({"scopes": [_probe_row("10.1.2.0")], "failover": _failover([_rel()])})
    monkeypatch.setattr(windows, "_run_ps", _PS(raw))
    out = await driver.probe_scopes(_SERVER, ["10.1.2.0"])
    assert out["scopes"]["10.1.2.0"]["present"] is True


def test_capabilities_say_read_and_manage() -> None:
    caps = windows.WindowsDHCPReadOnlyDriver().capabilities()
    assert caps["failover_read"] is True
    assert caps["failover_management"] is True


# ── failover management (#1110 Phase 2) ───────────────────────────────


def _creds_server(transport: str | None) -> SimpleNamespace:
    from app.core.crypto import encrypt_dict  # noqa: PLC0415

    blob = (
        encrypt_dict({"username": "u", "password": "p", "transport": transport})
        if transport is not None
        else encrypt_dict({"username": "u", "password": "p"})
    )
    return SimpleNamespace(id="s1", name="dhcp1", host="dhcp1", credentials_encrypted=blob)


@pytest.mark.parametrize(
    ("transport", "allowed"),
    [
        ("credssp", True),
        ("CredSSP", True),
        ("ntlm", False),
        ("kerberos", False),
        ("basic", False),
        (None, False),
    ],
)
def test_only_credssp_can_make_the_second_hop(transport: str | None, allowed: bool) -> None:
    """An NTLM / Basic logon over WinRM has no credential to pass on to the
    partner; the image has no GSSAPI stack for Kerberos. Unset means ntlm,
    pywinrm's default here."""
    blocker = windows.failover_management_blocker(_creds_server(transport))
    assert (blocker is None) is allowed
    if not allowed:
        assert "second hop" in (blocker or "")
        assert "Enable-WSManCredSSP" in (blocker or "")


@pytest.mark.asyncio
async def test_failover_op_refused_before_anything_is_sent(monkeypatch) -> None:
    ps = _PS("{}")
    monkeypatch.setattr(windows, "_run_ps", ps)
    drv = windows.WindowsDHCPReadOnlyDriver()
    with pytest.raises(windows.FailoverManagementUnavailable):
        await drv.delete_failover_relationship(_creds_server("ntlm"), name="r")
    assert ps.scripts == []


@pytest.mark.asyncio
async def test_create_ships_the_secret_encoded_never_in_script_text(monkeypatch) -> None:
    """Operator values are data-bound through ConvertFrom-Json, and errors are
    re-thrown as their message alone, so the script — which carries the
    secret — cannot come back in an error record."""
    secret = "it's; a $(secret)"
    raw = json.dumps(_failover([_rel(name="r")]))
    ps = _PS(raw)
    monkeypatch.setattr(windows, "_run_ps", ps)
    drv = windows.WindowsDHCPReadOnlyDriver()
    out = await drv.create_failover_relationship(
        _creds_server("credssp"),
        name="r",
        partner_server="dhcp2",
        scope_ids=["10.1.2.0"],
        mode="LoadBalance",
        load_balance_percent=50,
        shared_secret=secret,
    )
    assert out["relationships"][0]["name"] == "r"
    script = ps.scripts[0]
    assert secret not in script
    assert "Add-DhcpServerv4Failover @p" in script
    assert 'throw "$($_.Exception.Message)"' in script
    payload = script.split("FromBase64String('")[1].split("')")[0]
    import base64  # noqa: PLC0415

    decoded = json.loads(base64.b64decode(payload))
    assert decoded["shared_secret"] == secret
    assert decoded["op"] == "create" and decoded["scope_ids"] == ["10.1.2.0"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "kwargs", "cmdlet"),
    [
        (
            "update_failover_relationship",
            {"name": "r", "load_balance_percent": 70},
            "Set-DhcpServerv4Failover",
        ),
        ("delete_failover_relationship", {"name": "r"}, "Remove-DhcpServerv4Failover "),
        (
            "add_failover_scopes",
            {"name": "r", "scope_ids": ["10.1.2.0"]},
            "Add-DhcpServerv4FailoverScope",
        ),
        (
            "remove_failover_scopes",
            {"name": "r", "scope_ids": ["10.1.2.0"]},
            "Remove-DhcpServerv4FailoverScope",
        ),
        ("replicate_failover", {"name": "r"}, "Invoke-DhcpServerv4FailoverReplication"),
    ],
)
async def test_each_op_returns_the_servers_relationships(
    monkeypatch, method: str, kwargs: dict[str, Any], cmdlet: str
) -> None:
    ps = _PS(json.dumps(_failover([])))
    monkeypatch.setattr(windows, "_run_ps", ps)
    out = await getattr(windows.WindowsDHCPReadOnlyDriver(), method)(
        _creds_server("credssp"), **kwargs
    )
    assert out == {"ok": True, "error": None, "relationships": []}
    assert cmdlet in ps.scripts[0]


@pytest.mark.parametrize(
    "op", ["create", "update", "delete", "add_scopes", "remove_scopes", "replicate"]
)
def test_every_op_fits_the_command_line_with_maximal_input(op: str) -> None:
    """WinRM ships a script as ONE ``powershell -EncodedCommand`` line under
    CMD.EXE's cap; an over-long script is refused before it is sent. The first
    cut put every op and the relationship read in one script and came to over
    12,000 encoded characters — every management call would have failed."""
    sids = [f"10.{i // 250}.{i % 250}.0" for i in range(windows._FAILOVER_SCOPE_CHUNK)]
    script = windows._ps_failover_op(
        {
            "op": op,
            "name": "n" * 126,
            "partner_server": "p" * 255,
            "scope_ids": sids,
            "mode": "HotStandby",
            "server_role": "Standby",
            "load_balance_percent": None,
            "reserve_percent": 5,
            "max_client_lead_time_seconds": 3600,
            "auto_state_transition": True,
            "state_switch_interval_seconds": 3600,
            "shared_secret": "s" * 255,
        }
    )
    assert encoded_command_len(script) <= MAX_ENCODED_COMMAND


@pytest.mark.asyncio
async def test_a_long_scope_list_is_chunked_and_create_adds_the_rest(monkeypatch) -> None:
    ps = _PS(json.dumps(_failover([])))
    monkeypatch.setattr(windows, "_run_ps", ps)
    n = windows._FAILOVER_SCOPE_CHUNK * 2 + 1
    sids = [f"10.{i // 250}.{i % 250}.0" for i in range(n)]
    await windows.WindowsDHCPReadOnlyDriver().create_failover_relationship(
        _creds_server("credssp"), name="r", partner_server="p", scope_ids=sids, mode="LoadBalance"
    )
    ops = [
        (
            "create"
            if "Add-DhcpServerv4Failover @p" in sc
            else (
                "add"
                if "Add-DhcpServerv4FailoverScope" in sc
                else "read" if "Get-DhcpServerv4Failover" in sc else "?"
            )
        )
        for sc in ps.scripts
    ]
    assert ops == ["create", "add", "add", "read"]


@pytest.mark.asyncio
async def test_update_rejects_an_unknown_field(monkeypatch) -> None:
    monkeypatch.setattr(windows, "_run_ps", _PS("{}"))
    with pytest.raises(ValueError, match="unsupported"):
        await windows.WindowsDHCPReadOnlyDriver().update_failover_relationship(
            _creds_server("credssp"), name="r", partner_server="x"
        )
