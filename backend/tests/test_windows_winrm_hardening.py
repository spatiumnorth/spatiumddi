"""#426 — Windows DNS/DHCP integration hardening.

Unit-level coverage for the audit fixes that don't need a live Windows
host: the shared WinRM chokepoint's size budget, the data-only batch
packing (DHCP + DNS) that replaced the cmdline-overflowing per-op-snippet
design, the locale-safe exclusion idempotency, the lease-parse re-raise
(so a garbled response can't drive a mass purge), the TXT quote
normalisation, and the credential-schema validators.
"""

from __future__ import annotations

import base64

import pytest

from app.drivers import _winrm
from app.drivers._winrm import (
    MAX_ENCODED_COMMAND,
    WinRMCommandTooLong,
    encoded_command_len,
    run_ps,
)
from app.drivers.dhcp import windows as dhcp_win
from app.drivers.dhcp.base import ReservationItem
from app.drivers.dns import windows as dns_win
from app.drivers.dns.base import RecordChange, RecordData

# ── shared _winrm chokepoint ───────────────────────────────────────────


def test_encoded_command_len_matches_pywinrm_encoding() -> None:
    s = "Get-DhcpServerv4Scope | ConvertTo-Json"
    assert encoded_command_len(s) == len(base64.b64encode(s.encode("utf-16-le")))


def test_run_ps_rejects_oversized_script_before_dispatch() -> None:
    # The size guard runs before ``import winrm`` / any network, so this
    # raises without a Windows host. ~3100 raw chars × 2.67 > budget.
    huge = "x" * (MAX_ENCODED_COMMAND)  # encodes to ~2.67× → well over budget
    with pytest.raises(WinRMCommandTooLong):
        run_ps("host.example", {"username": "u", "password": "p"}, huge)


def test_run_ps_size_guard_boundary() -> None:
    # A script that encodes to just under the budget passes the guard
    # (it will then fail later trying to reach a host — but NOT for size).
    small = "x" * 100
    assert encoded_command_len(small) <= MAX_ENCODED_COMMAND


# ── DHCP data-only batch packing (BLOCKER #1) ──────────────────────────


def _reservations(n: int) -> list[ReservationItem]:
    return [
        ReservationItem(
            scope_id="10.0.0.0",
            ip_address=f"10.0.0.{i % 250 + 1}",
            mac_address=f"00:11:22:33:44:{i % 256:02x}",
            hostname=f"host-{i}",
            description="x" * 40,
        )
        for i in range(n)
    ]


def test_dhcp_pack_keeps_every_chunk_under_budget() -> None:
    items = _reservations(200)
    chunks = dhcp_win._pack_dhcp_chunks(
        items, dhcp_win._data_apply_reservation, dhcp_win._PS_BODY_APPLY_RESERVATION
    )
    # Many ops → more than one chunk, and not all in one giant script.
    assert len(chunks) >= 2
    # Every chunk's built script fits the encoded-command budget.
    for chunk in chunks:
        payload = [
            {"index": idx, **dhcp_win._data_apply_reservation(it)}
            for idx, (_, it) in enumerate(chunk)
        ]
        script = dhcp_win._build_dhcp_batch_script(dhcp_win._PS_BODY_APPLY_RESERVATION, payload)
        assert encoded_command_len(script) <= MAX_ENCODED_COMMAND
    # No item lost across the packing.
    assert sum(len(c) for c in chunks) == len(items)


def test_dhcp_batch_script_data_binds_operator_values() -> None:
    # An operator value with PS metacharacters must NOT appear raw in the
    # script — it travels inside the base64 payload + ConvertFrom-Json, so
    # it never touches the parser (no injection).
    evil = "10.0.0.0'; Remove-Item C:\\ -Recurse #"
    payload = [
        {
            "index": 0,
            **dhcp_win._data_apply_reservation(
                ReservationItem(
                    scope_id=evil, ip_address="10.0.0.5", mac_address="aa:bb:cc:dd:ee:ff"
                )
            ),
        }
    ]
    script = dhcp_win._build_dhcp_batch_script(dhcp_win._PS_BODY_APPLY_RESERVATION, payload)
    assert evil not in script
    assert "$op.scopeId" in script  # op body data-binds


def test_dhcp_exclusion_body_is_locale_safe() -> None:
    # #426: pre-check instead of matching the English substring 'already'.
    body = dhcp_win._PS_BODY_APPLY_EXCLUSION
    assert "Get-DhcpServerv4ExclusionRange" in body
    assert "already" not in body


# ── DHCP lease-parse re-raise (MAJOR #3) ───────────────────────────────


def test_parse_leases_reraises_on_garbage() -> None:
    # A garbled / truncated (but non-empty) payload must NOT read as
    # "zero leases" — that would drive pull_leases to purge everything.
    with pytest.raises(RuntimeError):
        dhcp_win._parse_leases("{ this is not json")


def test_parse_leases_empty_is_zero_leases() -> None:
    assert dhcp_win._parse_leases("") == []
    assert dhcp_win._parse_leases("   ") == []


def test_parse_leases_valid_empty_array() -> None:
    assert dhcp_win._parse_leases("[]") == []


# ── DNS TXT quote helper + SRV/MX rdata (#7, #424 regression guard) ─────


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('"v=spf1 -all"', "v=spf1 -all"),
        ("v=spf1 -all", "v=spf1 -all"),
        ('""', ""),
        ('"', '"'),  # single char — not a wrapping pair
        ("", ""),
        ('"unbalanced', '"unbalanced'),
    ],
)
def test_strip_txt_quotes(raw: str, expected: str) -> None:
    assert dns_win._strip_txt_quotes(raw) == expected


def test_format_rdata_srv_mx_and_txt() -> None:
    srv = RecordData(
        name="_sip._tcp", record_type="SRV", value="sip.x.", priority=10, weight=20, port=5060
    )
    assert dns_win._format_rdata(srv) == "10 20 5060 sip.x."
    mx = RecordData(name="@", record_type="MX", value="mail.x.", priority=5)
    assert dns_win._format_rdata(mx) == "5 mail.x."
    txt = RecordData(name="@", record_type="TXT", value='"v=spf1 -all"')
    # Quotes stripped then re-wired as a single quoted chunk.
    assert dns_win._format_rdata(txt) == '"v=spf1 -all"'


# ── DNS record batch packing (#6 — large TXT overflow) ─────────────────


def _txt_changes(n: int, value_len: int) -> list[tuple[int, RecordChange]]:
    out = []
    for i in range(n):
        rec = RecordData(name=f"k{i}", record_type="TXT", value='"' + "a" * value_len + '"')
        out.append(
            (i, RecordChange(op="create", zone_name="example.com.", record=rec, target_serial=1))
        )
    return out


def test_dns_pack_record_chunks_splits_large_txt() -> None:
    # A handful of big DKIM-sized TXT records must split across chunks,
    # each under the encoded budget — the old fixed count of 6 had no
    # length check and would overflow the cmdline.
    eligible = _txt_changes(12, 350)
    chunks = dns_win._pack_record_chunks(eligible)
    assert len(chunks) >= 2
    for chunk in chunks:
        script = dns_win._ps_apply_record_batch([c for _, c in chunk])
        assert encoded_command_len(script) <= MAX_ENCODED_COMMAND
    assert sum(len(c) for c in chunks) == len(eligible)


def test_dns_batch_txt_value_quote_stripped() -> None:
    # The batch payload should carry the literal TXT text (quotes stripped)
    # for parity with the singular + RFC-2136 paths.
    rec = RecordData(name="@", record_type="TXT", value='"hello world"')
    change = RecordChange(op="create", zone_name="x.", record=rec, target_serial=1)
    script = dns_win._ps_apply_record_batch([change])
    # The base64 payload decodes to JSON whose v field has no surrounding quotes.
    import base64 as _b64
    import json as _json
    import re as _re

    m = _re.search(r"FromBase64String\('([^']+)'\)", script)
    assert m, "payload not found in batch script"
    ops = _json.loads(_b64.b64decode(m.group(1)).decode("utf-8"))
    # #783 moved each op's value into a members list (``m``) so one op can
    # carry a whole RRset; the quote-stripping this test guards is unchanged.
    assert [member["v"] for member in ops[0]["m"]] == ["hello world"]


# ── credential schema validators (#11) ─────────────────────────────────


def test_dhcp_creds_validators_reject_bad_input() -> None:
    from pydantic import ValidationError

    from app.api.v1.dhcp.servers import WindowsCredentialsInput as DhcpCreds

    with pytest.raises(ValidationError):
        DhcpCreds(transport="telnet")
    with pytest.raises(ValidationError):
        DhcpCreds(winrm_port=99999)
    # Valid values pass.
    assert DhcpCreds(transport="credssp", winrm_port=5986).transport == "credssp"


@pytest.mark.parametrize("module", ["app.api.v1.dhcp.servers", "app.api.v1.dns.router"])
def test_kerberos_is_refused_with_the_reason(module: str) -> None:
    """#1128 — the images carry no GSSAPI stack, so Kerberos could never
    connect. Refused at save, saying why, rather than accepted and failing
    on every call."""
    import importlib

    from pydantic import ValidationError

    creds = importlib.import_module(module).WindowsCredentialsInput
    with pytest.raises(ValidationError, match="#1128"):
        creds(transport="kerberos")
    for t in ("ntlm", "credssp", "basic"):
        assert creds(transport=t).transport == t


def test_a_server_saved_with_kerberos_fails_with_the_reason_not_a_library_error() -> None:
    from app.drivers._winrm import run_ps

    with pytest.raises(RuntimeError, match="not supported.*pick another transport"):
        run_ps("host", {"username": "u", "password": "p", "transport": "kerberos"}, "1")


def test_dns_creds_validators_reject_bad_input() -> None:
    from pydantic import ValidationError

    from app.api.v1.dns.router import WindowsCredentialsInput as DnsCreds

    with pytest.raises(ValidationError):
        DnsCreds(transport="smb")
    with pytest.raises(ValidationError):
        DnsCreds(winrm_port=0)
    assert DnsCreds(transport="ntlm", winrm_port=5985).winrm_port == 5985


# ── _winrm transport warnings (#9) ─────────────────────────────────────


def test_winrm_warns_on_tls_without_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    # Pure helper — no network. Capture the structlog event name directly
    # (structlog doesn't route through pytest's caplog by default).
    events: list[str] = []
    monkeypatch.setattr(_winrm.logger, "warning", lambda event, **kw: events.append(event))
    _winrm._warn_insecure_transport("h", "ntlm", use_tls=True, verify_tls=False)
    assert "winrm_tls_verification_disabled" in events


def test_winrm_warns_on_cleartext_basic(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    monkeypatch.setattr(_winrm.logger, "warning", lambda event, **kw: events.append(event))
    _winrm._warn_insecure_transport("h", "basic", use_tls=False, verify_tls=False)
    assert "winrm_cleartext_basic_auth" in events


def test_winrm_no_warning_on_secure_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    monkeypatch.setattr(_winrm.logger, "warning", lambda event, **kw: events.append(event))
    # HTTPS + verify, and ntlm over plain HTTP (no cleartext password) → quiet.
    _winrm._warn_insecure_transport("h", "ntlm", use_tls=True, verify_tls=True)
    _winrm._warn_insecure_transport("h", "ntlm", use_tls=False, verify_tls=False)
    assert events == []


# ── reservation relocation (#5) + MAC/IP normalisation (#4) ────────────


def test_norm_mac_and_ip() -> None:
    from app.services.dhcp import windows_writethrough as wt

    assert wt._norm_mac("AA-BB-CC-DD-EE-FF") == wt._norm_mac("aa:bb:cc:dd:ee:ff")
    assert wt._norm_ip("10.0.0.5") == wt._norm_ip(" 10.0.0.5 ")
    assert wt._norm_ip("garbage") == "garbage"  # unparseable falls back to raw


async def _run_push(monkeypatch, *, prev_mac, prev_ip, cur_mac, cur_ip):
    """Drive push_static_change with a fake driver + DB and record the
    driver calls (remove/apply) in order."""
    from types import SimpleNamespace

    from app.services.dhcp import windows_writethrough as wt

    calls: list[tuple] = []

    class FakeDriver:
        async def remove_reservation(self, server, *, scope_id, mac_address):
            calls.append(("remove", mac_address))

        async def apply_reservation(
            self, server, *, scope_id, ip_address, mac_address, hostname, description
        ):
            calls.append(("apply", ip_address, mac_address))

    server = SimpleNamespace(id="srv", driver="windows_dhcp")
    monkeypatch.setattr(wt, "get_driver", lambda d: FakeDriver())

    async def fake_servers(db, gid):
        return [server]

    async def fake_cidr(db, scope):
        import ipaddress as _ip

        return _ip.ip_network("10.0.0.0/24")

    monkeypatch.setattr(wt, "_windows_servers_for_group", fake_servers)
    monkeypatch.setattr(wt, "_scope_cidr", fake_cidr)

    # push_static_change now fans a cloud write-through in first (agentless
    # FortiGate seam). These tests exercise the Windows path only, so stub the
    # cloud push to a no-op — otherwise it would query the DB for cloud members.
    async def fake_cloud_push(*args, **kwargs):
        return None

    monkeypatch.setattr(wt, "push_cloud_scope_upsert", fake_cloud_push)

    class FakeDB:
        async def get(self, model, key):
            return SimpleNamespace(id="s", group_id="g")

    static = SimpleNamespace(
        id="x", scope_id="s", mac_address=cur_mac, ip_address=cur_ip, hostname="", description=""
    )
    await wt.push_static_change(
        FakeDB(), static, action="update", prev_mac=prev_mac, prev_ip=prev_ip
    )
    return calls


@pytest.mark.asyncio
async def test_ip_only_change_relocates_remove_then_add(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = await _run_push(
        monkeypatch,
        prev_mac="aa:bb:cc:dd:ee:ff",
        prev_ip="10.0.0.5",
        cur_mac="aa:bb:cc:dd:ee:ff",
        cur_ip="10.0.0.9",
    )
    # Same MAC, moved IP → remove (by current MAC) THEN add at the new IP.
    assert calls[0] == ("remove", "aa:bb:cc:dd:ee:ff")
    assert calls[1] == ("apply", "10.0.0.9", "aa:bb:cc:dd:ee:ff")


@pytest.mark.asyncio
async def test_noop_update_just_upserts(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = await _run_push(
        monkeypatch,
        prev_mac="aa:bb:cc:dd:ee:ff",
        prev_ip="10.0.0.5",
        cur_mac="aa:bb:cc:dd:ee:ff",
        cur_ip="10.0.0.5",
    )
    # Nothing changed → no remove, just the idempotent apply (upsert).
    assert calls == [("apply", "10.0.0.5", "aa:bb:cc:dd:ee:ff")]


@pytest.mark.asyncio
async def test_cosmetic_mac_reformat_does_not_relocate(monkeypatch: pytest.MonkeyPatch) -> None:
    # Same MAC in a different format (dashes/upper) + same IP → must NOT
    # trigger a remove-then-add (#426 false-positive guard).
    calls = await _run_push(
        monkeypatch,
        prev_mac="AA-BB-CC-DD-EE-FF",
        prev_ip="10.0.0.5",
        cur_mac="aa:bb:cc:dd:ee:ff",
        cur_ip="10.0.0.5",
    )
    assert all(c[0] != "remove" for c in calls)
