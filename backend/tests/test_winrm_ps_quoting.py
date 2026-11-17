"""Operator strings stay inside PowerShell single-quoted literals.

PowerShell ends a single-quoted string at U+2018 to U+201B as well as at the
ASCII apostrophe, and writes a quote inside the literal by doubling that same
character. These tests tokenize the generated scripts the way PowerShell does
and assert the operator value is one literal, for every quote character.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.drivers import _winrm
from app.drivers.dhcp import windows as dhcp_windows
from app.drivers.dns import windows as dns_windows
from app.drivers.dns.base import RecordChange, RecordData

QUOTES = ["'", "\u2018", "\u2019", "\u201a", "\u201b"]
MARKER = "INJECTED"


def _payloads() -> list[str]:
    out = []
    for q in QUOTES:
        out.append(f"x{q}; Write-Output {MARKER}; #")
        out.append(f"{q}{q}x{q}")
        out.append(f"a{q}b")
    out.append("x\u2019'\u2018; Write-Output INJECTED; $d=\u201b")
    return out


def _literals(script: str) -> tuple[list[str], str]:
    """Tokenize single-quoted literals like PowerShell; return (values, rest).

    ``rest`` is the script with every literal blanked out, so anything left
    outside a literal is what PowerShell would execute.
    """
    sq = set(_winrm._PS_SINGLE_QUOTES)
    vals: list[str] = []
    rest: list[str] = []
    i = 0
    n = len(script)
    while i < n:
        c = script[i]
        if c in sq:
            i += 1
            buf: list[str] = []
            while True:
                if i >= n:
                    raise AssertionError("unterminated literal")
                d = script[i]
                if d in sq:
                    if i + 1 < n and script[i + 1] == d:
                        buf.append(d)
                        i += 2
                        continue
                    i += 1
                    break
                buf.append(d)
                i += 1
            vals.append("".join(buf))
            rest.append("''")
        else:
            rest.append(c)
            i += 1
    return vals, "".join(rest)


@pytest.mark.parametrize("value", _payloads())
def test_helper_round_trips_every_quote_character(value: str) -> None:
    vals, rest = _literals(_winrm.ps_single_quote(value))
    assert vals == [value]
    assert rest == "''"


def test_helper_doubles_each_quote_character() -> None:
    for q in QUOTES:
        assert _winrm.ps_single_quote_escape(q) == q * 2
    assert _winrm.ps_single_quote_escape(None) == ""


@pytest.mark.parametrize("value", _payloads())
def test_dns_record_script_keeps_value_in_literal(value: str) -> None:
    for rtype in ("TXT", "A", "CNAME"):
        for op in ("create", "delete"):
            change = RecordChange(
                op=op,
                zone_name="example.com.",
                record=RecordData(name="h", record_type=rtype, value=value, ttl=60),
                target_serial=1,
            )
            script = dns_windows._ps_apply_record(change)
            _, rest = _literals(script)
            assert MARKER not in rest


@pytest.mark.parametrize("value", _payloads())
def test_dns_names_and_messages_keep_value_in_literal(value: str) -> None:
    for op in ("create", "delete"):
        script = dns_windows._ps_apply_zone(SimpleNamespace(name=value + ".com"), op)
        _, rest = _literals(script)
        assert MARKER not in rest
    change = RecordChange(
        op="create",
        zone_name=value + ".com.",
        record=RecordData(name=value, record_type="A", value="10.0.0.1", ttl=60),
        target_serial=1,
    )
    _, rest = _literals(dns_windows._ps_apply_record(change))
    assert MARKER not in rest


def test_dns_operator_values_never_reach_a_double_quoted_string() -> None:
    value = "x$(Write-Output INJECTED)`n"
    script = dns_windows._ps_apply_zone(SimpleNamespace(name=value), "create")
    stripped, _ = _literals(script)
    # Remove literal contents, then look for double-quoted strings that carry
    # the value: there must be none.
    assert "$(Write-Output INJECTED)" not in re.sub(r"'(?:[^']|'')*'", "", script)
    assert stripped


@pytest.mark.parametrize("value", _payloads())
def test_dhcp_scripts_keep_value_in_literal(value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def fake_run(server: Any, creds: Any, script: str) -> str:
        seen.append(script)
        return "OK"

    monkeypatch.setattr(dhcp_windows, "_run_ps", fake_run)
    monkeypatch.setattr(dhcp_windows, "_load_credentials", lambda server: {})
    drv = dhcp_windows.WindowsDHCPReadOnlyDriver()
    server = SimpleNamespace(name="w1")

    async def go() -> None:
        await drv.apply_reservation(
            server,
            scope_id="10.0.0.0",
            ip_address="10.0.0.5",
            mac_address="aa:bb:cc:dd:ee:ff",
            hostname=value,
            description=value,
        )
        await drv.apply_scope(
            server,
            scope_id="10.0.0.0",
            subnet_mask="255.255.255.0",
            start_range="10.0.0.10",
            end_range="10.0.0.20",
            name=value,
            description=value,
            lease_seconds=3600,
            is_active=True,
            options={},
        )

    asyncio.run(go())
    assert len(seen) >= 2
    for script in seen:
        vals, rest = _literals(script)
        assert MARKER not in rest
        assert value in vals


def test_no_private_single_quote_escaping_under_app() -> None:
    """One definition of the rule: ``app.drivers._winrm``."""
    app_dir = Path(__file__).resolve().parents[1] / "app"
    allowed = {
        # SQL string literals, not PowerShell.
        Path("services/backup/restore.py"),
        Path("models/settings.py"),
    }
    pat = re.compile(r"""replace\(\s*(?:"'"|'\\''|chr\(39\))\s*,\s*(?:"''"|chr\(39\)\s*\*\s*2)""")
    bad = []
    for path in app_dir.rglob("*.py"):
        rel = path.relative_to(app_dir)
        if rel in allowed or rel == Path("drivers/_winrm.py"):
            continue
        if pat.search(path.read_text()):
            bad.append(str(rel))
    assert not bad, f"use app.drivers._winrm.ps_single_quote*: {bad}"


def _executable_outside_literals(script: str) -> str:
    """Script text PowerShell would run: literals blanked, comments dropped.

    A ``#`` outside a literal comments out the rest of its line, and only CR
    and LF end a line (checked against pwsh), so quotes inside a comment are
    not literals.
    """
    sq = set(_winrm._PS_SINGLE_QUOTES)
    out: list[str] = []
    i, n = 0, len(script)
    while i < n:
        c = script[i]
        if c == "#":
            while i < n and script[i] not in "\r\n":
                i += 1
        elif c in sq:
            i += 1
            while True:
                if i >= n:
                    raise AssertionError("unterminated literal")
                if script[i] in sq:
                    if i + 1 < n and script[i + 1] == script[i]:
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            out.append("''")
        else:
            out.append(c)
            i += 1
    return "".join(out)


_LINE_BREAKS = ["\n", "\r", "\r\n", " ", "\u0085"]


def _one_line_payloads() -> list[str]:
    out = _payloads()
    for nl in _LINE_BREAKS:
        out.append(f"dc1{nl}Write-Output {MARKER}{nl}#")
        out.append(f"dc1{nl}```{nl}Write-Output {MARKER}")
    return out


@pytest.mark.parametrize("value", _one_line_payloads())
def test_cutover_ttl_script_keeps_value_out_of_code(value: str) -> None:
    from app.services.cutover.preflight import windows_ttl_powershell

    for computer_name in (None, value):
        script = windows_ttl_powershell(value + ".com", 60, 3600, computer_name=computer_name)
        assert MARKER not in _executable_outside_literals(script)
        for line in script.splitlines():
            assert not line.startswith("```")


@pytest.mark.parametrize("value", _one_line_payloads())
def test_cutover_runbook_blocks_keep_value_out_of_code(value: str) -> None:
    from app.services.cutover import runbook

    blocks = [
        runbook._ps_disable_scavenging(value, value),
        runbook._ps_scope_state(value, value, active=False),
        runbook._ps_deauthorize_dhcp(value),
        runbook._ps_lower_ttls(value, value, 60, 3600),
    ]
    for lines in blocks:
        # A value must not open or close the Markdown fence the block sits in.
        assert lines[0] == "```powershell"
        fences = [i for i, ln in enumerate(lines) if ln.startswith("```")]
        assert fences == [0, lines.index("```")]
        body = "\n".join(lines[1 : fences[1]])
        assert MARKER not in _executable_outside_literals(body)


@pytest.mark.parametrize("value", _payloads())
def test_event_log_filter_keeps_value_in_literal(value: str) -> None:
    from app.drivers import windows_events

    script = windows_events._build_filter_script(
        log_name=value, max_events=10, level=None, since_iso=value, event_id=None
    )
    vals, rest = _literals(script)
    assert MARKER not in rest
    assert value in vals


def test_one_line_replaces_every_line_break() -> None:
    for nl in _LINE_BREAKS + ["\x00", " ", "\x0b"]:
        assert _winrm.ps_one_line(f"a{nl}b") in ("a b", "a  b")
    assert _winrm.ps_one_line(None) == ""
    assert _winrm.ps_one_line("dc1.corp.example") == "dc1.corp.example"
