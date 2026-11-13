"""Windows Event Log reader — shared by the Windows DNS + DHCP drivers.

Runs ``Get-WinEvent -FilterHashtable`` over WinRM against a Windows
server and returns a list of neutral dict rows. The two drivers expose
this via per-driver ``get_events`` / ``available_log_names`` methods
so the Logs API only needs to speak to the abstract driver interface.

The PowerShell filter hashtable is built from the passed keyword
filters so we push selection to the server rather than pulling the
whole log and filtering client-side — materially cheaper on busy
DCs. ``MaxEvents`` is a parameter on ``Get-WinEvent``, not a hash
key, so it's kept separate.

Level mapping (Windows Event Log standard):
  1  Critical
  2  Error
  3  Warning
  4  Informational
  5  Verbose

Empty result handling: ``Get-WinEvent`` raises on zero matches, so
``-ErrorAction SilentlyContinue`` + an ``if (-not $events)`` guard
returns ``[]`` cleanly rather than exploding.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import structlog

from app.drivers._winrm import ps_single_quote

logger = structlog.get_logger(__name__)


def _ps_single_quote(s: str) -> str:
    """Escape a string for a PowerShell single-quoted literal."""
    return ps_single_quote(s)


def _build_filter_script(
    *,
    log_name: str,
    max_events: int,
    level: int | None,
    since_iso: str | None,
    event_id: int | None,
) -> str:
    parts = [f"LogName = {_ps_single_quote(log_name)}"]
    if level is not None:
        parts.append(f"Level = {int(level)}")
    if event_id is not None:
        parts.append(f"Id = {int(event_id)}")
    if since_iso:
        parts.append(f"StartTime = [datetime]::Parse({_ps_single_quote(since_iso)})")
    filter_str = "; ".join(parts)
    capped = max(1, min(int(max_events), 500))
    # ``Get-WinEvent`` throws a ``System.Diagnostics.Eventing.Reader
    # .EventLogException`` when:
    #   * the log name doesn't exist on this host ("There is not an
    #     event log on the computer named X"),
    #   * zero events match ("No events were found"), or
    #   * a FilterHashtable key doesn't apply to the log ("The
    #     parameter is incorrect" — Win32 error 87).
    # ``-ErrorAction SilentlyContinue`` covers the non-terminating
    # error cases, but terminating exceptions from the .NET provider
    # still bubble up — so we wrap in try/catch and normalise any
    # "no data / bad log" variant into an empty result.
    return f"""
$ErrorActionPreference = 'Stop'
$events = $null
try {{
    $events = Get-WinEvent -FilterHashtable @{{ {filter_str} }} -MaxEvents {capped}
}} catch [System.Diagnostics.Eventing.Reader.EventLogException] {{
    Write-Output '[]'
    exit 0
}} catch {{
    $msg = $_.Exception.Message
    if ($msg -match 'No events were found|not an event log|parameter is incorrect|does not exist') {{
        Write-Output '[]'
        exit 0
    }}
    throw
}}
if (-not $events) {{ Write-Output '[]'; exit 0 }}
$events | Select-Object `
    @{{N='time';E={{$_.TimeCreated.ToString('o')}}}}, `
    @{{N='id';E={{$_.Id}}}}, `
    @{{N='level';E={{$_.LevelDisplayName}}}}, `
    @{{N='provider';E={{$_.ProviderName}}}}, `
    @{{N='machine';E={{$_.MachineName}}}}, `
    @{{N='message';E={{$_.Message}}}} | ConvertTo-Json -Compress -Depth 3
"""


async def fetch_events(
    server: Any,
    creds: dict[str, Any],
    *,
    run_ps: Callable[[Any, dict[str, Any], str], str],
    log_name: str,
    max_events: int = 100,
    level: int | None = None,
    since: datetime | None = None,
    event_id: int | None = None,
) -> list[dict[str, Any]]:
    """Fetch events matching the filters from ``log_name`` on ``server``.

    ``run_ps`` is the driver's existing PowerShell executor — passed in
    so this helper doesn't need to know about per-driver endpoint /
    transport defaults; each driver already encapsulates those.

    Returns a list of dicts with keys: ``time`` (ISO 8601 string),
    ``id`` (int), ``level`` (str: "Error" / "Warning" / "Information"
    / "Verbose" / "Critical"), ``provider`` (str), ``machine`` (str),
    ``message`` (str). Empty list on no matches.
    """
    # #426: coerce to tz-aware UTC so the ISO string carries an explicit
    # offset. A naive `since` would isoformat() without one, and the
    # Windows-side [datetime]::Parse() then reads it as server-LOCAL time,
    # shifting the StartTime filter window by the host's UTC offset.
    if since is not None:
        since = (since.replace(tzinfo=UTC) if since.tzinfo is None else since).astimezone(UTC)
    since_iso = since.isoformat() if since else None
    script = _build_filter_script(
        log_name=log_name,
        max_events=max_events,
        level=level,
        since_iso=since_iso,
        event_id=event_id,
    )
    raw = await asyncio.to_thread(run_ps, server, creds, script)
    text = (raw or "").strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        logger.warning(
            "windows_events_parse_failed",
            server=str(getattr(server, "id", "?")),
            log_name=log_name,
            raw=text[:400],
            error=str(exc),
        )
        return []
    items: list[dict[str, Any]] = parsed if isinstance(parsed, list) else [parsed]
    # Normalise — every row should have the expected keys even when
    # Windows omits them for some event types.
    out: list[dict[str, Any]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        out.append(
            {
                "time": it.get("time") or "",
                "id": int(it["id"]) if isinstance(it.get("id"), int) else 0,
                "level": (it.get("level") or "").strip(),
                "provider": (it.get("provider") or "").strip(),
                "machine": (it.get("machine") or "").strip(),
                "message": (it.get("message") or "").strip(),
            }
        )
    return out


__all__ = ["fetch_events"]
