"""Subprocess runners for the built-in network tools (issue #58).

Security model — mirrors :mod:`app.services.nmap.runner`:

* Argv is built by hand from validated inputs; we **never** invoke a
  shell. Subprocesses are spawned with ``create_subprocess_exec`` so no
  shell-metacharacter interpretation is possible even if a value slipped
  past validation.
* Targets are re-validated here (defence in depth — the Pydantic schema
  already validated, but the runner is a public-ish entry point).
* Every call carries a hard ``asyncio.wait_for`` timeout. Slow tools
  (traceroute / mtr) are additionally bounded by tool-specific args
  (``-m`` max-hops, ``--report-cycles`` small) so they finish well under
  the proxy timeout.
* A missing binary (``FileNotFoundError``) returns a clean structured
  result with ``available=False`` and a human ``error`` — never a 500.

All runners are server-perspective: they run inside the api container.
Agent-perspective dispatch is a deferred follow-up.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from typing import Final

import structlog

from app.services.nettools.schemas import (
    CommandResult,
    assert_target_allowed,
    resolve_checked_target,
    validate_host,
)

logger = structlog.get_logger(__name__)


class NetToolArgError(ValueError):
    """Raised when a runner's inputs fail validation."""


# Hard ceiling for any single tool invocation. Generous enough for an
# mtr report cycle or a slow traceroute, tight enough to finish under
# the frontend proxy timeout (nginx defaults to 60s; we stay well below).
_DEFAULT_TIMEOUT_SECONDS: Final[float] = 30.0

# Cap the captured output so a pathological tool can't blow out the
# response. 256 KiB is far more than any of these tools emit normally.
_MAX_OUTPUT_BYTES: Final[int] = 256 * 1024

# dig record types we pass through. Kept in lockstep with the schema's
# allowlist; the runner re-checks so a direct service caller can't slip
# an arbitrary token into the argv.
_VALID_DIG_TYPES: Final[frozenset[str]] = frozenset(
    {
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "TXT",
        "NS",
        "SOA",
        "PTR",
        "SRV",
        "CAA",
        "TLSA",
        "DS",
        "DNSKEY",
        "NAPTR",
        "ANY",
    }
)

_DNS_NAME_RE: Final = re.compile(r"^[A-Za-z0-9_.-]{1,253}$")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def _run(
    tool: str,
    argv: list[str],
    *,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> CommandResult:
    """Spawn ``argv`` (no shell), capture stdout/stderr, enforce a hard
    timeout, and return a uniform :class:`CommandResult`.

    A missing binary yields ``available=False`` with a clean message
    instead of raising — the caller surfaces it as a 200 so the UI can
    render "this tool isn't installed in the api image" rather than an
    opaque 500.
    """
    started = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        logger.warning("nettool_binary_missing", tool=tool, binary=argv[0])
        return CommandResult(
            tool=tool,
            argv=argv,
            available=False,
            error=(
                f"'{argv[0]}' is not installed in the api container image. "
                "This tool is unavailable on this deployment."
            ),
        )
    except OSError as exc:  # pragma: no cover — spawn-level failure
        logger.warning("nettool_spawn_failed", tool=tool, error=str(exc))
        return CommandResult(
            tool=tool,
            argv=argv,
            available=False,
            error=f"failed to spawn '{argv[0]}': {exc}",
        )

    try:
        out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
    except TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:  # pragma: no cover — race
            pass
        duration_ms = (time.perf_counter() - started) * 1000.0
        logger.info("nettool_timeout", tool=tool, timeout_s=timeout_seconds)
        return CommandResult(
            tool=tool,
            argv=argv,
            available=True,
            timed_out=True,
            duration_ms=duration_ms,
            error=f"{tool} exceeded the {timeout_seconds:.0f}s timeout",
        )

    duration_ms = (time.perf_counter() - started) * 1000.0
    stdout = out_b[:_MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
    stderr = err_b[:_MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
    return CommandResult(
        tool=tool,
        argv=argv,
        available=True,
        exit_code=proc.returncode,
        duration_ms=duration_ms,
        stdout=stdout,
        stderr=stderr,
    )


async def _checked_address(tool: str, host: str) -> tuple[str | None, CommandResult | None]:
    """Resolve ``host`` in the backend and refuse a blocked answer.

    Returns ``(address, None)`` when the name is fine: the caller hands the
    binary the address that was checked, never the name, so the binary cannot
    resolve it to something else. A blocked answer raises ``NetToolArgError``
    (the handlers answer 422); a name that does not resolve is an ordinary
    result with the reason in ``error``.
    """
    addr, err = await resolve_checked_target(host)
    if addr is not None:
        return addr, None
    reason = err or "target could not be resolved"
    if "blocked range" in reason:
        raise NetToolArgError(reason)
    return None, CommandResult(tool=tool, argv=[], available=True, error=reason)


# ── ping ────────────────────────────────────────────────────────────


def build_ping_argv(host: str, *, count: int = 4) -> list[str]:
    target = validate_host(host)
    if not 1 <= count <= 10:
        raise NetToolArgError("count must be between 1 and 10")
    # -c <count> bounded packets, -w <deadline> overall, -n numeric only
    # (no reverse-DNS so output is deterministic + fast). ``-4``/``-6``
    # auto-selected by iputils based on the literal; we don't force it so
    # a hostname can resolve to either family.
    return ["ping", "-n", "-c", str(count), "-w", "15", target]


async def run_ping(host: str, *, count: int = 4) -> CommandResult:
    target = validate_host(host)
    addr, failed = await _checked_address("ping", target)
    if failed is not None or addr is None:
        return failed or CommandResult(tool="ping", argv=[], available=True)
    argv = build_ping_argv(addr, count=count)
    return await _run("ping", argv, timeout_seconds=20.0)


# ── traceroute ──────────────────────────────────────────────────────


def build_traceroute_argv(host: str, *, max_hops: int = 20) -> list[str]:
    target = validate_host(host)
    if not 1 <= max_hops <= 30:
        raise NetToolArgError("max_hops must be between 1 and 30")
    # -n numeric, -m bounded hops, -w 2s per-probe wait, -q 1 single
    # probe per hop to keep wall-clock down.
    return ["traceroute", "-n", "-m", str(max_hops), "-w", "2", "-q", "1", target]


async def run_traceroute(host: str, *, max_hops: int = 20) -> CommandResult:
    target = validate_host(host)
    addr, failed = await _checked_address("traceroute", target)
    if failed is not None or addr is None:
        return failed or CommandResult(tool="traceroute", argv=[], available=True)
    argv = build_traceroute_argv(addr, max_hops=max_hops)
    return await _run("traceroute", argv, timeout_seconds=_DEFAULT_TIMEOUT_SECONDS)


# ── mtr ─────────────────────────────────────────────────────────────


def build_mtr_argv(host: str, *, cycles: int = 5, max_hops: int = 20) -> list[str]:
    target = validate_host(host)
    if not 1 <= cycles <= 10:
        raise NetToolArgError("cycles must be between 1 and 10")
    if not 1 <= max_hops <= 30:
        raise NetToolArgError("max_hops must be between 1 and 30")
    # --report runs a fixed number of cycles then exits (vs the live
    # curses UI); --report-cycles keeps it small; -n numeric; -m bounded
    # hops. mtr needs CAP_NET_RAW for ICMP — in the api container it
    # isn't granted, so mtr-tiny falls back to UDP probes (works for the
    # report). If it can't probe at all the exit code surfaces it.
    return [
        "mtr",
        "--report",
        "--report-wide",
        "-n",
        "-c",
        str(cycles),
        "-m",
        str(max_hops),
        target,
    ]


async def run_mtr(host: str, *, cycles: int = 5, max_hops: int = 20) -> CommandResult:
    target = validate_host(host)
    addr, failed = await _checked_address("mtr", target)
    if failed is not None or addr is None:
        return failed or CommandResult(tool="mtr", argv=[], available=True)
    argv = build_mtr_argv(addr, cycles=cycles, max_hops=max_hops)
    return await _run("mtr", argv, timeout_seconds=_DEFAULT_TIMEOUT_SECONDS)


# ── dig ─────────────────────────────────────────────────────────────


def build_dig_argv(name: str, record_type: str, server: str | None = None) -> list[str]:
    name = name.strip()
    # dig has no ``--`` end-of-options terminator, so a ``name`` or
    # ``@server`` that begins with '-' would be parsed by dig as a flag
    # (``-f`` batch-mode reads queries from a filesystem path, ``-k``/``-x``
    # toggle behaviour, etc). Reject leading-dash here unconditionally —
    # this runner is the documented re-validation point, so it must be
    # safe regardless of which caller built the inputs (the REST schema
    # blocks it, but the MCP path historically did not). The _DNS_NAME_RE
    # match below already forbids spaces; the explicit leading-dash check
    # is the security guard.
    if name.startswith("-"):
        raise NetToolArgError(f"name may not start with '-': {name!r}")
    if not name or not _DNS_NAME_RE.match(name):
        raise NetToolArgError(f"name is not a valid DNS name: {name!r}")
    rtype = record_type.strip().upper()
    if rtype not in _VALID_DIG_TYPES:
        raise NetToolArgError(f"unsupported record type: {record_type!r}")
    argv = [
        "dig",
        "+nocmd",
        "+noall",
        "+answer",
        "+authority",
        "+comments",
        "+timeout=3",
        "+tries=2",
    ]
    if server is not None:
        srv = server.strip()
        if srv.startswith("-"):
            raise NetToolArgError(f"server may not start with '-': {srv!r}")
        # SSRF guard — a dig @server that targets loopback / link-local
        # (incl. the cloud metadata IP) is a defence-in-depth block.
        # ``assert_target_allowed`` raises a plain ``ValueError``; re-wrap
        # as ``NetToolArgError`` so the runner's single arg-error type
        # flows through the REST handler's ``except NetToolArgError`` →
        # 422 path rather than escaping as an unhandled 500.
        try:
            srv = assert_target_allowed(srv)
        except ValueError as exc:
            raise NetToolArgError(str(exc)) from exc
        argv.append(f"@{srv}")
    argv.extend([name, rtype])
    return argv


async def run_dig(name: str, record_type: str, server: str | None = None) -> CommandResult:
    if server is not None and server.strip():
        # Build once with the name so a malformed server or query is refused
        # first, then query the address that was checked instead of the name.
        build_dig_argv(name, record_type, server)
        addr, failed = await _checked_address("dig", server.strip())
        if failed is not None or addr is None:
            return failed or CommandResult(tool="dig", argv=[], available=True)
        server = addr
    argv = build_dig_argv(name, record_type, server)
    return await _run("dig", argv, timeout_seconds=15.0)


# ── whois ───────────────────────────────────────────────────────────


def build_whois_argv(query: str) -> list[str]:
    query = query.strip()
    if not query:
        raise NetToolArgError("query is required")
    # Accept IP / domain / ASN. ASN form ("AS13335" or bare digits) is
    # validated loosely; otherwise it must be a host literal / hostname.
    if re.fullmatch(r"(?i:as)?\d{1,10}", query):
        validated = query
    elif _is_ip(query):
        validated = query
    else:
        validated = validate_host(query)
    # ``--`` terminates option parsing so a query that happens to start
    # with '-' can never be read as a whois flag.
    return ["whois", "--", validated]


async def run_whois(query: str) -> CommandResult:
    argv = build_whois_argv(query)
    return await _run("whois", argv, timeout_seconds=_DEFAULT_TIMEOUT_SECONDS)


__all__ = [
    "NetToolArgError",
    "build_dig_argv",
    "build_mtr_argv",
    "build_ping_argv",
    "build_traceroute_argv",
    "build_whois_argv",
    "run_dig",
    "run_mtr",
    "run_ping",
    "run_traceroute",
    "run_whois",
]
