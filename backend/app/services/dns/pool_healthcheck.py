"""DNS pool health-check engine.

Runs per-member checks (``tcp | http | https | icmp``) and updates
``DNSPoolMember`` state based on the consecutive-success / -failure
thresholds. Members that flip state trigger the pool apply-state
service to add or remove the corresponding ``DNSRecord`` rows so the
rendered record set reflects only healthy + enabled members.

ICMP shells out to ``/bin/ping`` (Debian's iputils-ping) which ships
with ``cap_net_raw+ep`` so the non-root app user can fire ICMP
echo-requests without ``CAP_NET_RAW`` on the container. The API
Dockerfile installs the package explicitly.

Where the checks run: from the API process (Celery worker container).
Phase 2 = delegate to a chosen DNS agent (matters for split-horizon
setups + private-network targets the API can't reach).
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass

import httpx
import structlog

from app.core.exc_text import describe_http_exc
from app.models.dns import DNSPool, DNSPoolMember

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class CheckResult:
    """Outcome of one health probe against one member."""

    healthy: bool
    error: str | None


async def run_check(pool: DNSPool, member: DNSPoolMember) -> CheckResult:
    """Run a single health probe and return success/failure.

    The check type and tuning come from the pool; ``hc_type=none`` is
    a special case that always reports healthy (operator opted out of
    health checks but still wants the pool's record-set semantics).
    """
    hc_type = (pool.hc_type or "tcp").lower()
    timeout = max(1, int(pool.hc_timeout_seconds or 5))

    if hc_type == "none":
        return CheckResult(healthy=True, error=None)

    if hc_type == "tcp":
        port = pool.hc_target_port
        if port is None:
            return CheckResult(healthy=False, error="tcp check requires hc_target_port")
        return await _check_tcp(member.address, int(port), timeout)

    if hc_type in ("http", "https"):
        return await _check_http(
            address=member.address,
            scheme=hc_type,
            port=pool.hc_target_port,
            path=pool.hc_path or "/",
            method=(pool.hc_method or "GET").upper(),
            expected=set(pool.hc_expected_status_codes or []),
            timeout=timeout,
            verify_tls=bool(pool.hc_verify_tls),
        )

    if hc_type == "icmp":
        return await _check_icmp(member.address, timeout)

    return CheckResult(healthy=False, error=f"unknown hc_type {hc_type!r}")


async def _check_tcp(address: str, port: int, timeout: int) -> CheckResult:
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(address, port)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, OSError):
                # Some peers RST on close; we still got the connection.
                pass
            _ = reader
            return CheckResult(healthy=True, error=None)
    except TimeoutError:
        return CheckResult(healthy=False, error=f"tcp timeout ({timeout}s)")
    except (OSError, socket.gaierror) as exc:
        return CheckResult(healthy=False, error=f"tcp error: {exc}")


async def _check_icmp(address: str, timeout: int) -> CheckResult:
    """One ICMP echo-request via ``/bin/ping``.

    ``ping -c 1 -W <timeout> <addr>`` exits 0 on a single reply, 1 if
    the host doesn't reply within ``timeout`` seconds, and >1 on a hard
    error (unknown host, network unreachable, etc). We map all non-zero
    exits to unhealthy with stderr captured for the operator-facing
    ``last_check_error``.

    Picks ping vs ping6 by literal address family — ping handles IPv4
    only on Debian, ping6 is the IPv6 counterpart.
    """
    cmd = "ping6" if ":" in address else "ping"
    try:
        proc = await asyncio.create_subprocess_exec(
            cmd,
            "-c",
            "1",
            "-W",
            str(timeout),
            address,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            async with asyncio.timeout(timeout + 2):
                _, stderr = await proc.communicate()
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return CheckResult(healthy=False, error=f"icmp timeout ({timeout}s)")
        if proc.returncode == 0:
            return CheckResult(healthy=True, error=None)
        msg = (stderr.decode("utf-8", errors="replace").strip().splitlines() or [""])[0]
        return CheckResult(
            healthy=False,
            error=f"icmp unreachable: {msg}" if msg else "icmp unreachable",
        )
    except FileNotFoundError:
        return CheckResult(
            healthy=False,
            error=f"{cmd} binary not found in api image",
        )
    except OSError as exc:
        return CheckResult(healthy=False, error=f"icmp error: {exc}")


async def _check_http(
    *,
    address: str,
    scheme: str,
    port: int | None,
    path: str,
    method: str,
    expected: set[int],
    timeout: int,
    verify_tls: bool,
) -> CheckResult:
    """One HTTP / HTTPS request.

    ``verify_tls`` only matters for ``https``. When True, httpx uses the
    system trust store + hostname matching, so self-signed or mismatched
    certs fail the check explicitly with a TLS error in
    ``last_check_error``. When False (default), TLS is established but
    not verified — appropriate for internal pool members that ship
    self-signed certs.
    """
    if not expected:
        # Default = "any 2xx or 3xx" if the operator left the list empty.
        expected = {200, 201, 202, 204, 301, 302, 304}
    if not path.startswith("/"):
        path = "/" + path
    if port is None:
        port = 443 if scheme == "https" else 80
    url = f"{scheme}://{address}:{port}{path}"
    # ``verify`` only meaningful on HTTPS; passing False to a plain HTTP
    # client is harmless but keeps the surface tight.
    verify = bool(verify_tls) if scheme == "https" else True
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            verify=verify,  # noqa: S501 — opt-in; default off for internal LAN members
        ) as client:
            resp = await client.request(method, url)
        if resp.status_code in expected:
            return CheckResult(healthy=True, error=None)
        return CheckResult(
            healthy=False,
            error=f"http {resp.status_code} not in expected {sorted(expected)}",
        )
    except httpx.TimeoutException:
        return CheckResult(healthy=False, error=f"http timeout ({timeout}s)")
    except (httpx.HTTPError, OSError) as exc:
        return CheckResult(healthy=False, error=f"http error: {describe_http_exc(exc)}")


@dataclass(frozen=True)
class StateChange:
    """How a member's state changed after a check."""

    member_id: str
    address: str
    new_state: str
    previous_state: str
    transitioned: bool


def apply_check_to_member(
    member: DNSPoolMember,
    result: CheckResult,
    *,
    unhealthy_threshold: int,
    healthy_threshold: int,
) -> StateChange:
    """Update member counters + state based on a single check result.

    State transitions only happen after ``consecutive_*_threshold``
    matching results in a row, so a single flapping check doesn't
    churn DNS records.
    """
    previous_state = member.last_check_state or "unknown"

    if result.healthy:
        member.consecutive_successes = (member.consecutive_successes or 0) + 1
        member.consecutive_failures = 0
        member.last_check_error = None
        if previous_state != "healthy" and member.consecutive_successes >= max(
            1, healthy_threshold
        ):
            new_state = "healthy"
        else:
            new_state = previous_state if previous_state != "unknown" else "healthy"
    else:
        member.consecutive_failures = (member.consecutive_failures or 0) + 1
        member.consecutive_successes = 0
        member.last_check_error = result.error
        if previous_state != "unhealthy" and member.consecutive_failures >= max(
            1, unhealthy_threshold
        ):
            new_state = "unhealthy"
        else:
            new_state = previous_state if previous_state != "unknown" else "unhealthy"

    transitioned = new_state != previous_state
    member.last_check_state = new_state

    return StateChange(
        member_id=str(member.id),
        address=member.address,
        new_state=new_state,
        previous_state=previous_state,
        transitioned=transitioned,
    )
