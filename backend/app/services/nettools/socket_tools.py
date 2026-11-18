"""Pure-Python network tools — no subprocess (issue #58).

Two tools:

* :func:`test_port` — open a TCP connection (or send a UDP datagram) to
  ``host:port`` and classify the result. TCP gives a definitive
  open/closed/filtered answer; UDP can only ever be
  ``open|filtered`` vs ``closed`` (ICMP port-unreachable), so we report
  the honest two-state result.
* :func:`inspect_tls_cert` — open a TLS connection with certificate
  verification *disabled* (we want to inspect whatever the server
  presents, including expired / self-signed certs), pull the DER, and
  parse subject / SAN / issuer / validity via ``cryptography.x509``.
  Hostname-match is computed separately so we can report a mismatch
  without failing the inspection.

Both are server-perspective and stateless.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from datetime import UTC, datetime

import structlog
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from app.services.nettools.schemas import (
    PortTestResult,
    TlsCertResult,
    resolve_checked_target,
)

logger = structlog.get_logger(__name__)


# ── port test ───────────────────────────────────────────────────────


async def _test_tcp(host: str, port: int, timeout: float) -> PortTestResult:
    started = time.perf_counter()
    try:
        fut = asyncio.open_connection(host, port)
        _reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        rtt_ms = (time.perf_counter() - started) * 1000.0
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 — close best-effort
            pass
        return PortTestResult(host=host, port=port, protocol="tcp", state="open", rtt_ms=rtt_ms)
    except TimeoutError:
        # No SYN-ACK and no RST within the window → firewalled / dropped.
        return PortTestResult(
            host=host,
            port=port,
            protocol="tcp",
            state="filtered",
            error=f"no response within {timeout:.1f}s (filtered / dropped)",
        )
    except ConnectionRefusedError:
        rtt_ms = (time.perf_counter() - started) * 1000.0
        return PortTestResult(host=host, port=port, protocol="tcp", state="closed", rtt_ms=rtt_ms)
    except (OSError, socket.gaierror) as exc:
        return PortTestResult(host=host, port=port, protocol="tcp", state="error", error=str(exc))


async def _test_udp(host: str, port: int, timeout: float) -> PortTestResult:
    """UDP probe — send an empty datagram and wait for an ICMP
    port-unreachable. No reply within the window is the ``open|filtered``
    ambiguity inherent to UDP; an ECONNREFUSED (ICMP unreachable
    surfaced by the kernel) means ``closed``.
    """
    loop = asyncio.get_running_loop()
    started = time.perf_counter()

    class _Proto(asyncio.DatagramProtocol):
        def __init__(self) -> None:
            self.error: Exception | None = None

        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            transport.sendto(b"")  # type: ignore[attr-defined]

        def error_received(self, exc: Exception) -> None:
            # ICMP port-unreachable arrives here as ConnectionRefusedError.
            self.error = exc

    try:
        transport, proto = await asyncio.wait_for(
            loop.create_datagram_endpoint(_Proto, remote_addr=(host, port)),
            timeout=timeout,
        )
    except (OSError, socket.gaierror) as exc:
        return PortTestResult(host=host, port=port, protocol="udp", state="error", error=str(exc))
    try:
        # Give the kernel a brief window to surface an ICMP unreachable.
        await asyncio.sleep(min(timeout, 2.0))
        if isinstance(proto.error, ConnectionRefusedError):
            rtt_ms = (time.perf_counter() - started) * 1000.0
            return PortTestResult(
                host=host, port=port, protocol="udp", state="closed", rtt_ms=rtt_ms
            )
        return PortTestResult(
            host=host,
            port=port,
            protocol="udp",
            state="open|filtered",
            error="no ICMP unreachable — UDP cannot distinguish open from filtered",
        )
    finally:
        transport.close()


async def test_port(host: str, port: int, protocol: str, timeout: float = 5.0) -> PortTestResult:
    """Classify the reachability of ``host:port``. Server-perspective.

    Defence in depth — re-checks the SSRF denylist here (the REST schema
    already validates, but MCP callers reach this function directly). A
    blocked-range IP literal returns a clean ``state="error"`` rather
    than ever opening the socket.
    """
    addr, err = await resolve_checked_target(host)
    if addr is None:
        return PortTestResult(
            host=host,
            port=port,
            protocol=protocol if protocol in {"tcp", "udp"} else "tcp",
            state="error",
            error=err,
        )
    # Connect to the address that passed the check, not the name.
    if protocol == "udp":
        result = await _test_udp(addr, port, timeout)
    else:
        result = await _test_tcp(addr, port, timeout)
    result.host = host
    return result


# ── TLS certificate inspection ──────────────────────────────────────


def _rfc4514(name: x509.Name) -> str:
    try:
        return name.rfc4514_string()
    except Exception:  # noqa: BLE001 — exotic name encodings
        return str(name)


def _common_names(name: x509.Name) -> list[str]:
    return [
        a.value
        for a in name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if isinstance(a.value, str)
    ]


def _san_dns_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = ext.value
        names = list(san.get_values_for_type(x509.DNSName))
        # Include IP SANs as strings too.
        names += [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
        return names
    except x509.ExtensionNotFound:
        return []


def _hostname_matches(server_name: str, san: list[str], cn: list[str]) -> bool:
    candidates = san or cn
    sn = server_name.lower().rstrip(".")
    for c in candidates:
        c = c.lower().rstrip(".")
        if c == sn:
            return True
        if c.startswith("*."):
            # Wildcard matches exactly one left-most label.
            suffix = c[1:]  # ".example.com"
            host_parts = sn.split(".", 1)
            if len(host_parts) == 2 and "." + host_parts[1] == suffix:
                return True
    return False


def _parse_cert(der: bytes, server_name: str) -> dict[str, object]:
    cert = x509.load_der_x509_certificate(der)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    now = datetime.now(UTC)
    days_remaining = (not_after - now).days
    san = _san_dns_names(cert)
    cn = _common_names(cert.subject)
    self_signed = _rfc4514(cert.subject) == _rfc4514(cert.issuer)
    try:
        sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:  # noqa: BLE001
        sig_alg = None
    fingerprint_serial = format(cert.serial_number, "x")
    return {
        "subject": _rfc4514(cert.subject),
        "issuer": _rfc4514(cert.issuer),
        "san": san,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": days_remaining,
        "expired": now > not_after or now < not_before,
        "self_signed": self_signed,
        "hostname_matches": _hostname_matches(server_name, san, cn),
        "serial": fingerprint_serial,
        "signature_algorithm": sig_alg,
    }


async def inspect_tls_cert(
    host: str,
    port: int,
    server_name: str | None,
    timeout: float = 8.0,
) -> TlsCertResult:
    """Connect to ``host:port`` over TLS (verification disabled, for
    inspection), fetch the leaf certificate, and parse it.

    We deliberately turn off ``check_hostname`` + verification so we can
    inspect expired / self-signed / mismatched certs — the operator's
    whole reason for reaching for this tool is often "why is this cert
    broken?". ``hostname_matches`` / ``expired`` / ``self_signed`` are
    reported as data, not enforced.
    """
    sni = server_name or host
    # Defence in depth — block loopback / link-local / metadata literals
    # here too, since MCP callers reach this function without the REST
    # schema validation.
    addr, err = await resolve_checked_target(host)
    if addr is None:
        return TlsCertResult(host=host, port=port, server_name=sni, ok=False, error=err)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        fut = asyncio.open_connection(addr, port, ssl=ctx, server_hostname=sni)
        _reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except TimeoutError:
        return TlsCertResult(
            host=host,
            port=port,
            server_name=sni,
            ok=False,
            error=f"TLS handshake timed out after {timeout:.1f}s",
        )
    except (ssl.SSLError, OSError, socket.gaierror) as exc:
        return TlsCertResult(
            host=host,
            port=port,
            server_name=sni,
            ok=False,
            error=f"TLS connection failed: {exc}",
        )

    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        der = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
        if not der:
            return TlsCertResult(
                host=host,
                port=port,
                server_name=sni,
                ok=False,
                error="server presented no certificate",
            )
        parsed = _parse_cert(der, sni)
        return TlsCertResult(host=host, port=port, server_name=sni, ok=True, **parsed)  # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001 — surface parse failures cleanly
        logger.warning("tls_cert_parse_failed", host=host, error=str(exc))
        return TlsCertResult(
            host=host,
            port=port,
            server_name=sni,
            ok=False,
            error=f"failed to parse certificate: {exc}",
        )
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


__all__ = ["inspect_tls_cert", "test_port"]
