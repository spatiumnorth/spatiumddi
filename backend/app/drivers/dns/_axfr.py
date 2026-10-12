"""Shared AXFR helper used by BIND9 + Windows DNS drivers.

Both drivers implement ``pull_zone_records`` by doing a standard AXFR over
TCP/53 and walking the returned zone. The only thing that differs is the
driver name in log lines — the wire protocol and the rdata shaping are
identical. Keep this in one place so they can't drift.

Also home to :func:`resolve_server_address`, shared with the RFC 2136 write
paths — see its docstring for why every ``dnspython`` call site needs it.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any

import structlog

from app.drivers.dns.base import RecordData, TsigKey

logger = structlog.get_logger(__name__)


def resolve_server_address(host: str, port: int, *, what: str) -> list[str]:
    """Return IP literals for ``host``, in the order to try them.

    Every low-level ``dnspython`` entry point we use — ``dns.query.xfr`` for
    transfers, ``dns.query.tcp`` for RFC 2136 updates — takes an IP *literal*,
    not a name. Each calls ``dns.inet.af_for_address(where)`` up front to pick
    the address family, and that raises a **bare, message-less**
    ``ValueError()`` for anything that doesn't parse as an address, before a
    single packet leaves the box.

    So any ``DNSServer.host`` holding a hostname — which is every
    containerised deployment and most others — failed 100% of the time, and
    the reason surfaced to the operator was the empty string. Resolve here and
    hand dnspython an address.

    ``what`` is the operation description used to prefix errors, e.g.
    ``"AXFR of example.com."``.
    """
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return [host]

    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise RuntimeError(
            f"{what} from {host}:{port} failed: could not resolve {host!r} ({exc})."
        ) from exc

    # Preserve getaddrinfo's ordering (RFC 6724 / system policy) but drop
    # duplicates — a dual-stack host commonly returns the same address for
    # both SOCK_STREAM and SOCK_DGRAM entries.
    addrs: list[str] = []
    for info in infos:
        addr = str(info[4][0])
        if addr not in addrs:
            addrs.append(addr)
    if not addrs:
        raise RuntimeError(f"{what} from {host}:{port} failed: {host!r} resolved to no addresses.")
    return addrs


def _hint(exc: BaseException, port: int) -> str:
    """Return a next-step hint matched to *why* the transfer failed.

    An unconditional "check allow-transfer" is worse than no hint at all when
    the real problem is that the host is unreachable — it sends the operator
    to the DNS config of a box they can't even open a socket to. Only mention
    the transfer ACL when the server actually answered and said no.
    """
    text = str(exc).upper()
    if isinstance(exc, TimeoutError) or "TIMED OUT" in text or "TIMEOUT" in text:
        return (
            f" The server did not answer in time — check that it is running and that "
            f"TCP/{port} is open (a transfer needs TCP, not just UDP)."
        )
    if isinstance(exc, OSError):
        # Connection refused / no route / network unreachable: we never got a
        # DNS-level answer, so the transfer ACL is not what's in the way.
        return f" The server could not be reached on TCP/{port} — check the address and firewall."
    if "REFUSED" in text or "NOTAUTH" in text:
        return (
            " The server answered but declined the transfer — check that its "
            "allow-transfer permits the SpatiumDDI control plane, and that it is "
            "authoritative for this zone."
        )
    # A signed transfer the server rejected on the signature itself. Sending
    # the operator to allow-transfer here would be actively wrong — the ACL
    # matched, the key didn't. dnspython signals these by exception TYPE and
    # its messages carry none of the RCODE mnemonics, so match the class
    # name: verified live, a wrong secret raises PeerBadSignature ("The peer
    # didn't like the signature we sent") and a wrong algorithm raises
    # PeerBadKey ("The peer didn't know the key we used").
    if type(exc).__name__ in {"PeerBadSignature", "PeerBadKey", "PeerBadTime", "BadSignature"}:
        return (
            " The server rejected the TSIG signature — check that the group's key "
            "name, secret and algorithm match the ones the agent was given, and "
            "that the two clocks agree (TSIG allows a 5-minute skew)."
        )
    return (
        f" Check that the server's allow-transfer permits the SpatiumDDI control "
        f"plane and that TCP/{port} is reachable."
    )


# Signing artefacts the authoritative server generates and owns. Never
# modelled as SpatiumDDI records, so they must not surface as drift.
_DNSSEC_ARTEFACTS = frozenset({"RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "DNSKEY", "CDS", "CDNSKEY"})


async def axfr_zone_records(
    *,
    host: str,
    port: int,
    zone_name: str,
    timeout: int = 20,
    log_driver: str = "dns",
    server_id: str | None = None,
    tsig: TsigKey | None = None,
) -> list[RecordData]:
    """AXFR ``zone_name`` from ``host:port`` and return neutral record dicts.

    Apex SOA and NS are filtered out — SpatiumDDI manages those at the zone
    level, so importing them as user records would create duplicate control
    surfaces. Out-of-zone glue (an NS target living in a different zone) is
    also skipped, as are DNSSEC signing artefacts (RRSIG / NSEC* / DNSKEY /
    CDS / CDNSKEY), which the signing server owns and rotates itself.

    ``tsig`` signs the transfer (#734). Agent-managed BIND9 and Technitium
    grant ``allow-transfer`` to the group's TSIG key rather than to a source
    address — the control plane's address is not knowable on the appliance —
    so an unsigned transfer is REFUSED there 100% of the time. Callers that
    have group context resolve the key and pass it; the parameter stays
    optional because the Windows Path A and cloud callers have no key and
    are authorised by address instead.

    A key that cannot be turned into a keyring raises rather than falling
    back to an unsigned transfer: silently degrading would turn a
    configuration error into the same permanent REFUSED this exists to fix.
    """
    import dns.name  # noqa: PLC0415
    import dns.query  # noqa: PLC0415
    import dns.rdatatype  # noqa: PLC0415
    import dns.tsig  # noqa: PLC0415
    import dns.zone  # noqa: PLC0415

    zone_origin = dns.name.from_text(zone_name)

    what = f"AXFR of {zone_name}"

    sign_kwargs: dict[str, Any] = {}
    if tsig is not None:
        try:
            keyname = dns.name.from_text(tsig.name)
            keyalgorithm = dns.name.from_text(tsig.algorithm)
            # Build the Key explicitly rather than via ``tsigkeyring.from_text``,
            # which yields ``{name: bytes}`` and so carries no algorithm at all.
            key = dns.tsig.Key(keyname, tsig.secret, algorithm=keyalgorithm)
            # An unknown algorithm is caught by NOTHING above: ``from_text``
            # and ``Key`` both accept "hmac-nonsense" happily, because it is a
            # perfectly valid DNS *name*. It only fails much later, inside the
            # signing call. ``get_context`` is the earliest hook that rejects
            # it, so probe here to keep the failure attributable to the key
            # rather than surfacing as an opaque mid-transfer error.
            dns.tsig.get_context(key)
            sign_kwargs = {
                "keyring": {keyname: key},
                "keyname": keyname,
                "keyalgorithm": keyalgorithm,
            }
        except Exception as exc:
            # Bad base64 secret, or an algorithm dnspython doesn't know.
            # Both are operator-fixable configuration, and neither should
            # be papered over by transferring unsigned.
            raise RuntimeError(
                f"{what} from {host}:{port} failed: TSIG key {tsig.name!r} is "
                f"unusable ({type(exc).__name__}: {exc}). Check the key's secret "
                f"is valid base64 and that {tsig.algorithm!r} is a supported algorithm."
            ) from exc

    def _axfr() -> dns.zone.Zone:
        # A dual-stack host can resolve to an address that isn't the one
        # permitted by allow-transfer (or isn't routable from here at all).
        # An AXFR is a read with no side effects, so walking the candidate
        # list is safe — try each and report the last failure if none work.
        addrs = resolve_server_address(host, port, what=what)
        last: Exception | None = None
        for addr in addrs:
            try:
                return dns.zone.from_xfr(
                    dns.query.xfr(addr, zone_origin, port=port, timeout=timeout, **sign_kwargs)
                )
            except Exception as exc:  # noqa: PERF203 — retry the next address
                last = exc
        assert last is not None  # resolve_server_address never returns []
        raise last

    try:
        z = await asyncio.to_thread(_axfr)
    except RuntimeError:
        raise  # already carries a specific, operator-readable message
    except Exception as exc:
        # dnspython also raises message-less exceptions for a refused or
        # malformed transfer, so ``str(exc)`` is routinely "". Never let a
        # blank reason reach the operator — drift reports and pull-imports
        # both surface this string verbatim.
        detail = str(exc).strip() or type(exc).__name__
        raise RuntimeError(
            f"{what} from {host}:{port} failed: {detail}.{_hint(exc, port)}"
        ) from exc

    def _absolutize(target: Any) -> str:
        """Return ``target`` as its absolute form with trailing dot.

        dnspython's ``from_xfr`` relativizes names; for in-zone CNAME / MX
        exchange / SRV target / NS / PTR the rdata target is relative.
        ``to_text()`` on a relative target gives the bare label ("host")
        while the rest of SpatiumDDI stores FQDNs ("host.zone.example.").
        The two are equivalent on the wire but diverge when the pull
        importer dedups by raw string match — always emit absolute form
        so everything downstream sees one representation.
        """
        if target.is_absolute():
            return target.to_text()
        return target.derelativize(zone_origin).to_text()

    out: list[RecordData] = []
    for name, node in z.items():
        rel = name.relativize(zone_origin)
        if rel.is_absolute():
            logger.debug(
                f"{log_driver}.skipping_out_of_zone_record",
                zone=zone_name,
                name=name.to_text(),
            )
            continue
        rel_label = "@" if rel == dns.name.empty else rel.to_text()
        for rdataset in node.rdatasets:
            rtype = dns.rdatatype.to_text(rdataset.rdtype)
            if rtype == "SOA":
                continue
            if rtype == "NS" and rel_label == "@":
                continue
            if rtype in _DNSSEC_ARTEFACTS:
                # The daemon owns these — it mints them when the zone is
                # signed and rotates them on its own schedule. They exist
                # on the wire but never as SpatiumDDI records, so a drift
                # report would list every signature as "extra on server"
                # and a signed zone could never read as in sync. Affects
                # every AXFR caller, not one driver.
                continue
            for rdata in rdataset:
                priority: int | None = None
                weight: int | None = None
                port_field: int | None = None
                if rtype == "CNAME":
                    value = _absolutize(rdata.target)
                elif rtype == "NS":
                    value = _absolutize(rdata.target)
                elif rtype == "PTR":
                    value = _absolutize(rdata.target)
                elif rtype == "MX":
                    priority = rdata.preference
                    value = _absolutize(rdata.exchange)
                elif rtype == "SRV":
                    priority = rdata.priority
                    weight = rdata.weight
                    port_field = rdata.port
                    value = _absolutize(rdata.target)
                elif rtype == "TXT":
                    value = "".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
                elif rtype in ("SVCB", "HTTPS"):
                    # Same reason as ``_absolutize``: ``to_text()`` on a
                    # relativized in-zone target gives ``svc``, which reads
                    # as a different record from a stored ``svc.zone.``
                    # (#1513). Derelativize so the target is unambiguous.
                    value = rdata.to_text(origin=zone_origin, relativize=False)
                else:
                    value = rdata.to_text()
                out.append(
                    RecordData(
                        name=rel_label,
                        record_type=rtype,
                        value=value,
                        ttl=int(rdataset.ttl) if rdataset.ttl else None,
                        priority=priority,
                        weight=weight,
                        port=port_field,
                    )
                )
    logger.info(
        f"{log_driver}.pull_zone_records",
        server=server_id or "",
        host=host,
        zone=zone_name,
        count=len(out),
        signed=tsig is not None,
    )
    return out


__all__ = ["axfr_zone_records"]
