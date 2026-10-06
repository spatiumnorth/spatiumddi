"""Ingest-back worker — reads externally-injected DDNS records off the live
zone and ships them to the control plane (issue #641, Alt.1).

When an operator enables dynamic updates on a zone, a third-party writer
(an AD domain controller, a DHCP server) can inject records straight into
the running daemon over RFC 2136. Those records live only in the daemon;
the control plane, which treats the DB as truth, would drop them on a full
re-render. This worker closes the loop:

* Every ``INGEST_INTERVAL`` seconds it reads the cached config bundle to
  find zones with ``dynamic_update_enabled``.
* For each one it reads the live zone back from the daemon — BIND9 via a
  loopback AXFR signed with the group loopback TSIG key (the zone stanza
  grants ``allow-transfer { key … }`` for exactly this — nothing is opened
  to the network), PowerDNS via ``GET /zones/{zone}`` on its loopback REST
  API, authenticated with the same API key the driver manages.
* It ships the full live record set (minus SOA / apex-NS / DNSSEC RRs the
  daemon owns) to ``/api/v1/dns/agents/ingested-records``. The control
  plane filters out anything it manages and mirrors the rest as
  ``import_source="ddns_external"`` rows, so the records become
  UI/IPAM-visible and survive a re-render.

Sending the whole zone (rather than an agent-side diff) keeps this robust:
rdata-formatting differences between the daemon's output and the DB's
stored value can't cause churn, because the control plane dedupes by
managed ``(name, type)`` — a formatting mismatch on a managed record is
skipped there, not double-created here.

PowerDNS support is issue #1524: before it, the worker ran only for
BIND9, so RFC 2136 records written to a PowerDNS zone never appeared in
SpatiumDDI at all — and where an external value shared a (name, type)
with a managed rrset, the next reconcile REPLACEd it away silently.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
from typing import Any

import httpx
import structlog

from .cache import load_config
from .config import AgentConfig

log = structlog.get_logger(__name__)

INGEST_INTERVAL = 180.0  # seconds between AXFR sweeps
AXFR_TIMEOUT = 20.0

# RR types the daemon manages itself — never shipped as "external" data.
# The control plane also filters these, but dropping them here saves a
# pointless round trip of every zone's SOA/DNSSEC apparatus.
_IGNORED_TYPES = frozenset(
    {
        "SOA",
        "RRSIG",
        "NSEC",
        "NSEC3",
        "NSEC3PARAM",
        "DNSKEY",
        "CDS",
        "CDNSKEY",
        "TYPE65534",
    }
)


def _relative_name(owner: str, zone: str) -> str:
    """Convert an absolute AXFR owner name to a zone-relative label."""
    o = owner.rstrip(".").lower()
    z = zone.rstrip(".").lower()
    if o == z:
        return "@"
    if o.endswith("." + z):
        return owner.rstrip(".")[: -(len(z) + 1)]
    return owner.rstrip(".")  # out-of-zone (shouldn't happen in an AXFR)


def parse_axfr(text: str, zone: str) -> list[dict[str, Any]]:
    """Parse ``dig +noall +answer AXFR`` output into record dicts.

    Each answer line is ``owner  TTL  CLASS  TYPE  rdata…``. MX / SRV
    rdata is split into priority (+ weight + port) so the control plane
    stores them in the matching columns; everything else keeps the full
    rdata string as ``value``. SOA / apex-NS / DNSSEC RRs are dropped.
    """
    records: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        owner, ttl_s, cls, rtype = parts[0], parts[1], parts[2], parts[3]
        if cls != "IN":
            continue
        rtype = rtype.upper()
        if rtype in _IGNORED_TYPES:
            continue
        name = _relative_name(owner, zone)
        if rtype == "NS" and name == "@":
            continue  # apex NS is zone-management data
        try:
            ttl = int(ttl_s)
        except ValueError:
            ttl = None
        rdata = parts[4:]
        rec: dict[str, Any] = {
            "name": name,
            "record_type": rtype,
            "ttl": ttl,
            "priority": None,
            "weight": None,
            "port": None,
        }
        if rtype == "MX" and len(rdata) >= 2:
            rec["priority"] = _int_or_none(rdata[0])
            rec["value"] = " ".join(rdata[1:])
        elif rtype == "SRV" and len(rdata) >= 4:
            rec["priority"] = _int_or_none(rdata[0])
            rec["weight"] = _int_or_none(rdata[1])
            rec["port"] = _int_or_none(rdata[2])
            rec["value"] = " ".join(rdata[3:])
        else:
            rec["value"] = " ".join(rdata)
        records.append(rec)
    return records


def _int_or_none(v: str) -> int | None:
    try:
        return int(v)
    except ValueError:
        return None


_TXT_CHUNK_RE = re.compile(r'"((?:\\.|[^"\\])*)"')


def _unquote_txt(content: str) -> str:
    """A PowerDNS TXT content back to the plain value the control plane stores.

    pdns returns TXT rdata in presentation form — one or more quoted
    chunks (``"v=spf1 " "-all"``); the control plane stores the plain
    string and the agent re-quotes on render. Unescape and concatenate.
    A content that is not quoted at all is returned unchanged.
    """
    chunks = _TXT_CHUNK_RE.findall(content)
    if not chunks:
        return content
    return "".join(c.replace('\\"', '"').replace("\\\\", "\\") for c in chunks)


def parse_pdns_zone(zone_doc: dict[str, Any], zone: str) -> list[dict[str, Any]] | None:
    """Parse a PowerDNS ``GET /zones/{zone}`` document into record dicts.

    The mirror image of :func:`parse_axfr` for the PowerDNS read-back
    (#1524): same output shape, same drops (SOA / apex-NS / DNSSEC RRs),
    MX / SRV rdata split into their columns. Returns None when the
    document carries no apex SOA — pdns answers a zone it does not hold
    (or only partially loaded) without one, and shipping an empty set
    for that would delete every external mirror on the control plane,
    exactly the failure ``_saw_soa`` guards on the AXFR path.
    """
    zname = zone.rstrip(".")
    saw_soa = False
    records: list[dict[str, Any]] = []
    for rrset in zone_doc.get("rrsets") or []:
        rtype = str(rrset.get("type") or "").upper()
        if not rtype:
            continue
        owner = str(rrset.get("name") or "")
        name = _relative_name(owner, zname)
        if rtype == "SOA" and name == "@":
            saw_soa = True
            continue
        if rtype in _IGNORED_TYPES:
            continue
        if rtype == "NS" and name == "@":
            continue  # apex NS is zone-management data
        try:
            ttl = int(rrset.get("ttl"))
        except (TypeError, ValueError):
            ttl = None
        for entry in rrset.get("records") or []:
            if entry.get("disabled"):
                continue  # not served — not external data either
            content = str(entry.get("content") or "")
            rec: dict[str, Any] = {
                "name": name,
                "record_type": rtype,
                "ttl": ttl,
                "priority": None,
                "weight": None,
                "port": None,
            }
            if rtype == "MX":
                first, _, rest = content.partition(" ")
                if _int_or_none(first) is not None and rest:
                    rec["priority"] = _int_or_none(first)
                    rec["value"] = rest
                else:
                    rec["value"] = content
            elif rtype == "SRV":
                parts = content.split(" ", 3)
                if len(parts) == 4 and all(
                    _int_or_none(p) is not None for p in parts[:3]
                ):
                    rec["priority"] = _int_or_none(parts[0])
                    rec["weight"] = _int_or_none(parts[1])
                    rec["port"] = _int_or_none(parts[2])
                    rec["value"] = parts[3]
                else:
                    rec["value"] = content
            elif rtype == "TXT":
                rec["value"] = _unquote_txt(content)
            else:
                rec["value"] = content
            records.append(rec)
    if not saw_soa:
        return None
    return records


def _saw_soa(text: str) -> bool:
    """True if the AXFR output carries an apex SOA record.

    A successful AXFR always begins (and ends) with the zone's SOA. We use
    its presence as the reliable success signal: ``dig +noall`` suppresses
    the ``; Transfer failed.`` comment and frequently still exits 0 on a
    refused / errored transfer, so an empty answer section is ambiguous
    between "healthy minimal zone" and "transfer failed". Seeing the SOA
    disambiguates — without it we must NOT ship (an empty record set would
    delete every external mirror on the control plane).
    """
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[3].upper() == "SOA":
            return True
    return False


class IngestWorker:
    """AXFR-and-ship loop for externally-injected DDNS records.

    Daemon thread spun up by the supervisor. ``stop()`` sets
    a thread-safe event checked between sweeps.
    """

    def __init__(self, cfg: AgentConfig, token_ref: list[str]) -> None:
        self.cfg = cfg
        self.token_ref = token_ref
        self._stop = threading.Event()
        self.dns_port = int(os.environ.get("DNS_LOOPBACK_PORT") or "53")

    def stop(self) -> None:
        self._stop.set()

    def _cp_client(self) -> httpx.Client:
        verify = self.cfg.httpx_verify()
        return httpx.Client(
            base_url=self.cfg.control_plane_url, verify=verify, timeout=20.0
        )

    def _write_loopback_keyfile(self, key: dict[str, Any]) -> str | None:
        """Write the loopback TSIG key to a private file for ``dig -k``.

        Using ``-k <file>`` instead of ``-y algo:name:secret`` keeps the
        secret out of the process argv (readable via ps / /proc). Overwritten
        each sweep (0600) so a key rotation is picked up. Returns the path or
        None when there's no usable key.
        """
        name, secret = key.get("name"), key.get("secret")
        if not name or not secret:
            return None
        algo = key.get("algorithm", "hmac-sha256")
        tsig_dir = self.cfg.state_dir / "tsig"
        tsig_dir.mkdir(parents=True, exist_ok=True)
        path = tsig_dir / "ingest.key"
        payload = f'key "{name}" {{ algorithm {algo}; secret "{secret}"; }};\n'
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, payload.encode())
        finally:
            os.close(fd)
        return str(path)

    def _axfr(
        self, zone: str, key: dict[str, Any] | None
    ) -> list[dict[str, Any]] | None:
        """Run a signed AXFR from loopback; return parsed records or None.

        Returns None (skip, no ship) on any failure signal so a transient /
        refused transfer can't be mistaken for "the zone has no records" —
        shipping an empty set would delete every external mirror.
        """
        zname = zone.rstrip(".")
        cmd = [
            "dig",
            "+noall",
            "+answer",
            "+onesoa",
            "-p",
            str(self.dns_port),
        ]
        keyfile = self._write_loopback_keyfile(key) if key else None
        if keyfile is not None:
            cmd += ["-k", keyfile]
        cmd += ["@127.0.0.1", "AXFR", zname]
        try:
            res = subprocess.run(
                cmd, capture_output=True, text=True, timeout=AXFR_TIMEOUT, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.warning("dns_ingest_axfr_failed", zone=zname, error=str(exc))
            return None
        if res.returncode != 0:
            log.warning(
                "dns_ingest_axfr_nonzero",
                zone=zname,
                rc=res.returncode,
                stderr=res.stderr.strip()[:200],
            )
            return None
        # A successful AXFR always carries the apex SOA. Its absence means the
        # transfer failed even though dig exited 0 (the "; Transfer failed."
        # comment is suppressed by +noall) — never ship an empty set here.
        if not _saw_soa(res.stdout):
            log.warning("dns_ingest_axfr_no_soa", zone=zname)
            return None
        return parse_axfr(res.stdout, zname)

    def _read_live_zone(
        self, zone: str, key: dict[str, Any] | None
    ) -> list[dict[str, Any]] | None:
        """Read one dynamic zone back from the live daemon.

        Returns the parsed records, or None (skip, no ship) on any
        failure signal so a transient error can't be mistaken for "the
        zone has no records". The BIND9 implementation AXFRs from
        loopback; PowerDNS overrides this to read its REST API (#1524).
        """
        return self._axfr(zone, key)

    def _ship(self, zone: str, records: list[dict[str, Any]]) -> None:
        try:
            with self._cp_client() as c:
                resp = c.post(
                    "/api/v1/dns/agents/ingested-records",
                    json={"zone_name": zone.rstrip("."), "records": records},
                    headers={"Authorization": f"Bearer {self.token_ref[0]}"},
                )
            if resp.status_code not in (200, 204):
                log.warning(
                    "dns_ingest_ship_failed", zone=zone, status=resp.status_code
                )
        except httpx.HTTPError as exc:
            log.warning("dns_ingest_ship_http_error", zone=zone, error=str(exc))

    def _sweep(self) -> None:
        bundle, _etag = load_config(self.cfg.state_dir)
        if not bundle:
            return
        # Loopback key = the group key the control plane appends first.
        tsig_keys = bundle.get("tsig_keys") or []
        loop_key = tsig_keys[0] if tsig_keys else None
        # Dedupe zone names — a split-horizon zone appears once per view in
        # the payload, but the live daemon serves one authoritative copy per
        # name for AXFR purposes.
        seen: set[str] = set()
        for zone in bundle.get("zones", []):
            if not zone.get("dynamic_update_enabled"):
                continue
            if zone.get("type", "primary") not in ("primary", "master"):
                continue
            zname = (zone.get("name") or "").rstrip(".")
            if not zname or zname in seen:
                continue
            seen.add(zname)
            records = self._read_live_zone(zname, loop_key)
            if records is None:
                continue
            self._ship(zname, records)

    def run(self) -> None:
        if not shutil.which("dig"):
            log.warning("dns_ingest_no_dig_binary_skipping")
            return
        log.info("dns_ingest_worker_starting", interval=INGEST_INTERVAL)
        # Small initial delay so the daemon is up + first bundle applied.
        self._stop.wait(timeout=30.0)
        while not self._stop.is_set():
            try:
                self._sweep()
            except Exception:  # noqa: BLE001 — never let ingest kill the thread
                log.exception("dns_ingest_sweep_failed")
            self._stop.wait(timeout=INGEST_INTERVAL)
        log.info("dns_ingest_worker_stopped")


class PowerDNSIngestWorker(IngestWorker):
    """PowerDNS read-back for the ingest loop (issue #1524).

    Same sweep / ship contract as the BIND9 worker; only the live read
    differs — ``GET /zones/{zone}`` on the loopback REST API with the
    API key the driver manages, instead of an AXFR. Until this existed
    the worker ran for BIND9 only, so records an RFC 2136 client wrote
    to a PowerDNS zone never reached the control plane.
    """

    def _read_live_zone(
        self, zone: str, key: dict[str, Any] | None
    ) -> list[dict[str, Any]] | None:
        from .drivers.powerdns import _PDNS_API_BASE, PowerDNSDriver

        zname = zone.rstrip(".") + "."
        api_key = PowerDNSDriver(
            state_dir=self.cfg.state_dir
        )._load_or_generate_api_key()
        try:
            with httpx.Client(timeout=20.0) as client:
                resp = client.get(
                    f"{_PDNS_API_BASE}/zones/{zname}",
                    headers={"X-API-Key": api_key},
                )
        except httpx.HTTPError as exc:
            log.warning("pdns_ingest_read_failed", zone=zname, error=str(exc))
            return None
        if resp.status_code != 200:
            log.warning(
                "pdns_ingest_read_non200", zone=zname, status=resp.status_code
            )
            return None
        try:
            zone_doc = resp.json()
        except ValueError:
            log.warning("pdns_ingest_read_bad_json", zone=zname)
            return None
        records = parse_pdns_zone(zone_doc, zname)
        if records is None:
            # No apex SOA in the document — not a zone pdns holds (yet).
            # Never ship: an empty set would delete every external mirror.
            log.warning("pdns_ingest_read_no_soa", zone=zname)
            return None
        return records

    def run(self) -> None:
        # No dig binary involved — the read-back is the REST API.
        log.info("pdns_ingest_worker_starting", interval=INGEST_INTERVAL)
        # Small initial delay so the daemon is up + first bundle applied.
        self._stop.wait(timeout=30.0)
        while not self._stop.is_set():
            try:
                self._sweep()
            except Exception:  # never let ingest kill the thread
                log.exception("pdns_ingest_sweep_failed")
            self._stop.wait(timeout=INGEST_INTERVAL)
        log.info("pdns_ingest_worker_stopped")


__all__ = [
    "INGEST_INTERVAL",
    "IngestWorker",
    "PowerDNSIngestWorker",
    "parse_axfr",
    "parse_pdns_zone",
]
