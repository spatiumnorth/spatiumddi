"""BIND9 query-counter poller — emits per-bucket deltas upstream.

Reads BIND9's statistics-channels XMLv3 endpoint every 60 s from
localhost (we inject the ``statistics-channels { inet 127.0.0.1
port 8053; };`` block during render, see bind9.py). The same
delta-on-monotonic-counters trick the DHCP poller uses applies here:
on a ``named`` restart counters drop back to zero, which we detect as
``delta < 0`` and absorb.

For MVP we report five scalar counters derived from the server-level
For MVP we report five scalar counters derived from the server-level
``<counters type="opcode">``, ``<counters type="rcode">`` and
``<counters type="nsstat">`` blocks (older builds spell some of them
differently — see ``_COUNTERS``):

    queries_total   — total incoming queries (opcode QUERY; the nsstat
                      Requestv4 + Requestv6 on a build without the
                      opcode table)
    noerror         — responses sent with rcode NOERROR (the server-level
                      rcode table's NOERROR; QrySuccess + QryNxrrset on a
                      build without the table)
    nxdomain        — responses sent with rcode NXDOMAIN (rcode NXDOMAIN;
                      QryNXDOMAIN on a build without the table)
    servfail        — responses sent with rcode SERVFAIL (rcode SERVFAIL;
                      QrySERVFAIL on a build without the table)
    recursion       — QryRecursion (queries that triggered recursion)

The rcode breakdown is read from the rcode table, never from the nsstat
answer classes: ``QryAuthAns`` / ``QryNoauthAns`` count every
authoritative / non-authoritative response whatever its rcode, so a
``noerror`` derived from them counted each authoritative NXDOMAIN answer
under ``noerror`` as well as under ``nxdomain`` (#1116).
    recursion       — QryRecursion (queries that triggered recursion)

The rcode breakdown is read from the rcode table, never from the nsstat
answer classes: ``QryAuthAns`` / ``QryNoauthAns`` count every
authoritative / non-authoritative response whatever its rcode, so a
``noerror`` derived from them counted each authoritative NXDOMAIN answer
under ``noerror`` as well as under ``nxdomain`` (#1116).

Per-QTYPE + per-zone breakdowns are in the XML too and can be added
later without a protocol change — the control-plane ingestion path
just ignores unknown fields today.

Delivery (#1077): each bucket is shipped through a :class:`.spool.Shipper`.
A bucket the control plane does not accept is spooled to disk under
``<state_dir>/spool/metrics/`` and replayed oldest-first once it answers,
carrying its ORIGINAL ``bucket_at``, so a late bucket lands on the minute
it happened and the time-series panels fill the gap in (the ingest has no
age guard). The ingest ACCUMULATES per ``(server_id, bucket_at)``, so it is
the spool's ``batch_id`` — answered as a duplicate on replay — not the
timestamp that stops a replayed bucket being counted twice. The
baseline (``_prev``) still advances on a failed report: the delta is kept
in the spool, not lost, so re-baselining against the old snapshot would
double-count it. Metrics have no max age — a minute per row is a few MB
for weeks of backlog.
"""

from __future__ import annotations

import random
import threading
from datetime import UTC, datetime
from xml.etree import ElementTree as ET

import httpx
import structlog

from .config import AgentConfig
from .spool import Shipper, Spool

log = structlog.get_logger(__name__)

STATS_URL = "http://127.0.0.1:8053/xml/v3/server"

# Column → the SPELLINGS of that column, in order of preference. Each
# spelling is one or more BIND counter names that are summed; the first
# spelling with any counter present is the column's value and the rest
# are ignored. Different BIND builds report under different element
# names, and the spellings exist so a typical Alpine/Debian ``named``
# lights up out of the box — but they are alternatives, never addends:
# the opcode table's ``QUERY`` and the nsstat family's ``Requestv4`` /
# ``Requestv6`` count the SAME requests (by opcode, by address family),
# and BIND 9.20 publishes both. Summing them counted every query twice
# on every current BIND (#1064).
_COUNTERS: dict[str, tuple[tuple[str, ...], ...]] = {
    "queries_total": (("QUERY",), ("Requestv4", "Requestv6")),
    # The rcode breakdown's fallback, for a build without the server-level
    # rcode table (_RCODE_TABLE below is the value when it is there): the
    # nsstat classes that carry exactly that rcode — NOERROR is an answer
    # with data (QrySuccess) or without (QryNxrrset, NODATA). Never
    # QryAuthAns / QryNoauthAns: those count every response whatever its
    # rcode, NXDOMAIN included (#1116).
    "noerror": (("QrySuccess", "QryNxrrset"),),
    "nxdomain": (("QryNXDOMAIN",),),
    "servfail": (("QrySERVFAIL",),),
    "recursion": (("QryRecursion",),),
    # Response Rate Limiting (#146 Phase 3). BIND9 publishes these in the
    # same statistics-channels XML under the rate-limiting family:
    # RateDropped = responses dropped, RateSlipped = responses truncated
    # (TC=1) so a legit client can retry over TCP. Both 0 when RRL is off.
    "rate_dropped": (("RateDropped",),),
    "rate_slipped": (("RateSlipped",),),
}


def _column_value(totals: dict[str, int], spellings: tuple[tuple[str, ...], ...]) -> int:
    """The first spelling with any of its counters present, summed; 0 when
    the snapshot carries none of them."""
    for names in spellings:
        present = [n for n in names if n in totals]
        if present:
            return sum(totals[n] for n in present)
    return 0


# Column → its counter in the server-level ``<counters type="rcode">``
# table: the responses BIND sent, by rcode — the breakdown itself. Read
# from the ``<server>`` element only: every view repeats NXDOMAIN /
# SERVFAIL / REFUSED under ``resstats`` as that view's RESOLVER counters
# (answers this server received, not sent), so a name-wide sum would
# fold them in.
_RCODE_TABLE: dict[str, str] = {
    "noerror": "NOERROR",
    "nxdomain": "NXDOMAIN",
    "servfail": "SERVFAIL",
}


def _server_rcodes(root: ET.Element) -> dict[str, int]:
    """The server-level rcode table as {name: value}; {} on a build that
    does not publish one (the nsstat fallback in ``_COUNTERS`` applies)."""
    out: dict[str, int] = {}
    server = root.find("server")
    if server is None:
        return out
    for counters in server.findall("counters"):
        if counters.get("type") != "rcode":
            continue
        for el in counters.findall("counter"):
            name = el.get("name")
            if not name:
                continue
            try:
                out[name] = int((el.text or "0").strip())
            except ValueError:
                continue
    return out


def _parse_snapshot(xml_bytes: bytes) -> dict[str, int]:
    """Walk the statistics XML and pull out the counters we care about."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        log.warning("dns_metrics_parse_error", error=str(e))
        return {}

    # Build a name → total map by scanning every ``<counter name="…">``
    # element; XMLv3 nests them under different parents depending on
    # the counter family but the name is globally unique.
    totals: dict[str, int] = {}
    for el in root.iter("counter"):
        name = el.get("name")
        if not name:
            continue
        try:
            val = int((el.text or "0").strip())
        except ValueError:
            continue
        totals[name] = totals.get(name, 0) + val

    out = {col: _column_value(totals, spellings) for col, spellings in _COUNTERS.items()}
    # The rcode breakdown: the rcode table when the build publishes it.
    rcodes = _server_rcodes(root)
    for col, name in _RCODE_TABLE.items():
        if name in rcodes:
            out[col] = rcodes[name]
    return out


class MetricsPoller:
    def __init__(
        self,
        cfg: AgentConfig,
        token_ref: list[str],
        *,
        spool: Spool | None = None,
    ):
        self.cfg = cfg
        self.token_ref = token_ref
        self._stop = threading.Event()
        self._prev: dict[str, int] | None = None
        # #1077 — no spool given (tests, ad-hoc callers) means a disabled one:
        # a failed bucket is dropped, exactly the pre-spool behaviour.
        if spool is None:
            spool = Spool(cfg.state_dir, "metrics", 0, enabled=False)
        self.shipper = Shipper(spool, self._post, event_prefix="dns_metrics_report")

    def stop(self) -> None:
        self._stop.set()

    def _cp_client(self) -> httpx.Client:
        verify: bool | str = True
        if self.cfg.insecure_skip_tls_verify:
            verify = False
        elif self.cfg.tls_ca_path:
            verify = self.cfg.tls_ca_path
        return httpx.Client(base_url=self.cfg.control_plane_url, verify=verify, timeout=15.0)

    def _poll_named(self) -> dict[str, int] | None:
        try:
            with httpx.Client(timeout=10.0) as c:
                resp = c.get(STATS_URL)
        except httpx.HTTPError as e:
            log.debug("dns_metrics_fetch_err", error=str(e))
            return None
        if resp.status_code != 200:
            log.debug("dns_metrics_fetch_non200", status=resp.status_code)
            return None
        return _parse_snapshot(resp.content)

    def _compute_delta(self, current: dict[str, int]) -> dict[str, int] | None:
        prev = self._prev
        self._prev = current
        if prev is None:
            return None
        delta: dict[str, int] = {}
        for col in _COUNTERS:
            d = current.get(col, 0) - prev.get(col, 0)
            if d < 0:
                log.info("dns_metrics_counter_reset")
                return None
            delta[col] = d
        return delta

    def _post(self, payload: dict) -> int:
        with self._cp_client() as c:
            resp = c.post(
                "/api/v1/dns/agents/metrics",
                json=payload,
                headers={"Authorization": f"Bearer {self.token_ref[0]}"},
            )
        return resp.status_code

    def _report(self, bucket_at: datetime, delta: dict[str, int]) -> str:
        """Send one bucket now, or queue it behind any backlog."""
        return self.shipper.ship({"bucket_at": bucket_at.isoformat(), **delta})

    def tick(self) -> None:
        """One poll: snapshot, delta, report — or just drain the backlog."""
        current = self._poll_named()
        delta = self._compute_delta(current) if current is not None else None
        if delta is not None:
            now = datetime.now(UTC).replace(microsecond=0)
            bucket = now.replace(second=(now.second // 60) * 60)
            self._report(bucket, delta)  # drains the backlog first
        elif len(self.shipper.spool):
            # No bucket this tick (first poll, counter reset, named down):
            # still give a queued backlog its chance to reach the control plane.
            self.shipper.drain()

    def run(self) -> None:
        while not self._stop.is_set():
            self.tick()
            interval = 60.0 + random.uniform(-3, 3)
            self._stop.wait(timeout=max(30.0, interval))


__all__ = ["MetricsPoller", "_parse_snapshot"]
