"""Async nmap scan runner.

The runner is intentionally side-effect-light: it owns the subprocess
lifecycle, line-buffers stdout into the database row, and persists a
parsed summary on completion. It does not own the celery task wrapper
(see :mod:`app.tasks.nmap`) nor the HTTP surface (see
:mod:`app.api.v1.nmap`).

Security model:

* Argv is built via ``shlex``-aware tokenisation; we never invoke a
  shell — the subprocess is spawned with ``create_subprocess_exec``.
* Operator-supplied ``extra_args`` is split with ``shlex.split`` and
  every token must be an option on an ALLOWLIST (#1223): timing, port
  selection, scan type, host discovery, service / OS detection, and
  ``--script`` with named scripts nmap itself classifies as
  non-intrusive. Anything else is refused, including every option that
  reads or writes a file (``-iL``, ``-o*``, ``--datadir``, ``--resume``,
  ``--script-args``), adds targets (a bare address, ``-iR``), or spoofs
  (``-S``, ``-D``, ``-e``). The gate is ``manage_nmap_scans``, which the
  builtin Network Editor role holds, so this is a delegated user's
  input, not a superadmin's.
* The API container runs as a non-root user, so privileged scan
  modes (raw SYN ``-sS``, OS detection ``-O`` without privilege) just
  fall back to TCP-connect / refuse — that's fine; we surface the
  exit code so the operator knows.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import re
import shlex
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, Final

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings
from app.models.nmap import NmapScan

logger = structlog.get_logger(__name__)


PRESETS: dict[str, list[str]] = {
    # ``quick`` formerly used ``-F`` (top 100 ports). Bumped to top
    # 1000 — same wall-clock under -T4 on modern networks, but
    # catches a meaningfully bigger slice of services (everything in
    # IANA's well-known + the bulk of registered ports). Operators
    # who genuinely need the original tiny scan can fall back to
    # ``custom`` with ``--top-ports 100`` in extra_args.
    "quick": ["-T4", "--top-ports", "1000"],
    "service_version": ["-T4", "-sV", "--version-light"],
    "os_fingerprint": ["-T4", "-O"],
    # service_and_os combines service detection + OS fingerprinting in
    # one pass — the right default for device profiling, since the IP
    # detail modal renders both. ``-A`` would also do this but adds NSE
    # scripts + traceroute which are heavyweight; this preset stays
    # comparable to ``service_version`` in runtime, just with ``-O`` on
    # top to fill the OS guess panel.
    "service_and_os": ["-T4", "-sV", "-O", "--version-light"],
    # Subnet sweep — accepts CIDR targets and reports alive hosts only
    # (no port scan). ``-sn`` is nmap's "ping scan" mode: ICMP echo +
    # TCP SYN to 80/443 + ARP for local subnets. Output is a list of
    # alive IPs the operator can use for discovery + IPAM seeding.
    "subnet_sweep": ["-sn", "-T4"],
    "default_scripts": ["-T4", "-sC"],
    "udp_top1000": ["-T4", "-sU", "--top-ports", "1000"],
    "aggressive": ["-T4", "-A"],
    "custom": [],
}

# nmap can only emit one format to stdout, but it accepts ``-oX <file>``
# alongside ``-oN -`` — so we get human-readable text streaming live to
# the SSE viewer AND a structured XML artefact on disk for parsing into
# ``summary_json`` once the process exits. The XML path is supplied per
# scan in :func:`run_scan` (NamedTemporaryFile); ``_BASE_ARGS`` only
# carries the format-independent flags.
_BASE_ARGS = ["nmap", "-oN", "-", "--stats-every", "2s"]

_PORT_SPEC_RE = re.compile(r"^[0-9,\-UTSI:]+$")

# CIDR-target safety limits. /16 IPv4 is 65k hosts which is at the
# upper end of "I know what I'm doing" — anything larger than this
# almost always means the operator typo'd a prefix. The
# ``MAX_CIDR_HOST_BITS`` value is just a derived display string used
# in the error message so operators know the equivalent prefix.
MAX_CIDR_HOST_BITS = 16
MAX_CIDR_HOST_COUNT = 1 << MAX_CIDR_HOST_BITS

# Maximum time we'll allow a single scan to run, mostly so a forgotten
# ``aggressive`` against a /16 doesn't pin a worker indefinitely. Eight
# minutes leaves headroom under the SSE 10-minute cap.
_SCAN_TIMEOUT_SECONDS = 8 * 60

# stdout flush cadence. The DB write throughput here is trivial
# compared to nmap's output rate (small payloads, no fsync), so 2 s is
# generous; the SSE consumer polls the DB at 500 ms.
_STDOUT_FLUSH_INTERVAL_SECONDS = 2.0


class NmapArgError(ValueError):
    """Raised when operator-supplied arguments fail validation."""


class NmapScanRowMissing(LookupError):
    """The NmapScan row wasn't visible when the worker picked up the task.

    Almost always the dispatcher committed *after* the worker started (the
    row is flushed but the caller's transaction hasn't committed yet, #510).
    The Celery wrapper retries a few times; if the row never appears the
    caller's transaction rolled back and there is nothing to run."""


_HOSTNAME_RE: Final = re.compile(
    # RFC 1123 / 952 hostname: labels of [A-Za-z0-9-] up to 63 chars,
    # joined by dots, no leading/trailing hyphen per label, total
    # length <= 253. We deliberately allow a trailing dot (FQDN form)
    # which nmap accepts. Operator can target a bare host
    # (``router1``) or an FQDN (``router1.lan``).
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)


def _validate_target(target: str) -> str:
    """Accept a literal IPv4/IPv6 address, a CIDR range, or a hostname / FQDN.

    Hostname mode is a deliberate extension over the original IP-only
    contract — operators routinely want to scan ``router1.lan``
    without first looking up its IP. nmap performs DNS resolution
    itself, so we just need to validate the syntax tightly enough
    that the argv builder can pass the value through to nmap without
    risk of injection. The hostname regex rejects shell metachars,
    spaces, slashes, and anything else that isn't a valid DNS label
    character.

    CIDR mode powers the ``subnet_sweep`` preset (and operator-driven
    multi-host scans of any preset). The CIDR is canonicalised through
    ``ipaddress.ip_network(strict=False)`` and the number of host bits
    is capped at ``MAX_CIDR_HOST_COUNT`` so a stray ``-sn 10.0.0.0/8``
    can't pin a worker for hours.
    """
    target = target.strip()
    if not target:
        raise NmapArgError("target is required")
    try:
        addr = ipaddress.ip_address(target)
        return str(addr)
    except ValueError:
        pass
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise NmapArgError(f"target is not a valid CIDR: {target!r} ({exc})") from exc
        if net.num_addresses > MAX_CIDR_HOST_COUNT:
            raise NmapArgError(
                f"CIDR is too large ({net.num_addresses} hosts) — limit is "
                f"{MAX_CIDR_HOST_COUNT} (≤ /{net.max_prefixlen - MAX_CIDR_HOST_BITS} for IPv4)"
            )
        return str(net)
    if _HOSTNAME_RE.match(target):
        return target
    raise NmapArgError(
        f"target must be a valid IPv4/IPv6 address, CIDR, or hostname (got {target!r})"
    )


# Keep the old name as an alias for callers that import it directly.
_validate_target_ip = _validate_target


def _validate_port_spec(spec: str | None) -> str | None:
    if spec is None:
        return None
    spec = spec.strip()
    if not spec:
        return None
    if not _PORT_SPEC_RE.match(spec):
        raise NmapArgError(
            "port_spec must be digits / commas / dashes / 'U:'/'T:'/'S:' "
            f"prefixes only (got {spec!r})"
        )
    return spec


# ── extra_args allowlist (#1223) ─────────────────────────────────────
#
# A blocklist cannot work here: nmap has well over a hundred options and
# the dangerous ones are ordinary-looking (``-iL /etc/passwd`` reads a
# file and echoes the unresolvable "targets" back into the scan output the
# caller streams; ``-oN <path>`` writes one as the api user). So every
# token must be an option listed below, and every value must match its
# option's shape. Anything else, including a bare positional token (which
# nmap would scan as an extra target, past target validation and the #722
# do-not-probe policy), is refused.

_DURATION_RE: Final = re.compile(r"^\d+(?:\.\d+)?(?:ms|s|m|h)?$")
_INT_RE: Final = re.compile(r"^\d{1,6}$")
_NUMBER_RE: Final = re.compile(r"^(?:\d{1,6}(?:\.\d+)?|\.\d+)$")
_TIMING_VALUES: Final = frozenset(
    {"0", "1", "2", "3", "4", "5", "paranoid", "sneaky", "polite", "normal", "aggressive", "insane"}
)

# Options that take no value.
_EXTRA_FLAGS: Final = frozenset(
    {
        # scan technique (raw-socket ones degrade to connect() unprivileged)
        "-sS",
        "-sT",
        "-sA",
        "-sW",
        "-sM",
        "-sU",
        "-sN",
        "-sF",
        "-sX",
        "-sY",
        "-sZ",
        "-sO",
        "-sn",
        "-sL",
        # host discovery
        "-Pn",
        "-PE",
        "-PP",
        "-PM",
        "-PR",
        "-n",
        "-R",
        "--system-dns",
        "--disable-arp-ping",
        "--traceroute",
        # port selection
        "-F",
        "-r",
        "--allports",
        # service / OS detection
        "-sV",
        "-O",
        "--version-light",
        "--version-all",
        "--version-trace",
        "--osscan-limit",
        "--osscan-guess",
        # timing
        "--defeat-rst-ratelimit",
        "--defeat-icmp-ratelimit",
        # output detail (stdout only; the output FILE options are refused)
        "--reason",
        "--open",
        "--packet-trace",
        "--script-trace",
        # address family
        "-6",
    }
)


def _is_port_spec(value: str) -> bool:
    return bool(_PORT_SPEC_RE.match(value))


# Options that take exactly one value, and what the value must look like.
_EXTRA_VALUE_OPTIONS: Final[dict[str, Any]] = {
    "-p": _is_port_spec,
    "--exclude-ports": _is_port_spec,
    "--top-ports": _INT_RE.match,
    "--port-ratio": _NUMBER_RE.match,
    "-T": _TIMING_VALUES.__contains__,
    "--max-retries": _INT_RE.match,
    "--host-timeout": _DURATION_RE.match,
    "--scan-delay": _DURATION_RE.match,
    "--max-scan-delay": _DURATION_RE.match,
    "--min-rate": _NUMBER_RE.match,
    "--max-rate": _NUMBER_RE.match,
    "--min-parallelism": _INT_RE.match,
    "--max-parallelism": _INT_RE.match,
    "--min-hostgroup": _INT_RE.match,
    "--max-hostgroup": _INT_RE.match,
    "--min-rtt-timeout": _DURATION_RE.match,
    "--max-rtt-timeout": _DURATION_RE.match,
    "--initial-rtt-timeout": _DURATION_RE.match,
    "--script-timeout": _DURATION_RE.match,
    "--version-intensity": re.compile(r"^[0-9]$").match,
    "--max-os-tries": _INT_RE.match,
    # Validated separately: see _validate_script_value.
    "--script": None,
}

# Short options nmap accepts with the value attached (``-p22``, ``-T4``,
# ``-PS22,80``, ``-vv``).
_ATTACHED_SHORT: Final = (
    (re.compile(r"^-p(.+)$"), _is_port_spec),
    (re.compile(r"^-T(.+)$"), _TIMING_VALUES.__contains__),
    (re.compile(r"^-P[SAUY]([0-9,\-]*)$"), lambda v: v == "" or _is_port_spec(v)),
    (re.compile(r"^-(v+|d+)$"), lambda v: True),
)

# nmap's own script database, written by ``nmap --script-updatedb`` and
# shipped with the package.
_NMAP_SCRIPT_DB = "/usr/share/nmap/scripts/script.db"

# A script in any of these categories is refused. ``external`` is here for
# non-negotiable #17 as much as for safety: those scripts send data about
# the target to third parties (WHOIS, ASN lookups, DNS blocklists, ...).
# No category NAME is accepted in ``--script``, because none is clean:
# nmap's own ``safe`` category holds 33 scripts that are also ``external``
# or ``intrusive``, and ``default`` holds two open-proxy probes.
_FORBIDDEN_SCRIPT_CATEGORIES: Final = frozenset(
    {"intrusive", "exploit", "dos", "brute", "external", "malware", "fuzzer"}
)
_SCRIPT_NAME_RE: Final = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
_SCRIPT_ENTRY_RE: Final = re.compile(r'filename = "([^"]+)\.nse", categories = \{([^}]*)\}')


def _load_script_categories(path: str) -> dict[str, frozenset[str]] | None:
    """Script name → categories, from nmap's script.db; None if unreadable."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return None
    return {
        name: frozenset(re.findall(r'"([^"]+)"', cats))
        for name, cats in _SCRIPT_ENTRY_RE.findall(text)
    }


def _validate_script_value(value: str) -> None:
    """``--script`` takes a comma list of script NAMES, each one nmap
    classifies in no forbidden category.

    Categories, wildcards (``http-*``), boolean expressions (``not
    intrusive``) and paths are refused: each can expand to scripts this
    check never saw. Unknown names are refused too, since nmap would
    otherwise try the value as a file or directory.
    """
    names = value.split(",")
    for name in names:
        if not _SCRIPT_NAME_RE.match(name):
            raise NmapArgError(
                f"--script accepts a comma-separated list of script names only (got {value!r})"
            )
    catalogue = _load_script_categories(_NMAP_SCRIPT_DB)
    if catalogue is None:
        raise NmapArgError("--script is unavailable: nmap's script database could not be read")
    for name in names:
        bare = name.removesuffix(".nse")
        categories = catalogue.get(bare)
        if categories is None:
            raise NmapArgError(
                f"--script: unknown script {name!r} (script names only; "
                "category names such as default or safe are not accepted)"
            )
        forbidden = categories & _FORBIDDEN_SCRIPT_CATEGORIES
        if forbidden:
            raise NmapArgError(
                f"--script: {name!r} is in the {', '.join(sorted(forbidden))} "
                "category and is not allowed from extra_args"
            )


def _check_option_value(option: str, value: str) -> None:
    if option == "--script":
        _validate_script_value(value)
        return
    if not _EXTRA_VALUE_OPTIONS[option](value):
        raise NmapArgError(f"extra_args: invalid value for {option}: {value!r}")


def _validate_extra_args(extra: str | None) -> list[str]:
    """Validate operator-supplied nmap options against the allowlist.

    Returns the tokens unchanged; raises :class:`NmapArgError` naming the
    first one that is not allowed.
    """
    if extra is None:
        return []
    extra = extra.strip()
    if not extra:
        return []
    try:
        tokens = shlex.split(extra)
    except ValueError as exc:
        raise NmapArgError(f"extra_args could not be parsed: {exc}") from exc

    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in _EXTRA_FLAGS:
            i += 1
            continue
        if tok.startswith("--") and "=" in tok:
            option, value = tok.split("=", 1)
            if option in _EXTRA_VALUE_OPTIONS:
                _check_option_value(option, value)
                i += 1
                continue
        elif tok in _EXTRA_VALUE_OPTIONS:
            if i + 1 >= len(tokens):
                raise NmapArgError(f"extra_args: {tok} needs a value")
            _check_option_value(tok, tokens[i + 1])
            i += 2
            continue
        else:
            matched = False
            for pattern, check in _ATTACHED_SHORT:
                m = pattern.match(tok)
                if m:
                    if not check(m.group(1)):
                        raise NmapArgError(f"extra_args: invalid value in {tok!r}")
                    matched = True
                    break
            if matched:
                i += 1
                continue
        if tok in ("-sC", "-A") or tok.startswith("--script-args"):
            hint = (
                "use the default_scripts or aggressive preset"
                if tok in ("-sC", "-A")
                else "script arguments are not accepted"
            )
            raise NmapArgError(f"extra_args: {tok!r} is not allowed here; {hint}")
        raise NmapArgError(
            f"extra_args: {tok!r} is not an allowed nmap option. Allowed: scan type, "
            "host discovery, port selection, timing, service / OS detection, "
            "--reason / --open, and --script with named non-intrusive scripts. "
            "Options that read or write files, add targets, or spoof are refused."
        )
    return tokens


def build_argv(
    target_ip: str,
    preset: str,
    port_spec: str | None,
    extra_args: str | None,
    xml_output_path: str | None = None,
) -> list[str]:
    """Build the full nmap argv from validated inputs.

    Always prepends ``-oN -`` + ``--stats-every 2s``. When
    ``xml_output_path`` is given, ``-oX <path>`` is appended so a
    parseable XML artefact lands on disk in parallel to the streamed
    human output. Returns the list in the order: base args, ``-oX``
    pair (optional), preset args, ``-p <spec>`` (when given), extra
    args, then the target IP last.

    Raises :class:`NmapArgError` on any validation failure.
    """
    if preset not in PRESETS:
        raise NmapArgError(f"unknown preset: {preset!r}")
    target = _validate_target_ip(target_ip)
    pspec = _validate_port_spec(port_spec)
    extra = _validate_extra_args(extra_args)

    argv = list(_BASE_ARGS)
    if xml_output_path is not None:
        argv.extend(["-oX", xml_output_path])
    argv.extend(PRESETS[preset])
    if pspec is not None:
        argv.extend(["-p", pspec])
    argv.extend(extra)
    argv.append(target)
    return argv


# ── XML parsing ─────────────────────────────────────────────────────


def _safe_text(elem: ET.Element | None, attr: str) -> str | None:
    if elem is None:
        return None
    val = elem.get(attr)
    return val if val else None


def _parse_host(host: ET.Element) -> dict[str, Any]:
    """Extract a single ``<host>`` element into a summary dict.

    Returns the same ``{address, host_state, ports, os}`` shape used in
    the multi-host ``hosts`` list. The single-host fields on the
    top-level summary are populated from the first parsed host.
    """
    addr_elem = host.find("address")
    address = addr_elem.get("addr") if addr_elem is not None else None

    status = host.find("status")
    state = _safe_text(status, "state") or "unknown"

    ports: list[dict[str, Any]] = []
    ports_root = host.find("ports")
    if ports_root is not None:
        for p in ports_root.findall("port"):
            port_state_elem = p.find("state")
            service_elem = p.find("service")
            try:
                port_num = int(p.get("portid", "0"))
            except ValueError:
                continue
            ports.append(
                {
                    "port": port_num,
                    "proto": p.get("protocol") or "tcp",
                    "state": _safe_text(port_state_elem, "state") or "unknown",
                    "reason": _safe_text(port_state_elem, "reason"),
                    "service": _safe_text(service_elem, "name"),
                    "product": _safe_text(service_elem, "product"),
                    "version": _safe_text(service_elem, "version"),
                    "extrainfo": _safe_text(service_elem, "extrainfo"),
                }
            )

    os_data: dict[str, Any] | None = None
    os_elem = host.find("os")
    if os_elem is not None:
        match = os_elem.find("osmatch")
        if match is not None:
            try:
                accuracy = int(match.get("accuracy", "0"))
            except ValueError:
                accuracy = 0
            os_data = {"name": match.get("name") or None, "accuracy": accuracy}

    hostname_elem = host.find("hostnames/hostname")
    hostname = hostname_elem.get("name") if hostname_elem is not None else None

    return {
        "address": address,
        "hostname": hostname,
        "host_state": state,
        "ports": ports,
        "os": os_data,
    }


def parse_nmap_xml(xml_str: str) -> dict:
    """Parse the XML emitted by ``nmap -oX -`` into a compact summary.

    Single-host scans return ``{host_state, ports, os, hosts: None}``.
    CIDR / multi-target scans additionally populate ``hosts`` with one
    entry per ``<host>`` in the XML — the single-host fields then
    reflect the first parsed host so existing callers (auto-profile
    stamper, IP detail panel) keep working without a shape check.
    """
    out: dict[str, Any] = {
        "host_state": "unknown",
        "ports": [],
        "os": None,
        "hosts": None,
    }
    if not xml_str:
        return out
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as exc:
        logger.debug("nmap_xml_parse_failed", error=str(exc))
        return out

    host_elems = root.findall("host")
    if not host_elems:
        return out

    parsed = [_parse_host(h) for h in host_elems]
    first = parsed[0]
    out["host_state"] = first["host_state"]
    out["ports"] = first["ports"]
    out["os"] = first["os"]
    if len(parsed) > 1:
        out["hosts"] = parsed
    return out


# ── Runner ──────────────────────────────────────────────────────────


def _new_engine_factory() -> tuple[Any, async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(settings.database_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, factory


async def _flush_stdout(
    db: AsyncSession,
    scan_id: uuid.UUID,
    buffer: list[str],
) -> None:
    """Persist accumulated stdout lines to the row.

    We re-load the row each flush so a concurrent ``DELETE`` (operator
    cancel) is observed promptly — the runner checks the latest
    ``status`` after every flush and self-terminates on ``cancelled``.
    """
    if not buffer:
        return
    row = await db.get(NmapScan, scan_id)
    if row is None:
        return
    blob = "".join(buffer)
    row.raw_stdout = (row.raw_stdout or "") + blob
    await db.commit()
    buffer.clear()


async def run_scan(scan_id: uuid.UUID) -> None:
    """Drive one scan to completion.

    Loads the scan row, marks it ``running``, spawns nmap, line-buffers
    stdout into ``raw_stdout`` every ~2 s, and on EOF persists the
    full XML + parsed summary. On any exception the row lands in
    ``failed`` with ``error_message`` populated.

    Safe to invoke from a Celery task body via ``asyncio.run``. Owns
    its own engine + session — does not share with the calling
    request handler's session.
    """
    engine, factory = _new_engine_factory()
    xml_path: str | None = None
    try:
        async with factory() as db:
            scan = await db.get(NmapScan, scan_id)
            if scan is None:
                # Not visible yet — signal the wrapper to retry (commit race)
                # rather than silently no-op'ing and leaving the row stuck in
                # "queued" forever, occupying a per-subnet profile slot (#510).
                logger.warning("nmap_run_scan_missing", scan_id=str(scan_id))
                raise NmapScanRowMissing(str(scan_id))

            # Operator cancelled before we picked it up — bow out.
            if scan.status == "cancelled":
                return

            # XML lands on disk in parallel to stdout so the operator
            # sees human-readable output streaming while we still get a
            # parseable artefact for ``summary_json``. Tmpfile is opened
            # with delete=False so nmap can write to it; we clean up in
            # ``finally``.
            xml_tmp = tempfile.NamedTemporaryFile(
                prefix=f"nmap-{scan_id}-",
                suffix=".xml",
                delete=False,
            )
            xml_tmp.close()
            xml_path = xml_tmp.name

            try:
                argv = build_argv(
                    str(scan.target_ip),
                    scan.preset,
                    scan.port_spec,
                    scan.extra_args,
                    xml_output_path=xml_path,
                )
            except NmapArgError as exc:
                scan.status = "failed"
                scan.error_message = str(exc)
                scan.finished_at = datetime.now(UTC)
                await db.commit()
                logger.warning("nmap_argv_invalid", scan_id=str(scan_id), error=str(exc))
                return

            scan.status = "running"
            scan.started_at = datetime.now(UTC)
            scan.command_line = " ".join(shlex.quote(a) for a in argv)
            await db.commit()

            logger.info(
                "nmap_scan_starting",
                scan_id=str(scan_id),
                target=str(scan.target_ip),
                preset=scan.preset,
                argv=argv,
            )

            buffer: list[str] = []
            started_monotonic = time.monotonic()

            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
            except FileNotFoundError as exc:
                scan.status = "failed"
                scan.error_message = (
                    "nmap binary not found in PATH. " "Install nmap inside the api container image."
                )
                scan.finished_at = datetime.now(UTC)
                await db.commit()
                logger.error("nmap_binary_missing", error=str(exc))
                return
            except Exception as exc:  # noqa: BLE001 — surface to operator
                scan.status = "failed"
                scan.error_message = f"failed to spawn nmap: {exc}"
                scan.finished_at = datetime.now(UTC)
                await db.commit()
                logger.exception("nmap_spawn_failed", scan_id=str(scan_id))
                return

            assert proc.stdout is not None  # noqa: S101 — PIPE was set
            last_flush = time.monotonic()
            cancelled_by_operator = False

            try:
                while True:
                    if time.monotonic() - started_monotonic > _SCAN_TIMEOUT_SECONDS:
                        logger.warning("nmap_scan_timeout", scan_id=str(scan_id))
                        proc.kill()
                        await proc.wait()
                        scan_row = await db.get(NmapScan, scan_id)
                        if scan_row is not None:
                            scan_row.status = "failed"
                            scan_row.error_message = (
                                f"scan exceeded {_SCAN_TIMEOUT_SECONDS}s timeout"
                            )
                            scan_row.finished_at = datetime.now(UTC)
                            scan_row.duration_seconds = time.monotonic() - started_monotonic
                            scan_row.exit_code = proc.returncode
                            scan_row.raw_stdout = (scan_row.raw_stdout or "") + "".join(buffer)
                            scan_row.raw_xml = _read_xml_artefact(xml_path)
                            try:
                                scan_row.summary_json = parse_nmap_xml(scan_row.raw_xml or "")
                            except Exception:  # noqa: BLE001 — best-effort
                                scan_row.summary_json = None
                            await db.commit()
                        return

                    try:
                        line_bytes = await asyncio.wait_for(
                            proc.stdout.readline(),
                            timeout=_STDOUT_FLUSH_INTERVAL_SECONDS,
                        )
                    except TimeoutError:
                        line_bytes = b""

                    if line_bytes:
                        line = line_bytes.decode("utf-8", errors="replace")
                        buffer.append(line)

                    # Periodic flush + cancel check
                    if time.monotonic() - last_flush >= _STDOUT_FLUSH_INTERVAL_SECONDS and buffer:
                        await _flush_stdout(db, scan_id, buffer)
                        last_flush = time.monotonic()

                    refreshed = await db.get(NmapScan, scan_id)
                    if refreshed is not None and refreshed.status == "cancelled":
                        cancelled_by_operator = True
                        proc.kill()
                        await proc.wait()
                        break

                    # Process exited
                    if proc.returncode is not None and not line_bytes:
                        # Drain anything still buffered in the pipe.
                        remaining = await proc.stdout.read()
                        if remaining:
                            chunk = remaining.decode("utf-8", errors="replace")
                            buffer.append(chunk)
                        break
                    if line_bytes == b"" and proc.returncode is None:
                        # Empty read while process still alive — nothing
                        # buffered yet, loop back into ``readline``.
                        continue
            finally:
                if proc.returncode is None:
                    try:
                        proc.kill()
                        await proc.wait()
                    except ProcessLookupError:
                        pass

            scan_row = await db.get(NmapScan, scan_id)
            if scan_row is None:
                return
            scan_row.raw_stdout = (scan_row.raw_stdout or "") + "".join(buffer)
            full_xml = _read_xml_artefact(xml_path)
            scan_row.raw_xml = full_xml
            scan_row.exit_code = proc.returncode
            scan_row.finished_at = datetime.now(UTC)
            scan_row.duration_seconds = time.monotonic() - started_monotonic
            try:
                scan_row.summary_json = parse_nmap_xml(full_xml or "")
            except Exception as exc:  # noqa: BLE001 — best-effort
                logger.warning("nmap_summary_parse_failed", error=str(exc))
                scan_row.summary_json = None

            if cancelled_by_operator:
                scan_row.status = "cancelled"
            elif proc.returncode == 0:
                scan_row.status = "completed"
            else:
                scan_row.status = "failed"
                scan_row.error_message = (
                    scan_row.error_message or f"nmap exited with code {proc.returncode}"
                )

            # Stamp the IPAddress when a scan that targeted a known
            # IPAM row finishes successfully. Powers the device-profile
            # surface in the IP detail modal (last scan, last summary)
            # and the dedupe window in services.profiling.auto_profile.
            # We do this here — not in the auto_profile service —
            # because operator-driven "Scan with nmap" runs deserve
            # the same treatment, and the runner is the only place
            # that knows when a scan is actually done.
            if scan_row.status == "completed" and scan_row.ip_address_id is not None:
                from app.models.ipam import IPAddress as _IPAddress

                ip_row = await db.get(_IPAddress, scan_row.ip_address_id)
                if ip_row is not None:
                    ip_row.last_profiled_at = scan_row.finished_at
                    ip_row.last_profile_scan_id = scan_row.id
                    # Mirror nmap's OS guess onto the row's ``device_type``
                    # so the IP table + detail modal can render the OS
                    # without re-fetching the scan row. Defers to the
                    # passive (fingerbank) layer when that's already
                    # populated something — those values are usually
                    # more specific ("HP iLO" vs nmap's "Linux 3.X").
                    summary = scan_row.summary_json or {}
                    os_info = summary.get("os") if isinstance(summary, dict) else None
                    os_name = (os_info or {}).get("name") if isinstance(os_info, dict) else None
                    if os_name and not ip_row.device_type:
                        ip_row.device_type = str(os_name)[:100]

            await db.commit()
            logger.info(
                "nmap_scan_finished",
                scan_id=str(scan_id),
                status=scan_row.status,
                exit_code=proc.returncode,
                duration_s=scan_row.duration_seconds,
            )
    finally:
        if xml_path is not None:
            with contextlib.suppress(Exception):
                os.unlink(xml_path)
        await engine.dispose()


def _read_xml_artefact(path: str | None) -> str | None:
    """Read the per-scan ``-oX`` artefact off disk.

    Returns ``None`` on any IO failure (file missing, truncated, etc.) —
    nmap may exit before flushing if it crashes hard, and a missing
    artefact shouldn't propagate as a runner exception. The summary
    parser tolerates ``None`` / empty XML.
    """
    if path is None:
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


async def stream_scan_lines(
    scan_id: uuid.UUID,
    *,
    poll_interval: float = 0.5,
    cap_seconds: float = 600.0,
) -> AsyncIterator[str]:
    """Async generator yielding new ``raw_stdout`` lines as they appear.

    Polls the row at ``poll_interval`` seconds. Yields each newly
    appended line (already terminated with ``\\n``). Exits when the
    scan reaches a terminal state, with a final ``"__DONE__:<status>"``
    sentinel line so the SSE wrapper can emit a ``done`` event.

    The ``cap_seconds`` ceiling is a defensive bound — the SSE wrapper
    enforces it by closing the connection.
    """
    engine, factory = _new_engine_factory()
    try:
        offset = 0
        deadline = time.monotonic() + cap_seconds
        async with factory() as db:
            while time.monotonic() < deadline:
                row = await db.get(NmapScan, scan_id)
                if row is None:
                    yield "__DONE__:not_found\n"
                    return

                blob = row.raw_stdout or ""
                if len(blob) > offset:
                    new_chunk = blob[offset:]
                    offset = len(blob)
                    # Yield line-by-line so SSE events are properly
                    # framed even when nmap flushes mid-line.
                    pending = ""
                    for ch in new_chunk:
                        pending += ch
                        if ch == "\n":
                            yield pending
                            pending = ""
                    if pending:
                        # No trailing newline yet — emit as-is so the
                        # browser sees progress; nmap will terminate
                        # the line on the next stats tick.
                        yield pending

                if row.status in ("completed", "failed", "cancelled"):
                    yield f"__DONE__:{row.status}\n"
                    return

                # Force the session to drop its identity-map cache so the
                # next ``db.get`` re-reads from the DB.
                db.expire_all()
                await asyncio.sleep(poll_interval)

            yield "__DONE__:timeout\n"
    finally:
        await engine.dispose()


__all__ = [
    "PRESETS",
    "NmapArgError",
    "build_argv",
    "parse_nmap_xml",
    "run_scan",
    "stream_scan_lines",
]
