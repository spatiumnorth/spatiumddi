#!/usr/bin/env python3
"""DNS query-set generator + the §4.9 Layer-2 in-zone SAFETY gate.

This is the HEART of the DNS generator (docs/PERFORMANCE_TESTING.md §4.2) and the
single most safety-critical script in the suite. It builds ``queries.txt`` files
(``<qname> <qtype>`` per line) that dnsperf / resperf / flamethrower replay against
the appliance's authoritative-only BIND. Because recursion is OFF on the test BIND
(§4.9 Layer 3), **any qname that is not a suffix-match of a seeded zone returns
REFUSED** — and at campus query volume that would mean leaking out-of-zone names to
the public internet. So this generator carries a hard validator (§4.9 Layer 2): it
asserts EVERY generated qname is in-zone and ABORTS LOUDLY otherwise.

Composition (§1.7 record-type mix + Zipfian s≈1.0):

    A     55%   DDNS forward names + seeded host names      NOERROR (leased) / NXDOMAIN (tail)
    AAAA  10%   same forward names                          NOERROR / NOERROR-empty
    PTR   20%   in-addr.arpa for pool/lease ranges          NOERROR (leased) / NXDOMAIN
    SRV    5%   seeded _ldap._tcp / _kerberos._udp / _sip._tcp
    MX+TXT 5%   seeded mail / SPF / DKIM
    SOA+NS 3%   zone apexes
    miss-A 2%   RANDOM LABELS *UNDER* A SEEDED ZONE         NXDOMAIN ONLY (never REFUSED)

The names are computable WITHOUT scraping the live zone — they derive from the SAME
deterministic device fleet (``spddi_perf.fleet``) the DHCP generator drives and the
seeded-zone manifest, so "a device that got a lease then gets queried by name" works
by construction (§4.5 correlation).

Two output files are emitted (§4.2):
    <out>.steady.txt   — the Zipfian steady-state set (the plateau/soak set)
    <out>.cold.txt     — cold / NXDOMAIN-heavy set (negative-path sub-run)

CLI (registry contract + extras):
    --run-id --run-root --manifest          (contract)
    --out PATH            base path; .steady.txt / .cold.txt are derived from it
    --seed-manifest PATH  optional; defaults to rp.seed_manifest (the seeder's output)
    --count N             total lines per file (default 2,000,000)
    --shard N --shards K  optional disjoint device partition (sharded generators)
    --self-check          re-validate an already-written file (or the just-written
                          files) against the seeded-zone set and exit non-zero on any
                          out-of-zone name

Grounding (real SpatiumDDI shapes — do NOT invent):
  * generated forward label ``dhcp-<a>-<b>-<c>-<d>`` — backend/app/services/dns/ddns.py
    (_generate_hostname; mirrored deterministically in spddi_perf.fleet.generated_forward_name)
  * reverse-zone name from a CIDR — backend/app/services/dns/reverse_zone.py:36
    (compute_reverse_zone_name); per-subnet PTR resolution
    backend/app/api/v1/ipam/router.py:806 (_resolve_reverse_zone)
  * PTR qname form (reverse_pointer) — spddi_perf.fleet.ptr_qname
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import random
import sys
from dataclasses import dataclass, field
from pathlib import Path

import spddi_perf.fleet as fleet
import spddi_perf.manifest as manifest_mod
from spddi_perf.logging_util import atomic_write_json, get_logger, log_event, read_json
from spddi_perf.runpaths import RunPaths

SERVICE = "spddi-perf-dns-queryset"

# --- §1.7 record-type mix (must sum to 1.0) -------------------------------------
MIX = {
    "A": 0.55,
    "AAAA": 0.10,
    "PTR": 0.20,
    "SRV": 0.05,
    "MX_TXT": 0.05,
    "SOA_NS": 0.03,
    "MISS": 0.02,   # deliberate in-zone miss → authoritative NXDOMAIN
}
assert abs(sum(MIX.values()) - 1.0) < 1e-9, "MIX must sum to 1.0"

# Cold/NXDOMAIN-heavy file mix — same in-zone safety, but heavy on the negative path.
COLD_MIX = {
    "A": 0.20,
    "AAAA": 0.05,
    "PTR": 0.15,
    "SRV": 0.0,
    "MX_TXT": 0.0,
    "SOA_NS": 0.0,
    "MISS": 0.60,   # mostly random-label-under-seeded-zone → NXDOMAIN
}
assert abs(sum(COLD_MIX.values()) - 1.0) < 1e-9, "COLD_MIX must sum to 1.0"

# Zipfian exponent — §1.7 / §4.2: s≈1.0 makes the top ~1% of names absorb ~50%.
ZIPF_S = 1.0

# Seeded service / infra records every forward zone gets (the seeder bulk-loads these;
# we only need their *names* to query them). _ldap._tcp etc. per §1.7.
SRV_PREFIXES = ("_ldap._tcp", "_kerberos._udp", "_sip._tcp")
MX_HOSTS = ("mail",)
TXT_HOSTS = ("@", "default._domainkey")   # @ = apex SPF, DKIM selector
SEEDED_INFRA_HOSTS = ("www", "vpn", "mail", "portal", "ns1", "ns2")

# §4.9: a known out-of-zone canary used ONLY by the recursion-leak probe, never
# written into a query file. Exposed so the runner / preflight can import it.
LEAK_CANARY = "leak-canary.invalid"

_RAND_LABEL_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


# ================================================================================
# Seed model — where the in-zone universe comes from
# ================================================================================
@dataclass
class SeedModel:
    """The set of seeded zones + the device/pool universe queries may target.

    Sourced (in priority order) from:
      1. the seeder's ``seed-manifest.json`` (authoritative — what was *actually*
         created), when present, OR
      2. the run manifest's ``seed`` block (forward_zones / reverse_zones / CIDRs),
         used before the seeder has run or in standalone generation.
    """

    forward_zones: list[str]          # e.g. ["campus.example.edu"]
    reverse_zones: list[str]          # e.g. ["0.10.in-addr.arpa", ...]
    subnet_cidrs: list[str]           # e.g. ["10.0.0.0/16", ...]
    pool_ranges: list[tuple[str, str]] = field(default_factory=list)  # (first, last) per subnet
    unique_devices: int = 250_000
    hostname_fraction: float = 0.7

    # Pre-computed normalized zone suffixes for the validator (no trailing dot, lower).
    _all_zone_suffixes: tuple[str, ...] = field(default_factory=tuple, repr=False)

    def __post_init__(self) -> None:
        zones = [z.rstrip(".").lower() for z in (self.forward_zones + self.reverse_zones) if z]
        self._all_zone_suffixes = tuple(sorted(set(zones), key=len, reverse=True))

    @property
    def primary_forward(self) -> str:
        return (self.forward_zones[0].rstrip(".").lower() if self.forward_zones
                else "campus.example.edu")

    def in_zone(self, qname: str) -> bool:
        """§4.9 Layer 2: is ``qname`` a suffix-match of ANY seeded zone?

        ``host.campus.example.edu`` matches ``campus.example.edu`` (label boundary),
        and the apex itself matches. ``campus.example.edu.evil.com`` does NOT.
        """
        q = qname.rstrip(".").lower()
        for z in self._all_zone_suffixes:
            if q == z or q.endswith("." + z):
                return True
        return False


def _pool_ranges_from_subnet(cidr: str, pool_fraction: float) -> tuple[str, str]:
    """Replicate the seeder's pool placement so PTR/forward names target the leased
    space: a contiguous block of ``pool_fraction`` of host space, offset from the
    network address (skip .0 network + a small gateway/static head). This MUST stay
    inside ``cidr`` so the derived names are in-zone by construction.
    """
    net = ipaddress.ip_network(cidr, strict=False)
    hosts_total = net.num_addresses
    # Skip network addr + a small head (gateway/static room); never exceed broadcast.
    head = min(16, max(1, hosts_total // 256))
    pool_size = max(1, int(hosts_total * pool_fraction))
    first_int = int(net.network_address) + head
    last_int = min(int(net.broadcast_address) - 1, first_int + pool_size - 1)
    if last_int < first_int:
        last_int = first_int
    return str(ipaddress.ip_address(first_int)), str(ipaddress.ip_address(last_int))


def build_seed_model(m: manifest_mod.Manifest, seed_manifest_path: Path | None,
                     log) -> SeedModel:
    """Build the in-zone universe, preferring the seeder's recorded manifest."""
    sm = read_json(seed_manifest_path) if seed_manifest_path else None
    if isinstance(sm, dict) and sm.get("dns"):
        dns = sm["dns"]
        fwd = list(dns.get("forward_zones", []) or [])
        rev = list(dns.get("reverse_zones", []) or [])
        cidrs = list(sm.get("subnet_cidrs", []) or [])
        pools_raw = sm.get("pool_ranges", []) or []
        pools = [(p[0], p[1]) for p in pools_raw if isinstance(p, (list, tuple)) and len(p) == 2]
        log_event(log, 20, "seed model from seed-manifest", source=str(seed_manifest_path),
                  forward_zones=len(fwd), reverse_zones=len(rev), subnets=len(cidrs))
        return SeedModel(forward_zones=fwd, reverse_zones=rev, subnet_cidrs=cidrs,
                         pool_ranges=pools, unique_devices=m.scale.unique_devices,
                         hostname_fraction=m.scale.hostname_fraction)

    # Fallback: derive from the run manifest's seed block.
    fwd = list(m.seed.dns.forward_zones)
    rev = list(m.seed.dns.reverse_zones)
    block = ipaddress.ip_network(m.seed.ip_block, strict=False)
    count = int(m.seed.subnets.get("count", 8))
    prefix = int(m.seed.subnets.get("prefix", 16))
    pool_fraction = float(m.seed.subnets.get("pool_fraction", 0.90))
    # Carve ``count`` subnets of ``prefix`` out of the block, in order (matches the
    # seeder's deterministic layout — first N subnets of the block).
    cidrs: list[str] = []
    pools: list[tuple[str, str]] = []
    for i, sub in enumerate(block.subnets(new_prefix=prefix)):
        if i >= count:
            break
        cidrs.append(str(sub))
        pools.append(_pool_ranges_from_subnet(str(sub), pool_fraction))
    # If the manifest declared no reverse zones, derive them per-subnet from the
    # CIDRs the same way the backend does (reverse_zone.py:36 alignment).
    if not rev:
        rev = sorted({_reverse_zone_name(c) for c in cidrs})
    log_event(log, 20, "seed model from run manifest", forward_zones=len(fwd),
              reverse_zones=len(rev), subnets=len(cidrs))
    return SeedModel(forward_zones=fwd, reverse_zones=rev, subnet_cidrs=cidrs,
                     pool_ranges=pools, unique_devices=m.scale.unique_devices,
                     hostname_fraction=m.scale.hostname_fraction)


def _reverse_zone_name(cidr: str) -> str:
    """Octet-aligned reverse-zone name for an IPv4 CIDR (no trailing dot).

    Mirrors backend/app/services/dns/reverse_zone.py:36 compute_reverse_zone_name
    (the /8,/16,/24 alignment) so our derived reverse zones match the seeder's.
    """
    net = ipaddress.ip_network(cidr, strict=False)
    if isinstance(net, ipaddress.IPv4Network):
        if net.prefixlen <= 8:
            aligned_prefix = 8
        elif net.prefixlen <= 16:
            aligned_prefix = 16
        else:
            aligned_prefix = 24
        aligned = ipaddress.ip_network(f"{net.network_address}/{aligned_prefix}", strict=False)
        name = aligned.network_address.reverse_pointer  # "0.0.0.10.in-addr.arpa"
        octets_kept = aligned_prefix // 8
        parts = name.split(".")
        reversed_octets = parts[:4]
        suffix = ".".join(parts[4:])
        keep = reversed_octets[4 - octets_kept:]
        return ".".join(keep + [suffix])
    # IPv6: nibble-aligned reverse name.
    aligned_prefix = ((net.prefixlen + 3) // 4) * 4
    aligned = ipaddress.ip_network(f"{net.network_address}/{aligned_prefix}", strict=False)
    name = aligned.network_address.reverse_pointer
    nibbles_kept = aligned_prefix // 4
    parts = name.split(".")
    reversed_nibbles = parts[:32]
    suffix = ".".join(parts[32:])
    keep = reversed_nibbles[32 - nibbles_kept:]
    return ".".join(keep + [suffix])


# ================================================================================
# Name candidate pools (the universe we Zipf-weight over)
# ================================================================================
def _iter_pool_ips(seed: SeedModel, cap: int):
    """Yield leased-space IPs across all pool ranges, round-robin, up to ``cap``."""
    ranges = [(int(ipaddress.ip_address(a)), int(ipaddress.ip_address(b)))
              for a, b in seed.pool_ranges]
    if not ranges:
        return
    emitted = 0
    offset = 0
    while emitted < cap:
        progressed = False
        for lo, hi in ranges:
            ip_int = lo + offset
            if ip_int <= hi:
                yield str(ipaddress.ip_address(ip_int))
                emitted += 1
                progressed = True
                if emitted >= cap:
                    return
        if not progressed:
            return
        offset += 1


def build_forward_names(seed: SeedModel, shard: int, shards: int, cap: int) -> list[str]:
    """Forward FQDNs that EXIST in the zone — the §4.5 correlation set.

    Two deterministic sources, both in-zone by construction:
      * per-device client hostnames (``dev-NNNNNNN.<forward>``) — fleet.client_hostname
      * per-leased-IP generated labels (``dhcp-<a>-<b>-<c>-<d>.<forward>``) —
        fleet.generated_forward_name (ddns.py) over the pool space
    Plus seeded infra hosts (www/vpn/mail/...).
    """
    zone = seed.primary_forward
    names: list[str] = []

    # Seeded infra (always present, small set).
    names.extend(fleet.forward_fqdn(h, zone) for h in SEEDED_INFRA_HOSTS)

    # Per-device client hostnames — only the DDNS-publishing fraction has a name.
    n_devices = min(seed.unique_devices, cap)
    publish_cutoff = seed.hostname_fraction
    rnd = random.Random(0xD15EA5E ^ (shard << 16))   # deterministic per shard
    for idx in fleet.shard_indices(n_devices, shard, max(1, shards)):
        # Stable per-device publish decision (matches the DHCP generator's lever).
        if (idx * 2654435761 & 0xFFFFFFFF) / 0xFFFFFFFF >= publish_cutoff:
            continue
        names.append(fleet.forward_fqdn(fleet.client_hostname(idx), zone))
        if len(names) >= cap:
            break

    # Per-leased-IP generated names (the always_generate dhcp-<a>-<b>-<c>-<d> shape).
    remaining = max(0, cap - len(names))
    for ip in _iter_pool_ips(seed, remaining):
        names.append(fleet.forward_fqdn(fleet.generated_forward_name(ip), zone))

    # Deterministic shuffle so Zipf rank isn't correlated with source ordering.
    rnd.shuffle(names)
    return names


def build_ptr_names(seed: SeedModel, cap: int) -> list[str]:
    """PTR qnames for the leased space — in the seeded reverse zones (fleet.ptr_qname)."""
    return [fleet.ptr_qname(ip) for ip in _iter_pool_ips(seed, cap)]


def build_srv_names(seed: SeedModel) -> list[str]:
    return [f"{p}.{seed.primary_forward}" for p in SRV_PREFIXES]


def build_mx_txt_names(seed: SeedModel) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for h in MX_HOSTS:
        out.append((seed.primary_forward, "MX") if h == "@"
                   else (f"{h}.{seed.primary_forward}", "MX"))
    for h in TXT_HOSTS:
        out.append((seed.primary_forward, "TXT") if h == "@"
                   else (f"{h}.{seed.primary_forward}", "TXT"))
    return out


def build_apex_names(seed: SeedModel) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for z in seed.forward_zones + seed.reverse_zones:
        zn = z.rstrip(".").lower()
        out.append((zn, "SOA"))
        out.append((zn, "NS"))
    return out


def _random_label(rnd: random.Random, n: int = 12) -> str:
    return "".join(rnd.choice(_RAND_LABEL_ALPHABET) for _ in range(n))


def build_miss_names(seed: SeedModel, count: int, rnd: random.Random) -> list[str]:
    """§1.7/§4.9 deliberate misses: RANDOM LABELS *UNDER* A SEEDED ZONE.

    These resolve to authoritative NXDOMAIN (recursion off) — NEVER apex/external
    names (which would REFUSED → leak). Spread across forward + reverse zones.
    """
    zones = [z.rstrip(".").lower() for z in (seed.forward_zones + seed.reverse_zones)]
    if not zones:
        return []
    out: list[str] = []
    for _ in range(count):
        z = rnd.choice(zones)
        # 1-2 random labels prepended to a real seeded zone → in-zone, nonexistent.
        depth = rnd.choice((1, 1, 2))
        labels = [_random_label(rnd, rnd.randint(8, 16)) for _ in range(depth)]
        out.append(".".join(labels + [z]))
    return out


# ================================================================================
# Zipfian weighting
# ================================================================================
def zipf_weighted_choices(items: list, k: int, rnd: random.Random, s: float = ZIPF_S) -> list:
    """Pick ``k`` items from ``items`` with a Zipf(s) popularity over their order.

    Item at rank r (1-based) gets weight 1/r**s. With s≈1.0 the top ~1% absorb
    ~50% of picks (§4.2). ``items`` should already be shuffled so rank != source.
    """
    n = len(items)
    if n == 0:
        return []
    # Cumulative weights (harmonic). Build once, sample k times via bisect.
    import bisect
    cum: list[float] = []
    total = 0.0
    for r in range(1, n + 1):
        total += 1.0 / (r ** s)
        cum.append(total)
    out = []
    for _ in range(k):
        x = rnd.random() * total
        idx = bisect.bisect_left(cum, x)
        if idx >= n:
            idx = n - 1
        out.append(items[idx])
    return out


# ================================================================================
# The §4.9 Layer-2 validator — out-of-zone = ABORT
# ================================================================================
class OutOfZoneError(RuntimeError):
    """Raised when a generated qname is NOT a suffix-match of any seeded zone."""


def validate_qname(seed: SeedModel, qname: str) -> None:
    if not seed.in_zone(qname):
        raise OutOfZoneError(
            f"OUT-OF-ZONE qname {qname!r} is not a suffix of any seeded zone "
            f"{list(seed._all_zone_suffixes)!r} — this would REFUSED/leak (§4.9 Layer 2)")


def validate_line(seed: SeedModel, line: str) -> None:
    """Validate one ``<qname> <qtype>`` line. Empty/comment lines are ignored."""
    s = line.strip()
    if not s or s.startswith(";") or s.startswith("#"):
        return
    parts = s.split()
    if len(parts) < 2:
        raise OutOfZoneError(f"malformed query line (need '<qname> <qtype>'): {line!r}")
    validate_qname(seed, parts[0])


# ================================================================================
# File emission
# ================================================================================
def _compose_lines(seed: SeedModel, mix: dict[str, float], count: int,
                   shard: int, shards: int, salt: int, log) -> tuple[list[str], dict]:
    """Compose ``count`` ``<qname> <qtype>`` lines per ``mix``, Zipf-weighted,
    validating EVERY qname is in-zone (aborts on the first leak)."""
    rnd = random.Random(0xBADCAFE ^ salt ^ (shard << 24))

    # Cap candidate universes so memory stays bounded on a 5–20M-line file.
    fwd_cap = min(500_000, max(10_000, count))
    ptr_cap = min(500_000, max(10_000, count))

    fwd_names = build_forward_names(seed, shard, shards, fwd_cap)
    ptr_names = build_ptr_names(seed, ptr_cap)
    srv_names = build_srv_names(seed)
    mxtxt = build_mx_txt_names(seed)
    apex = build_apex_names(seed)

    lines: list[str] = []
    counts = {k: 0 for k in mix}

    def emit(qname: str, qtype: str, bucket: str) -> None:
        validate_qname(seed, qname)   # §4.9 — abort before any name reaches the file
        lines.append(f"{qname} {qtype}")
        counts[bucket] += 1

    # A + AAAA over the forward set (Zipf).
    n_a = int(count * mix["A"])
    n_aaaa = int(count * mix["AAAA"])
    if fwd_names:
        for nm in zipf_weighted_choices(fwd_names, n_a, rnd):
            emit(nm, "A", "A")
        for nm in zipf_weighted_choices(fwd_names, n_aaaa, rnd):
            emit(nm, "AAAA", "AAAA")

    # PTR over the reverse set (Zipf).
    n_ptr = int(count * mix["PTR"])
    if ptr_names:
        for nm in zipf_weighted_choices(ptr_names, n_ptr, rnd):
            emit(nm, "PTR", "PTR")

    # SRV (uniform over the small seeded set).
    n_srv = int(count * mix["SRV"])
    if srv_names:
        for _ in range(n_srv):
            emit(rnd.choice(srv_names), "SRV", "SRV")

    # MX + TXT.
    n_mxtxt = int(count * mix["MX_TXT"])
    if mxtxt:
        for _ in range(n_mxtxt):
            nm, qt = rnd.choice(mxtxt)
            emit(nm, qt, "MX_TXT")

    # SOA + NS apexes.
    n_apex = int(count * mix["SOA_NS"])
    if apex:
        for _ in range(n_apex):
            nm, qt = rnd.choice(apex)
            emit(nm, qt, "SOA_NS")

    # Deliberate misses — random labels UNDER seeded zones (NXDOMAIN, never REFUSED).
    n_miss = count - len(lines)   # absorb rounding into the miss slice
    if n_miss > 0:
        for nm in build_miss_names(seed, n_miss, rnd):
            emit(nm, "A", "MISS")

    rnd.shuffle(lines)   # interleave types so the replay isn't bursty per-class
    stats = {
        "lines": len(lines),
        "composition": counts,
        "candidate_pools": {
            "forward_names": len(fwd_names),
            "ptr_names": len(ptr_names),
            "srv_names": len(srv_names),
            "apex_names": len(apex),
        },
    }
    return lines, stats


def write_query_file(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Stream to a temp file then rename (durability for multi-million-line files).
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(f"; SpatiumDDI perf DNS query set — {len(lines)} lines\n")
        f.write("; format: '<qname> <qtype>' per line (dnsperf/resperf -d input)\n")
        f.write("; §4.9 SAFETY: every qname validated as a suffix of a seeded zone.\n")
        f.write("\n".join(lines))
        f.write("\n")
    os.replace(tmp, path)


# ================================================================================
# Self-check — re-validate written files (defense-in-depth for §4.9 Layer 2)
# ================================================================================
def self_check_file(seed: SeedModel, path: Path, log) -> int:
    """Re-validate every line of ``path``. Returns the count of out-of-zone lines
    (0 == clean). Logs the first few offenders."""
    bad = 0
    total = 0
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            s = line.strip()
            if not s or s.startswith(";") or s.startswith("#"):
                continue
            total += 1
            try:
                validate_line(seed, line)
            except OutOfZoneError as e:
                bad += 1
                if bad <= 10:
                    log_event(log, 40, "self-check OUT-OF-ZONE line", file=str(path),
                              line_no=n, detail=str(e))
    log_event(log, 40 if bad else 20, "self-check complete", file=str(path),
              checked=total, out_of_zone=bad)
    return bad


# ================================================================================
# CLI
# ================================================================================
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Build (and safety-validate) the DNS query set (§4.2 / §4.9 Layer 2).")
    p.add_argument("--run-id", required=True)
    p.add_argument("--run-root", required=True)
    p.add_argument("--manifest", required=True)
    p.add_argument("--out", default=None,
                   help="base output path; .steady.txt / .cold.txt derived from it. "
                        "Default: <run>/generators/dns/queries")
    p.add_argument("--seed-manifest", default=None,
                   help="seeder's seed-manifest.json (default: rp.seed_manifest)")
    p.add_argument("--count", type=int, default=2_000_000,
                   help="lines per output file (default 2,000,000)")
    p.add_argument("--shard", type=int, default=0)
    p.add_argument("--shards", type=int, default=1)
    p.add_argument("--self-check", action="store_true",
                   help="re-validate the (existing or just-written) files and exit")
    return p.parse_args(argv)


def _resolve_out_base(args, rp: RunPaths) -> Path:
    if args.out:
        base = Path(args.out)
        # Strip a trailing .txt/.steady.txt so we can derive both files cleanly.
        for suf in (".steady.txt", ".cold.txt", ".txt"):
            if str(base).endswith(suf):
                base = Path(str(base)[: -len(suf)])
                break
        return base
    return rp.generators_dir / "dns" / "queries"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    rp = RunPaths.for_run(args.run_id, args.run_root)
    log = get_logger("dns_queryset", service=SERVICE, run_id=args.run_id,
                     logfile=rp.worker_log("dns_queryset"))
    m = manifest_mod.load(args.manifest)

    seed_manifest_path = Path(args.seed_manifest) if args.seed_manifest else rp.seed_manifest
    if not seed_manifest_path.exists():
        log_event(log, 30, "seed-manifest not found — deriving in-zone set from run "
                  "manifest seed block", path=str(seed_manifest_path))
        seed_manifest_path = None
    seed = build_seed_model(m, seed_manifest_path, log)

    if not seed._all_zone_suffixes:
        log_event(log, 40, "no seeded zones — cannot build a safe query set (§4.9)")
        return 2

    base = _resolve_out_base(args, rp)
    steady_path = Path(str(base) + ".steady.txt")
    cold_path = Path(str(base) + ".cold.txt")

    if args.self_check:
        # Re-validate whatever exists (defense-in-depth gate, runnable standalone).
        targets = [p for p in (steady_path, cold_path) if p.exists()]
        if not targets:
            log_event(log, 40, "self-check: no query files to check", base=str(base))
            return 2
        bad = sum(self_check_file(seed, p, log) for p in targets)
        return 1 if bad else 0

    log_event(log, 20, "building query set", count=args.count, shard=args.shard,
              shards=args.shards, steady=str(steady_path), cold=str(cold_path))

    try:
        steady_lines, steady_stats = _compose_lines(
            seed, MIX, args.count, args.shard, args.shards, salt=0x5EED, log=log)
        cold_lines, cold_stats = _compose_lines(
            seed, COLD_MIX, args.count, args.shard, args.shards, salt=0xC01D, log=log)
    except OutOfZoneError as e:
        # §4.9 Layer 2 — a leak/bug. ABORT LOUDLY, write nothing.
        log_event(log, 50, "ABORT — generated an out-of-zone qname (§4.9 safety gate)",
                  detail=str(e))
        return 3

    write_query_file(steady_path, steady_lines)
    write_query_file(cold_path, cold_lines)

    # Defense-in-depth: re-validate what we just wrote.
    bad = self_check_file(seed, steady_path, log) + self_check_file(seed, cold_path, log)
    if bad:
        log_event(log, 50, "ABORT — self-check found out-of-zone lines post-write", bad=bad)
        return 3

    stats_path = rp.snapshot("dns_queryset")
    atomic_write_json(stats_path, {
        "shard": args.shard, "shards": args.shards, "count": args.count,
        "seeded_zones": list(seed._all_zone_suffixes),
        "primary_forward": seed.primary_forward,
        "steady": {"path": str(steady_path), **steady_stats},
        "cold": {"path": str(cold_path), **cold_stats},
        "self_check_out_of_zone": 0,
    })
    log_event(log, 20, "query set written + validated in-zone", steady_lines=len(steady_lines),
              cold_lines=len(cold_lines), stats=str(stats_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
