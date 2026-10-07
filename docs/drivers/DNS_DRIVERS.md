# DNS Driver Specification

## Overview

DNS drivers implement the `DNSDriver` abstract base class in [`app/drivers/dns/base.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/dns/base.py). They are responsible for translating SpatiumDDI's internal DNS model into backend-neutral config + per-record ops. The critical constraint: **no DNS driver may restart the DNS daemon** as part of normal record or zone operations.

The control-plane driver is a *thin* translator (CLAUDE.md non-negotiable #10): it takes SpatiumDDI DB models and emits a canonical `ConfigBundle` (plus per-record `RecordChange` ops) in neutral types. For agent-managed drivers (BIND9, PowerDNS) the actual daemon lifecycle — `nsupdate`, `rndc`, the PowerDNS REST API — runs inside the agent container; the control-plane `apply_record_change` is a formulate-only no-op that logs the op. For agentless drivers (Windows DNS, the cloud providers) `apply_record_change` runs synchronously from the control plane.

---

## 1. Abstract Base Class

The neutral data shapes and the ABC both live in [`app/drivers/dns/base.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/dns/base.py). The driver speaks only in these frozen dataclasses — `RecordData`, `ZoneData`, `RecordChange`, `RecordChangeResult`, `ConfigBundle`, `ServerOptions`, plus the BIND9 config pieces (`ViewData`, `AclData`, `TsigKey`, `TrustAnchorData`, `DNSSECPolicyData`, `EffectiveBlocklistData`). A couple of the central ones:

```python
@dataclass(frozen=True)
class RecordData:
    name: str             # relative label ("@" = apex)
    record_type: str      # A | AAAA | CNAME | MX | TXT | NS | PTR | SRV | CAA | ...
    value: str
    ttl: int | None = None
    priority: int | None = None   # MX, SRV
    weight: int | None = None     # SRV
    port: int | None = None       # SRV

@dataclass(frozen=True)
class RecordChange:
    op: Literal["create", "update", "delete"]
    zone_name: str
    record: RecordData
    target_serial: int
    tsig_key_name: str | None = None
    op_id: str = ""               # caller-supplied UUID for ACK tracking

@dataclass(frozen=True)
class RecordChangeResult:
    ok: bool
    change: RecordChange          # original input echoed back verbatim
    error: str | None = None
```

The ABC itself:

```python
from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any

class DNSDriver(ABC):
    """Abstract base class for DNS backend drivers.

    Drivers are pure renderers + single-record appliers. They do not manage
    daemon lifecycle (the agent does that). They must be stateless and safe
    to instantiate per call.
    """

    name: str = "abstract"

    # ── Rendering ──────────────────────────────────────────────────────────
    @abstractmethod
    def render_server_config(
        self, server: Any, options: ServerOptions, *, bundle: ConfigBundle | None = None
    ) -> str:
        """Render the daemon's top-level config (e.g. ``named.conf``)."""

    @abstractmethod
    def render_zone_config(self, zone: ZoneData) -> str:
        """Render the per-zone stanza to be included in the server config."""

    @abstractmethod
    def render_zone_file(self, zone: ZoneData, records: list[RecordData]) -> str:
        """Render an RFC 1035-format zone file."""

    @abstractmethod
    def render_rpz_zone(self, blocklist: EffectiveBlocklistData) -> str:
        """Render an RPZ zone file (or equivalent) from an effective blocklist."""

    # ── Runtime (agent-side; control plane only *formulates* these) ────────
    @abstractmethod
    async def apply_record_change(self, server: Any, change: RecordChange) -> None:
        """Apply a single record change to the daemon (loopback RFC 2136 / API)."""

    async def apply_record_changes(
        self, server: Any, changes: Sequence[RecordChange]
    ) -> list[RecordChangeResult]:
        """Apply many record changes in as few round trips as possible.

        Default impl: sequential loop over apply_record_change, catching each
        per-op exception into a RecordChangeResult(ok=False) so one bad record
        doesn't abort the batch. BIND9 + PowerDNS inherit it unchanged;
        Windows DNS overrides it with a real WinRM batch (§3.7)."""

    @abstractmethod
    async def reload_config(self, server: Any) -> None:
        """Instruct the daemon to re-read its full config (e.g. ``rndc reconfig``)."""

    @abstractmethod
    async def reload_zone(self, server: Any, zone_name: str) -> None:
        """Instruct the daemon to reload a single zone."""

    # ── Validation / introspection ─────────────────────────────────────────
    @abstractmethod
    def validate_config(self, bundle: ConfigBundle) -> tuple[bool, list[str]]:
        """Validate a bundle before apply. Returns (ok, errors)."""

    @abstractmethod
    def capabilities(self) -> dict[str, Any]:
        """Return a dict describing what this driver supports."""
```

`apply_record_changes` is the only concrete method on the ABC — every other method is `@abstractmethod`. There is no `health_check` / `get_zones` / `create_zone` / `create_record` style CRUD surface on the driver: zone reads/writes for agentless drivers go through their own `pull_zones_from_server` / `pull_zone_records` / `apply_zone_change` helpers (§3, §4A), not the ABC. Incremental updates only — drivers must never restart the daemon for normal operations (see the per-driver update-strategy tables below).

---

## 2. BIND9 Driver

### Update Strategy: RFC 2136 + rndc (never named restart)

| Operation | Mechanism | Notes |
|---|---|---|
| Add/update/delete record | RFC 2136 `nsupdate` (via `dnspython`) | Incremental, instant, TSIG-signed |
| Create zone | `rndc addzone` | No restart; zone active immediately |
| Delete zone | `rndc delzone` | No restart |
| Update zone options (SOA, TTL) | `nsupdate` SOA record replacement | Incremental |
| Add/update view | Regenerate `named.conf` → SCP → `rndc reconfig` | No restart; new config loaded in-place |
| Update forwarders, options | Regenerate `named.conf` → SCP → `rndc reconfig` | No restart |
| Update RPZ (blocking) | `rndc reload <rpz-zone>` after writing RPZ zone file | Zone-level reload only |
| **Full daemon restart** | ❌ NEVER for normal operations | Only for: initial install, major version upgrade |

### Record ops carry the whole RRset ([#773](https://github.com/spatiumnorth/spatiumddi/issues/773))

A record op names one record, but none of the three agent wire protocols
can express "change this RR and leave its siblings alone" from a payload
that only carries the NEW value. Each driver therefore had to perform a
whole-RRset write, and each lost the siblings doing it: BIND9 used
`upd.replace(...)`, Technitium `overwrite=true`, and PowerDNS — which
read-merged and so kept siblings — could not remove the *old* value on an
edit. A name with several values at one type (round-robin A, a backup MX,
SPF beside a verification TXT, multiple apex NS) ended up serving only
whichever op landed last.

The control plane is the only place that knows the complete set, so it
ships it. Every agent-bound `create` / `update` / `delete` op payload
carries:

```json
"rrset": {"ttl": 3600,
          "members": [{"value": "10.20.7.21"},
                      {"value": "10.20.7.22"}]}
```

`members` is the desired state **after** the op — an empty list means the
RRset should not exist. Members carry `priority` / `weight` / `port` so
each driver composes their wire form exactly as it composes the op's own.
Per RFC 2181 an RRset has one TTL, resolved control-plane-side (lowest of
the members, with a NULL falling back to the zone default rather than a
hardcoded 3600).

Each driver applies it atomically where it can: BIND9 as a single
`upd.replace(name, ttl, rtype, *values)` — dnspython emits one
delete-RRset plus N adds in ONE update message — and PowerDNS as one
`REPLACE` PATCH with no preceding GET. Technitium's REST API is one
record per call, so a create/update is N calls (member 0 with
`overwrite=true`, the rest `false`) while a delete stays a single
value-scoped call. Ops are therefore idempotent: replaying one converges
the server to the database rather than depending on what ran before it.

Ops enqueued together all carry the RRset as it should be once the WHOLE
batch has landed, not a running prefix — so they are order-independent
too. That matters because `bulk_delete_records` builds its ops from live
rows and only removes them once the wire result comes back: reconciling
each op against the raw snapshot in isolation would have two deletes at
one name ship contradictory sets, and whichever landed last would
reinstate a value the operator deleted.

`rrset_action` (`add` / `delete_value`) is the older per-op override.
Setting it **opts an op out** of the stamping above, and it remains the
fallback for an op enqueued by a control plane that predates `rrset`. Two
callers use it: DNS pools and the Windows-cutover TTL pre-flight. Pools
opt out deliberately — a pool re-points a member as a `delete_value` plus
an `add` across two separate enqueue calls on one serial, and whole-RRset
writes would make that pair order-dependent, since the delete's set is
computed before the row is mutated.

The **agentless** drivers get the same set (#783), through
`RecordChange.rrset` rather than the wire payload — `record_ops` stamps the
op, then lifts it into the neutral `RRsetData` the drivers consume. Windows
DNS applies it as one remove-all-then-add-each-member write on both its
PowerShell paths and as an RFC 2136 `replace` on its Path A path; Route 53,
Azure DNS and Google Cloud DNS apply it on their `update` path, which
previously replaced the whole RRset with the op's single value (their
create/delete paths already read-merged and were never affected).
Cloudflare stores one row per value and applies it on create and update as
a set write (#1494): rows matching a member are kept, missing members are
created, then the remaining rows at that name + type are deleted. That
includes a row added in the Cloudflare dashboard, by design: SpatiumDDI
owns the RRsets it manages, so a value it does not know is removed on the
next create or update at that name + type, as with the other drivers that
write whole RRsets. A delete stays a single-value delete. A driver that sees
`rrset=None` keeps its previous per-value behaviour.

### TSIG Authentication

All RFC 2136 updates are TSIG-signed:
```python
keyring = dns.tsigkeyring.from_text({
    self.tsig_keyname: self.tsig_secret   # stored encrypted in DB
})
update = dns.update.Update(zone, keyring=keyring, keyalgorithm=dns.tsig.HMAC_SHA256)
```

### Zone Creation via rndc addzone

```bash
rndc addzone example.com '{ type primary; file "/var/named/example.com.db"; };'
```

The driver:
1. Generates the zone file from SpatiumDDI zone data
2. SCPs zone file to BIND9 host
3. Runs `rndc addzone`
4. Verifies zone is active with `rndc zonestatus example.com`

### Named.conf Management

`named.conf` is **never edited by hand** when SpatiumDDI manages BIND9. The driver maintains:
- `named.conf.spatiumddi` — generated includes (views, zones, options)
- `named.conf` includes `named.conf.spatiumddi`
- Changes: regenerate `named.conf.spatiumddi` → SCP → `rndc reconfig`

**Geo-steering views (issue #530).** GSLB pool members that carry a
*serving scope* (client CIDRs and/or a Site) render as synthesized
`view { match-clients … }` blocks — a "geo view". The driver renders
these exactly like operator split-horizon views (`ViewData` +
per-`view_name` `ZoneData`); the geo synthesis lives in the bundle
builders (`app.services.dns.pool_geo`), so the driver itself needs no
special-casing. A catch-all `spatium-geo-default` view (`match-clients
{ any; }`) renders last so non-matching clients get the default member
set. v1 steers on **resolver source IP**; ECS (RFC 7871) is a
documented future improvement. See DNS.md §17.

### Serial Number Management

Zone serial follows `YYYYMMDDnn` format:
- On each record change via `nsupdate`, serial auto-increments (BIND handles this)
- Driver tracks and displays current serial from `rndc zonestatus`

### BIND9 Driver Configuration

```python
@dataclass
class BIND9DriverConfig:
    host: str
    ssh_port: int = 22
    ssh_user: str = "bind-mgmt"
    ssh_key: str                  # Path to SSH private key (or key content)
    rndc_key_name: str
    rndc_key_secret: str          # Encrypted in DB
    tsig_key_name: str
    tsig_key_secret: str          # Encrypted in DB
    named_conf_dir: str = "/etc/bind"
    zone_file_dir: str = "/var/cache/bind"
    rndc_host: str = "127.0.0.1"
    rndc_port: int = 953
```

### 2.5 DNSSEC — inline-signing (issue #49)

BIND9 9.16+ `dnssec-policy` inline-signing. **BIND owns + auto-rotates the
private keys**; the control plane stores only public state. The flow is
config-driven, not op-driven (unlike PowerDNS's REST sign):

1. **Control plane.** A signed zone (`DNSZone.dnssec_enabled`) carries an
   optional `dnssec_policy_id` → a `DNSSECPolicy` row (algorithm / NSEC3 /
   KSK+ZSK lifetimes). The bundle assembler stamps `dnssec_enabled` +
   `dnssec_policy_name` onto each zone and ships referenced custom policies
   in `dnssec_policies` (the built-in `default` carries no block). Both flow
   into the structural ETag, so a sign/policy change triggers a re-render.
2. **Agent render.** `named.conf` gets `key-directory "/var/cache/bind/keys"`,
   a top-level `dnssec-policy "<name>" { keys { ksk … ; zsk … ; }; nsec3param … ; };`
   per custom policy, and each signed primary zone's stanza gets
   `dnssec-policy "<name>"; inline-signing yes;`. BIND auto-generates keys in
   the key-directory and signs on load.
3. **DS + key-state report.** After a reload the agent's `collect_dnssec_state`
   runs `rndc dnssec -status <zone>` (parsed by the version-tolerant
   `_parse_dnssec_status`) + `dnssec-dsfromkey` over the KSK key files, and
   POSTs the DS rrset + per-key state to `/dns/agents/dnssec-state`. The
   control plane mirrors it into `DNSZone.dnssec_ds_records` + `DNSKey` rows
   (replace-per-zone) for the operator's DS-export + key-status view.
4. **Manual rollover.** `POST .../dnssec/rollover` enqueues a
   `dnssec_rollover` op (key tag); the agent runs
   `rndc dnssec -rollover -key <tag> <zone>` and re-reports. Sign/unsign ops
   are no-ops on the BIND9 agent (the config render drives signing).

Gating: `_DRIVER_GATED_OPERATIONS` allows `dnssec_sign`/`dnssec_unsign` on
`{powerdns, bind9}` and `dnssec_rollover` on `{bind9}`.

### 2.6 Rate limiting (RRL) + amplification (issue #146)

Group-level `DNSServerOptions` fields flow through the standard
`ServerOptions` → `ConfigBundle` → ETag → long-poll path (so a UI change
shifts the etag and re-renders `named.conf` with no extra wake plumbing) and
land in the `options {}` block of both renderers — the agent's
`NAMED_CONF_SKELETON` (the live config; see `_render_rate_limit_block`) and
the control-plane preview template `named.conf.j2`.

- `rrl_enabled` gates a `rate-limit { responses-per-second; window; slip;
  [qps-scale]; [exempt-clients]; [log-only]; }` stanza. `log-only` is BIND's
  dry-run (count + log drops, drop nothing) for sizing the limit safely.
- `minimal_responses`, `tcp_clients`, `clients_per_query`,
  `max_clients_per_query` each render only when set.
- **Every field defaults to a no-op**, so adding the feature renders
  byte-identical config for groups that haven't opted in (the bundle etag
  shifts once on upgrade, causing a single graceful `rndc reconfig`).
- BIND9-only. PowerDNS authoritative has no RRL equivalent; the planned
  answer there is a dnsdist front (#146 Phase 2 — shipped; see below). RRL
  drop counters (`RateDropped`/`RateSlipped` → `dns_metric_sample` →
  Stats-tab "RRL drops/s" line) + the default-off `dns_rate_limit_dropping`
  alert are #146 Phase 3 (shipped).

### 2.7 dnsdist front for PowerDNS (issue #146 Phase 2)

PowerDNS Authoritative has no RRL, so rate limiting in front of a PowerDNS
group is an opt-in **dnsdist front** (`ghcr.io/spatiumnorth/dns-dnsdist`, Alpine
+ dnsdist) — a **separate container** that forwards to pdns:53 over the
network. **pdns never moves port** (no shared netns, no restart race): the
front owns the published `:53` and forwards to `dns-powerdns:53`.

The PowerDNS agent's `render_dnsdist_conf(opts)` compiles ONLY the operator's
rate-limit **rules** (`MaxQPSIPRule` + `TCAction`/`DropAction`,
`dynBlockRulesGroup:setQueryRate`) from the group's `dnsdist_*`
`DNSServerOptions` into a shared `dnsdist-rules.conf`. The front container's
entrypoint composes those rules onto its env-driven base (`setLocal(:53)` +
`newServer({address=$DNSDIST_BACKEND})`), `--check-config`-validates, and
(re)starts dnsdist on rule-file change (dnsdist has no clean full-config hot
reload). With dnsdist disabled the rules file is absent and the front runs as
a plain pass-through — so the per-group toggle is decoupled from the deploy
and can't break pdns. Default-off; deploy via the `dns-powerdns-with-dnsdist`
compose profile. **docker-compose only for now** — the k8s/appliance front (a
dnsdist Deployment fronting the hostNetwork pdns DaemonSet) is a follow-up.

---

## 3. Windows DNS Driver

Located at [`app/drivers/dns/windows.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/dns/windows.py). Class: `WindowsDNSDriver`. Two capability tiers coexist on the same driver class; which one applies at runtime depends on whether `DNSServer.credentials_encrypted` is set.

### 3.1 Path A — RFC 2136 (always available)

| Operation | Mechanism | Notes |
|---|---|---|
| Add / update / delete record | RFC 2136 via `dnspython` (`dns.update.Update`) | TSIG-signed when configured, unsigned when allowed. |
| Zone record pull | AXFR via `dns.query.xfr` + `dns.zone.from_xfr` | Requires AXFR ACL on the Windows zone. |
| Create / delete zone | Not available in Path A | Zones must be created in Windows DNS Manager (or via Path B when credentials are set). |
| Rendering (`render_server_config`, etc.) | Returns empty string | SpatiumDDI does not write named.conf-style config for Windows DNS. |
| `reload_*` | No-op | AD replication handles zone propagation across DCs. |

Supported record types: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `PTR`, `SRV`, `NS`, `TLSA`.

### 3.2 Path B — WinRM + PowerShell (credentials required)

Activated when `DNSServer.credentials_encrypted` is set. Does **not** replace Path A for record writes; it complements it.

| Operation | Mechanism | Notes |
|---|---|---|
| List zones | `Get-DnsServerZone \| Where { -not $_.IsAutoCreated }` | Feeds the group-level "Sync with Servers" step 1. |
| Create zone | `Add-DnsServerPrimaryZone -Name <n> -ReplicationScope Domain -DynamicUpdate Secure` | Guarded with `Get-DnsServerZone -ErrorAction SilentlyContinue` — idempotent. |
| Delete zone | `Remove-DnsServerZone -Name <n> -Force` | Same idempotent guard — no-op when zone already absent. |
| Pull records | `Get-DnsServerResourceRecord -ZoneName <n>` | Sidesteps AXFR ACLs on AD-integrated zones. Returns JSON that the driver normalises into `RecordData`. |
| Test connection | `(Get-DnsServerSetting -All).BuildNumber` | Cheap probe used by the `POST /dns/test-windows-credentials` endpoint and the UI's Test button. |
| Record writes | **Still RFC 2136** | PowerShell-per-record would be too slow for hot writes. |

### 3.3 Credentials

Fernet-encrypted JSON dict, same shape as Windows DHCP:

```json
{
  "username": "CORP\\spatium-dns",
  "password": "…",
  "winrm_port": 5986,
  "transport": "ntlm",
  "use_tls": true,
  "verify_tls": true
}
```

Required security group for the service account: `DnsAdmins` on the domain (or a delegated group with equivalent rights). See [WINDOWS.md](../deployment/WINDOWS.md).

### 3.4 Driver registry classification

In [`app/drivers/dns/__init__.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/dns/__init__.py):

```python
AGENTLESS_DRIVERS: frozenset[str] = frozenset(
    {"windows_dns", "cloudflare", "route53", "azure_dns", "google_dns",
     "digitalocean", "hetzner", "linode", "vultr"}
)
```

Agentless drivers don't emit a `ConfigBundle`; the API's `record_ops.enqueue_record_op` short-circuits them and calls `apply_record_change` directly instead of queueing for a co-located agent. The cloud-hosted DNS providers (§4A) joined this set in issue #37 (the four SDK-backed ones) and issue #327 (the token-only tier: DigitalOcean / Hetzner / Linode / Vultr).

### 3.5 Write-through pattern

Zone CRUD is pushed through the Windows server **before** the SpatiumDDI DB commit:

```python
await _push_zone_to_agentless_servers(db, zone, op="create")
await db.commit()
```

If the push fails, the 502 response prevents the DB commit — the Windows DNS state and SpatiumDDI state stay consistent. Record ops follow the same pattern via the agent-side op queue for agented drivers and direct calls for agentless.

### 3.6 Shared AXFR helper

[`drivers/dns/_axfr.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/dns/_axfr.py) extracts the AXFR → `RecordData` logic used by both BIND9 and Windows Path A. Filters SOA + apex NS; absolutises CNAME / NS / PTR / MX / SRV targets.

### 3.7 Batched WinRM dispatch

Record CRUD against a Windows DNS server used to round-trip WinRM **per record** — a 40-record Sync DNS took 2-3 minutes of wall time. The driver now ships one PowerShell script per zone-chunk with every op inside: each chunk does every op server-side with a per-op `try / catch` and returns a JSON result array so one bad record doesn't abort the batch.

**Driver surface.** New plural method on the ABC:

```python
class DNSDriver(ABC):
    async def apply_record_changes(
        self, server: Any, changes: Sequence[RecordChange]
    ) -> list[RecordChangeResult]:
        """Apply many record changes in as few round trips as possible.

        Default impl calls apply_record_change in a loop — BIND9
        inherits it. Windows overrides with a real batch."""
```

BIND9 + any future driver gets the plural interface for free via the default loop.

**Windows batch sizing — length-measured chunks (issue #426).** The real constraint isn't WinRM's envelope cap (`MaxEnvelopeSize` defaults to 500 KB) but the way `pywinrm.run_ps` ships the script: UTF-16-LE → base64 → `powershell.exe -EncodedCommand <b64>` → **single CMD.EXE command line, hard-capped at ~8191 chars by Windows**. Base64 costs ×1.33, UTF-16-LE costs ×2, so each raw script char eats ~2.67 chars of command-line budget.

Rather than a fixed op count, `_pack_record_chunks` greedily packs each chunk and measures the **actual built script** against `MAX_ENCODED_COMMAND` (7800, in [`drivers/_winrm.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/_winrm.py)) via `encoded_command_len`, so a chunk of large TXT (DKIM/SPF/DMARC) records can't silently overflow the cmdline. `_WINRM_MAX_BATCH_OPS = 25` is a coarse sanity cap on top of the length check. A single op that won't fit even alone still ships as a one-op chunk; the dispatcher catches the resulting too-long error and fails just that op. (The previous fixed count of 6 had no length check — a few big TXT records would blow the cap and fail the whole chunk.)

**Script layout.** One invocation carries data-only JSON with short keys (`i/op/z/n/t/v/ttl/pr/w/p`) and a single dispatch wrapper:

```
$ErrorActionPreference='Continue'
$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64>'))
$r = @()
($p | ConvertFrom-Json) | % {
    $e = [ordered]@{change_index=[int]$_.i; ...; ok=$false}
    try {
        $ze = [bool](Get-DnsServerZone -Name $_.z -EA SilentlyContinue)
        if ($_.op -eq 'delete') { ... }
        elseif ($_.op -eq 'create' -or $_.op -eq 'update') {
            switch ($_.t) { 'A' { ... }; 'AAAA' { ... }; 'CNAME' { ... }; ... }
        } else { throw "Unsupported op" }
        $e.ok = $true
    } catch { $e.error = "$($_.Exception.Message)" }
    $r += (New-Object PSObject -Property $e)
}
$r | ConvertTo-Json -Compress -Depth 3
```

`$ErrorActionPreference = 'Continue'` ensures a per-op `throw` doesn't abort the enclosing script; the try/catch per op records the error into the result array. Chunk-wide script errors (syntax, base64 decode) still raise from `_run_ps` and propagate to the caller.

**Lifting the ceiling — pypsrp.** Future upgrade path: swap `pywinrm` for `pypsrp`. PSRP uses the WSMan Runspace protocol instead of CMD.EXE and removes the 8K limit entirely — would yield ~100 ops/batch on the same envelope settings. Tracked as a TODO comment in [`drivers/dns/windows.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/dns/windows.py).

**RFC 2136 path — `asyncio.gather`.** The 2136 write path is cheap per-op but was still serial. Record ops now run in parallel via `asyncio.gather`; no batching needed because the dnspython update framing is already compact.

**Dispatch.** `enqueue_record_ops_batch(db, zone, ops)` in [`services/dns/record_ops.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/services/dns/record_ops.py) groups pending ops by zone and calls `apply_record_changes` once per group. Zone serial bumps once per batch instead of N times. **State-aware commit**: the caller zips through the returned op rows and keeps the DB row only when the op came back `state == "failed"` — a server rejected the delete, so the record is still published and reporting "deleted" would leave a zombie the next "Sync with server" pulls back. Every other outcome deletes locally: `applied` (agentless, inline), `pending` (agent-based — the agent applies it on its next long-poll; gating on `applied` here was the #950 / #962 defect, which reported every agent-side delete as failed) and `None` (no primary to push to — DB-only cruft, #623).

**Results.**

| Path | Before | After |
|---|---|---|
| Sync DNS / 40 records | ~3 min | ~5 s |
| Bulk delete / 80 records on one zone | 80 HTTP calls | 1 HTTP call, a handful of length-packed WinRM round trips |

---

## 4. PowerDNS Driver

Located at [`app/drivers/dns/powerdns.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/dns/powerdns.py). Class: `PowerDNSDriver`. Shipped in issue #127.

PowerDNS is a second authoritative driver running side-by-side with BIND9. It is **agent-managed** the same way BIND9 is — there is one DNS agent per server, the agent owns the local PowerDNS daemon (`pdns_server`), and the control plane never opens a connection to PowerDNS directly. The agent talks to PowerDNS's REST API on `127.0.0.1:8081`; the control plane talks to the agent through the existing long-poll `/config` channel.

The shipped image (`ghcr.io/spatiumnorth/dns-powerdns`) bundles `pdns 5.0.x` with the `pdns-backend-lmdb` backend. **Upgrading this image across the 4.x → 5.x boundary migrates the LMDB schema one way** — see §4.9. LMDB is a single-file embedded zone store — no external Postgres, no shared credentials, full operational symmetry with BIND9's "zone files on local disk" model. A `gpgsql`-backend image variant is on the Phase 5+ wishlist for operators who want PowerDNS-pod-replicas-against-shared-Postgres HA, but is not the default.

### 4.1 Update Strategy: REST API (never daemon restart)

| Operation | Mechanism | Notes |
|---|---|---|
| Add / update / delete record | `PATCH /api/v1/servers/localhost/zones/<zone>` rrset patch | Idempotent; one HTTP call per rrset; PowerDNS handles serial bump internally. |
| Create zone | `POST /api/v1/servers/localhost/zones` | LMDB row created; available to query immediately. |
| Delete zone | `DELETE /api/v1/servers/localhost/zones/<zone>` | LMDB row removed; idempotent. |
| Reconcile zone (full sync) | `PUT /api/v1/servers/localhost/zones/<zone>` with full rrset list | Used on first sync or on detected drift. |
| Online DNSSEC sign | `POST .../zones/<zone>/cryptokeys` (KSK + ZSK) + `PUT .../zones/<zone>/rectify` | Idempotent — re-sign skips when keys exist. No `PRESIGNED` metadata (see §4.5). |
| Online DNSSEC unsign | `DELETE .../cryptokeys/<id>` per key | Same idempotent shape. |
| Catalog zone (RFC 9432) producer | Render apex SOA + NS + `version` TXT + per-member SHA-1-hashed PTR via the same rrset PATCH path | Producer-only; consumer mode is not wired up in the agent (Phase 5 polish). |
| **Full daemon restart** | ❌ NEVER for normal operations | Only for: image bump, zone-storage backend swap (LMDB → gpgsql). |

The agent never reads `pdns.conf` to figure out what to do — it queries PowerDNS over REST and reconciles against the `ConfigBundle` shipped from the control plane. This is the same conceptual loop as the BIND9 driver, but the wire protocol is HTTP+JSON instead of RFC 2136+rndc.

> ⚠️ **Never write zones with `pdnsutil` against a running daemon** (issue #132).
> `pdnsutil` writes straight to LMDB, behind `pdns_server`'s back.
> `pdns_server` caches the set of zones it is authoritative for
> (`zone-cache-refresh-interval`, default **300 s**), so a zone created
> after startup by `pdnsutil` is missing from that cache and the daemon
> answers as **non-authoritative** — the records are genuinely in the
> database and `dig` still returns nothing, with no error anywhere.
> `pdns_control purge` does *not* help: it flushes the query/packet
> cache, not the zone cache. Reproduced identically on 4.9.5 and 5.0.5.
>
> Writes through the REST API go through `pdns_server` itself, so the
> zone cache updates as a side effect and the zone is served immediately
> — no purge, no `rediscover`, no restart. That is why every write path
> in the agent is REST, and why the `agent-e2e.yml` DNSSEC smoke was
> rewritten onto the API in #132 (it had driven `pdnsutil`, and had
> therefore never passed since the day it was added).
>
> `pdnsutil` remains fine for **read-only** inspection (`list-zone`,
> `show-zone`) — which is exactly what makes it useful as a failure
> diagnostic: if `list-zone` shows a record that `dig` won't return,
> you are looking at this cache.

### 4.2 PowerDNS API key

PowerDNS gates its REST API with a static API key (`api-key=...` in `pdns.conf`). The container's entrypoint generates a key on first boot into **`/var/lib/spatium-dns-agent/pdns-api.key`** (mode `0600`, owned `spatium:spatium`) and the agent renders it into `pdns.conf` on every config sync. **Operators never touch this key.**

The key **persists** in the agent state dir — the entrypoint only generates when the file is absent (`if [ ! -f "$API_KEY_FILE" ]`), so it survives container restarts and is stable for the life of the volume. The agent's `_load_or_generate_api_key` reads the same path and refuses to overwrite a file it cannot read, rather than silently minting a second key while `pdns_server` is already running with the first (issue #253). Anything that needs to talk to the local API — including the `agent-e2e` DNSSEC smoke — reads that file rather than inventing a key.

The control plane has no knowledge of the API key — the trust boundary is between the agent and its co-located PowerDNS daemon, not between the control plane and PowerDNS.

### 4.3 Capabilities

```python
class PowerDNSDriver(DNSDriver):
    @classmethod
    def capabilities(cls) -> dict[str, Any]:
        return {
            "alias_records": True,         # CNAME-at-apex via PATCH
            "lua_records": True,           # ENABLE-LUA-RECORDS=1 zone metadata auto-set
            "dnssec_inline_signing": True, # online sign / unsign / re-sign
            "catalog_zones": "producer-only",  # consumer not wired up in the agent
            "views": False,                # tag-based; not surfaced as views in UI yet
            "rpz": False,                  # authoritative-only — RPZ is a recursor feature
        }
```

`alias_records: True` and `lua_records: True` are PowerDNS-only: the `ALIAS` / `LUA` record types are gated server-side by the API's `_DRIVER_GATED_RECORD_TYPES` map to `{powerdns}`, so creating them against a non-PowerDNS group returns 422 with a remediation message ("move to a PowerDNS-only group"). Online DNSSEC sign/unsign is no longer PowerDNS-only — BIND9 ships inline-signing via `dnssec-policy` (§2.5), so `_DRIVER_GATED_OPERATIONS` allows `dnssec_sign`/`dnssec_unsign` on both `{powerdns, bind9}` (and `dnssec_rollover` on `{bind9}`); only the *mechanism* differs (PowerDNS signs online via REST, BIND9 via config-driven inline-signing).

### 4.4 LUA records

LUA records are PowerDNS's mechanism for computed responses — geo-routing, weighted answers, conditional `pickrandom` / `ifportup` / `createReverse` snippets. The frontend exposes a `<textarea>` for the LUA value when the operator selects record type `LUA`; the agent auto-sets `ENABLE-LUA-RECORDS=1` zone metadata via the PowerDNS REST API the first time a zone gains a LUA record (idempotent — the metadata stays harmless when no LUA records remain).

**Security note.** LUA records execute server-side at query time. Treat them as code. The frontend's contextual banner explains this; restrict who can create LUA records via the existing RBAC `dns.record.create` permission scoped to PowerDNS groups only.

### 4.5 Online DNSSEC

PowerDNS does the full DNSSEC dance internally:

1. `POST /cryptokeys` with `keytype: ksk` (Algorithm 13 / ECDSAP256SHA256, pinned explicitly). PowerDNS generates the key and starts publishing DNSKEY rrsets.
2. `POST /cryptokeys` with `keytype: zsk` (same algorithm). PowerDNS now signs all rrsets in the zone with the ZSK on every query.
3. `PUT /zones/<zone>/rectify` — recomputes NSEC / NSEC3 chain. The agent deliberately does **not** set the `PRESIGNED` zone metadata: that flag is for externally-signed zones loaded as already-signed, whereas pdns derives online-signing intent from the presence of active/published cryptokeys (and pdns rejects setting `PRESIGNED` with "Unsupported metadata kind" — re-verified on 5.0.5 in #638).

After signing, the agent enumerates DS records via `GET /cryptokeys` and POSTs them back to the control plane through the new `POST /api/v1/dns/agents/dnssec-state` endpoint. The control plane caches them in `dns_zone.dnssec_ds_records` (JSONB) so the operator-facing zone-edit page renders them without round-tripping the agent.

**Backup integration.** DNSSEC keys live in the agent's LMDB store, **not** in the control-plane backup. Restoring a DNSSEC-signed zone to a fresh agent regenerates keys and produces NEW DS records, which must be re-published to the parent registrar. The restore endpoint surfaces this as a `RestoreOutcomeResponse.warnings[]` advisory. See [issue #127 Phase 4d](https://github.com/spatiumnorth/spatiumddi/issues/127).

### 4.6 Catalog zones (RFC 9432)

Producer-side only. When `DNSServerGroup.catalog_zones_enabled` is on and this server is the group primary, the agent renders the catalog zone alongside regular zones via the same PATCH rrset path used for normal zones:

- Apex SOA + NS
- `version` TXT pinned to `"2"` (RFC 9432 §4.1)
- One PTR per primary zone under `<sha1>.zones.<catalog-zone>.` using the canonical RFC 9432 wire-format hash. **Identical bytes to BIND9's catalog renderer** — a SpatiumDDI catalog can be served from either driver and consumed by either.

Consumer mode logs a structured warning at agent startup: the agent does not wire up PowerDNS catalog-consumer mode. Operators with PowerDNS secondaries pull via plain AXFR against the producer; full consumer-side support is still a Phase 5 polish item.

### 4.7 PowerDNSDriver Configuration

```python
@dataclass
class PowerDNSDriverConfig:
    api_url: str = "http://127.0.0.1:8081"   # local-only by design
    api_key: str                             # generated by entrypoint, agent reads from env
    api_timeout: float = 10.0
```

There is no `host` / `ssh_user` / `ssh_key` / RNDC counterpart — PowerDNS configuration is entirely REST-driven, and the REST endpoint is bound to loopback. This is significantly less surface area than the BIND9 driver maintains.

### 4.8 LMDB cache + recovery

LMDB is a single mmap'd file at `/var/lib/powerdns/pdns.lmdb`. The shipped Helm chart and standalone Compose file mount it on a persistent PVC / volume:

```yaml
# charts/spatiumddi/templates/dns-agent.yaml — flavor: powerdns branch
volumeMounts:
  - { name: dns-state, mountPath: /var/lib/powerdns }
```

```yaml
# docker-compose.agent-dns-powerdns.yml
volumes:
  dns_powerdns_lmdb: {}
services:
  dns-powerdns:
    volumes:
      - dns_powerdns_lmdb:/var/lib/powerdns
```

On a fresh install the LMDB backend **self-initialises on first `pdns_server` start** — the daemon mmaps the configured `lmdb-filename` (and its sharded siblings) and writes the env header itself, so the entrypoint deliberately does **not** pre-create the file (an empty 0-byte `pdns.lmdb` would be rejected by `mdb_env_open`; the entrypoint only removes a stale 0-byte leftover from a prior bad start). Once pdns is up, the long-poll picks up the first ConfigBundle and reconciles the zones. If the LMDB file is already populated (restart on existing volume), `pdns_server` boots straight into serving and the agent reconciles any DB drift on the next ConfigBundle ETag flip.

LMDB cache survives control-plane outages — non-negotiable #5 in `CLAUDE.md`. The daemon keeps answering queries from the on-disk LMDB store regardless of whether the agent can reach the control plane.

### 4.9 The LMDB schema guard — rollback is a two-step operation (issue #638)

**PowerDNS 5.0 migrates the LMDB schema from v5 to v6 the first time it opens the database.** A read is enough to trigger it, it is silent, and upstream ships no downgrade. The documented `lmdb-schema-version=5` escape hatch is a docs bug — setting it makes pdns refuse to boot outright. Afterwards, pdns 4.9 cannot open the database at all:

```
Caught an exception instantiating a backend (lmdb), cleaning up
Error: Somehow, we are not at schema version 5. Giving up
```

This matters because **rolling back the image does not roll back the database.** The LMDB is persisted in every deployment shape (Compose named volume / appliance hostPath / chart PVC), and the appliance A/B slot rollback swaps the *rootfs* while `/var` — where the database lives — is the shared persistent partition and is untouched. Phase 8c's health-gated auto-revert lands in that state on its own, without an operator ever choosing it.

**What the image does about it.** `agent/dns/images/powerdns/lmdb-guard.sh` is installed as `spatium-pdns-lmdb-guard` and the entrypoint runs `snapshot` before the agent spawns `pdns_server`:

1. It records which pdns version last owned the database in `/var/lib/powerdns/.pdns-version`.
2. When the running binary's **major** is *higher* than the recorded one, it copies the database — the main env plus the lazily-created shards, but **not** the `-lock` reader tables, which LMDB recreates on open — into `/var/lib/powerdns/snapshots/<UTC>-pdns<from>-to-<to>/` with a `MANIFEST`, **before** the daemon can open, and therefore migrate, anything. The timestamp leads the directory name so that lexical order is always chronological. A *downgrade* is deliberately not snapshotted: the database is already at the newer schema, so the copy would be worthless and would sort ahead of the real pre-upgrade snapshot.
3. It **fails closed.** If the snapshot cannot be taken (no free space, copy error), the container refuses to start. That is deliberate: a container that won't start is recoverable by redeploying the previous image, while a migrated database is not. `PDNS_LMDB_ALLOW_UNPROTECTED_UPGRADE=1` overrides for operators who have their own backup.
4. Both kinds of snapshot — automatic pre-upgrade copies and the `pre-restore-*` undo copies a restore leaves behind — are independently pruned to the newest `PDNS_LMDB_SNAPSHOT_KEEP` (default 3). Neither is exempt: the undo copies are generated by exactly the recovery path most likely to be retried, and an unbounded pile of them fills the partition the daemon needs to write to.

**Rolling a node back.** Two steps, not one:

```sh
# 1. redeploy the older dns-powerdns image (slot rollback / image tag / helm)
# 2. put the database back, from a shell in the DNS container:
spatium-pdns-lmdb-guard list                 # inspect available snapshots
spatium-pdns-lmdb-guard restore latest       # daemon must be stopped
```

`restore` stages the incoming copy before touching the live database and saves the current one to a `pre-restore-*` snapshot first, so a failed or wrong restore is itself recoverable. For a node whose pdns is already crash-looping, set `PDNS_LMDB_RESTORE=latest` in the container environment instead — the entrypoint restores before starting the agent (`dnsPowerdns.lmdbRestore` in the appliance chart). It is safe to leave set: the guard records which snapshot the database came from, so later restarts are a no-op rather than a repeated restore over live changes.

**Multi-node rolling upgrades are safe.** During a #296 rolling upgrade node A can be on pdns 5.0 while node B is still on 4.9. They do not share a database: post-#170 every agent renders its zones as `type master` (an independent authoritative copy) and record ops fan out per-server, so each node migrates its own LMDB independently and neither can see the other's schema. A mixed-major window is a normal steady state for the duration of the run.

**The operator is warned before Start.** The rolling-upgrade preflight check `powerdns_lmdb_migration` (`backend/app/services/upgrades/preflight.py`) warns — never fails — when any appliance node still reports pdns 4.x, and names the restore command in the message. It reads `dns_server.daemon_version`, which the agent reports on every heartbeat. Once every node reports ≥ 5.0 the check goes green and stops firing.

---

## 4A. Cloud DNS drivers (agentless) — issue #37 Part B

Cloud-hosted authoritative-DNS providers ship as a driver family. The four SDK-backed ones documented in detail here are **Cloudflare**, **Amazon Route 53** (`route53`), **Azure DNS** (`azure_dns`), and **Google Cloud DNS** (`google_dns`); a token-only tier (**DigitalOcean**, **Hetzner**, **Linode**, **Vultr**) followed in issue #327 with the same agentless `CloudDNSDriverBase` shape. SpatiumDDI manages their zones and records exactly like a local BIND9 / PowerDNS / Technitium / Windows zone — same Zones / Records / group surfaces — except the control plane calls the provider's REST/SDK API directly. There is **no agent**.

These are infrastructure-DNS drivers, distinct from the *Cloud (AWS / Azure / GCP)* read-only infrastructure mirror (issue #37 Part A, in [INTEGRATIONS.md](../features/INTEGRATIONS.md)). A cloud DNS server is added through the normal Add DNS server flow and lives in a `DNSServerGroup`; it has no `CloudEndpoint` row.

### 4A.1 Agentless shape (reuses Windows-DNS Path B)

The shared base [`drivers/dns/_cloud_base.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/dns/_cloud_base.py) (`CloudDNSDriverBase`) mirrors how `windows_dns` Path B already works (§3 above):

- **No ConfigBundle / long-poll.** The `render_*` methods return `""` and the `reload_*` methods are no-ops — agentless drivers never render daemon config. `validate_config` accepts anything.
- **Credentials in the existing column.** The per-provider credential dict is Fernet-encrypted in the existing `DNSServer.credentials_encrypted` column — no new credential store. `_load_credentials` decrypts it, raising a clean `CloudDNSError` when unset vs. when the API rejects the key.
- **Record writes run synchronously from the control plane.** Once the driver name is listed in `AGENTLESS_DRIVERS` (registry §5), the API's `record_ops._apply_agentless` calls `apply_record_change` directly and records each op as `applied` / `failed` on a `DNSRecordOp` row — exactly the path Windows DNS uses. The default batch loop in `DNSDriver` isolates a per-op failure into a `RecordChangeResult(ok=False)`.
- **Zone create / delete via `apply_zone_change(server, zone, op)`** (`op` ∈ `create` / `delete`) — cloud providers have no rename, so the caller sends delete+create. Routed through the same write-through pattern as Windows zone CRUD (§3.5): pushed to the provider before the SpatiumDDI DB commit so the two states stay consistent.
- **Reads via `pull_zones_from_server` / `pull_zone_records`** — the same method names Windows DNS exposes, returning the same neutral dict / `RecordData` shape (record names relative to the apex, `@` for apex). So the existing `sync-from-server` drift path *and* the cloud import service (§ MIGRATION.md) both work against any cloud driver with no per-provider glue.

A concrete provider subclasses `CloudDNSDriverBase` and implements only five cloud-specific hooks — `_list_zones`, `_list_zone_records`, `_apply_record`, `_apply_zone`, `capabilities` — plus the `name` / `credential_fields` class attrs. Everything DNSDriver-shaped lives in the base.

### 4A.2 Per-driver credential dict shapes

`credential_fields` is an ordered tuple the Add-DNS-server modal renders and the probe validates as required:

| Driver | `name` | Credential dict (decrypted from `DNSServer.credentials_encrypted`) | SDK / transport |
|---|---|---|---|
| Cloudflare | `cloudflare` | `{api_token}` — `account_id` optional, only consulted on zone create | plain `httpx` REST against `api.cloudflare.com/client/v4` (no vendor SDK) |
| Route 53 | `route53` | `{access_key_id, secret_access_key}` — global service, no region | `boto3` |
| Azure DNS | `azure_dns` | `{tenant_id, client_id, client_secret, subscription_id, resource_group}` | `azure-identity` + `azure-mgmt-dns` |
| Google Cloud DNS | `google_dns` | `{service_account_json, project_id}` | `google-cloud-dns` |

All SDK imports are lazy (inside the client factory) so the modules import cleanly without the optional wheel, and tests can patch the factory; blocking SDK calls run under `asyncio.to_thread`. Cloudflare is the exception — pure JSON over HTTPS, so it uses `httpx` directly.

### 4A.3 Capabilities + online-DNSSEC matrix

Each driver's `capabilities()` returns the same dict shape Windows / PowerDNS use (`agentless: True`, `manages_zones: True`, `views: False`, `rpz: False`, a `record_types` list, a `notes` blurb). The operator-visible differences:

| | Cloudflare | Route 53 | Azure DNS | Google Cloud DNS |
|---|:---:|:---:|:---:|:---:|
| `dnssec_online` | ❌ | ❌ | ❌ | ❌ |
| ALIAS records | apex CNAME auto-flattened | read-only (`AliasTarget`, null TTL; authoring deferred) | deferred | — |
| Apex handling | Cloudflare flattens CNAME-at-apex | apex SOA / NS provider-managed | apex SOA Azure-managed (skipped on read) | apex SOA provider-managed |

**No cloud driver advertises online DNSSEC sign/unsign (#29).** Cloud DNSSEC is a zone-level *provider* toggle — Route 53 needs a KMS asymmetric key, Cloudflare/Google a managed-zone enable — not the per-record online signing the `dnssec_sign`/`unsign` ops model, so every cloud driver's capability dict carries `dnssec_online: False` and the DNSSEC sign/unsign operations stay gated server-side by `_DRIVER_GATED_OPERATIONS` to BIND9 / PowerDNS / Technitium (rollover to BIND9 alone). Likewise **cloud ALIAS authoring is deferred** — Route 53 / Azure alias targets need a provider resource id the generic `ALIAS` record type can't express (so `alias_records: False` and `ALIAS` is gated to PowerDNS), though existing alias rrsets are still read back. Wiring real cloud DNSSEC (provider enable + DS retrieval) and cloud ALIAS authoring is a #29 follow-up.

### 4A.4 Provider-specific wrinkles the hooks paper over

- **Cloudflare** — every reply is wrapped in a `{success, errors, result, result_info}` envelope; `_unwrap` raises `CloudDNSError` on non-2xx *or* a `success: false` (the API returns 200 with `success: false` for some validation failures). The opaque zone id is resolved by name per call. "Automatic" TTL is the sentinel `1`, surfaced as `ttl=None`. A create or update with its RRset is a set write (see the #783 section above; dashboard-added rows at that name + type are removed); without one, `update` is create-on-miss. SpatiumDDI does not model `proxied`, but no write drops it: a PUT carries the row's own flag, a proxied row's TTL (always auto) is never "corrected", and a row created at a name whose rows are proxied is created proxied.
- **Route 53** — MX / SRV priority is baked into the record value (`"10 mail.example.com."`), kept raw so it isn't double-encoded on write. ALIAS rrsets (`AliasTarget`) have no TTL → surfaced with `ttl=None`. Writes are `UPSERT`/`DELETE` change batches; a `DELETE` of a non-existent rrset (`InvalidChangeBatch`) is treated as an idempotent no-op. Hosted-zone id resolved from the FQDN via `list_hosted_zones_by_name` with an exact-name match.
- **Azure DNS** — records live in *record sets*, one per `(name, type)`, each with a typed list (`a_records`, `mx_records`, …); each set expands into one neutral `RecordData` per contained record. Create and update are both a `create_or_update` PUT of the full set. SOA is Azure-managed and dropped on read.
- **Google Cloud DNS** — calls scope by the managed-zone *id* (a slug like `example-com`), not the DNS name, so the hooks re-resolve the managed zone by matching `dns_name`. A single rrset carries one or more `rrdatas` (one `RecordData` each on read, collapsed to a single-value rrset on write). Writes are transactional change sets (`changes.create()`); the op polls `changes.status` until `done` (bounded ~60 s) so it only returns once Cloud DNS has applied it.
- **Hetzner** — talks to the **Hetzner Cloud API** (`https://api.hetzner.cloud/v1`, `Authorization: Bearer` with a Cloud *project* token, Read & Write to apply changes). Hetzner retired the standalone DNS Console API (`dns.hetzner.com/api/v1`), which now answers every call with a `301` to the Cloud Console; `_unwrap` names that case instead of reporting a bare "HTTP 301". The API is RRset-oriented like Route 53 / Azure: an op carrying a resolved `RRsetData` (#783) becomes one `set_records` (plus `change_ttl` when the TTL moved), an empty set deletes the RRset, and the per-value fallback uses `add_records` / `remove_records` against the live set. Every write returns an `action` that may still be `running`; the driver polls `/zones/actions/{id}` (backing off from 1 s to 5 s, bounded at ~60 s) before reporting success, so a change the API later rejects is not reported as applied. The backoff matters because the Cloud API allows 3600 requests per hour per project: a write answered `423 locked` (another action still running on the zone) is retried for up to 60 s, and a `429` is reported with the time the limit resets. Values are zone-file presentation format: TXT is quoted (split into 255-byte strings) on write and joined on read, and CNAME / NS / PTR / MX / SRV targets are absolutised so a value stored without the trailing dot is not read as zone-relative. Only `mode: primary` zones are listed — a secondary zone is AXFR'd by Hetzner from the operator's primaries and has no RRsets to manage.

### 4A.5 Probe

`CloudDNSDriverBase.probe(server)` is the cheap credential check behind the Add-DNS-server **Test** button — by default it lists zones and reports the count, never raising for an expected failure (returns `ok=False` with the provider message). The Cloudflare driver's `_unwrap`, Route 53's `_is_invalid_change_batch`, Azure's `_wrap_errors`, and Google's `_wrap_call` all normalise raw SDK faults into operator-facing `CloudDNSError` messages first.

---

## 4B. Technitium Driver (v1)

Third authoritative driver, alongside BIND9 and PowerDNS. Same agent-colocated shape as PowerDNS (control-plane driver is a thin/no-op translator; the real work — reconcile, auth, lifecycle — lives in the agent-side driver talking to the daemon over loopback), but even thinner: Technitium has **no config file for zone/record state at all**. The daemon persists its own config under `/etc/dns` and is configured entirely through its HTTP API (`http://127.0.0.1:5380/api/...`).

### 4B.1 Update Strategy: REST API, full-zone diff reconcile

Unlike PowerDNS's rrset-REPLACE PATCH semantics, Technitium's `/api/zones/records/add` **appends** at a given `(name, type)` by default (round-robin A records coexist without a GET-merge-PATCH dance) and only wipes the rrset when `overwrite=true` is passed explicitly. The agent driver exploits this:

- **Bulk reconcile** (`swap_and_reload`, fired on structural config changes): fetch the zone's full record set via `GET /api/zones/records/get?listZone=true`, diff by `(domain, type, params)` fingerprint against the desired bundle state, then `POST` deletes for what's extra and adds for what's missing. No `update` endpoint call needed — a changed value is just delete-old + add-new, computed from the full diff.
- **Incremental ops** (`apply_record_op`, fired per live edit): the op carries the complete desired `rrset` (see §2, [#773](https://github.com/spatiumnorth/spatiumddi/issues/773)), so `create`/`update` is member 0 with `overwrite=true` — which clears — followed by an `add` per remaining member with `overwrite=false`, and `delete` is a single value-scoped `delete` of the op's own value (the survivors are already on the server; wiping and rebuilding them would open a window where the name serves less than it should). Before #773 this path was one `add` with `overwrite=true`, which is what collapsed every multi-value RRset to its last value.
- Zone apex `NS`/`SOA` are **daemon-managed** — Technitium auto-creates its own SOA + one NS pointing at its own hostname on `/api/zones/create`, so the bundle's apex NS/SOA are intentionally excluded from every reconcile pass (pushing them would create duplicate/foreign records). Off-apex `NS` (delegations) reconcile normally.

### 4B.2 Auth — agent-provisioned bearer token

Technitium has no static local secret file the entrypoint pre-seeds (unlike PowerDNS's API key). Instead:

1. The agent generates a random admin bootstrap password once, persisted the same atomic `O_NOFOLLOW`/0600 way as PowerDNS's API key.
2. `start_daemon()` passes it via the `DNS_SERVER_ADMIN_PASSWORD` env var on every daemon start — Technitium only consumes it the very first time `/etc/dns` is empty, so this is a harmless no-op on every subsequent start.
3. On first-ever config apply, the driver calls `GET /api/user/createToken?user=admin&pass=<bootstrap-pw>&tokenName=spatiumddi-agent` **exactly once** and persists the resulting bearer token. Confirmed empirically: `createToken` is **not idempotent on tokenName** — calling it again mints a brand-new token and leaves the old one orphaned on the server — so the local token file's mere presence is the "already provisioned" signal, not an API-side check.
4. All subsequent calls carry `Authorization: Bearer <token>`. **Auth failure surfaces as HTTP 200** with `{"status": "invalid-token", ...}` in the body — confirmed empirically — so every caller must inspect the JSON `status` field, never the HTTP status code alone.

The token never reaches the control plane — same agent-local trust boundary as PowerDNS's API key and BIND9's TSIG/rndc key.

### 4B.3 Capabilities

```python
{
    "name": "technitium",
    "views": False,
    "rpz": False,
    "dnssec_inline_signing": True,
    "incremental_updates": "rest_api",
    "zone_types": ["forward", "primary", "secondary", "stub"],
    "record_types": [...],            # A/AAAA/CNAME/MX/TXT/NS/PTR/SRV/CAA/
                                       # TLSA/SSHFP/NAPTR/URI/SOA/SVCB/HTTPS/DNAME
    "alias_records": False,           # Technitium has ANAME/APP instead —
                                       # a different shape, not a drop-in
    "lua_records": False,
    "catalog_zones": True,
}
```

`dynamic_update_caps` is the all-False default (no RFC 2136 client-facing UPDATE listener wired in v1 — all mutation flows through the agent's queued record-op reconciler).

### 4B.3a Zone types, transfer and catalog (issue #743)

Neutral `zone_type` → Technitium's `/api/zones/create` `type`:

| SpatiumDDI | Technitium | Extra create param |
|---|---|---|
| `primary` | `Primary` | — |
| `secondary` | `Secondary` | `primaryNameServerAddresses` (comma-joined `masters`) |
| `stub` | `Stub` | `primaryNameServerAddresses` |
| `forward` | `Forwarder` | `forwarder` — **one** upstream only |

Three behaviours worth knowing, all confirmed against a live daemon:

- **Only a primary's records are reconciled.** A secondary and a stub fill themselves from the transfer and a forwarder holds none, so diffing them would delete whatever the daemon just pulled down. `_RECORD_MANAGED_ZONE_TYPES` gates this on both the render and the reconcile side.
- **A secondary/stub create is not guaranteed to succeed, and is not safely retryable-forever.** Technitium resolves SOA against the configured primaries at create time and errors if none answer (`DNS Server did not receive SOA record in response from any of the primary name servers`). An unreachable primary therefore fails on *every* reconcile pass. The control-plane driver rejects a secondary/stub with no `masters` up front so the operator gets a 422 on save instead of a zone that silently never appears.
- **A Forwarder zone takes a single upstream** where BIND's takes a list. The first is used and the rest are dropped with a `technitium_forwarder_extra_upstreams_ignored` warning, rather than silently.

**Zone transfer.** BIND declares `allow-transfer` once per server; Technitium has no global equivalent, so the same policy is stamped onto each primary. `["none"]`/empty → `Deny`, `any` → `Allow`, anything else → `UseSpecifiedNetworkACL` plus the CIDR list. TSIG key names are attached only where transfer is actually permitted — naming keys on a `Deny` zone would read as if signed transfer were enabled when nothing can transfer at all.

> ⚠️ **`zones/options/set` silently ignores values it does not recognise.** Setting `zoneTransfer="Bogus"` returns `{"status":"ok"}` and leaves the previous value in place. A typo therefore does not fail — it leaves transfer at whatever it was, which for a zone you meant to lock down is a security regression no log line would report. The driver validates against `_ZONE_TRANSFER_VALUES` and refuses to send anything else. Do not remove that check.

**TSIG keys** live in *global* settings, not per zone. The wire format is a **flat pipe-delimited token list read in triples** — `name|secret|algorithm|name2|secret2|algorithm2|…`. Not JSON, and not `name|algorithm|secret` (that fails with "TSIG algorithm is not supported", because it reads the secret as the algorithm). `settings/set` **replaces the whole list**, so keys an operator added directly in the Technitium console are dropped on the next sync — the same control-plane-is-truth stance the rest of the driver takes, but worth knowing. Note also that `zoneTransferTsigKeyNames` accepts a key the server does not have, so keys are pushed *before* anything references them.

**Catalog zones (RFC 9432)** work in both roles. As **producer** the agent creates the `Catalog` zone and stamps `catalog=<name>` onto each primary it owns. As **consumer** it creates a `SecondaryCatalog` zone pointed at the producer — note that zone is *not* in the bundle's zone list (the control plane ships it as a catalog block, not a zone row), so `_apply_catalog` has to create it or a consumer silently does nothing at all. Turning catalog zones off clears membership by writing `catalog=""`, which is how Technitium unsets the field; without that, disabling the feature would leave every member permanently enrolled.

### 4B.3b DNSSEC (issue #740)

Online signing, op-driven — the same shape as PowerDNS, not BIND9's config-rendered `dnssec-policy`. `dnssec_sign` / `dnssec_unsign` ride the record-op queue and branch out before any rrset machinery.

```
POST /api/zones/dnssec/sign?zone=<z>&algorithm=ECDSA&curve=P256&nxProof=NSEC
POST /api/zones/dnssec/unsign?zone=<z>
```

The neutral op carries no algorithm — it is a bare "sign this zone" from the UI, and BIND expresses the choice through a `dnssec-policy` name that means nothing here — so the driver picks **ECDSA P256 / NSEC**. RSA (with `hashAlgorithm` + `kskKeySize`/`zskKeySize`), ECDSA P384, EDDSA ED25519, and NSEC3 (`nxProof=NSEC3` + `iterations`/`saltLength`) all sign successfully if that default ever needs to become operator-selectable.

Signing is idempotent: an already-signed zone answers `Cannot sign zone: the zone is already signed.`, which is treated as success so repeated "Sign zone" clicks converge on signed rather than erroring.

**Getting the DS records out is the non-obvious part.** Technitium splits the information across two calls:

- `zones/dnssec/properties/get` has the key inventory — `keyTag`, `keyType`, `algorithmNumber`, `state`, rollover timings — and **no DS records at all**.
- The DS material lives on the zone's own DNSKEY records, at `rData.computedDigests`, and only on the KSK (a DS attests the key-signing key to the parent). Each KSK yields one digest per type — SHA256 and SHA384 observed — all of which the operator should publish to cover validators of differing sophistication.

The driver joins the two into standard presentation form, `<keyTag> <algorithm> <digestType> <digest>`, mapping Technitium's digest-type *names* back to their RFC 4034 numbers:

```
34619 13 2 DD98135E57B56C0EAB…
34619 13 4 309DB47A617B7E122C…
```

Unlike the PowerDNS agent, this driver reports `keys` as well as `ds_records` — Technitium exposes per-key state and the control plane already models it as #49's `DNSKey` rows.

> ⚠️ A signed zone serves DNSKEY / RRSIG / NSEC / NSEC3 / NSEC3PARAM records that **no bundle describes**. `_DNSSEC_RECORD_TYPES` filters them out of `_get_zone_records`; without that, the full-zone reconcile treats every signing artefact as an extra record and tries to delete the zone's own signatures on every single pass. There is a regression test for exactly this.

Manual key rollover stays BIND9-only. Technitium rolls on its own schedule — `dnssecPrivateKeys` carries `rolloverDays` per key — so `dnssec_rollover` is deliberately *not* widened to technitium.

### 4B.3c Encrypted transports (issue #741)

Technitium serves **DoT, DoH and DoQ natively** and forwards over all of them — no dnsdist-style sidecar, and no BIND-style "we can receive it but not send it" gap. Everything is driven through `settings/set`.

| Setting | Purpose |
|---|---|
| `enableDnsOverTls` / `dnsOverTlsPort` | inbound DoT (TCP, default 853) |
| `enableDnsOverHttps` / `dnsOverHttpsPort` | inbound DoH (TCP, default 443) |
| `enableDnsOverQuic` / `dnsOverQuicPort` | inbound DoQ (**UDP**, default 853) |
| `dnsTlsCertificatePath` | cert served by all three |
| `forwarderProtocol` | `Udp` / `Tcp` / `Tls` / `Https` / `Quic` |

DoQ is UDP where DoT is TCP, so `doq_port` may legitimately equal `dot_port` — 853 is the RFC default for both, and they do not collide. The firewall layer must open **udp**/`doq_port`, not tcp.

Four behaviours to know, all verified live and all silent if you get them wrong:

- **The certificate must be PKCS #12**, supplied as a file path. PEM is rejected with `DNS Server TLS certificate file must be PKCS #12 formatted`. The bundle ships PEM (that is what `ApplianceCertificate` holds and what BIND9 consumes), so `_write_tls_cert` converts and writes a 0600 `.pfx` into the agent state dir. A cert that fails to parse returns `None` and the listeners stay down — degrade to Do53, never take the daemon with it.
- **Enabling a listener and setting the cert path are independent.** `enableDnsOverTls=true` lands even when the `dnsTlsCertificatePath` in the *same call* is rejected, which would leave a listener enabled with no certificate. So the cert path goes first, in its own call, and the listeners are only enabled once it succeeds.
- **`forwarderProtocol` is silently ignored unless `forwarders` is set in the same call.** Setting the protocol alone returns `{"status":"ok"}` and leaves it at `Udp`. The two are always sent together.
- **Encrypted forwarding needs a domain name, not an IP.** `1.1.1.1` is rejected with `Address must be a domain name` — there would be nothing to validate the upstream certificate against. The neutral model carries a list of forwarder IPs plus a single `forward_tls_hostname`, so over `tls`/`https`/`quic` the hostname wins and the IPs are dropped with a log line naming what went. Technitium then normalises a bare hostname into the transport's canonical form (`cloudflare-dns.com` → `cloudflare-dns.com:853` for DoT, `https://cloudflare-dns.com/dns-query` for DoH).

`forward_transport` accepts `do53` / `tls` / `https` / `quic`, but `https` and `quic` are gated to technitium groups at the API boundary (`_TRANSPORT_DRIVER_GATE`) — BIND 9.20 has no client-side HTTP or QUIC transport, so allowing them on a bind9 group would render a `named.conf` that will not load. `doq_enabled` is gated the same way.

### 4B.3d Blocklists and the live-pull importer (issue #744)

**Blocklists.** Technitium has no RPZ. It blocks natively, from subscribed URL lists or from a per-domain *blocked zones* set, so SpatiumDDI's effective blocklist entries map onto the latter and its exceptions onto the *allowed* set — Technitium's allowed set is exactly an RPZ passthru. `blockingType` derives from the entries' block modes (`nxdomain` → `NxDomain`, `sinkhole`/`redirect` → `CustomAddress`), and it has the same silent-ignore trap as `zoneTransfer`, so it is validated before sending.

Per-view blocklists **collapse into one flat set**: Technitium's native blocking is server-wide with no view concept, and the driver declines views outright. Collapsing is the honest reading of "block these names on this server" — the alternative would be silently applying one view's list to every client. `is_wildcard` is likewise dropped: Technitium blocks a domain *and* its subdomains by default, so exact-match and wildcard land identically.

The apply **reads the live set with `blocked/export` / `allowed/export`** and leaves a set alone when it already matches the bundle, so a structural apply that did not touch a blocklist rewrites nothing and opens no window without blocking (#1425). `export` is a flat list, one name per line, which `blocked/list` is not: `list` is a one-level *tree browser* whose intermediate nodes appear without being blocked domains, and deleting one removes the whole subtree beneath it — reconciling against a flat read of its root wiped every entry in testing. A set that differs is **flushed, then written with `{kind}/import`** in chunks of 5,000 comma-separated names. Never per-domain `blocked/add` or `delete`: each of those rewrites Technitium's zone file, so a 16k-entry list took about 30 minutes and grew roughly quadratically, while `import` saves once per call. Names compare in their IDNA form, which is how Technitium stores and exports them; an error answer to `export` is treated as a difference and rewritten, never as a match.

**Live-pull importer** (`services/dns_import/technitium.py`) — one-shot migration off an existing Technitium install, feeding the same canonical IR and commit pipeline as the BIND9 / Windows / PowerDNS importers.

The difference from those is the record shape. PowerDNS hands back `content` strings that parse straight into a value; Technitium hands back structured `rData` whose field names do not match its own *write* API and which renders numeric rdata as enum names. `_rdata_to_value` is the inverse of the agent's `_normalize_rdata` — `{"certificateUsage": "DANE-EE", "selector": "SPKI", "matchingType": "SHA2-256"}` becomes `3 1 1 <hex>`. Unknown enum members pass through unchanged so a future Technitium release degrades to one odd record rather than an exception mid-import.

Only `Primary` zones are imported. Secondary / Stub / Forwarder / Catalog are reported as warnings — a secondary is a copy of someone else's data, and importing it would mint rows SpatiumDDI then serves authoritatively. Disabled records are skipped too, since importing one would resurrect something the operator had turned off. And because Technitium answers HTTP 200 even on failure, `_unwrap` checks the body's `status` — that is the only place an expired token surfaces.

### 4B.3e Config drift (issue #61)

`pull_zone_records` AXFRs the zone off the Technitium host, the same path BIND9's drift uses. Technitium's own REST API would be the more natural source — it is exactly what the live-pull importer reads — but that API listens on loopback `:5380` inside the agent's container and only the co-located agent can reach it, so the control plane goes over DNS.

**The transfer is TSIG-signed** ([#734](https://github.com/spatiumnorth/spatiumddi/issues/734)). `allow transfer` defaults to `none` → `zoneTransfer: Deny`, which used to mean drift could never read anything on a stock install. So when the group has TSIG keys, `_zone_options_payload` renders `zoneTransfer: Allow` **plus** `zoneTransferTsigKeyNames`, and the control plane signs with the group key.

That is a *narrowing*, not an opening, and the reason is in Technitium's own source: `DnsServer.cs` runs two gates in sequence, `IsZoneTransferAllowed` (address/policy) and then `IsTsigAuthenticated`, and the second returns "no auth needed" **only** when the key-name set is empty. So `Allow` + non-empty key names means *any source, but the request must be signed by one of these keys* — the same posture BIND9 renders as `allow-transfer { key "…"; };`, and stricter than an address ACL, which admits anyone who can occupy the address.

A group with **no** key stays at `Deny`: without a key there is nothing to authenticate with, so `Allow` would be a plain open-AXFR hole. That case surfaces on the drift row as `unsupported`, naming the missing key. An operator-set network ACL is never overridden — the keys are added as the second gate alongside it.

A refused transfer is surfaced as an error on the drift row rather than an empty diff — an empty diff from a refused transfer would read as "in sync", which is the worst possible answer.

### 4B.4 Record type mapping

Technitium's API takes structured per-type params rather than PowerDNS's single wire-format `content` string — e.g. `ipAddress` for A/AAAA, `cname` for CNAME, `exchange`+`preference` for MX, `target`+`priority`+`weight`+`port` for SRV. SVCB/HTTPS are best-effort: the driver parses the BIND-zone-file-style rdata string SpatiumDDI stores (`'1 . alpn="h2,h3"'`) into Technitium's `svcPriority`/`svcTargetName`/`svcParams` (`key|value` pairs) — confirmed empirically that Technitium's `svcParams` wire format does **not** accept a comma-separated multi-value single param the way BIND's rdata does, so only the first value of a multi-value param carries through (logged as a warning); single-value params round-trip exactly.

### 4B.5 Still outstanding

The v1 fast-follow list has been worked off. **Shipped since:** online DNSSEC
signing ([#740](https://github.com/spatiumnorth/spatiumddi/issues/740), §4B.3b),
native DoT/DoH/DoQ listeners plus encrypted upstream forwarding
([#741](https://github.com/spatiumnorth/spatiumddi/issues/741), §4B.3c),
secondary / stub / catalog zones and TSIG transfer
([#743](https://github.com/spatiumnorth/spatiumddi/issues/743), §4B.3a), and the
live-pull importer + native blocklist wiring
([#744](https://github.com/spatiumnorth/spatiumddi/issues/744), §4B.3d).

What is left:

- **Query-log shipping** ([#742](https://github.com/spatiumnorth/spatiumddi/issues/742)) — Technitium's query logging is API/DB-backed (`/api/logs/query*`), not a tailable text file like BIND9's `query_log_file` or PowerDNS's redirected stderr capture, so it needs a poll-and-diff shipper rather than the existing file-tailing `QueryLogShipper`. Until it lands, a Technitium group's queries do not reach the Logs page's **DNS Queries** tab.
- **ANAME / APP / FWD record types** — Technitium-proprietary, and a different shape than PowerDNS's ALIAS/LUA rather than a drop-in equivalent, so they need their own design pass.
- **Views** — declined outright, not deferred. Technitium has no view concept, which is also why per-view blocklists collapse into one flat set (§4B.3d).

### 4B.6 Image

`ghcr.io/spatiumnorth/dns-technitium` builds `FROM technitium/dns-server:<pinned>` (Ubuntu 24.04 + .NET 10, **not Alpine** — see `docs/deployment/DNS_AGENT.md` §7 for why) with the `spatium_dns_agent` wheel layered on top. Healthcheck queries the RFC 6761 reserved `invalid.` TLD rather than a CHAOS-class query — confirmed empirically that Technitium REFUSES `id.server`/`version.bind` CH TXT entirely, unlike BIND9/PowerDNS.

---

## 4C. Technitium — agentless (`technitium_api`), issue [#810](https://github.com/spatiumnorth/spatiumddi/issues/810)

Two Technitium drivers ship, and the difference is **who owns the daemon**:

| | `technitium` (§4B) | `technitium_api` (this section) |
|---|---|---|
| Who runs the daemon | SpatiumDDI — we deploy the container | The operator, wherever they already have it |
| Who talks to the API | The co-located agent, over loopback `:5380` | The control plane, over the network |
| Auth | Agent mints its own token on first boot | Operator pastes a permanent token |
| Config channel | ConfigBundle long-poll | None — writes are synchronous |
| Deploy step | Run a container | None |

They coexist. A `DNSServerGroup` is single-driver (§5.1), so a mixed estate is one group each.

### 4C.1 Why it exists

Technitium was the only backend SpatiumDDI supported in *one* shape. BIND9 has the agent path and RFC 2136; Windows DNS has Path A and Path B; the cloud providers are agentless-only. An operator with an existing Technitium install had to migrate off it with the #744 importer, stand up a second one under our agent, or not use SpatiumDDI — for the backend whose entire control surface is a plain HTTP API and is therefore the *easiest* one to drive remotely.

### 4C.2 Shape — agentless, but not cloud

`TechnitiumAPIDriver` subclasses `CloudDNSDriverBase` (§4A.1), which despite the name is really "agentless driver that keeps a credential dict". What does **not** carry over is membership of `CLOUD_DNS_DRIVERS`, the set that gates the cloud-import flow and the hosted-provider UI. The registry therefore has three sets, not two:

| Set | Members | What it gates |
|---|---|---|
| `AGENTLESS_DRIVERS` | windows_dns, technitium_api, 8 cloud | Synchronous record-op apply |
| `CREDENTIALED_DNS_DRIVERS` | technitium_api, 8 cloud | `cloud_credentials` on server create/update |
| `TOPOLOGY_PULL_DRIVERS` | the above + windows_dns | `pull-zones` + sync-from-server |

`supports_topology_pull()` replaced two inline `driver == "windows_dns" or driver in CLOUD_DNS_DRIVERS` comparisons in `api/v1/dns/router.py` that had to be kept in step by hand.

### 4C.3 Credentials

```json
{"api_url": "https://dns.example.com:53443",
 "api_token": "<permanent API token>",
 "verify_tls": true}
```

Fernet-encrypted into `DNSServer.credentials_encrypted`, the same column every other credentialed driver uses — **no migration**. `host` / `port` on the row stay meaningful: they are the DNS service address, not the API's.

`api_url` is the web-service root, not the `/api` path; the driver strips back to `scheme://host[:port]` so pasting either works. A bare hostname with no scheme is **refused rather than guessed** — defaulting to `http://` would put the bearer token on the wire in cleartext.

`verify_tls` defaults to true and only an explicit `false` turns it off, so a credential blob written before the field existed stays strict.

Auth is `Authorization: Bearer`, required for everything since Technitium 15.0. The operator mints the token at Administration → Sessions → Create Token. Technitium's own docs recommend a dedicated limited user for token use, and SpatiumDDI only needs **Zones: Modify** and **DnsClient: View** — not Administrator. The token inherits that user's permissions, including Technitium's per-zone ACLs.

SECURITY: the URL is operator-supplied and the *server* dials it, so create/update runs it through `app.core.ssrf.assert_safe_target`. Advisory, not blocking, per that module's contract — a co-located Technitium on the appliance's own loopback is a legitimate target.

### 4C.4 The trap: errors arrive as HTTP 200

Technitium answers `{"status": "error" | "invalid-token" | "2fa-required", …}` with a **200 status line**. A driver that trusts `raise_for_status()` reads every auth failure as an empty success — and an empty zone list handed to a sync diff is exactly the [#430](https://github.com/spatiumnorth/spatiumddi/issues/430) shape that proposes deleting everything SpatiumDDI knows about. Non-negotiable #5 in one sentence.

`_unwrap` is the only path responses are read through, and it distinguishes:

- `invalid-token` → names the console page that fixes it. The single most common operator error; a generic "error" sends people reading zone config instead.
- `2fa-required` → says to use a permanent token rather than a session one.
- no envelope at all → reports the HTTP status. A reverse proxy's error page must raise, never read as zero zones.

### 4C.5 rdata translation is shared, three ways

Technitium's read API does not echo back the params its write API takes: it renames keys, and renders TLSA/SSHFP numeric fields as enum *names* (`tlsaSelector=1` reads back as `selector: "SPKI"`). Both directions live in `app/services/technitium/rdata.py`, consumed by this driver *and* the #744 importer.

The agent driver (`agent/dns/spatium_dns_agent/drivers/technitium.py`) keeps a **third copy** it cannot share: it ships in the agent image as a separate Python package and cannot import from `app`. Do not delete either side thinking it is dead code.

Two details are worth knowing before touching either.

**Value params are load-bearing on `delete`.** That is how Technitium identifies which member of an rrset to remove, and SpatiumDDI keys records per value — so dropping them takes out a sibling round-robin A record rather than the intended one.

**`overwrite=false` on a create/update is a bug, not a style choice.** Technitium *appends* at that setting, so editing `www A 10.0.0.1` to `10.0.0.2` leaves the zone answering both, round-robin. That is documented at length in the agent driver, verified live against 15.4.0 — and it is worse here, because there is no structural reload to eventually re-converge it.

The write path therefore mirrors the agent's:

| op | shape |
|---|---|
| `create` / `update` with `change.rrset` (#783) | replay the whole set — member 0 with `overwrite=true` to clear, the rest appended |
| `create` / `update` without it (`rrset is None`) | single-value REPLACE, per the `RRsetData` contract's fallback rule |
| empty `members` | the RRset should not exist → value-scoped delete |
| `delete` | value-scoped, always. The survivors are already correct on the server; a wipe-and-rebuild would open a window where the name serves less than it should |

Two error strings are **not** failures: `already exists` on a replayed create, and `no such record` on a delete of something already gone. Both mean the server is already in the state the op asks for, which is what a replayed op should find (non-negotiable #9). Crucially they must not abort a multi-member RRset write partway — one member the server already has does not make the rest optional. `_is_idempotent_noop` matches the same two substrings the agent driver does, deliberately.

### 4C.6 Zone types

`pull_zones_from_server` preserves Technitium's own zone type rather than reporting everything as `Primary` the way the cloud base does — a hosted provider serves nothing else, Technitium serves Secondary / Stub / Forwarder too. Non-Primary zones come back with `manageable: false`, and the sync-from-server auto-import path skips those rather than adopting them: importing a Secondary as `zone_type="primary"` would claim authority over a zone this server only transfers. They land in the result's `zones_skipped_system` list alongside SpatiumDDI's own reserved names. The key is absent for every other driver, and absent means adoptable.

Zone **create** is Primary-only, matching `capabilities()["zone_types"]`, and refuses anything else rather than defaulting. Silently creating a Primary for a secondary/stub/forward zone would mint an *empty* authoritative zone on the operator's live server — the whole domain would start answering NXDOMAIN from a server that used to transfer or forward it. Delete is unrestricted: refusing to remove a secondary SpatiumDDI tracks would strand it.

Technitium's own internal zones (`localhost`, the RFC 1918 reverse stubs) carry `internal: true` and are dropped.

### 4C.7 Probe — and the endpoint that finally calls one

`probe()` uses `/api/dnsClient/healthCheck`, which Technitium documents as the automated-health-check call: it confirms the process is up *and* that it resolves, and generates **no query-log entries**, which matters because a UI polls it. A failure counting zones afterwards downgrades the message but keeps the probe green — auth is already proven, and a token legitimately scoped to a subset of zones must not render as a red X on a working connection.

`CloudDNSDriverBase.probe` has existed since #37 with **no caller**: nothing in the API, tasks or services invoked it, so the answer to "did that token work?" was "wait for the next sync to fail". #810 adds `POST /api/v1/dns/groups/{gid}/servers/{sid}/test-connection`, which probes a saved server with its stored credentials and returns `{ok, message}`. It covers every driver in `CREDENTIALED_DNS_DRIVERS`, so the eight cloud drivers get it too. Post-save only — the credentials come from the row, unlike `/test-windows-credentials`, which also accepts plaintext for a pre-save dry run.

### 4C.8 Not in scope for this driver

DNSSEC signing, forwarders and the native blocklists stay on the agent-managed driver. `capabilities()` advertises `dnssec_online: false` and `technitium_api` is absent from `_DRIVER_GATED_OPERATIONS["dnssec_sign"]`, so the sign/unsign endpoints refuse it rather than half-working. Also deferred: query-log polling (`/api/logs/query` is paginated with time filters, so a control-plane poll-and-diff shipper is straightforward here in a way it is not on the agent path — see [#742](https://github.com/spatiumnorth/spatiumddi/issues/742)), Technitium's DHCP API (a separate driver, not part of this one), clustering (`node` param on most calls), and DNS Apps.

---

## 5. Driver Selection and Registration

Drivers are registered by name and instantiated by the service layer:

```python
# app/drivers/dns/__init__.py
_DRIVERS: dict[str, type[DNSDriver]] = {
    "bind9": BIND9Driver,
    "powerdns": PowerDNSDriver,
    "technitium": TechnitiumDriver,
    "windows_dns": WindowsDNSDriver,
    # Agentless cloud-hosted DNS providers (issue #37, Part B).
    "cloudflare": CloudflareDNSDriver,
    "route53": Route53DNSDriver,
    "azure_dns": AzureDNSDriver,
    "google_dns": GoogleCloudDNSDriver,
    # Token-only providers (issue #327) — single API token, plain JSON.
    "digitalocean": DigitalOceanDNSDriver,
    "hetzner": HetznerDNSDriver,
    "linode": LinodeDNSDriver,
    "vultr": VultrDNSDriver,
}

# Drivers whose record ops run from the control plane directly, no agent.
AGENTLESS_DRIVERS: frozenset[str] = frozenset(
    {"windows_dns", "cloudflare", "route53", "azure_dns", "google_dns",
     "digitalocean", "hetzner", "linode", "vultr"}
)
# The cloud subset (used by the cloud import + sync-from-server widening).
CLOUD_DNS_DRIVERS: frozenset[str] = frozenset(
    {"cloudflare", "route53", "azure_dns", "google_dns",
     "digitalocean", "hetzner", "linode", "vultr"}
)

def get_driver(server_type: str) -> DNSDriver:
    cls = _DRIVERS.get(server_type)
    if cls is None:
        raise ValueError(f"Unknown DNS driver: {server_type!r}")
    return cls()
```

### 5.1 Per-group driver homogeneity

Each `DNSServerGroup` is **single-driver**. The control plane rejects mixing drivers within one group because catalog-zone semantics, AXFR/IXFR shape, and the gate logic for driver-only features (PowerDNS's ALIAS / LUA, BIND9's views and RPZ, Technitium's DoQ and encrypted forwarding) all assume every member of the group runs the same driver.

Mixed installs work via multiple groups:

- "Internal-zones" group runs PowerDNS (LMDB-backed, fast apply, ALIAS records for apex)
- "External-zones" group runs BIND9 (battle-tested, RPZ for outbound blocklists, well-known operator surface)
- "Edge-technitium" group runs Technitium (REST-API driven like PowerDNS, native DoT/DoH/DoQ listeners and encrypted upstream forwarding — see §4B.3c)

### 5.2 Decision tree — when to pick which driver

| You want... | Pick |
|---|---|
| Reference impl, BIND muscle memory, RPZ blocking | **BIND9** |
| ALIAS records (CNAME at apex) | **PowerDNS** |
| LUA records (computed responses, geo-routing) | **PowerDNS** |
| One-toggle online DNSSEC | **PowerDNS** or **Technitium** |
| Manual NSEC3 + KSK / ZSK rollover control | **BIND9** |
| First-class views / split-horizon (issue #24) | **BIND9** |
| Catalog zones as **producer** | BIND9, PowerDNS or Technitium — same wire bytes |
| Catalog zones as **consumer** | **BIND9** or **Technitium** (not wired up on the PowerDNS agent) |
| Native DoT / DoH with no sidecar | **BIND9** or **Technitium** |
| DNS-over-QUIC, or encrypted *upstream* forwarding over DoH / DoQ | **Technitium** (BIND 9.20 has no client-side HTTP or QUIC transport; pdns doesn't forward at all) |
| Query logs on the Logs page | **BIND9** or **PowerDNS** (Technitium pending, §4B.5) |
| Simple REST-driven primary zones, minimal footprint | **PowerDNS** or **Technitium** |
| Active Directory-integrated DNS | **Windows DNS** (separate path) |
| A Technitium server that **already exists** and should stay where it is | **`technitium_api`** (agentless, §4C) — nothing deployed, no agent, no migration |

BIND9, PowerDNS, and Technitium drivers are all supported indefinitely. PowerDNS landed in issue #127 as a second driver; Technitium landed as a third, not a replacement for either.

**Picking between the two Technitium drivers** comes down to one question — do you want SpatiumDDI to *run* the daemon?

- Yes → `technitium` (§4B). Full feature set: DNSSEC, encrypted transports, forwarders, blocklists, catalog zones.
- No, it's already running → `technitium_api` (§4C). Zones and records only; the rest stays managed in Technitium's own console.

A group is single-driver, so servers of the two kinds live in separate groups.

---

## 6. Error Handling

There is no dedicated driver-exception hierarchy. Drivers raise plain exceptions and let the caller decide how to surface them:

- **BIND9 / Windows DNS** raise stdlib `RuntimeError` / `ValueError` on bad input or a hard failure (e.g. `BIND9Driver.apply_record_change` raises `RuntimeError` when no TSIG key is configured rather than ever sending an unsigned update; the Windows PowerShell helpers `raise ValueError` on an unsupported op / record type).
- **Cloud drivers** (`CloudDNSDriverBase` and its subclasses) raise `CloudDNSError` ([`drivers/dns/_cloud_base.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/drivers/dns/_cloud_base.py)) — each provider's `_unwrap` / `_wrap_errors` / `_wrap_call` helper normalises the raw SDK/HTTP fault into an operator-facing `CloudDNSError` message first (§4A.5).

Rules every driver follows:

- **Never swallow errors silently.** A single record op either succeeds or raises; the caller is responsible for isolation (see below).
- **Log via structlog**, not bare strings — `logger.info("powerdns.apply_record_change.formulated", server=…, zone=…, op=…)` is the house style; errors carry the failing op's identifying fields.
- **Be idempotent where possible** — re-running create/update/delete against an already-converged server is a no-op (e.g. cloud `DELETE` of a non-existent rrset is treated as success; PowerDNS re-sign skips when keys exist).

**Per-op isolation lives in `apply_record_changes`, not in the driver methods.** The default batch loop on `DNSDriver` (§1) catches each per-op exception and records it as `RecordChangeResult(ok=False, error=str(exc))` so one bad record never poisons the rest of the batch. Whole-batch failures (connection refused, auth, a malformed generated script) still propagate by raising from the driver.

The service layer turns those outcomes into persisted state. [`services/dns/record_ops.py`](https://github.com/spatiumnorth/spatiumddi/blob/main/backend/app/services/dns/record_ops.py) writes a `DNSRecordOp` row per op, marking it `state="applied"` (clearing `last_error`) on success or `state="failed"` with the truncated `last_error` on exception, so operators get a per-op audit trail either way. A whole-batch exception marks every row in the batch `failed` with the same error. Retry, where applicable, is the caller's concern (e.g. Celery task retries on the agent push path) — the driver itself does not retry.

---

## 7. Local Config Cache (DNS Agent)

Same agent caching model as DHCP (see DHCP spec). For DNS:

- Cached config includes: all zones + all records the server is authoritative for
- On control plane outage: DNS server continues serving from its own zone data (it always does — DNS servers are not stateless)
- The agent ensures the **last-known-good config** (zone files DB) is preserved
- On reconnect: agent fetches diff of changes made during outage and applies incrementally

### BIND9 Cache
- Zone files on local disk ARE the cache — BIND9 serves from them natively
- Agent tracks which zone file versions were last pushed by SpatiumDDI
- On reconnect: compare SpatiumDDI DB serial vs. zone file serial; apply missing changes

### PowerDNS Cache
- LMDB file at `/var/lib/powerdns/pdns.lmdb` IS the cache — `pdns_server` serves from it natively
- Agent tracks the last-applied `ConfigBundle` ETag in `/var/lib/spatium-dns-agent/config/current.etag` (alongside the cached bundle in `config/current.json`)
- On reconnect: long-poll picks up any new ETag, the agent reconciles by GET-ing PowerDNS's current zone list and PATCHing the rrset diff against the new ConfigBundle. Same convergence shape as BIND9.


## 8. Dynamic-update (RFC 2136) ACLs (issue #641)

The driver ABC exposes what a backend can express for operator-configured
dynamic-update ACLs via a capability descriptor + a validator:

```python
@property
def dynamic_update_caps(self) -> DynamicUpdateCaps: ...
def validate_update_acl(self, zone_name, entries) -> list[str]: ...  # warnings; raises on unsupported
```

`DynamicUpdateCaps` flags: `supports_ip_acl`, `supports_tsig_acl`,
`supports_name_scoping`, `supports_per_type`, `coarse_enum_only`. The base
class defaults every flag to **False** (feature unsupported), so cloud
drivers 422 the write for free; drivers override to opt in.

| Driver | ip | tsig | name-scope | per-type | render path |
|---|---|---|---|---|---|
| **BIND9** | ✅ | ✅ | ✅ | ✅ | coarse `allow-update` or fine `update-policy` (agent `_render_allow_update` / `_render_update_policy`) |
| **PowerDNS** | ✅ | ✅ | ⬜ | ⬜ | `dnsupdate=yes` + per-zone `ALLOW-DNSUPDATE-FROM` / `TSIG-ALLOW-DNSUPDATE` metadata |
| **Windows DNS** | ⚠️ | ✅ | ⬜ | ⬜ | `coarse_enum_only` — maps to `None` / `Secure` / `NonsecureAndSecure` over WinRM |
| **Cloud (R53/Azure/CF/Google)** | ⬜ | ⬜ | ⬜ | ⬜ | N/A — no RFC 2136; feature disabled |

`validate_update_acl` returns human-readable **warnings** for
lossy-but-accepted mappings (an IP entry is UDP-spoofable; on a
`coarse_enum_only` backend an IP entry opens the zone wider than the CIDR)
and **raises** `ValueError` (surfaced as a 422 by the API) on a
hard-unsupported entry — any entry on a no-surface driver. For a
name-scoped / per-type / `deny` ACL (which must render as `update-policy`,
TSIG-identity only) it also rejects any IP entry in the same ACL, and
requires a `name_pattern` for the ruletypes that take a name
(`subdomain` / `name` / `wildcard` / `self`).

### 8.1 BIND9 agent rendering

The **agent** (`agent/dns/spatium_dns_agent/drivers/bind9.py`) is the
authoritative renderer on an appliance. It picks ONE clause per zone:

1. **Coarse** — `_render_allow_update(zone, group_key)` builds one
   `allow-update { … }` mixing the always-present group loopback key with
   the operator ACL's grant entries (`<cidr>;` / `key "<name>";`). Used when
   no entry needs the fine-grained path.
2. **Fine-grained** — `_render_update_policy(zone, group_key)` builds an
   `update-policy { … }` when `_zone_needs_update_policy` sees any
   `name_scope` / `record_types` / `deny` entry. Renders
   `grant <groupkey> zonesub;` (loopback) + one
   `<grant|deny> <keyname> <ruletype> [<name>] [<types>];` per operator
   entry. IP entries are skipped (rejected upstream).
3. Every TSIG key in the bundle renders a `key { … }` block (not just
   `tsig_keys[0]`), so an operator key named in either clause is defined —
   BIND rejects a stanza that references an undefined key.

The control-plane driver mirrors the same selection in
`_render_update_clause(zone)` (`backend/app/drivers/dns/bind9.py`) for the
preview / agentless path.

Dynamic zones also render `allow-transfer { key "<group-key>"; };` so the
ingest-back worker can AXFR the live zone from loopback (see DNS.md §19.5).

### 8.2 PowerDNS (coarse, P3)

PowerDNS is coarse-only — no per-name / per-type / `deny`, so
`validate_update_acl` rejects those fields. Enforcement is two parts:

1. **Global** — the agent renders `dnsupdate=yes` in `pdns.conf`
   (`_render_conf`) instead of the old `dnsupdate=no`. It's enabled
   unconditionally because per-zone metadata is the real gate (a zone with
   no allow-metadata rejects every update), so it's a no-op for zones
   without an ACL. `dnsupdate` is a **startup** setting, so a pdns already
   running with it off only picks this up on the next container restart.
2. **Per-zone** — the agent's `_reconcile_zones` calls
   `_apply_dynamic_update` per zone, which (a) imports the referenced TSIG
   keys into pdns via the `tsigkeys` API and (b) sets the zone metadata via
   the REST API: `ALLOW-DNSUPDATE-FROM` ← grant IP/CIDRs,
   `TSIG-ALLOW-DNSUPDATE` ← grant key names. An empty ACL DELETEs both so a
   zone whose dynamic updates were turned off stops accepting them.

**Drift** — the pdns reconciler is additive per-rrset (`REPLACE` per managed
`name+type`, never a blanket zone replace), so externally-injected records
(new names) **already survive** a reconcile, and a conflicting managed
`name+type` is re-asserted (control-plane wins). An active ingest-back for
*visibility* (mirroring external records into the control-plane DB, like the
BIND9 AXFR worker) is a deferred follow-up — not needed for survival.

**dnsdist** — when the optional dnsdist front (#146 Phase 2) is enabled it
stays a rate-limit tier; an `OpcodeRule(Update)` + `NetmaskGroupRule`
advisory gate is a possible defense-in-depth add-on, never the sole
enforcement (pdns metadata is authoritative). Deferred.

### 8.3 Windows DNS (coarse enum, P3)

Windows DNS has no per-client ACL — only a zone-level `-DynamicUpdate` enum,
so `dynamic_update_caps.coarse_enum_only = True` and `validate_update_acl`
maps the ACL coarsely (`windows_dynamic_update_mode`):

| ACL state | Windows enum |
|---|---|
| disabled | `None` |
| enabled, TSIG-only | `Secure` (AD GSS-TSIG) |
| enabled, any IP entry | `NonsecureAndSecure` **+ loud warning** |

`NonsecureAndSecure` accepts **any** nonsecure client, not just the
operator's CIDR — Windows can't restrict by source, so the API returns a
warning telling the operator the range isn't enforced. Name-scope /
per-type / `deny` are rejected (Windows can't express them).

Windows is **agentless**, so the enum is pushed over WinRM
(`Set-DnsServerPrimaryZone -DynamicUpdate <mode>`) by
`apply_dynamic_update_mode`, which the `update-acl` endpoint (and the MCP
apply) call for every Windows-driver server in the group after commit — a
best-effort push whose failures come back as warnings. **Drift** needs
nothing new: Windows updates land in the same AD-integrated store the
existing `Get-DnsServerResourceRecord` sync reads.

The control-plane BIND9 template (`zone.stanza.j2`) renders the same coarse
`allow-update` for the preview / agentless path, kept in parity with the
agent renderer.

---

## 9. Encrypted transports (issue #50)

Rendering details for DoT / DoH listeners and TLS upstream forwarding.
Operator-facing behaviour + the certificate lifecycle live in
`docs/features/DNS.md` §20.

### 9.1 BIND9

Verified against BIND **9.20.23** (the version in
`agent/dns/images/bind9`) with `named-checkconf` plus live `dig +tls` /
`dig +https` queries.

Top-level statements are emitted before `options {}` by
`_render_tls_statements` in `agent/dns/spatium_dns_agent/drivers/bind9.py`:

```
tls spatium-local-tls {
    cert-file "/var/lib/spatium-dns-agent/tls/listener.crt";
    key-file "/var/lib/spatium-dns-agent/tls/listener.key";
    protocols { TLSv1.2; TLSv1.3; };
};
http spatium-local-http {
    endpoints { "/dns-query"; };
};
tls spatium-upstream-tls {
    ca-file "/etc/ssl/certs/ca-certificates.crt";
    remote-hostname "cloudflare-dns.com";
    protocols { TLSv1.2; TLSv1.3; };
};
```

`protocols { … }` pins a modern floor **and** keeps the block non-empty in
the opportunistic case (verification off ⇒ no `ca-file` /
`remote-hostname`), which BIND would otherwise reject as an empty `tls`
block.

Listeners land inside `options {}` via `_render_encrypted_listeners`,
alongside — never replacing — the plain pair:

```
listen-on port 853 tls spatium-local-tls { any; };
listen-on port 8443 tls spatium-local-tls http spatium-local-http { any; };
```

A DoH listener needs **both** clauses: `tls` terminates, `http` routes the
path.

Forwarders go through `_format_forwarder`, which also fixed a latent bug:
the wire shape is `ip` or `ip@port`, and the previous code emitted the raw
string, rendering an unloadable `192.0.2.2@5353;` token for any forwarder
that pinned a port. Over TLS the port defaults to 853 rather than 53.

Cert material arrives in the config bundle as `tls_cert` and is written to
the stable `tls/` paths above — outside the `rendered.new` swap, like the
TSIG key, and with the same atomic `O_NOFOLLOW` 0600 write so the private
key is never briefly world-readable.

The server-side Jinja preview (`templates/bind9/named.conf.j2`) mirrors
all of this so the config-preview UI matches what the agent will write.

### 9.2 PowerDNS / dnsdist

pdns Authoritative speaks neither protocol and doesn't recurse, so:

* **inbound** is `addTLSLocal` / `addDOHLocal` on the dnsdist front, which
  terminates TLS and forwards plaintext to pdns;
* **outbound** has no meaning here — the only hop dnsdist makes is to the
  local pdns backend.

`render_dnsdist_conf` emits into the same shared rules file the #146 Phase
2 rate-limit rules use. Two cross-container details matter:

1. **Paths are dnsdist-side.** The front runs in its own container and
   mounts the agent's state dir at `/agent-state`, so the rendered rules
   reference `/agent-state/tls/listener.crt`, not the agent's own
   `state_dir`. Override with `DNSDIST_STATE_MOUNT` if that mount moves.
2. **uid alignment.** Both images create `spatium` as uid 101, so the 0600
   key the pdns agent writes is readable by dnsdist. If either image's
   user ever changes, the listeners break with a fatal TLS-load error.

The agent writes the cert **before** the rules file, so the front can
never observe rules pointing at a PEM that isn't on disk yet.

See §20.4 of `docs/features/DNS.md` for the `--check-config` hazard and
the entrypoint pre-flight that guards against it.
