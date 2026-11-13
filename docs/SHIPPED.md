# SpatiumDDI — Shipped roadmap items

Companion to `CLAUDE.md`. The roadmap sections in CLAUDE.md track only items that haven't shipped yet — each ✅ entry below is the full body of an item that landed, kept here so future sessions can recover the design context (migration id, file paths, deferred follow-ups, why-it-was-built) without crowding the working list.

Mirrors CLAUDE.md's three mixed sections:
- [Major roadmap items](#major-roadmap-items) — feature-level tracker for the IPAM / DNS / DHCP core.
- [Integration roadmap](#integration-roadmap) — read-only pull mirrors (Kubernetes, Docker, Proxmox, Tailscale, …).
- [Future ideas — categorised](#future-ideas--categorised) — the 2026.04.26 brainstorm pass, organised by topic.

## Major roadmap items

- ✅ **Multicast group tracking — IPAM-native registry of streams + producer/consumer relationships**
  ([#126](https://github.com/spatiumnorth/spatiumddi/issues/126))
  — Full multicast registry shipping the four-phase issue body
  (registry → PIM domain → SNMP discovery → Operator Copilot tools)
  end-to-end. Eleven commits between 2026-05-08 and 2026-05-09:

  | Phase | Wave | Commit | What landed |
  |---|---|---|---|
  | 1 | 1 | `d56f3a6` | Data model — `multicast_group` + `multicast_group_port` + `multicast_membership` tables (migration `f1e7a3c92b40`), CHECK enforcing the IANA multicast classes (`224.0.0.0/4` v4 / `ff00::/8` v6) on `address`, UNIQUE `(group_id, ip_address_id, role)` on memberships, REST CRUD with `network.multicast` feature module gate (default-enabled per CLAUDE.md #14), permission grammar wired into the Network Editor builtin role |
  | 1 | 2 | `7f3ffd9` | Operator UI — `/network/multicast` list page, three-tab editor modal (General / Ports / Memberships), sidebar entry with the Radio icon under Network → Infrastructure |
  | 1 | 3 | `31749c5` | Bulk-allocate — `POST /multicast/groups/bulk-allocate/{preview,commit}` reusing the IPAM `_expand_bulk_template` grammar, `BulkAllocateModal` form→preview→commit flow, reusable `IPAddressPicker` component (debounced search via `/search?types=ip_address`) |
  | 1 | 4 | `a11b5a4` | Cross-group `GET /multicast/memberships?ip_address_id=…` returning joined group info, IPDetailModal "Multicast memberships" section (module-gated), `no_multicast_collision` conformity check + seeded built-in policy + engine `multicast_group` target-kind resolver |
  | 1 | bulk-delete | `2be4d59` | `POST /multicast/groups/bulk-delete` + checkbox column + select-all toolbar matching the Circuit pattern |
  | 2 | 1 | `cea3fda` | PIM domain registry — `multicast_domain` table (migration `c8d2f47a90b3`) with PIM mode (sparse/dense/ssm/bidir/none) + VRF binding + RP (device FK + free-text address) + SSM range, REST CRUD with sparse/bidir-needs-RP validation, FK promotion of `multicast_group.domain_id` from placeholder UUID to real ON DELETE SET NULL |
  | 2 | 2 | `f79f88b` | Domains UI + group→domain picker on the create modal |
  | 2 | 3 | `00edc06` | `Subnet.kind` discriminator (migration `d3a9c5b71e84`) auto-detected from CIDR on create, IPAM allocation endpoints refuse on `kind="multicast"`, frontend badge in IPAM tree |
  | 2 | tabs | `bfc99ef` | Sub-tab refactor — Groups + Domains live as `?tab=` sub-tabs of `/network/multicast`; legacy `/network/multicast/domains` route redirects to `?tab=domains` |
  | 3 | 1 | `77d66cd` | SNMP IGMP-snooping populator — vendor-neutral RFC 2933 walker (`walk_igmp_cache`) + cross-reference matcher writing `MulticastMembership` rows tagged `seen_via='igmp_snooping'`, promotes `manual` → `igmp_snooping` when discovery validates a hand entry, opt-in `NetworkDevice.poll_igmp_snooping` toggle (migration `a1f4d97c8e25`) |
  | 4 | 1 | `84aa308` | Operator Copilot tools — 4 read tools (`find_multicast_group` / `find_multicast_membership` / `find_multicast_domain` / `count_multicast_groups_by_vrf`, default-on, module-gated) + `propose_create_multicast_group` write proposal (default-off) + `create_multicast_group` Operation (preview/apply with multicast-class validation + collision soft-warn) |
  | 4 | 2 | `3d8be70` | `propose_allocate_multicast_group` bulk-stamp proposal + IGMP membership reaper Celery beat task (drops `seen_via='igmp_snooping'` rows older than 30 min every 5 min, manual + sap_announce rows untouched) |

  **Test coverage**: 40 cases in `backend/tests/test_multicast.py` covering CRUD + IPv4/IPv6 multicast-class validation + port range CHECK + unique-triplet membership + feature-module 404 gate + bulk-allocate flow + memberships-by-IP joined response + conformity check (pass/fail/cross-space) + PIM domain CRUD + sparse-without-RP rejection + Subnet.kind auto-detection + IPAM-allocation-refuses-on-multicast + IGMP cross-reference matcher + Operator Copilot read tools + module-disabled tool filtering + bulk-allocate operation preview/apply + IGMP reaper sweep.

  **Phase 3 deferrals (explicit non-goals)**:
  * **SAP listener (RFC 2974)** — needs raw multicast packet capture inside the agent (scapy + `NET_RAW` capability, like the DHCP fingerprint sniffer). Audience is legacy pro-AV / NDI; SNMP IGMP-snooping covers the same use case for >90% of operators.
  * **NMOS IS-04 mirror** — fits the integration shelf shape (peer of UniFi / OPNsense / pfSense) better than baked into multicast core. Ship if/when an SMPTE 2110 broadcast operator asks for it.

  Both deferrals captured in the issue close-out comment.

- ✅ **DNS configuration importer — BIND9, PowerDNS, Windows DNS**
  ([#128](https://github.com/spatiumnorth/spatiumddi/issues/128))
  — One-shot migration tool that turns three common upstream DNS
  sources into native SpatiumDDI zones + records. Three phases
  shipped 2026-05-09 across seven commits; all three sources feed
  the same source-agnostic canonical IR (`ImportedZone` /
  `ImportedRecord` / `ImportedSOA` / `ZoneConflict` /
  `ImportPreview`) so conflict handling + per-zone savepoint
  commit + audit logging stay in lock-step. Explicit one-shot
  semantics — once imported, SpatiumDDI is the source of truth
  with no continuous two-way mirror; operators wanting a running
  mirror are served by the existing read-only Path A drivers.
  Imported rows carry `import_source` (`bind9 | windows_dns |
  powerdns`) + `imported_at` provenance columns + audit-log
  `new_value` blob so re-imports dedupe and operators can answer
  "where did this come from" later.

  | Phase | Wave | Commit | What landed |
  |---|---|---|---|
  | 1 | 1 | `787a328` | Data model — migration `b7e2d9a5f314` adds `import_source` + `imported_at` to `dns_zone` + `dns_record` with partial index `WHERE import_source IS NOT NULL`; seeds `dns.import` feature module (default-enabled, new "DNS" group on Settings → Features) |
  | 1 | 2 | `32f4059` | BIND9 archive parser — `services/dns_import/bind9.py` unpacks `.zip` / `.tar(.gz/.bz2/.xz)` (50 MB archive cap, 200 MB unpacked cap, path-traversal rejection, regular-files-only filter), tokenises `named.conf` for `zone "..." { ... };` declarations including nested `view {} ` blocks, four-strategy `file` directive resolution (absolute-as-archive-relative → `options.directory` → named.conf parent dir → basename search), reuses `dns_io.parser.parse_zone_file` (dnspython-backed) for per-zone master file parsing. DNSSEC records (DNSKEY/RRSIG/NSEC*/DS/CDS/CDNSKEY) stripped with per-zone "stripped N records, re-sign post-import" warning |
  | 1 | 3 | `920b31f` | Preview/commit endpoints — `POST /dns/import/bind9/{preview,commit}` (preview is multipart, commit is JSON carrying the previewed plan + per-zone `conflict_actions`), source-agnostic `commit_import` write layer with per-zone savepoints (failure on zone N rolls back N but keeps zones 1..N-1) + audit log per zone tagged `new_value.import_source=bind9` |
  | 1 | 4 | `196e1a2` | Admin UI — `/admin/dns-import` page with three tabs (BIND9 active, Windows DNS / PowerDNS placeholder), preview + commit panels with per-row Action-on-conflict select (skip/overwrite/rename), action pills + records-created/deleted columns on the result panel, sidebar entry under Administration → Configuration |
  | 1 | 5 | `cddd82a` | 17 tests — parser layer (basic .tar.gz + .zip, reverse zone, view block, DNSSEC strip, missing named.conf, empty zone list, path traversal, partial import, comment styles) + commit layer (preview, commit with provenance, default skip-on-conflict, overwrite, rename, missing target group → 422). Companion: `dns_io.parser.ParsedZone` gains `skipped_types` histogram so callers can warn about DNSSEC + experimental rdtypes. View warning fires on any view, not just multi-view |
  | 2 | — | `a2900bb` | Windows DNS live pull — `services/dns_import/windows_dns.py` reuses `WindowsDNSDriver.pull_zones_from_server` + `pull_zone_records` (Path B WinRM read methods the Logs surface already drives). Maps Windows zone-types (Primary/Secondary/Stub/Forwarder), honours `IsReverseLookupZone` flag, applies SOA defaults with "edit primary_ns/admin_email post-import" warning (Windows owns SOA on the server side), per-zone record-pull failures become warnings rather than aborting. System-zone awareness for TrustAnchors / RootDNSServers / `_msdcs.*` / DomainDnsZones / ForestDnsZones / 0.in-addr.arpa with both per-zone + top-level preview warnings (not silently filtered — some shops replicate `_msdcs` for staging). New `GET /dns/import/windows-dns/servers` for the picker (lists driver=windows_dns servers with `has_credentials` flag), `POST .../{preview,commit}`. UI tab parallels BIND9 with server dropdown instead of file picker; servers without WinRM creds listed-but-disabled. 8 new tests with `WindowsDNSDriver.pull_*` monkeypatched |
  | 3 | — | `0fe73df` | PowerDNS REST live pull — `services/dns_import/powerdns.py` is a fresh httpx-backed REST client that walks `GET /api/v1/servers/{id}/zones` then per-zone `GET /zones/{zone_id}` for the rrset payload. SOA hoisted from rrset content (PowerDNS encodes it as one space-separated string), MX preference + SRV priority/weight/port split out of `content` into the dedicated columns, `kind` mapping (Native/Master → primary, Slave → secondary, Producer/Consumer → primary for now, Forward → forward). Disabled records (`disabled: true` operator soft-delete) dropped with a warning, DNSSEC + PowerDNS-specific (LUA, ALIAS) rdtypes dropped with two distinct warnings, hard cap of 5000 zones per pull. `test_powerdns_connection()` probes `/api/v1/servers/{id}` for daemon info so the UI's "Test connection" button can confirm a live API. URL accepts both `http://host:8081` and `http://host:8081/api/v1`. New `POST /dns/import/powerdns/{test-connection,preview,commit}` (credentials in body, never persisted — upstream isn't managed by SpatiumDDI). UI tab with API URL + password-masked API key + server-name + Test connection button (shows daemon version pill on success). 9 new tests with `httpx.AsyncClient` monkeypatched via `MockTransport` |

  **Test coverage**: 34 cases total in `backend/tests/test_dns_import.py` + `test_dns_import_windows.py` + `test_dns_import_powerdns.py` covering all three sources end-to-end through the FastAPI test client.

  **Phase 4 polish split out to [#130](https://github.com/spatiumnorth/spatiumddi/issues/130)** — gated on real operator demand:
  * **Catalog-zone awareness** — current "imports as a regular zone" is fine for most cases (catalog zones are rare in BIND9/PowerDNS deployments people migrate *from*); operator can delete post-import. Build trigger: a real operator hits this and is surprised.
  * **Multi-view → per-view import** — hard blocked on [#24 DNS Views](https://github.com/spatiumnorth/spatiumddi/issues/24); current behavior collapses to default view with a warning.
  * **`propose_dns_import` MCP tool** — low value over the UI; build if specifically asked.

  **One item dropped, not deferred**: DNSSEC re-sign automation. Current "strip on import + warn + operator re-enables in zone editor" is the right UX — auto-enabling at import time would bake in algorithm/KSK/ZSK choices the operator should make on the SpatiumDDI side. Don't re-pitch.

- ✅ **PowerDNS authoritative driver — second driver alongside BIND9**
  ([#127](https://github.com/spatiumnorth/spatiumddi/issues/127))
  — Full second authoritative DNS driver with native REST API +
  LMDB embedded backend, multi-arch (`linux/amd64` + `linux/arm64`)
  `ghcr.io/spatiumnorth/dns-powerdns` image, agent + supervisor +
  long-poll integration, frontend driver picker, and per-driver
  capability gating (ALIAS / LUA / online DNSSEC / catalog zones
  reject 422 against non-PowerDNS groups). Five phases + two
  post-test fix waves shipped across 15 commits between
  2026.05.07 and 2026.05.08:

  | Phase | Commit | What landed |
  |---|---|---|
  | 1 | `047fb66` | Driver class, agent driver, container image, multi-arch build matrix |
  | 2 | `cd6311c` | Frontend driver picker (PowerDNS joins BIND9 + Windows DNS in the dropdown) |
  | 3a | `559bafa` | ALIAS records (CNAME-at-apex) — `_DRIVER_GATED_RECORD_TYPES` |
  | 3b | `5f8875f` | LUA records (computed responses — `pickrandom` / `ifportup` / `createReverse` …) |
  | 3c.1 | `d967556` | DNSSEC online-signing backend (sign/unsign endpoints, agent dispatch via cryptokey API) |
  | 3c.fe | `f8c5208` | DNSSEC frontend (`DnssecCard`, DS-rrset list with copy-to-clipboard); migration `e7f94b21c8d5` adds `dnssec_ds_records` + `dnssec_synced_at` |
  | 3d | `c32bf0d` | RFC 9432 catalog zones, **producer-only** (consumer mode not wired up in the agent) |
  | 4a | `2e1901c` | Standalone-VM compose plumbing — new `docker-compose.agent-dns-powerdns.yml`; renamed `agent-dns.yml` → `agent-dns-bind9.yml` |
  | 4b | `494f5d6` | Helm chart per-flavor StatefulSet — `dnsAgents.flavors.powerdns.{repository,tag}`; mount path swaps to `/var/lib/powerdns` for LMDB |
  | 4c | `be5579d` | Kind-cluster smoke test extension — both bind9 + powerdns flavors install side-by-side; `dig id.server CH TXT` on the powerdns pod |
  | 4d | `57004e1` | Backup DNSSEC restore advisory — `RestoreOutcomeResponse.warnings[]` flags signed zones whose keys live on the (un-archived) agent LMDB volume |
  | 4e | `f3a08b5` | Operator Copilot `propose_create_dns_zone` write-tool with `driver_hint` (one of `bind9` / `powerdns` / `windows_dns`) |
  | 5 | `8c7a7bd` | Docs pass — `DNS_DRIVERS.md` Section 4 chapter, `features/DNS.md` Section 0 driver-choice subsection, `TOPOLOGIES.md` PowerDNS-hybrid + BIND→PowerDNS migration recipe; LUA snippet dropdown; DNSSEC online-signing kind smoke test |
  | post-test wave 1 | `00e5405` | 8 bugs from a live-test pass: `pdns_server` CLI flag-syntax (`--config-dir=/path` not space-separated); LMDB pre-seed (let pdns init the env on first start); ZSK creation needs explicit `algorithm=ecdsa256`; `PRESIGNED` metadata path removed (REST API rejects the kind for online-signing); DS state-sync handler trailing-dot bug; `enable-lua-records=yes` global flag instead of rejected per-zone metadata; `expand-alias=yes` + upstream resolver; multi-record rrset PATCH GET-merge-PATCH so pool fan-out works. Same drop pinned `docker-compose.dev.yml` build-able services to `image: spatiumddi-<svc>:dev` so `make dev` always builds locally |
  | post-test wave 2 | `982bc1b` | (a) Server-group RecordsTab record-type colour-coding (shared `RECORD_TYPE_BADGE` map); (b) DNS Pools page deep-links into zone Pools sub-tab via `subtab=pools`; (c) destroy + recreate container restores config cleanly — `DNS_REQUIRE_AGENT_APPROVAL` now actually gates the fingerprint-mismatch lockout, cold-boot reconcile starts pdns + waits for the REST API + propagates errors so the structural_etag doesn't advance on a botched apply; (d) PowerDNS query logs surface in `/logs` end-to-end — `log-dns-queries=yes` + `loglevel=6` rendered when toggled, agent captures pdns stderr, new `pdns_parser`, ingest dispatches by `server.driver` |

  **End-to-end verified** against a fresh `make dev` install with
  the `dns-powerdns` profile: zone CRUD via API, dig answers for
  every record type (A/AAAA/CNAME/MX/TXT/SOA), ALIAS at apex
  resolves through the configured upstream, LUA `pickrandom`
  rotates correctly, online DNSSEC produces RRSIG-signed answers
  + 3 DS records (SHA-1/256/384) synced to the control plane,
  GSLB pool with TCP health-check returns only healthy members
  (multi-A fan-out works), container destroy + persistent volume
  wipe + recreate-with-same-PSK re-pushes all zones + records,
  and query logs flow into the DNS Queries tab within one batch
  interval (~5 s).

  **Operator-elective tail (deferred — open separate issues if
  needed):** gpgsql-backend image variant (LMDB stays the
  default); catalog-zone consumer support on the PowerDNS agent;
  bundled-Postgres subchart for the gpgsql
  variant. Plus a known soft-delete-on-PowerDNS limitation: the
  soft-delete + trash-purge paths don't enqueue a `record_op` for
  PowerDNS-driver groups (only `?permanent=true` deletes do), so
  soft-deleted records keep getting served until the operator
  hard-deletes via the trash UI.

- ✅ **Windows DNS — Path A (RFC 2136, agentless)** — `WindowsDNSDriver`
  in `backend/app/drivers/dns/windows.py`. Record CRUD only (A / AAAA /
  CNAME / MX / TXT / PTR / SRV / NS / TLSA) via dnspython over RFC 2136;
  zones are managed externally in Windows DNS Manager. Optional TSIG
  signing; GSS-TSIG and SIG(0) are Path B. Control plane sends updates
  directly; `record_ops.enqueue_record_op` short-circuits the agent queue
  for servers whose driver is in `AGENTLESS_DRIVERS`.

- ✅ **Windows DHCP — Path A (WinRM, read-only lease monitoring)** —
  `WindowsDHCPReadOnlyDriver` in `backend/app/drivers/dhcp/windows.py`.
  Implements `get_leases` via `Get-DhcpServerv4Scope` /
  `Get-DhcpServerv4Lease` over WinRM (`pywinrm`). All write methods
  (`apply_config`, `reload`, `restart`, `validate_config`) raise
  `NotImplementedError` — Path A is strictly read-only. Credentials are
  stored Fernet-encrypted on `DHCPServer.credentials_encrypted`. Driver
  registry gains `AGENTLESS_DRIVERS` + `READ_ONLY_DRIVERS` sets mirroring
  the DNS side. Scheduled Celery beat task
  `app.tasks.dhcp_pull_leases.auto_pull_dhcp_leases` fires every 60 s;
  task gates on `PlatformSettings.dhcp_pull_leases_enabled` /
  `_interval_minutes`. Leases are upserted by `(server_id, ip_address)`
  and mirrored into IPAM as `status="dhcp"` + `auto_from_lease=True` rows
  when the lease IP falls inside a known subnet; the existing lease-
  cleanup sweep handles expiry uniformly. Manual "Sync Leases" button
  on the server detail header for agentless drivers. Beat ticks every
  10 s and the per-run interval is stored in seconds
  (`PlatformSettings.dhcp_pull_leases_interval_seconds`, default 15 s)
  so operators can tune near-real-time IPAM population — Windows
  DHCP has no streaming primitive, so short-interval polling is the
  practical upper bound without putting an agent on the DC.

- ✅ **OUI/vendor lookup** — opt-in IEEE OUI database fetched by
  `app.tasks.oui_update.auto_update_oui_database` (hourly beat, task
  honours `PlatformSettings.oui_lookup_enabled` +
  `oui_update_interval_hours`, default 24 h). `oui_vendor(prefix
  CHAR(6) PK, vendor_name, updated_at)` replaced atomically each run
  so lookups always see a consistent snapshot. `services/oui.py`
  exposes `bulk_lookup_vendors` + `normalize_mac_key`; IPAM's
  `list_addresses` and DHCP's `list_leases` use them to attach a
  `vendor` field. Settings → IPAM → OUI Vendor Lookup carries the
  toggle + interval + "Refresh Now" (queues
  `update_oui_database_now`). MACs render as `aa:bb:cc:dd:ee:ff
  (Cisco Systems)` in the IP table + DHCP leases; feature off =
  vendor null + UI falls back to bare MAC.

- ✅ **SNMP polling / network device management** — vendor-neutral
  read-only polling of routers/switches via standard MIBs, with
  every result cross-referenced into IPAM. Lands the "every
  managed IP gets a heartbeat + switch-port automatically" payoff
  this whole roadmap pivots on. **Mirror scope:**
  - **Data model** (migration
    `c4e7a2f813b9_network_devices`): `network_device` (SNMP
    credentials Fernet-encrypted at rest; v1 / v2c / v3 USM all
    supported with auth + priv protocol enums), `network_interface`,
    `network_arp_entry` keyed `(device, ip, vrf)`, and
    `network_fdb_entry` keyed `(device, mac, vlan)` with the
    Postgres 15+ `NULLS NOT DISTINCT` unique index — so a single
    port can carry the same MAC across multiple VLANs (hypervisor
    with VMs in different access VLANs, IP phone with PC
    passthrough on voice + data VLANs).
  - **MIBs walked** — SNMPv2-MIB system group (sysDescr /
    sysObjectID / sysName / sysUpTime), IF-MIB `ifTable` +
    `ifXTable`, IP-MIB `ipNetToPhysicalTable` with legacy
    RFC1213 `ipNetToMediaTable` fallback, Q-BRIDGE-MIB
    `dot1qTpFdbTable` with BRIDGE-MIB `dot1dTpFdbTable` fallback.
    All standard, no vendor-specific MIBs — works on Cisco /
    Juniper / Arista / Aruba / MikroTik / OPNsense / pfSense /
    FortiNet / Cumulus / SONiC / FS.com / Ubiquiti out of the
    box.
  - **Polling pipeline** — `pysnmp` 7.x async (`bulk_walk_cmd` for
    table OIDs, ~10–50× faster than GETNEXT; v1 devices walk via
    `walk_cmd` since GETBULK doesn't exist in SNMPv1).
    `app.tasks.snmp_poll.poll_device` runs sysinfo → interfaces
    → ARP → FDB sequentially under a per-device
    `SELECT FOR UPDATE SKIP LOCKED` so concurrent dispatches
    can't double-poll the same row. `dispatch_due_devices`
    beat-fires every 60 s and queues every active device whose
    `next_poll_at <= now`. Per-device interval default 300 s,
    minimum 60 s. Status: `success | partial | failed |
    timeout`, with `last_poll_error` populated for ops triage.
    Stale ARP entries are kept with `state='stale'` (no
    delete); `purge_stale_arp_entries` daily beat task removes
    rows older than 30 days.
  - **IPAM cross-reference** — after every successful ARP poll,
    `cross_reference_arp` finds matching `IPAddress` rows in
    the device's bound `IPSpace` and updates `last_seen_at`
    (max-merge), `last_seen_method='snmp'`, and fills
    `mac_address` only when currently NULL — operator-set MACs
    are never overwritten. When the per-device
    `auto_create_discovered=True` toggle is on (off by default;
    operator stays in control), inserts new
    `status='discovered'` rows for ARP IPs that fall inside a
    known `Subnet`. Returns counts (`updated`, `created`,
    `skipped_no_subnet`).
  - **API** — full CRUD at `/api/v1/network-devices` plus
    `POST /test` (synchronous SNMP probe, ≤10 s, returns
    `TestConnectionResult` with sysDescr + classified
    `error_kind`: `timeout | auth_failure | no_response |
    transport_error | internal`), `POST /poll-now` (queues
    immediate Celery task, returns 202 + task_id), and
    per-device list endpoints `/interfaces`, `/arp` (filter by
    ip/mac/vrf/state), `/fdb` (filter by mac/vlan/interface_id).
    The IP-detail surface gains
    `GET /api/v1/ipam/addresses/{id}/network-context` — joins
    `IPAddress.mac_address → NetworkFdbEntry → NetworkInterface
    → NetworkDevice` and returns one row per (device, port,
    VLAN, MAC) tuple so a hypervisor / IP phone surfaces every
    leg.
  - **Frontend** — top-level `/network` page in the core sidebar
    (always visible between VLANs and Logs — this is core IPAM
    functionality, not gated on a Settings → Integrations
    toggle). Per-device detail at `/network/:id` with Overview /
    Interfaces / ARP / FDB tabs, each filterable + paginated.
    Add/edit modal with SNMP-version-conditional credential
    fields (community for v1/v2c; security_name + level + auth
    + priv for v3) plus inline Test Connection (saves first on
    create, then probes against the saved row). New "Network"
    tab on the IP detail modal showing per-IP switch/port table
    sorted by `last_seen DESC`.
  - **Permissions** — single `manage_network_devices` permission
    gates all endpoints (read + write); new "Network Editor"
    builtin role gets it. Superadmin always bypasses.
  - **Tests** — 35 backend tests covering pysnmp wrapper paths
    (mocked: v1 / v2c / v3 auth construction, OID resolution,
    `ipNetToPhysical → ipNetToMedia` fallback,
    `Q-BRIDGE → BRIDGE` fallback, error classification),
    API CRUD + `/test` + `/poll-now` + the four list endpoints
    + `/network-context`, and three cross-reference paths
    (existing IP gets last_seen + MAC fill; operator-set MAC
    never overwritten; auto-create on/off; no-matching-subnet
    skip).

  **Deferred follow-ups:**
  - **CDP neighbour collection** + topology graph. LLDP shipped
    in the categorised brainstorm section below; CDP (Cisco-only)
    deferred — modern Cisco gear runs LLDP alongside CDP, so the
    standard-MIB path covers the typical case.
  - **VRF-aware ARP polling.** `network_device.v3_context_name`
    column exists for SNMPv3 context-name targeting, but the
    poller doesn't iterate per-VRF in v1. Per-VRF SNMPv2c
    community-string indexing
    (`<community>@<vrf-name>` Cisco convention) and SNMPv3
    context-name iteration are both pending.
  - **Standalone `snmp-poller` container** (per
    `docs/features/IPAM.md §13`). Today the polling lives in
    the existing Celery worker pool, which is fine to ~100
    devices on a 5-min interval. Splitting becomes interesting
    once SNMP traffic competes with the worker's other tasks
    or when the operator wants different network reachability
    for the poller (different VLAN, jumphost, etc).
  - **Beat-tick fan-out cap.** `dispatch_due_devices` queues
    every due device in one tick; at >1k devices this is a
    queue spike. Chunking + per-tick rate-limit is the cheap
    follow-up.
  - **Permission granularity** — read vs write split. Today
    `manage_network_devices` covers both; ops teams that want
    network-engineer read access without write privs need a
    `view_network_devices` companion permission.
  - **Stateless probe endpoint** — today `/test` requires the
    device row to exist; the create-then-test flow on the UI
    saves first then probes. A
    `POST /network-devices/probe` that accepts inline creds
    would let operators verify before committing the row.
  - **Frontend permission gating** — sidebar nav entry shows
    for every authenticated user (backend 403s unauthorised
    callers). A `useCurrentUser` hook + `hasPermission` check
    on the sidebar item is the polish step; depends on
    introducing those hooks (they don't exist anywhere in the
    frontend today).
  - **Vendor-specific MIBs** — CISCO-VRF-MIB for VRF
    auto-discovery, ENTITY-MIB for chassis info, vendor PoE
    MIBs. The vendor-neutral path covers the IPAM payoff;
    extensions are operator-pull additions.
  - **`/network-context` reverse-lookup pages.** "Show me every
    IP currently learned on switch X port 24" needs an
    interface-detail page or a query mode on the FDB tab.
    Today operators can filter the FDB tab by interface_id —
    the dedicated UI is a polish iteration.

  Original spec lives at `docs/features/IPAM.md §13` (the
  pre-build placeholder). The shipped behaviour matches that
  spec for the standard-MIB scope.

- ✅ **Nmap scanner** — on-demand nmap scans against any IPv4 /
  IPv6 host or **CIDR** from the SpatiumDDI host perspective.
  Three entry points: a per-IP "Scan with Nmap" button on the
  IPAM IP detail modal, a per-subnet "Scan with nmap" entry in
  the IPAM Tools dropdown (pre-fills target = subnet CIDR +
  preset = `subnet_sweep`), and a standalone `/tools/nmap` page
  for ad-hoc targets (including IPs that aren't in IPAM yet).
  Backend: `NmapScan` model + migration `d2f7a91e4c8b`,
  sanitised argv builder with preset table (quick /
  service+version / **service_and_os** / OS fingerprint /
  **subnet_sweep** / default-scripts / UDP top-100 / aggressive
  / custom), CIDR-aware target validation
  (`ipaddress.ip_network(strict=False)`, capped at /16 worth of
  hosts), async subprocess runner using `-oN -` on stdout for
  the live SSE viewer + `-oX <tmpfile>` in parallel for
  structured XML parsing. The XML parser walks every `<host>`
  element and emits a `hosts[]` list when more than one
  responded — single-host fields stay populated for backward
  compat. Celery task on the `default` queue, SSE endpoint at
  `GET /api/v1/nmap/scans/{id}/stream`. SSE auth uses
  `?token=<...>` because EventSource can't set Authorization
  headers; the router has no global `Depends(get_current_user)`
  because that would 401 before the query-token resolver runs
  (each non-SSE endpoint declares its own permission dep).
  Bulk operations on the history surface:
  `POST /nmap/scans/bulk-delete` (cap 500; per-row policy
  cancels queued/running scans + deletes terminal ones in one
  transaction) and
  `POST /nmap/scans/{id}/stamp-discovered` (claims alive hosts
  from a CIDR scan as `discovered` IPAM rows + stamps
  `last_seen_at` via nmap; integration-owned rows just bump the
  timestamp without changing status). `NmapToolsPage` rewritten
  as a 3-tab right panel (Live / History / Last result) that
  auto-switches Live → Last result on completion; History tab
  has a checkbox column + amber bulk-delete toolbar.
  `NmapResultPanel` renders both single-host and multi-host
  (CIDR) scans with "Copy alive IPs" + "Stamp alive hosts →
  IPAM" actions. New `manage_nmap_scans` permission seeded
  into the existing Network Editor builtin role. nmap installed
  in the api image.
  **Deferred follow-ups:**
  - **Trigger pipeline** — auto-scan on ARP/SNMP discovery (the
    `auto_create_discovered=True` path) and alert-rule-driven
    re-scans. Phase 2.
  - **Realtime fanout** — the SSE stream polls the DB-persisted
    `raw_stdout` column every 500 ms per active viewer. Fine
    at human cadence and a handful of operators; if many
    operators end up watching live scans simultaneously
    (>~20-30) it'll show up as Postgres load. Swap to Redis
    pub/sub or `LISTEN/NOTIFY` behind the same HTTP shape.
  - **Privileged scans** — nmap runs as the api container's
    non-root user; raw-SYN (`-sS`) and unprivileged OS-detect
    silently fall back to TCP-connect. Bare-metal deployments
    can give the API process `CAP_NET_RAW` to unlock those
    modes; containerised deployments can't and shouldn't.

- ✅ **API tokens with auto-expiry** (Phase 1 close-out) — `APIToken`
  model already existed; this session wires the create/list/revoke
  router, extends `get_current_user` to accept `spddi_*` bearer
  tokens alongside JWTs, tracks `last_used_at`, and adds an admin UI
  at `/admin/api-tokens`. Tokens are hashed at rest (SHA-256) and
  shown in plaintext once at creation.

- ✅ **Syslog + event forwarding** — every successful `AuditLog`
  commit is optionally forwarded to an external syslog target
  (RFC 5424 over UDP / TCP) and/or a generic HTTP webhook. Hook is
  a SQLAlchemy `after_commit` session listener in
  `services/audit_forward.py`; delivery is fire-and-forget on a
  dedicated asyncio task so audit writes never block on network I/O.
  Configured in Settings; targets live on `PlatformSettings`
  (single syslog + single webhook for now — multi-target moves to a
  dedicated table when a second customer asks).

- ✅ **DHCP state failover (Kea HA)** — under the group-centric data
  model (shipped 2026.04.21-2), a `DHCPServerGroup` with two Kea
  members is implicitly an HA pair. HA tuning (mode, heartbeat /
  max-response / max-ack / max-unacked, auto-failover) lives on the
  group; per-peer URL lives on each `DHCPServer.ha_peer_url`.
  `DHCPFailoverChannel` is gone — merged into the group.
  `ConfigBundle` carries a `FailoverConfig` when the server's group
  is an HA pair; the agent's `render_kea.py` injects `libdhcp_ha.so`
  + `high-availability` alongside the always-loaded
  `libdhcp_lease_cmds.so` hook. Peer URLs are resolved agent-side
  (`_resolve_peer_url`) before render because Kea's Boost asio
  parser only accepts IP literals. Kea image splits ports: `:8000`
  is owned by the HA hook's `CmdHttpListener`, `:8544` by the
  operator-facing `kea-ctrl-agent`. Agent supervises an
  `HAStatusPoller` thread that calls `status-get` (Kea 2.6 folded
  HA state into the generic status command; pre-2.6 `ha-status-get`
  shapes still accepted) and POSTs state to
  `/api/v1/dhcp/agents/ha-status`. Bootstrap-from-cache issues
  `config-reload` with retry so Kea picks up HA on agent restart.
  HA config lives in the main DHCP tab's server-group edit modal;
  dashboard shows one row per HA pair with a live state dot per
  peer. Scope mirroring is automatic — all servers in a group
  render the same scopes, pools, statics, and client classes.
  **`PeerResolveWatcher`** re-resolves peer hostnames every 30s
  and triggers render + reload on IP drift, so compose
  `--force-recreate` / k8s pod restarts heal without operator
  action. Kea daemons (`kea-dhcp4` + `kea-ctrl-agent`) run under
  per-daemon supervise loops with stale-PID-file scrubbing, 5-in-
  30s crash-loop guards, and SIGTERM forwarding. **Deferred
  follow-ups:**
  - **Kea version skew guard.** The `status-get` HA shape shifted
    between Kea 2.4 and 2.6. Pairing peers on mismatched Kea
    versions is accepted today. Cheap fix: ship Kea version in the
    heartbeat, reject group membership changes if peers differ.
  - **DDNS double-write under HA.** Agent-side DDNS
    (`apply_ddns_for_lease`) doesn't gate on HA state — if the
    standby ever serves a lease (pre-sync window, partner-down),
    both peers could try to write the same RR. Kea's hook
    coordinates DHCP serving but not our DDNS pipeline.
  - **State-transition actions** (`ha-maintenance-start`,
    `ha-continue`, force-sync) — observable today but operators
    can't drive the HA state machine from the UI.
  - **Peer compatibility validation** (refuse groups with ≥ 3 Kea
    members because `libdhcp_ha.so` only supports pairs), per-pool
    HA scope tuning for load-balancing.
  - **HA e2e test.** `.github/workflows/agent-e2e.yml` stands up
    a single-agent DNS pair today; an HA DHCP variant would have
    caught the bootstrap / port-split / `status-get` / wire-shape
    regressions we hit in 2026.04.21-2.

- ✅ **DHCP MAC blocklist (group-global)** — `DHCPMACBlock` table
  hung off `DHCPServerGroup`, unique on `(group_id, mac_address)`,
  indexed on `expires_at`. Per-row fields: `mac_address` (MACADDR),
  `reason` (`rogue` / `lost_stolen` / `quarantine` / `policy` /
  `other`), `description`, `enabled`, `expires_at`, `created_at` +
  `created_by_user_id`, `updated_by_user_id`, `last_match_at`,
  `match_count`. `MACBlockDef` added to `ConfigBundle`; the control
  plane strips `enabled=False` + expired rows pre-render so the
  ETag naturally shifts on expiry transitions and agents long-poll
  pick it up. **Kea path**: agent's `render_kea.py` wraps the active
  MAC list in Kea's reserved `DROP` client class via an OR-ed
  `hexstring(pkt4.mac, ':') == '...'` expression — packets are
  silently dropped before allocation; if the operator hand-defined
  a `DROP` class the renderer steps aside rather than clobber it.
  **Windows DHCP path**: `WindowsDHCPReadOnlyDriver.sync_mac_blocks`
  diffs desired-set against `Get-DhcpServerv4Filter -List Deny` and
  ships one batched PS script per WinRM round trip. Beat tick every
  60 s (`app.tasks.dhcp_mac_blocks.sync_dhcp_mac_blocks`) reconciles
  Windows servers — Kea doesn't need the task since blocklist
  changes flow through the bundle. CRUD at `/api/v1/dhcp/server-
  groups/{gid}/mac-blocks` (list + create) + `/api/v1/dhcp/mac-
  blocks/{id}` (update + delete). List endpoint joins OUI vendor
  lookup and an `IPAddress.mac_address` cross-reference so the UI
  surfaces vendor + any IPAM rows tied to the blocked MAC.
  Frontend `MacBlocksTab` on the DHCP server detail view (mirrors
  where `ClientClassesTab` lives): filterable table, reason pills,
  status pill (active / disabled / expired), IPAM link-outs, add /
  edit modal accepting any common MAC format. Permission gate
  `dhcp_mac_block`; built-in "DHCP Editor" role gets it. Migration
  `d4a18b20e3c7_dhcp_mac_blocks`. **Deferred follow-ups:**
  - **Bulk import / paste** from CSV — the current UI is one-at-a-
    time; large blocklists need a paste-a-list path.
  - **Per-scope restriction.** Kea's class/pool pinning supports
    "block this MAC only on subnet X" — would mean dropping the
    `DROP` shortcut in favour of per-pool `client-class` + a
    per-subnet class. Windows can't do per-scope deny at all
    (deny-list is server-global). Group-global is the right
    default; per-scope is a Phase 5 precision tool.
  - **`last_match_at` + `match_count` wiring.** The columns exist
    but nothing writes to them yet. Kea has a lease-event hook and
    Windows has a `FilterNotifications` event channel we already
    surface in Logs — either can drive the counter.
  - **HA pair compatibility**: the beat task iterates every
    agentless server regardless of group HA state. Should still be
    idempotent but worth a targeted test when HA + Windows DHCP
    land together.


- ✅ **Alerts framework (v1)** — `AlertRule` + `AlertEvent` tables;
  evaluator at `services/alerts.py:evaluate_all()` runs from
  `app.tasks.alerts.evaluate_alerts` on a 60 s beat tick. Two rule
  types on launch: `subnet_utilization` (honours
  `PlatformSettings.utilization_max_prefix_*` so PTP / loopback
  subnets can't trip the alarm) and `server_unreachable` (DNS /
  DHCP / any). Delivery reuses the audit-forward syslog + webhook
  send helpers against the platform-level targets; per-rule
  override of targets deferred. Admin UI at `/admin/alerts` with
  live events viewer + "Evaluate now". SNMP trap delivery is the
  remaining v2 work (SMTP + chat-flavored webhooks landed in
  2026.04.30-1).

- ✅ **SMTP delivery for alerts + audit forward** — landed in
  2026.04.30-1. New SMTP target type with host / port / username /
  Fernet-encrypted password / TLS mode (`starttls` / `ssl` /
  `none`) / from-address / to-list fields. Wired through stdlib
  `smtplib` driven via `asyncio.to_thread` so we don't take a
  dependency on `aiosmtplib`. Audit-forward targets gain
  `kind="smtp"`; alert rules gain a `notify_smtp` toggle alongside
  the existing syslog + webhook channels. Migration
  `30cda233dce9_add_smtp_chat_flavor_to_audit_forward`.

- ✅ **Chat-flavored webhooks (Slack / Teams / Discord)** — landed
  in 2026.04.30-1. New `webhook_flavor` column on
  `audit_forward_target` selects between generic JSON (default),
  Slack `mrkdwn` block, Teams `MessageCard`, and Discord `embed`
  body renderers. Single payload renderer per flavor, no extra
  dependency. Operator pastes the platform's incoming-webhook URL
  into a webhook target and picks the matching flavor.

- ✅ **Typed-event webhooks (generic outbound on resource
  changes)** — landed in 2026.04.30-1. Curated automation surface
  separate from audit-forward. `EventSubscription` + `EventOutbox`
  tables (migration
  `0f83a227b16d_event_subscription_outbox_tables`). 96 typed
  events derived from a `resource_namespace × verb` cross-product
  (`space.created`, `subnet.bulk_allocate`, `dns.zone.updated`,
  `dhcp.scope.deleted`, `auth.user.created`,
  `integration.kubernetes.created`, …). SQLAlchemy
  `after_flush` + `after_commit` listeners snapshot committed
  `AuditLog` rows and write one outbox row per matching
  subscription. Celery beat (`event-outbox-drain`, every 10 s)
  drains via `SELECT … FOR UPDATE SKIP LOCKED`, signs each POST
  with `hmac(secret, ts + "." + body, sha256)`, and retries with
  exponential backoff (2 / 4 / 8 … 600 s capped) up to
  `max_attempts` (default 8 ≈ 8.5 min cumulative). Permanent
  failures flip to `state="dead"` for operator review. Reserved
  `X-SpatiumDDI-*` headers (Event / Delivery / Timestamp /
  Signature) are protected from operator override; custom headers
  are applied last so platform-owned headers can't be silently
  overridden. Admin UI at `/admin/webhooks` with one-time secret
  reveal on create (auto-generated 32-byte hex unless an operator
  supplies their own), event-type multi-select with filter,
  custom-headers editor, per-row test button (synthesizes a
  `test.ping` through the live pipeline), expandable deliveries
  panel with auto-refresh + manual **Retry now** on failed/dead
  rows, and a secret rotation toggle on edit. **Worker engine
  fix bundled** — first cut of `event_outbox` imported
  `AsyncSessionLocal` from `app.db`, which binds asyncpg
  connections to the loop that first checked them out. Celery's
  prefork pool reuses processes across tasks so the second
  `asyncio.run` re-entered with a different loop and surfaced as
  `Future attached to a different loop` followed by cascading
  `cannot perform operation: another operation is in progress`
  errors. Replaced with a per-tick `NullPool` ephemeral engine —
  same pattern `audit_forward._ephemeral_session` and
  `event_publisher._ephemeral_session` use.

- ✅ **Dashboard time-series (MVP)** — agent-driven DNS query rate +
  DHCP traffic charts, self-contained (no Prometheus / InfluxDB
  required). BIND9 agents poll `statistics-channels` XMLv3 on
  `127.0.0.1:8053` (injected into rendered `named.conf`); Kea
  agents poll `statistic-get-all` over the existing control socket.
  Both report per-60s-bucket deltas to `POST
  /api/v1/{dns,dhcp}/agents/metrics`. Counter resets on daemon
  restart are detected agent-side (`delta < 0`) and drop the
  bucket rather than emitting a phantom spike. Storage in two
  narrow tables `dns_metric_sample` + `dhcp_metric_sample` keyed
  on `(server_id, bucket_at)`. Dashboard reads `GET
  /api/v1/metrics/{dns,dhcp}/timeseries?window={1h|6h|24h|7d}`
  with server-side `date_bin` downsampling (60 s for ≤24 h,
  5 min for 7 d). Retention by nightly `prune_metric_samples`
  Celery task (default 7 d). Migration
  `bd4f2a91c7e3_metric_samples`. **Deferred follow-ups:**
  - **Windows DNS / DHCP stats** — needs `Get-DnsServerStatistics`
    + `Get-DhcpServerv4Statistics` driver methods over WinRM.
    Chart currently shows "no data yet" for Windows-only
    deployments.
  - **Prometheus export** of the same samples — one Gauge per
    column with `server_id` label would make the existing
    `/metrics` endpoint a full-featured scrape target for
    operators who prefer Grafana.
  - **InfluxDB push export** (`InfluxDBTarget`) — **shipped**
    (#889). See `docs/features/SYSTEM_ADMIN.md §8` for the built
    shape; the v1 / v2 / v3 writer, the beat task and the
    high-water-mark semantics all live there.
  - **Per-qtype** (BIND) / **per-subnet** (Kea) breakdowns —
    `statistic-get-all` already carries per-subnet counters; the
    agent strips them for MVP. Adding them is column-only, no
    protocol change.
  - **Alert rule types `dns_query_rate` / `dhcp_lease_rate`** —
    threshold-based alerts keyed off the timeseries data.

- ✅ **ACME / Let's Encrypt — DNS-01 provider for external clients**
  — landed in the 2026.04.22-1 wave. Lets certbot / lego / acme.sh
  on a client box prove control of a FQDN hosted in (or delegated
  to) a SpatiumDDI-managed zone and issue public certs (wildcards
  included). Implementation shipped as an `acme-dns`-compatible HTTP
  surface under `/api/v1/acme/` with the following pieces:
  - **Data model** — `ACMEAccount` (`app/models/acme.py`,
    migration `ac3e1f0d8b42`): `username` + `password_hash`
    (bcrypt), UUID `subdomain`, FK `zone_id`, optional
    `allowed_source_cidrs`, `last_used_at`. Credentials shown once
    at registration; only the hash persists.
  - **Endpoints** — `POST /register` (JWT auth, gated by
    `manage_acme` / `write:acme_account`), `POST /update` +
    `DELETE /update` (acme-dns `X-Api-User` / `X-Api-Key` auth,
    subdomain must match authenticated account), `GET /accounts`
    / `DELETE /accounts/{id}` admin ops.
  - **Record write** — routes through the normal
    `enqueue_record_op` pipeline so TXT records land in the UI +
    audit log + DDNS pipeline uniformly. `subnet_id`-equivalent
    routing here is the zone's primary server.
  - **Propagation wait** — `/update` blocks up to 30 s polling
    `DNSRecordOp.state` until `applied`, so the CA's subsequent
    DNS-01 poll finds the record live. Returns 504 on timeout,
    502 on primary driver error.
  - **Wildcard support** — keeps the 2 most-recent TXT values per
    subdomain so wildcard + base cert issuance (which presents two
    different validation tokens at the same record name) works.
  - **Protocol choice** — `acme-dns` compat means certbot
    (`dns-acmedns` plugin), lego, acme.sh all work out of the box
    with no custom plugin. Delegation pattern documented in
    `docs/features/ACME.md` — operator CNAMEs
    `_acme-challenge.<their-fqdn>` to
    `<account.subdomain>.<our-acme-zone>` and delegates the small
    subzone via NS records, so a leaked credential can't rewrite
    anything outside that label.
  - **Audit** — every register / update / delete / revoke lands in
    `audit_log`. TXT values logged as a 12-char prefix only, never
    in full. Credentials never logged, hashed or otherwise.
  - **Tests** — `backend/tests/test_acme.py`, 24 tests covering
    crypto roundtrip, source-CIDR allowlist edge cases, HTTP auth
    paths, wildcard rolling window, revocation, cleanup.

  **Deferred follow-ups:**
  - **Dedicated rate-limit bucket** for `/api/v1/acme/*` + Fail2Ban-
    style temp-ban on repeated `/update` auth failures. Today the
    endpoint rides the general API rate limit (none in v1; add
    slowapi or similar when it lands).
  - **Per-op `asyncio.Event` ack channel** to replace the DB-polling
    `wait_for_op_applied` loop. ~250 ms latency savings on the
    typical path; the polling approach is simple and correct but
    opens/closes a DB session every 500 ms.
  - **Celery janitor task** for the 24 h stale TXT sweep — service-
    level function `acme.sweep_stale_txt_records` is written and
    unit-testable; wiring it into the beat schedule is pending.
  - **Metric exposure** for ACME activity (registrations,
    /update rate, sweep counts) on the admin dashboard.


- ✅ **Kubernetes integration (read-only cluster mirror).** Poll one
  or more Kubernetes clusters with a read-only service-account
  token and mirror the stable bits of cluster state into SpatiumDDI.
  **Deliberately not mirroring pod IPs** — they churn too fast to
  be useful in IPAM. The value is reserving cluster CIDRs in IPAM
  (so operators can't accidentally overlap), surfacing LoadBalancer
  VIPs with their owning `namespace/service`, and auto-generating
  DNS records for Ingress hostnames. Pure pull, SpatiumDDI never
  writes to the cluster.

  **UX shape (agreed):**
  - **Settings → Integrations** is a new top-level settings section
    that hosts one card per integration type. Each card carries its
    own independent enable toggle on `PlatformSettings` (no single
    master `integrations_enabled` flag — granular by design so
    enabling Kubernetes doesn't also enable a future Terraform
    Cloud integration). When an integration's toggle is on, its
    corresponding top-level sidebar nav item appears (flat, not
    nested under an "Integrations" meta-item — matches how DHCP /
    DNS already surface).
  - **`KubernetesCluster` rows** are the per-cluster config, not
    PlatformSettings. Each cluster binds to exactly one
    `IPAMSpace` (required — discovered IPs / blocks land there)
    and optionally one `DNSServerGroup` (for ingress → DNS sync).
    Many clusters supported, same or different space/group per
    cluster.
  - **Credentials**: API server URL + CA bundle PEM + bearer token,
    with the token Fernet-encrypted at rest alongside the other
    driver creds (`DHCPServer.credentials_encrypted`,
    `DNSServer.credentials_encrypted`).
  - **Modal** shows an embedded setup guide with the exact
    ServiceAccount / ClusterRole / ClusterRoleBinding YAML plus
    `kubectl` commands to extract the token + CA bundle. Cluster
    version + node count round-trip via a **Test Connection**
    button before save.
  - **Operator also enters pod CIDR + service CIDR** in the form —
    service CIDR is not reliably extractable from the API; pod CIDR
    could be derived from Node objects but asking is simpler and
    matches how the DHCP / DNS server forms work.

  **Phased scope:**

  - ✅ **Phase 1a — Scaffolding.** Settings → Integrations UX +
    per-integration toggle on PlatformSettings + sidebar gating.
    `KubernetesCluster` model + migration `f8c3d104e27a` + CRUD API
    + admin UI page + setup-guide modal (embedded YAML + kubectl
    extract commands) + Test Connection button that probes
    `/version` + `/api/v1/nodes` with structured error
    reporting (401/403/TLS/network distinguished).

  - ✅ **Phase 1b — Read-only reconciliation.** Every 30 s beat
    tick; per-cluster `sync_interval_seconds` (min 30 s) gates the
    actual reconcile. Gated overall by
    `PlatformSettings.integration_kubernetes_enabled`. Provenance
    via dedicated `kubernetes_cluster_id` FK on `ip_address`,
    `ip_block`, `dns_record` (migration `a917b4c9e251`); FK is
    `ON DELETE CASCADE` so removing a cluster sweeps every mirror
    row atomically. What gets mirrored:
    - Pod CIDR + Service CIDR → one `IPBlock` each under the bound
      space.
    - Node objects → `IPAddress` with `status="kubernetes-node"`,
      hostname = node name.
    - `Service` objects with `spec.type=LoadBalancer` + populated
      `status.loadBalancer.ingress[0].ip` → `IPAddress` with
      `status="kubernetes-lb"`, hostname = `<service>.<namespace>`.
    - `Ingress` objects with `status.loadBalancer.ingress[0].ip`
      → DNS **A** record per `rules[].host` in the longest-suffix-
      matching zone from the bound DNS group; `ingress[0].hostname`
      (cloud LBs) → **CNAME**. `auto_generated=True` + fixed 300 s
      TTL. Rows missing a matching subnet / zone increment
      `skipped_no_subnet` / `skipped_no_zone` on the reconcile
      summary — non-fatal, surfaced in logs + audit. Diff is
      create / update / delete (option 2a: delete, not orphan).
    **Admin UI**: "Sync Now" button per cluster (fires
    `sync_cluster_now` Celery task, bypasses interval gating) plus
    per-row `last_synced_at` / `last_sync_error` display. K8s
    client is a thin `httpx`-based REST wrapper — no
    `kubernetes-asyncio` dep.

  - ⬜ **Phase 2 — external-dns webhook provider (separate
    feature).** Implement the external-dns webhook provider HTTP
    protocol so teams already running external-dns can just point
    it at SpatiumDDI as a DNS backend. Different protocol, different
    testing story — deliberately not bundled with the pull-based
    integration above.

  **Explicit non-goals:**
  - Mirroring pod IPs (too dynamic, too noisy — the CIDR block is
    what matters).
  - Writing to the cluster (no CRD create, no annotation updates).
    If we want write-back, Phase 2's external-dns webhook is the
    right pattern — it's what ops teams already expect.
  - Managing the kubeconfig / kubectl flow — operator brings their
    own cluster-admin credentials to create the ServiceAccount; we
    only ever see the resulting read-only token.


- ✅ **Docker integration (read-only host mirror).** Poll one or
  more Docker daemons with a read-only connection and mirror the
  networks + (opt-in) containers into IPAM. Same UX shape as the
  Kubernetes integration above — `DockerHost` rows bound per-host
  to one `IPAMSpace` + optional `DNSServerGroup`, Settings →
  Integrations → Docker toggle, sidebar item gated on the toggle,
  Fernet-encrypted TLS client key, per-row Test Connection + Sync
  Now buttons, Setup guide with copy-paste TCP+TLS daemon config
  or Unix socket mount instructions.

  **Transport:** `unix` socket or `tcp` with optional mTLS. SSH
  (`docker -H ssh://`) is deferred — needs paramiko +
  `docker system dial-stdio` stream shuffling. No Docker Python
  SDK dep; we hit three Engine API endpoints (`/networks`,
  `/containers/json`, `/info`) over `httpx`.

  **What's mirrored:**
  - Every non-skipped Docker network → IPAM subnet under an
    enclosing operator block when one exists, else a cluster-
    owned wrapper block at the CIDR. Default `bridge` / `host` /
    `none` / `docker_gwbridge` / `ingress` are skipped unless
    `include_default_networks=true`. Swarm overlay networks
    always skipped (cluster-wide — would duplicate across nodes).
  - Network gateway → one `reserved`-status `IPAddress` per
    subnet (mirrors the LAN placeholder that `/ipam/subnets`
    creates for operator-made subnets).
  - Containers (opt-in via `host.mirror_containers`) → one
    `IPAddress` per (container × connected network) with
    `status="docker-container"` and hostname = either
    `<compose_project>.<compose_service>` when Docker Compose
    labels are present, else the container name. Stopped
    containers skipped unless `include_stopped_containers=true`.

  **Phase-3 placeholder (deferred).** Rich per-host management
  surface like mzac/uhld's Docker plugin: container actions
  (start/stop/restart), log streaming, shell exec (pty over
  websocket), image management, compose project up/down,
  volume browser, live events feed. Queries the stored
  connection live — no schema migration needed. Same treatment
  for Kubernetes (pod logs, shell exec, YAML apply, scaling).
  Scoped as a separate feature because it's a full management UI,
  not IPAM, and needs a websocket pipeline we don't have today.

- ✅ **Network sidebar section — group VLANs / VRFs / ASNs /
  Devices** (issue #84). Pure sidebar nav reorg replacing the
  standalone "Network" (SNMP routers/switches) and "VLANs"
  top-level entries with a non-clickable "Network" parent
  mirroring the Administration shape. Devices replaces the old
  top-level Network entry; VLANs lifts up from its own slot.
  Routes moved to `/network/devices`, `/network/vlans`,
  `/network/vrfs`, `/network/asns`; old `/network` and `/vlans`
  paths redirect so existing bookmarks keep working, and the
  legacy `/network/:id` device-detail URL is preserved alongside
  the canonical `/network/devices/:id` form.

- ✅ **ASN management** (issue #85). First-class entity for the
  autonomous systems carrying our IP space, with RDAP holder
  refresh, RPKI ROA tracking, holder-drift detection, four
  ASN/RPKI alert rule types, BGP peering relationships, and the
  BGP communities catalog (issues #88 + #89 ride along).
  - **Data model.** `asn` table — BigInteger `number` to fit the
    full 32-bit AS range; `kind` (public / private) auto-derived
    from RFC 6996 + RFC 7300; `registry` (RIR) auto-derived from
    a hand-curated IANA ASN delegation snapshot at
    `app/data/asn_registry_delegations.json`; WHOIS columns
    populated by the refresh task. `asn_rpki_roa` sibling table —
    prefix CIDR + max_length + validity window + trust_anchor +
    state, ON DELETE CASCADE from `asn`. Migrations
    `f59a5371bdfb_asn_management` + `4a7c8e3d51b9_asn_phase2`.
  - **RDAP holder refresh.** `app/services/rdap_asn.py` derives
    the RIR via `derive_registry()` and queries the RIR's RDAP
    base directly (`rdap.arin.net`, `rdap.db.ripe.net`,
    `rdap.apnic.net`, `rdap.lacnic.net`, `rdap.afrinic.net`) —
    `rdap.iana.org/autnum/<n>` is a bootstrap *registry* not a
    query proxy and returns HTTP 501 for every real query, so
    routing-by-RIR is mandatory. `app/tasks/asn_whois_refresh.
    refresh_due_asns` ticks hourly; per-row Refresh button drives
    the same code path synchronously (`POST /api/v1/asns/{id}/
    refresh-whois`). `next_check_at` cadence tunable via
    `PlatformSettings.asn_whois_interval_hours` (default 24, range
    1..168).
  - **RPKI ROA pull.** `app/services/rpki_roa.py` fetches the
    global ROA dump from Cloudflare (`rpki.cloudflare.com/rpki.
    json`, ~80 MB JSON, ~850k entries) or RIPE NCC's validator
    JSON, filters by AS number, and caches the multi-MB payload
    in-memory for 5 min via `_get_cached_roas` so a beat sweep
    refreshing 50 ASNs makes a single HTTP call instead of 50.
    `app/tasks/rpki_roa_refresh.refresh_due_roas` ticks hourly,
    derives state (`valid` / `expiring_soon` / `expired` /
    `not_found`) off `valid_to`, audit-logs adds / removes / state
    transitions. `_parse_validity` accepts Cloudflare's `expires`
    (Unix epoch) + RIPE's `notBefore` / `notAfter` (ISO 8601) on
    the same row. Per-row Refresh RPKI button (`POST
    /api/v1/asns/{id}/refresh-rpki`) reuses `_refresh_one_asn`
    for the synchronous path. Two new `PlatformSettings` knobs:
    `rpki_roa_source` (cloudflare | ripe) and
    `rpki_roa_refresh_interval_hours` (default 4, range 1..168).
  - **Holder-drift diff viewer.** `asn_whois_refresh` persists
    `previous_holder` into `whois_data` on every successful RDAP
    refresh — drift or not — so the WHOIS tab can render the
    side-by-side without consulting the audit log.
  - **Alert rules.** Four new types: `asn_holder_drift` (latched
    via `alert_event.last_observed_value` JSONB so a single flip
    fires exactly one event auto-resolved after 7 d),
    `asn_whois_unreachable`, `rpki_roa_expiring` (severity
    escalation at threshold/4 + threshold/12 around
    `threshold_days`, default 30 d), `rpki_roa_expired`.
  - **BGP peering relationships (issue #89).** `bgp_peering`
    table — `peer | customer | provider | sibling`. Both
    endpoints FK ON DELETE CASCADE; unique on `(local, peer,
    relationship_type)`. Column named `relationship_type` so it
    doesn't shadow the imported `sqlalchemy.relationship`
    function. `router.local_asn_id` FK ON DELETE SET NULL stamps
    which AS a router originates routes from. `PeeringsTab` on
    ASN detail with directional listing (`→ outbound` / `←
    inbound` from this AS's POV) and clickable counter-AS;
    `PeeringFormModal` lets the operator pick either side as
    "local" + normalises to canonical shape on submit. Migration
    `d3f2a51c8e76_bgp_peering`.
  - **BGP communities catalog (issue #88).** `bgp_community`
    table; `asn_id` nullable so platform-level rows (RFC 1997 /
    7611 / 7999 well-knowns: no-export, no-advertise,
    no-export-subconfed, local-as, graceful-shutdown, blackhole,
    accept-own) are shared across all ASes. `kind` denormalises
    on-the-wire shape: `standard` / `regular` (`ASN:N` per RFC
    1997) / `large` (`ASN:N:M` per RFC 8092).
    `app.services.bgp_communities` owns the well-known catalog +
    seeds it on first boot via a hook in `main.py`'s lifespan
    (subsequent boots refresh the description text so upgrades
    that reword a row land without an admin edit). CRUD: `GET
    /asns/communities/standard`, `GET|POST /asns/{asn_id:uuid}/
    communities`, `PATCH|DELETE /asns/communities/{community_id:
    uuid}`. Standard catalog rows refuse PATCH / DELETE with a
    400. `CommunitiesTab` with collapsible standard catalog +
    "Use on this AS" buttons + per-AS list grouped by kind.
    Migration `f4a6c8b2e571_bgp_communities`.
  - **BGP FK on IPSpace / IPBlock.** `asn_id` UUID column on
    both, FK to `asn.id` ON DELETE SET NULL, indexed. Shared
    `AsnPicker` at `components/ipam/asn-picker.tsx` wired into
    the four IPSpace / IPBlock modals as an optional "Origin ASN
    (BGP)" field. Migration `c9f1e47d2a83_bgp_asn_fk`.
  - **Detail page tabs.** WHOIS · RPKI ROAs · Linked IPAM ·
    BGP Peering · Communities · Alerts.

- ✅ **VRFs as first-class entities** (issue #86). Replaces the
  freeform `vrf_name` / `route_distinguisher` / `route_targets`
  text fields on IPSpace with a relational `vrf` table.
  - **Data model.** `vrf` table carries name, description,
    optional `asn_id` FK, RD with format validation, split
    import / export RT lists, tags, custom_fields. `ip_space.
    vrf_id` + `ip_block.vrf_id` FKs ON DELETE SET NULL. Migration
    backfills new VRF rows from every distinct (vrf_name, rd,
    rt-list) triple on existing IPSpace rows and stamps each
    space's `vrf_id` at the matching new row; freeform columns
    stay in place for one release cycle so operators can verify
    the mapping landed before they get dropped.
  - **Cross-cutting RD / RT validation.** Each `ASN:N` entry
    whose ASN portion does not match `vrf.asn.number` produces a
    non-blocking warning on the response. `PlatformSettings.
    vrf_strict_rd_validation` flips to escalate the same
    mismatch to 422. Second warning fires when `vrf.asn_id` is
    null but the RD is in `ASN:N` form. `IPBlock` responses also
    carry `vrf_warning` flagging when a block's pinned VRF
    differs from its parent space's VRF (intentional in
    hub-and-spoke designs but worth a heads-up).
  - **VRF picker** at `components/ipam/vrf-picker.tsx` wired into
    the New / Edit IPSpace + Create / Edit IPBlock modals,
    replacing the freeform text inputs. Space-detail header
    surfaces the linked VRF's name + RD + RTs read-only via the
    cached VRF list.
  - **Permission + UI.** `manage_vrfs` permission seeded into
    the Network Editor builtin role. List page at `/network/
    vrfs` with bulk-select + draggable create/edit modal. Detail
    page at `/network/vrfs/:id` with linked IP spaces / blocks
    tabs and a Pencil HeaderButton wired to the shared
    `VRFEditorModal`. Migrations `2c4e9d1a7f63_vrf_first_class`
    + `b7e2a4f91d35_vrf_phase2`.

- ✅ **Domain registration tracking** (issue #87). Distinct from
  DNSZone — tracks the registry side of a name (registrar /
  registrant / expiry / nameservers / DNSSEC) versus the records
  SpatiumDDI serves.
  - **Data model.** `domain` table with the registry-side fields,
    expected-vs-actual nameservers, `whois_state` (ok / drift /
    expiring / expired / unreachable), `consecutive_failures`
    counter. Migrations `3124d540d74f_domain_registration` +
    `4a9e7c2d18b3_domain_phase2`.
  - **RDAP refresh.** `app.services.rdap` httpx client (10 s
    per-call / 15 s total budget). TLD → RDAP-base lookup driven
    by the IANA bootstrap registry at `data.iana.org/rdap/dns.
    json`, cached in-process for 6 h with an asyncio lock against
    thundering-herd refetch + a stale-cache fallback if the
    bootstrap fetch fails — `rdap.iana.org/domain/<n>` returns
    404 for any non-test domain so per-TLD routing is mandatory.
    Routes `.com` → `rdap.verisign.com/com/v1/`, `.net` →
    `rdap.verisign.com/net/v1/`, etc. Beat-fired `app/tasks/
    domain_whois_refresh.refresh_due_domains` ticks hourly,
    self-paces via `PlatformSettings.domain_whois_interval_hours`
    (default 24 h, 1–168 h range). `derive_whois_state` decision
    tree (unreachable → expired → expiring < 30 d → drift → ok)
    + `compute_nameserver_drift` shared between sync `POST
    /domains/{id}/refresh-whois` endpoint and the task.
  - **Alert rules.** `domain_expiring` (severity escalation at
    threshold/4 + threshold/12 around the operator-set
    `threshold_days`, default 30 d), `domain_nameserver_drift`,
    `domain_registrar_changed`, `domain_dnssec_status_changed`.
    The two transition-once rules latch the observed value into
    a new `alert_event.last_observed_value` JSONB column so a
    single flip fires exactly one event, auto-resolved after
    7 d. `alert_rule.threshold_days` is the new params column
    (mirrors the existing `threshold_percent` shape).
  - **DNSZone linkage.** `dns_zone.domain_id` nullable FK ON
    DELETE SET NULL. Picker on the DNS zone create / edit modal —
    "Auto-match by zone name" remains the default for backward-
    compat. Domain detail's "Linked DNS Zones" tab prefers the
    explicit FK and falls back to a left-anchored suffix match
    (`zone === domain || zone.endsWith("." + domain)`) when
    `domain_id` is unset, so child zones inherit (`test.example.
    com` shows up under `example.com`) but `example.com.au`
    correctly does NOT match `example.com`. Sub-zones get a
    "sub-zone" badge. Migration `e7b8c4f96a12_dns_zone_domain_fk`.
  - **List + detail UI.** Domains nav lives in the core sidebar
    (between DNS Pools and Logs) — registration tracking is core
    operational data, not platform admin. List page at `/admin/
    domains` with sticky table, expiry countdown badges (green >
    90 d / amber 30–90 d / red < 30 d / dark-red expired),
    per-row Refresh + Edit + Delete, multi-select bulk refresh /
    bulk delete, expandable row with raw RDAP payload. Detail
    page at `/admin/domains/:id` with registration card,
    expected-vs-actual NS diff panel, raw WHOIS / Linked DNS
    Zones / Alert History tabs.

- ✅ **Multi-group DNS publishing — split-horizon at the IPAM
  layer** (issue #25). `IPBlock.dns_split_horizon` boolean +
  the existing `dns_inherit_settings` walk. When set,
  descendant subnets publish records to `dns_zone_id`
  (internal) AND every entry in `dns_additional_zone_ids`
  (DMZ / external). Per-record routing is decided by the new
  `IPAddress.dns_zone_overrides` JSONB list
  (`[{zone_id, record_type}]`) so an operator can pin one
  address to publish only into the internal zone. Auto-sync
  task respects the split. Closes the IPAM-layer half of the
  split-horizon roadmap; DNS Views (#24) covers the
  recursive-resolver-side split.

- ✅ **IPAM template classes — reusable stamp templates with
  child layouts** (issue #26). New `ipam_template` table
  captures default tags / custom-fields / DNS / DHCP / DDNS
  settings (plus an optional sub-subnet `child_layout`) and
  stamps them onto blocks or subnets at apply time.
  ``applies_to`` locks each template to one of the two
  carriers so apply-time semantics stay unambiguous.
  ``force=False`` fills only empty/null target columns;
  ``force=True`` overwrites unconditionally and is the path
  ``/reapply-all`` uses to refresh drift across every recorded
  instance (cap 200). ``IPBlockCreate.template_id`` /
  ``SubnetCreate.template_id`` add optional pre-fill on the
  create paths; carrier rows now carry an
  ``applied_template_id`` SET-NULL FK so a "reapply across
  instances" sweep can find every row touched. Block templates
  with ``child_layout`` carve sub-subnets sequentially on
  apply (and on create); idempotent — sub-subnets already at a
  target CIDR are skipped. ``/admin/ipam/templates`` page (list
  + tabbed editor: General / Tags + CFs + DNS-DHCP / DDNS /
  Child layout) + per-row Reapply with typed-name confirm. New
  ``manage_ipam_templates`` permission seeded into the IPAM
  Editor builtin role.

- ✅ **Move IP block / space across IP spaces** (issue #27).
  `POST /ipam/blocks/{id}/move` accepts a target `space_id` +
  a typed-name confirmation. Pre-flight validates target
  space exists, no CIDR overlap in the target tree, every
  dependent row (DNS records, DHCP scopes, addresses with
  custom-field inheritance) survives the move.
  `MoveBlockModal` walks the operator through the
  consequences with a chevron-revealed list of affected
  resources before the typed-name confirm unlocks Move.

- ✅ **Operator Copilot — Ask-AI everywhere with multi-vendor
  failover** (issue #90). Two phases:
  - **Phase 1 — provider config + LLM driver foundation, MCP
    HTTP endpoint, chat orchestrator + SSE chat endpoint,
    floating chat drawer, observability + caps.** Migration
    `a4b8c2d619e7` adds `ai_provider` (Fernet-encrypted
    api_key, kind discriminator, ordered priority for
    failover, JSONB options bag). LLM driver ABC at
    `app/drivers/llm/base.py` defines neutral
    request / chunk / tool dataclasses; concrete drivers
    translate at the SDK boundary. OpenAI-compat driver
    covers OpenAI / Ollama / OpenWebUI / vLLM / LM Studio /
    llama.cpp server / LocalAI / Together / Groq / Fireworks.
    Tool registry mirrors the driver registry shape. A
    set of read-only tools covers the common operator asks
    (`list_subnets`, `get_subnet`, `list_ips`, `get_ip`,
    `list_zones`, `list_records`, `list_dhcp_scopes`,
    `list_leases`, `list_alerts`, `list_audit`,
    `list_devices`, `list_circuits`, `list_customers`,
    `list_sites`, `list_providers`, `list_asns`, `list_vrfs`,
    `list_overlays`). MCP-shaped HTTP endpoint at
    `/api/v1/ai/mcp` exposes the same set so external MCP
    clients (Claude Desktop / Cursor / Cline) can connect
    directly. Chat orchestrator runs the iterative
    tool-calling loop. SSE endpoint at
    `POST /api/v1/ai/chat/{session_id}/messages` streams
    `text-delta` / `tool-call-delta` / `tool-result` events;
    sets `X-Accel-Buffering: no` so nginx doesn't batch the
    stream. Floating chat drawer renders Markdown + code
    blocks + tool-call collapsed-by-default cards;
    optimistically renders the user's just-sent message.
    Migration `c8e3a7f10b54` adds `ai_usage_event`; pricing
    table at `services/ai/pricing.py` covers the major
    hosted models; per-user daily cap enforced in the
    orchestrator; live token chip in the drawer header; AI
    usage card on Platform Insights aggregates the last 7
    days by provider + model.
  - **Phase 2 — Anthropic / Azure OpenAI / Google Gemini
    drivers, failover chain, "Ask AI about this"
    affordances, custom prompts library, Cmd-K palette
    entry, daily digest, write tools.** Anthropic driver
    translates to Messages API (system prompt as a top-level
    field; tool-use blocks vs. tool-calls). Azure OpenAI
    driver adapts the OpenAI-compat shape to per-deployment
    URL + `?api-version=` query param. Google Gemini driver
    translates to `generateContent` API and reassembles
    streamed function calls. Orchestrator walks providers in
    priority order on transient failures (5xx / timeout /
    rate-limit) — first successful chunk wins; permanent
    errors (4xx / auth) surface immediately. Compact "Ask AI
    about this" icon button on subnets / IPs / DNS zones /
    records / alerts / audit / DHCP / network devices
    pre-fills the chat drawer with a templated prompt + the
    resource UUID. Custom prompts library
    (`ai_custom_prompt`) with a built-in starter pack (Find
    unused IPs, Audit recent changes, Summarize subnet
    utilization, Triage open alerts). Cmd-K palette top
    entry; fixed shortcut conflict with the existing search
    hotkey. Daily Operator Copilot digest fired by Celery
    beat at 0900 local through audit-forward / SMTP /
    webhook channels (off by default). Write tools follow a
    two-phase preview / apply contract: model proposes via
    `propose_*` returning a planned `proposed_change`
    envelope, operator clicks Apply in the chat drawer,
    frontend sends `apply_change` follow-up that hits the
    real CRUD endpoint. Three pilot tools:
    `propose_create_ip`, `propose_update_ip_status`,
    `propose_create_dns_record`. System prompt now
    interpolates platform stats (subnet count, alert count,
    recent audit summary), the operator's role + scoped
    permissions, and "today's interesting things" (services
    expiring < 30 d, alerts opened in the last hour, devices
    last seen > 7 d ago).

- ✅ **Customer / Site / Provider — logical ownership
  entities** (issue #91). Three first-class rows that
  cross-cut IPAM / DNS / DHCP / Network so operators can
  answer "who owns this?", "what's at NYC?", and "which
  circuits does Cogent supply us?" without resorting to
  free-form tags. `Customer` is soft-deletable; `Site` is
  hierarchical (`parent_site_id`) with a unique-per-parent
  `code` (NULLS NOT DISTINCT for top-level deduping);
  `Provider` carries an optional `default_asn_id` FK + a
  `kind` enum (transit / peering / carrier / cloud /
  registrar / sdwan_vendor). Cross-reference columns added
  on every existing IPAM/DNS/DHCP/Network table with
  `ON DELETE SET NULL` so a customer/site/provider deletion
  never cascades into core rows — operators want to re-tag,
  not lose data. Three new admin pages (Customers / Sites /
  Providers) + shared `CustomerPicker` / `SitePicker` /
  `ProviderPicker` (with optional kind filter) + matching
  Chip components plug into every IPAM / DNS / circuit /
  overlay create + edit modal. RBAC seeded into Network
  Editor + IPAM Editor. Migration
  `c2a7e4f81b69_logical_ownership_entities`. **Deferred
  follow-ups:** customer-scoped dashboard KPIs, site-scoped
  DNS auto-pin, customer-bulk-assign tool, freeform
  `Domain.registrar` text → FK backfill.

- ✅ **WAN circuits — first-class transport tracking** (issue
  #93). New `circuit` table — carrier-supplied logical pipe
  (the contract + transport class + bandwidth + endpoints +
  term + cost), distinct from the equipment lighting it up
  (CMDB territory, intentionally out of scope).
  `provider_id` is `ON DELETE RESTRICT` (carrier
  relationship too load-bearing to silently null);
  `customer_id` and the four endpoint refs (a/z-end site +
  subnet) are `ON DELETE SET NULL`. Nine transport classes
  (mpls / internet_broadband / fiber_direct / wavelength /
  lte / satellite + three cloud cross-connects:
  direct_connect_aws / express_route_azure /
  interconnect_gcp). Soft-deletable so `status='decom'` is
  the operator-visible end-of-life flag while history stays
  restorable. CRUD under `/api/v1/circuits` with filters
  (provider_id / customer_id / site_id matching either end /
  subnet_id / transport_class / status / expiring_within_days
  / search) + `/by-site/{site_id}` convenience endpoint.
  `/network/circuits` page with bulk-action table + tabbed
  editor modal (General / Endpoints / Term + cost / Notes) +
  colour-coded term-end badge + asymmetric bandwidth display.
  Two new alert rule types — `circuit_term_expiring` (mirrors
  `domain_expiring` shape with severity escalation per
  `threshold/4` / `threshold/12`) and `circuit_status_changed`
  (transition-style — fires once on `suspended` or `decom`
  with auto-resolve after 7 d; routine `active` ↔ `pending`
  flips during commissioning are intentionally excluded).
  Migration `d9f3b21e8c54_wan_circuits`.

- ✅ **Service catalog — MPLS L3VPN service modeling
  (extensible)** (issue #94). First-class
  customer-deliverable bundle. `NetworkService` is one row
  per thing the operator delivers (`mpls_l3vpn` + `custom`
  shipped in v1; `sdwan` lit up alongside #95). Polymorphic
  `NetworkServiceResource` join row binds a service to VRF
  / Subnet / IPBlock / DNSZone / DHCPScope / Circuit / Site
  / OverlayNetwork. `customer_id` is `ON DELETE RESTRICT`
  (contractual weight too load-bearing to silently null).
  Hard rule: `mpls_l3vpn` services may have at most one VRF
  attached (422 on second VRF, 422 on kind-flip-to-L3VPN if
  >1 VRF already linked). Soft rules surfaced as warnings on
  `GET /summary`: missing VRF, fewer than 2 edge sites, edge
  subnet's enclosing block in a different VRF than the
  service. Endpoints: standard CRUD + bulk-delete,
  `POST/DELETE /{id}/resources` for attach / detach,
  `GET /{id}/summary` with kind-aware shape (L3VPN view
  returns canonical VRF + edge sites + edge circuits + edge
  subnets + warnings), `GET /by-resource/{kind}/{id}`
  reverse lookup. Two new alert rule types —
  `service_term_expiring` (mirrors circuit shape) and
  `service_resource_orphaned` (sweep over join rows whose
  target was deleted; auto-resolves on detach). Migration
  `e1d8c92a4f73_network_service_catalog` +
  `f2c8d49a1e76_alert_event_subject_type_widen` (VARCHAR(20)
  → VARCHAR(40) to fit `network_service_resource`).
  `/network/services` page (bulk-action table) + tabbed
  editor modal (General / Resources / Term + cost / Notes /
  Summary) with per-kind resource pickers (cross-group
  fan-out for DNS zones + DHCP scopes). RBAC into Network
  Editor + IPAM Editor. **Deferred follow-ups:** service
  templates, per-customer monthly spend rollup, service
  status timeline, L2VPN / VPLS / EVPN / DIA / hosted-DNS /
  hosted-DHCP kinds, right-click "show services using this
  resource" entry points (issue #99).

- ✅ **SD-WAN — overlay networks + transport-aware routing
  policies** (issue #95). Vendor-neutral source of truth for
  SD-WAN overlay topology + routing-policy intent. Vendor
  config push (vManage / Meraki Dashboard / FortiManager /
  Versa Director) and real-time path telemetry are
  explicitly out of scope. Four tables landing together:
  `overlay_network` (soft-deletable; six kinds — sdwan /
  ipsec_mesh / wireguard_mesh / dmvpn / vxlan_evpn /
  gre_mesh; free-form vendor + encryption_profile so
  non-curated vendors plug in without enum migration),
  `overlay_site` (m2m binding sites with role hub / spoke /
  transit / gateway, edge device, loopback subnet, ordered
  `preferred_circuits` jsonb — first wins, fall through on
  outage), `routing_policy` (declarative per-overlay policy
  with priority + match-kind + match-value + action +
  action-target + enabled), and `application_category`
  (curated SaaS catalog used by `match_kind=application`,
  seeded at startup with 33 well-known apps following the
  BGP-communities pattern). CRUD under `/api/v1/overlays`
  (with sites + policies sub-resources) and
  `/api/v1/applications`. `GET /overlays/{id}/topology`
  returns nodes (sites + roles + device + loopback +
  preferred-circuits) + edges (site pairs whose
  `preferred_circuits` lists overlap — `shared_circuits` is
  the intersection so the UI can colour by transport class)
  + policies. `POST /overlays/{id}/simulate` is pure
  read-only what-if; body specifies `down_circuits`,
  response shows per-site fallback resolution (surviving
  preferred chain + primary circuit + `blackholed` flag) and
  per-policy effective-target with `impacted` flag + a
  human-readable note. Three new RBAC resource types
  (`overlay_network` / `routing_policy` /
  `application_category`) into Network Editor.
  Service-catalog (#94) integration unlocked: `sdwan` added
  to `SERVICE_KINDS_V1`, `overlay_network` lit up as a real
  attach target, `service_resource_orphaned` alert sweep
  covers deleted overlays. `/network/overlays` list page +
  detail page at `/network/overlays/{id}` with five tabs —
  Overview / Topology (SVG circular layout, role-coloured
  nodes, transport-coloured edges with solid for
  single-class and dashed for mixed) / Sites / Policies
  (priority-ordered with up/down reorder + per-kind editors)
  / Simulate (toggle circuits down + see per-site fallback
  + per-policy impact). Migration
  `c4f7e92d3a18_sdwan_overlay`. **Deferred follow-ups (issue
  #100):** vendor read-only mirror integrations (Meraki /
  Viptela / Fortinet / VeloCloud / Versa), topology diff,
  cross-vendor policy lint, application catalog enrichment
  from upstream feeds, path-quality SLA targets, overlay
  templates, plus v1 UX polish — D3 force-directed topology
  layout, drag-and-drop reordering, Applications admin UI
  page, "Used by N services" link on the overlay detail
  header.


## Integration roadmap

- ✅ **Proxmox VE** — `ProxmoxNode` model + REST client
  + reconciler landed. Auth is API-token (`user@realm!tokenid`
  + UUID), token secret Fernet-encrypted at rest. One row
  covers a standalone host OR a whole cluster (PVE API is
  homogeneous across cluster members; `/cluster/status` surfaces
  cluster name + node count). Mirror scope:
  - **SDN VNets** (`/cluster/sdn/vnets/{vnet}/subnets`) →
    `Subnet` named `vnet:<vnet>` with the declared gateway.
    Authoritative over bridge-derived rows for the same CIDR —
    operator intent from PVE SDN wins. Returns 404 when SDN
    isn't installed; reconciler treats that as "no SDN" and
    keeps going.
  - **SDN VNet subnet inference** (opt-in via
    `infer_vnet_subnets` toggle, default off) — for VNets that
    exist but have no declared subnets, derive the CIDR from
    guests. Priority: (1) exact `static_cidr` from a VM's
    `ipconfigN gw=` or LXC's inline `ip=`/`gw=`; (2) /24 guess
    around guest-agent runtime IPs with a `proxmox_vnet_cidr_guessed`
    warning hinting at the `pvesh create` replacement. Solves
    the "PVE is L2 passthrough, gateway lives on upstream
    router" case where operators have many VNets with zero
    declared subnets. Migration `e5a72f14c890`.
  - Bridges + VLAN interfaces with a CIDR → Subnet (under
    enclosing operator block when present, else auto-created
    RFC 1918 / CGNAT supernet via the shared helper). Bridges
    without a CIDR skipped.
  - VM + LXC NICs → IPAddress with `status="proxmox-vm"` /
    `"proxmox-lxc"`, MAC from config. Runtime IP from QEMU
    guest-agent (when `agent=1` + agent running) or LXC
    `/interfaces`; falls back to `ipconfigN` static IP (VMs)
    or inline `ip=` (LXC); NIC silently skipped when nothing
    resolves. Link-local + loopback addresses filtered out.
  - Bridge gateway IP → `reserved` placeholder row per subnet.
  `mirror_vms` + `mirror_lxc` default **true** (PVE guests are
  long-lived, unlike Docker CI containers). **Discovery
  modal** — the reconciler writes a `last_discovery` JSONB
  snapshot on every successful sync (category counters + a
  per-guest list with single top-level `issue` code + operator-
  facing `hint`); admin page gets a magnifier-icon button per
  endpoint that opens a filterable Discovery modal showing
  agent-state pills + IPs-mirrored split + copy-ready fix
  hints like "install qemu-guest-agent inside the VM". Default
  filter is `Issues` so operators land on what needs attention.
  Migration `e7b3f29a1d6c`. Covered by 38 tests:
  `test_proxmox_client.py` (NIC + ipconfig + SDN-id parsing) +
  `test_proxmox_reconcile.py` (pipeline end-to-end, SDN
  subnet merge, VNet inference with both static-CIDR and
  runtime-IP paths, cascade delete). Migration
  `d1a8f3c704e9` (base) + `e5a72f14c890` (infer toggle) +
  `e7b3f29a1d6c` (discovery payload).
  **Deferred follow-ups:**
  - **Phase 2 per-cluster management surface** — VM / LXC
    start/stop/shutdown, console access, live migrate,
    snapshot, backup browser. Mirrors the Kubernetes /
    Docker Phase-3 pattern; needs websocket pipeline we
    don't have today.
  - **Pool / resource-tag awareness.** PVE has a "pool" object
    for grouping resources and an arbitrary tag system; neither
    surfaces in IPAM today. Low-effort to add as custom-field
    passthrough once an operator asks.
  - **Cluster-quorum alerting.** `/cluster/status` carries a
    `quorate` bool — wire that into the alerts framework so an
    HA cluster losing quorum pages operators.


- ✅ **Tailscale — Phase 1: device mirror.** Per-`TailscaleTenant`
  row, PAT token + tailnet name (default `-`), Fernet-encrypted
  at rest. 60 s default sync interval (Tailscale rate-limits
  `/api/v2` at 100 req/min, so 30 s floor is the same as the
  other integrations). The reconciler hits
  `GET /api/v2/tailnet/{tn}/devices?fields=all` and mirrors each
  device's `addresses[]` (both IPv4 in `100.64.0.0/10` and IPv6
  ULA in `fd7a:115c:a1e0::/48`) as IPAddress rows under the
  bound IPAM space. The CGNAT + IPv6-ULA blocks are
  auto-created on first sync — operator can override the CGNAT
  CIDR per tenant for non-default tailnets. Per-row shape:
  - `status="tailscale-node"`, hostname = device FQDN
    (`<host>.<tailnet>.ts.net`), MAC null (no L2 on the overlay).
  - `description` = `<os> <clientVersion> — <user>`.
  - `custom_fields` = `{os, client_version, user, tags,
    authorized, last_seen, expires, key_expiry_disabled,
    update_available, advertised_routes, enabled_routes,
    node_id}`.
  - Tailnet domain is auto-derived from the first device's FQDN
    (no separate config field; mirrors the uhld pattern).
  Read-only-ish: integration-owned status + the
  `user_modified_at` lock keep operator edits sticky across
  reconciles (same pattern as Proxmox / Docker / Kubernetes).
  Provenance via `tailscale_tenant_id` FK on
  `ip_address`/`ip_block`/`subnet` with `ON DELETE CASCADE`.
  Subnet-router routes (`enabledRoutes`) are stored in
  custom_fields today; promoting them to first-class IPBlock
  rows is a follow-up. Test Connection probe + Sync Now button
  in the admin page mirror the other integrations.


- ✅ **Tailscale — Phase 2: synthetic tailnet DNS surface.**
  Implemented as Option 2 from the original plan (synthetic
  `DNSZone` materialised by the reconciler). When a
  `TailscaleTenant` has `dns_group_id` bound, every reconcile
  pass derives `<tailnet>.ts.net` from the first device FQDN,
  upserts a `DNSZone` with `is_auto_generated=True` and
  `tailscale_tenant_id=<tenant>`, and materialises one A / AAAA
  `DNSRecord` per device address. Records also carry
  `auto_generated=True` + the tenant FK. **Read-only enforcement**:
  `update_zone` / `delete_zone` / record CRUD reject writes
  with 422 when `tailscale_tenant_id IS NOT NULL`; UI renders a
  "Tailscale (read-only)" badge near the zone title and disables
  the Edit / Delete / Add Record buttons; the per-record lock
  badge in the records table branches on `tailscale_tenant_id`
  to read "Tailscale" instead of "IPAM" for synthesised rows.
  **Diff semantics**: keyed on `(name, record_type, value)` —
  removed devices have their records deleted on the next sync;
  idempotent on stable input. **Conflict safety**: a pre-
  existing operator-managed zone with the same name is left
  untouched, with a `summary.warnings` entry that surfaces in
  the audit log. **Filtering**: expired-key devices skipped per
  Phase 1's `skip_expired` toggle; devices with no FQDN or
  foreign tailnet suffix are skipped without error. **Bonus**:
  because we land actual `DNSRecord` rows, the existing BIND9
  render path picks them up automatically — non-Tailscale LAN
  clients can resolve `<host>.<tailnet>.ts.net` through
  SpatiumDDI's managed BIND9 with no forwarder plumbing. TTL
  is 300 s (short by design — IP assignments shift after re-auth).
  Migration `e6f12b9a3c84_tailscale_phase2_dns`.

  **Deferred follow-ups:**
  - **Per-tenant zone-name override.** Today we use the auto-
    derived `<tailnet>.ts.net`. Some operators run Tailscale
    with a custom split-DNS arrangement and want the synthetic
    zone published under a different name (e.g.
    `tailnet.internal`). Adding a `synthetic_zone_name` column
    on `TailscaleTenant` (defaulting to null = derive) would
    cover that without much code.
  - **Subnet-router routes (`enabled_routes`) → first-class
    `IPBlock` rows.** Phase 1 stores them in `custom_fields`;
    promoting them to real IPBlocks (one per route, FK to
    tenant) would let the IPAM tree show "this CIDR is reachable
    via tailnet device X." Worthwhile if operators start
    advertising LAN subnets through Tailscale.
  - **BIND9 forwarder zone for `100.100.100.100`.** Optional
    alternative for operators who don't want SpatiumDDI's BIND9
    serving the records itself but DO want to forward `*.ts.net`
    queries through MagicDNS (which only listens on the local
    Tailscale daemon — works only if the BIND9 host is itself
    on Tailscale).


## Future ideas — categorised

### Discovery & network awareness

- ✅ **LLDP neighbour collection** — vendor-neutral via
  LLDP-MIB (IEEE 802.1AB) `lldpRemTable`. Per-device opt-in
  `poll_lldp` toggle (default on); polled as a 5th step after
  ARP / FDB in `app.tasks.snmp_poll.poll_device`.
  `network_neighbour` table keyed
  `(device_id, interface_id, remote_chassis_id, remote_port_id)`
  with absence-delete every poll so stale neighbours fall off
  cleanly. Captures remote chassis ID + port ID (with subtype
  decoding — MAC addresses formatted, interface names left
  raw), system name + description, port description, and a
  decoded capabilities bitmask (Bridge / Router / WLAN AP /
  Phone / Repeater / Other / Station / DocsisCableDevice).
  API: `GET /api/v1/network-devices/{id}/neighbours` with
  `sys_name` (ilike) / `chassis_id` / `interface_id` filters.
  Frontend: new "Neighbours" tab on the network device detail
  view, with vendor-aware enable hints (Cisco IOS / NX-OS,
  Junos, Arista EOS, ProCurve / Aruba, MikroTik RouterOS,
  OPNsense / pfSense) when no rows are present. Migration
  `b9e4d2a17c83_network_neighbour`. **Deferred:** CDP polling
  (Cisco-only — LLDP usually runs alongside on modern gear);
  topology graph rendering (the data is captured, the graph UI
  isn't built yet); IP cross-reference via
  `lldpRemManAddrTable`; per-port enrichment via
  `lldpLocPortIfIndex` to resolve LLDP's own port numbering to
  ifIndex (today the local port is recorded by SNMP-side
  ifIndex via the FDB / interface walk, not LLDP's local
  port-num index).

- ✅ **Switch-port mapping in the IP table (column-level).** The
  IPAM IP table now carries a "Network" column showing
  `<device> · <port> [VLAN N]` for the most-recent FDB hit on
  each IP's MAC, with a `+N more` badge + hover tooltip listing
  every (device, port, VLAN) tuple when the MAC is learned in
  multiple places (hypervisor host + VMs across access VLANs,
  trunk ports). Backed by a batched
  `GET /api/v1/ipam/subnets/{id}/network-context` endpoint that
  returns `{ip_address_id: NetworkContextEntry[]}` in one round
  trip — no N+1 fan-out per page-of-IPs. The per-IP detail
  modal's "Network" tab still works as the deep-dive surface.
  **Deferred follow-ups:**
  - Reverse "click MAC → all IPs on this port" drilldown
    starting from an interface row in the network detail page.
    Useful when an operator's looking at a switch port and
    wants to see "what's plugged in here?".
  - Per-user column show/hide (lives under the broader Saved
    Views work in UX polish below).
  - Filter input on the Network column (the column header has
    no filter today; operators can still filter via the device
    detail page's ARP/FDB tabs).

### Subnet planning & calculation tools

- ✅ **Built-in CIDR calculator** — utility page at `/tools/cidr`
  with sidebar nav under Tools. Pure client-side, no API. Accepts
  IPv4 or IPv6 (CIDR or bare address), renders network / netmask /
  wildcard / broadcast / first-last usable / total addresses /
  decimal + hex / binary breakdown (v4) and compressed +
  expanded forms (v6). Quick-paste preset buttons for the common
  RFC 1918 / CGNAT / ULA blocks. BigInt math throughout so v6
  prefixes work cleanly.

- ✅ **Subnet planner / "what-if" workspace** — `/ipam/plans`.
  Operator designs a multi-level CIDR hierarchy as a draggable
  tree (one root + nested children, arbitrary depth), saves it
  as a `SubnetPlan` row, validates against current state, then
  one-click applies — every block + subnet created in a single
  transaction. **Data model:** `subnet_plan(id, name,
  description, space_id, tree JSONB, applied_at,
  applied_resource_ids JSONB, created_by_user_id)`. Tree node
  shape: `{id, network, name, description, kind, existing_block_id?,
  dns_group_id?, dns_zone_id?, dhcp_server_group_id?,
  vlan_ref_id?, gateway?, children[]}`. **`kind` is explicit**
  per node (`block` or `subnet`) — root must be a block
  (subnets need a block parent), and a subnet may not have
  children (validation enforces both). **Resource bindings**
  (DNS group, DHCP group, gateway) are optional per-node;
  `null` = inherit, explicit value sets the field on the
  materialised row and flips the corresponding
  `*_inherit_settings=False`. UI exposes DNS group + DHCP
  group dropdowns + gateway field on subnets; VLAN + DNS-zone
  fields exist in the model but UI binding is deferred (VLAN
  is router-scoped — needs a flat list endpoint first). **Root
  modes:** new top-level CIDR (creates a fresh block at the
  space root) OR anchor to an existing `IPBlock` (descendants
  land as children of the existing block, root not re-created).
  **Validation** (`/plans/{id}/validate` + `/plans/validate-tree`
  for in-flight trees) checks duplicate node ids, kind rules,
  parent-containment of every child, sibling-overlap, and
  overlap against current IPAM state in the bound space.
  Auto-fires every 300 ms as the operator edits — conflicts
  surface inline as red ring on offending nodes + a banner
  above the tree. **Apply** opens a confirmation modal with
  block + subnet counts ("this will create N blocks + M
  subnets"), then re-validates inside the txn; any conflict
  → 409 with the full conflict list and nothing is written.
  Once applied, the plan flips read-only and
  `applied_resource_ids` records every created block + subnet
  for audit. **Reopen** (`/plans/{id}/reopen`) flips an
  applied plan back to draft state, but only if every
  materialised resource has been deleted from IPAM —
  otherwise 409 with the survivor list. Lets operators
  iterate on the same plan after a teardown rather than start
  fresh. **Frontend:** `@dnd-kit/core` (already a dep) for
  drag-to-reparent; drops onto descendants OR onto subnet
  targets are refused. Properties panel on the right edits
  CIDR / name / kind / DNS / DHCP / gateway for the selected
  node. Sidebar entry "Subnet Planner" alongside NAT
  Mappings. Migration `c8e1f04a932d_subnet_plan`.
  **Deferred:** sibling reordering via `@dnd-kit/sortable`
  (today reparenting only appends as last child); split-into-N
  action on a node; VLAN dropdown in the planner UI (model
  field exists; needs a flat VLAN list endpoint first); DNS
  zone selector that's gated on the chosen DNS group; per-node
  custom-fields / tags / status (those are per-IP and edited
  through normal IPAM use after apply).

- ✅ **Address planner** — `POST /api/v1/ipam/blocks/{id}/plan-
  allocation` accepts a list of `{count, prefix_len}` requests
  (e.g. `4 × /24, 2 × /26, 1 × /22`) and packs them into the
  block's free space using largest-prefix-first ordering with
  first-fit-by-address placement (so sequential same-size
  requests pack contiguously from low addresses rather than
  chasing small isolated free islands).
  Returns the planned allocations + any unfulfilled rows + the
  remaining free space after the plan. Reuses the same
  `address_exclude` walk that powers `/free-space`. UI: "Plan
  allocation…" button next to the Allocation map on the block
  detail; modal lets the operator add/remove rows and shows the
  packed result. Preview only — no writes — so the operator can
  iterate freely. **Deferred:** one-click apply that chains the
  preview into N `POST /subnets` calls inside a transaction.

- ✅ **Aggregation suggestion** — `GET /api/v1/ipam/blocks/{id}/
  aggregation-suggestions` runs `ipaddress.collapse_addresses` on
  the block's direct-child subnets; any output that subsumes more
  than one input is a clean merge opportunity (the inputs pack
  perfectly into a supernet with no gaps). Read-only banner on the
  block detail surfaces them when present (e.g. `10.0.0.0/24 +
  10.0.1.0/24 → /23`). **Deferred:** one-click merge flow — needs
  to handle the cascade across IP rows + DNS records owned by the
  deleted siblings, plus operator confirmation. Today operators
  see the suggestion and act manually (delete + recreate).

- ✅ **Free-space treemap** — Recharts squarified Treemap on the
  block detail, toggled via a Band / Treemap selector next to
  the Allocation map header (selection persisted in
  sessionStorage per block). Cells are coloured by kind (violet
  child blocks, blue subnets, hashed-zinc free) and sized by
  raw address count. Pixel-thin slices on the 1-D band become
  visible squares here, surfacing fragmentation that's easy to
  miss otherwise. Uses the existing `recharts` dep — no new
  packages added.


### DNS-specific

- ✅ **TSIG key management UI** — `DNSTSIGKey` model with
  Fernet-encrypted `secret_encrypted`, `algorithm` enum
  (hmac-sha1/224/256/384/512), `name`, `purpose`, `notes`, and
  `last_rotated_at`. CRUD lives at
  `/api/v1/dns/groups/{gid}/tsig-keys` with a side `/generate-secret`
  helper that returns a fresh random base64 secret of the right
  size for the chosen algorithm, and a `/{kid}/rotate` endpoint
  that re-randomises the secret. Plaintext is returned **once** on
  the create / rotate response — list / get never expose it.
  Operator-managed rows distribute to every BIND9 agent in the
  group via the existing `tsig_keys` block in the ConfigBundle
  (alongside the legacy auto-generated agent loopback key);
  named.conf renders one `key { algorithm …; secret …; };`
  stanza per row. UI: new "TSIG Keys" tab on the DNS server
  group view, with create / edit / rotate / delete plus a
  one-shot "Copy this secret now" modal after each
  create / rotate. These keys are attachable to a zone's
  dynamic-update ACL — see the **Dynamic-update (RFC 2136)
  ACLs** entry below (issue #641), which is the surface that
  wires a key into a zone's `allow-update` clause.
  Migration `7c299e8a5490_dns_tsig_keys`.
  **Deferred:** per-key audit-log of which zones reference it.

  > **Correction (issue #641):** earlier revisions of this entry
  > claimed operators "reference keys from a zone's allow-update /
  > allow-transfer fields as `key keyname.;`" and listed only a
  > dropdown picker as deferred. That was inaccurate — the zone
  > model never had an `allow-update` field, only `allow_query` /
  > `allow_transfer`, and nothing rendered `allow-update` from a
  > key reference. The real "last mile" (a per-zone dynamic-update
  > ACL that attaches these TSIG keys to `allow-update`) shipped
  > under issue #641; the dropdown picker landed there too.

- ✅ **Conditional forwarders** — per-zone forwarding for mixed-AD
  environments. `DNSZone` carries `forwarders` (JSONB list of IPs)
  + `forward_only` (true → `forward only;`, false → `forward
  first;`). When `zone_type = "forward"` the BIND9 driver renders
  `zone "X" { type forward; forward only; forwarders { ... }; }`
  in `zone.stanza.j2` and the agent's wire-format renderer
  (no zone file written, no allow-update); the form gates the
  forwarders/policy fields on `zone_type === "forward"` and
  refuses submit when no upstreams are listed. Migration
  `a07f6c12e5d3_dns_zone_forwarders`. **Deferred:** Windows DNS
  via `Add-DnsServerConditionalForwarderZone` (the field
  shape is identical; just needs the WinRM dispatch).

- ✅ **BIND9 catalog zones (RFC 9432)** — opt-in per group via
  `DNSServerGroup.catalog_zones_enabled` + `catalog_zone_name`
  (defaults to `catalog.spatium.invalid.`). The producer is the
  group's `is_primary=True` bind9 server; every other bind9
  member joins as a consumer. Bundle assembly emits a `catalog`
  block per server: `mode=producer` ships the member zone list,
  `mode=consumer` ships the producer's IP. The agent renders
  the catalog zone file per RFC 9432 §4.1 — SOA + NS at apex,
  `version IN TXT "2"`, and one `<sha1-of-wire-name>.zones IN
  PTR <member>` per primary zone — and on consumers injects a single
  `catalog-zones { zone "<catalog>." default-masters { <producer-ip>; } in-memory yes; };`
  directive into the options block. The catalog block is part of the structural
  ETag so membership changes trigger a daemon reload, and SHA-1
  hashing uses the proper wire format (length-prefixed labels +
  null terminator) so consumer BINDs find the same labels.
  Frontend toggle lives in the server-group create / edit
  modal alongside the recursion checkbox. Migration
  `d8e4a73f12c5_dns_catalog_zones`. **Deferred:** version-skew
  guard (refuse the toggle on groups with a server <9.18);
  visualising consumer pull state (today operators rely on
  the existing per-server zone-serial drift pill);
  per-member properties (epoch, change-of-ownership) — most
  homelab / SMB groups won't need them.

- ✅ **Response Policy Zones (RPZ)** — DNS-level malware / phishing
  / ad blocking via BIND9 `response-policy { zone … };`. Full
  `DNSBlockList` + `DNSBlockListEntry` + `DNSBlockListException`
  model with categories / source types (manual / url /
  file_upload) / block modes (nxdomain / sinkhole / refused) /
  per-list scheduled refresh. Service-side aggregation produces
  effective entries per server-group or view; agent renders one
  RPZ master zone per blocklist with CNAME-based actions
  (`. = NXDOMAIN`, `rpz-drop. = sinkhole`, target = redirect,
  `rpz-passthru. = exception). CRUD lives at
  `app/api/v1/dns/blocklist_router.py`. BIND9-only — Windows
  DNS has no RPZ equivalent (closest is Query Resolution
  Policies which lack the wire format).

- ✅ **Curated RPZ blocklist source catalog** — ships a static
  JSON catalog at `backend/app/data/dns_blocklist_catalog.json`
  with 14 well-known public blocklists drawn from AdGuard's
  HostlistsRegistry + Pi-hole defaults + Hagezi / OISD: AdGuard
  DNS Filter, StevenBlack Unified, OISD Small/Big, Hagezi Pro
  / Pro+, 1Hosts Lite, Phishing Army Extended, URLhaus,
  DigitalSide Threat-Intel, EasyPrivacy, plus StevenBlack
  fakenews / gambling / adult add-ons. Each entry carries
  `{id, name, description, category, feed_url, feed_format,
  license, homepage, recommended}`. `GET /dns/blocklists/catalog`
  returns the snapshot (cached in-process). `POST
  /dns/blocklists/from-catalog` creates a normal `DNSBlockList`
  row with `source_type="url"` prefilled — leverages the
  existing `parse_feed` + `_refresh_blocklist_feed_async` task
  for fetch / parse / ingest with no new beat task. Frontend
  has a "Browse Catalog" button on the Blocklists tab opening a
  filterable picker (category + free-text), with already-
  subscribed entries flagged. Catalog snapshot moves in
  lockstep with releases; operators can still add custom
  sources via the existing "New Blocking List" flow.
  **Deferred:** "Refresh catalog from upstream" button that
  re-fetches `filters.json` from HostlistsRegistry between
  releases.

- ✅ **DNS query analytics aggregation** — `POST
  /api/v1/logs/dns-queries/analytics` returns top-10 qnames +
  top-10 clients + complete qtype distribution in a single
  round trip. Computed on-demand via `GROUP BY` against the
  existing `dns_query_log_entry` rows (24 h retention) — no
  new schema, no new beat task. The Logs → DNS Queries tab
  renders an Analytics strip above the raw event grid: three
  cards each showing key + count + percentage of total, with
  every row clickable to seed the corresponding filter
  (qname / client_ip / qtype). The strip refetches only when
  `(server_id, since)` changes, so per-keystroke filter edits
  on the events grid don't pay for a re-aggregation.
  Deliberately mirrors the query log's retention window —
  longer history belongs in Loki, not Postgres. **Deferred:**
  rcode breakdown (BIND9's `query` log channel doesn't emit
  rcode; would need a parallel `client error` channel + parser);
  pre-aggregated `dns_query_aggregate` table with longer
  retention (only worth it if the on-demand `GROUP BY` becomes
  slow, which it won't for typical 24h windows).

- ✅ **Zone delegation wizard** — `services/dns/delegation.py` finds
  the longest-suffix-matching parent zone in the same group
  (forward zones excluded), reads the child's apex NS records,
  and computes the NS records the parent needs to delegate the
  child plus glue (A / AAAA) for any in-bailiwick NS hostnames.
  Diffs against existing parent records so a second run is a
  no-op, surfaces warnings ("ns1 is in-bailiwick but has no
  A/AAAA in child"), and applies through the normal
  `enqueue_record_op` pipeline so the parent zone's serial bumps
  once and the agent / Windows-driver push fires uniformly.
  Endpoints: `GET /dns/groups/{gid}/zones/{zid}/delegation-preview`
  + `POST /dns/groups/{gid}/zones/{zid}/delegate-from-parent`.
  Frontend: a contextual "Delegate" button appears in the zone
  header only when an eligible parent has missing records;
  `DelegationModal` shows the exact records that would land in
  the parent before commit, with skipped/already-present rows
  in a separate section.

- ✅ **DNS template wizards** — static catalog at
  `backend/app/data/dns_zone_templates.json` with four starter
  shapes (Email zone with MX + SPF + DMARC + optional DKIM
  selector, Active Directory zone with the standard LDAP /
  Kerberos / GC SRV records + optional `_sites` entries, Web
  zone with apex A + optional AAAA + `www CNAME`, Kubernetes
  external-dns target — empty zone). `services/dns/zone_templates.py`
  loads the catalog once per process, validates required
  parameters, and substitutes `{{key}}` placeholders (plus a
  built-in `{{__zone__}}`) at materialise time; records can
  declare `skip_if_empty: ["param"]` so optional fields drop
  out cleanly. Endpoints: `GET /dns/zone-templates` +
  `POST /dns/groups/{gid}/zones/from-template`. Frontend
  `ZoneTemplateModal` with a left-column category-grouped
  template list and a right-column parameter form; submitting
  creates the zone + every materialised record in one
  transaction and navigates straight into the zone detail.
  Mounted as a "From Template" button on the ZonesTab header,
  alongside "Add Zone".

- ✅ **Multi-resolver propagation check** — `POST
  /dns/tools/propagation-check` fires the same query against
  Cloudflare / Google / Quad9 / OpenDNS in parallel using
  `dnspython`'s `AsyncResolver` (each query carries its own
  timeout so a slow resolver can't poison the others) and
  returns per-resolver `{resolver, status, rtt_ms, answers,
  error}`. UI surfaces as a Radar button on each record row in
  the records table; modal lets the operator switch record
  type and re-check. Driver-agnostic — queries are made from
  the API process, doesn't touch the BIND9 / Windows drivers.
  **Deferred:** operator-customisable resolver list (today the
  curated set is hard-coded server-side; the API accepts an
  override but the UI doesn't yet expose it).

- ✅ **DNS pool with health monitoring (GSLB-lite)** — named
  pool of A / AAAA targets where one DNS name (e.g.
  `www.example.com`) returns one record per healthy + enabled
  member. Health checks (`tcp | http | https | icmp | none`)
  run on a per-pool interval, members flip in/out of the
  rendered record set as state changes; operator can also
  manually enable/disable members like a load-balancer pool.
  Driver-agnostic: pool members render as **regular A/AAAA
  records** in the bound zone (one per healthy + enabled
  member) via the normal `enqueue_record_op` pipeline, so
  BIND9 and Windows DNS render unchanged.

  **Data model** (migration `f5b1a8c3d927_dns_pool_healthcheck`):
  - `dns_pool(id, group_id, zone_id, name, description,
    record_name, record_type, ttl, enabled, hc_type,
    hc_target_port, hc_path, hc_method, hc_verify_tls,
    hc_expected_status_codes JSONB, hc_interval_seconds,
    hc_timeout_seconds, hc_unhealthy_threshold,
    hc_healthy_threshold, next_check_at, last_checked_at,
    created_at, modified_at)`. Unique on
    `(zone_id, record_name)`.
  - `dns_pool_member(id, pool_id, address, weight, enabled,
    last_check_state, last_check_at, last_check_error,
    consecutive_failures, consecutive_successes,
    created_at, modified_at)`. Operator-set `enabled=False`
    keeps the member out of the rendered set regardless of
    health.
  - `dns_record` gains a nullable `pool_member_id` FK with
    `ON DELETE CASCADE`. When set, the records-tab UI
    renders a violet "Pool" lock badge with a click-through
    to the Pools tab and disables the row's edit/delete
    buttons; record CRUD endpoints reject writes with 422.

  **Pipeline:**
  - `app.tasks.dns_pool_healthcheck.dispatch_due_pools` is
    a Celery beat tick (30 s) that queues
    `run_pool_check(pool_id)` for every pool whose
    `next_check_at <= now`. Per-pool task uses
    `SELECT FOR UPDATE SKIP LOCKED` so concurrent
    dispatches can't double-poll. Mirrors the
    `app.tasks.snmp_poll` shape.
  - `services/dns/pool_healthcheck.run_check` fires per
    member with the chosen check type. TCP =
    `asyncio.open_connection`, HTTP/HTTPS = `httpx`,
    ICMP = `asyncio.create_subprocess_exec` calling
    `/bin/ping` (Debian's `iputils-ping` ships
    `cap_net_raw+ep` so the non-root app user can fire ICMP
    without `CAP_NET_RAW` on the container — the API
    Dockerfile installs the package explicitly).
    `hc_type=none` always reports healthy (operator opted
    out of health checks but still wants the record-set
    semantics).
  - State transitions only after
    `consecutive_failures >= unhealthy_threshold` (or
    successes for recovery), so a single flapping check
    doesn't churn DNS records.
  - On state change, `services/dns/pool_apply.apply_pool_state`
    diffs current pool DNSRecords against desired (healthy
    + enabled members) and emits create / delete via
    `enqueue_record_op` — pool records ride the normal
    record pipeline (audit log, ETag bump, agent push).
  - Pool ops carry `rrset_action` on the record payload
    (`"add"` for create, `"delete_value"` for delete). The
    bind9 driver branches on this so multiple members share
    a single (name, rtype) RRset cleanly. Without it, the
    driver's default `dns.update.replace()` semantics would
    delete every existing RR at the name+type before adding
    the new one, silently clobbering siblings — for an N-
    member pool, only the most-recently-applied member
    would survive in BIND9's running zone. **Superseded but
    kept** by [#773](https://github.com/spatiumnorth/spatiumddi/issues/773):
    every agent-bound op now carries the complete desired
    `rrset`, which is what a current agent acts on. Pools
    were the only caller that ever set `rrset_action`
    correctly, and the field remains their fallback for an
    agent running an image older than that change.
  - Rename / type-change branch in `apply_pool_state`:
    when `record_name` or `record_type` shifts on an
    existing pool, emit a `delete_value` op for the old
    (name, type, value) and an `add` op for the new one
    on the same target_serial. Operator-edit of those
    fields actually moves the live records instead of
    leaving stale entries under the old labels.

  **HTTPS TLS validation toggle** — `hc_verify_tls` controls
  whether httpx verifies the server cert. Default off because
  internal pool members commonly ship self-signed certs; on
  for public-facing targets where a bad cert should itself be
  a signal (self-signed / expired / hostname mismatch all
  fail the check fast).

  **Operator UX:**
  - **Top-level "DNS Pools" sidebar item** under DNS — lands
    on `/dns/pools` showing every pool across every zone with
    pool name (clickable to navigate to its zone), FQDN,
    group, type, check config, health summary, TTL, last
    check. Create flow asks for group → zone first
    (`PickGroupZoneModal`) before launching the pool form.
  - **Per-zone "Pools" tab** on the zone detail page mirrors
    the Records tab — same `PoolModal` reused for create /
    edit. Pool members render with status dot (`healthy`
    green, `unhealthy` red, `unknown` gray pre-first-check,
    `disabled` zinc when operator-toggled), manual enable
    toggle, and live last-check error.
  - Records tab on the zone detail surfaces pool-managed
    rows with a violet "Pool" lock badge and an Info button
    that switches to the Pools tab.

  **Tradeoff (operator-facing warning in the UI):** TTL
  races. DNS is cached client-side; a member dropping out
  doesn't take effect until TTL expires, so this is **not**
  the same as a real L4/L7 load balancer — clients can
  still hit a dead box for up to `ttl` seconds. UI defaults
  TTL to 30 s with an inline note pointing operators at the
  LB-mapping roadmap item for real load balancing.

  **Permission gate** `manage_dns_pools` seeded into the
  existing "DNS Editor" role.

  **Deferred follow-ups:**
  - **Phase 2: delegate checks to a chosen DNS agent** so
    the probe originates from the same network vantage as
    the DNS server. Matters for split-horizon setups + when
    targets are on a private network the API process can't
    reach. Today checks fire from the API/worker container.
  - **Weighted record sets.** `dns_pool_member.weight` exists
    but isn't honoured on render — every healthy member gets
    one record. BIND9 supports per-record weight via the
    `dnsrps` plugin and Route 53 has weighted routing
    natively; would need driver-specific render paths.
  - **Geo / latency routing** — picking which subset of
    healthy members to return based on client IP or RTT.
    Real GSLB territory; would need view-aware record
    rendering plus a geo-IP database. Phase 5+.
  - **Per-pool / per-member metrics in dashboard** — the
    health-check engine has all the data; pairs with the
    existing dashboard timeseries work.
  - **Pre-aggregated health-event log** — today operator
    triage of "why did this member flap?" goes through the
    normal audit log entries from `enqueue_record_op`. A
    dedicated `dns_pool_event` table would let the UI render
    a per-member uptime timeline.


- ✅ **DNS server detail modal** — clickable server rows in
  the DNS group's Servers tab open a tabbed read-only
  inspector (`frontend/src/pages/dns/ServerDetailModal.tsx`).
  Surfaces everything we know about a server without
  requiring the operator to SSH in. Tabs (last three are
  bind9-only):
  - **Overview** — name, host:port, driver, role
    (primary / secondary), agent version, last heartbeat,
    JWT expiry, structural ETag (current vs. last-acked =
    drift indicator), health status dot. Includes a live
    `rndc status` panel showing daemon uptime + zone count
    + the same fields operators normally `ssh + rndc` for.
  - **Zones** — table of zones served by this server with
    per-zone serial + drift state pulled from
    `DNSServerZoneState`. Click-through to zone detail.
  - **Sync** — pending / in-flight / failed `DNSRecordOp`
    rows for this server. Lets operators triage stuck
    record pushes without trawling the audit log.
  - **Events** — last N audit-log rows scoped to this
    server (`resource_id` match).
  - **Logs** — filterable parsed BIND9 query log
    (`dns_query_log_entry`, 24 h retention) scoped to this
    server. qname / qtype / client IP filters + auto-refresh
    every 30 s. Reuses the existing `/logs/dns-queries`
    endpoint with `server_id` filter — no new schema.
  - **Stats** — query-rate Recharts time-series
    (queries_total / NOERROR / NXDOMAIN / SERVFAIL, per-
    second rate) over selectable 1h / 6h / 24h / 7d windows
    plus three rollup cards: top qnames, top clients, qtype
    distribution. Sources: `metricsApi.dnsTimeseries` (the
    same `dns_metric_sample` table the dashboard MVP uses)
    + `/logs/dns-queries/analytics`.
  - **Config** — file picker (named.conf + every rendered
    zone file) with monospace viewer + copy-to-clipboard.
    Driven by a new agent push pipeline (see below).

  **Backing endpoints**: `GET /api/v1/dns/servers/{sid}/{zone-state,pending-ops,recent-events,rendered-config,rndc-status}`.
  The first three are thin server-scoped projections of
  existing data; the last two read the new
  `dns_server_runtime_state` table populated by agent
  pushes (one row per server, idempotent overwrite).

  **Agent push pipeline** for Config + rndc:
  - `POST /api/v1/dns/agents/admin/rendered-config`: agent
    walks `state_dir/rendered/`, ships every text file's
    relative path + content (size-capped at 5k files,
    256 KB/file, 8 MB total). Fires after every successful
    structural reload + once on bootstrap-from-cache so the
    snapshot lands the moment the agent comes up.
  - `POST /api/v1/dns/agents/admin/rndc-status`: a new
    `RndcStatusPoller` thread shells out to
    `rndc -c <state_dir>/rndc.conf status` every 60 s ±3 s
    jitter and POSTs the stdout. Migration
    `c3e9a2b71f48_dns_server_runtime_state`.

  **Agent rndc credentials** are agent-owned (not the
  alpine package's `/etc/bind/rndc.key`, which lives in a
  dir `spatium` can't traverse). The container entrypoint
  generates a fresh keypair via `rndc-confgen` at
  `/var/lib/spatium-dns-agent/rndc.{key,conf}` on first
  boot, and the bind9 driver renders an explicit
  `controls { … keys { "spatium-rndc"; }; };` block in
  named.conf referencing the same key — both ends agree by
  construction, so `rndc reconfig` + the rndc-status push
  authenticate cleanly. Without this, BIND9's auto-
  generated controls channel uses an in-memory key that
  doesn't match the on-disk file (causing "bad auth"
  failures even when the file contents are byte-identical).

  Implementation deliberately landed as a modal (not a
  per-server page) because the seven tabs all fit
  comfortably and operators stay in the group context for
  comparing sibling servers side-by-side.

  **Deferred follow-ups:**
  - **Windows DNS Stats** — `Get-DnsServerStatistics` via
    WinRM driver method. Today the Stats tab is bind9-only;
    Windows servers don't get a Stats button.
  - **`/api/v1/dns/agents/admin/stats` push from BIND9
    statistics-channels** — could surface richer per-zone
    or per-qtype counters than the dashboard MVP carries,
    but the existing `dns_query_log_entry` analytics path
    already covers operator triage so this is a future-
    polish item, not a blocker.


### DHCP-specific

- ✅ **DHCP option library / templates** — `DHCPOptionTemplate`
  row, group-scoped, holds a named bundle of option-code → value
  pairs (e.g. "VoIP phones", "PXE BIOS clients"). CRUD at
  `/api/v1/dhcp/server-groups/{gid}/option-templates` +
  `/api/v1/dhcp/option-templates/{id}` plus a server-side
  `POST /scopes/{id}/apply-option-template` for programmatic
  apply (mode=`merge` template-wins, mode=`replace` drop-existing).
  UI: new "Option Templates" tab on the DHCP server-group view
  (mirrors the Client Classes / MAC Blocks tabs) with the
  shared `DHCPOptionsEditor` for authoring, plus an
  "Apply template…" picker above the options editor on the
  scope create / edit modal that does a client-side merge into
  the editor's local state (operator still hits Save to
  persist; conflict-key list surfaces inline). Apply is a
  stamp, not a binding — later template edits do not
  propagate back to scopes that already used it. Permission
  gate `dhcp_option_template`, seeded into the existing "DHCP
  Editor" role. Migration `e7f218ac4d9b_dhcp_option_templates`.
  **Deferred:** pool / static template-apply (scope only first),
  auto-apply default template on scope create, drift report
  showing which scopes diverged from a template after apply.

- ✅ **Option-code library lookup** — static catalog at
  `backend/app/data/dhcp_option_codes.json` covering 95 RFC
  2132 + IANA `bootp-dhcp-parameters` v4 entries operators
  actually configure (each entry: `code`, `name`, `kind`,
  `description`, `rfc`). Loaded once per process via
  `services/dhcp/option_codes.py` (lru_cache); `search()`
  helper does case-insensitive name/description matching with
  numeric-prefix code lookup. `GET /api/v1/dhcp/option-codes`
  returns the catalog (with optional `q=` substring filter
  + `limit`). Frontend wires it into `DHCPOptionsEditor`'s
  custom-options row: the bare numeric code input becomes a
  combobox that searches by code or name, surfaces the
  description as a hint under the row, and auto-fills `name`
  on pick. Catalog is fetched once per session
  (`staleTime: Infinity`) and filtered client-side, so
  per-keystroke search has no server round-trip.
  **Deferred:** v6 option-code catalog (separate namespace —
  ships once v6 UI lands).

- ✅ **Device profiling — Phase 1: active layer (auto-nmap on
  DHCP lease).** Subnet-level opt-in
  (`auto_profile_on_dhcp_lease` + `auto_profile_preset` +
  `auto_profile_refresh_days` on `Subnet`). When a fresh DHCP
  lease lands the lease-event handler calls
  `services/profiling/auto_profile.maybe_enqueue_for_lease`,
  which gates on three guards before dispatch: (1) the
  subnet's master toggle, (2) a per-(IP, MAC) refresh window
  read from `IPAddress.last_profiled_at` so churning Wi-Fi
  clients don't fan out, (3) a per-subnet concurrency cap of
  4 in-flight scans counted across the existing `NmapScan`
  queue (operator-driven scans count too — better to defer
  the next auto-profile than queue ahead of a human). Pass
  through the existing `app.tasks.nmap.run_scan_task` Celery
  pipeline; the runner finaliser at
  `services/nmap/runner.py` stamps `last_profiled_at` +
  `last_profile_scan_id` on completion and mirrors
  `summary_json["os"]["name"]` into `IPAddress.device_type`
  when the passive layer hasn't already set a more specific
  value.

  Operator endpoint `POST /api/v1/ipam/addresses/{id}/profile`
  exposes "Re-profile now" — bypasses the refresh-window
  dedupe, returns 429 when the per-subnet cap is hit. UI:
  `ProfilingSettingsSection` reused in the create + edit
  Subnet modals; the IP detail modal grew a "Device profile"
  section that surfaces the most recent scan's OS guess +
  top 8 open services with a deep-link to the full nmap row.
  Migration `d4f2a86c5b91_device_profiling_phase1`.

  **Image / cluster-side fix-ups (landed alongside Phase 1).**
  Operator-driven OS detection (`nmap -O`) and SYN scans need
  raw-socket privilege, which the non-root `app` user in the api
  + worker images doesn't have by default. We grant
  `cap_net_raw,cap_net_bind_service+eip` to `/usr/bin/nmap` via
  `setcap` in the runtime layer of `backend/Dockerfile`, then
  set `NMAP_PRIVILEGED=1` as a baked-in env var so Debian's nmap
  doesn't bail on its early `getuid()==0` check (which ignores
  file caps). The K8s side adds
  `securityContext.capabilities.add: ["NET_RAW"]` to the worker
  pod in `k8s/base/worker.yaml`; the Helm chart gates the same
  on `worker.netRawCapability` (default true). On permissive
  clusters this is a no-op (NET_RAW is in containerd's default
  cap set); on restricted PSA / OpenShift-SCC / GKE Autopilot
  it's required for the cap to actually reach the process.

  **Deferred:** block / space inheritance for `auto_profile_*`
  fields (Phase 1 is subnet-only — added once operators ask for
  cascade), per-subnet `auto_profile_on_snmp_discovery` toggle
  (depends on the still-pending SNMP discovery task), IPAM list
  column for `device_type` (operator show/hide).

- ✅ **Device profiling — Phase 2: passive DHCP fingerprinting
  + fingerbank.** The companion to Phase 1's active-layer
  auto-nmap. The DHCP agent's
  `DhcpFingerprintShipper` thread runs `scapy.AsyncSniffer` with
  the BPF filter `udp and (port 67 or port 68)`, extracts
  option-55 / option-60 / option-77 / option-61 from each
  DISCOVER + REQUEST, dedupes per-MAC at 1/min, and POSTs
  batches of up to 50 to `POST /api/v1/dhcp/agents/dhcp-fingerprints`
  every 10 s. Default off — operators flip
  `DHCP_FINGERPRINT_ENABLED=1` and add `cap_add: [NET_RAW]` in
  their compose override (the shipped `docker-compose.yml`
  doesn't grant the cap unconditionally because most installs
  don't need it).

  Control-plane side: new `dhcp_fingerprint` table
  (MAC-keyed, one row per device) with the raw signature plus
  cached fingerbank result. New
  `services/profiling/fingerbank.py` (async httpx client against
  `https://api.fingerbank.org/api/v2/combinations/interrogate`,
  7-day cache window, swallows 404 / 429 / 5xx / network errors
  to avoid breaking ingestion). New
  `app.tasks.dhcp_fingerprint.lookup_fingerprint_task` Celery
  task (idempotent + retry-3) does the slow lookup off the
  ingestion request path and stamps `IPAddress.device_type` /
  `device_class` / `device_manufacturer` on every matching
  IPAM row sharing the MAC — respecting the `user_modified_at`
  lock the integration reconcilers already use.
  Operators set the fingerbank API key in **Settings → IPAM
  → Device Profiling** (Fernet-encrypted at rest, password-
  style input with a "Configured ✓ Replace… Clear" view once
  set; the encrypted bytes never round-trip through the API
  response — `SettingsResponse` exposes only a boolean
  `fingerbank_api_key_set`). No key = passive collection
  still happens, enrichment doesn't.

  IPAM `IPAddressResponse` extended with the three device_*
  columns + a new `GET /api/v1/ipam/addresses/{id}/dhcp-fingerprint`
  endpoint returning the joined `dhcp_fingerprint` row by
  MAC. Migration `e5a3f17b2d8c_device_profiling_phase2`. New
  agent dep on scapy (>=2.5) + Alpine `libpcap` package; both
  are pure-python at install time, no compilation, multi-arch
  clean. Tests at `backend/tests/profiling/` +
  `agent/dhcp/tests/test_dhcp_fingerprint.py` (parser-only,
  scapy.importorskip so the suite still passes without the
  optional dep).
  **Deferred:** v6 DHCPv6 fingerprint capture (DHCPv6 has its
  own option-numbering namespace), Wi-Fi-roaming-aware MAC
  privacy randomisation handling (the per-MAC dedupe means
  randomised MACs each look like a fresh device — by design
  in Phase 2; revisit when MAC-hashing-aware grouping is
  scoped).

- ✅ **IPAM bulk allocate + table polish** (2026-04-30, post
  device profiling). Five-item polish wave on the IPAM IP table
  surface that landed alongside the device-profiling work.
  - **Bulk allocate.** New
    `POST /ipam/subnets/{id}/bulk-allocate/{preview,commit}`
    pair stamps a contiguous IP range plus a name template in
    one transaction. Template language: `{n}` iterator,
    `{n:03d}` zero-pad, `{n:x}` / `{n:X}` hex, `{oct1}`–
    `{oct4}` IPv4 octets — anything else literal. Capped at
    1024 IPs per call; preview returns counts plus a
    first-5/last-2 sample of rendered hostnames; commit runs
    under a `FOR UPDATE` subnet lock and applies per-row
    conflict detection (already-allocated, dynamic-DHCP-pool
    membership, hostname+zone collisions including
    within-batch duplicates). `on_collision: skip | abort`
    chooses whether conflicts skip or refuse the whole batch.
    Per-row audit + one summary `bulk_allocate` audit at the
    subnet level. `BulkAllocateModal` lives first in the IPAM
    Tools dropdown (alphabetical) with a three-phase form →
    preview → committed flow and a live client-side template
    preview that mirrors the backend `_BULK_TEMPLATE_RE` regex
    so the operator sees rendered hostnames as they type.
  - **IPAM Tools dropdown.** Subnet header collapsed from 9
    buttons to 6 by folding Resize / Split / Merge / Clean
    Orphans + the new "Scan with nmap" + "Bulk allocate…" into
    one `[Tools ▾]` menu (alphabetised). Standard IPAM-style
    outside-click handler; mirrors the existing `[Sync ▾]` and
    `[Import / Export ▾]` patterns.
  - **"Seen" recency column.** New `SeenDot` component renders
    a 4-state coloured dot derived from
    `IPAddress.last_seen_at`: alive (<24h) green, stale
    (24h–7d) amber, cold (>7d) red, never grey. Source method
    (`via dhcp` / `via nmap` / `via snmp` / `via arp` / etc.)
    sits in the tooltip. Orthogonal to lifecycle status — an
    `allocated` IP can be down, a `discovered` IP can be live.
    Same dot also sits next to the status pill in
    `IPDetailModal`. Companion: `discovered` added to
    `IP_STATUSES_INTEGRATION_OWNED` so `Stamp alive hosts →
    IPAM` writes integration-owned rows the operator can
    transition by editing.
  - **Sticky thead, finally.** The IP table's `<thead>` is
    `sticky top-0 bg-card` so column headers stay visible
    while scrolling long IP lists. The earlier landing
    silently failed in Chrome because an inner
    `<div className="overflow-x-auto">` wrapper around the
    `<table>` was establishing a Y-scroll context per CSS
    spec (`overflow-x: auto` with `overflow-y: visible`
    computes to `overflow-y: auto` automatically), which
    anchored the head's sticky context to a non-scrolling
    intermediate parent. Removed the wrapper so sticky
    resolves to the outer `flex-1 overflow-auto` scroll
    container; horizontal overflow now happens at that level
    too (the table's `min-w-[640px]` still triggers x-scroll
    on narrow viewports).
  - **Shift-click range select on IP checkboxes.** `onChange`
    doesn't carry `shiftKey` so we stash the modifier state in
    `onClick` (which fires first) plus the previously-clicked
    id, then the change handler walks the IP-only ordered list
    from `tableRows` (display order — survives sort changes)
    between the two endpoints and toggles every selectable row
    to the new state. Standard Gmail-style multi-select.
  - **Free-IP gap markers.** New `kind: "gap"` row variant
    rendered as a slim half-height row with a dashed emerald
    border (`192.168.0.11 · 1 free` for single-IP gaps,
    `.11 – .13 · 3 free` for ranges). Inserted between
    non-adjacent IP rows during the same build loop that
    interleaves DHCP pool boundary markers. Suppressed when a
    pool boundary just got emitted (the boundary already shows
    the discontinuity) and when the gap falls fully inside a
    dynamic DHCP pool (those slots are owned by the DHCP
    server, not operator-allocatable). Heads-up for "you
    deleted something and might have missed the hole" — easy
    to miss otherwise.

  **Two debug fixes caught during testing:** (1) The
  module-level `_BULK_ALLOWED_STATUSES` constant collided with
  the existing subnet-bulk-edit name; Python's silent rebind
  meant the IPAddress-status validator was reading the subnet
  status set (`active / deprecated / quarantine / reserved`)
  at request time. Renamed the new one to
  `_BULK_ALLOC_ALLOWED_STATUSES`. (2) `BulkAllocateRequest.tags`
  was originally typed `list[str]` but `IPAddress.tags` is a
  JSONB **dict** (matching the rest of IPAM); 11 bulk-allocated
  rows landed with `tags=[]` and broke `GET /addresses`
  response validation for the whole subnet. Schema corrected to
  `dict[str, Any]` (frontend type `Record<string, unknown>`),
  broken rows repaired with
  `UPDATE ip_address SET tags = '{}'::jsonb WHERE jsonb_typeof(tags) = 'array'`.

- ✅ **PXE / iPXE provisioning profiles** (issue #51). New
  `pxe_profile` table — operator-curated profiles per
  architecture (`bios_x86` / `efi_x86_64` / `efi_arm64` /
  `efi_x86`). Each profile binds to a TFTP `next-server` + a
  `boot-filename` per arch, plus an optional iPXE script body.
  `DHCPScope.pxe_profile_id` SET-NULL FK; on render, the Kea
  driver emits one `client-class` per arch-match guarded by
  `option dhcp.user-class` matching the iPXE signature so
  legacy PXE clients see the BIOS bootfile and iPXE clients
  see the iPXE script. New `/dhcp/groups/{id}/pxe` admin page
  with profile CRUD and a per-scope "PXE profile" picker on
  the scope editor.

### Security & compliance

- ✅ **Audit-log tamper detection** (issue #73). Append-only
  hash chain over the ``audit_log`` table: every row carries a
  ``row_hash = sha256(prev_hash || canonical_json(row))``
  computed in the SQLAlchemy ``before_flush`` event listener
  inside a Postgres transaction-scoped advisory lock (so
  concurrent inserts can't fork the chain). A nightly
  Celery task ``verify_chain`` walks the table in ``seq``
  order, recomputes each hash, and surfaces breaks as
  ``prev_hash_mismatch`` (insert / delete / hash rewrite) or
  ``row_hash_mismatch`` (content edit on the row). 2026.05.14-1
  fixed a defaults-vs-flush ordering bug where the listener
  was hashing ``id=None`` + ``timestamp=None`` because both
  columns' SQLAlchemy defaults fire AFTER ``before_flush`` —
  the runtime hash never matched what Postgres later stored,
  so the verifier reported tampering on every row. Fix
  pre-populates both defaults before hashing; one-shot data
  migration ``d4f8c91a2e35_audit_chain_repair`` re-hashed
  every existing row in ``seq`` order with the now-correct
  values so post-upgrade ``verify_chain`` reports
  ``ok=True``. Operator-visible columns (action, user,
  timestamp, old/new value, …) preserved verbatim — only
  the chain fields the verifier owns were rewritten.

- ✅ **TOTP MFA for local users** (issue #69). New
  `user_mfa_secret` table with Fernet-encrypted TOTP shared
  secret + backup-codes JSONB list. Enrolment flow: Settings
  → Security → "Enable MFA" → scan QR (`pyotp` + `qrcode`
  libraries) → enter 6-digit code to confirm → backup codes
  shown once. Login flow gains a second step when MFA is
  enabled — JWT pre-token issued on username+password,
  exchanged for full token after TOTP code or backup code
  accepted. Backup codes are single-use and persisted hashed.
  Admin can force-disable MFA per user (audit-logged).

- ✅ **API-token scopes** (issue #74). `api_token` rows gain
  a `scopes` JSONB column listing the resource_types the
  token is allowed to touch (vs. inheriting all of the user's
  permissions). Scope set is permission-name granularity
  (`subnet:read`, `subnet:admin`, `*` for full inheritance).
  Token create modal lets the operator pick scopes via a
  chip selector grouped by resource family. Authorization
  enforces scope intersection: token can do at most what the
  scope set allows AND what the user has permission for.

- ✅ **Subnet classification tags** (issue #75).
  `subnet.pci_scope`, `subnet.hipaa_scope`,
  `subnet.internet_facing` first-class boolean columns,
  each individually indexed (partial index `WHERE col =
  true`) so the auditor's "show me every PCI subnet"
  filter hits an index without competing. List filters
  across the IPAM page + the API. Compliance dashboard at
  `/admin/compliance` shows the three buckets side-by-side.
  Feeds the compliance-change alert rule (#105) and
  conformity policy filters (#106). Inheritance through
  the IP block tree is intentionally not implemented today
  — flags live on the subnet row only; revisit when block
  / space-level classification is needed.

- ✅ **Compliance change alerts** (issue #105). New
  `compliance_change` rule type plus three disabled seed
  rules covering each classification flag. Migration
  `e3f1c92a4d68` adds three columns to `alert_rule`:
  `classification` (one of `pci_scope` / `hipaa_scope` /
  `internet_facing`), `change_scope` (one of `any_change`
  / `create` / `delete`), and `last_scanned_audit_at`
  watermark. The evaluator scans `audit_log` on the
  existing 60 s alert tick, opens one event per mutation
  against a classification-flagged subnet (or descendant
  IP / DHCP scope via the subnet FK), and auto-resolves
  after 24 h. Watermark baselines to `now()` on first run
  so historical audit rows don't retro-page operators.
  Resource resolution falls back to
  `audit_log.old_value.subnet_id` for delete actions
  where the live row no longer exists. Per-pass scan
  capped at 1000 audit rows so a long-disabled rule
  flipping on doesn't pause the evaluator. Frontend
  `AlertsPage` rule-type picker + form gain a Compliance
  optgroup with classification + change-scope fields.

- ✅ **Conformity evaluations + auditor PDF export**
  (issue #106). Companion to the reactive #105 alerts:
  declarative `ConformityPolicy` rows pin a `check_kind`
  against a target set; a beat-driven engine ticks every
  60 s and runs every enabled policy on its
  `eval_interval_hours` cadence (default 24 h). On-demand
  re-evaluation via `POST /conformity/policies/{id}/
  evaluate`. Migration `b5d8a3f12c91` creates
  `conformity_policy` (declarative check definitions) and
  `conformity_result` (append-only history, indexed twice
  on `(policy_id, evaluated_at)` and `(resource_kind,
  resource_id, evaluated_at)` so both natural drilldowns
  hit an index). Six starter `check_kind` evaluators ship
  in `services/conformity/checks.py`: `has_field`,
  `in_separate_vrf`, `no_open_ports` (warn-not-fail when
  no recent scan), `alert_rule_covers`,
  `last_seen_within`, `audit_log_immutable`. Eight
  disabled seed policies span PCI-DSS / HIPAA / SOC2.
  Built-in rows accept narrow updates only (enabled /
  interval / severity / fail_alert_rule_id / description)
  — clone first to author a variant. `pass→fail`
  transitions emit `AlertEvent` rows against the policy's
  wired alert rule (when set) so conformity drift surfaces
  in the existing alerts dashboard. Synchronous
  `reportlab`-based PDF export at `/conformity/
  export.pdf` with per-framework section, failing-row
  enumeration with diagnostic JSON, SHA-256 integrity
  hash over `(result_id, status)` tuples in the trailer.
  New `conformity` permission resource type plus two new
  built-in roles (Auditor + Compliance Editor). Frontend
  `/admin/conformity` page + Platform Insights conformity
  card.

### UX polish

- ✅ **API docs link in sidebar + header** (issue #96).
  Surface the existing Swagger UI / ReDoc at `/docs` and
  `/redoc` from the navigation itself instead of expecting
  operators to know the URL. New "API Docs" entry under Help
  in the sidebar; new external-link icon in the header next
  to the user menu.


## Moved from CLAUDE.md (13 Nov 2026)

CLAUDE.md is loaded into every Claude Code session, so the historical narrative and the full bodies of shipped roadmap items were moved here, verbatim. CLAUDE.md keeps a one-line summary of each shipped item and links to its heading below (`#issue-NNN`).

### Repo Layout notes (moved from CLAUDE.md)

<a id="repo-layout-notes"></a>

> **Documentation sites (`/docs`).** The Jekyll docs in `docs/` are **documentation only** ([#1070](https://github.com/spatiumnorth/spatiumddi/issues/1070)): `index.md` is the documentation index, every page uses the one `default` layout, and there is no hero, feature grid, screenshot gallery or install pitch — the product / company site is a separate project, and a link to it will be added to the nav once it exists. Do not reintroduce product copy here. The site is served from **two** GitHub Pages sites, and it matters which one you are looking at:
>
> | URL | Pages site type | Source | Tracks |
> |---|---|---|---|
> | `www.spatiumddi.com` | organization site | repo `spatiumnorth/spatiumnorth.github.io` | **`main`** (published by CI) |
> | `www.spatiumddi.com/spatiumddi/` | project site | this repo, `main` branch, `/docs` path | **`main`** |
>
> The custom domain `www.spatiumddi.com` is configured on the **org-site repo** (its `CNAME` file), which is why *both* URLs live under it — setting a custom domain on an organization site moves its project sites too. The repo must be named `spatiumnorth.github.io` — matching the org — because that name is what makes GitHub serve it as the org site at all; the domain sits on top. `spatiumnorth.github.io` 301s to the custom domain. **Never add a `CNAME` to `docs/`** — it would be mirrored to the site repo *and* applied to the project site, pointing the domain at the wrong one; `docs-publish.yml` excludes `CNAME` from its `rsync --delete` so the real one survives releases. There is **no `gh-pages` branch** — both sites build from a `/docs` path, and the project site needs no workflow at all. The org-root site exists because GitHub only ever serves an org's root Pages site from a repo named `<org>.github.io`; that repo holds **no sources of its own** and is mirrored from `docs/` by `.github/workflows/docs-publish.yml` on every `main` push (auth: the `DOCS_DEPLOY_KEY` secret, an SSH deploy key with write access to the site repo — `GITHUB_TOKEN` cannot push cross-repo). Never hand-edit the site repo; the next publish overwrites it. Both sites therefore serve the same content; the root is the canonical one, and the one the README badge, `docs/sitemap.xml` and `docs/robots.txt` advertise. The root was originally release-pinned, but that let a docs fix sit unpublished behind the release cadence — the wrong trade for documentation, so it now publishes on every `main` push. It no longer republishes on release tags (#1226): a tag on an older commit rolled the site back behind `main`, and a tag off `main` published unreviewed docs. `docs/_config.yml` deliberately sets **no `baseurl`**, and none should be added: GitHub Pages injects the correct one per build (empty for the org site, `/spatiumddi` for the project site), and hardcoding either value overrides that and breaks the other site. The layouts in `docs/_layouts/` address assets by a **relative prefix** computed from page depth rather than by `baseurl`, because baseurl is empty for a local `jekyll build` — that is what makes the site previewable before publishing. See [#751](https://github.com/spatiumnorth/spatiumddi/issues/751).

> **Marketing website.** The company / product site is being built as a **completely separate project**, outside this repository; the docs site above carries none of it (#1070 removed the landing page that used to stand in for it). `www.spatiumddi.com` — the domain this note originally earmarked for it — serves the **docs**, so the marketing site needs either a different hostname or a decision to move the docs to `docs.spatiumddi.com` and give it the apex. Should its source ever land in this monorepo, `website/` is the reserved location. Cloudflare Pages can build it straight from `website/` in this monorepo, needing no second repo and no cross-repo sync. Tracked in [#754](https://github.com/spatiumnorth/spatiumddi/issues/754). When editing the marketing site, leave the Jekyll docs alone; when editing the Jekyll docs, leave the marketing site alone. Both can ship in the same PR but never as the same artifact. Open questions: which static-site generator to lock in (raw HTML / Astro / Next.js static), whether to mirror the README screenshots / feature table here, and the CI pipeline (separate workflow that builds + publishes to a `marketing` branch / Cloudflare Pages on every `website/**` change). See `website/README.md` (once it lands) for the deployment recipe.

### Historical narrative sections

<a id="auth-waves"></a>
#### Auth waves A–D (landed after `2026.04.16-2`)

**Wave A — external auth providers.** GUI-configured LDAP / OIDC / SAML replacing the old env-var stubs.
- `AuthProvider` + `AuthGroupMapping` tables; Fernet-encrypted secrets (`backend/app/core/crypto.py`).
- Admin CRUD at `/api/v1/auth-providers` with per-type structured forms.
- **LDAP** — `ldap3`-based auth in `backend/app/core/auth/ldap.py`; wired into `/auth/login` as a password-grant fallthrough.
- **OIDC** — authorize / callback redirect flow with signed state+nonce cookie, discovery + JWKS caching, `authlib.jose` ID-token validation; login page lists enabled providers as "Sign in with …" buttons.
- **SAML** — `python3-saml` SP-side flow with HTTP-Redirect AuthnRequest, ACS POST binding, SP-metadata endpoint.
- Unified user sync at `backend/app/core/auth/user_sync.py`: creates/updates Users, replaces group membership with mapped groups, **rejects logins with no mapping match**.

**Wave B — RADIUS + TACACS+.** `pyrad` and `tacacs_plus` drivers added; share the same password-grant fallthrough as LDAP via `PASSWORD_PROVIDER_TYPES`. Admin test-connection probe for each.

**Backup servers for LDAP / RADIUS / TACACS+.** Each password provider's config now accepts an optional list of backup hosts (`config.backup_hosts` for LDAP, `config.backup_servers` for RADIUS/TACACS+). Each entry is `host` or `host:port`. LDAP uses `ldap3.ServerPool(pool_strategy=FIRST, active=True, exhaust=True)`; RADIUS and TACACS+ iterate the primary then backups manually, failing over on timeout / network error and stopping on any definitive auth answer. All backups share the primary's shared secret and timeout settings.

**Wave C — group-based RBAC enforcement.** Permission model (`{action, resource_type, resource_id?}`) with wildcard support; `user_has_permission()` / `require_permission()` / `require_any_permission()` / `require_resource_permission()` helpers in `backend/app/core/permissions.py`. Five builtin roles seeded at startup (Superadmin, Viewer, IPAM / DNS / DHCP Editor). `/api/v1/roles` CRUD + expanded `/api/v1/groups` CRUD with role/user assignment. Router-level gates applied across IPAM / DNS / DHCP / VLANs / custom-fields / settings / audit. Superadmin always bypasses. `RolesPage` + `GroupsPage` admin UI. See `docs/PERMISSIONS.md`.

**Wave D — UX polish + partial IPv6.**
- Per-field opt-in toggles on bulk-edit IPs (status/description/tags/CF/DNS zone individually) plus a "replace all tags" mode.
- `EditSubnetModal` + `EditBlockModal` now show inherited custom-field values as HTML `placeholder` with "inherited from block/space `<name>`" badges; `/api/v1/ipam/blocks/{id}/effective-fields` added for parity with the subnet endpoint.
- Mobile responsive — sidebar becomes a drawer on `<md` with backdrop, `Header` hamburger toggle, 10+ data tables wrapped in `overflow-x-auto` with `min-w`, all modals sized `max-w-[95vw]` on `<sm`.
- IPv6 partial — `DHCPScope.address_family` column + Kea driver `Dhcp6` branch; subnet create skips the v6 broadcast row; `_sync_dns_record` emits AAAA + PTR in `ip6.arpa`; `/next-address` returns 409 on v6 (EUI-64/hash allocation is a future enhancement). Dhcp6 option-name translation now lands in `backend/app/drivers/dhcp/kea.py` via `_KEA_OPTION_NAMES_V6` + `_DHCP4_ONLY_OPTION_NAMES`; v4-only options (`routers`, `broadcast-address`, `mtu`, `time-offset`, `domain-name`, tftp-*) are dropped from v6 scopes with a warning log.

<a id="ipam-polish"></a>
#### IPAM polish (shipped alongside the waves)

- **Block overlap validation** — `_assert_no_block_overlap` rejects same-level duplicates and CIDR overlaps in `create_block` + the reparent path in `update_block`.
- **Scheduled IPAM ↔ DNS auto-sync** — opt-in Celery beat task `app.tasks.ipam_dns_sync.auto_sync_ipam_dns`. Beat fires every 60 s; the task itself gates on `PlatformSettings.dns_auto_sync_enabled` + `dns_auto_sync_interval_minutes`, so cadence changes in the UI take effect without restarting beat. Optionally deletes stale auto-generated records.
- **Shared `ZoneOptions` dropdown** (`frontend/src/pages/ipam/IPAMPage.tsx`) — renders primary zone first, `<optgroup label="Additional zones">` below; applied in Create / Edit / Bulk-edit IP modals. Zone picker is restricted to the subnet's explicit primary + additional zones when any are pinned.
- **Bulk-edit DNS zone** — new `dns_zone_id` field on `IPAddressBulkChanges`; each selected IP routes through `_sync_dns_record` for move / create / delete.

<a id="landings-20260419"></a>
#### 2026.04.19-1 landings (performance, polish, visibility)

- **Batched WinRM dispatch.** `apply_record_changes` on DNSDriver + `apply_reservations` / `remove_reservations` / `apply_exclusions` on DHCPDriver. Windows drivers override with real batching: DNS at `_WINRM_BATCH_SIZE = 6` ops/chunk (ceiling given `pywinrm.run_ps` encodes UTF-16-LE + base64 through `powershell -EncodedCommand` as a single 8191-char CMD.EXE line; see comment in `drivers/dns/windows.py`), DHCP at `_WINRM_BATCH_SIZE = 30`. Each chunk ships a compact data-only JSON payload + one shared PS wrapper with per-op try/catch. BIND9 / Kea inherit the batch interface via the default loop impls. 40-record Sync DNS went from ~3 min to ~5 s.
- **Logs surface.** New `/logs` page and `api/v1/logs/router.py`. Four tabs:
  - **Event Log** — `POST /logs/query` runs `Get-WinEvent -FilterHashtable` server-side via `app/drivers/windows_events.py`. Drivers expose inventory through `available_log_names()` + `get_events()`: `WindowsDNSDriver` returns `DNS Server` + `Microsoft-Windows-DNSServer/Audit`; `WindowsDHCPReadOnlyDriver` returns `Operational` + `FilterNotifications`. Filters keyed into React Query so tab entry + filter changes auto-fetch; Refresh button calls `refetch()`.
  - **DHCP audit** — `POST /logs/dhcp-audit` reads `C:\Windows\System32\dhcp\DhcpSrvLog-<Day>.log` over WinRM via `app/drivers/windows_dhcp_audit.py`. UTF-16 + ASCII both handled. Event-code → human label map; unknown codes come through as `Code <n>`.
  - **DNS Queries** *(landed post-2026.04.24)* — BIND9 query log surfaced via the agent push pipeline. The DNS agent's `QueryLogShipper` thread tails `/var/log/named/queries.log` (template-rendered when `DNSServerOptions.query_log_enabled`), batches up to 200 lines / 5 s and POSTs to `POST /api/v1/dns/agents/query-log-entries`. Lines are parsed into `dns_query_log_entry` rows (timestamp / client IP+port / qname / qclass / qtype / flags / view + raw original) by `app/services/logs/bind9_parser.py`; UI reads via `POST /logs/dns-queries` with substring / qtype / client-IP / since / max filters. 24 h retention via `prune_log_entries` Celery task — query logs are operator triage, not analytics; longer history belongs in Loki.
  - **DHCP Activity** *(landed post-2026.04.24)* — Kea DHCPv4 activity surfaced the same way. `render_kea` adds a file `output_options` (`/var/log/kea/kea-dhcp4.log`, in-process rotation `maxsize=50MB / maxver=5 / flush=true`) alongside the existing `stdout` output so `docker logs` keeps working. `LogShipper` thread → `POST /api/v1/dhcp/agents/log-entries` → `kea_parser.py` → `dhcp_log_entry` rows (severity / Kea log code / MAC / IP / transaction id + raw). UI filters: severity, log code, MAC, IP, since, raw substring. `GET /logs/agent-sources` lists `bind9` DNS + `kea` DHCP servers. Migration `d8c5f12a47b9_query_log_entries`.
- **IPAM subnet + block resize.** Grow-only. Preview + commit endpoints at `/ipam/subnets/{id}/resize/{preview,commit}` and `/ipam/blocks/{id}/...`. Preview returns blast-radius summary + `conflicts[]`; commit requires typed-CIDR confirmation + holds a pg advisory lock + re-runs every validation pre-mutation. Default-named network/broadcast placeholder rows recreated at new boundaries; renamed/DNS-bearing rows preserved. Cross-subtree overlap scan (not just siblings). `ResizeSubnetModal` / `ResizeBlockModal` in frontend.
- **Subnet-scoped IP address import.** `POST /ipam/import/addresses/{preview,commit}`. Parser auto-routes CSV / JSON / XLSX rows (`address`/`ip` → addresses, `network` → subnets); unrecognised columns drop into `custom_fields`. Validates each IP against the subnet CIDR. `AddressImportModal` + combined `Import / Export` dropdown on the subnet header.
- **DHCP pool awareness in IPAM.**
  - `_load_dynamic_pool_ranges` + `_ip_int_in_dynamic_pool` helpers in `backend/app/api/v1/ipam/router.py`. `create_address` returns 422 when `body.address` lands inside a dynamic pool (excluded/reserved pools still allow manual allocation). `_pick_next_available_ip` hoisted from `allocate_next_ip` so both the commit path and the new `GET /ipam/subnets/{id}/next-ip-preview` share the same dynamic-skip semantics.
  - Frontend `tableRows` interleaves ▼ start / ▲ end pool boundary rows with IP rows (dynamic cyan, reserved violet, excluded zinc). `AddAddressModal` "next" mode shows the preview IP inline; manual mode warns + disables submit when the typed IP hits a dynamic range.
- **IP assignment collision warnings.** `_normalize_mac` + `_check_ip_collisions` helpers + `force: bool = False` on `IPAddressCreate` / `IPAddressUpdate` / `NextIPRequest`. 409 with `{warnings, requires_confirmation}` when not forced. Update path uses `model_dump(exclude_unset=True)` so unchanged rows don't surface pre-existing collisions. Shared `CollisionWarning` + `CollisionWarningBanner` in `IPAMPage.tsx`; submit button flips to "Allocate anyway" / "Save anyway" on collision.
- **DHCP stale-lease absence-delete.** `pull_leases` now finds every active `DHCPLease` for this server whose IP wasn't in the wire response and deletes both the lease row and its `auto_from_lease=True` IPAM mirror. `PullLeasesResult` / `SyncLeasesResponse` / scheduled-task audit rows gain `removed` + `ipam_revoked` counters. The time-based `dhcp_lease_cleanup` sweep still handles between-poll expiry.
- **Sync menu + DHCP sync modals.** Replaces the standalone "Sync DNS" button on the subnet detail with a `[Sync ▾]` dropdown (DNS / DHCP / All). `DhcpSyncModal` fans out `POST /dhcp/servers/{id}/sync-leases` across every unique server backing a scope in the subnet, shows per-server counters. `SyncAllModal` combines DHCP results + DNS drift summary in one modal with a "Review DNS changes…" button that chains into the existing `DnsSyncModal`.
- **Refresh buttons** on DNS zone records, IPAM subnet detail, and the VLANs sidebar — each invalidates every relevant React Query key.
- **Dashboard rewrite.** Six KPI cards + **Subnet Utilization Heatmap** (every managed subnet = one grid cell coloured by utilization, click-through to IPAM) + Top Subnets + Live Activity feed (15 s auto-refresh, action-family colour coding) + DNS/DHCP service panel. **Time-series panels landed post-release** (2026-04-22 metrics MVP) — two Recharts cards under the activity row render DNS query rate + DHCP traffic from agent-driven `metric_sample` tables.
- **Draggable modals.** Seven per-page `function Modal({...})` copies collapsed into a single `<Modal>` at `frontend/src/components/ui/modal.tsx` + `use-draggable-modal.ts` (utility split out so Vite fast-refresh doesn't warn on mixed exports). Title bar is a drag handle; backdrop is `bg-black/20` so the page behind stays readable; Esc closes. Custom modal shapes (header with border-b + footer slot) use `useDraggableModal(onClose)` + `MODAL_BACKDROP_CLS` directly. Migrated across admin, DNS, DHCP, VLANs, IPAM + `ResizeModals` + `ImportExportModals` + inline `DnsSyncModal`.
- **Standardised header buttons.** `<HeaderButton>` primitive with three variants (`secondary` / `primary` / `destructive`) on a shared `inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm` base. Logical left→right ordering applied everywhere: `[Refresh] [Sync …] [Import] [Export] [misc reads] [Edit] [Resize] [Delete] [+ Primary]`. DNS / DHCP / VLANs were smaller (`text-xs`); all bumped to match IPAM's dominant size.

<a id="landings-20260420"></a>
#### 2026.04.20 roadmap completions

Phase 1 IPv6 closure + the Phase 2/3 DDNS / zone-state / CI-hardening items all landed in this window.

- **Full IPv6 `/next-address`** — EUI-64 + random /128 + sequential modes selected via `Subnet.ipv6_allocation_policy`; `_eui64_from_mac` in `backend/app/api/v1/ipam/router.py` implements RFC 4291 §2.5.1 Modified EUI-64 (u/l bit flip + `fffe` insertion); random /128 uses `secrets.randbits` with collision retry; dynamic-pool respect applies on v6 too. Test coverage in `backend/tests/test_ipv6_allocation.py` includes the RFC 4291 Appendix A worked example. Closes Phase 1.
- **DDNS pipeline (subnet-level)** — `Subnet.ddns_enabled` / `ddns_hostname_policy` / `ddns_domain_override` / `ddns_ttl`; `services/dns/ddns.py` resolves hostname per policy and calls the same `_sync_dns_record` path static allocations use; `pull_leases.py` + `dhcp_lease_cleanup.py` are the two integration points.
- **Agent-side lease-event DDNS for Kea** — `apply_ddns_for_lease` + `revoke_ddns_for_lease` wired into `POST /api/v1/dhcp/agents/lease-events` (commit `bad8cf3`), so Kea lease events drive DNS updates with the same semantics as the poll-based Windows DHCP path.
- **Block/space inheritance for DDNS settings** — `IPSpace` + `IPBlock` carry the four DDNS fields; `Subnet` / `IPBlock` carry `ddns_inherit_settings`; `services/dns/ddns.resolve_effective_ddns` walks subnet → block → space and is consulted by both the hostname resolver and the apply path (commit `a29d4fe`).
- **Per-server zone serial reporting** — `DNSServerZoneState` table + `POST /dns/agents/zone-state` for agents (agent reports after each successful apply in `agent/dns/spatium_dns_agent/sync.py`) + `GET /dns/groups/{gid}/zones/{zid}/server-state` for the UI + `ZoneSyncPill` on the zone detail header showing per-server convergence against the current SOA serial.
- **Trivy-clean + kind-AXFR acceptance tests for the agent images** — Trivy now enforces HIGH/CRITICAL (with `ignore-unfixed: true`) on both `build-dns-images.yml` and `build-dhcp-images.yml`; kind-based installation + `dig version.bind CH TXT` smoke test runs on PR via the new `.github/workflows/agent-e2e.yml` — spins up a kind cluster via `helm/kind-action@v1`, installs the umbrella chart with `dnsAgents.enabled=true`, port-forwards the API for `/health/live`, and checks the DNS agent pod isn't crash-looping.

<a id="appliance-pivot-170"></a>
#### Appliance architecture pivot (#170, 2026-05-14)

The Application appliance role + `spatium-supervisor` + approval workflow shipped in [#170](https://github.com/spatiumnorth/spatiumddi/issues/170) waves A–D on 2026-05-14:

- **Wave A** — scaffolding. New `spatium-supervisor` container in `agent/supervisor/spatium_supervisor/`; supervisor identity (Ed25519 keypair on `/var/persist/spatium-supervisor/`, appliance row in `pending_approval` state); pairing codes reshape (drops `deployment_kind`, adds `persistent` + `enabled` + `max_claims` + Fernet-encrypted reveal); container images baked into the appliance OS image for air-gap-ready installs (originally `/usr/lib/spatiumddi/images/*.tar.zst`; #183 Phase 7 moved them to `/var/lib/rancher/k3s/agent/images`, where k3s imports them, see #3169 for the slot-rollback consequence); A/B slots bumped from 4 GiB to 8 GiB each.
- **Wave B** — provisioning. Internal CA + cert lifecycle (RSA-2048 self-signed root, lazy-bootstrap on first approve, 90-day supervisor cert signed against the supervisor's Ed25519 pubkey); admin approve / reject / delete / re-key endpoints; supervisor `/poll` + `/heartbeat` endpoints with session-token interim auth; installer wizard collapsed from 5 roles to 3 (`full-stack` / `frontend-core` / `application`); the Application install prompt asks only control-plane URL + 8-digit pairing code; Approvals frontend tab with pending queue + drilldown.
- **Wave C** — service vs supervisor split. All four host bind mounts (`/etc/spatiumddi-host`, `/boot/efi-host`, `/var/lib/spatiumddi-host/release-state`, `/run/udev`) move off the DNS / DHCP service containers onto the supervisor; `slot_state.py` ported to `appliance_state.py` (one impl instead of three); supervisor heartbeat persists slot telemetry + reads back `desired_appliance_version` / `desired_slot_image_url` / `reboot_requested` for trigger-file firing; role assignment endpoint with capability gate (supervisor must advertise `can_run_dns_bind9=true` etc.) + multi-role + DHCP `network_mode: host` vs `bridged` for relay deployments; per-role nftables drop-in renderer (`/etc/nftables.d/spatium-role.nft`) with always-open mgmt rules + per-role service ports + operator-pasted override fragment, `nft -c -f` dry-run before live-swap.
- **Wave D** — fleet UI + MCP + docs. `Approvals` tab renamed to `Fleet`; drilldown grows an OS & lifecycle block (per-slot version chips, schedule OS upgrade, cancel pending, reboot host with double-confirm checkbox) and the existing firewall preview + role-assignment + capabilities sections; new admin endpoints `/upgrade` + `/clear-upgrade` + `/reboot` stamp desired state on the appliance row for the supervisor to act on; four MCP tools land for the Operator Copilot (`find_pending_appliances`, `find_appliance_fleet`, `propose_approve_appliance`, `propose_assign_role`) — all superadmin-gated; APPLIANCE.md + DNS_AGENT.md gain post-#170 architecture sections.

**Landed after 2026.05.14-1 — fleet shake-out + Wave E watchdog layer:**

- **DNS record propagation across all agents in a group** — `enqueue_record_op` previously queued one op against `is_primary=True`, and the bundle's pending-op shipper gated on the same flag. Under #170 every agent renders the zone as `type master` (independent authoritative copy), so secondaries stayed frozen at the bundle they received on initial register. Now fans out per-server: one `DNSRecordOp` row per enabled agent-based server in the group; `agent_config.py` ships them regardless of `is_primary`. `is_primary` only matters for the agentless / Windows-DNS path.
- **Supervisor → service-container auth-key delivery** — `SupervisorRoleAssignment` carries `dns_agent_key` / `dhcp_agent_key` (only when the matching role is assigned). The supervisor writes them into `role-compose.env`; service containers interpolate `${DNS_AGENT_KEY}` / `${DHCP_AGENT_KEY}` on first boot with zero operator action. Closes the "the bind9 / kea container can't register itself" gap that surfaced post-Wave-A3 when the `/api/v1/appliance/pair` endpoint was removed.
- **Supplementary-group fix on docker.sock** — `su-exec spatium:spatium` (explicit `:group`) cleared supplementary groups, so the unprivileged supervisor couldn't read `/var/run/docker.sock` (owned `root:103` on Debian). Every `_docker_image_present` call returned False → `can_run_*` flags all False → role checkboxes grayed out in the Fleet UI. Entrypoint now detects the host docker.sock gid, adds `spatium` to a matching `docker` group, and drops the `:spatium` suffix so `initgroups()` pulls the new group. Supervisor image also gained `docker-cli-compose` — without it every `apply_role_assignment` failed with `docker: unknown command: docker compose`.
- **Profile → service mapping for DHCP** — `apply_role_assignment` intersected compose *profile* names (`dhcp`) against `SUPERVISED_SERVICES` (`dhcp-kea`), so DHCP role assignments silently no-op'd. New `_PROFILE_TO_SERVICE` table (identity for BIND9 + PowerDNS, `dhcp → dhcp-kea`) shared with the new watchdog.
- **Docker poll storm reduction (~5× CPU cut on a 1-CPU VM)** — new `agent/supervisor/spatium_supervisor/docker_api.py` talks to `/var/run/docker.sock` directly via `http.client.HTTPConnection` over a unix-socket subclass (~10 ms per call instead of ~300 ms for a CLI shell). 5-min cache on `_docker_image_present`. `apply_role_assignment` skips the `docker compose ps` + `up -d` pair when the rendered env-file content hash is unchanged from the last successful apply (sidecar `role-compose.env.hash`). Same direct-socket pattern adopted by the console's `docker_ps`. The dashboard's previous 3 s subprocess timeout was killing dockerd mid-response, generating `superfluous response.WriteHeader call from go.opentelemetry.io/contrib/...` log spam in a self-feeding loop; that's gone.
- **Wave E in-process watchdog (`agent/supervisor/spatium_supervisor/watchdog.py`)** — runs inside the heartbeat loop every 5 min. Reads `role-compose.env` for desired profiles, maps profile → compose service, snapshots running containers via `docker_api`, derives `healthy` / `missing` / `unhealthy` / `starting` per service with a `since` first-observed timestamp. Auto-heal: `missing` services trigger an idempotent `apply_role_assignment` re-fire. Cached verdict rides on every heartbeat as `role_health`; persisted to new `appliance.role_health` JSONB column (migration `c4e2b7f81a39`); rendered as a per-service health table in the Fleet drilldown (status chip + `since X ago`). Cache invalidates whenever `apply_role_assignment` runs so the next heartbeat re-probes immediately instead of waiting 5 min.
- **Wave E external watchdog** — host-side `bash` script + systemd `.service` + `.timer` units that catch the case where the supervisor process is alive (pgrep passes, `restart: unless-stopped` doesn't fire) but the heartbeat loop has wedged. The supervisor `touch()`es `/var/persist/spatium-supervisor/last-loop-at` at the top of every iteration; `/usr/local/bin/spatiumddi-supervisor-watchdog` stats the file every 2 min and `docker restart spatium-supervisor` when mtime > 5 min stale. Rate-limited to 3 restarts per 30 min, beyond which it writes an alert trigger file the in-process watchdog reads and surfaces as a red `Watchdog: Restart cap hit` chip on the console dashboard. Intentionally `bash`-only (no Python, no docker SDK) so it survives anything that breaks the supervisor's own runtime stack. Enabled at install time by `mkosi.postinst`.
- **Firewall drift detection** — every 5 min the supervisor reads the kernel-active ruleset via `nft -j list chain inet filter input`, confirms each expected per-role service port is present, and forces a re-apply if anything's missing. Catches the "drop-in file is right but `nft -f /etc/nftables.conf` silently failed" and "operator `nft flush ruleset`'d in a debugging session" cases. Logs `supervisor.firewall.drift_detected`. `FirewallProfile` gains `expected_tcp_ports` + `expected_udp_ports` frozensets so the comparison is straightforward.
- **Fleet UI** — file rename `ApprovalsTab.tsx` → `FleetTab.tsx` (component + React-Query keys + URL hash all migrated from `approvals` → `fleet`); sidebar regrouped under **Infrastructure** (Appliances / Pairing codes / Slot images) + **Services** (NTP / SNMP) sub-headings so future Wave-E host-config surfaces drop in cleanly; new **Services** column on the Appliances list with per-role chips coloured by `role_switch_state` (green `ready` / amber `pending` / rose `failed` / neutral observer); new **Service health** section in the per-appliance drilldown rendering the watchdog's `role_health` table; **Approve + sign cert** now refreshes the drilldown row on success; **Role assignment Save** shows a transient `✓ Saved` indicator and re-baselines the `dirty` check; **Slot image Delete** gated behind a `ConfirmModal` that shows version + notes + SHA-256 prefix.
- **Console dashboard polish** — F9 / Diag chip removed (handler was a no-op); live-log noise filter drops Python traceback frames + systemd restart-counter spam; `--since` 10 min → 2 min so crash spam from a previous instance clears 5× faster; CPU usage 92 % → 1.4 % via `auto_refresh=False` on Rich Live + tick 0.25 s → 0.5 s; Build line collapses when `APPLIANCE_VERSION == SPATIUMDDI_VERSION`; `slot_a` → `A` in the slot indicator; IPv6 SLAAC addresses fold into a `+N IPv6` chip; Agent panel deleted (Control plane URL + Identity fold into one header row); Vitals + Disks merged into one row; Services row gains a ports / network-mode column (`53/tcp 53/udp` for published-port containers, `host net` in bold cyan for DHCP-kea); Disk dedupe — `/home` / `/root` bind mounts collapse to the underlying `/var` device, `/var/lib/spatiumddi/docker-overlay/lower` hidden; new `Watchdog` header line surfacing the external watchdog state (green `Loop ticking · Ns ago` / yellow `Loop stale · Ns ago` / red `Restart cap hit`); Services panel unions whichever supervisor-managed service is either in `docker ps` or listed in `role-compose.env`'s `COMPOSE_PROFILES` so a crashed container surfaces as `(not running)` instead of disappearing.
- **Misc** — `spatiumddi-firstboot` writes `/etc/spatiumddi/.env` mode 644 (was 600) so the supervisor's unprivileged user can read it through the `/etc/spatiumddi:/etc/spatiumddi-host:ro` bind mount; `service_lifecycle.py` passes the host `.env` as an additional `--env-file` to `docker compose` so `${SPATIUMDDI_VERSION}` / `${DOCKER_GID}` interpolation resolves without re-emitting every var into the role env.

Open Wave E follow-ups: container-watchdog auto-heal cap (currently re-fires `apply_role_assignment` on every probe — could backoff after N consecutive `missing` cycles); nftables base-config strip (`/etc/nftables.conf` currently has hardcoded DNS / DHCP / HTTP "belt-and-braces" rules from the pre-#170 5-role world); per-appliance scoped agent keys (current implementation passes the platform-wide global PSK — a per-appliance scoped key would limit blast radius if a supervisor cert ever leaked); host-OS config plane (#155–#166 — APT sources / proxy, syslog forwarder, SSH `authorized_keys`, static routes, etc., riding the same ConfigBundle → trigger-file → host runner pattern as shipped SNMP / NTP; **APT #155 implemented on `issue-77-99-155`** — opt-in `platform_settings.apt_*` (managed sources / proxy / Fernet-encrypted GPG keys + private-mirror auth / unattended-upgrades toggle) → `apt_bundle` in the supervisor heartbeat → `spatiumddi-apt-reload` host runner that **validates a staged config with `apt-get update` before swapping the live files** (classifies failures into `proxy-failed` / `mirror-unreachable` / `signature-mismatch` / `no-sources`), `POST /settings/apt/validate` structural pre-check, `find_apt_settings` MCP tool, APT Services-sidebar form + per-row `apt_state` Fleet chip).

Superseded by #170 (still functional for in-field installs, deprecated for new ones): legacy `dns-agent-bind9` / `dns-agent-powerdns` / `dhcp-agent` installer roles, the per-service slot-state collectors on DNS + DHCP agents, the PSK-based `DNS_AGENT_KEY` / `SPATIUM_AGENT_KEY` registration path, and pairing codes' `deployment_kind` field from #169.


### Major roadmap items (shipped bodies)

<a id="issue-21"></a>
#### **Windows DNS — Path B (WinRM + PowerShell)** (#21)

- ✅ [**Windows DNS — Path B (WinRM + PowerShell)**](https://github.com/spatiumnorth/spatiumddi/issues/21) — shipped: agentless WinRM + PowerShell path in `backend/app/drivers/dns/windows.py` (enabled per-server when `DNSServer.credentials_encrypted` is set) drives zone CRUD (`Add-DnsServerPrimaryZone` / `Remove-...`), an AXFR-free record pull (`Get-DnsServerResourceRecord`), and server-level probes over the `DnsServer` module. Record-level writes still ride RFC 2136 to avoid the PowerShell-per-record cost. Remaining literal-scope items — zone *edit* via `Set-DnsServerZone`, server-level option writes, DNS view config, GSS-TSIG for "Secure only" AD zones — were re-homed to [#444](https://github.com/spatiumnorth/spatiumddi/issues/444) (open). See [`docs/features/DNS.md`](docs/features/DNS.md) §13.

<a id="issue-22"></a>
#### **Windows DHCP — Path B (WinRM + PowerShell, full CRUD)** (#22)

- ✅ [**Windows DHCP — Path B (WinRM + PowerShell, full CRUD)**](https://github.com/spatiumnorth/spatiumddi/issues/22) — shipped: despite the legacy `WindowsDHCPReadOnlyDriver` class name, `capabilities()` reports `read_only=False` and the driver does scope / reservation / exclusion write CRUD + scope-option reconcile + MAC deny-filter over WinRM, wired through `backend/app/services/dhcp/windows_writethrough.py` (batched, transactional, multi-server). Remaining gaps — client-class CRUD, a broader option-code map, and the stale "read-only" naming/docs — were re-homed to [#444](https://github.com/spatiumnorth/spatiumddi/issues/444) (open).

<a id="issue-23"></a>
#### **IP discovery** (#23)

- ✅ [**IP discovery**](https://github.com/spatiumnorth/spatiumddi/issues/23) — shipped `2026.06.04-1`: opt-in per-subnet scheduled ping / ARP sweep + reconciliation (unprivileged `SOCK_DGRAM` ICMP with TCP-connect fallback, `/proc/net/arp` scan for ICMP-silent hosts, `status="discovered"` rows for live IPs with no row). Producer of the #45 / #41 hygiene loop. Migration `a7e3c1f49d20`.

<a id="issue-24"></a>
#### **DNS Views — end-to-end split-horizon wiring** (#24)

- ✅ [**DNS Views — end-to-end split-horizon wiring**](https://github.com/spatiumnorth/spatiumddi/issues/24) — shipped `2026.06.04-1`: the BIND9 agent now emits one `view "<name>" { match-clients …; }` block per view with per-view zone files (`view_id IS NULL` records render into every view). Storage + CRUD + record-form picker had shipped earlier. Full body in [`docs/SHIPPED.md`](docs/SHIPPED.md).

<a id="issue-28"></a>
#### **ACME embedded client — certs for SpatiumDDI's own services** (#28)

- ✅ [**ACME embedded client — certs for SpatiumDDI's own services**](https://github.com/spatiumnorth/spatiumddi/issues/28) — [#438](https://github.com/spatiumnorth/spatiumddi/issues/438) **shipped 2026.06.19-1**, **Phases 1–5 implemented + Phase 6 resolved N/A**: a hand-rolled RFC 8555 ACME client (`backend/app/services/acme_client/` — `engine.py` manual JWS over `cryptography` + `httpx`, `dns01.py` self-solve over SpatiumDDI's own managed zones via the `record_ops` pipeline, `orchestrator.py` end-to-end driver) that issues a CA-trusted Web UI TLS cert from Let's Encrypt, landing the chain in the existing `ApplianceCertificate` storage + deploy path with `source="letsencrypt"`. Surface at `/api/v1/appliance/acme` (account upsert + `POST /preview` + `POST /issue` → `app.tasks.acme.run_acme_order` + orders list/get/cancel) behind the default-enabled `security.certificates` feature module (group Security), plus the unauthenticated root route `GET /.well-known/acme-challenge/{token}` for HTTP-01 (nginx-proxied). Account key + EAB HMAC are Fernet-encrypted + never returned (`eab_hmac_set` boolean only). **Phase 1** DNS-01 over managed zones; **Phase 2** 12h beat task `app.tasks.acme.renew_due_certificates` (re-issues active LE certs within 30d of `valid_to`, idempotent + advisory-locked, gated on `acme_enabled`+`acme_auto_renew`) + the `secret_expiring` alert now covers the LE Web-UI cert (`appliance_cert_tls:<id>`); **Phase 3** cloud-hosted DNS-01 auto-solve via the Cloudflare/Route53/Azure/Google agentless drivers (creds configured under DNS, not the ACME screen) + `POST /preview` per-domain managed/manual report + `allow_manual` manual-TXT fallback (`manual_challenges[]` + public-DNS polling converges the order); **Phase 4** http-01 (`challenge_type:"http-01"`, CA fetches the well-known route, appliance must be reachable on :80/:443 at the FQDN, no wildcards); **Phase 5** `tls-alpn-01` → 422 (not supported on the nginx/k3s topology, UI shows it disabled); **Phase 6** per-appliance certs resolved N/A (Web UI is control-plane-only behind one shared VIP cert = fleet-singleton). MCP: `find_certificates` / `count_certificates_expiring` (default on) + `get_acme_account` (default off). See `docs/features/ACME.md`. Distinct from the shipped ACME *provider* (`/api/v1/acme/`).

<a id="issue-129"></a>
#### **DHCP configuration importer — ISC DHCP, Kea, Windows DHCP** (#129)

- ✅ [**DHCP configuration importer — ISC DHCP, Kea, Windows DHCP**](https://github.com/spatiumnorth/spatiumddi/issues/129) — shipped `2026.06.04-1`: one-shot import-to-evaluate (sister to the DNS importer #128) behind one canonical IR + preview → commit pipeline — Kea JSON-with-comments upload, Windows live-pull (reuses the Path A driver), ISC `dhcpd.conf` parse. Provenance columns via migration `c7f1a3e58b94`. See [`docs/features/MIGRATION.md`](docs/features/MIGRATION.md).

<a id="issue-756"></a>
#### **Windows → SpatiumDDI cutover (guided migration)** (#756)

- ✅ [**Windows → SpatiumDDI cutover (guided migration)**](https://github.com/spatiumnorth/spatiumddi/issues/756) — shipped `2026.08.12-1`: the half the #128 / #129 importers stop short of. **Not a fifth importer** — it creates no zones, scopes, pools or records; its only writes are TTL reductions on a zone SpatiumDDI already owns, reservations synthesised from live Windows leases, and `is_active` on a managed scope. Unit of work is a `cutover_plan` holding independent `cutover_item`s (one zone or one scope), each cut over and rolled back on its own — no big-bang step. Four phases: **parity** (diff vs live Windows, classified by *why* the sides differ — `value_mismatch` / `drifted_since_import` / `never_imported` / `intentionally_diverged`; CAA/TLSA/SSHFP are `not_compared` because a Path-B pull can't emit them, and an unparseable response is `unverified`, never "everything diverged"), **parallel run** (replay query-log traffic at both sides, RD=0, IP literal not hostname), **the switch** (TTL pre-flight snapshot/restore, DHCP lease→reservation handover, deactivate-Windows-before-activate-managed with compensating rollback sealed inside the transaction), **decommission checklist** (15 items, 3 advisory-evaluated, none auto-ticked). Plus a markdown runbook carrying the Windows-side PowerShell we deliberately don't run. **Load-bearing refusal:** an AD-integrated zone with "Secure only" dynamic updates is a hard block `force` cannot bypass (GSS-TSIG unimplemented — #444), failing closed. Behind the default-on `migration.cutover` module (group Tools), **superadmin on every endpoint**; router `/api/v1/migration/cutover`; 4 MCP tools (`find_cutover_parity_check` default-off — live WinRM pull). Migration `a4f1c93d7e28`. See [`docs/features/MIGRATION.md`](docs/features/MIGRATION.md). **Deferred:** auto-approve of parity warnings, and a non-Windows (BIND9 / ISC) cutover source.

<a id="issue-810"></a>
#### **Technitium — agentless driver for an install the operator already runs** (#810)

- ✅ [**Technitium — agentless driver for an install the operator already runs**](https://github.com/spatiumnorth/spatiumddi/issues/810) — shipped `2026.08.12-1`: new `technitium_api` driver (`backend/app/drivers/dns/technitium_api.py`), agentless like Windows Path B: operator pastes an API URL + permanent bearer token, control plane drives Technitium's HTTP API directly, nothing deployed. Coexists with the agent-managed `technitium` (a group is single-driver). **No migration** — credentials ride the existing `DNSServer.credentials_encrypted`. Zone + record CRUD and topology pull only; DNSSEC / forwarders / blocklists stay agent-managed and `technitium_api` is deliberately absent from `_DRIVER_GATED_OPERATIONS["dnssec_sign"]`. Also extracted the rdata translation both drivers and the #744 importer need into `app/services/technitium/rdata.py` (the agent keeps a third copy it can't share — separate package), and replaced two inline `windows_dns or CLOUD_DNS_DRIVERS` topology gates with `TOPOLOGY_PULL_DRIVERS` / `supports_topology_pull()`. See [`docs/drivers/DNS_DRIVERS.md` §4C](docs/drivers/DNS_DRIVERS.md). **Deferred:** query-log polling (#742's shape, easier here than on the agent path), Technitium's DHCP API as a DHCP driver, and clustering awareness.


### Integration roadmap (shipped bodies)

<a id="issue-30"></a>
#### **UniFi Network Application** (#30)

- ✅ [**UniFi Network Application**](https://github.com/spatiumnorth/spatiumddi/issues/30) — read-only mirror of UniFi networks + clients into IPAM (local + cloud-hosted controllers) behind the `integrations.unifi` feature module (`backend/app/services/unifi/`, model `models/unifi.py`, task `tasks/unifi_sync.py`, router `api/v1/unifi/`).

<a id="issue-31"></a>
#### **OPNsense (tier 1 — firewall-of-choice for labs)** (#31)

- ✅ [**OPNsense (tier 1 — firewall-of-choice for labs)**](https://github.com/spatiumnorth/spatiumddi/issues/31) — read-only mirror of OPNsense interfaces + DHCP leases + reservations into IPAM behind the `integrations.opnsense` feature module (`backend/app/services/opnsense/`, model `models/opnsense.py`, task `tasks/opnsense_sync.py`, router `api/v1/opnsense/`).

<a id="issue-605"></a>
#### **Palo Alto PAN-OS / Panorama (enterprise-firewall family reference vendor)** (#605)

- ✅ [**Palo Alto PAN-OS / Panorama (enterprise-firewall family reference vendor)**](https://github.com/spatiumnorth/spatiumddi/issues/605) — shipped `2026.07.11-1`: read-only mirror of address objects/groups → a new `firewall_endpoint_object` "shadow IPAM" store (with IPAM drift report), NAT rules → `nat_mapping` provenance rows, + opt-in zones/interfaces + DHCP leases, behind the `integrations.paloalto` feature module (`backend/app/services/panos/`, model `models/panos.py`, task `tasks/panos_sync.py`, router `api/v1/panos/` at the `/paloalto` prefix). Also a commit-free **Dynamic Address Group** enforcement tier extending Active block sync (#601) — `paloalto` target kind registers `IP → tag` via the User-ID API, gated by the new `manage_firewall_enforcement` permission. Fortinet / Check Point / Cisco FTD / Meraki follow this pattern.

<a id="issue-606"></a>
#### **Enterprise firewall family — Fortinet / Check Point / Cisco FTD / Meraki + policy-aware conformity** (#606)

- 🟡 [**Enterprise firewall family — Fortinet / Check Point / Cisco FTD / Meraki + policy-aware conformity**](https://github.com/spatiumnorth/spatiumddi/issues/606) — **Phase 1 (Fortinet + Meraki) shipped `2026.07.11-1`.** Both follow the #605 shape via a new shared mirror engine `backend/app/services/firewall_mirror.py` (the #605 PAN-OS reconciler was migrated onto it; `firewall_endpoint_object` generalized to one-of-three vendor owners with a `num_nonnulls=1` CHECK). **Fortinet FortiGate** — read-only FortiOS-REST mirror (address objects/groups → shadow IPAM, VIPs → `nat_mapping`, opt-in interfaces + DHCP leases) behind `integrations.fortinet` (`services/fortinet/`, `models/fortinet.py`, `tasks/fortinet_sync.py`, `api/v1/fortinet/`); enforcement is the credential-free **Threat-Feed inversion** — new `FirewallFeed` (`models/firewall_feed.py`, `services/firewall_feeds/`, `api/v1/firewall_feeds/`) serves a token-scoped `blocklist.txt` the FortiGate polls (module `security.firewall_feeds`, default-on). **Cisco Meraki MX** — read-only Dashboard-API mirror (VLANs → subnets, DHCP fixed-IP reservations → IPAM, org policy objects → shadow IPAM, 1:1-NAT/port-forward → `nat_mapping`, opt-in clients) behind `integrations.meraki` (`services/meraki/`, `models/meraki.py`, `tasks/meraki_sync.py`, `api/v1/meraki/`); enforcement is a `meraki` block-sync target (kind=`mac`, per-client `Blocked` device policy via the Dashboard API, gated by `manage_firewall_enforcement`). 3 MCP tools (`list_fortinet_targets` / `list_meraki_targets` / `list_firewall_feeds`); `find/count_firewall_objects` made vendor-neutral. **Deferred:** FortiManager JSON-RPC centralization; Phase 2 (Check Point + Cisco FTD/FMC, both leading with feed-based enforcement); and the cross-cutting **policy-aware conformity checks** (`pci_scope`/`internet_facing` subnets asserted against live firewall policy, plugging into #106).

<a id="issue-603"></a>
#### **NetBird (managed WireGuard mesh)** (#603)

- ✅ [**NetBird (managed WireGuard mesh)**](https://github.com/spatiumnorth/spatiumddi/issues/603) — shipped `2026.07.11-1`: read-only mirror of NetBird peers into IPAM behind the `integrations.netbird` feature module (`backend/app/services/netbird/`, model `models/netbird.py`, task `tasks/netbird_sync.py`, router `api/v1/netbird/`), cloned from the Tailscale shape — NetBird's real management API is what makes it a legitimate pull mirror where raw WireGuard isn't. Phase 1 mirrors each peer's overlay IP (OS / version / groups / connection state in custom fields) under an auto-created overlay block + subnet; Phase 2 adds an optional synthetic read-only DNS zone for the mesh domain. Per-instance operator-supplied management URL + `verify_tls` toggle (SSRF-guarded at the test-connection boundary), Token auth, and a cross-integration ownership guard — NetBird and Tailscale both default to `100.64.0.0/10`, so neither reconciler will claim the other's rows. 1 MCP tool (`list_netbird_targets`).

<a id="issue-36"></a>
#### **NetBox read-only import (one-shot)** (#36)

- ✅ [**NetBox read-only import (one-shot)**](https://github.com/spatiumnorth/spatiumddi/issues/36) — **shipped 2026.06.28-1**. One-shot migration importer (not a continuous reconciler): live-pulls prefixes / addresses / VRFs / tenants→Customers / sites / VLANs out of a NetBox install and stamps them into native IPAM rows via a stateless preview → commit flow (`backend/app/services/netbox_import/`, router at `/api/v1/ipam/import/netbox/{test-connection,preview,commit}`). Provenance `import_source="netbox"` + `netbox_id` makes re-runs idempotent (default-skip-on-conflict); `per_vrf` (one IPSpace per VRF + Global) vs `single` (collapse into a chosen space) strategy; connection + token supplied per-request, never persisted. Behind the default-on `ipam.import.netbox` feature module; 2 MCP tools (`find_netbox_import_preview` + `propose_commit_netbox_import`). See `docs/features/MIGRATION.md`.

<a id="issue-37"></a>
#### **Cloud connectors — unified "Cloud" integration with per-provider picker (Azure / AWS / GCP)** (#37)

- ✅ [**Cloud connectors — unified "Cloud" integration with per-provider picker (Azure / AWS / GCP)**](https://github.com/spatiumnorth/spatiumddi/issues/37) — shipped `2026.06.04-1`. Part A: read-only infra mirror (`cloud_endpoint` + AWS/Azure/GCP connectors → IPBlock/Subnet/IPAddress, `services/cloud/`, feature module `integrations.cloud`). Part B: Cloudflare / Route 53 / Azure DNS / Google Cloud DNS as agentless first-class DNS drivers (`drivers/dns/{cloudflare,route53,azuredns,googledns}.py`) with import-existing-zones (`services/dns_import/cloud.py`). See `docs/features/INTEGRATIONS.md` + `docs/drivers/DNS_DRIVERS.md`. Stretch token-only DNS providers (DigitalOcean / Hetzner / Linode / Vultr) deferred.


### Future ideas — categorised (added 2026.04.26) — Discovery & network awareness (shipped bodies)

<a id="issue-41"></a>
#### **Reverse-DNS auto-population** (#41)

- ✅ [**Reverse-DNS auto-population**](https://github.com/spatiumnorth/spatiumddi/issues/41) — shipped `2026.06.04-1`: scheduled, platform-opt-in sweep that PTR-resolves `hostname IS NULL` rows against configured resolvers (bounded concurrency, per-run cap), filling the short label into `hostname` and the FQDN into `description` only when blank. Migration `d7a3f2b9c1e4`.

<a id="issue-42"></a>
#### **CGNAT (RFC 6598) awareness** (#42)

- ✅ [**CGNAT (RFC 6598) awareness**](https://github.com/spatiumnorth/spatiumddi/issues/42) — shipped `2026.06.04-1`: amber "CGNAT" badge on subnet detail + a New-Subnet advisory hint when the typed network falls in `100.64.0.0/10` — the one reserved IPv4 range overlays actively carve, so reaching for it as an on-prem LAN silently overlaps overlay space.


### Future ideas — categorised (added 2026.04.26) — Vertical network awareness (shipped bodies)

<a id="issue-540"></a>
#### **AV / Audio-Video-over-IP — Dante · AES67 · SMPTE 2110 · NDI** (#540)

- ✅ [**AV / Audio-Video-over-IP — Dante · AES67 · SMPTE 2110 · NDI**](https://github.com/spatiumnorth/spatiumddi/issues/540)
  — shipped `2026.07.30-1` (#714): `network.av` module,
  `av_flow_profile` 1:1 AV descriptor on `multicast_group` + operator-declared `av_reserved_range` per
  protocol, allocation-conflict preview, 2 conformity checks, 3 MCP
  tools. **Phase 2 (Dante mDNS) blocked** — #40 closed not-planned.
  **Phase 3 (NMOS IS-04 mirror) deferred** — a full pull integration
  with both dashboard surfaces, separable into its own change.

<a id="issue-541"></a>
#### **BACnet/IP building automation** (#541)

- ✅ [**BACnet/IP building automation**](https://github.com/spatiumnorth/spatiumddi/issues/541)
  — shipped `2026.07.30-1` (#714): `network.bacnet` module,
  `bacnet_device` with the internetwork-wide
  `uq_bacnet_device_instance` constraint (the differentiating hook),
  BBMD flag + BDT/FDT snapshots, 3 conformity checks incl.
  `bbmd_one_per_subnet` failing in both directions, 3 MCP tools.
  **Phase 2 (`Who-Is` sweep) deferred** — needs a UDP broadcast
  carrying a real payload; the only generic prober sends an empty
  datagram.

<a id="issue-542"></a>
#### **Industrial / OT — PROFINET · EtherNet/IP · Modbus TCP · OPC UA** (#542)

- ✅ [**Industrial / OT — PROFINET · EtherNet/IP · Modbus TCP · OPC UA**](https://github.com/spatiumnorth/spatiumddi/issues/542)
  — shipped `2026.07.30-1` (#714): `network.ot` module, `ot_device`
  1:1 descriptor + `ot_zone` Purdue zoning (`Numeric(2,1)` so level 3.5 / the DMZ is representable), CSV import
  of engineering-tool exports, 2 conformity checks, 3 MCP tools.
  Read-only identification only — control-protocol writes are
  permanently out of scope. **Phase 2 (routable probes) deferred** —
  nmap runs NSE but nothing parses `<script>` output. **Phase 3
  (PROFINET DCP) deferred** — raw L2, needs a container capability grant.

<a id="issue-723"></a>
#### **DICOM AE Title registry + peer-association map** (#723)

- ✅ [**DICOM AE Title registry + peer-association map**](https://github.com/spatiumnorth/spatiumddi/issues/723)
  — Phase 1 shipped `2026.07.30-1` (#731): `network.dicom` module,
  `dicom_ae` with the institution-wide `uq_dicom_ae_title` constraint (the differentiating hook — PS3.15 Annex H specifies a
  registry for exactly this and nobody deploys one), `dicom_peer`
  directed AE→AE edges + a renumber-impact view, CSV import of the
  estate's AE table, 4 conformity checks, 3 MCP tools. `ip_address_id`
  is **nullable / SET NULL**, deliberately unlike BACnet's CASCADE: an
  AE Title outlives its host, so decommissioning demotes it to a
  reservation rather than freeing a name peers still send to. AE-title
  validation follows PS3.5 exactly — 16 **bytes**, spaces legal as
  padding, all-space forbidden, no backslash / control chars. **No PHI,
  ever** — network identity only, or SpatiumDDI becomes a HIPAA
  Business Associate. **C-ECHO verification probe deferred** to its own
  issue: it is the one probe in the family that does *not* inherit the
  agent↔subnet blocker (routable unicast TCP), but it must respect #722.

<a id="issue-722"></a>
#### **Fragile-device "do not probe" flag** (#722)

- ✅ [**Fragile-device "do not probe" flag**](https://github.com/spatiumnorth/spatiumddi/issues/722)
  — shipped `2026.07.30-1` (#731). **Not a vertical and not
  behind a feature module**: a constraint on our own behaviour and a
  correctness fix to three shipped features (#23 sweeps, `tools.nmap`,
  `tools.network`), so hiding it behind a default-off module would leave
  the sites that need it unprotected. `do_not_probe` +
  `do_not_probe_reason` on `IPSpace` / `IPBlock` / `Subnet` **OR down**
  the chain with no per-level inherit toggle — deliberately unlike the
  DDNS fields they mirror, because a descendant must not be able to opt
  a clinical space back into being swept. One resolver
  (`services/ipam/probe_policy.py`) that every prober consults; audited
  superadmin-only per-request override; `fragile_subnet_probed`
  conformity check working backwards from the `ot_device` / `dicom_ae` /
  `role="bmc"` registries; `bmc` added to `IP_ROLES`. Migration
  `b1e7c04a93df`.


### Future ideas — categorised (added 2026.04.26) — Reporting & analytics (shipped bodies)

<a id="issue-44"></a>
#### **Per-subnet utilization history** (#44)

- ✅ [**Per-subnet utilization history**](https://github.com/spatiumnorth/spatiumddi/issues/44) — shipped `2026.06.11-1`: daily beat task snapshots each subnet's allocated / total IP counts (pruned > 90 d); Trend tab on subnet detail renders a 30 / 90-day % used line chart; `get_subnet_utilization_trend` MCP tool. Migration `c7a3e1f90d24`.

<a id="issue-45"></a>
#### **Stale-IP report** (#45)

- ✅ [**Stale-IP report**](https://github.com/spatiumnorth/spatiumddi/issues/45) — shipped `2026.06.04-1`: over the #23 discovery `last_seen_at` signal — which allocated IPs has nothing answered for in N days. Paginated report (optional space / block / subnet scope) + one-click bulk-deprecate of selected or all-matching (capped, reversible).

<a id="issue-46"></a>
#### **Decom-date awareness** (#46)

- ✅ [**Decom-date awareness**](https://github.com/spatiumnorth/spatiumddi/issues/46) — shipped `2026.06.11-1`: first-class `decom_date` on subnet + IP, a `decom_expiring` alert rule (severity escalation reused from the other `*_expiring` rules), a dashboard widget, and a `find_subnets_decommissioning` MCP tool. Migration `a3f7c1e92b48`.

<a id="issue-47"></a>
#### **Top-N reports** (#47)

- ✅ [**Top-N reports**](https://github.com/spatiumnorth/spatiumddi/issues/47) — shipped `2026.06.11-1`: a `/reports` surface (top subnets by utilization, owners by IP count, most-modified resources via `audit_log`, noisiest DNS clients), feature-module-gated with 4 MCP read tools.

<a id="issue-48"></a>
#### **Compliance / change report PDF** (#48)

- ✅ [**Compliance / change report PDF**](https://github.com/spatiumnorth/spatiumddi/issues/48) — shipped `2026.06.11-1`: `GET /api/v1/audit/export.pdf` renders an auditor-facing PDF of every `audit_log` mutation in a date range, grouped by user / resource / action, with a per-row SHA-256 tamper-evidence trailer.

<a id="issue-889"></a>
#### **InfluxDB push export** (#889)

- ✅ [**InfluxDB push export**](https://github.com/spatiumnorth/spatiumddi/issues/889) — shipped `2026.09.04-1`. The writer the tech-stack
  table claimed for months while `grep -ri influx` over `backend/` returned
  nothing. Now `InfluxDBTarget` + `backend/app/services/influxdb/`
  (`line_protocol` / `client` / `collect` / `push`) + a 30 s beat task with
  per-target interval gating, CRUD at `/settings/influxdb-targets` with a
  **test-write**, and 1 MCP tool (`find_influxdb_targets`, default on,
  superadmin-only). Migration `a2e7f31c9b48`.
  **"All versions" is three declared versions over two wire dialects:**
  `v3` is not a third client — every InfluxDB 3 product (Core, Enterprise,
  Cloud Dedicated, Cloud Serverless) accepts the **v2** write endpoint, so
  v3 reuses that path with `Authorization: Bearer` instead of `Token` and a
  *database* named in the `bucket` parameter. All three verified against a
  live server during development, `v1` via InfluxDB 2.7's DBRP
  compatibility mapping.
  **The idempotency (non-negotiable #9) is the server's, not ours:** line
  protocol overwrites a point with an identical measurement + tag set +
  timestamp, so a retry is free. That is what lets each push run **two
  queries per source on separate row budgets** — a forward drain
  (strictly `> watermark`, capped) and a replay of the closed
  `(watermark − 5 min, watermark]` window, so a bucket an agent reported
  late is still exported rather than skipped permanently and silently.
  The separation is load-bearing, not tidiness: fold the replay into the
  drain's lower bound and a fleet dense enough to fill the row cap inside
  that window returns a truncated batch whose maximum is *below* the
  watermark — pulling the cursor backwards every tick until it pins on
  the oldest retained sample, with every push still reporting success and
  the UI still green. Replayed rows never set the cursor.
  Watermarks advance only on a successful write, so a dead collector
  delays the export rather than punching a hole in it (the samples sit in
  Postgres until `prune_metrics` retires them, so a target that recovers
  inside `metric_retention_days` backfills itself). `last_push_at` moves
  on failure too, or a fast-failing target would retry on every 30 s tick
  instead of on its own interval — and the push is wrapped in a broad
  per-target boundary, because the sweep pushes every due target in one
  transaction and an escaping exception would discard the state updates
  of the ones that succeeded. `httpx.InvalidURL` is named explicitly
  alongside `HTTPError` for that reason: it derives from `Exception`, not
  from the httpx error base.
  **Two shapes of metric, and the difference matters on a dashboard:**
  the DNS/DHCP counter deltas carry the **agent's own 60 s bucket
  timestamp**, so a backfill lands on the hour the traffic happened — and
  60 s, not the push interval, is the resolution floor (`push_interval`
  below that just re-sends the same bucket). The IPAM utilization and
  per-scope lease gauges the spec asked for are sampled *at push time*
  from counters the app already maintains — no new table, but also no
  backfill: the first point is when the target was enabled. Documented
  as such rather than labelled "realtime". The lease gauge counts
  **distinct addresses**: `dhcp_lease` is per-server and a Kea HA pair
  mirrors each lease twice, so `COUNT(*)` would report 2× on exactly the
  deployments that matter, and disagree with `pool_occupancy.py`.
  **Test is a real single-point write**, not a reachability ping: a
  correct URL with the wrong bucket, org or token answers a GET perfectly
  well and then rejects every point. Explicitly **not** a feature module
  (non-negotiable #14) — no sidebar section, no router prefix, and "off"
  is already `enabled=false` on the row. **Deferred:** API request
  rate/latency and per-component health, which the old spec listed but
  nothing samples at push cadence.


### Future ideas — categorised (added 2026.04.26) — DNS-specific (shipped bodies)

<a id="issue-49"></a>
#### **DNSSEC** (#49)

- ✅ [**DNSSEC**](https://github.com/spatiumnorth/spatiumddi/issues/49) — shipped `2026.06.04-1`: BIND9 inline-signing, policies, DS export, rollover. `DNSSECPolicy` (reusable `dnssec-policy`) + `DNSKey` (public per-zone key state — no private-key custody; BIND owns + auto-rotates keys), config-driven `dnssec-policy { … }` + per-zone `inline-signing yes;`. Migration `f2b6d4a91c37`. PowerDNS online-signing landed separately in `2026.05.11-1`.

<a id="issue-50"></a>
#### **DoT / DoH — inbound listener + encrypted upstream forwarding** (#50)

- ✅ [**DoT / DoH — inbound listener + encrypted upstream forwarding**](https://github.com/spatiumnorth/spatiumddi/issues/50) —
  shipped `2026.07.30-1` (#692). Serves DoT (853) / DoH (`/dns-query`)
  to local clients *and* forwards to upstream resolvers
  over TLS instead of plaintext 53. Both halves are per-group, default-off
  (existing installs render a byte-identical `named.conf`), and additive —
  the Do53 listener is unaffected. **BIND9** renders `tls` / `http`
  statements + extra `listen-on` clauses natively and forwards over DoT
  with strict `remote-hostname` validation that fails closed;
  **PowerDNS** gets inbound-only via the dnsdist sidecar (#146 Phase 2,
  docker-compose-only) since pdns auth speaks neither protocol and doesn't
  forward at all. Certs come from the existing `ApplianceCertificate`
  store + the shipped ACME client (#438), ride the hashed config bundle so
  a renewal shifts the ETag, and degrade to Do53 (never a dead daemon) if
  the cert is deleted out from under a live listener. Operator-chosen
  ports flow to the supervisor firewall via a new `dns_encrypted_tcp_ports`
  field on the role assignment. Deferred: DoH-upstream (BIND has no
  client-side HTTP transport — needs the dnsdist path), per-forwarder TLS
  hostnames (one per group today, so mixed providers need one group each),
  and a k8s dnsdist front to unblock PowerDNS DoT/DoH off compose. DoQ
  shipped on Technitium (#741); on BIND9 / PowerDNS it is tracked in
  [#2886](https://github.com/spatiumnorth/spatiumddi/issues/2886).
  Not to be confused with `PlatformSettings.resolver_dns_over_tls`, which
  is the appliance host's own systemd-resolved stub resolver.

<a id="issue-877"></a>
#### **Upstream resolver presets** (#877)

- ✅ [**Upstream resolver presets**](https://github.com/spatiumnorth/spatiumddi/issues/877) — shipped in PR
  [#893](https://github.com/spatiumnorth/spatiumddi/pull/893): 16 verified
  presets across 7 providers in `backend/app/data/dns_resolver_presets.json`,
  served by `GET /dns/forwarder-presets` and picked from the Forwarders
  card. Each carries the **certificate name its addresses actually
  present**, which is the point: since DoT upstream forwarding (#50),
  BIND validates against ONE group-level `remote-hostname` and a
  mismatch fails closed (SERVFAIL), so "Quad9 is 9.9.9.9" without
  "…and its DoT name is dns.quad9.net" yields a group that resolves
  nothing. Two hard 422s for configurations that cannot work (a
  forwarder set spanning two certificate names under verification;
  Mullvad on plaintext 53) and a UI advisory — deliberately not a
  refusal — for a non-canonical hostname, because providers list
  several names per certificate. Addresses are matched by **value, not
  spelling**: `2606:4700:4700::1111` and its expanded form are one
  host, and a string compare would fail OPEN. Manual entry is
  unconstrained — the catalogue is a convenience, never a whitelist,
  with a test pinning that. 1 MCP tool (`list_resolver_presets`).

<a id="issue-878"></a>
#### **Family filter — adult-content blocking bundle + SafeSearch enforcement** (#878)

- ✅ [**Family filter — adult-content blocking bundle + SafeSearch enforcement**](https://github.com/spatiumnorth/spatiumddi/issues/878)
  — the catalog gains **templates** (entry sets shipped inline, for rules
  with no upstream feed) and **profiles** (compositions applied in one
  action), alongside the existing feeds:
  `backend/app/services/dns/blocklist_templates.py` +
  `POST /dns/blocklists/{from-template,apply-profile}`. Ships a
  **SafeSearch enforcement** template — RPZ *rewrites*, not blocks,
  riding the `entry_type="redirect"` path that already existed — and a
  **Family filter** profile pairing adult + gambling feeds with the
  **DoH / VPN / proxy bypass** lists, because a filter one browser
  setting routes around is not one. Five new sources; the two shipped
  Hagezi entries were **dead** (`hosts/` retired upstream, and one was
  `recommended: true`) and are repointed. Applying a profile assigns to
  nothing — auto-scoping would filter the server VLAN too.
  **Six latent bugs fixed on the way**, each of which made the feature
  wrong rather than merely absent. Three about **RPZ zone validity** —
  and note the shared blast radius: BIND rejects a malformed zone
  *whole*, so any one of these silently stopped every other entry being
  enforced, and nothing caught it because `validate()` runs
  `named-checkconf`, which never reads zone files. (1) the two renderers
  disagreed about `redirect` — the agent emitted `CNAME <target>`, the
  control-plane driver `IN A <target>` — so a hostname target produced
  rdata BIND rejects; both now branch on IP-vs-hostname. (2) the agent
  renderer never filtered entries against `exceptions` (the
  control-plane one did), so excepting a domain a feed lists — *the
  entire point of an exception* — put a block CNAME and a passthru CNAME
  on one owner name. (3) nothing deduped owner names, so one domain in
  two assigned lists with different `block_mode`s did the same; the
  Family filter ships four overlapping Hagezi feeds (146 shared domains
  measured) so this went from hand-assembled to one setting away. Both
  renderers now emit each owner once, first writer wins, and log the
  collision. Verified against `named-checkzone`: identical duplicates
  load, differing ones do not. Plus (4) Technitium routed
  `action="redirect"` into its **allow** set, silently inverting a
  SafeSearch rule into an exemption — now skipped with a warning, since
  its native blocking has no per-domain rewrite; (5) feed-sourced
  entries never set `is_wildcard`, so every subscribed list blocked
  apexes only and `www.<blocked>` resolved fine — now on, matching the
  manual add-entry default, with migration `b7e4a1c56d93` backfilling
  existing rows (`parse_feed` also strips the `*.` prefix OISD and
  Hagezi publish); (6) `entry_count` double-counted on a first sync,
  because the recount query autoflushes the pending inserts and the old
  code added `len(to_add)` on top — a 16k-domain feed reported 33k.
  Sizing consequence of (5), documented in DNS.md: two RPZ records per
  feed entry, so the Family filter's ~596k entries render ~1.2M records.
  1 MCP tool (`list_blocklist_templates`). BIND9-only,
  and [`docs/features/DNS.md` §8.1](docs/features/DNS.md) is explicit
  that DNS filtering is bypassable at all.

<a id="issue-876"></a>
#### **Per-subnet DNS blocklist scoping — surface it in the UI** (#876)

- ✅ [**Per-subnet DNS blocklist scoping — surface it in the UI**](https://github.com/spatiumnorth/spatiumddi/issues/876)
  — the backend has scoped a blocklist to a view *or* a server group
  since #24 (`dns_blocklist_view_assoc`, rendered per-view by the agent);
  the UI wrote only the group half, so the #878 family filter's whole
  point — filtering one network and not another — was unreachable from
  the product. Now: the **Views tab is full CRUD** (it was read-only, so
  split-horizon was API-only to configure at all), with an *Add subnets…*
  picker that turns IPAM prefixes into `match_clients`; a **scope modal**
  on each blocking list writing group and view assignment in one PUT; and
  per-view chips on both tabs. **The load-bearing addition is server-side
  validation** (`app/services/dns/named_conf_validation.py`): `match_clients`,
  `match_destinations` and the view name are interpolated *verbatim* into
  `named.conf`, and the name additionally becomes a directory on the
  agent — so a malformed prefix, an undefined ACL name, a `;`-injection or
  a `../` traversal are now 422s naming the offending element. That gate
  matters because the agent runs `named-checkconf` before swapping config
  in: an accepted-but-invalid value doesn't break one view, it stops the
  whole group's config converging, silently. Also fixed: the Blocklists
  tab classified a view-scoped list as "Available (not applied)" — i.e.
  reported a list actively filtering a VLAN as doing nothing — and its
  Apply/Detach toggle keyed off that section rather than the actual group
  relationship, so "Detach" on a view-scoped list was a no-op that looked
  broken. BIND9-only, and both surfaces say so when the group runs another
  driver. **Found on the way:** the agent never renders `acl {}`
  definitions at all — `DNSAcl` rows are stored and editable but the bundle
  ships only `{id, name}` and the agent renderer ignores it, so naming an
  ACL in a view would leave an undefined symbol and stop the group
  converging. Named ACLs were therefore rejected in a view's match-list
  with a 422 saying why, until
  [#899](https://github.com/spatiumnorth/spatiumddi/issues/899) made them real.

<a id="issue-894"></a>
#### **Blocklist feed wildcard semantics are per-list** (#894)

- ✅ [**Blocklist feed wildcard semantics are per-list**](https://github.com/spatiumnorth/spatiumddi/issues/894)
  — #878 made every feed row `is_wildcard=True`, right for all 19
  catalog sources but a global constant, and wrong for a host-specific
  threat-intel feed. Now `DNSBlockList.feed_entries_are_wildcard`
  (migration `c8a3f207e51b`, defaults true so nothing changes for
  existing lists), a checkbox on the list form, and an optional
  `entries_are_wildcard` key on a catalog source. **Flipping it
  restamps the rows already imported** — the refresh task diffs by
  domain and never revisits an unchanged one, so without that the
  toggle would appear to do nothing until the feed's contents happened
  to churn. Feed rows only: a manual entry's `is_wildcard` is that
  row's own choice. `parse_feed_detailed` also reports how many lines
  arrived `*.`-prefixed, so an apex-only list fed a wildcard-syntax
  feed logs that it is overriding the feed's stated intent instead of
  doing it silently.

<a id="issue-899"></a>
#### **DNS agent never renders `acl {}` definitions** (#899)

- ✅ [**DNS agent never renders `acl {}` definitions**](https://github.com/spatiumnorth/spatiumddi/issues/899)
  — `DNSAcl` rows were stored, listed and editable on the ACLs tab and
  applied to **nothing**: the bundle carried `{id, name}` with no entries
  and the agent's BIND9 renderer emitted no `acl {}` stanza at all (the
  control-plane template that does render one has no production caller).
  Citing an ACL anywhere that reached `named.conf` therefore left an
  undefined symbol — `named-checkconf` fails, the agent declines the
  *whole* bundle, and the group stops converging rather than just that
  statement, which is why #876 had to reject ACL names outright. Now the
  bundle ships entries and the agent renders `acl "<name>" { … };` **above
  `options`** — placement is the correctness property, since BIND resolves
  an `acl` where it is written and a definition below its first use is an
  error, not a forward declaration. The list is emitted
  dependency-ordered (`order_acls_for_render`, a DFS topological sort) so
  a nested reference resolves, and **cycles are refused at the commit**
  with a graph check: `a → b → a` has two individually-legal edges, so
  per-field validation cannot see it. Entry values now go through the same
  gate as a view's `match_clients`, and an entry-less ACL is skipped at
  render because BIND rejects `acl "x" { };`. Global ACLs (`group_id IS
  NULL`) are documented unsupported — nothing creates one and the bundle
  is per-group. **The audit the issue asked for found a second instance of
  the same bug class:** `DNSServerOptions.forward_policy` was settable,
  persisted and shipped, and no `forward` statement was ever rendered — so
  `only` silently behaved as BIND's default `first`, letting queries leak
  past a filtering upstream that an operator had deliberately forced
  everything through. Third field in this class after `allow_transfer`
  (#734); the lesson recorded in `DNS.md` §8.2 is to assert on the
  *rendered config*, not the stored row.

<a id="issue-934"></a>
#### **A DNS server cannot be moved between server groups** (#934)

- ✅ [**A DNS server cannot be moved between server groups**](https://github.com/spatiumnorth/spatiumddi/issues/934)
  — shipped `2026.09.04-1`. Reported in discussion #933 the obvious way: an auto-registered BIND9
  agent lands in `default`, the operator creates the group they actually
  wanted, and the server is stuck there. `ServerUpdate` carried no
  `group_id` and no move endpoint existed, while the DHCP side has had
  `server_group_id` on its update payload since #430 — an asymmetry, not
  a design decision. Now `group_id` on the server PUT, routed through
  `services/dns/server_move.py` rather than the generic setattr loop, and
  a **Server group** picker in the edit modal. No migration, no new table.
  **The move is not a column write**, because a DNS server accumulates
  group-scoped state that becomes false the instant its group changes.
  `DNSServerZoneState` rows and pending `DNSRecordOp`s reference the OLD
  group's zones — left behind, the Zone Sync pill reports convergence for
  zones the server no longer serves, and queued RFC 2136 updates ship to a
  daemon that has never heard of those zones. `config_apply_status` (#882)
  means "the live config is the saved one", so carrying `ok` across a move
  is false at commit; it resets to NULL, which is UNKNOWN and never `ok`.
  The target group's TSIG key is generated if absent, since a group created
  in the UI has never been through agent registration, where that
  generation used to be inlined (now `ensure_group_tsig_key`, shared by
  both paths). Both group channels **and the server's own** are woken — the
  server channel is the load-bearing one, because an agent already parked
  in a long-poll subscribed using its OLD group and a group wake alone
  would never reach it.
  **`is_primary` is the sharp edge, in both directions.** A group with none
  drops every record write to its zones *silently* — a log line, no error
  to the caller — so moving a primary out elects the oldest enabled,
  unpaused survivor. A group with **two** is worse than a wrong pick: the
  catalog-zone producer lookup in `build_config_bundle` used
  `scalar_one_or_none` with no `LIMIT`, so a second primary raises
  `MultipleResultsFound` *inside the agent long-poll* — a 500 that stops
  the whole group converging. So the incoming server is elected in the
  target only when it has none, an existing primary is never demoted, and
  that query was capped defensively. **The election bug this class predicts
  was in the first draft and caught by tests**: the departing server is
  still `group_id == old_group` in-session when the election runs, so
  without an explicit `exclude_id` the query re-elects the very server
  being demoted — the flag stays on a member that has left AND the target
  ends up with two.
  Two refusals. A **name collision** in the target (409 — names are unique
  per group; the constraint would fire anyway, but not say which name).
  And a move that would leave the target **mixed-driver** (422): a group is
  single-driver, which `DNS_DRIVERS.md` §5.1 has always asserted the
  control plane enforces — it does not, it only 422s *later*, at DNSSEC-sign
  or ALIAS time. A move is a new operation with no installs to break, so it
  fails closed rather than manufacturing a state that breaks something
  else afterwards; moving into an *empty* group is always allowed, whatever
  its driver, which is the reported case.
  **The move survives agent re-registration**, which is what makes it an
  operator action rather than a setting the next restart undoes:
  `/register` resolves the row by `agent_id` first, globally, and its
  update branch never writes `group_id`, so a stale `AGENT_GROUP` neither
  drags the server back nor forks a second row. Pinned by a test, and
  `DNS_AGENT.md` now says so where that variable is documented. **The
  appliance path needed the opposite treatment**, found in review: there
  the agent is not configured from its own environment at all — the
  supervisor derives `AGENT_GROUP` *and* the per-role nftables ports from
  `Appliance.assigned_dns_group_id`, so that pointer is repointed by the
  move (only when it names the group being left) and the supervisor
  heartbeat woken. Otherwise the firewall keeps the OLD group's #50
  DoT/DoH/DoQ ports open while the agent listens on the new group's —
  every config file valid, the listener simply unreachable.
  **Three more from review.** The op purge covers `in_flight` as well as
  `pending`: an op already shipped is not finished with, because `ack_op`
  returns a NACKed one to `pending` and that ack can land *after* the move,
  re-queueing an old-group zone's update against the new group's daemon.
  The derived TSIG key name is now folded to a safe identifier — it is
  interpolated verbatim into `key "<name>" { … };`, so a group named
  `edge"; };` made `named-checkconf` reject the file whole and the agent
  decline the entire bundle, the #876 / #899 class again, newly reachable
  because the move generates keys for operator-typed group names
  (sanitised, not refused: the name is derived, and `Edge (DMZ)` is not a
  mistake). And the frontend invalidated only the *source* group's server
  list, so with a 30 s `staleTime` a moved server was invisible in both
  groups if the operator navigated straight to the target.
  **Also fixed, found on the way:** `is_primary` was settable by **no API
  at all**, while three separate comments told operators to flip it "later
  via the API" — including the hint `record_ops` logs when it drops a write
  for want of a primary, i.e. the message shown at the exact moment the
  advice was needed. It is now on `ServerUpdate`, demoting the incumbent
  atomically; clearing the *last* primary is refused (422) rather than
  silently re-creating the footgun create-time auto-election exists to
  prevent. 1 MCP tool (`find_dns_servers`, read-only, default on) — the
  copilot could list server *groups* and had no way to see the servers in
  them, so "which group is ns1 in?" and "which group has no primary?" were
  both unanswerable. Deliberately **no** `propose_move_*` write tool
  (explicit decision per non-negotiable #13): the move re-renders two
  groups' configs, which is the broad-blast-radius shape that guidance says
  to keep off the copilot. Not a feature module (#14) — it extends an
  existing resource rather than adding a top-level family.

<a id="issue-935"></a>
#### **A DNS zone cannot be moved between server groups** (#935)

- ✅ [**A DNS zone cannot be moved between server groups**](https://github.com/spatiumnorth/spatiumddi/issues/935)
  — shipped `2026.09.04-1`. The other half of discussion #933, and a much sharper tool than the
  #934 server move. A server carries state *about* a group; a zone
  carries references *into* one — `DNSView`, `DNSTSIGKey`, `DNSAcl`,
  `DNSPool` are all group-scoped. Preview → commit at
  `POST …/zones/{id}/move/{preview,commit}`, service in
  `services/dns/zone_move.py`, Move button on the zone detail. No
  migration.
  **The design turns on one property: clearing a view WIDENS exposure.**
  Under split-horizon a record with `view_id` set renders in exactly that
  view; one with NULL is *shared* and renders in **every** view
  (`pool_geo.records_for_view`). So dropping a reference the target cannot
  resolve does not remove the zone from a view, it adds it to all of them —
  a zone that answered only on `internal` starts answering on `external`,
  with no operator-visible symptom. Views and TSIG keys therefore remap
  **by name** (a view called `internal` in each group is the operator's own
  statement that the two mean the same thing), and where they cannot, the
  move refuses until the widening is acknowledged. The issue text as filed
  had this wrong — it treated clearing as a neutral tidy-up.
  **Three acknowledgements, each its own checkbox** rather than one blanket
  "I understand", or the DNSSEC warning gets accepted by someone who only
  read the view one: `view_widening`; `dnssec_rollover` (the private keys
  live on the *current* group's servers and do not move, so the target
  signs from scratch and the DS at the registrar is wrong until
  republished); `lost_update_grants` (a grant naming a TSIG key absent from
  the target cannot be kept — `num_nonnulls(tsig_key_id, ip_cidr) = 1`
  forbids clearing the key — so the row is deleted, which fails *closed*,
  the safe direction, but not silently). Plus the zone name typed back, as
  the IPAM block move takes a typed CIDR.
  **The collision check runs against the RESOLVED view.** The constraint is
  `(group_id, view_id, name)`, so a zone whose view is cleared lands at
  `(target, NULL, name)` and can collide with an unviewed zone a
  `(group, name)` check would have missed — while the same name in two
  different views is not a collision at all, which is the entire point of
  split-horizon.
  Pools follow the zone (attached by `zone_id`, health-checked from the
  control plane rather than the group's agents); per-server zone state and
  queued ops are purged; a driver change **warns rather than refuses**,
  unlike the server move, because a zone is data and BIND9 → PowerDNS is a
  legitimate migration.
  **Eight findings from /code-review, all confirmed, and they clustered:**
  the move reassigned `group_id` but skipped validations every *other* path
  into a group performs. An integration-owned zone could be moved out from
  under its reconciler; agentless groups (`windows_dns` / cloud /
  `technitium_api`) were driven at neither end, leaving the zone live and
  unmanaged on the old server and absent from the new (now create-first,
  so a failure leaves it in both places rather than in neither); a signed
  zone could land on a group that cannot sign and read as signed forever
  while served unsigned; a named ACL the target does not define becomes an
  undefined symbol that makes BIND reject the file *whole*, stopping the
  entire target group — and the module docstring had claimed `DNSAcl` was
  handled when it was never imported; a forwarders-less forward zone could
  reach a Technitium group (the #743 failure). Plus: the DNSSEC purge left
  `dnssec_ds_records` stale, so the UI would name a DS for keys no server
  holds (now `clear_dnssec_key_state`, the helper every other flag-off path
  uses); and the view-remap SELECT was soft-delete filtered, so a deleted
  record kept a source-group `view_id` — whose test then caught the fix
  going into the plan scan but not the commit loop, i.e. the preview
  counting rows the commit did not rewrite. The two new refusals are
  deliberately **not** acknowledgement-waivable: an acknowledgement is for
  a consequence the operator can see and accept, and neither of those
  leaves a state they could inspect afterwards.
  1 MCP tool (`preview_dns_zone_move`, read-only, default on) —
  deliberately **no** commit tool per non-negotiable #13, since the
  operation's safety rests on a human reading three consequences and typing
  the zone name back, none of which survives being driven from a chat
  window.

<a id="issue-986"></a>
#### **Zone name scope — classify zones by TLD against the IANA root list** (#986)

- ✅ [**Zone name scope — classify zones by TLD against the IANA root list**](https://github.com/spatiumnorth/spatiumddi/issues/986)
  — shipped `2026.10.02-1`: `validate_fqdn` said a zone name was *syntactically* a domain and stopped,
  so `corp.example.com`, `ad.contoso.local`, `lab` and `acme.lan` rendered
  identically — while the first is a name the public internet resolves, the
  second collides with mDNS, and the last two sit on TLDs nobody has
  delegated. Now four scopes (`reverse` / `reserved` / `public` /
  `undelegated`) from `services/dns/name_scope.py`, surfaced as a pill +
  filter in the zone table, an icon on the zone detail, a live hint under the
  name field, a column on every importer preview, and a field on
  `list_dns_zones`. **Derived at serialisation, no column** — so it changes on
  its own when IANA delegates a TLD.
  **The evaluation order is the design.** Reverse is tested first because
  `.arpa` IS a delegated TLD, so `10.in-addr.arpa` would otherwise read as
  *Public* — and those zones are always ours (#41 auto-creates them), so they
  must not read as *Private* either. Reserved precedes public because
  `example.com` sits under a delegated TLD and is still reserved. Matching is
  label-wise, never `endswith`: `mylocal` is not under `.local`.
  **Nothing refuses anything** — Microsoft told a generation of admins to
  build AD on `.local`, so it is an amber pill and a tooltip, never a 422.
  `.lan` / `.intranet` / `.private` are deliberately **not** reserved: SSAC
  considered them and did not protect them, so saying otherwise would tell an
  operator they are safe when they are exactly as unprotected as a typo.
  Two sources, one answer: the list bundled with each release
  (`app/data/iana_tlds.json`, regenerated by `make tld-registry`) and a
  one-row `tld_registry_snapshot` an operator fills from Settings → DNS
  (migration `b6f2c04a71d8`). **The snapshot wins only when NEWER** — the
  other direction would make an upgrade lose TLDs to a year-old stored copy.
  Postgres not disk, the #886 reasoning. No scheduled fetch (#17); the
  on-demand call is in `PRIVACY.md` §3.2 and sends nothing.
  **The download guard is the load-bearing part:** under 1,000 entries, or
  missing `com`/`net`/`org`/`arpa`, is a 502 that writes nothing — storing a
  truncated payload would relabel every public zone in the estate as
  *Undelegated* in one action, with no error anywhere. The release script and
  the product share **one** parser rather than two copies of that guard (the
  #878 class), pinned by a test that asserts both resolve to the same source
  function. The special-use table is never overridable by a download: it
  changes by RFC and by ICANN action, and the script refuses to run without
  it. Also: a Domain (#85) with no registry behind it no longer queries RDAP and
  reports "unreachable" forever — it sits at `whois_state="n/a"`, mirroring a
  private ASN, which also stops an internal-only name like `corp.lan` being
  sent to a public registry every 24 h. **That gate is deliberately not the
  bundled TLD list**: `reserved` / `reverse` are settled locally, but
  `undelegated` defers to IANA's LIVE RDAP bootstrap, or a TLD delegated after
  the release was cut would be frozen at `n/a` forever with `domain_expiring`
  alerts on data that never refreshes. An unreachable bootstrap is distinct
  from "no registry" and falls through to the lookup — the other way round
  marks the whole estate `n/a` in one tick. No new MCP tool (#13 — one field on
  an existing read) and not a feature module (#14).


### Future ideas — categorised (added 2026.04.26) — DHCP-specific (shipped bodies)

<a id="issue-52"></a>
#### **DHCPv6 stateful + SLAAC config UI** (#52)

- ✅ [**DHCPv6 stateful + SLAAC config UI**](https://github.com/spatiumnorth/spatiumddi/issues/52) — shipped `2026.06.04-1`: `DHCPScope.v6_address_mode` + `ra_managed_flag` / `ra_other_flag`; the Kea driver renders `subnet6` by mode (stateful → pools + options; stateless / SLAAC → options only). Migration `e4c1a8f63b29`.

<a id="issue-700"></a>
#### **Fingerprint-driven DHCP policy — compile device profiles into Kea client-classes** (#700)

- ✅ [**Fingerprint-driven DHCP policy — compile device profiles into Kea client-classes**](https://github.com/spatiumnorth/spatiumddi/issues/700)
  — shipped `2026.09.04-1`. Device profiling told us what a device *is*; client classes let us treat
  kinds of device differently; nothing joined them. Now `dhcp_device_policy`
  (migration `f3b8d21c74ae`) + `services/dhcp/device_policy.py` compile an
  operator's choice of fingerbank device classes into a real Kea client-class
  `test`, carrying an option set, a per-class `valid-lifetime`, and a stable
  generated class name a pool's `class_restriction` can bind to. NAC-lite with
  no 802.1X and no switch config. 4 REST routes, 2 MCP tools
  (`find_dhcp_device_policies`, `preview_dhcp_device_policy`, both read-only,
  default on), a Device Policies tab. Permissions ride on `dhcp_client_class`
  — a device policy *is* a client class, generated rather than typed — so the
  builtin DHCP Editor role gains **read** with no role migration (writes stay
  superadmin, matching the hand-authored client-class surface rather than
  quietly widening it). Explicitly **not**
  a feature module (non-negotiable #14): it adds no top-level family, and
  "off" is already `enabled=false` on the row.
  **The compiler cannot match the category, and says so.** Fingerbank
  classifies by querying its corpus; Kea has no `device-class == IoT`
  predicate. So it matches *the signatures observed and classified into the
  selected classes* — which makes v1 honestly "classify on first lease, apply
  on renewal", stated in the UI rather than implied away.
  **The load-bearing safety property is ambiguity exclusion.** A parameter
  request list like `1,3,6,15` comes from a doorbell and a rack server alike,
  so a signature seen both inside and outside the selected classes is excluded
  by default, counted and listed — otherwise the headline use ("quarantine
  unknown devices") is also how the CEO's laptop gets quarantined.
  `include_ambiguous` is the audited opt-in. Unclassified devices are
  deliberately *not* treated as ambiguity evidence (that would make the
  feature unusable before a fingerbank key is set) but are reported — and
  only for signatures that survive filtering and the 128-term cap, so the
  count reflects devices the rendered expression actually reaches.
  **Nothing device-controlled reaches the config as a string:** option 60 is
  chosen by the *device*, so both halves of every term are emitted as hex
  (`option[60].hex == 0x4D5346…`), making a vendor class of `' or 1--` inert
  bytes rather than syntax. An absent option 60 compiles to `not
  option[60].exists` rather than being ignored, which would silently widen the
  match to every device sharing the request list.
  **Nine findings from /code-review, all confirmed and fixed**, two of which
  were live 500s. The worst: `Signature` carried `order=True`, whose generated
  `__lt__` compares `None` against `str` the moment two in-class signatures
  agree on option 55 and differ on whether option 60 is present — a
  `TypeError` raised *inside* `build_config_bundle`, i.e. a 500 on the agent
  long-poll that stops the whole group converging. Every fixture happened to
  differ on option 55, which is why the suite was green. Sorting now goes
  through an explicit key that gives absence a defined position. Also: an
  explicit `null` reached NOT NULL columns through `exclude_unset` (500 → now
  422, while a null on a *nullable* field still clears it, which
  `exclude_none` would have broken); the new table was absent from the backup
  catalogue, so a selective `dhcp` restore would TRUNCATE-CASCADE it and never
  repopulate it — a failing test caught that one; `compiled_expression` echoed
  the override, making the documented comparison impossible; the preview GET
  committed `last_compiled_at`, an unaudited write on a `read`-authorised path
  that maintenance mode does not gate (the column was dropped — the only other
  compile site is the bundle build, and stamping there would write on every
  long-poll tick); and the fingerprint scan ran once per policy per tick
  instead of once per bundle.
  **Validated against a live fingerbank key**, which corrected a wrong
  assumption carried by the issue text and the first draft of the docs: there
  is no plain `Printer` or `IoT` class. Fingerbank's `device_class` is its own
  taxonomy at mixed granularity — real observed values are `HP Print Server`
  (score 89), `Operating System` (78), `Generic Android` (60),
  `Hardware Manufacturer` (29), `Generic IoT` (15). The last of those is the
  interesting one: a low score means fingerbank *failed* to identify the
  device and fell back to the MAC vendor, so that class groups unrelated
  hardware and is a poor policy target however plausible the name reads in a
  list. `fingerbank_score` was already stored and surfaced nowhere, so the
  class picker now shows it per class and flags anything under 30, and the
  compiler warns when the best score among matched devices is below that.
  **Two fail-closed rules, both about the same Kea behaviour:** a class with
  no `test` matches *every* packet, so a policy compiling to nothing is
  dropped rather than rendered testless (in both renderers), and `text_to_hex`
  returns None for empty rather than emitting `0x`, which is a parse error
  that fails the WHOLE config. Kea's parser is *not* the term-cap constraint
  (1024 terms / 32 KB loads fine) — per-packet cost and legibility are, and
  hitting the cap is reported, never silent. Every expression form was
  validated against a live kea-dhcp4 3.0.3, and the end-to-end path
  (REST → bundle → wire → agent → on-disk `kea-dhcp4.conf`) was walked on the
  dev stack rather than reasoned about. **v4-only by construction** — options
  55/60 are DHCPv4 codes, and the v6 branch of both renderers builds its class
  list from generic client classes alone. **Deferred:** auto-creating the
  quarantine pool, DHCPv6, and rules keyed on fingerbank device *name*.

<a id="issue-1110"></a>
#### **Windows DHCP failover relationships — two Windows members of one group no longer serve a scope uncoordinated** (#1110)

- ✅ [**Windows DHCP failover relationships — two Windows members of one group no longer serve a scope uncoordinated**](https://github.com/spatiumnorth/spatiumddi/issues/1110)
  — **shipped `2026.10.02-1`; only live verification against a real
  failover pair remains.** The write-through sent every scope / pool /
  reservation write to EVERY Windows member of a group, create-or-update,
  so a new scope landed on both servers and an edit to a scope one server
  held CREATED it on the other: two DHCP servers, one range, no
  coordination, both writes reporting success. Now
  `get_failover_relationships` (`Get-DhcpServerv4Failover`, shared secret
  never selected) and per-server scope presence are recorded by the
  existing topology poll (`dhcp_failover_relationship` +
  `dhcp_server_scope_state`, freshness per server on `DHCPServer`;
  migration `8e317fdd5b12`), and one pure classifier —
  `services/dhcp/windows_failover.classify_serving`, verdicts
  `single_server` / `failover` / `failover_one_sided` / `split_scope` /
  `uncoordinated` / `unknown` / `not_on_windows` — feeds the write-through
  (from a live probe), the poll, two REST views
  (`GET /dhcp/{server-groups,scopes}/{id}/failover`), 1 MCP tool
  (`find_dhcp_failover_relationships`, default on) and the default-on
  `dhcp_scope_uncoordinated` alert rule, so a refusal, a badge and an alarm
  cannot disagree. Two holders are a pair when both report a relationship
  of the same NAME covering the scope, so no `PartnerServer`-vs-host
  matching is needed.
  **On 2+ Windows members** a scope write goes to the current holders only,
  update-only — the no-create check runs in the same PowerShell as the
  write. A NEW scope goes to ONE member by its `windows_placement` (into a
  relationship — created on one side, then `Add-DhcpServerv4FailoverScope`
  copies it to the partner — or on one server only; with none, the one
  shared relationship, else 422). Activating an uncoordinated shared scope
  is 422. Deleting a failover-pair scope goes out of the relationship first;
  a partner outside the group is 409. Writes that would make a split
  scope's halves overlap (a new range, a removed exclusion) are simulated
  and refused. Kea + Windows in one group is refused at server create /
  move (Kea HA cannot coordinate with Windows failover); an existing mixed
  group is reported uncoordinated.
  **Deliberately NOT the issue's "write one partner, let Windows
  replicate"**: Windows failover syncs LEASES, not CONFIGURATION (option
  values, exclusions, reservations need `Invoke-DhcpServerv4FailoverReplication`),
  so one partner would go stale; Microsoft's IPAM writes both, and so does
  this. Replication is an explicit operator action instead.
  **Phase 2 — managing relationships** (`services/dhcp/windows_failover_manage.py`,
  routes under `/dhcp/server-groups/{id}/failover/relationships`,
  superadmin): create / edit / delete, add / remove scopes, replicate.
  Imperative, not desired-state — no new table; each action runs one cmdlet
  and re-reads. Every such cmdlet acts on both partners from the server it
  runs on, so it needs the **CredSSP** WinRM transport (the second hop) —
  anything else is 422 before sending. `requests-credssp` added for it,
  which also fixes CredSSP having been offered in the UI and broken on
  every call. Where a cmdlet runs is what it does: create/add copies from
  the holder, remove/delete deletes the partner's copy (caller picks the
  keeper), a share or role is the running side's value (an edit names the
  side). One-script-per-op: the first cut encoded to ~12,700 chars against
  WinRM's 7,800 budget; a test pins every op under it. No `propose_*` (#13):
  these create/delete partner scopes and carry the shared secret, which is
  never stored, logged or audited.
  **Also fixed:** the poll's per-member merge undid itself on drifted
  partners every tick (one reconcile owner per shared scope now — lowest
  name among views fresher than 15 min — others compared by config hash);
  `purge_lease` / expiry sweep / Kea release tore down a shared IPAM mirror
  + DDNS while a peer still leased the address (`peer_holds_active_lease`);
  and the Kea lease-event handler keyed its maps on raw `IPv4Address` vs
  string, so every renewal INSERTED a duplicate `dhcp_lease` row and a
  release never found a stored mirror. See `WINDOWS.md` §3,
  `DHCP_DRIVERS.md` §4. **Not yet verified against a live failover pair**:
  the JSON shape of `Get-DhcpServerv4Failover`, its no-relationships
  behaviour, whether `DHCP Users` may run it, and the management cmdlets
  over CredSSP; unreadable = unknown, never "none". The `kerberos` WinRM
  transport had the same missing-library problem CredSSP had and is no
  longer offered — see #1128 below.


### Future ideas — categorised (added 2026.04.26) — Operational tooling (shipped bodies)

<a id="issue-57"></a>
#### **Maintenance mode** (#57)

- ✅ [**Maintenance mode**](https://github.com/spatiumnorth/spatiumddi/issues/57) — shipped `2026.06.11-1`: middleware 503s mutating requests during a change window (`Retry-After`, superadmin bypass, agent / auth / health exempt per non-negotiable #5); PlatformSettings-driven, audited, with a global banner + Settings surface. Migration `d1b8f4a92c30`.

<a id="issue-58"></a>
#### **Built-in network tools page** (#58)

- ✅ [**Built-in network tools page**](https://github.com/spatiumnorth/spatiumddi/issues/58) — shipped `2026.06.11-1`: a `/tools` page (ping / traceroute / mtr / dig / whois over sandboxed argv, port-test / TLS-cert over sockets, DNS-propagation, MAC-vendor), permission-gated + Redis rate-limited, with 7 MCP tools.

<a id="issue-59"></a>
#### **PCAP capture trigger** (#59)

- ✅ [**PCAP capture trigger**](https://github.com/spatiumnorth/spatiumddi/issues/59) — shipped `2026.06.15-1`: on-demand tcpdump as an RBAC-gated/audited Tools page, both server-container and appliance-host (real-NIC) vantages, keep-partial-on-Stop, `.pcap` download, 4 Operator Copilot tools.

<a id="issue-61"></a>
#### **Config-drift report (full record diff)** (#61)

- ✅ [**Config-drift report (full record diff)**](https://github.com/spatiumnorth/spatiumddi/issues/61) — **backend shipped `2026.06.11-1`**: `GET …/zones/{id}/drift` AXFRs the live zone from every server in the group and diffs it against the DB — extra-on-server (manual host change) / missing-on-server / in-sync, per server, read-only — plus a `find_dns_zone_drift` MCP tool. **UI shipped `2026.07.30-1` (#735)** — a Drift tab on the zone detail, fetched on demand because one call fans out an AXFR to every server in the group. That PR also fixed the reason nothing had ever consumed the endpoint: `dns.query.xfr` takes an IP *literal* and raises a bare, message-less `ValueError` for a hostname before sending a packet, so every hostname-addressed server failed 100% of the time reporting `""` as the error. **[#734](https://github.com/spatiumnorth/spatiumddi/issues/734) closed the last gap** — agent-managed BIND9 / Technitium reached the server but got `REFUSED`, because the control plane transferred unsigned while the agent granted `allow-transfer` only to the group key and only on *dynamic* zones; separately, `DNSServerOptions.allow_transfer` and `DNSZone.allow_transfer` were both settable, persisted and **never rendered at all** (a silent no-op). Now: the shared AXFR helper takes an optional `TsigKey`, `resolve_group_transfer_key` picks the same key the agent granted (legacy group key first, then operator `DNSTSIGKey` rows by name — matching the bundle's ordering, which is why `op_keys` is now `order_by(name)`), the BIND9 agent renders the grant in the **options** block so it covers every zone type, Technitium falls back to `Allow` + `zoneTransferTsigKeyNames` (verified against upstream `DnsServer.cs`: the two gates AND, so naming keys makes a signature *required*), and a keyless group reports `unsupported` naming the missing key instead of a misleading ACL error. Windows Path A is deliberately excluded from `AXFR_TSIG_DRIVERS` — it authorises by address, so signing would break a working pull. **Drift now works on every driver except PowerDNS**, which implements no record pull.

<a id="issue-875"></a>
#### **Support bundle** (#875)

- ✅ [**Support bundle**](https://github.com/spatiumnorth/spatiumddi/issues/875)
  — platform-wide scrubbed diagnostics export at
  `POST /system/support-bundle{,/preview,/decode-map}`
  (`backend/app/services/support_bundle/`), superadmin + audited, and
  working on **all three deployment shapes** — the appliance-only
  `/appliance/diagnostics/bundle` it supersedes 503s on compose and
  plain k8s because its pod-log and self-test halves go through kubeapi.
  **Research finding that shaped the design:** GitHub has no private
  channel for this. Attachment URLs on a public repo follow *repository*
  visibility, and deleting the comment does not purge the file — so the
  answer is scrubbing, not secrecy. **Two tiers:** secrets (Fernet,
  bcrypt/argon2, PEM, JWT, PSK, TSIG) are **hard-excluded in every
  mode** including the unscrubbed one, matched by field name *and* value
  shape; identifiers (IPs / hostnames / MACs / usernames) are
  pseudonymised HMAC-deterministically off `SECRET_KEY` so mappings are
  stable per install and unguessable outside it. Topology survives —
  same /24 → same synthetic /24 with the host octet kept; zone and
  subdomain grouping preserved. Synthetic v4 lands in **240.0.0.0/6,
  not sos's CGNAT range**, because #42 makes CGNAT a real modelled thing
  here and obfuscating into it would read as genuine. The IPv6 interface
  ID is **discarded rather than mapped** — SLAAC embeds the MAC (RFC
  4291), so preserving it would route hardware identity past the MAC
  scrubber. Decode map is a separate endpoint, **never in the archive**.
  A last-chance `safety_net` sweeps the assembled text and *reports*
  what it caught, because a net firing means a collector has a bug.
  **Two bugs found building it, both about failure isolation:** a
  collector that swallows its own DB error leaves PostgreSQL in
  "transaction is aborted" so every *later* section fails and the bundle
  blames the wrong ones — every guarded query now runs in its own
  SAVEPOINT, as does every section. 1 MCP tool
  (`get_support_bundle_preview`, default **off**). No feature-module
  gate: an ops primitive like backup. **Deferred:** true streaming (a
  zip's central directory is written last, so it needs a third-party
  writer — bounded by per-section + 48 MB caps instead) and a CLI
  fallback for a host that cannot serve HTTP.

<a id="issue-882"></a>
#### **Agents never read the `previous.json` they write** (#882)

- ✅ [**Agents never read the `previous.json` they write**](https://github.com/spatiumnorth/spatiumddi/issues/882)
  — non-negotiable #5's cached config protects against a *dead* control
  plane; this closes the other half, a *wrong* one. All three agents
  (DNS / DHCP / looking-glass) gain `config_apply.py`: an `ApplyStatus`
  reported on the heartbeat and a persisted `Quarantine` so a failed etag
  is not re-applied every poll (the long-poll's 12 s wake tick + 2 s
  fallback made a bad bundle a re-render *loop*, not one failure). The
  agent parks on the failing etag — the long-poll then blocks on a 304,
  costing nothing — and retries on a 60 s → 5 min → 15 min ladder so a
  *transient* failure still self-heals.
  **The rotation was the actual bug.** `previous.json` was written on
  every *fetch*, so it meant "the bundle before this one", not "the last
  one that worked" — identical only while every apply succeeds, which is
  the case it does not exist for. Worse, it destroyed the fallback in two
  poll cycles: a failing bundle leaves the etag unadvanced, so the next
  poll re-fetches the *same* bundle and rotates it, now known-bad, over
  the only good config on disk. `previous` is now written by an explicit
  `commit_config` that **refuses to run if `current` is not the bundle
  that applied**.
  Apply is phased (render → validate → swap/reload) and the phase picks
  the recovery: BIND validates into `rendered.new`, so a
  `named-checkconf` failure never reached `named` and re-rendering would
  bounce a healthy daemon to reach the state it is already in. Kea is the
  mirror image — `config-test` rejects without touching the running
  server, but the refused document is already at `kea_config_path`, which
  is what Kea reads on its next start, so that one always rewrites the
  files. Only Kea's *rejected* is a verdict about the config;
  *socket-unreachable* is not, and reverting there would discard a good
  bundle because Kea happened to be restarting.
  **Four latent bugs found on the way, all of the "written, never read"
  class the #899 audit named.** (1) `daemon` and `config` were declared
  on the DNS + DHCP heartbeat request models and read by **neither
  handler** — the degraded verdict agents already computed was discarded
  at the door; the LG agent's `daemon_status` was set by its sync loop and
  never even put on the wire. (2) A config **Kea refused** was reported as
  a success: the loop advanced its etag, called `_record_success()`,
  logged `dhcp_config_applied` and stamped the K8s readiness marker.
  (3) `named-checkconf` writes its diagnostics — with the line number —
  to **stdout**, and `validate()` read only stderr, so the error was
  always the empty string `"named-checkconf failed: "`. Harmless while it
  went nowhere; now it is the operator's only explanation. (4) The
  supervisor audit the issue asked for: `maybe_fire_console_mode`
  bypassed `_fire_host_config`, so the console-mode plane had none of
  #387's protections — a failing `spatiumddi-verbose-boot-reload` left
  the applied sidecar unchanged, the next heartbeat rewrote the trigger,
  its rename re-fired the `.path` unit, and it repeated every ~30 s
  forever with nothing said upward; that runner's three failure paths
  also left the trigger in place (the #550 pattern, unfixed there).
  Reporting matters more than it sounds: a reverted agent keeps serving
  and keeps heartbeating, so `status`, the health check and `last_seen_at`
  all read normal while the saved zone or scope is live nowhere. Verdict
  → `{dns_server,dhcp_server,looking_glass_collector}.config_apply_*`
  (migration `e9c2d47b1a63`, partial index on the failing states only),
  a chip + detail banner, the default-**on** `agent_config_rejected` alert
  rule (severity from the agent's own verdict — `reverted` is a warning,
  `revert_failed` / `no_previous` critical), and 1 MCP tool
  (`find_agents_with_config_failures`). NULL means UNKNOWN, never `ok` —
  an agent too old to report is exactly where a silent revert would hide.
  **Deferred:** the `tz-status` / `verbose-boot-status` sidecars carry a
  failure *reason* nothing reads (`host_config_health` reports only that a
  plane is unapplied); and `DNSServerOptions.allow_query` is interpolated
  into `named.conf` unvalidated — a third instance of the #876/#899
  class, used deliberately here as the E2E fault-injection lever.

<a id="issue-1077"></a>
#### **Agents spool and replay what they collect during a control-plane outage** (#1077)

- ✅ [**Agents spool and replay what they collect during a control-plane outage**](https://github.com/spatiumnorth/spatiumddi/issues/1077)
  — shipped `2026.10.02-1`: the *reporting* half of non-negotiable #5. Every shipper
  used to drop a batch the control plane refused, from in-memory buffers an
  agent restart emptied, so a maintenance window lost its query logs, DHCP
  activity, metrics and — the correctness hole — Kea lease events, the only
  way the control plane learns about agent-managed leases. Now each agent
  keeps a byte-capped on-disk spool per stream (`AGENT_SPOOL_MAX_BYTES`,
  default 256 MiB, oldest trimmed; log streams also age-capped at 24 h) and
  drains it in order on reconnect, and the DHCP agent reconciles leases from
  a full Kea snapshot after each start and recovery. **Replay is made safe
  server-side**: every batch-ingest endpoint claims the batch's `batch_id` in
  `agent_ingest_receipt` in the same transaction as its rows
  (`services/agents/ingest_receipt.py`, one helper for all nine), so a batch
  whose response was lost comes back `duplicate` and inserts nothing — which
  is what let DNS metrics switch from overwrite to accumulate (#980's jitter
  collision, DNS side) without a replay double-counting. Log ingest skips
  lines already past the 24 h retention. Spool state rides the heartbeat to
  `{dns,dhcp}_server.spool_status` (NULL = unknown) → server-row chip, the
  default-on `agent_spool_trimmed` alert (critical when lease events were
  trimmed) and `find_agents_with_spool_backlog`. Receipts are their own
  volatile backup section on purpose: restored without the rows they vouch
  for, they would turn a replay into silent loss. Migration `c5e8a1f3d027`.

<a id="issue-890"></a>
#### **Service restart from the GUI** (#890)

- ✅ [**Service restart from the GUI**](https://github.com/spatiumnorth/spatiumddi/issues/890) — shipped `2026.09.04-1`, closing the #111 gap on
  docker-compose and Helm, where the appliance's pod restart had no
  equivalent. One surface at **Admin → Platform Insights → Services**
  over `app/services/service_control/` (`backends` / `compose` / `kube`),
  `GET|POST /system/services*`, opt-in RBAC in
  `charts/spatiumddi` + `k8s/service-control/`, and 2 MCP tools
  (`find_services` default on, `propose_restart_service` default **off**
  per non-negotiable #13). No migration — nothing here is persisted
  beyond the audit row.
  **The capability is answered before anything is attempted**, which is
  the design point rather than a nicety: the same 503 used to mean both
  "this deployment cannot do that" and "the daemon is down", and those
  need opposite responses from the operator. `GET /system/services`
  reports the live backend (`kubernetes` / `compose` / `none`), whether
  the gate is open, and the exact toggle to flip — so the UI renders the
  buttons that exist instead of drawing one and learning from its error.
  **The inventory is the allowlist.** An action names a service from the
  listing and is resolved against a *fresh* one server-side, so there is
  no second list to keep in sync and an id that is not currently ours is
  a 404 rather than a string handed to a daemon. On compose the scope is
  the api container's own `com.docker.compose.project` label — needs no
  configuration, cannot be widened by a request, and **fails closed**: a
  container that cannot identify its own project reports the backend
  unavailable rather than falling back to a `spatiumddi-` name prefix,
  which a co-tenant container could match on purpose. On Kubernetes it is
  the api pod's own namespace filtered to `app.kubernetes.io/name` /
  `part-of=spatiumddi`, which is also why the Role carries no
  `resourceNames` (a release-name prefix isn't expressible there, and the
  list would silently omit any workload added later).
  **`start` / `stop` are deliberately absent on Kubernetes.** They would
  mean scaling to zero and back, and restoring the previous replica count
  needs somewhere durable to remember it — a control plane that forgets
  is worse than one that never offered.
  **Restarting the api that serves the page is allowed and flagged.** The
  audit row commits and the 202 returns *before* the daemon is signalled,
  because on compose the container stops the moment the request is
  accepted and signalling inline would abort the response into a
  connection reset; the row records `accepted`, not `success`, since
  nothing survives to observe the outcome. Kubernetes doesn't have the
  problem — a rollout keeps the current pod serving.
  Gate defaults **off** everywhere except the appliance, where
  `appliance_mode` implies it: `POST /appliance/containers/{name}/{action}`
  has shipped the same control since #134, so an opt-in there would take
  a capability away rather than add one. The env gate and the RBAC are
  separate switches on purpose — each failure is reported as itself
  ("enable SERVICE_CONTROL_ENABLED" vs "enable api.serviceControlRBAC")
  rather than as an empty inventory that reads as "nothing to restart".
  **Also fixed on the way:** the Fleet restart was one button hardcoded to
  `deploy/dns-bind9`, so a node running PowerDNS, Technitium or Kea had no
  restart at all — now a picker fed by
  `GET /appliance/appliances/{id}/k8s/workloads` through the supervisor
  proxy (and `StatefulSet` joined the restart endpoint's `kind` union, or
  the picker could list a row that errors on click). And
  `SYSTEM_ADMIN.md` described Start/Stop/Restart across Docker,
  Kubernetes and bare-metal SSH `systemctl`, none of which had been
  written; that section now documents what ships and says plainly that
  the `systemctl` path is not planned.
  **Deferred:** remote *compose*-based agents (legacy pre-#170 installs),
  which have no supervisor to proxy through.


### Future ideas — categorised (added 2026.04.26) — Workflow & RBAC (shipped bodies)

<a id="issue-62"></a>
#### **Approval workflows for risky ops — P1** (#62)

- ✅ [**Approval workflows for risky ops — P1**](https://github.com/spatiumnorth/spatiumddi/issues/62) — shipped `2026.06.25-1`: two-person rule over the 6 delete handlers behind the default-off `governance.approvals` module + a self-governance lock; lifecycle API + Change Requests admin page + 4 MCP tools + Change Approver builtin role. The issue closed on P1, so its P2 scope was re-filed ↓.

<a id="issue-696"></a>
#### **Self-service request portal — IP / subnet / DNS / DHCP requests with approve-and-provision** (#696)

- ✅ [**Self-service request portal — IP / subnet / DNS / DHCP requests with approve-and-provision**](https://github.com/spatiumnorth/spatiumddi/issues/696) — shipped `2026.07.30-1` (#721): the Phase 5 "IP request workflows" item. #62's approval engine pointed the other way: a low-privilege user asks for something they cannot do themselves, an approver reviews it with the operation's own preview, and approving **provisions** it. Deliberately **not** a second state machine — portal rows live in `change_request` under `origin="portal"` and reuse the entire #62 approve spine (FOR UPDATE guard, self-approval block, approver must hold the operation's own permission, re-preview stale guard, `apply()` under the approver, audit rows, expiry sweep), so provisioning behaves identically to a manual create. A catalog allow-list (`services/requests/catalog.py`) maps four kinds onto existing `Operation`s — that allow-list is load-bearing security, because submit intentionally skips the operation's permission check. Behind the default-off `governance.requests` module; new `provisioning_request` permission (`write` + `read`) + `Requester` builtin role; 3 MCP tools. **Auto-approve rules are designed for but not built** — the seam is in `submit_request`. Pairs with multi-tenancy and #64.

<a id="issue-65"></a>
#### **Time-bound permissions** (#65)

- ✅ [**Time-bound permissions**](https://github.com/spatiumnorth/spatiumddi/issues/65) — shipped `2026.06.11-1`: a `time_bound_grant` table of auto-expiring *additive* RBAC grants (`{action, resource_type, resource_id?}` to a group until `expires_at`), consulted live by `user_has_permission` and soft-revoked by a 60 s beat sweep. Migration `d5e9b2c14a07`.


### Future ideas — categorised (added 2026.04.26) — Notifications & external integrations (shipped bodies)

<a id="issue-67"></a>
#### **Ansible dynamic-inventory endpoint** (#67)

- ✅ [**Ansible dynamic-inventory endpoint**](https://github.com/spatiumnorth/spatiumddi/issues/67) — shipped `2026.06.11-1`: `GET /api/v1/ansible/inventory` returns standard Ansible dynamic-inventory JSON built from IPAM — hosts grouped by space / block / subnet / tag / custom-field, with `_meta.hostvars`. Read-only.


### Future ideas — categorised (added 2026.04.26) — Security & compliance (shipped bodies)

<a id="issue-70"></a>
#### **Password policy enforcement** (#70)

- ✅ [**Password policy enforcement**](https://github.com/spatiumnorth/spatiumddi/issues/70) — shipped `2026.05.07-1`: configurable complexity / history / max-age rules applied to every local-auth password set, over seven `platform_settings.password_*` knobs; `password_changed_at` + Fernet-wrapped `password_history_encrypted` on `user`.

<a id="issue-71"></a>
#### **Account lockout after N failed logins** (#71)

- ✅ [**Account lockout after N failed logins**](https://github.com/spatiumnorth/spatiumddi/issues/71) — shipped `2026.05.07-1`: windowed-counter lockout for local-auth users over `user.failed_login_count` / `failed_login_locked_until` / `last_failed_login_at`, reset on any success. Defaults to disabled (`threshold=0`). Migration `a7b3c8d92e14`.

<a id="issue-72"></a>
#### **Active session viewer + force-logout** (#72)

- ✅ [**Active session viewer + force-logout**](https://github.com/spatiumnorth/spatiumddi/issues/72) — shipped `2026.05.07-1`: live JWT registry the operator can browse and revoke from — access tokens carry a `jti`, and `user_session` gains `auth_source` / `last_seen_at` / `revoked` + a `(revoked, expires_at)` index. Migration `c8e4f7a91d36`.

<a id="issue-76"></a>
#### **Internal cert + secret expiry monitoring** (#76)

- ✅ [**Internal cert + secret expiry monitoring**](https://github.com/spatiumnorth/spatiumddi/issues/76) — shipped `2026.06.11-1`: one `secret_expiring` alert rule that fires per internal credential expiring within `threshold_days` — supervisor mTLS certs (`appliance.cert_expires_at`) + API tokens (`api_token.expires_at`). Extended in `2026.06.19-1` to cover the Let's Encrypt Web-UI cert (#438).

<a id="issue-976"></a>
#### **Privacy statement — no telemetry, no analytics, your data stays in your install** (#976)

- ✅ [**Privacy statement — no telemetry, no analytics, your data stays in your install**](https://github.com/spatiumnorth/spatiumddi/issues/976)
  — shipped `2026.10.02-1`: SpatiumDDI has been privacy-first by construction since the first commit
  and said so **nowhere**, so an operator evaluating a platform that will hold
  every hostname, lease and subnet they own had to infer it from the absence of
  a settings page. Now [`docs/PRIVACY.md`](docs/PRIVACY.md) (short form in the
  README, linked from the docs nav, footer and hero), written from a sweep of
  every outbound connection in the tree rather than from a slogan.
  **The release check stays default-on and is disclosed in the first
  paragraph**, not a footnote — the issue's other option was flipping it to
  opt-in so the headline sentence needed no exception. It is an unauthenticated
  GET that carries *nothing* about the install, GitHub is the only party that
  sees it, and an operator who misses a security fix is worse off than one
  whose firewall logged a daily GET; the Settings → Application → Updates toggle that
  closes it now says exactly that instead of being an unlabelled switch.
  **The guard is the deliverable, not the prose.** A statement like this rots
  the first time somebody adds a convenience fetch — it does not go vague, it
  goes *false*. `backend/tests/test_outbound_hosts_documented.py` scans
  `backend/app` for hostname literals and fails until each appears on the page,
  and a second test pins §3.1 to **one** row, because the README
  and the Settings copy both state there is exactly one default-on connection
  and a second would falsify both surfaces at once. Both lists — connections
  *and* non-connections — live in PRIVACY.md rather than in a test allowlist,
  so filing a real endpoint under "not a connection" is a lie a human has to
  type into the document readers actually read. `docs/PRIVACY.md` is a declared
  carve-out in `.github/scripts/ci-backend-must-run.txt`, or deleting a row
  from it would go green (docs/ is denied wholesale). The sweep found six
  hostnames the hand-written issue table missed, which is the argument for the
  guard in one line. See non-negotiable #17.

<a id="issue-972"></a>
#### **E911 dispatchable location — SpatiumDDI as a Location Information Server** (#972)

- 🟡 [**E911 dispatchable location — SpatiumDDI as a Location Information Server**](https://github.com/spatiumnorth/spatiumddi/issues/972)
  — **Phases 1a–3 shipped `2026.10.02-1`.** Given a phone's IP, MAC or LLDP
  chassis+port, answer "which room is this device in, right now?" as a
  dispatchable location. Every input was already in the database, collected for
  IPAM, and nothing joined them: `dhcp_lease` / `ip_mac_history` for IP↔MAC,
  `network_fdb_entry` for MAC↔port, `network_neighbour` for the phone's own LLDP
  claim, `subnet.site_id` for the building, `subnet.subnet_role='voice'` for
  which networks are phones. Behind the default-on `network.e911` module; 3
  tables (migration `c1f4a90e7d63`), 15 REST routes, 3 conformity policies, 3
  MCP tools.
  **RAY BAUM'S Act §506 puts the dispatchable-location duty on the ENTERPRISE**,
  not the carrier — so this is a location *source*: no call routing, no ALI
  upload, no ELIN provisioning, no PSAP, and the docs say plainly that installing
  it does not make anyone compliant. It also never asserts an address is valid on
  its own say-so; validation is the provider's verdict against the MSAG / NG911
  LVF and SpatiumDDI records it.
  **The civic address is 31 separate RFC 5139 columns**, not a string or a JSONB
  blob: PIDF-LO and every provider API want the elements apart, a string cannot
  be decomposed later, and #917 established that an unconstrained object
  publishes as `{"type": "object"}` with no properties — unusable to a generated
  client, on the one field every external consumer reads. `CIVIC_ELEMENTS` holds
  the columns *with* their RFC 4776 CAtype numbers and PIDF-LO tags so the
  deferred option-99 encoder and PIDF-LO renderer cannot drift from the schema
  (#878's two-renderers lesson), pinned by a test.
  **The load-bearing property is that a stale precise answer is worse than a
  fresh coarse one.** A phone re-patched onto another floor stays in the switch's
  FDB on the old port until it ages out, and in *our* copy until the next poll —
  so a port-level answer older than the freshness window (the device's own
  `poll_interval_seconds` × 2, so one missed poll is tolerated and two are not)
  is REFUSED, the resolver degrades to a coarser rule, and the answer reports
  `confidence="degraded"` with the reason. There is no code path returning an
  address with no provenance. Two independent staleness signals: age, and an LLDP
  neighbour on the same port announcing a different chassis-id than the FDB puts
  there — which fires immediately where age must wait out the window, and is the
  only thing that catches a phone swapped for another phone on the same port.
  **Binding precedence is a constant, not a column.** An operator able to reorder
  it could put `site_default` above `switch_port` and send every ambulance to the
  front door while the UI showed a rule for the room; one ERL per target per kind
  is a UNIQUE constraint for the same reason. **The shipped order deviates from
  the issue's**, which numbered the manual pin below `subnet` — that makes the pin
  dead code, since every pinned device is also on some subnet, and reverting the
  constant to the issue's ordering makes `test_a_manual_pin_beats_the_subnet`
  fail, which is the proof rather than the argument.
  Three conformity policies, the first in the tree carrying a real regulatory
  citation (`47 CFR 9.16(b)`) rather than `framework: custom`:
  `e911_voice_subnet_unbound` (the §506 gap; counts the site default as a pass,
  because a check demanding room-level bindings everywhere fails every site on
  day one and gets switched off), `e911_erl_validated` (a REJECTED verdict fails
  harder than a missing one — somebody checked and the answer was no), and
  `e911_port_binding_evidence_fresh` (keyed on the switch's poll state, not on
  stale FDB rows, because an unpolled switch eventually has none and a
  stale-row check would PASS on the worst case). No `propose_*` MCP tools, per
  non-negotiable #13: a wrong binding misroutes an ambulance.
  **Phases 2–3 added the protocol and the provisioning surfaces.** HELD
  (RFC 5985) is mounted at the application root rather than under `/api/v1`,
  because a HELD client is configured with a whole URL and the protocol names the
  path, and it returns PIDF-LO (RFC 4119 + 5139 civic, RFC 5491 geodetic) — which
  is what makes the feature work with **zero phone-side change**, since CUCM,
  Cisco MPP firmware, Webex, RedSky, Intrado and Bandwidth all already speak it.
  `PIDF_ELEMENT_ORDER` is the RFC 5139 *schema sequence*, deliberately not column
  order, and the Geopriv `method` token distinguishes `Wiremap` (a cable was
  traced) from `Manual`. PIDF-LO has nowhere to say "this answer is a fallback",
  so the confidence and the matched rule ride on `X-SpatiumDDI-*` response headers
  instead of being silently dropped.
  **The parser is lxml with `resolve_entities=False`, which is a measured
  correction rather than a preference:** a 4-level internal-entity bomb expands to
  50,000 characters under `xml.etree.ElementTree` (CodeQL `py/xml-bomb` caught the
  first cut, whose docstring asserted the opposite). The document is size-capped, a
  DOCTYPE is refused outright, identities are matched by **local name**, and an
  identity that cannot be resolved is *reported* rather than ignored.
  **Device self-query (RFC 5985 §6) is opt-in and off by default**
  (`E911_SELF_QUERY_ENABLED`): it answers by source address with no credential, so
  it is rate-limited by the one throttle in the tree that fails **CLOSED** — an
  open unauthenticated location oracle is a worse failure than refusing a lookup.
  **DHCP options 99 (RFC 4776) and 123 (RFC 6225)**, IPv4-gated, module-gated and
  batched per bundle. Kea **refuses to override a standard option definition**,
  measured against a live `kea-dhcp4 -t`: 99 must be emitted under Kea's own
  `geoconf-civic` name with no definition of ours, while 123 has none and needs
  one. Getting that backwards does not degrade location, it stops DHCP for every
  client on the server. The encode order puts street, then the dispatchable
  detail, then free text, so an option overflowing 255 bytes drops the free text
  and keeps the room.
  **Both exports refuse rather than mangle.** The civic CSV quotes formula leaders
  (`=` `+` `-` `@`) so a spreadsheet cannot execute a room name, and the IOS
  LLDP-MED snippet **omits** any value it cannot express safely and lists it under
  its stanza instead of truncating — a room silently shortened to `312` is a phone
  in the wrong place that looks correct. Snippets are generated for review;
  writing switch configuration is permanently out of scope.
  **Still open: the provider validation *call* and the push reconcilers**, now one
  issue per vendor —
  [#1048](https://github.com/spatiumnorth/spatiumddi/issues/1048) RedSky Horizon,
  [#1049](https://github.com/spatiumnorth/spatiumddi/issues/1049) Bandwidth 911
  Access, [#1050](https://github.com/spatiumnorth/spatiumddi/issues/1050) Intrado
  ERS. Each is a new **outbound connection** needing a `docs/PRIVACY.md` row under
  non-negotiable #17, and each needs its API shape checked against current vendor
  documentation rather than recalled. **Checked 2026-09-10: none of the three is
  obtainable without a commercial relationship.** RedSky's Provisioning API
  Programmer's Guide is behind their support portal (403); Intrado provisions over
  customer-only SOAP methods its own service guide calls a proprietary API; and
  Bandwidth's public DLR guide — the one readable contract of the three — carries
  **no floor and no room field at all**, only `AddressLine2`. So the single mapping
  that matters, how `FLR` / `ROOM` / `UNIT` collapse into one free-text line, is
  precisely what must be confirmed rather than guessed: a wrong composition still
  pushes a correct street address and still returns success, losing only the
  dispatchable part, which is the whole of §506. Do not implement these from
  recalled field names.
  Also open: **bulk CSV import** of ERLs and bindings (the export exists, the
  reverse does not — the next piece of work here); **`locationURI`** in a HELD
  response, which means minting a dereferenceable unauthenticated URL that hands
  a person's location to whoever holds it, so a request demanding it
  `exact="true"` gets `cannotProvideLiType` rather than a silent substitution;
  **DHCPv6 options 36 / 63**; **Kari's Law on-site notification**, cheap now the
  resolver exists and the thing front-desk staff actually want; **historical
  lookup** for the PSAP callback case, pairing with time-travel
  ([#56](https://github.com/spatiumnorth/spatiumddi/issues/56)); and **wireless**,
  which is a data gap not a design one — the UniFi and Meraki mirrors carry no
  client→AP association, so the `wireless_ap` rule has nothing to match and its
  precedence slot is reserved for when they do. There is deliberately **no
  CER-format export**: CER's columns differ between versions, so the civic CSV is
  what you map into its ERL bulk load rather than a format we claim to track. See
  [`docs/features/E911.md`](docs/features/E911.md).


### Future ideas — categorised (added 2026.04.26) — UX polish (shipped bodies)

<a id="issue-77"></a>
#### **Saved searches / saved views** (#77)

- ✅ [**Saved searches / saved views**](https://github.com/spatiumnorth/spatiumddi/issues/77) — **shipped 2026.06.19-1**: per-user `SavedView(user_id, page, name, payload, is_default)` table + `/api/v1/saved-views` CRUD (scoped by user, audited) behind the default-enabled `ui.saved_views` feature module, 2 read-only MCP tools (`find_saved_views` / `count_saved_views`), and a reusable `SavedViewsMenu` header dropdown (save / load / set-default / delete) wired into the Services / Circuits / Sites list pages. New pages opt in with two props (`currentPayload` + `onApply`).

<a id="issue-81"></a>
#### **Keyboard shortcut help overlay** (#81)

- ✅ [**Keyboard shortcut help overlay**](https://github.com/spatiumnorth/spatiumddi/issues/81)
  — shipped `2026.07.30-1` (#737): `?` opens a modal listing every
  binding, from a new `frontend/src/lib/shortcuts.ts`
  mounted via `Header`. The map is deliberately **load-bearing rather
  than a parallel list** — `GlobalSearch`'s Cmd/Ctrl+K listener matches
  against it and its trigger keycap renders from it, so retuning a combo
  moves the handler, the keycap and the help together. That coupling
  reaches exactly two shortcuts today (Cmd/Ctrl+K, `?`); the other ten
  are flagged `describedOnly` because their handlers live in components
  that don't consult the map, and are the rows that can still drift.
  Note for anyone adding a binding: declare it here and match via
  `matchesShortcut` rather than adding another described-only row.

<a id="issue-82"></a>
#### **Print / PDF export for IPAM tree + subnet detail** (#82)

- ✅ [**Print / PDF export for IPAM tree + subnet detail**](https://github.com/spatiumnorth/spatiumddi/issues/82) — shipped `2026.07.30-1` (#739): `GET /ipam/export.pdf` takes the same scope selector as the CSV/JSON/XLSX exporter (and reuses its `_collect`, so the two can't disagree about the subtree) and renders one of two shapes — a **tree** report for a space / block, or a **detail** report for a subnet. Surfaced as *Print / PDF* in both Export dropdowns. **reportlab, not the weasyprint the issue text proposed** — two reportlab PDFs already ship and a second engine would add Cairo / Pango to every image for no new capability. Unlike #48 and the conformity report, this one paginates: `repeatRows=1` plus a two-pass `_NumberedCanvas` for "Page N of M". Two things worth knowing if you touch it: reportlab's `Paragraph` parses mini-XML, so **all** DB-sourced text must go through `_para()` (an unescaped `a<b>c` space name 500s the export, and `<legacy> net` silently renders as "net"); and the tree indent must stay inside WinAnsiEncoding, or reportlab swaps in ZapfDingbats and nested blocks render as `■■`. Both have regression tests. *(GitHub auto-closed this issue on 2026-06-18 in error — PR [#446](https://github.com/spatiumnorth/spatiumddi/pull/446) said `CodeQL #82`, meaning alert 82. Reopened 2026-07-28, genuinely shipped now.)*

<a id="issue-879"></a>
#### **Global search v2** (#879)

- ✅ [**Global search v2**](https://github.com/spatiumnorth/spatiumddi/issues/879) — all six gaps closed.
  Matching, ranking and gating moved out of the router into
  `backend/app/services/search/` (`ranking` / `providers` / `engine`),
  which the `global_search` MCP tool now calls instead of carrying its
  own copy of the fan-out. Coverage went 7 types → 20 via a
  `SearchProvider` registry that the engine, the scope chips, the MCP
  tool and `GET /search/types` all read from. **Ranking is computed in
  SQL, before each type's `LIMIT`** — the ordering bug was not really
  about order: with no `ORDER BY`, the database returned any N matching
  rows and the exact hit was routinely not among them, which sorting in
  Python afterwards cannot fix. Trigram GIN indexes (migration
  `f4b91d38a70c`) back the leading-wildcard `ILIKE` on the tables that
  actually grow; small tables are left unindexed on purpose. Frontend:
  scope chips, sessionStorage recents, and go-to-page commands sourced
  from the sidebar's own nav tree, extracted to `lib/navigation.ts` so
  the palette can't drift from the sidebar (the `lib/shortcuts.ts`
  argument from #737).
  **Four bugs found on the way, three of them pre-existing.** (1) Search
  applied **no permission filtering at all** — it was the widest read
  surface in the product and the only one that checked nothing, so an
  IPAM-only operator could read DNS zones and records straight out of a
  palette whose `GET /dns/zones` would have 403'd them; the Copilot tool
  had the same hole. (2) The query was interpolated raw into `%…%`, so
  searching `50%` matched every row in every table. (3) The MAC branch
  in the address query was unindexable and sat in an `OR` beside two
  indexed predicates, forcing the whole query to a sequential scan —
  the two working indexes bought nothing until it was normalised.
  (4) `_statement_references` in `app/db.py` called
  `statement.get_final_froms()` once per soft-delete model, ~1.9 ms
  each × 8, i.e. **~16 ms of Python on every ORM SELECT in the
  application** — invisible because it was uniform. Resolving the FROM
  graph once cut a 20-provider fan-out over 500k addresses from 734 ms
  to 93 ms. **Deferred:** an expression index for custom-field values
  (the field name is runtime-chosen, so no trigram index can serve
  `custom_fields ->> 'x' ILIKE …`), and action commands that *do*
  something rather than navigate.

<a id="issue-884"></a>
#### **Native mobile app** (#884)

- 🟡 [**Native mobile app**](https://github.com/spatiumnorth/spatiumddi/issues/884) — PWA groundwork first, then iOS
  (SwiftUI) against the REST API. Non-negotiable #1 means the API is
  already complete enough to build against. The app itself now lives in its
  own repo, **[spatiumnorth/spatiumddi-mobile](https://github.com/spatiumnorth/spatiumddi-mobile)**;
  what remains here is the server side of that split. **Still open:** the app.
  - ✅ [**Enrolment QR code when minting an API token**](https://github.com/spatiumnorth/spatiumddi/issues/906)
    — the reveal-token modal renders a QR in two shapes: the bare token, or
    `spatiumddi://enrol?host=…&port=…&scheme=…&token=…&fingerprint=…`, both
    of which the mobile client already parses (so the URI is a **contract
    with another repo**, not a local convention). Typing a token across
    devices was the worst step in mobile sign-in, and worse than annoying:
    an operator who cannot paste cleanly emails it to themselves.
    **The fingerprint is the point.** A self-hosted control plane presents a
    private-CA or self-signed cert, so the client must ask the operator to
    confirm it — and comparing 64 hex characters by eye on a phone is
    exactly the check people skim. Scanned from inside an authenticated
    session, the comparison becomes machine-checked.
    `GET /api/v1/api-tokens/enrolment-context` answers **only** when
    SpatiumDDI owns TLS termination (an active `ApplianceCertificate`);
    on Compose / plain-k8s an external proxy holds a cert this process has
    never seen, so it returns `null` with a reason rather than guessing — a
    fingerprint disagreeing with the wire would make the client report a
    mismatch on a *correct* setup, training operators to click through the
    one warning the feature exists to make meaningful. **The connection
    comes from `window.location`, not the server**, which behind a proxy or
    split DNS does not know its own external address; the operator can
    correct it, since a laptop on a VPN and a handset on wifi disagree
    routinely. QR hidden behind an explicit reveal and not mounted until
    then — it makes the credential *camera-readable*, which the masked
    string is not. **No new MCP tool**: `find_certificates` already returns
    `fingerprint_sha256`, so a second surface would be redundant (explicit
    decision per non-negotiable #13); no feature module, since this extends
    an existing resource rather than adding a top-level family.
    **This is also where the frontend got its first test runner.** vitest
    was added because the QR is verified by *decoding what it renders* (via
    `jsqr`, dev-only): a transposed row/column or inverted polarity yields a
    code that looks perfectly normal and scans as nothing, which neither
    review nor `tsc` can catch. Cross-checked once against ZXing and segno
    during development. 25 frontend + 7 backend tests; `npm test` runs in
    the existing Frontend Lint CI job. Ships `qrcode-generator` (MIT, zero
    deps, +10 kB gzip).
  - ✅ [**Publish `openapi.json` as a release asset**](https://github.com/spatiumnorth/spatiumddi/issues/903)
    — with the app out of this repo the schema stops being a file a client
    reads off the working tree and becomes the contract *between two repos*,
    so it has to be versioned and fetchable. New `export-openapi` job in
    `release.yml` attaches it to every CalVer tag;
    `scripts/export_openapi.py` + `make openapi VERSION=…` reproduce the
    identical bytes locally and in the client repo's CI.
    **`info.version` was hardcoded `"0.1.0"`** in `create_app()` while
    `settings.version` carried the real one — so every release would have
    published a spec claiming to be 0.1.0, and a generated client would be
    stamped with a version that never changes, defeating the entire point
    of pinning. Fixed at the source, which also means a *running* server
    stops misreporting itself at `/api/docs`. The export must go through
    `app.openapi()` and never `get_openapi`: `create_app()` wraps it to
    widen `HTTPValidationError.detail` to the string form ~270 handlers
    actually return, and re-deriving the document drops that without
    touching a call site — verified present in generated TypeScript as
    `ValidationError[] | string`. `info.title` is pinned to the default
    because it follows the operator-settable `app_title` (#886/#888), so a
    branded install would otherwise publish its own name as the name of the
    public API. **Two footguns found building it:** an *empty* `VERSION`
    env var is not an absent one — pydantic-settings honours `""`, so
    `settings.version` becomes empty and FastAPI asserts on a falsy version
    (`create_app()` now passes `settings.version or "dev"` so a stray empty
    `VERSION` degrades instead of killing the container at import); an
    undefined Make
    variable and an unset `GITHUB_REF_NAME` both produce exactly that. And
    the script only imported `app` because the API image happens to set
    `PYTHONPATH=/app`; run from a plain checkout — the client repo's case —
    Python puts `scripts/` on `sys.path` rather than the cwd, so it now
    self-locates `backend/`. Output is `sort_keys`-canonical so the
    release-to-release diff stays readable; ~3.6 MB (not the "few hundred
    KB" the issue estimated). Retained on every release via the pruner's
    "unknown / future asset" default branch — **do not add a pattern for it
    to `scripts/prune-release-assets.sh`**. The version handshake the issue
    wanted is `GET /api/v1/version` (unauthenticated), **not**
    `/health/platform`, which reports no version at all.
  - ✅ [**API-surface sweep — MCP-only capabilities and untyped responses**](https://github.com/spatiumnorth/spatiumddi/issues/917)
    — shipped `2026.09.04-1`. The five issues the mobile client filed were all one finding: **data the
    server already has that a REST client cannot get, or cannot get typed**.
    Non-negotiable #13 guarantees every REST surface gets MCP tools, and
    nothing guaranteed the converse — the copilot tools are written against
    the *service layer*, so a capability could exist, be reachable from a chat
    window, and be invisible to the only API an external client has. A sweep of
    every registered tool against the route table, all 181 models against
    `backend/app/api/`, and all ~1,058 handlers for response typing found four
    more instances and one systemic gap.
    **Four capabilities given routes**, each sharing one service function with
    its tool so the two cannot answer differently: fleet-wide **lease search +
    lease history** (`GET /dhcp/leases`, `/dhcp/lease-history` — the mobile
    client-lookup screen's own question, "does this MAC have a lease
    *anywhere*", previously one call per server plus a client-side merge that
    is order-sensitive); **IPAM hygiene** (`GET /ipam/reports/hygiene` — the
    three #369 detections on demand, at a threshold the caller picks, rather
    than only as fired alert events at whatever a rule was configured with);
    the **vendor rollup** (`/ipam/reports/vendors{,/devices}`); and the
    **customer decommission summary** (`/customers/{id}/summary` — nine list
    calls collapsed to one). The `mac` filter on `/dhcp/leases` normalises
    separators (`AA-BB-…` / `aabb.ccdd.…` / bare hex all match) and compares
    as `MACADDR` rather than casting to text, which would have been
    non-sargable and defeated `ix_dhcp_lease_server_mac` on the endpoint's
    flagship query. Also `GET /alerts/events` gained
    `subject_type` / `subject_id` / `severity`, so a per-resource alert panel
    no longer pulls 1,000 events and filters client-side.
    **The systemic gap was response typing.** ~113 handlers returned a bare
    `dict`, publishing an unconstrained object — and annotating `-> dict[str,
    Any]` does *not* help, because FastAPI infers a response model from the
    return annotation and the inferred one is still `{"type": "object"}` with
    no properties. That detail matters: the first cut of the guard checked
    `route.response_model is not None` and reported **zero** findings while
    every one of those routes stayed unusable to a generator, so detection runs
    against the generated document instead. ~22 routes were typed (the reports
    #917 named, plus shared `StatusResponse` / `BulkDeleteResponse` for the
    sync-trigger and bulk-delete shapes that were identical in six places), and
    `scripts/lint_untyped_routes.py` + a checked-in baseline of the remaining
    91 stops the set growing — the `lint_migrations.py` pattern.
    **Two bugs found on the way.** `enrich_leases` extraction surfaced that the
    per-server lease route's INET/MACADDR `field_validator` would have been
    lost by a naive copy (it exists because the first `windows_dhcp` lease
    500'd the list); and the MCP vendor-device lookup ran a `db.get(Subnet, …)`
    **per matching row** — an N+1 that was invisible on a lab estate and is now
    reachable over HTTP, so it became one batched query. 1 MCP tool
    (`find_dhcp_lease_history`) — the only place the sweep found the gap
    pointing the *other* way.
  - ✅ [**The published document is consumable by a code generator**](https://github.com/spatiumnorth/spatiumddi/issues/907)
    — two defects found generating the Swift client against a running control
    plane, both of which break a generated client *silently*: it compiles,
    passes review, and is wrong. (1) FastAPI emits OpenAPI 3.1's nullable
    idiom, `anyOf: [X, {"type": "null"}]`; a generator that cannot model the
    `null` arm **skips the member — which drops the whole property from the
    generated type**, with a warning rather than an error. Measured on this
    document: 3,291 schema properties and 297 query parameters gone, including
    `limit` on list endpoints, so the client could not paginate at all.
    `app.openapi()` now states nullability the other way round
    (`app/core/openapi_compat.py`): the plain schema, with the property out of
    `required` — which is the half that carries it, since 971 of them were
    nullable *and* required. **Request bodies keep their `required`**, though:
    there it is not a description but what the server enforces, so publishing
    a no-default `X | None` field as optional would have a generated client
    omit a key and take a 422 (`ImportedZoneOut.soa`, the one schema in the
    document used in both directions, got the default it should always have
    had, and a test now fails loudly on the next one). **Deliberate trade, written down in `API.md`:**
    the server still *sends* `null` rather than omitting the key, so a strict
    response validator now sees an explicit null the schema no longer admits.
    The alternative (`exclude_none` on responses) changes the wire for every
    existing client to fix a documentation defect, and the validator complaint
    is loud where the generated-code failure is silent. (2) Timestamps went
    out as `datetime.isoformat()` — six fractional digits, or **none at all**
    on a whole second, which is the nastier half: a decoder configured *for*
    fractional seconds fails intermittently, depending on when a row happened
    to be written. 6 of 7 endpoints a client called were undecodable, every
    one of them a 200 OK. Now pinned to RFC 3339 with exactly three digits
    (`app/core/json_datetime.py`), truncated not rounded. **The mechanism is
    the interesting part**: the framework-blessed `Annotated[datetime,
    PlainSerializer(...)]` means editing 714 annotations across 166 files and
    trusting every future model to remember, `json_encoders` is deprecated and
    gone in pydantic v3, and rewriting the rendered body means sniffing every
    string in every response for something date-shaped — mutating opaque
    operator data (a raw BIND query-log line carries a timestamp) and paying a
    second traversal per request. So it wraps
    `pydantic_core.core_schema.datetime_schema`, the one point every
    `datetime` core schema is built through, from `app/__init__.py` — the only
    import site that reliably beats the first model class, since isort would
    reorder the equivalent line in `main.py` below the routers. `install()`
    also patches FastAPI's own encoder table — ordered ahead of the stock
    entry, because `datetime` subclasses a `date` whose encoder is registered
    first — or the wire format would depend on whether a route declared a
    `response_model`. Three response models (`AuditLogResponse`, `SessionRow`,
    `UserResponse`) additionally carried their timestamps as **`str`** filled
    by `isoformat()`, so they published with no `format: date-time` at all;
    now declared `datetime` and serialised like everything else. **One trap found on the
    way, worth more than the rest:** declaring the serialiser's obvious
    `return_schema=str_schema()` rewrites the *serialisation* JSON schema —
    which is the mode FastAPI publishes response models in — so every
    `created_at` in the document silently lost `format: date-time`, trading a
    decode failure for a client that never parses a date at all. Omitted, and
    asserted in both schema modes. Tests assert on the **wire format**, never
    on the patch: the regression worth catching is a future pydantic that
    stops routing through that function.
  - ✅ [**Expose DHCP pool occupancy over REST**](https://github.com/spatiumnorth/spatiumddi/issues/913)
    — shipped `2026.09.04-1`. `services/dhcp/pool_occupancy.py` has computed `assigned` / `total` /
    `free` / `percent` since #339 and **no HTTP route called it**: it was
    reachable only from the `find_dhcp_pool_occupancy` MCP tool and the
    `dhcp_pool_exhaustion` alert evaluator. So "is this pool full?" — the
    first question asked when a client cannot get an address — could only be
    answered by fetching pools, leases and reservations separately and redoing
    the range arithmetic, three round trips and easy to get subtly wrong.
    Now `GET /dhcp/pools/{id}/occupancy` and
    `GET /dhcp/scopes/{id}/pools/occupancy`, the second batching one lease +
    reservation query across every pool — the scope shape is the one that
    matters, since a scope with several pools is where "the scope looks fine"
    hides one exhausted class-restricted pool. **Dynamic pools only** — the
    scope call omits every other type and the per-pool call 422s, because each
    would report a number that is not a fact about it: an `excluded` range is
    never offered to a client, a `reserved` one is *supposed* to approach
    100 % and would render as a red exhaustion bar for doing its job, and a
    `pd` pool (#368) stores its prefix's network address in both range ends as
    NOT NULL placeholders, so the arithmetic yields a one-address pool at 0 %.
    That also keeps this endpoint agreeing with the `dhcp_pool_exhaustion`
    alert evaluator and the `find_dhcp_pool_occupancy` MCP tool, which filter
    the same way — a disagreement between those is precisely how a wrong "the
    pool is fine" is produced. No new MCP tool (explicit decision per
    non-negotiable #13): `find_dhcp_pool_occupancy` answers exactly this, over
    the same pool set.
  - ✅ [**DNS query log has no rcode**](https://github.com/spatiumnorth/spatiumddi/issues/914)
    — shipped `2026.09.04-1`. The log recorded the *question* and nothing about the *answer*, so
    "was it answered, refused or NXDOMAIN?" collapsed into "there is a row"
    or "there is not" — and the most common real outcome, a query that *was*
    answered just not as the user expected, was indistinguishable from one
    that was refused. BIND's `queries` category is request-side by design;
    BIND 9.20's **`responselog`** emits a second category (`responses`)
    carrying the RCODE and the section counts. Routed to the same
    `queries_channel` the shipper already tails, told apart at ingest by
    separator (`: response: ` vs `: query: `, neither expressible in a DNS
    name), and stamped onto the query row it belongs to — matched on client
    address + ephemeral port + qname + qtype, in-batch first and against the
    DB when a batch boundary splits the pair, because that split lands on the
    *same* row every time under load and would be a bias rather than noise.
    An orphan response is dropped, never stored: a row with an outcome and no
    question answers nothing and would double-count every query in the
    analytics the same table feeds. **`answer_count` is carried as well as
    `rcode`** — NOERROR with zero answers is NODATA, a different fault from
    NXDOMAIN that reads identically without it. Opt-in per group
    (`response_log_enabled`, migration `f1c7a92e4b06`) because it roughly
    doubles query-log volume, and **422 when a caller explicitly asks for
    response logging without query logging** rather than accepting a toggle
    whose lines have no channel to go to — while simply turning query logging
    off clears response logging with it, since refusing there would name a
    field the caller never sent and leave no single call that disables query
    logging at all. **NULL means
    UNRECORDED, never NOERROR**, in every surface: `not recorded` in italics
    in the grid, an explicit `UNKNOWN` key in the analytics breakdown (so a
    group with the toggle off shows one honest bar, not an empty panel reading
    as "no failures"), a selectable filter value, and the reason spelled out
    in the copilot tool's own field. Also closes the issue's related gap:
    `GET /dns-threat/rpz/hits` returns the individual blocked lookups behind
    the four rollups, PASSTHRU excluded by default because an explicit ALLOW
    listed among blocks makes a working allowlist read as an infection.
    2 MCP tools (`find_dns_queries`, `find_rpz_hits`).
    **Two bugs found on the way, both of the "written, never read" class the
    #899 audit named.** (1) The agent's BIND9 renderer — what every
    agent-managed server actually runs — never emitted
    `category rpz { queries_channel; };`, so named logged every policy rewrite
    to a category with no channel and #699's whole per-client attribution
    recorded *nothing* on the only path that ships it. The control-plane Jinja
    template has carried the line since #699, which is why review never caught
    it: the code was right in the file nothing renders from. `rpz-passthru`
    was missing too, leaving the exception half dark and the
    `policy != PASSTHRU` filters unreachable. Verified live: a blocked lookup
    that produced no row before now produces one. (2) **`rndc reconfig` does
    not apply `responselog`** — verified against BIND 9.20.26, config swapped
    and reconfig clean, `rndc status` still `response logging is OFF`. It is a
    live switch and reconfig preserves what the server was last told; query
    logging escapes this only by accident of BIND's defaulting (no `querylog`
    statement, so it follows the `queries` category, which a reload *does*
    pick up). Without the explicit `rndc responselog on|off` the agent now
    issues after each structural reload — reading the desired state back off
    the config it just swapped in — the toggle would rewrite `named.conf`,
    pass `named-checkconf`, reload cleanly and produce not one line until the
    daemon was next restarted.

<a id="issue-885"></a>
#### **Login banner** (#885)

- ✅ [**Login banner**](https://github.com/spatiumnorth/spatiumddi/issues/885) · [**custom logo**](https://github.com/spatiumnorth/spatiumddi/issues/886) ·
  [**environment banner**](https://github.com/spatiumnorth/spatiumddi/issues/887) · [**`app_title` wired up**](https://github.com/spatiumnorth/spatiumddi/issues/888)
  — shipped together in PR
  [#892](https://github.com/spatiumnorth/spatiumddi/pull/892): an
  acceptable-use banner on the login screen, an operator-uploaded logo,
  a coloured DEV/TEST/PROD strip, and a real browser/product title
  (`app_title` was previously settable and read by nothing). All four
  ride nine `platform_settings` columns plus a `branding_asset` table;
  migration `d3f8b6c02a41`. The **logo lives in Postgres, not on
  disk** — a node-local file does not propagate across a multi-node
  control plane, the same reasoning as the #296 slot-image mirror.
  New unauthenticated `GET /settings/public` + `/settings/public/logo`
  (ETag + 304), because the login page needs all of this *before* a
  token exists. 1 MCP tool (`find_branding_settings`).

<a id="issue-921"></a>
#### **Conformance-fuzz sweep — undeclared media types, FK 500s, and tools that never ran** (#921)

- ✅ [**Conformance-fuzz sweep — undeclared media types, FK 500s, and tools that
  never ran**](https://github.com/spatiumnorth/spatiumddi/issues/921)
  ([#922](https://github.com/spatiumnorth/spatiumddi/issues/922),
  [#923](https://github.com/spatiumnorth/spatiumddi/issues/923)) — shipped `2026.09.04-1`. Three QA
  reports that turned out to be three *classes*, each fixed at class scope
  with a guard so the set cannot regrow.
  **(#921) `POST /system/support-bundle` served `application/zip` and declared
  only `application/json`.** FastAPI documents a bare `-> Response` as JSON, so
  a generated client and any strict validator reject the *success* path.
  #861 had fixed the three `export.pdf` routes one at a time; sweeping the
  whole surface found **eleven more** — SSE streams (`/ai/chat`,
  `/nmap/scans/{id}/stream`, `/appliance/cluster/health/stream`), backup and
  DNS zone archives, the SAML metadata document, pod logs, upgrade images and
  the pcap download. **The obvious fix only half works**, which is the part
  worth remembering: `responses={200: {"content": {…}}}` *merges* with the
  inferred `application/json` instead of replacing it, so the route quietly
  declares both — the conformance failure goes away while a generator is
  still told the endpoint might return JSON. Replacing it takes
  `response_class` set to a subclass that declares `media_type`
  (`app/core/responses.py`; a bare `Response` or `StreamingResponse` leaves
  it `None` and documents *no* content, which is worse). All seventeen routes
  including #861's three now use it.
  `tests/test_response_media_types.py` compares each handler's own
  `media_type=` against the **generated OpenAPI document** — not
  `route.response_model`, which reports clean while the route stays
  undecodable, the same trap #917's first cut of its guard fell into — and
  fails the spurious-JSON case too.
  **(#922) A dangling foreign key answered an unhandled 500.** #861's global
  handler maps unique violations (23505) and deliberately re-raises everything
  else, on the reasoning that NOT NULL / FK / CHECK means *our* bug and a 4xx
  would both misattribute it and **hide it** from the fuzz's no-5xx assertion.
  That is right about NOT NULL and CHECK and only half right about FK: a
  reference the CLIENT sent is an ordinary client error; the same violation on
  a server-computed value is exactly the bug being protected. The
  discriminator is the value itself — Postgres names it in `DETAIL`, so
  `app/core/integrity_errors.py` answers 422 (missing referent) or 409 (still
  referenced) **only when every offending value appears in what the request
  carried**, and returns None — re-raise, 500 — otherwise, including for the
  half of a composite key the server filled in. Reading the DETAIL is the part
  that is easy to get silently wrong: `IntegrityError.orig` is SQLAlchemy's
  `AsyncAdapt_asyncpg_dbapi` wrapper, which re-exports `sqlstate` but **not**
  `detail` — the asyncpg error carrying it hangs off `__cause__`, and reading
  `orig.detail` alone returns `""` for every error, so the handler looks wired
  up and changes nothing.
  **(#923) Rows the API accepts that break later reads — the read half did not
  reproduce, and running the same program found a different real class.** A
  two-pass whole-API fuzz over ~1,150 routes produced **zero** newly-broken
  reads; every write-side 500 it did find reduced to #922. What it found
  instead was **ten references to columns no model has** — valid Python,
  clean under ruff, and clean under mypy for a specific reason worth knowing:
  `attr-defined` is in `disable_error_code` repo-wide (`backend/pyproject.toml`),
  because roughly thirty of its findings are false positives from
  dynamic-model patterns. So the one check that would name these exactly
  (`"DHCPScope" has no attribute "subnet"; maybe "subnet_id"?`) is off. Each is an
  `AttributeError` the first time its line runs, so the surface answers
  *nothing, for every input*: `DHCPScope.server_group_id` meant a phone
  profile could never be assigned to a scope, so the validation that function
  exists to perform had never once run; `list_dhcp_scopes` /
  `list_dhcp_servers` / `list_dhcp_server_groups` / `list_network_devices`
  had never returned a row since they shipped; and the copilot's
  `create_dhcp_static` operation raised in **both** its preview and its
  apply, so proposing a reservation from chat had never worked either. Two
  more sit in `GET /services/{id}/summary` (`Subnet.ip_block_id` and
  `Subnet.cidr`, really `block_id` / `network`), which 500'd the L3VPN
  summary for any service with a linked subnet. Two guards,
  because neither can see the other's half:
  `tests/test_model_attribute_references.py` walks the AST for the
  `Model.attr` spelling in a query, and `tests/test_ai_tool_execution_smoke.py`
  **executes** every read-only copilot tool, which is the only way to catch
  `row.attr` while building a response dict — half the findings were that
  kind. Each tool runs in its own SAVEPOINT: a failed statement leaves
  Postgres refusing everything until rollback, and rolling the session back
  instead expires the shared objects, so every later tool reports
  `MissingGreenlet` and buries the real finding. It is one test rather than
  300 parametrised ones because the `db_session` fixture truncates every
  mapped table between tests and 300 of those exhausted memory before
  finishing. Stated limit: an empty database exercises each tool's query, not
  every response-row branch — `Subnet.cidr` in `list_platform_health` only
  runs once a subnet passes 80% utilisation, and was found by the manual
  `attr-defined` sweep instead.
  No migration, no new endpoint, no MCP change.

<a id="issue-920"></a>
#### **Agent-managed BIND9 AXFR fails PeerBadKey on operator-key-only groups** (#920)

- ✅ [**Agent-managed BIND9 AXFR fails PeerBadKey on operator-key-only groups**](https://github.com/spatiumnorth/spatiumddi/issues/920)
  — **shipped `2026.10.02-1`**, closed by #1133: drift and Sync with Servers now
  read each zone from the view that holds it. The earlier pass:
  **not reproduced; one real latent defect in that path fixed, and the
  regression case the issue asks for added.** The reported shape — a group
  whose only TSIG material is an operator `DNSTSIGKey`, on a registered
  agent — was built live and verified end to end: the bundle carries operator
  keys, `tsig_keys` is inside the *structural* fingerprint so adding one
  shifts the ETag and converges, the agent renders every bundle key into
  `tsig/ddns.key`, BIND loads keys whether the include sits above or below
  `options` (both tested against a running `named`), `rndc reconfig` **does**
  pick up a key added to an include file — unlike `responselog` in #914 — and
  a signed AXFR returns the zone while a wrong secret answers **BADSIG**, not
  the reported BADKEY. That last distinction is the whole diagnosis: BADKEY
  means named has no definition for the *name*, so a passing "wrong secret is
  rejected" is what proves the key was rendered.
  The real defect found on the way: the `include` for the key file was the one
  path in the BIND9 agent renderer **hardcoded to `/var/lib/spatium-dns-agent`**
  instead of derived from `state_dir`, while zone files, `rndc.key` and the
  DoT/DoH cert all derive from it and `AGENT_STATE_DIR` is an honoured
  override. Under a non-default state dir the key file is written to one place
  and named told to read another — and if anything happens to exist at the
  default path, `named-checkconf` passes, the apply reports **ok**, and named
  holds a stale key set, which is precisely the "apply ok + BADKEY"
  contradiction the issue reports. `live_axfr_check.py` had been working
  around it by rewriting the path; it now asserts on it, and gains the
  operator-key-only case #920 asks for. **Left open by that pass:** the reported failure
  itself, which needs `rndc tsig-list` (or the effective `named.conf` plus
  includes) from an affected node to say what named actually loaded.

<a id="issue-980"></a>
#### **Kea drops relayed DHCP requests before it reads them under CPU pressure** (#980)

- ✅ [**Kea drops relayed DHCP requests before it reads them under CPU pressure**](https://github.com/spatiumnorth/spatiumddi/issues/980)
  — shipped `2026.10.02-1`: a QA report whose *observation* was exact and whose three proposed fixes
  were all wrong, in ways only measurement could show. Reproduced against a
  live kea-dhcp4 3.0.3 rather than reasoned about.
  **The counter the issue asked us to report does not move.** It proposed
  surfacing `pkt4-receive-drop`; measured, a run that lost **9,700** datagrams
  to receive-buffer overflow reported it as **0** for the whole duration —
  it counts packets Kea *read* and discarded, and this loss is the kernel
  discarding them first. The number that moves is the per-socket `sk_drops`
  in `/proc/net/udp`, the same event as the `Udp RcvbufErrors` the reporter
  saw. Both are per-bucket columns on `dhcp_metric_sample`, but only
  `socket_drop` is treated as loss — the DROPPED line, the chip and the
  default-on `dhcp_packets_dropped` rule all read it alone. **`pkt4-receive-drop`
  counts deliberate drops too**: verified, a `DROP` client-class match
  increments it, and a `DROP` class is exactly what the shipped MAC blocklist
  renders, so a rule counting it would fire permanently on a working install.
  **NULL means unmeasured** in every surface, keyed on `socket_drop` alone —
  `receive_drop` always arrives from an upgraded agent, so testing the pair
  would read an unmeasurable server as measured-and-clean.
  **Its two mitigations are dead ends.** `packet-queue-size` 64 → 2048 (32x)
  changed neither throughput nor drops: that queue sits *behind* the receive
  thread. A bigger receive buffer was already known to trade drops for a 34 s
  DORA p50 (#952).
  **What works is the knob nobody named.** Kea sizes its packet-worker pool
  from `hardware_concurrency()` — the MACHINE's CPU count, ignoring the
  cgroup share — so a container limited to 0.20 CPU starts **ten** workers
  that compete, inside that cgroup, with the one thread draining the socket.
  Packets served at 12,000 relayed pkt/s, median of 4: at 0.25 CPU 19,381
  (pool 1) / 11,119 (2) / 6,723 (4); with 4 CPUs and no quota 93,717 /
  73,089 / 55,957. Monotonic, so `kea_thread_pool_size` defaults to **1**
  and existing groups pick it up on upgrade. Deliberately a *resize*, not
  `enable-multi-threading: false`: MT-off makes one thread both receive and
  process (15,170 socket drops where pool 1 had none) and flips
  host-reservation lookup order. **Kea's HA hook does NOT keep independent
  HTTP pools** — `http-listener-threads` / `http-client-threads` default to 0,
  which Kea reads as "same as `thread-pool-size`" (counted: pool=1 → 8 OS
  threads, pool=8 → 29, three pools of N), so the agent pins both to 4 rather
  than let a packet-path fix silently serialise HA peer traffic.
  Second knob `kea_packet_logging` (default **true** = today's behaviour) is
  worth 1.30x when turned off, and is opt-in because it removes two log codes
  an operator can see — the #637 lease-cache call. `kea-dhcpN.dhcpN` is never
  silenced despite looking like the same noise: it also carries
  `DHCP4_OPEN_SOCKETS_FAILED` and the line reporting whether the pool size
  took effect. Pairs with the #983 PSI alert, which names the cause where
  this names the effect.
  **Found on the way:** the metrics ingest *substituted* on a bucket
  collision instead of accumulating, silently discarding roughly one poll in
  forty since #195 — the agent floors `bucket_at` to the minute while its
  interval is 60 s ± 3 s. Migration `c93f1a72e408`. No new MCP tool
  (explicit decision per non-negotiable #13 — `find_dhcp_server_stats`
  answers exactly this question and gained a `packet_loss` block; a
  `propose_*` for the pool size is the broad-blast-radius shape that
  guidance says to keep off the copilot) and not a feature module (#14 — it
  extends an existing resource).

<a id="issue-925"></a>
#### **celery-beat reported unhealthy forever after a slot upgrade** (#925)

- ✅ [**celery-beat reported unhealthy forever after a slot upgrade**](https://github.com/spatiumnorth/spatiumddi/issues/925)
  — shipped `2026.09.04-1`. The rollup was right that something was broken and wrong about what.
  **Beat only *schedules* `beat_tick`; a worker executes it**, so the
  `spatium:beat:heartbeat` key is a round trip and its absence indicts
  either end — while the old detail asserted "beat is stopped", which sent
  the investigation to a pod that was running perfectly.
  **Root cause, reproduced in isolation:** `make_sync_redis` in
  `tasks/heartbeat.py` was **the one Redis caller of fourteen passing no
  timeout at all**. #590 had bounded the sentinel hops but did it *per call
  site*, and this was the site it missed. `REDIS_URL` on a multi-node
  control plane lists sentinels by **per-pod headless DNS** (deliberately —
  a client must reach every sentinel mid-failover), and those names keep
  resolving through the 20–40 s a rebooting node takes to be marked
  NotReady. Measured against an unreachable sentinel: unbounded is **still
  blocked at 60 s** (and past 5 min); bounded returns `MasterNotFoundError`
  in ~28 s. A tick is enqueued every 30 s regardless, so one wedged slot
  per interval takes the default 4-slot pool in **~2 minutes** — which is
  exactly the "still unhealthy after 120 s" the report measured, and why
  *every* periodic job stops, not just the heartbeat.
  **The second half is why it looked like beat's fault:** `inspect ping` is
  answered by the worker's MainProcess pidbox consumer, independent of the
  prefork pool, so a worker with **every** slot blocked still reports
  `celery-workers: ok`. Verified directly against a 2-slot worker holding
  two forever-tasks. Documented as a known limit rather than fixed with an
  `inspect.active()` round trip — `/health/platform` is unauthenticated, so
  every extra broadcast RPC there is amplification an anonymous caller
  controls.
  Fix: the connect timeout is now a **default inside
  `core/redis_client.py`**, because a per-call-site convention is what
  failed; `socket_timeout` is deliberately *not* defaulted, since
  `core/agent_wake` parks a pub/sub read that is supposed to be slow and a
  read timeout would turn the wake bus into a reconnect loop. `beat_tick`
  gains `soft_time_limit` / `time_limit`, both **under** its own 30 s
  interval — a tick allowed to outlive the interval still accumulates one
  occupied slot per interval, just more slowly — sized from measurement
  (walking past one resolving-but-dead sentinel costs ~12.8 s at a 1 s
  connect timeout, far more than the timeout itself because redis-py
  retries internally, so a limit that does not clear it kills the tick just
  before it succeeds). `expires` was tried and **removed in review**: Celery
  stamps it as an absolute time from the *publisher's* clock and the
  *worker* compares it, so a worker running ahead of beat would revoke every
  tick and make the reported symptom permanent — trading the bug for a
  strictly worse one, in exactly the post-reboot window where NTP has not
  converged. Redis errors are swallowed and logged rather than filing a
  diagnostics row every 30 s for the length of an outage.
  The health detail now names both suspects, and a stamp more than 90 s in
  the **future** reads as clock skew instead of as perfectly fresh — the
  plain `age_s > 90` test would have masked a genuinely dead beat behind a
  skewed worker clock. No migration, no new endpoint, no MCP change.

<a id="issue-992"></a>
#### **Appliance role chart never installed since #988 — two Helm releases both claimed the PriorityClasses** (#992)

- ✅ [**Appliance role chart never installed since #988 — two Helm releases both claimed the PriorityClasses**](https://github.com/spatiumnorth/spatiumddi/issues/992)
  — shipped `2026.10.02-1`: the appliance chart is installed **twice per appliance**, under two
  release names, and #988's cluster-scoped PriorityClasses were rendered by
  both. Helm stamps `meta.helm.sh/release-name` on everything it creates and
  refuses an install *whole* when it meets an object owned by another
  release, so every fresh install after #988 had **no role DaemonSet on the
  cluster at all** — assigning DNS or DHCP from Fleet could never produce a
  running pod. Silently: the k3s helm-controller job carries
  `backoffLimit: 1000`, so the release sat `FAILED` while a job retried
  forever and nothing in Fleet reads that.
  **One owner.** `spatium-bootstrap` renders them; it *must* install first,
  since the supervisor that writes the other release does not exist until it
  has. The supervisor's `_build_values` now sets
  `priorityClasses.create: false` + `external: true`.
  **The guard had to change with it**, because `create: false` alone no
  longer means "nothing will create these". It now fails only when the
  classes are also absent from the live cluster (`lookup`), with
  `external: true` as the deterministic assertion for any offline render —
  `lookup` returns empty under `helm template`, which is why the flag has to
  exist rather than the live check being the only test.
  **The template's own comment was the root cause**, asserting the chart was
  "installed exactly once per appliance cluster". It never was.
  **Verified, not assumed** — the issue flagged the upgrade path as unknown:
  `spatiumddi-firstboot`'s `firstboot.done` stamp is *written and never
  read*, so the bootstrap manifest is re-rendered from the running slot's
  baked chart on **every** boot and a slot upgrade re-applies the classes.
  Two CI gates, since neither sees the other's half: charts-lint renders
  **both release shapes** and fails on any cluster-scoped object in both
  (plus a negative control that the guard still fires), and
  `agent/supervisor/tests/test_role_chart_values.py` pins the Python the
  shell script mirrors. No migration.

<a id="issue-993"></a>
#### **Direct kubelet transport (#990) was firewalled shut on every appliance** (#993)

- ✅ [**Direct kubelet transport (#990) was firewalled shut on every appliance**](https://github.com/spatiumnorth/spatiumddi/issues/993)
  — shipped `2026.10.02-1`: the supervisor's `input` chain is `policy drop` and opened 10250 to
  *cluster peers* only, an empty set on a single node, so the rule was not
  emitted at all. A non-hostNetwork api pod reaching its own node's IP
  enters via `cni0` with a pod-CIDR source and traverses INPUT like any LAN
  packet — which is why 6443 (widened to peers ∪ pod ∪ svc) answered from
  the same pod at the same moment. So #983 item 6's end state, dropping the
  broad `nodes/proxy` grant, was unreachable: it would have blanked the
  cluster-health screen on every appliance.
  Now a second rule scopes 10250 to **pod ∪ service** — deliberately *not*
  the operator's `kubeapi_expose_cidrs` allowlist, which exists so someone
  can reach the RBAC-guarded apiserver from the LAN and has no business
  widening an API that serves `/exec`, `/run` and `/attach`. New
  `source_kind="kubelet"`; seeded at seq 25 by migration `d4a9e37b2c15`,
  since the byte-identity contract across the **three** renderers
  (supervisor in-pod, the frozen 2a port, the 3b merge) is on the emitted
  *order*, not just the set.
  The probe's socket timeout drops **6 s → 1.5 s**: the snapshot probes each
  node before it can fall back, so on 3 nodes that first stall was ~18 s and
  the browser gave up first — the api logged the request cancelled
  mid-flight with its DB connection torn down under it.
  **Found on the way:** `test_builtin_seed_matches_migration` compared the
  flat concatenation of every seed migration's policies, which can only
  express a migration adding a whole *policy*. It now folds contributions
  onto the policy they belong to and sorts by `seq` — what has to match is
  the state a fresh DB reaches, not the order the files happen to be listed
  in. A second test covers what folding hides: the in-code list must itself
  be in `seq` order, because `builtin_policy_set` preserves list order while
  `_policy_from_orm` sorts, so an out-of-order entry makes an unseeded DB
  render different bytes from a seeded one.

<a id="issue-994"></a>
#### **Boot cosmetics — a failed console unit and a Warning event on every healthy first boot** (#994)

- ✅ [**Boot cosmetics — a failed console unit and a Warning event on every healthy first boot**](https://github.com/spatiumnorth/spatiumddi/issues/994)
  — shipped `2026.10.02-1`: both make `systemctl --failed` and the events feed lie about a healthy
  node, which is how operators learn to skim past the one that matters.
  `spatium-console@ttyS0` exits 75 when there is no serial device (the
  kernel cmdline carries `console=ttyS0` on every install; most VMs have no
  serial port), and `RestartPreventExitStatus` stopped the loop but left the
  unit `failed` — `SuccessExitStatus=75` records the probe's "nothing to
  render here" verdict as the success it is. Applied to the tty1 twin too:
  75 means the same thing on both and they should not disagree.
  The TLS Secret manifest is now **staged** as `.deferred` and renamed in
  once `kubectl get namespace spatium` succeeds, mirroring the control
  chart's existing deferral, with placement forced on the k3s-never-ready
  path so a slow boot can never strand the appliance's only Web UI cert.
  **The fix the issue proposed was not taken, deliberately:** prepending a
  `kind: Namespace` would put one object in two k3s Addon object sets, and
  wrangler prunes what an addon used to own — so the two would fight over
  the owner annotation on every resync and removing either manifest would
  delete the namespace and everything in it. That is #992's failure shape
  one layer down. Ordering by filename is no answer either: k3s reconciles
  each Addon's contents asynchronously, so lexical order guarantees nothing.

<a id="issue-996"></a>
#### **DNS zone detail clipped its own primary action — eleven header buttons in one row** (#996)

- ✅ [**DNS zone detail clipped its own primary action — eleven header buttons in one row**](https://github.com/spatiumnorth/spatiumddi/issues/996)
  — shipped `2026.10.02-1`: at ~1,460 px with the sidebar open, `+ Add Record` rendered as a `+`
  sliver at the right edge. Folded into `Data ▾` / `Zone ▾` behind a new
  shared `HeaderMenu` (`components/ui/header-menu.tsx`), leaving the shape
  every detail page should read as: `Refresh`, at most two menus, one
  primary action last. Each item keeps its `disabled` state **and its
  `title` reason**; a menu whose items all vanish (a forward zone has
  nothing to import or export) renders nothing rather than a trigger onto an
  empty panel. `+ Add Record` gains a real binding declared in
  `lib/shortcuts.ts`, so it appears in the `?` overlay instead of being
  another `describedOnly` row.
  **The extraction was the bigger half.** `IPAMPage.tsx` alone carried
  **three** hand-rolled copies of the open-state + outside-mousedown dance
  (`SyncMenu`, the subnet `ToolsMenu`, and a generic one confusingly already
  named `HeaderMenu`), and the DNS header was about to be a fourth. All
  three now adapt onto the shared primitive, which also gives them the
  keyboard handling every copy left out.
  Independent of the menus, the header gets `flex-wrap` + `min-w-0 flex-1` +
  `shrink-0` so a narrow window wraps rather than clips — the Wave D
  admin-page rule, applied to the IPAM subnet header too.
  **The audit the issue asked for:** no other detail header is over the
  line. IPAM subnet detail is already `Refresh` + three menus + a primary;
  DHCP scope, DNS server-group and the Fleet drilldown are well under. The
  two IPAM headers that *look* heavy are bulk-selection toolbars whose
  branches are mutually exclusive.
  **This is also the repo's first component test.** `jsdom` +
  `@testing-library/react` are new dev dependencies (not shipped, so no
  `NOTICE` entry) because a keyboard menu's failure modes — an arrow key
  that does not wrap, a disabled item that still takes focus — are invisible
  to review and to `tsc` alike. It earned its keep on the first run, catching
  that `focusItem(0, -1)` lands on the *last* item rather than the first.

<a id="issue-995"></a>
#### **Installer wizard review — 28 fixes in five phases** (#995)

- ✅ [**Installer wizard review — 28 fixes in five phases**](https://github.com/spatiumnorth/spatiumddi/issues/995)
  — shipped `2026.10.02-1`: a review of `spatium-install` (2,723 lines, 19 screens) prompted by a
  fresh install of the #988 ISO. **All five phases landed.** The two items
  that cannot ship without image work — a RAID1 or multipath *install*,
  needing `mdadm` / `multipath-tools` / initramfs changes `mkosi.conf` does
  not carry — moved to
  [#999](https://github.com/spatiumnorth/spatiumddi/issues/999). What shipped
  here is their **refusal**, which is the half that mattered: the picker used
  to offer each PATH of a SAN LUN as a separate disk and let you install to
  one of them. That is not "unsupported", it is an install that looks like it
  worked and has no failover.
  **Three of the ten were silent failures, which is the theme.**
  The **install logs did not survive the reboot** — `INSTALL_LOG`, the bash-xtrace
  `TRACE_LOG` and the launch log all lived on the live ISO's tmpfs and the
  rootfs rsync excludes `/var/log/*`, so the one artefact explaining how a box
  was built was the one artefact the build threw away. Now copied to
  `/var/log/spatiumddi/install/` as the last write before the unmount **and
  from the failure path**, and collected by the support bundle (#875).
  0755/0644, matching every sibling: the api reads them through the
  read-only host-log mount as uid 1000, so the root-only modes the first cut
  used would have made the collector ship a PermissionError instead of the
  logs, on every appliance. A **subdirectory**
  deliberately, not a flat name: the host log dir is bind-mounted into the api
  pod and its collector globs `*.log` non-recursively, so a subdir keeps three
  static files out of the live Logs-tab dropdown *and* out of reach of
  `logrotate`, which would otherwise age the install record out after twelve
  weeks. The bundle reaches it explicitly rather than by widening
  `list_log_sources`, which is the allowlist behind that tab's path-injection
  sanitizer.
  The **UEFI `grub-install` ended in `|| true`**, so on a UEFI-only guest the
  Done screen appeared and the box did not boot. Now `/sys/firmware/efi` says
  how the *live ISO* booted and the matching install is fatal — the other stays
  best-effort, because `--removable` needs no efivars and the ef02 partition is
  laid down regardless, so either can legitimately succeed on the other kind of
  machine. Confirm names the detected mode.
  The **`useradd` failure was swallowed** too, and `mkosi.postinst` sets
  `PermitRootLogin no` — so a bad username produced a box with no way in at all,
  discovered after the reboot with the installer gone. Fatal now, and the
  username is validated at the prompt.
  **The validators are shared, not copied.** `admin_user` (32 chars, Debian's
  `NAME_REGEX`, a reserved-account list) and `timezone` were enforced for the
  preseed path since #581 and by the interactive wizard **not at all**; rather
  than transcribe them into bash, the wizard shells out to
  `spatium-preseed-parse --check-field`, answered above that script's `import
  yaml` so a username prompt cannot fail for want of python3-yaml. A validator
  that cannot *run* is a third answer, distinct from a value that is invalid:
  it accepts and logs loudly, because refusing would let an image defect block
  every install, and the now-fatal `useradd` is the backstop.
  **The timezone rule got stricter on the way**, closing two holes the preseed
  path had: the old check was `os.path.exists` on the interpolated name, and
  the value is interpolated into `ln -sf /usr/share/zoneinfo/$TIMEZONE
  /etc/localtime` — so `../../../etc/passwd` (three levels; it resolves) and
  `America` (a directory) both passed. Now a shape rule runs FIRST so a
  traversal never reaches the filesystem, `isfile` rejects the directories, and
  the `TZif` magic separates a zone from `leapseconds` / `posixrules`, which are
  paths, are files, and are not zones.
  **The device-mapper teardown removed every linear map on the machine**, not
  just the target's — so installing alongside existing storage tore down a
  volume group on another disk. Now a transitive closure from the target's own
  partitions to a fixed point (LVM-on-LUKS gives the LV no direct dependency on
  the disk at all), one dependency level per pass so the emitted order is
  provably outermost-first — `dmsetup remove` refuses a device another map sits
  on. **The seed must exclude `dm-*`**, which the first cut got wrong: `lsblk`
  walks holders unless given `-d`, so seeding from its raw output puts the very
  maps being searched for into the "already known" set, and the function returns
  nothing on precisely the disks it exists for. Caught in review, reproduced
  against a real kernel with real maps — the fixture had modelled
  `lsblk --nodeps`, so eight passing tests were exercising an inert function.
  **And failing to release is a refusal now, not a corruption.** The first cut
  reasoned that unreleased maps would make `wipefs` fail and abort the install
  harmlessly. `wipefs -af` *forces*: measured, it and `sgdisk -Z` both return 0
  on a disk held open by a live map, and only `blockdev --rereadpt` fails, which
  the installer tolerates as advisory. The GPT would be destroyed, the kernel
  would keep the stale partition table, and `mkfs` would write at the old
  offsets. The release is verified explicitly now, before anything is written.
  **Found on the way, and a prerequisite for item 1:** #581 wrapped the password
  prompt in `set +x` and **missed the 8-digit pairing code beside it** — so
  `set -x` wrote it to the trace log that `on_failure` tails 30 lines of to the
  console, and that item 1 would now copy onto disk. A single-use code is spent
  on first boot; a persistent multi-claim code is a standing fleet-join
  credential.
  **`useradd` being fatal needed a pre-wipe gate to go with it**, or a
  reserved-list miss turns a recoverable mistake into an unbootable disk: it
  fires at ~63%, after the wipe and the rsync, on an unattended run with nobody
  watching. The list is a hand-written approximation that misses `_apt` — which
  matches the username regex and comes from a package `mkosi.conf` names
  explicitly. The live ISO's rootfs *is* the target rootfs, so `getent passwd`
  answers exactly and keeps answering as packages change.
  Plus the stale text: the Done screen advertised `http://` (the frontend 301s
  to https), said first boot "pulls the SpatiumDDI container images" (baked
  since #170 Wave A4 — it *imports* them, nothing is downloaded), and showed a
  web login to both roles when an Additional node has no web UI at all. It is
  role-aware now, offers the live DHCP lease rather than `<appliance IP>`, and
  is **sized to its own content and clamped to the terminal** — the old fixed
  24 rows was already over newt's usable area, and an 80x24 serial console is a
  first-class install path here. Confirm no longer promises "api + db + DNS +
  DHCP" that #272 leaves off; the retired "Application install" naming is gone;
  Welcome lists the two questions it omitted; and the backtitle reads
  `APPLIANCE_VERSION` instead of a hardcoded `0.1.0` — the first thing asked
  when an install misbehaves.
  No migration, no new endpoint, no MCP change, no new screen in Phase 1.
  **Phase 2 (items 11–14) changes what the installer ACCEPTS**, so each
  refusal boundary is pinned by a test. The OS account had *no* password
  policy — any non-empty string passed, and it became root's password too.
  Eight characters and not-the-username / not-the-hostname REFUSE;
  everything past that advises, because a prompt that refuses a
  merely-weak password is one an operator routes around with something
  worse they can retype. Validated over **stdin**, never argv. **Root is
  locked by default** now (`passwd -l`, opt-in `--defaultno` checkbox) — a
  behaviour change, but sshd refused root either way and `sudo -i` / `su -`
  / single-user mode all still work, so it removes a console login rather
  than a recovery path. **The control-plane URL is probed before the disk
  is wiped**: `GET /api/v1/version`, because the operator's question is not
  "does something listen there" but "is that MY control plane", and a typo
  landing on another host's web server answers a ping perfectly well;
  Retry / Edit / Continue-anyway, the last one logged. The **pairing code
  is deliberately not probed** — it can only be validated by claiming it,
  and an unauthenticated "is this code valid" endpoint would be an oracle
  for guessing eight digits. And **an Additional node no longer pins k3s
  CIDRs**: k3s compares them against the datastore when a server joins, a
  mismatch is fatal, and `spatium-cluster-join` never removes the drop-in
  — so that screen offered a choice whose only possible effect was to make
  the node's later *promotion* impossible.
  **Phase 3 (items 15–22) adds the questions the wizard never asked.** A
  **pre-flight screen** (CPU / RAM / firmware / disks / per-NIC link state
  / gateway / resolver / clock) that deliberately does **not** probe the
  internet — non-negotiable #17, and an air-gapped install is a normal
  case, not a red line; its clock check catches the dead CMOS battery that
  later breaks TLS and pairing in ways that read as a networking fault.
  **Keyboard layout** applied with `loadkeys` before the password screen
  and persisted to both readers, because on AZERTY the symbols in a good
  password land elsewhere and the login fails later with no explanation.
  **NTP**, pre-filled from the DHCP lease's option 42 and written as a
  chrony `sources.d` file — with the #154 runner now deleting it when
  central config takes over, or the two would silently stack. **SSH keys**
  validated with `ssh-keygen` rather than a regex (a truncated paste is the
  common failure, and a key sshd will not load is worse than no key), with
  password-SSH-off offered only when a key is present and refused outright
  headlessly without one.
  **Four network fixes.** The **interface picker is offered in DHCP mode
  too** and its rows say which cable is plugged in — NetworkManager DHCPs
  every port by default, so a multi-NIC server came up answering on
  whichever replied first; a pinned port needs `autoconnect-priority=100`
  to beat NM's own auto profiles. **Static mode offers the live lease's
  values** as a starting point. **Static IPv6**, where a **link-local
  gateway is accepted** — a router advertising a /64 answers on `fe80::…`,
  so transliterating the v4 in-subnet check would refuse the commonest
  correct answer on every IPv6 network there is. And the **k3s overlap
  check now knows the LAN in DHCP mode**: it only ever knew it for a static
  install, so the check was dead on the path most installs take, including
  for a site whose LAN is `10.42.0.0/16` — the k3s pod default, and the
  exact range it exists for. `--check-preseed` still does not probe,
  because the linting workstation's lease says nothing about the
  appliance's future LAN.
  **Phases 4 + 5** add the reinstall the layout was designed for (`/var`
  and STATE kept, both OS slots replaced — promised in a partition-table
  comment since #276 and never implemented), the stable `by-id` disk name
  in the picker / Confirm / log / STATE, a progress bar that moves during
  the rsync, a Confirm screen that is a **menu of fields** so correcting
  the hostname no longer means walking Back past four screens, an export
  of the answers as a #549 preseed (secrets deliberately absent, and the
  export is round-tripped through the real linter in all four
  role × network shapes), and a **post-install verification** pass — ESP
  bootloader, a `grub.cfg` that parses, grubenv on `slot_a`, a kernel in
  the inactive slot — reported as a warning rather than an abort, because
  the install is complete and the point is that the operator learns
  before the reboot rather than after it.
  **~180 new appliance tests** (the suite went 276 → 460), and the ones that
  matter most execute rather than
  grep: the device-mapper closure runs against stubbed `lsblk`/`dmsetup` with a
  second disk present as the negative control, because the failure mode of
  getting it wrong is destroying someone else's data and a structural
  string-match would not catch an inverted comparison. Every guard was run
  against the unpatched script — and the fixture itself was the thing that had
  to be fixed first, since it modelled an `lsblk` that does not exist.

<a id="issue-1001"></a>
#### **Three host runners discard their piped input — `python3 -` reads the program from stdin** (#1001)

- ✅ [**Three host runners discard their piped input — `python3 -` reads the program from stdin**](https://github.com/spatiumnorth/spatiumddi/issues/1001)
  — shipped `2026.10.02-1`: one bug, three call sites, and the blast radius was decided entirely by
  whichever `except` clause each site happened to have. `python3 -` means
  *read the program from stdin*, so `printf … | python3 - … <<'PYEOF'` has the
  pipe and the heredoc both claiming fd 0; under bash the heredoc, being the
  later redirection, wins outright and the piped data is discarded.
  **The one that matters failed OPEN.** `spatiumddi-ssh-reload` renders the
  nftables drop-in that scopes the SSH port to the operator's networks — sshd
  has no native source filter, so that fragment *is* the enforcement. Its
  `except Exception: cidrs = []` turned the discarded JSON into the documented
  empty-list branch, which opens the port unconditionally. Nothing anywhere
  reported a problem: the rule is valid nftables so the #550 `nft -c` dry-run
  passes, the reload succeeds, the applied sidecar reports success, and Fleet
  shows the CIDR list exactly as typed. `spatiumddi-syslog-reload` failed
  closed and loudly instead, so TLS syslog with an operator CA had never
  worked; `spatiumddi-image-prune`'s documented fail-safe
  `except: sys.exit(0)` made pruning silently inert, so the disk-reclaim
  feature had never reclaimed anything and reported success doing it.
  Fixed by passing data as **argv** — what the four correct sites in the same
  tree already do — except in `image-prune`, where the crictl inventory is
  unbounded and goes via a temp file rather than into `ARG_MAX`.
  **The `except Exception` in ssh-reload is gone**, not preserved: a CIDR blob
  that will not parse is not a condition to paper over with "open to
  everyone". Unparseable JSON, a non-list, and a non-empty list yielding no
  usable entry are now refusals; an *absent* list stays the legitimate "any
  source" answer it has always been, and the port-22 accept floor in the
  firewall renderer keeps a default install reachable while the operator
  fixes it. Rendering goes to a temp file first, so a refusal cannot leave a
  truncated fragment where the real rule used to be.
  Two of the three swallowed the exception, so **the guard asserts on the
  rendered artefact, not the exit code** (#899's lesson) — it extracts the
  real command line plus heredoc out of each shipped script and runs it under
  bash, so it tests the bytes that ship. Plus a structural sweep that fails
  any `| python3 -` opening a heredoc, and any `python3 -` heredoc whose body
  reads `sys.stdin`; both catch the shape rather than the symptom, since the
  symptom is different at all three sites. Every guard was run against the
  unpatched scripts and fails there. No migration, no API change.
  **The apply order changed with the refusal**, found by /code-review: both
  paths that can now abort — the renderer's, and the `nft -c -f` dry-run that
  could always refuse a malformed CIDR — ran *after* the sshd drop-in was
  installed. `fail` exits before `reload_sshd`, so the running daemon keeps
  the old port and nothing looks wrong, while the installed config has already
  moved it: the next sshd start or reboot is the lockout, long after the log
  line explaining it. The fragment is the only thing that opens a non-22 port,
  so it is now staged, installed and validated *first*, and an abort leaves
  the port untouched. Opening a port before anything listens on it is
  harmless; the reverse is not.
  **Found on the way, and left deliberately unfixed:** the allowlist has a
  SECOND, independent reason for doing nothing, and it is the default case.
  `/etc/nftables.conf` emits an unconditional `tcp dport 22 accept` in its
  management floor *above* the include glob that pulls the drop-in in, and
  nftables is first-match-wins — verified against a real kernel, both rules
  loaded, the unconditional one listed first. So the scoped rule only bites
  once SSH is moved off 22. That floor is the un-removable recovery channel
  that keeps a bad Web-UI source restriction from bricking the appliance;
  the Web UI resolves the same collision by *retiring* its unconditional
  accept when a scope is set (`webui_action`), and doing that for SSH would
  make a wrong CIDR a console-only recovery — a behaviour decision, not a bug
  fix, and so out of scope here; filed as
  [#1009](https://github.com/spatiumnorth/spatiumddi/issues/1009). Stated in the
  CHANGELOG and pinned by a test that fails if the ordering ever changes
  without the note moving with it.

<a id="issue-1002"></a>
#### **Blanking the installer's Time source did not disable NTP** (#1002)

- ✅ [**Blanking the installer's Time source did not disable NTP**](https://github.com/spatiumnorth/spatiumddi/issues/1002)
  — shipped `2026.10.02-1`: Debian's `/etc/chrony/chrony.conf` carries its own `pool` directive and
  `sourcedir` is additive, so removing the installer's sources file left the
  appliance synchronising against the public Debian pool. Four surfaces said
  "none", including `docs/PRIVACY.md`, which is normative for
  non-negotiable #17 — a false claim about an outbound connection, on the page
  an operator reads to decide what the box talks to.
  **Blank now means none**, in both windows, because they need different
  mechanisms. The installer comments out the `pool` line *and* the
  `/run/chrony-dhcp` sourcedir — marked, line-preserving and exactly
  reversible by stripping the prefix. And the answer reaches
  `platform_settings.ntp_pool_servers` as `[]`, because the #154 chrony plane
  replaces `chrony.conf` wholesale a few minutes into the first boot and would
  otherwise put the pool straight back. That half needed **"declined" and "not
  asked" to stop being the same value** (`NTP_EXPLICITLY_NONE`, a sentinel
  outside the character set a server name may use) — the #882 NULL-vs-zero
  lesson, in a new place: firstboot reads the STATE config through a `nofail`
  mount, so "the operator answered empty" and "the volume was not up yet" both
  arrived as `""`, and recording the wrong one loses what they typed.
  Suppressing the DHCP sourcedir is deliberate: the prompt PRE-FILLS the field
  with the servers the lease offered, so clearing it rejects exactly those.
  `sources.d` and `conf.d` are left in place as the way back.
  **All four of the issue's open questions were settled by measurement**
  against chrony 4.6.1, not reasoned about: `chronyd -p -f` still passes,
  the daemon starts cleanly with zero sources, `chronyc tracking` reports
  `Not synchronised` (honest, and no alert rule reads it), and the edit
  round-trips. One premise in the issue was wrong — chrony *does* have a
  `confdir` on Debian stable — but it is additive like `sourcedir`, so nothing
  dropped into it can retract a `pool` line and the conclusion stands.
  Tests assert on the **rendered on-target config** and on the rendered
  `chrony.conf` body, which is what the issue asked for: every one of the four
  wrong surfaces was prose, and prose is what nothing checks.

<a id="issue-1004"></a>
#### **Change Password accepted a password the server then refused** (#1004)

- ✅ [**Change Password accepted a password the server then refused**](https://github.com/spatiumnorth/spatiumddi/issues/1004)
  — shipped `2026.10.02-1`: two minimums were in play on the forced first-login screen, a hardcoded 8
  and the configured 12, and the page reported neither honestly.
  The rule list and the submit gate were computed **separately**: the list
  evaluated five rows, the button checked only the confirm-field mismatch. So
  an 8-character password rendered four green ticks and an enabled button, and
  the browser threw away an answer it had already computed. Both now come from
  one `evaluatePolicy` — that sharing is the fix, not a tidy-up.
  **The wrong answer was worse than the useless one.** Under 8 characters the
  request never reached the handler: the pydantic `field_validator` fired a
  422 whose `detail` is an error **array**, and an array *is* an object in JS,
  so the page's `detail.errors` check read `undefined`, both branches missed,
  and it fell through to "Check your current password and try again". The
  current password was fine. That sent the operator to the wrong field on the
  one screen they cannot navigate away from.
  The hardcoded floor is now non-emptiness, at all three sites (change
  password, admin create user, admin reset) — it exists so a legacy client
  still 422s on empty input, and 1 cannot collide with a policy minimum the
  settings validator clamps to 6..128. A relaxed 6-character policy was
  previously unreachable through the API while the UI offered it.
  Password history renders as a **note**, not a rule: its old test was
  `candidate.length > 0`, so one character ticked it, which is most of why a
  failing password read as four-of-five done.
  **This is the repo's first page-level component test.**
  `lib/password-policy.test.ts` pins the evaluation and
  `pages/ChangePasswordPage.test.tsx` pins the wiring, because the evaluation was never wrong — the gate ignored
  it, and neither review nor `tsc` can see that. It earned its keep
  immediately: `setup(undefined)` silently received the default parameter, so
  the "policy has not loaded" case was asserting nothing until the test failed.

<a id="issue-1005"></a>
#### **Every control-plane first boot wrote a second helm revision** (#1005)

- ✅ [**Every control-plane first boot wrote a second helm revision**](https://github.com/spatiumnorth/spatiumddi/issues/1005)
  — shipped `2026.10.02-1`: helm-controller MERGES a `HelmChartConfig` on top of the same-named
  `HelmChart`, and since #1003 item 4 firstboot renders the same sizing the
  supervisor computes. So the first heartbeat created a CR carrying nothing
  the Chart did not already say: no Deployment changed, but helm recorded
  revision 2 and ran a second helm-install Job.
  `_helmchartconfig_upsert` could not catch it — its idempotence is against
  the CR's own previous body, and on a fresh boot there is none. So the guard
  compares the **effective** values, `deep_merge(chart, config)`, and skips
  when merging the supervisor's keys in leaves them exactly as they are. An
  unreadable Chart falls through to the write, because suppressing a needed
  override is worse than writing a redundant one.
  **Deliberately not create-only**, which /code-review caught the first cut
  being: `chart_bump._patch_image_tag` CREATES this CR carrying only
  `image.tag` to roll the control plane to a new version, so from the next
  heartbeat — at most 30 s later, i.e. mid-upgrade — a create-only guard is
  bypassed and PATCHes every owned key in while the tag-bump apply is still in
  flight. That does not merely fail to remove the redundant write, it moves it
  to the worst possible moment; before #1005 it did not happen at all.
  Skipping stays safe with a Config present precisely because it is a skip:
  nothing is replaced, so `image.tag` cannot be dropped.
  **The guard alone would have been dead code**, which the issue's "two lines"
  estimate did not account for: firstboot rendered every overridden key except
  `frontend.loadBalancerSourceRanges` and `slotImageMirror.enabled`, so the
  comparison never matched. Both now render, and a test executes firstboot's
  actual `_render_control_helmchart` and asserts the merge is a no-op — so a
  future override key that firstboot omits fails loudly instead of silently
  restoring the second revision. Its failure message names the offending keys.

<a id="issue-1009"></a>
#### **SSH source-CIDR allowlist was dead code on port 22** (#1009)

- ✅ [**SSH source-CIDR allowlist was dead code on port 22**](https://github.com/spatiumnorth/spatiumddi/issues/1009)
  — shipped `2026.10.02-1`: the second of the two independent reasons the allowlist did nothing, and
  the one #1001 deliberately left. `/etc/nftables.conf` opened
  `tcp dport 22` unconditionally in its management floor, *above* the
  `include "/etc/nftables.d/*.nft"` glob, and nftables is first-match-wins —
  so a perfectly-rendered scoped rule restricted nothing, while Fleet showed
  the CIDR list exactly as typed. Verified against a real kernel in both
  directions: with the floor present every packet takes it; with it retired,
  every port-22 accept that remains is source-scoped.
  **The design doc had already decided this, differently from the issue.**
  `docs/design/FLEET_FIREWALL.md` §6.1 specifies `firewall_mgmt_cidrs` +
  `firewall_mgmt_lockdown` — the floor becomes scoped only behind an explicit
  second opt-in — and calls the LAN-wide floor the *irreducible recovery
  channel*, which its risk register then names as the mitigation for every
  OTHER firewall risk. Neither field existed in code. So the shipped answer is
  that design under the name `ssh_lockdown`, reusing #157's existing
  `ssh_allowed_source_networks` rather than adding a second CIDR list. It is
  also the pfSense / OPNsense anti-lockout pattern, which is what operators
  already expect.
  **Reading §6.1 closely turns up a contradiction worth knowing about**, now
  annotated in the doc: "the base-conf floor stays LAN-wide regardless" cannot
  hold at the same time as line 192's `OR ip saddr {mgmt} when
  firewall_mgmt_lockdown` — first-match-wins makes the second dead. The floor
  is therefore *retireable*, not un-removable: present by default so §6.1's
  guarantee holds for every install that has not opted in.
  **The mechanism already existed and is reused rather than reinvented.** The
  Web UI's unconditional accept has lived in a retireable sentinel since #769,
  and `spatium-firewall-reload` carries a generic `apply_sentinel_directive`.
  The SSH accept was baked into the base config instead, which is the only
  reason it could not be retired — so it moved to
  `/etc/nftables.d/00-spatium-ssh.nft` and became the third caller.
  **Retiring the sentinel alone is not enough, and the pair has to move
  together**: all three renderers ALSO emit an SSH accept in
  `spatium-role.nft`, which sorts *after* `50-spatium-ssh.nft` in the glob, so
  a packet the scoped rule declined would fall straight through to it. Under
  lockdown that line is emitted source-scoped too, and a test asserts both
  halves so a future edit cannot do one without the other.
  **Nothing tightens on upgrade**: `effective_ssh_scope` — the one place the
  flag is resolved — returns `[]` while lockdown is off, which every consumer
  already reads as "open unconditionally", so an operator who configured the
  list while it was inert is unaffected, and an older host runner that has
  never heard of the flag does the safe thing by construction. Behaviour also
  stops depending on the port number, which was the real defect: post-#1001 it
  enforced on a moved port and not on 22.
  **/code-review found six, and the first re-created the bug one layer down.**
  The ssh bundle's `config_hash` — the only thing that re-fires the host
  runner — was sha256 over the authorized-keys and sshd-config bodies, and the
  scope appears in neither (it is an nftables scope, not an sshd directive).
  Harmless while the scoped rule was dead code; not harmless now: toggling
  lockdown changed the effective scope and nothing else, so the hash was
  unchanged, the trigger never fired, and `50-spatium-ssh.nft` kept its
  UNCONDITIONAL accept — which sorts ahead of the scoped management line —
  while the firewall plane had already retired the floor. SSH open from
  anywhere, every surface reporting it restricted. The hash now covers the
  scope and the port. Also: the UI matched on `err.message`, which on an
  AxiosError is always `Request failed with status code 422` and never the
  FastAPI detail — so the acknowledgement modal could never open and
  `ssh_lockdown_force` was unreachable from the product; removing the last
  CIDR under lockdown left the toggle checked AND disabled, with Save 422ing
  and no way out; the self-lockout pre-flight gated on the resulting state
  rather than the transition, demanding an acknowledgement on every later
  `ssh_*` save; the force flag latched on a save that failed for any other
  reason; and the ordering test sorted its own literals, so it exercised
  `sorted()` and could never catch the rename that would silently un-enforce.
  Two refusals on the way in — enforcing with an empty list (that closes SSH
  from everywhere rather than restricting it, the 422 §6.1 already specified),
  and enforcing from an address the list does not cover, which is advisory
  rather than fatal because browsing the UI from one network and SSHing from
  another is legitimate. That second one reads the same spoofing-resistant
  client IP the login throttle uses, and fails OPEN when the address is
  unknown: it exists to catch a typo, not to be a security control, and a
  pre-flight that blocks on "I could not tell" is one operators learn to force
  past by reflex. Turning lockdown back OFF never needs the acknowledgement —
  that is the recovery path. Migration `e5b1d47a9c62`; 1 field on the existing
  `find_ssh_settings` MCP tool (reported as a pair with the list, since
  "restricted to 10/8" and "would be if enforced" are opposite answers to the
  only question worth asking); no new feature module (#14 — it extends an
  existing resource).

<a id="issue-999"></a>
#### **Storage redundancy — RAID1 + multipath: fleet monitoring, management, and install support** (#999)

- ✅ [**Storage redundancy — RAID1 + multipath: fleet monitoring, management, and
  install support**](https://github.com/spatiumnorth/spatiumddi/issues/999) — shipped `2026.10.02-1`. Split out
  of #995 items 23 + 24, whose *refusal* half shipped there. Three parts, and the
  **ordering is the design point**: monitoring first, install support last.
  **Part A (monitoring) shipped** — `read_storage_health()` in the supervisor,
  the three surfaces, the default-on `appliance_storage_degraded` rule and
  `find_appliance_storage`; no manifest change, no heartbeat field, no migration,
  and array state DERIVED from member counts because the kernel reports
  `array_state=clean` for a mirror down to its last disk. **Part B (management)
  + Part C (install support) shipped** — `mdadm` / `multipath-tools` / `kpartx`
  / `lvm2` in the image, a mirror mode in the picker (`mirror_disk:` preseeds
  it), named arrays with metadata 1.2, two ESPs kept in step by
  `spatiumddi-esp-sync` from every writer, and a Fleet-UI management surface
  over a host runner with the last-good-member / bootloader-member refusals.
  **Hardware-verified 2026-09-08** on a two-disk VM: installs, boots from the
  mirror, and — with one disk detached — boots the survivor in 40 s with all
  four arrays serving `[2/1] [_U]` and `/boot/efi` absent. That test found the
  bug that mattered: `spatium-grub-render`'s `discover_live_uuids()` resolves
  the slot by PARTLABEL, which on a mirror is a `linux_raid_member`, so the
  #395 first-boot re-render overwrote a working `grub.cfg` with the ARRAY's
  UUID — install, boot once, unbootable. Plus `esp-sync`'s missing `-t` and a
  host runner that did not claim its request (level-triggered `PathExistsGlob`
  → start-limit → the path unit itself dead). **Not yet verified: a
  slot-upgrade-then-check-both-ESPs test, and C3 (multipath) has never been run
  against a real SAN.**
  A mirrored root with no degraded-array alarm is a mirror that silently becomes a
  single disk — the operator pays for two disks, the array loses a member at 03:00,
  and the appliance keeps serving perfectly until the survivor dies. That is strictly
  worse than never mirroring, because it displaced the backup discipline they would
  otherwise have kept. So **Part A (monitoring) is a precondition for Part C
  (install), not a follow-on** — and it is also far cheaper: `/proc/mdstat` is a
  kernel interface rather than an mdadm feature, an mpath map is identifiable from
  `/sys/block/dm-*/dm/uuid` exactly as `_disk_hazard()` already does it in the
  installer, and the telemetry rides inside the `cluster_health` dict per the #402
  pattern — no image change, no heartbeat field, no column, no migration.
  Part A: a `read_storage_health()` collector, a chip on the Cluster → Overview node
  cards + a Storage block in the Fleet drilldown + the console Disks row, a default-on
  `appliance_storage_degraded` alert whose severity keys off *redundancy remaining*
  rather than the state string (`2 of 3` is a warning, `1 of 2` is critical, both
  report "degraded"), and 1 read MCP tool. Part B: fail / remove / add / scrub and
  path reinstate over the existing trigger-file host-runner plane, with `mdadm --add`
  carrying the installer's own wipe confirmation (it overwrites the disk it is given)
  and removing the last good member **refused** rather than confirmed. Part C: the
  `mkosi.conf` packages + initramfs, mirror-two-disks in the picker, and the part
  easiest to skip and fatal to skip — **two ESPs kept in sync from the slot-upgrade
  path**, or the mirror boots the old kernel off the surviving disk after an upgrade.

<a id="issue-1031"></a>
#### **Alert forwarding filtered — and rendered — against keys alert payloads never carry** (#1031)

- ✅ [**Alert forwarding filtered — and rendered — against keys alert payloads never carry**](https://github.com/spatiumnorth/spatiumddi/issues/1031)
  — shipped `2026.10.02-1`: three payload shapes go through one delivery path, and only one of them was
  handled. Audit rows carry `result` + `timestamp`; alert events and the AI digest
  carry `severity` + `fired_at`. Everything downstream read the audit keys
  unconditionally, so alerts were mishandled **four ways at once**. The filed bug:
  a target with a `min_severity` set dropped every alert, criticals included, because
  they all bucketed to `info` — the operator configured a filter and silently received
  nothing. **The one that hid it:** a syslog target on `rfc5424_json`, the DEFAULT
  format, received nothing at all, because rendering raised `KeyError: 'timestamp'`
  and `alerts._deliver` catches per-target and logs `alert_deliver_failed`. The other
  two RFC 5424 formats and CEF stamped every alert *informational* on the wire, and
  CEF/LEEF rendered alerts as a content-free `…|audit|audit|3|` line — two different
  alerts indistinguishable in a SIEM. **Nobody noticed because the "Test target"
  button sends an audit-shaped payload with the filter forced off**, so the probe was
  green on a target that could not carry a single real alert; the shape a test
  exercises has to be the shape the feature sends.
  One set of adapters (`_payload_severity` / `_payload_timestamp` /
  `_payload_syslog_severity`) now reconciles the shapes and every renderer plus the
  gate goes through them. Alert severities rank on the same scale as the audit
  buckets, with **`critical` level with `denied` at the top**: `denied` is the
  strictest threshold selectable, and a threshold that silently opts you out of the
  most severe alerts is the same defect one notch narrower. `resource_types` matches
  an alert's `subject_type` for the same reason — the same vocabulary, a different
  key. The audit mappings are **byte-identical**, pinned by a test, because moving
  them moves every line an existing collector already indexes; unrankable severities
  fail OPEN, since silently swallowing one is the bug. **A deliberate behaviour
  change** (CHANGELOG says so plainly): every target with a non-null `min_severity`
  received nothing and now receives whatever clears it. It also revisits #999's
  decision to drop the RAID-scrub finding — `info` is mutable now, but the column
  still defaults to NULL, so a finding quiet only for operators who configured it is
  not quiet, and it stays out. No migration, no new endpoint, no MCP change.
  **Three more from /code-review, all in the SIEM formats.** LEEF 2.0 defines `sev` as an
  integer 1–10, and the newly-added field emitted the word `critical` — not a value QRadar
  can map, so it leaves the event at default severity: the same "the wire says
  informational" defect being fixed for the PRI and for CEF, reintroduced by the fix.
  `_leef_escape` did not escape `^`, the delimiter *this* renderer declares (its comment
  described LEEF's default tab instead), and the diff had just started routing free-form
  text through it — an alert message, or the AI digest's generated summary — where an
  unescaped one splits the record and loses every field after it. **Fixing that broke the
  header**, caught by the pre-existing header test: the DelimiterChar field declares the
  delimiter and is a control character, not a value, so escaping it emitted a
  backslash-caret and told a parser that was the delimiter. And the `subject_type`
  fallback missed the one rule that NAMESPACES its subject — `compliance_change` reports
  `audit:<resource_type>` — so precisely those alerts still failed every `resource_types`
  allowlist, which is the bug the fallback exists to fix surviving in the one rule whose
  subject genuinely is an audited resource.

<a id="issue-1028"></a>
#### **Three build-guard defects that each made a guard useless in its own way** (#1028)

- ✅ [**Three build-guard defects that each made a guard useless in its own way**](https://github.com/spatiumnorth/spatiumddi/issues/1028)
  ([#1029](https://github.com/spatiumnorth/spatiumddi/issues/1029),
  [#1030](https://github.com/spatiumnorth/spatiumddi/issues/1030)) — shipped `2026.10.02-1`: all three found
  while cutting the #999 ISO, and they share a lesson the repo has now recorded four
  times: **a guard that evaluates nothing looks exactly like one that passed.**
  **(#1028)** `appliance-verify-arch` probed with
  `docker image inspect -f '{{.Architecture}}'`, which on Docker Desktop's containerd
  store answers for the HOST platform when the tag is a multi-platform index — so on
  the arm64 cross-build host it reported `arm64` for one image and the **empty
  string** for ten more, every one of them correct amd64 content, and blocked the
  cross-build path on precisely the machine that path exists for. The fix asks for the
  platform explicitly and moved out of the Makefile into
  `appliance/scripts/verify-image-arch.sh` so it could be tested. **The obvious
  one-line fix inverts the guard**, which is the part worth knowing: `--platform`
  exits non-zero for a genuinely wrong-arch image, so bolted onto the old loop's
  `|| continue` it falls through to "not present locally (the bake will pull it)" — a
  silent pass on the one case the guard exists for. Existence is established first,
  and three outcomes are separated: correct, wrong-arch, and an index that *lists* the
  platform without having pulled it (reported, and not counted towards "did we verify
  anything at all"). An older CLI with no `--platform` degrades to the previous
  behaviour and says so.
  **(#1029)** `bake-images.sh`'s staleness guard asked "is this image over 24 h old?",
  which cannot express what it means: a `docker build` that is a complete cache hit
  produces the identical image — same digest, same ID, same `.Created` — so an image
  whose inputs have not changed **can never refresh its own timestamp**. It ages past
  24 h and blocks every bake until somebody passes `--allow-stale-images`, which is
  how a guard stops being read. It now asks "was this built AFTER its inputs last
  moved?", from git: the last commit touching that image's copied paths, plus the mtime
  of anything dirty or untracked under them, because an **uncommitted** edit is the
  commonest shape of "I forgot to rebuild" and a commit-time comparison misses it. On
  this repo it moved in both directions at once — the three DNS images dropped from a
  hard error to a note, and three images built two hours earlier were correctly flagged
  because their sources moved after them, which the wall-clock rule could not see at
  all. The three DNS images deliberately do **not** share one coarse `agent/dns`
  mapping: a `images/bind9/` change would flag powerdns, whose rebuild is a cache hit
  that does not advance `.Created` — a false alarm the operator cannot clear, i.e. this
  bug again. **Stated limit:** a floating base tag rebuilt upstream moves nothing in
  git; the wall-clock check survives as a note saying so.
  **(#1030)** `lint_untyped_routes --check` compared an empty listing against the
  baseline, found no unbaselined route, and printed `OK — 0 untyped route(s), all
  baselined.` So any import-time error in the app — exactly what the guard watches for
  — silently disabled it, and `0` versus `87` was the entire signal with nothing in the
  output naming which one you were reading. It now refuses an empty listing when the
  baseline is not (`--baseline` still accepts one, or the last route could never be
  retired), CI chains with `&&`, and the Makefile stops sending the extraction's stderr
  to `/dev/null` — when it fails, the traceback IS the diagnosis — and stages through a
  temp file so a failed run leaves no empty listing behind. A sweep found no other
  producer/consumer guard with this shape.
  Every one of the three is covered by tests that **execute the shipped script** against
  stubs, and every test was run against the unpatched code first: 27 new appliance
  cases, plus one pre-existing test loosened from pinning a function *name* to pinning
  the *shape* it was really asserting, because #1029's rename had made a correct guard
  report itself as a regression.
  **/code-review found six, and the worst was the fix reproducing the bug class it was
  fixing.** `inputs="$(image_inputs_mtime "$repo")"` is a BARE assignment, which takes the
  command substitution's exit status as its own — and the script runs under `set -e`, so
  rc=1 (no git) and rc=2 (no mapping) killed the whole bake right there instead of
  reaching the `case` fallback, which was therefore dead code while the CHANGELOG
  described it as the safety net. Outside a git repo the bake exited 1 straight after the
  version banner, saying nothing. **The new tests could not see it because the harness
  dropped `-e`** — it hardcoded `set -uo pipefail` instead of reading the script's own
  `set` line, so it ran the shipped bytes in a shell the shipped bytes never meet. That is
  the lesson rather than the shell trivia; the harness now extracts the real options, and
  doing so immediately failed two existing tests for the same reason. Also:
  `verify-image-arch.sh` reported "nothing was verified — run `make build`" AHEAD of the
  wrong-arch verdict, so the flagship case (every image wrong, because `make build` ran
  without `DOCKER_DEFAULT_PLATFORM`) told the operator to do exactly what they had just
  done and never printed the line that fixes it. And an uncommitted *deletion* was skipped
  by `[ -f ] || continue`, leaving an image judged fresh after a source file was removed —
  now resolved from the parent directory's mtime, which `unlink()` updates and which,
  unlike stamping "now", does not make the image permanently stale on every later run.

<a id="issue-1026"></a>
#### **Appliance ISO + upgrade image for arm64 — with an architecture gate on the slot-upgrade path first** (#1026)

- ✅ [**Appliance ISO + upgrade image for arm64 — with an architecture gate on the slot-upgrade path first**](https://github.com/spatiumnorth/spatiumddi/issues/1026)
  — shipped `2026.10.02-1`: three parts, and the ordering is the issue's own: **part 1 (the gate) shipped
  alone**, before any arm64 artifact exists, because it is a correctness fix on the
  x86-64 fleet that already exists rather than a prerequisite for one that does not.
  `appliance_upgrade_image` carried no architecture, and the catalogue,
  `desired_slot_image_url` and `spatium-upgrade-slot` all selected by **version** — so
  the day an arm64 image is published, a per-box schedule or a fleet-wide upgrade can
  hand an amd64 appliance an arm64 root filesystem and nothing notices: the download
  verifies (the SHA matches, it is a perfectly good image), the slot writes, GRUB
  switches, and the node does not come back.
  Now `appliance.architecture` (supervisor `uname -m`, reported on every heartbeat) and
  `appliance_upgrade_image.architecture`, with **two independent gates**. The control
  plane refuses at `stamp_desired_slot_image` — the one chokepoint all three write paths
  already go through, so the check cannot be remembered in two of them and skipped in the
  third — as a `SlotImageResolutionError` subclass, which is why both scheduling
  endpoints answer 422 without either handler learning a new exception; the rolling
  orchestrator catches it per-node instead, so a mixed-architecture fleet upgrades the
  nodes the image fits rather than dying at whichever node was scheduled first. Then
  `spatium-upgrade-slot` re-checks the real decompressed image against the node's own
  `uname -m` and exits 5. **Two gates because the control plane can only refuse what it
  knows** — an operator-pasted external URL tells it nothing — and it must never be the
  only gate on an operation that bricks a node.
  **Two premises in the issue did not survive contact with the artifacts**, and both
  shaped the design. It proposed detecting an image's architecture from the root GPT type
  GUID: there is no GPT. `build-slot-image.sh` extracts the root partition, so a slot
  image is a **bare ext4 filesystem** — verified against a real `.raw.xz`, `53ef` at
  0x438 — inside a non-seekable xz stream. So neither the control plane nor the host
  runner can read a type GUID, and finding `/etc/spatiumddi/appliance-release` in it
  means decompressing ~8 GiB. Hence the split: on import the architecture comes from the
  release asset name (metadata *we* published, not a filename an operator chose — the
  issue's "never from the filename" is about the upload path, where the answer is a
  declared field beside `appliance_version`, which is declared the same way), and the
  host runner reads the file for real, **after the `dd` and before the bootloader** —
  the only window that is both possible and safe, since earlier cannot know and later
  cannot be undone. That ordering is pinned by a structural test, which caught the first
  draft anchoring on `_write_progress("bootloader")` — a progress *label* emitted several
  steps before anything bootable is written.
  **NULL means UNKNOWN and never blocks**, deliberately: every image staged before this
  is amd64 in fact, and a backfill saying so would assert something the row never
  reported, so the first unlabelled arm64 upload would inherit an amd64 claim and pass
  the gate. The Fleet picker disables a mismatched image and names the architecture it
  needs rather than hiding it — an image the operator uploaded a minute ago silently
  missing reads as a broken upload. A release publishing both architectures is now one
  row per architecture (the asset picker keyed by arch, not longest-name-wins, which was
  a coin flip between an image that boots and one that does not), and importing without
  saying which is a 422. Migration `f7c3a91e50b4`, two nullable columns, no backfill; 2
  MCP tools gained the field; no new endpoint.
  **Parts 2 + 3 shipped alongside it.** `mkosi.conf` no longer pins `Architecture`;
  the kernel, GRUB packages and `BiosBootloader` moved to `mkosi.conf.d/` drop-ins
  matched on architecture, with the Makefile always passing `--architecture`
  explicitly — left unset, mkosi defaults to the BUILD HOST, which on an Apple Silicon
  dev box is a silent change to what `make appliance` produces. `release.yml` +
  `nightly.yml` matrix `[amd64, arm64]`, `fail-fast: false`, arm64 on
  `ubuntu-24.04-arm` because mkosi's builder cannot be emulated (#991's
  `mount_setattr(2)` wall).
  **arm64 is UEFI-only by platform, not by simplification** — no i386-pc target, no
  BIOS to chain-load — so the installer lays down no BIOS-boot partition, installs only
  `--target=arm64-efi`, and REFUSES before touching the disk if the machine did not
  boot EFI. **The partition NUMBERING is identical on both**: p1 is absent on arm64
  rather than the rest shifting down, so `partition_node`, `_MD_NAMES`, the #999 mirror
  path and the verification pass need no arch branch at all — the single decision that
  kept this change small. Roots are typed `8305`, looked up per-arch by
  `build-slot-image.sh` and `wrap-iso.sh`; `grub-mkrescue -d` FORCES one platform, or an
  arm64 ISO would silently carry x86 boot paths just because the builder has both
  module sets.
  **The versioned ISO name gained its architecture** — it never had one while the
  stable name always did, which is invisible with one build leg and a filename
  COLLISION with two. The pruner treats the arches as a pair: its `*)` fallthrough
  leaves unknown assets alone, right for a new artifact and exactly wrong for an
  architecture added to the matrix (~3 GB per release nothing reclaims), and a test pins
  its arch list against both workflow matrices.
  **Verified on real hardware** — UTM on an M4, Apple Virtualization, UEFI: ISO boots,
  installer runs, installed system comes up with `root-arm64` partition types, no
  `vda1`, `BOOTAA64.EFI` on the ESP, an `ELF ARM aarch64` k3s, a Ready node on
  `6.12.107+deb13-arm64`, and A/B slot detection working unchanged (it matches on
  PARTLABEL, not the type code — which is *why* it needed no change, and the docstring
  claiming otherwise was corrected). Part 1's host gate was then proven on that box:
  a real ext4 slot claiming `amd64` mounted against a real `uname -m` of `arm64` →
  refused.
  **Three bugs found doing it, all the same shape as the issue itself.** `fetch-k3s.sh`
  keyed its cache on the version alone while the binary path carries no arch, so
  building arm64 then amd64 again SKIPPED and left the ARM binary — an ISO that builds,
  boots, and never starts k3s, with nothing in the log. The post-install check looked
  for `EFI/BOOT/BOOTX64.EFI` and reported a correct arm64 install as FAILED on the one
  screen that says whether to trust the reboot (found on the first real install). And
  the arm64 UEFI refusal, in its first draft, ran at script load — which made `--help`
  and `--check-preseed` exit 1 on any non-EFI arm64 host, including the macOS laptop the
  preseed linter exists to run on; the appliance suite caught it within a minute.

