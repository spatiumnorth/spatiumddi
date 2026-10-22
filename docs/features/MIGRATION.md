# Migration — importing existing DNS + DHCP + IPAM estates

> **One-shot import, not ongoing sync.** These importers exist so an
> operator can load a real DNS / DHCP / IPAM estate into a sandbox
> SpatiumDDI without retyping every zone, record, scope, pool,
> reservation, prefix, and address. Once imported, **SpatiumDDI is the
> source of truth** for the imported objects. There is no
> conflict-resolution loop and no scheduled re-pull. Operators who want
> a running read-only mirror are served by the Windows DNS / Windows
> DHCP Path A drivers and the integration shelf instead.

Three sibling importers share one design — a per-source parser feeding
a shared canonical intermediate representation (IR), then a
source-agnostic two-phase **preview → commit** pipeline. Each lives
behind a togglable feature module so operators who don't need the
surface can hide it (Settings → Features).

The fourth column below is **not** an importer. The Windows cutover
(#756) picks up where they stop — the estate is already in
SpatiumDDI, the Windows server is still the one clients talk to, and
what is left is proving the two agree and then moving the traffic. It
shares the family's superadmin posture, provenance columns and
preview → commit idiom, so it sits in the same table.

| | DNS importer (#128) | DHCP importer (#129) | NetBox / IPAM importer (#36) | Windows cutover (#756) |
|---|---|---|---|---|
| Feature module | `dns.import` | `dhcp.import` | `ipam.import.netbox` | `migration.cutover` |
| Admin surface | DNS Import (sidebar) | DHCP Import (sidebar) | Import → NetBox | Import → Windows cutover |
| Sources | BIND9 archive · Windows DNS live-pull · PowerDNS REST · Technitium REST · Cloud DNS live-pull (Cloudflare / Route 53 / Azure DNS / Google Cloud DNS) | Kea JSON file · Windows DHCP live-pull · ISC `dhcpd.conf` | NetBox REST live-pull (v3.x–4.6+) | live Windows DNS + Windows DHCP over WinRM |
| Target | DNS server group (+ optional view) | DHCP server group (+ IPAM linkage) | native IPAM rows (space / block / subnet / address + VRF / VLAN / Customer / Site) | zones + scopes that already exist here — it creates none |
| Provenance columns | `dns_zone` / `dns_record` `import_source` + `imported_at` | `dhcp_scope` / `dhcp_pool` / `dhcp_static_assignment` / `dhcp_client_class` `import_source` + `imported_at` | IPAM / network rows `import_source` + `imported_at` + `netbox_id` (in `custom_fields` / `tags`) | `dhcp_static_assignment` `import_source="windows_cutover"` + `imported_at` (lease handover only) |
| Conflict actions | skip / overwrite / rename (per zone) | skip / overwrite (per scope) | skip / overwrite (per entity) | — parity report + readiness blockers instead |
| API prefix | `/api/v1/dns/import/{source}/…` | `/api/v1/dhcp/import/{source}/…` | `/api/v1/ipam/import/netbox/…` | `/api/v1/migration/cutover/…` |
| RBAC | superadmin | superadmin | superadmin | superadmin |

The provenance columns are nullable + non-default: pre-existing,
hand-created rows look "not imported" to the matcher, so a re-import
never claims ownership of a row it didn't create.

---

## Shared shape

1. **Configure source.** File upload (BIND9 archive, Kea JSON, ISC
   `dhcpd.conf`) or a connection (a pre-registered Windows server, a
   PowerDNS or Technitium REST endpoint). Plus the **target** — which
   server group the import lands in.
2. **Preview.** `POST …/{source}/preview` parses the source into the
   canonical IR and returns the would-create plan plus per-object
   conflict status. Side-effect-free — no DB writes, no audit rows.
   The operator can re-upload / re-pull while iterating.
3. **Commit.** `POST …/{source}/commit` replays the previewed plan
   (the UI hands the plan back in the request body, so the server stays
   stateless between the two calls) and writes the IR. Each object
   commits in **its own savepoint** — a failure on object N never rolls
   back objects 1..N-1, and the result ledger carries one row per
   attempted object so partial success is visible.

Anything the source carries that SpatiumDDI can't model surfaces in the
preview: per-object `parse_warnings`, a top-level `warnings` list, and
a **"didn't import"** panel (`unsupported`) for whole subsystems we
deliberately don't translate (DNSSEC keys, Kea hook libraries, ISC
failover / TSIG keys, classifier DSL).

The DNS preview also carries a **Scope** column per zone
(`ImportedZoneOut.name_scope`, #986) — *Public* / *Private* /
*Undelegated* / *Reverse*, classified against IANA's root-zone list. A
bulk import is where an estate full of `.lan` zones first becomes
visible, and the preview is the last point before they are committed.
It is advisory: nothing about the scope blocks an import. See
[`DNS.md` §22](DNS.md).

---

## DNS importer (#128)

Five sources, all reducing to canonical `ImportedZone` + `ImportedRecord`:

- **BIND9 archive** — upload a `.zip` / `.tar(.gz|.bz2|.xz)` containing
  `named.conf` + the referenced master files. The parser walks every
  `zone "…" [class] { … }` declaration (including those nested in
  `view {}` blocks), resolves the `file "…"` directive inside the
  archive, and parses each master file. Only class `IN` zones import;
  `hint` / `mirror` / `redirect` / `static-stub` / `delegation-only`
  zones, unquoted zone names and `include`d files are not read, and
  each is named in the preview's warnings. ACL / controls / logging / key declarations
  stay out of scope; DNSSEC records (DNSKEY / RRSIG / NSEC* / DS) are
  stripped with a warning — re-sign post-import via the zone DNSSEC tab.
- **Windows DNS live-pull** — pick a registered `windows_dns` server
  with WinRM credentials; the importer walks `Get-DnsServerZone` +
  `Get-DnsServerResourceRecord`.
- **PowerDNS REST** — paste an API URL + key (read once, never
  persisted); the importer walks `/api/v1/servers/{server}/zones`.
- **Technitium REST** *(issue #744)* — paste a console URL + API token
  (read once, never persisted); the importer walks `/api/zones/list`
  and resolves each zone's full record set. Endpoints are
  `POST /dns/import/technitium/{test-connection,preview,commit}`.
  Two behaviours differ from the PowerDNS source and are deliberate:
  **only `Primary` zones import** — secondary / stub / forwarder /
  catalog zones are reported as warnings, because a secondary is a copy
  of another server's data and importing one would mint rows SpatiumDDI
  then serves authoritatively — and **disabled zones and records are
  skipped** rather than silently re-enabled. Technitium also returns
  structured `rData` whose field names do not match its own *write* API
  and which renders numeric rdata as enum names, so the importer
  inverts that back to wire form — a TLSA whose rdata comes back as
  `DANE-EE` / `SPKI` / `SHA2-256` is stored as `3 1 1 <digest>`.
  Unknown enum members pass through unchanged, so a future Technitium
  release degrades to one odd record rather than an exception mid-import.
- **Cloud DNS live-pull** *(issue #37)* — pick a registered cloud DNS
  server (driver in `{cloudflare, route53, azure_dns, google_dns}`)
  that has its provider credentials configured. The control plane
  pulls every hosted zone + its records through the agentless driver's
  `pull_zones_from_server` / `pull_zone_records` reads — the same
  method names Windows DNS uses, so this source is a near-clone of the
  Windows live-pull. Cloud providers own the SOA + apex NS on their
  side, so the importer applies standards-compliant SOA defaults
  (rewritten from the zone's own `primary_ns` / `admin_email` at push
  time) and surfaces a per-zone warning; a DNSSEC-signed source zone
  warns that signing state isn't imported and must be re-established on
  the destination driver after commit.

Endpoints: `GET /dns/import/cloud/servers` (the credentialled
server picker), `POST /dns/import/cloud/preview`, and
`POST /dns/import/cloud/commit` — same preview → commit shape, same
per-zone conflict actions (below). This is also the engine behind a
cloud DNS server's **Sync from provider** button.

Per-zone conflict actions: **skip** (default — never trample an
existing zone), **overwrite** (delete + recreate), **rename** (create
under an operator-typed FQDN).

**Per-provider provenance.** Unlike the other DNS sources (which stamp
a single `bind9` / `windows_dns` / `powerdns` / `technitium` label), the cloud source
stamps the **provider name** — `cloudflare`, `route53`, `azure_dns`,
or `google_dns` — into every created row's `import_source` column, so
provenance stays queryable per provider. The plan's `source` field
must match the endpoint or the commit is rejected.

**Apex NS (#1892).** The BIND9, PowerDNS and Technitium sources carry the
source server's apex NS (`@ NS tech1.example.`) into the zone's records, and
the group's agents serve those rows as the zone's whole NS set (#1153), so the
managed zone stays delegated to the host it was migrated off and goes lame once
that host is retired. Preview therefore lists, per primary zone, any apex NS
whose target is not a server of the target group (matched on the server's name
or host), in the zone's `foreign_apex_ns` and as a warning. A group with no
servers yet is not compared. Nothing changes unless the operator asks: an apex
NS outside the group can be deliberate, for example a hidden primary whose
public name servers are a provider's. The review step shows the affected zones
with an unticked **Replace them with the target group's servers** box; the
commit API's `apex_ns_policy: "replace"` (and the Copilot's
`commit_dns_import`) does the same. Replacing drops the foreign apex NS rows,
adds every enabled server in the group whose host is a DNS hostname (not an IP,
not a single label) as an apex NS, and moves a SOA primary name that named a
foreign host. Delegations below the apex are never touched, the change is
recorded in the zone's audit row (`apex_ns_replaced`), and a group with no such
server keeps the imported rows with a warning rather than falling back to the
agent's loopback placeholder. Existing zones are not rewritten.

**CNAME beside other data (#2089).** A CNAME must be the only record at its
name and never sits at the apex (RFC 1034 §3.6.2, RFC 2181 §10.1). The record
API refuses both (#1381), and so does every importer, with the same rule
(`services/dns/cname_conflict.py`). A source that holds such a pair (a
PowerDNS, Windows, Technitium or cloud zone; a zone file with one is already
refused by the parser) imports without the offending row, rather than as a zone
the server then refuses to load. Which side is kept:

- within one imported zone, the non-CNAME data is kept and the CNAME skipped;
  of several CNAMEs at one name the first in the source's order is kept; an
  apex CNAME is skipped;
- in a zone-file import into an existing zone, the records already there win,
  in both directions. Records in the trash do not count, IPAM-generated records
  do, and records match per view (a row with no view meets every view). A
  `replace` frees the names of the records it deletes, so the preview takes
  `conflict_strategy` as the commit does.

The preview lists each such record as a warning (or under **Will not be
imported** for a zone file), the commit's warnings repeat it, and the zone's
audit row names it (`records_skipped_unsafe`, or `skipped` for a zone file).

See `docs/drivers/DNS_DRIVERS.md` for parser + agentless-driver
internals.

---

## DHCP importer (#129)

Three sources, all reducing to canonical `ImportedScope` +
`ImportedPool` + `ImportedReservation` + `ImportedClientClass`:

- **Kea JSON** *(Phase 1)* — upload a `kea-dhcp4.conf` /
  `kea-dhcp6.conf` from a non-managed daemon. Cleanest source: it's
  exactly the shape SpatiumDDI's own Kea driver renders. The parser
  strips Kea's JSON-with-comments extensions (string-aware), accepts
  either a wrapped (`{"Dhcp4": {…}}`) or bare (`{"subnet4": […]}`)
  body, and maps `subnet4` / `subnet6` → scopes, `pools` → pools,
  `reservations` → reservations, `option-data` → canonical options,
  and top-level `client-classes` → client classes (Kea `test`
  expressions are SpatiumDDI's native class shape, so they import
  verbatim).
- **Windows DHCP live-pull** *(Phase 2)* — pick a registered
  `windows_dhcp` server with WinRM credentials; the importer reuses the
  Path A read driver (`Get-DhcpServerv4Scope` + option values +
  exclusion ranges + reservations). IPv4 only.
- **ISC `dhcpd.conf`** *(Phase 3)* — upload a `dhcpd.conf`. A hand-rolled
  tokeniser + recursive-descent walker maps `subnet` / `subnet6` →
  scopes, `range` / `range6` / `pool {}` → pools, `host` → reservations
  (a global `host` attaches to the subnet whose CIDR contains its
  `fixed-address`), and scope `option` statements → canonical options.
  ISC classifier expressions don't translate to SpatiumDDI's
  constrained class model, so `class` declarations are surfaced for
  **manual review** (`supported=false`) and never auto-created;
  `failover` / `key` / `zone` / `include` are listed in the "didn't
  import" panel.

### IPAM linkage (the DHCP-specific wrinkle)

A `DHCPScope` must bind to an IPAM `Subnet`. For each imported scope the
commit either:

- **links** to an existing IPAM subnet whose CIDR matches the scope, or
- **auto-creates** a subnet under the operator-chosen **IP space +
  block** (containment + non-overlap validated; the network /
  broadcast / gateway placeholder rows the manual create path adds are
  skipped — the imported pools + reservations are the real occupancy).

Leave the IP space + block blank for **link-only** mode: scopes with no
matching subnet report an actionable per-scope error rather than
silently creating something. The auto-created (or linked) subnet gets
its `dhcp_server_group_id` set so IPAM reflects DHCP ownership.

Per-scope conflict actions when the target group **already serves a
scope on the matched subnet**: **skip** (default) or **overwrite**
(delete the existing scope — cascading its pools + statics — and
recreate). Client classes are group-scoped and created once, skipping
any that already exist by name.

### Not imported

- **Live leases** — transient, unrelated to config, and would race with
  the running daemon. They repopulate from the running daemon once a
  real Kea server is attached to the target group.
- **Kea hook libraries** (HA / host-cache / lease-cmds), **ISC
  failover** — SpatiumDDI's HA is implicit at the server-group level;
  configure it server-side post-import.
- **ISC / Kea classifier DSL** beyond the directly-modellable subset,
  **TSIG / failover keys**, **`include` files** (inline them before
  upload).

See `docs/drivers/DHCP_DRIVERS.md` § "Importing existing daemon
configs" for parser internals.

---

## NetBox → IPAM importer (#36)

A one-shot **migration** importer — *not* a continuous reconciler.
There is no `netbox_target` row, no beat sweep, and no absence-delete:
the operator live-pulls a NetBox install once, reviews the plan, and
commits it into native IPAM. (Operators who want an ongoing read-only
mirror belong on the integration shelf, not here.) The service package
is `backend/app/services/netbox_import/`; the router lives at
`/api/v1/ipam/import/netbox/`.

### What it imports

| NetBox source | → SpatiumDDI |
|---|---|
| `/api/ipam/vrfs/` | `VRF` (name / rd / import + export targets / tenant→customer) |
| `/api/tenancy/tenants/` | `Customer` (ownership FK, **not** the space boundary) |
| `/api/dcim/sites/` (+ regions) | `Site` (region is the single parent axis; site-groups fold into `tags`) |
| `/api/ipam/aggregates/` | top-level `IPBlock` |
| `/api/ipam/prefixes/` | `IPBlock` (container) **or** `Subnet` (leaf), by NetBox `status` |
| `/api/ipam/ip-addresses/` | `IPAddress` (mask stripped, `dns_name` → fqdn) |
| `/api/ipam/vlans/` | `VLAN` under a synthesized router |

DCIM devices / racks / cables / interfaces, circuits, and write-back to
NetBox are **out of scope** — the `assigned_object` on an IP is read
for hostname enrichment only, never imported as its own row.

### Flow — test → preview → commit

1. **Test connection.** `POST …/test-connection` probes
   `GET /api/status/`, validates the token (NetBox 4.5+ exposes a cheap
   `authentication-check`), and returns the daemon version + object
   counts so the operator confirms scale before a large pull.
2. **Preview.** `POST …/preview` live-pulls every in-scope endpoint,
   maps onto the canonical IR, and flags every entity whose key already
   exists in the target. Side-effect-free — no DB writes, no audit
   rows. Optional `filters` (vrf / tenant / status / family /
   within-include) slice a large NetBox; re-run freely while iterating.
3. **Commit.** `POST …/commit` replays the **unmodified** previewed
   plan (the UI hands the same `PreviewOut` shape straight back as
   `CommitIn.plan`, so the server is stateless between the two calls).
   Conflicts are **re-detected fresh** against current state; each
   entity writes in its **own savepoint**, so a FK / overlap error on
   entity N never rolls back 1..N-1, and the result ledger carries one
   `created` / `overwrote` / `skipped` / `failed` row per attempt. Each
   committed entity gets one `audit_log` row tagged
   `import_source=netbox`. There is **no agent wake** — NetBox seeds
   IPAM rows only and touches no DNS / DHCP config bundle.

### Space strategy — `per_vrf` vs `single`

The crux decision is which IP space each prefix / address lands in:

- **`per_vrf`** (default) — synthesise one `IPSpace` per NetBox VRF
  (named after the VRF), plus a **Global** space for everything with no
  VRF. Each block / subnet / address resolves its space from its VRF.
- **`single`** — collapse every imported row into one operator-chosen
  `target_space_id`; no `ImportedSpace` rows are synthesised. The
  preview **warns** and the commit **422s** if `target_space_id` is
  missing under this strategy.

### Provenance + idempotent re-run

Every created (or overwritten) row is stamped `import_source="netbox"`
+ `imported_at` + the NetBox primary key (`netbox_id`, carried in
`custom_fields` for rows that have a custom-fields column, or `tags`
for those that don't — `Site` / `VLAN`). On a re-run the matcher keys
off `(import_source="netbox", netbox_id)`, so a second commit
re-detects conflicts against the live DB and defaults every conflicting
entity to **skip** — a double-"Commit" never duplicates or tramples.
To intentionally refresh, set the entity's per-conflict action to
**overwrite**. Pre-existing, hand-created rows look "not imported" to
the matcher, so the importer never claims ownership of a row it didn't
create.

### Connection + token

The NetBox `base_url` + API `token` (v1 `Token` or v2 `Bearer nbt_…`,
auto-detected) are supplied **in the request body** on every call and
**read once — never persisted**. The token should be read-only on the
NetBox side; an advisory SSRF guard logs the resolved target IP (a
co-located / LAN NetBox is a legitimate source, so it is not
hard-blocked). The surface is superadmin-only; the feature module
`ipam.import.netbox` is **default-on** (importers are default-on for
discovery per non-negotiable #13/#14 — only continuous integration
*mirrors* default off).

---

## Windows → SpatiumDDI cutover (#756)

The importers land a *copy* of the Windows estate. They prove nothing
about what happens next: the Windows server is still running, still
authoritative, and still the thing clients actually talk to. This
surface is the other half — verify the two sides agree, run them in
parallel, perform the switch, and track the decommission.

It is emphatically not a fifth importer. It creates no zones, scopes,
pools or records. Its only writes are TTL reductions on a zone
SpatiumDDI already owns, reservations synthesised from live Windows
leases, and the `is_active` flag on a managed scope.

Behind the `migration.cutover` feature module, which ships **disabled**
(Settings → Features, group **Tools**) — unlike the three importers, which
stay on because a fresh install is exactly when an estate gets imported. A
cutover is the far end of that journey: it happens after a parity check and a
parallel run, only on installs leaving Windows
([#1069](https://github.com/spatiumnorth/spatiumddi/issues/1069)). Router at
`/api/v1/migration/cutover`,
**superadmin on every endpoint**. That matches the three importers, on
the grounds that a cutover is strictly more dangerous than an import —
inventing a grantable permission for it would be a *weaker* posture
than the surface it extends. Four MCP tools ship with it:
`find_cutover_plans`, `find_cutover_plan_status` and
`count_cutover_blockers` (DB-only, default-enabled) plus
`find_cutover_parity_check`, which is default-**off** because it runs a
live WinRM pull.

### The plan

The unit of work is a **plan**: a name, a source Windows DNS and/or
DHCP server, a target DNS and/or DHCP server group, and a list of
**items**. One item is one zone or one scope
(`kind = dns_zone | dhcp_scope`). Items are independent — they can be
cut over on different days, and each one rolls back on its own. There
is no big-bang step anywhere.

`POST …/plans/{id}/discover` live-pulls both source servers and hands
back pickable candidates already matched against the target group
(zones by name with the trailing dot and case normalised away, scopes
by canonical subnet CIDR) with their readiness blockers pre-computed,
so nobody types a zone name. The two halves are independent: a WinRM
failure on the DHCP side is reported as an `error` string on that side
while the DNS candidates still come back.

Every mutating endpoint writes an `audit_log` row *and* a per-plan
timeline event (`GET …/events`) — the audit row is the compliance
record, the timeline is the operator's narrative of what was done to
this plan and by whom. `GET …/runbook` renders the whole plan as
markdown for a change ticket, built from persisted state so it does
not re-pull the source.

Plan status walks `draft` → `verifying` → `parallel` → `cutting_over`
→ `completed`, with `rolled_back` and `abandoned` as terminal states.
Item stage walks `pending` → `parity_checked` → `preflight_done` →
`cut_over` / `rolled_back`.

### Phase 1 — parity

*Do we answer the same as Windows does right now?*

`POST …/items/{id}/parity` runs one item; `POST …/plans/{id}/parity`
runs every item on the plan. The fan-out is **sequential** on purpose:
one `AsyncSession` cannot serve concurrent operations, and every parity
computation reads from the DB before it touches the wire. A slow
Windows box makes the request slow; it does not corrupt the session.
Each report is persisted onto the item and refreshes its blockers.

**DNS** diffs the live `pull_zone_records` result against the zone's
`DNSRecord` rows. Identity and value normalisation are reused verbatim
from `app.services.dns.pull_from_server._key`, so relative-vs-FQDN
storage and TTL-only noise never register as failures. Records bucket
on `(name, type)` **first**, which is the delta over the #61 drift
report: a changed record surfaces as one difference rather than the
missing+extra pair keying on `(name, type, value)` produces. TTLs are
the pre-flight's business, not parity's.

**DHCP** diffs `get_scopes()` against the managed scope — lease time,
the pool set as `(start, end, type)` triples, reservations keyed by
MAC, and scope options by canonical name. Activation posture is
reported as a *warning*, never as a difference: through the parallel
run the two sides are deliberately never both active, so a mismatch
there is the expected posture, and recording it as a difference would
make "in parity" structurally unreachable.

Every difference is classified by *why* the two sides differ, because
during a migration that is the decision, not the fact that they do:

| Classification | What it means |
|---|---|
| `in_sync` | Both sides hold the same record or fact. Carried as the report's `in_sync` **count**, not as a difference row. |
| `value_mismatch` | Same `(name, type)` on both sides, different data. One difference, not an add plus a remove — "the value changed" is a different decision from "a record appeared". |
| `drifted_since_import` | Windows has it, SpatiumDDI doesn't, **and** the SpatiumDDI object carries import provenance. It came across once and Windows has moved on since; re-import or add it here. |
| `never_imported` | Windows has it, SpatiumDDI doesn't, and there is no import provenance. Nothing drifted — it was simply never brought across. |
| `intentionally_diverged` | SpatiumDDI has it, Windows doesn't. Almost always an operator addition made after the import; it starts being served at cutover. Surfaced, never auto-reconciled. |

Report `status` is one of `ok`, `unmatched` (the object exists on one
side only, so there is nothing to diff), `error` (the pull failed — a
per-item failure never raises, so one dead host cannot take down a
whole-plan run), or `unverified`. That last status, and the
`not_compared` counter beside it, both exist because the *reader* can
be wrong about the source — and saying so beats guessing.

**`not_compared` — records the reader physically cannot see.** The
Windows DNS driver picks its read path from whether the server has
WinRM credentials, and the two paths are blind to different things.
Path B (`Get-DnsServerResourceRecord`) maps only the types in
`_PULL_RECORD_TYPES`; anything else reaches the parser as a raw
`.ToString()` it refuses to guess at, so a CAA / TLSA / SSHFP / NAPTR /
LOC row held here would read as "Windows does not have it" purely
because the PowerShell walker cannot emit it. Path A (AXFR) has no
type allowlist but strips DNSSEC artefacts. Both drop the SOA and the
apex NS set, which SpatiumDDI models as zone-level fields rather than
as records. Those rows are counted into `not_compared` and surfaced as
a warning instead of falling out as `intentionally_diverged` — a
difference there says something about the reader, not about the two
servers, and chasing it means "fixing" records that are already
correct on both sides.

**`unverified` — the pull returned, and the answer cannot be trusted.**
`WindowsDNSDriver._parse_records` logs a warning and returns an **empty
list** when the PowerShell output does not parse, which is
byte-identical to a genuinely empty zone. So a pull that comes back
with no records at all while SpatiumDDI holds some gets
`status="unverified"` rather than reporting every row as
SpatiumDDI-only: calling that "everything diverged" would be actively
misleading, and calling it "in parity" would be dangerous. Readiness
treats `unverified` exactly like never-checked — a hard block.

### Phase 2 — parallel run (shadow queries)

Parity proves the two *configurations* agree. That is necessary and not
sufficient: a zone can be byte-identical in the database and still
answer differently on the wire — a view that matches on the control
plane's source address, a stale zone file an agent never reloaded, a
name served from a forwarder rather than from the zone.

`POST …/items/{id}/shadow` (DNS items only; a DHCP item 422s) replays a
sample of real questions at the Windows source **and** at every
enabled, queryable server in the target group, then compares the
answers.

Names come from the BIND9 query log (`dns_query_log_entry`, scoped to
the zone's own group, over a 24 h window matching what
`prune_log_entries` retains). Those are questions clients actually
asked, and that is what makes this a *shadow* run rather than a second
look at our own rows. When the log is empty — query logging off, or the
managed side not receiving traffic yet — it falls back to the zone's
`DNSRecord` names. `sample_source` on the report says which, and it
matters: parity demonstrated against production traffic is a
materially stronger claim than parity against the rows being tested.
The fallback also emits a warning telling the operator to enable query
logging and re-run during the parallel window.

Mechanics worth knowing:

- Queries go to an **IP literal**; hostnames are resolved first. Every
  low-level dnspython entry point resolves the nameserver itself and
  raises a bare, message-less `ValueError` for anything that is not an
  address — one of the two reasons #61's drift report failed 100% of the
  time against hostname-addressed servers (the other was the unsigned
  transfer, #734).
- Recursion is disabled (RD=0). Both sides are supposed to be
  authoritative, and letting either recurse would let a cached answer
  from somewhere else stand in for the server under test.
- Answers compare as sorted, de-duplicated, lower-cased,
  trailing-dot-stripped sets — RRset order is not meaningful on the
  wire, and round-robin makes it actively unstable.
- Sample size 1–200 (default 25), 3 s per query, at most 8 in flight.
- Cloud-hosted DNS drivers are skipped with a warning: their `host` is
  a display label reached over a provider API, not a resolver.

Per-sample verdicts are `match`, `mismatch`, `source_error` and
`target_error`. A target that could not be reached outranks a mismatch
that was seen — the comparison is incomplete, and reporting it as a
clean mismatch would understate how much is still unknown.

### Readiness blockers — and the GSS-TSIG refusal

Every reason an item is not ready is a **blocker** with a stable code
and one of two severities. `warn` is advisory and can be acknowledged
by passing `force=true`; `block` refuses the cutover outright and
**cannot be forced, ever**. Unacknowledged warnings also refuse, so
`force` is an explicit "I have read these" rather than a bypass.

Blockers are re-derived against **live** source state at the moment of
the switch, not read from the last parity run. A report from twenty
minutes ago is a claim about the past, and the whole guard is worthless
if an operator can flip a zone on Windows afterwards and still be
allowed through.

> **The one that matters is `ad_secure_dynamic_update`.** A Windows
> zone set to Active Directory **"Secure only"** dynamic updates
> accepts registrations exclusively over GSS-TSIG. SpatiumDDI does not
> implement GSS-TSIG (#444), so the moment that zone is served from
> here instead, every domain controller and domain-joined client
> silently fails to register — no error the operator will see, just an
> Active Directory that stops resolving itself. That is the difference
> between a DNS migration and a domain outage, so it is a hard block
> and there is no flag anywhere that turns it off. Fix it on the
> Windows side (set the zone to "Nonsecure and secure"), or leave that
> zone on Windows and migrate the rest.

The detection **fails closed**. Windows' `DynamicUpdate` arrives from
`ConvertTo-Json` either as a string (`None` / `NonsecureAndSecure` /
`Secure`) or as the raw enum integer (`0` / `1` / `2`), depending on
the build, and both shapes are decoded — case-insensitively, and with
punctuation squashed. An **AD-integrated** zone whose mode cannot be
interpreted at all is treated as `Secure` and blocked, because "we
could not tell" must not read as "it is fine".

The rest, in brief. Blocking: no source server; the source zone /
scope could not be read (so it is unverified — the message is rewritten
to name the transport error when that is what happened); no target zone
/ scope linked; the target group has no servers; parity never verified
or not trustworthy; and `managed_scope_active`, which refuses a DHCP
item whose managed scope is already active while Windows is still
serving — the parallel run must be structurally unreachable to clients.
Warnings: parity differences, a missing reverse zone, nonsecure dynamic
updates, an AD-integrated source zone, a view-scoped target zone, an
already-inactive source scope, and a pending lease handover.

### Phase 3a — TTL pre-flight (DNS)

The DNS switch is a delegation or forwarder change made outside
SpatiumDDI, so its blast radius is governed entirely by how long
resolvers keep serving the old answers — the TTL. A zone sitting on the
common 3600 default means a bad cutover stays visible for an hour after
it is reverted; lowered to 300 well ahead of the window, the same
mistake clears in five minutes. Nothing else in the cutover buys as
much safety for as little effort.

`POST …/items/{id}/ttl-preflight/preview` describes the change;
`…/commit` applies it; `…/restore` puts it back. `target_ttl` is
bounded 30–86400 s (default 300) — the ceiling exists so an operator
cannot quietly *raise* every TTL in the zone through a screen labelled
"lower TTLs".

Commit snapshots the zone SOA (`ttl` / `minimum` / `refresh` / `retry`)
and **every** record's TTL into `cutover_item.ttl_snapshot`, then
lowers `zone.ttl`, `zone.minimum` and every record above the target.
Records with `ttl IS NULL` inherit the zone TTL, so they are given an
explicit value and snapshotted as `null` — that is what lets a restore
put the *inheritance* back rather than pinning them to whatever the
zone default happened to be. Changes ride the ordinary record pipeline:
one `bump_zone_serial` for the whole batch, then
`enqueue_record_ops_batch`. The snapshot is written **once**; a second
apply at a lower target still lowers TTLs but keeps the pristine
snapshot, so a restore always returns the true pre-migration values.

> **SpatiumDDI does not lower the TTLs on the Windows side, and that is
> deliberate** — even though those are the values resolvers are
> actually caching today, and therefore the ones that matter. Record
> writes to a Windows DNS server ride RFC 2136, where "change the TTL"
> is expressed as a **delete of the rrset followed by an add**, and
> SpatiumDDI will not issue an unattended delete against a zone that is
> still live and authoritative for production. The WinRM Path B
> alternative is no better here: it is a clone-and-`Set` per record
> against that same live zone. So the preview and commit responses both
> carry `source_side_instructions` — a copy-pasteable PowerShell block
> for the operator to run there — and the runbook repeats it. **A TTL
> drop applied to only one side is worse than none at all**: it looks
> done and buys nothing, which is why the instructions are part of
> every response rather than an optional extra.

Both sides then need waiting out. The preview warns with the real
number: resolvers may keep serving the previous values for up to the
zone's *current* TTL, so the drop has to happen at least that long
before the window.

### Phase 3b — DHCP lease handover

The DHCP importer deliberately skips live leases (see "Not imported"
above) — they are transient state, and an importer that invented
reservations out of them would be lying about operator intent. A
cutover is the one moment where that trade flips.

At the instant the managed scope starts answering, **Kea's lease
database is empty**. The first client to renew is handed a fresh
address out of the pool while it is still using, and still answering
on, the one Windows gave it. On a busy subnet a naive switch is
therefore a wave of duplicate-address complaints during the exact
window an operator is least able to absorb them.

`POST …/items/{id}/lease-handover/preview` reads the live Windows lease
table (`get_leases` already filters to the states Windows considers
live) and classifies every lease; `…/commit` writes the `create`
entries as `DHCPStaticAssignment` rows on the managed scope, so a
renewing client is offered **the address it already holds**. Same
stateless preview → commit contract as the importers: the plan comes
back from the client, and every entry is re-classified against live DB
state on the way in.

- `create` — becomes a reservation.
- `skip` — outside the managed scope's subnet (leases are selected by
  subnet containment, because the driver's neutral lease dict carries
  no scope id), already reserved with that address, or carrying a
  client id that is not a MAC.
- `conflict` — the MAC is already reserved to a *different* address on
  this scope, or the address is already reserved to a different MAC.
  Never overwritten; resolve those by hand.

Rows are stamped `import_source="windows_cutover"` + `imported_at`,
which is distinct from the importer's `windows_dhcp` on purpose: these
were synthesised from *leases* at cutover, not read from the server's
config, and an operator who later wants the addresses back in the
dynamic pool can find and drop exactly this set. Each row is written in
its **own savepoint** together with its IPAM mirror, so one failure
fails exactly one entry — the same ledger idiom the importers use — and
the rollup lands on `cutover_item.lease_handover`.

### Phase 3c — the switch, and rollback

`POST …/items/{id}/cutover` re-evaluates blockers first and returns
**409** with the blocker list when it refuses (409 rather than 422:
the request is well-formed, the *state* is what refuses it).

**DHCP is a real switch, and the order is the entire point.** The
Windows scope is deactivated **first**
(`Set-DhcpServerv4Scope -State InActive` over WinRM), and only then is
the managed scope activated. Between the two steps the subnet has *no*
DHCP server, which costs renewing clients nothing — they hold their
lease until half its lifetime elapses — and lasts about one WinRM
round-trip. The reverse order would leave **both** servers answering
the same subnet, which hands two clients the same address within
seconds. If activating the managed scope then fails, the Windows scope
is put back (best-effort, logged); if that compensation also fails, the
log says in so many words that the subnet may currently have no active
DHCP server.

**DNS is not switched here at all**, because there is no server-side
flag SpatiumDDI owns: which server answers for a zone is decided by the
delegation at the parent (or by what the resolvers forward to), and
both live outside SpatiumDDI. So the DNS path stamps the transition,
returns the operator instructions — repoint the delegation, repoint
conditional forwarders and stub zones, update DHCP option 6, leave the
Windows zone serving as the fallback — and **never touches the Windows
zone**. Deleting or disabling it before the delegation has actually
moved removes the thing that is still serving.

`POST …/items/{id}/rollback` reverses it. DHCP: deactivate the managed
scope, re-activate the Windows one — the mirror image of the cutover
ordering, with its own compensation. DNS: restore the TTL snapshot and
return the revert instructions. Rollback deliberately does **not**
re-evaluate blockers — it is the escape hatch, and gating it on
readiness would mean the state that made the switch go wrong is also
the state that stops you undoing it.

Both cutover and rollback return `recovery_estimate_seconds`, so the
recovery-time expectation is a number rather than a hope: the zone's
current TTL for DNS (which is exactly what the pre-flight exists to
shrink — cutting over without it earns a warning saying a rollback will
propagate at the zone's full TTL), and the scope's lease time for DHCP.
The generated runbook states the same figure in prose per item, derived
from that item's real pre-flight TTL or lease time, and says so
explicitly when it is falling back to an assumed default.

### Phase 4 — decommission checklist

The switch is the visible part of a migration; the decommission is the
part that bites weeks later. A Windows DNS server left running with
scavenging on quietly deletes the fallback copy of the zone. A DHCP
server left *authorized in Active Directory* starts answering again the
first time it is patched and rebooted, racing the managed scope for the
same subnet. A conditional forwarder on one resolver in one branch
office keeps a whole site resolving from a box everybody believes is
retired.

None of that is discoverable from the cutover state, so it is a
checklist. `GET …/plans/{id}/checklist` seeds it on first read from a
static catalog and returns it; `PATCH …/checklist/{key}` ticks an item
or annotates it. Fifteen entries across four categories — `ad`, `dns`,
`dhcp`, `general` — covering DC SRV re-registration, forced Netlogon
re-registration, scavenging, dynamic-update sources and permissions,
AD deauthorization of the DHCP server, conditional forwarders and stub
zones, reverse-zone ownership, zone-transfer ACLs, WINS / GlobalNames,
the Windows DHCP failover relationship, DHCP option 6, monitoring and
alerting, a retained final export, and stopping (not uninstalling) each
Windows service.

The catalog is versioned code and the ticks are data: seeding is an
idempotent upsert on `(plan, key)` that refreshes an item's wording and
ordering while leaving `is_done` / `done_at` / notes strictly alone, and
a key dropped from the catalog keeps its row rather than silently
discarding an operator's tick.

**Three items are auto-evaluated, and none of them is ever
auto-ticked.** `dc_srv_registration` looks for `_ldap._tcp` /
`_kerberos._tcp` / `_gc._tcp` / `_kpasswd._tcp` SRV records still
living in the plan's zones; `reverse_zone_ownership` derives the `/24`
`in-addr.arpa` companions implied by those zones' A records and reports
which are missing from the plan or absent from SpatiumDDI entirely
(IPv6 is deliberately not derived — an AAAA record's reverse boundary
is a site convention, so guessing it would report companions that were
never supposed to exist); `zone_transfer_acls` resolves each zone's
effective `allow-transfer` (zone value, else the server group's
default, the same precedence the renderer uses) and flags anything that
lands on `any`. Each comes back as `ok` / `attention` /
`not_applicable` / `manual` with a detail line beside the item. Every
other entry is `manual`, because it is about the state of a Windows
box, a resolver in a branch office, or a monitoring system — none of
which SpatiumDDI can see. **A checklist that ticks itself is a
checklist nobody reads**, so the operator is always the one who decides
an item is done.

---

## Re-running an import

All three importers are safe to re-run. A second commit of the same
source re-detects conflicts against the live DB and defaults every
conflicting object to **skip**, so a fat-fingered "Commit" twice
doesn't duplicate or trample. To intentionally refresh an imported
object, set its conflict action to **overwrite** (DNS also offers
**rename**; NetBox keys re-runs off the stored `netbox_id`).
