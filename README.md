<p align="center">
  <img src="docs/assets/logo.svg" alt="SpatiumDDI Logo" />
</p>

<h1 align="center">SpatiumDDI</h1>

<p align="center">
  <strong>Self-hosted DNS, DHCP, and IPAM — one control plane, real servers underneath.</strong><br/>
  A modern, open-source alternative to commercial DDI platforms.<br/>
  Built in the open by <a href="https://www.spatiumnorth.com">SpatiumNorth</a>, Montréal.
</p>

<p align="center">
  <a href="https://github.com/spatiumnorth/spatiumddi/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/spatiumnorth/spatiumddi/ci.yml?branch=main&label=CI" alt="CI"/></a>
  <a href="https://github.com/spatiumnorth/spatiumddi/security/code-scanning"><img src="https://img.shields.io/badge/security-CodeQL-1f6feb" alt="CodeQL"/></a>
  <a href="https://github.com/spatiumnorth/spatiumddi/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"/></a>
  <a href="https://www.spatiumddi.com"><img src="https://img.shields.io/badge/docs-spatiumddi.com-informational" alt="Docs"/></a>
  <img src="https://img.shields.io/badge/status-beta-blue" alt="Status"/>
</p>

<p align="center">
  <a href="https://github.com/spatiumnorth/spatiumddi/releases/latest"><img src="https://img.shields.io/github/v/release/spatiumnorth/spatiumddi?label=release" alt="Latest release"/></a>
  <a href="https://github.com/spatiumnorth/spatiumddi/commits/main"><img src="https://img.shields.io/github/last-commit/spatiumnorth/spatiumddi" alt="Last commit"/></a>
  <img src="https://img.shields.io/maintenance/yes/2026" alt="Maintained"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.12+-green" alt="Python"/>
  <img src="https://img.shields.io/badge/react-18+-61DAFB" alt="React"/>
  <a href="https://github.com/psf/black"><img src="https://img.shields.io/badge/code%20style-black-000000" alt="Code style: black"/></a>
  <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/badge/lint-ruff-FCC21B" alt="Lint: ruff"/></a>
  <a href="https://mypy-lang.org/"><img src="https://img.shields.io/badge/type%20checked-mypy-blue" alt="Type checked: mypy"/></a>
</p>

<p align="center">
  <a href="https://discord.com/invite/ANJAnvg2Dd"><img src="https://img.shields.io/badge/Discord-Join%20the%20community-5865F2?logo=discord&logoColor=white" alt="Discord"/></a>
  <a href="https://github.com/spatiumnorth/spatiumddi/stargazers"><img src="https://img.shields.io/github/stars/spatiumnorth/spatiumddi?style=social" alt="Stars"/></a>
  <a href="https://github.com/spatiumnorth/spatiumddi/discussions"><img src="https://img.shields.io/github/discussions/spatiumnorth/spatiumddi" alt="Discussions"/></a>
  <a href="https://github.com/spatiumnorth/spatiumddi/graphs/contributors"><img src="https://img.shields.io/github/contributors/spatiumnorth/spatiumddi" alt="Contributors"/></a>
  <a href="https://github.com/spatiumnorth/spatiumddi/issues"><img src="https://img.shields.io/github/issues/spatiumnorth/spatiumddi" alt="Issues"/></a>
</p>

---

> ⚠️ **Beta software.** SpatiumDDI is under active development. Core IPAM / DNS / DHCP / appliance surfaces have stabilised since the `2026.04.16-1` alpha cut, but expect occasional schema changes between releases and roadmap features that are still in flight. Suitable for labs, homelabs, and pilots in front of non-critical client populations; production deploys in front of business-critical DHCP should pin to a tested release and snapshot Postgres before upgrading. Early adopter feedback is very welcome — open an issue or start a discussion on GitHub.

---

## Contents

- [Why I built this](#why-i-built-this) — the story
- [About SpatiumNorth](#about-spatiumnorth) — the company behind it
- [Why SpatiumDDI](#why-spatiumddi) — the elevator pitch
- [Privacy: your data stays yours](#privacy-your-data-stays-yours) — no telemetry, no analytics, no phone-home
- [Support the project](#support-the-project) — sponsors, tip jar, getting involved
- [What's in the box](#whats-in-the-box) — quick capability tour
- [Full feature detail](#full-feature-detail) — deep dive on every subsystem
- [Screenshots](#screenshots)
- [Architecture](#architecture)
- [Getting Started](#getting-started) — three ways to run SpatiumDDI:
  - [Try the demo in GitHub Codespaces](#try-the-demo-in-github-codespaces) — one-click full stack with seeded data, browser-only, free 60 h/month
  - [Quick start with the OS appliance ISO](#quick-start-with-the-os-appliance-iso-recommended) — easiest deploy: Debian 13 + embedded k3s + atomic A/B upgrades, guided installer
  - [Quick start with Docker Compose](#quick-start-with-docker-compose) — `docker compose up` on any Docker host, full control
  - Plus: [demo seed](#seeding-demo-data) · [in-place upgrade flow](#upgrading) · [built-in DNS/DHCP containers](#running-the-built-in-bind9--powerdns--technitium--kea-containers) · [API docs](#api--interactive-docs)
- [Deployment Options](#deployment-options)
- [Documentation](#documentation)
- [Project Status](#project-status)
- [Contributing](#contributing)
- [License](#license)

---

## Why I built this

I'm a network engineer. I've spent years working with enterprise DDI platforms, and while they're solid pieces of software, the licensing puts them out of reach for smaller teams, homelabs, and folks who just want to learn how this stuff fits together.

The open source world has excellent standalone tools — NetBox for IPAM, BIND9 / PowerDNS / Technitium for DNS, Kea for DHCP — but nothing that pulls them into a single control plane the way the commercial platforms do. So I started building one on nights and weekends.

If SpatiumDDI ends up being useful to you, that's the whole point. If you want to file an issue, send a PR, or just tell me what's broken, I'd genuinely appreciate it.

## About SpatiumNorth

SpatiumDDI is built by [SpatiumNorth](https://www.spatiumnorth.com), a Montréal-based software company that builds infrastructure software in the open. The whole product ships under Apache 2.0 — every feature, free wherever you run it — and the company charges for the part that actually costs something: support, deployment and migration, from the people who wrote the code. If your organization wants that, see [pricing](https://www.spatiumnorth.com/spatiumddi/pricing) or [get in touch](https://www.spatiumnorth.com/contact); managed service providers can [partner](https://www.spatiumnorth.com/spatiumddi/partners) to run it for their clients. The code lives here, in the open, as it always has.

## Support the project

SpatiumDDI started on nights and weekends and homelab hardware, and the software is free and stays free. If it's saving your team work and you want to chip in, there are two ways, depending on who you are.

**Individuals** — small tips help cover the boring stuff (a domain, a homelab SSD, the occasional cloud VM I spin up to test a deploy topology I don't have locally). No tier system, no perks list, no obligation — just a "thanks, here's a coffee" button if the project saved you an afternoon. Every contribution is genuinely appreciated.

<p align="left">
  <a href="https://buymeacoffee.com/mzac"><img src="https://img.shields.io/badge/Buy%20me%20a%20coffee-FFDD00?logo=buy-me-a-coffee&logoColor=000000" alt="Buy me a coffee" /></a>
</p>

**Organizations** — if your team runs SpatiumDDI in production, the way to back the project is the support your operators will want anyway: that's what [SpatiumNorth](https://www.spatiumnorth.com) sells — support, deployment and migration from the people who wrote the code. See [pricing](https://www.spatiumnorth.com/spatiumddi/pricing) or [contact us](https://www.spatiumnorth.com/contact). Want to sponsor a specific feature or just say hi? Still happy to talk — [open an issue](https://github.com/spatiumnorth/spatiumddi/issues/new).

## Why SpatiumDDI

**It runs DNS and DHCP — not just configures them.** A modern alternative to Infoblox and EfficientIP: most open-source IPAM tools are pretty dashboards over someone else's `/etc/bind/named.conf`. SpatiumDDI bundles BIND9 and Kea as first-class service containers; the control plane owns their config, they auto-register, and they keep serving if the control plane is down.

**One platform, three surfaces.** IPAM tree, DNS zones, DHCP scopes — one UI, one REST API, one source of truth. Hostname changes in IPAM propagate to DNS; reservations propagate to DHCP. No more three-tab reconciliation.

**Bring your own servers — or ours.** Use the bundled Kea and BIND9, or point SpatiumDDI at your existing Windows DCs and DHCP servers via WinRM. Agentless in both directions — nothing installed on the Windows side.

**Built for delegation.** Group-based RBAC with LDAP, OIDC, SAML, RADIUS, and TACACS+ (with backup-server failover). Hand a subnet or a zone to a department without handing over root.

**API-first.** Every UI action is a REST call. Terraform, Ansible, and ad-hoc scripts all speak the same surface. If you can click it, you can automate it.

## Privacy: your data stays yours

SpatiumDDI collects **no telemetry, no usage analytics, no crash reports, and no account or registration data**. There is no phone-home, no license server, no sign-up, and no project-controlled endpoint the software talks to. Everything you put in it — zones, records, leases, subnets, credentials, query logs, audit history — lives in *your* PostgreSQL on *your* infrastructure, and the maintainers have no way to see it and do not want it. This README, the documentation site and the web UI use no analytics or tracking scripts.

The software makes no outbound connection you did not configure, with one exception: a **daily anonymous check of GitHub for a newer release** (an unauthenticated GET; GitHub sees your IP address and nothing about your install — no version, no counts, no identifiers). Turn it off under **Settings → Application → Updates → Check for GitHub Releases**, or run fully air-gapped — every feature works with no internet access at all. Optional features that do reach third parties (Fingerbank device profiling, the Operator Copilot's LLM provider, Let's Encrypt, blocklist feeds, cloud DNS / integration mirrors, the whois and RBL tools) are off until you configure them, and [docs/PRIVACY.md](docs/PRIVACY.md) lists exactly what each one sends, to whom, and how to stop it.

## What's in the box

> **One control plane for IPAM, DNS, DHCP — plus the discovery and integrations to keep it honest.** No vendor lock-in, no per-IP licence, no agents on Windows.

### 🏠 Core DDI

| | Feature | Highlights |
|---|---|---|
| 🗂 | **Hierarchical IPAM** | spaces · blocks · subnets · IPv4 + full IPv6 (EUI-64 / random / sequential) · per-IP roles · MAC history · reservation TTL · bulk allocate with name templates · atomic next-available-subnet carve (`POST /blocks/{id}/allocate-subnet` — race-safe, Terraform-ready) · server-side address pagination / search / sort + **cross-subnet IP search** (select-all-matches → bulk edit / delete) that survives a busy `/16` · hourly utilization-recount self-heal · scheduled reconciliation hygiene alerts (free-but-responding / stale reservation / unknown-MAC squatting) |
| ✂️ | **Subnet operations** | Split · Merge · Find-free · subnet planner (multi-level CIDR design + transactional apply) — preview-then-commit with typed-CIDR confirm · single Tools dropdown on subnet headers |
| 🧮 | **Planning tools** | CIDR calculator · address planner (pack /N requests into free space) · aggregation suggestion · free-space treemap |
| 🌐 | **DNS** | **BIND9 *or* PowerDNS *or* Technitium** container, auto-registering — pick per server group; zones and records are authored identically either way, but **split-horizon views and RPZ blocklists are BIND9-only**, ALIAS / LUA are PowerDNS-only, and Technitium blocks natively rather than via RPZ · RFC 2136 dynamic updates · per-zone dynamic-update ACLs (authorize external writers by TSIG key or source IP/CIDR, with ingest-back of records they inject) · per-server zone-serial drift + **record-level drift report** (AXFR the live zone, diff it against the database, per server) · TSIG keys · zone delegation wizard · zone templates · RPZ blocklists with curated catalog · catalog zones (RFC 9432) — producer *and* consumer on BIND9 and Technitium, producer-only on PowerDNS · secondary / stub zones (`masters`) · SVCB / HTTPS / DNAME records · **ALIAS** (apex CNAME-equivalent) + **LUA** (scripted / health-aware answers) on PowerDNS · Response Rate Limiting (RRL) + amplification defenses · query-log analytics (top names / clients / qtypes + per-view breakdown) with NXDOMAIN-spike / query-rate-spike alerting — and, with BIND 9.20 response logging on, **the answer as well as the question**: `rcode` + answer count per row, so NODATA is distinguishable from NXDOMAIN and from a query that was refused (opt-in per group; NULL means *unrecorded*, never NOERROR) · **move a server or a zone between server groups** — the server move re-elects a primary, purges the old group's queued ops and repoints the appliance firewall; the zone move is preview→commit with three separate acknowledgements, because clearing a view *widens* exposure rather than narrowing it |
| 🔒 | **Encrypted DNS (DoT / DoH / DoQ)** | serve DNS-over-TLS (853) + DNS-over-HTTPS (`/dns-query`) — plus **DNS-over-QUIC on Technitium** — to local clients **and** forward upstream over TLS instead of plaintext 53 · BIND9 native, PowerDNS via the dnsdist front, Technitium native (and the only driver that also forwards over **HTTPS and QUIC** — BIND 9.20 has no client-side HTTP or QUIC transport) · certs from the built-in ACME client or an upload, auto-picked-up on renewal · strict upstream `remote-hostname` validation that fails closed · per-group, default-off, additive (plain :53 keeps working) |
| 🔐 | **DNSSEC** | BIND9 inline-signing (BIND owns + auto-rotates keys) + **PowerDNS and Technitium online sign / unsign** from the zone page · reusable `dnssec-policy` library — KSK + ZSK algorithm / size / lifetime, **NSEC or NSEC3** (iterations · salt length · opt-out) · per-zone public key state + **DS export** to hand to the parent-zone registrar · manual + automatic rollover · SpatiumDDI never holds private key material — the signer owns and rotates it |
| 🔀 | **DNS Views (split-horizon)** | per-view zone + record rendering on BIND9 — `view_id IS NULL` records shared across views, scoped records render only in their view, RPZ / blocklists replicate into each view block |
| ⚖️ | **GSLB-lite + GeoDNS steering** | health-checked DNS pools — tcp / http / https / icmp / none probes flip A/AAAA records in/out of the rendered rrset; manual enable per member · **topology-aware steering** — a per-member serving scope (client CIDRs and/or Site) renders as BIND9 geo views composed over split-horizon, evaluated before operator views with a union fallback so a scoped-only pool never blackholes |
| 🔄 | **DHCP** | Kea container · agentless FortiGate cloud DHCP driver (FortiOS REST, no agent) · group-centric Kea HA (load-balanced or hot-standby) with self-healing peer drift · option templates · 95-entry option-code library · **PXE / iPXE provisioning profiles** — per-architecture boot-file selection (BIOS · UEFI x64 / ia32 / arm64 · iPXE chainload) rendered as Kea client classes, one reusable profile assigned per scope · DHCPv6 stateful / stateless / SLAAC modes · DHCPv6 prefix delegation (IA_PD / pd-pools + RFC 6603 excluded-prefix) · DUID host reservations · per-subnet relay-agent addresses · **IPv6 Router Advertisements** (radvd rendered per RA-enabled scope + rogue-RA passive sniffer) · fingerbank device-class on the lease list (filterable) · rogue-DHCP detection (opt-in active probe → unexpected-responder alert + allowlist) · **fingerprint-driven device policies** — compile chosen fingerbank device classes into a real Kea client class with its own option set and lease time, bindable from a pool's class restriction (NAC-lite, no 802.1X, no switch config); ambiguous signatures are excluded by default, counted and listed, because a request list of `1,3,6,15` comes from a doorbell and a rack server alike |
| 🪟 | **Windows DNS + DHCP** | agentless — RFC 2136 + WinRM, no software on the DC |
| 🧩 | **Agentless Technitium** | already run Technitium? Point SpatiumDDI at it — paste an API URL + permanent bearer token and the control plane drives its HTTP API directly, nothing deployed. Zone + record CRUD and topology pull; DNSSEC / forwarders / blocklists stay in Technitium's own console. Coexists with the agent-managed container driver — a group is single-driver, so a mixed estate is one group each |
| ☁️ | **Cloud DNS** | agentless first-class drivers — Cloudflare · Route 53 · Azure DNS · Google Cloud DNS · DigitalOcean · Hetzner · Linode · Vultr · import-existing-zones · client-side multi-value RRset disambiguation |
| 📥 | **DNS configuration import** | one-shot migration from BIND9 (`named.conf` archive upload), Windows DNS (live WinRM pull), PowerDNS (live REST pull), and Technitium (live REST pull) · preview-before-commit · per-zone savepoint so partial failures don't abort the batch · provenance stamps (`import_source` + `imported_at`) on every imported zone + record |
| 📥 | **DHCP configuration import** | one-shot migration from Kea (JSON-with-comments upload), Windows DHCP (live WinRM pull), and ISC `dhcpd.conf` · every scope binds to an IPAM subnet (link-existing or auto-create) · per-scope savepoints + skip / overwrite conflict actions · provenance stamps |
| 📥 | **IPAM import (NetBox)** | one-shot read-only migration from a live NetBox install (REST v3.x–4.6+) → prefixes / addresses / VRFs / tenants→Customers / sites / VLANs as native IPAM rows · stateless test → preview → commit · per-entity savepoints · `per_vrf` vs `single` space strategy · provenance stamps make re-runs idempotent (skip / overwrite) · creds supplied per-request, never persisted |
| 🪟 | **Windows cutover** | the half the importers stop short of — **not** a fifth importer: it creates no zones, scopes, pools or records. Per-plan, per-zone and per-scope: **parity** (diff SpatiumDDI against the live Windows server, classified by *why* the two differ) · **parallel run** (replay real queries from the query log at both sides and compare answers) · **TTL pre-flight** (snapshot and restore exactly) · **DHCP lease handover** (promote live Windows leases to reservations so a renewing client keeps its address) · **the switch**, deactivating Windows before activating the managed side, with per-item rollback and a real `recovery_estimate_seconds` · **decommission checklist** · a markdown **runbook** to paste into a change ticket, carrying the Windows-side PowerShell SpatiumDDI deliberately doesn't run for you |
| 📤 | **IPAM export** | any scope (space / block / subnet) out as CSV · JSON · XLSX — or **Print / PDF**: a *tree* report for a space or block (summary counters, block hierarchy indented by nesting depth, every subnet with utilization) or a *detail* report for a subnet (its facts, custom fields, address table) · paginated with repeating column headers and "Page N of M", so a printout handed to an auditor says whether a page is missing · same scope resolution as the spreadsheet exporters, so the two can't disagree about what a subtree contains |
| 📡 | **Multicast group registry** | RFC 5771 catalog seeded · per-IPSpace groups + PIM rendezvous-point domains · auto-created enclosing `224.0.0.0/4` / `ff00::/8` IPBlock for tree visibility · per-IP collision conformity check · bulk-allocate from RFC 2365 admin-scoped ranges |
| 🔁 | **NAT cross-reference** | 1:1 / PAT / hide-NAT tracked in IPAM with FK links to live IP rows |
| 📜 | **DHCP lease history** | forensic trail of every expiry, MAC reassignment, absence-delete |
| 🗑 | **Soft-delete trash** | 30-day Trash with cascade restore for spaces, blocks, subnets, zones, scopes — a scope's pools + static reservations cascade with it, so one Restore brings the scope back whole |
| ✅ | **DNS-name conformance** | every hostname / DNS name validated on write against the right standard for its role — RFC 1123 LDH for host names (IDN normalised to `xn--`, not rejected), the looser RFC 2181 owner rule for records so `_acme-challenge` / `_dmarc` / `_443._tcp` / `*` stay legal, dotted-label FQDNs for zones · client-supplied lease hostnames are sanitised, never dropped · read-only `/diagnostics/name-conformance` audits what already exists — validate-on-write never rewrites an existing row |

### 🌐 Network entities

| | Feature | Highlights |
|---|---|---|
| 🌐 | **ASN management** | first-class ASN entity · RDAP holder refresh (per-RIR routing via IANA bootstrap) · RPKI ROA pull (Cloudflare or RIPE) with expiry tracking · holder-drift detection with side-by-side diff · alert rules for drift / unreachable / ROA expiry · **BGP Footprint tab** with RIPEstat (announced prefixes / prefix-overview / routing history) + PeeringDB (peering profile / IXP presence) — REST + MCP tools · in-process TTL cache (RIPEstat 6 h, PeeringDB 24 h) |
| 🤝 | **BGP peering + communities** | peer / customer / provider / sibling graph between tracked ASNs · BGP communities catalog (RFC 1997 / 7611 / 7999 well-knowns + per-AS extensions, large communities per RFC 8092) |
| 🚨 | **BGP prefix-hijack detection** | RIPEstat poll (source of truth) + optional RIS Live streaming consumer watching your ASNs' tracked prefixes · `bgp_prefix_hijack` / `bgp_more_specific_announced` alerts (RPKI-invalid → `critical`, unknown → `warning`) · evidence kept on a pruned victim prefix · outage-safe stale resolution |
| 🔭 | **BGP Looking Glass** | receive-only GoBGP collector peers with your routers and ingests their live Adj-RIB-In — it never advertises routes back · Sessions + Routes grids with clickable peer / route detail modals (multi-origin *possible hijack* + anycast headlines, best-path heuristic) · every learned prefix resolved into IPAM / ASN / VRF at ingest, RPKI-validated · VPNv4 / VPNv6 Route-Target matching · six `bgp_lg_*` alert rule types + dashboard health card · as-path-regexp Query tab + collector-vantage ping / traceroute · optional **MetalLB BGP mode** advertises the control-plane VIP to the same routers |
| 🛣 | **VRFs as first-class** | name / RD / import + export RTs / optional ASN linkage · cross-cutting RD/RT validator (warns or 422s on ASN-portion mismatch) · VRF picker on IPSpace + IPBlock modals · auto-backfill from existing freeform fields |
| 📛 | **Domain registration tracking** | distinct from DNSZone — registrar / registrant / expiry / nameservers / DNSSEC · RDAP refresh (TLD → RDAP-base via IANA bootstrap) · NS-drift, registrar-changed, DNSSEC-status-changed alerts · explicit `dns_zone.domain_id` linkage with sub-zone tree fallback |
| 🏢 | **Customer / Site / Provider** | logical ownership entities cross-cutting IPAM / DNS / DHCP / Network · `ON DELETE SET NULL` cross-references on every existing table so re-tagging is safe · shared pickers + chips wired into every modal |
| 🛤 | **WAN circuits** | carrier-supplied logical pipe (provider + transport class + bandwidth + endpoints + term + cost) · 9 transport classes including AWS DX / Azure ER / GCP Interconnect cross-connects · soft-deletable (`status='decom'` is operator-visible end-of-life) · alerts for term-expiring + status-changed |
| 📦 | **Service catalog** | bundles VRF / Subnet / IPBlock / DNSZone / DHCPScope / Circuit / Site / Overlay into a customer-deliverable · `mpls_l3vpn` + `sdwan` + `custom` kinds in v1 · kind-aware `/summary` endpoint with L3VPN canonical shape · alerts for term-expiring + resource-orphaned |
| 🌐 | **SD-WAN overlays** | vendor-neutral overlay topology + routing-policy intent · 6 kinds (sdwan / ipsec / wireguard / dmvpn / vxlan-evpn / gre) · ordered preferred-circuit chain per site · 33 well-known SaaS apps in the catalog · pure read-only `/simulate` what-if when circuits go down · SVG circular-layout topology view |

### 🏭 Vertical network awareness

Four IP-native domains a generic IPAM doesn't speak. Each is a
**registry + segmentation documentation + conformity** module built on
the DDI primitives already here — not a protocol implementation. All
four are read-only by construction: SpatiumDDI records what the estate
*is*, and never reads or writes a device object, a control tag, or a
study. Default-on, individually togglable.

| | Domain | What it models |
|---|---|---|
| 🎚 | **AV over IP** (`network.av`) | Dante / AES67 / SMPTE ST 2110 / NDI / RAVENNA flow descriptors on top of the multicast registry · PTP clock domain per flow · operator-declared reserved ranges per protocol, so an allocation that lands outside the studio address plan is caught at preview time |
| 🏢 | **BACnet/IP** (`network.bacnet`) | building-automation device registry keyed on the **internetwork-unique device instance number** · BACnet network numbers · per-subnet BBMD designation with BDT / FDT snapshots · the exactly-one-BBMD-per-subnet rule checked in *both* directions (0 = unreachable across routers, >1 = duplicated broadcasts) |
| 🏭 | **Industrial / OT** (`network.ot`) | PROFINET / EtherNet-IP / Modbus TCP / OPC UA role + vendor + criticality per address · **Purdue-level zoning** per subnet (`Numeric(2,1)`, so level 3.5 — the DMZ — is representable) · CSV import of engineering-tool exports · devices whose Purdue level contradicts their subnet's zone are flagged |
| 🏥 | **DICOM AE registry** (`network.dicom`) | the institution-wide-unique **AE Titles** PS3.15 Annex H specifies a registry for and that in practice live in a spreadsheet · directed AE→AE association map behind *"what breaks if I renumber this host"* · PS3.5-exact title validation (16 **bytes**, spaces legal as padding) · an AE outlives its host, so decommissioning demotes it to a reservation rather than freeing a name peers still send to. **Network identity only — no patient data, ever** |

### 🔍 Discovery & visibility

| | Feature | Highlights |
|---|---|---|
| 📡 | **SNMP discovery** | v1 / v2c / v3 polling of routers + switches → ARP / FDB / interfaces / LLDP neighbours feed back into IPAM |
| 🔦 | **IP discovery** | opt-in per-subnet ping (unprivileged ICMP + TCP-connect fallback) / ARP sweep → `discovered` rows for live IPs · three-bucket reconciliation report · stamps the `last_seen_at` signal |
| ♻️ | **Address hygiene** | reverse-DNS auto-population (PTR → hostname) · Stale-IP report + one-click bulk-deprecate over the `last_seen_at` signal · CGNAT (RFC 6598) awareness badge + new-subnet hint |
| 🎯 | **Nmap scanner** | per-IP / per-subnet (CIDR sweep) / `/tools/nmap` · live SSE streaming · stamp alive hosts → IPAM |
| 🚧 | **Fragile-device "do not probe"** | mark an IP space / block / subnet as *do not probe* with a reason, and every prober SpatiumDDI owns — discovery sweeps, nmap, the network tools — refuses it · **ORs down the chain with no per-level opt-out**, deliberately unlike the DDNS fields it mirrors: a descendant must not be able to opt a clinical or plant-floor segment back into being swept · one resolver every prober consults, an audited superadmin-only per-request override, and a conformity check that works *backwards* from the OT / DICOM / BMC registries to find fragile subnets nobody flagged · not behind a feature module — a default-off safety flag protects nobody |
| ⏰ | **Wake-on-LAN** | send a magic packet from the IP detail modal, the **Network Tools** page, or the Operator Copilot · **server** vantage (control plane broadcasts) *or* **appliance** vantage (dispatched to a Fleet appliance on the target's segment) · MAC + broadcast resolved server-side · SSRF-denylisted + audited · `read:use_network_tools` |
| 🗓 | **Scheduled Wake-on-LAN** | **Tools → Wake Schedules** — recurring DST-safe cron wake of a whole fleet, targeted by address tags / subnet / subnet tags / explicit hosts · holiday gate (blackout dates + term range) or a subscribed **iCal / CalDAV calendar** (skip-on-event or only-on-event) · **multi-source post-wake verify** (`ping` / `tcp` / `seen` / `auto`) stamps responders into the `last_seen_at` signal and re-wakes only the hosts that didn't come up — ad-hoc single-host wakes opt into the same verify + bounded re-wake chain · **evidence trail** per target records what each source actually said, so "down according to what?" has an answer (`ping timed out, TCP refused nothing, last seen 3 days ago` is a dead box; `ping timed out, TCP connected` is a contradiction worth a look) · `wol_wake_failed` alert rule with a per-schedule mute · MAC fallback via `ip_mac_history` → DHCP lease · hard fan-out cap + auto-tuned stagger · togglable `tools.wake_scheduler` module |
| 📦 | **Packet capture** | on-demand tcpdump from **Tools → Packet Capture** — control-plane container *or* an appliance's real host NICs (interface dropdown + BPF presets + packet/duration/byte stop conditions) · live progress · keeps the partial on Stop · download `.pcap` for Wireshark · RBAC-gated (`manage_packet_capture`) + audited + auto-pruned |
| 🛰 | **Device profiling** | passive DHCP fingerprinting (scapy + fingerbank) **and** opt-in auto-nmap on new DHCP lease — what kind of device is on every IP |
| 🏷 | **OUI vendor lookup** | MAC → vendor names in IP tables, DHCP leases, search filters |
| 🛡 | **New-device detection** | arpwatch-style alert the moment a never-before-seen MAC appears · trusted-MAC / OUI allowlist · one-click block (writes a DHCP MAC block) · ingests from DHCP lease events + SNMP ARP/FDB + an opt-in L2 ARP/ND sniffer · review queue + "new devices 24h" dashboard KPI · randomised MACs excluded by default · opt-in `security.new_device_watch` module |
| 🕵 | **DNS threat analytics** | four independent detections over the query log SpatiumDDI already collects — no extra capture, no response inspection (the BIND9 log records the question, never the answer) · **tunneling** (iodine / dnscat2 / dnsteal — long high-entropy labels, many unique subdomains under one parent, elevated TXT/NULL/CNAME ratio) · **DGA** (a *crop* of implausible registrable names, structurally the inverse of tunneling, so it scores separately) · **C2 beaconing** (inter-arrival regularity — a callback on a timer barely varies, which almost nothing human-driven does; catches a beacon using one short ordinary name that scores zero on content) · **RPZ hit attribution** (a blocked lookup isn't a problem, but a host generating thousands of them is an infected machine announcing itself) · Threat tab on Logs + Security dashboard card + alert, deep-linked to the IP · **default-off — it reads the names clients look up** · needs query logging on at least one DNS group |
| 🚫 | **DNSBL / RBL reputation** | curated blocklist catalog + a daily sweep over NAT-egress / public / `internet_facing` / pinned IPs · `ip_blocklisted` latch alert that auto-resolves on delist or de-scope · **Reputation panel** on the IP detail modal · `security.dnsbl` module (no external DNS queries until the sweep switch is on) |
| 🎨 | **Dashboards** | nine sub-tabs — **Overview / IPAM / DNS / DHCP / Network / Integrations / Security / Compliance / Conformity** — each backed by a single rollup endpoint under `/api/v1/dashboards/`, refreshed every 60 s · utilization heatmap · DNS query rate · DHCP traffic · ASN drift + RPKI ROA expiry · circuit alerts · service-catalog orphans · per-mirror integration counts · account lockout state + active sessions + audit-chain verification · platform health card |
| 🔎 | **Global search + command palette** | `Cmd/Ctrl+K` from anywhere — **20 resource types** across IPAM / DNS / DHCP / network modeling / ownership / compliance, plus go-to-page commands sourced from the sidebar's own nav tree (so the palette cannot drift from the sidebar) · ranked **in SQL, before each type's `LIMIT`** — without an `ORDER BY` the database returns any N matching rows and the exact hit is routinely not among them, which sorting afterwards cannot recover · **every hit is filtered through the caller's own read grants**, so search can never be the way around a permission the rest of the API enforces · scope chips + recent searches · trigram GIN indexes on the tables that actually grow |
| 📊 | **Platform Insights** | native Postgres diagnostics + per-container CPU / mem / IO. No extra agents |
| 📈 | **InfluxDB push export** | ship DNS / DHCP counter deltas and IPAM + lease gauges to **InfluxDB v1, v2 or v3** on a per-target interval · counter points carry the agent's own 60 s bucket timestamp, so a backfill lands on the hour the traffic happened · watermarks advance only on a successful write, so a dead collector delays the export rather than punching a hole in it · the connection test is a real single-point **write**, not a reachability ping — a wrong bucket, org or token answers a GET perfectly well and then rejects every point |

### 🔌 Integrations (read-only mirrors)

| | Source | What's mirrored |
|---|---|---|
| 🐳 | **Docker** | networks · optional container IPs |
| ☸️ | **Kubernetes** | cluster CIDRs · nodes · LoadBalancer VIPs · Ingress → DNS |
| 🖥 | **Proxmox VE** | bridges · SDN VNets + subnets · VM / LXC NICs (qemu-guest-agent) |
| ☁️ | **Cloud (AWS / Azure / GCP)** | VPCs → IP blocks · subnets · NIC / public / load-balancer IPs · per-provider picker · paired with the agentless Cloud DNS drivers |
| 🔐 | **Tailscale** | tailnet devices + synthetic `*.ts.net` zone |
| 🕸 | **NetBird** | managed-WireGuard mesh peers + synthetic mesh zone |
| 📡 | **UniFi Network** | controller sites · networks (VLANs / CIDRs) · clients (with hostnames + MAC) |
| 🛡 | **OPNsense** | firewall interfaces (LAN / OPT / VLAN → subnets) · VLANs · DHCPv4 leases + static reservations → IPAM |
| 🔥 | **Palo Alto PAN-OS / Panorama** | address objects + groups → shadow IPAM · NAT rules · zones / interfaces · DHCP leases |
| 🔥 | **Fortinet FortiGate** | address objects + groups → shadow IPAM · VIPs (DNAT) · interfaces · DHCP leases |
| 🔥 | **Cisco Meraki MX** | appliance VLANs · DHCP fixed-IP reservations · org policy objects · 1:1 NAT + port-forward |

### 🚫 Active enforcement (the one write path)

Every integration above is a read-only mirror. **Active block sync** is
the deliberate exception — a narrow, heavily guarded write path that
pushes a real block at the natural enforcement point, so a device that
self-assigns a static IP can't walk past a DHCP block.

| | Target | How the block is enforced |
|---|---|---|
| 🛡 | **OPNsense** | firewall **table-alias** membership (by IP) — never rule CRUD |
| 📡 | **UniFi Network** | L2 client quarantine (by MAC) |
| 🔥 | **Palo Alto** | **Dynamic Address Group** `IP → tag` register via the User-ID API — no policy commit |
| 🔥 | **Cisco Meraki** | per-client built-in `Blocked` device policy via the Dashboard API |
| 🔥 | **Fortinet** | **credential-free feed inversion** — SpatiumDDI serves a token-scoped `blocklist.txt` the FortiGate polls as an External Threat Feed, so it holds *no write credentials on the firewall at all* |

Off by default, behind a feature module, a per-target enforcement master
switch, distinct write-scoped credentials, preview + audit on every push,
dedicated RBAC permissions (`manage_block_sync` /
`manage_firewall_enforcement`), and two-person approval. SpatiumDDI only
ever removes values it added — never alias members or blocked clients it
doesn't own.

### 🛡 Identity & ops

| | Feature | Highlights |
|---|---|---|
| 🔒 | **RBAC + external auth** | LDAP · OIDC · SAML · RADIUS · TACACS+ with backup-server failover · API tokens with auto-expiry · scoped API tokens (per-permission + resource-scoped — bind a token to one subnet / DNS zone for CI/Terraform credentials) · **enrolment QR** on the reveal-token modal — the bare token, or a `spatiumddi://enrol?…` URI carrying host, port, scheme **and the TLS certificate fingerprint**, so the mobile client's trust-this-certificate prompt becomes a machine check instead of 64 hex characters compared by eye |
| 🛡 | **TOTP MFA** | 2FA on local logins — QR enrolment via `pyotp` + `qrcode` · single-use backup codes · admin force-disable per user (audit-logged) · enrolment also open to SSO accounts so external-auth superadmins can re-confirm sensitive secret reveals (#408) |
| 🔐 | **Local-auth hardening** | configurable **password policy** (min length · per-class complexity · history depth · max-age) · **account lockout** after N failed logins inside a rolling window (default off; opt-in in Settings) · **active session viewer + force-logout** at `/admin/sessions` — every login carries a `jti` claim that resolves to a `UserSession` row, flip `revoked=True` to 401 the in-flight token on its next call |
| 🏷 | **Subnet classification tags** | `pci_scope` · `hipaa_scope` · `internet_facing` first-class boolean columns on every subnet · indexed predicates · compliance roll-up card on Platform Insights · feeds the compliance-change alert + conformity policy filters |
| 🤖 | **Operator Copilot (AI)** | grounded chat over your live IPAM / DNS / DHCP / Network data — multi-vendor (OpenAI / Anthropic / Azure OpenAI / Gemini / OpenAI-compat for Ollama, vLLM, etc.) with automatic failover · **hundreds of tools** spanning IPAM (incl. discovery / stale-IP / reconciliation / utilization trends / hygiene findings), DNS (records / pools / blocklists / views / DNSSEC / query stats / drift), DHCP (pools / statics / classes / option templates / PXE / MAC blocks / pool occupancy / rogue responders), network modeling (ASNs / VRFs / circuits / services / overlays / domains), the BGP Looking Glass (sessions / learned routes / as-path + community queries / reverse route lookup for an IP), ownership (customers / sites / providers), admin (users / groups / roles / time-bound grants), reports (top-N), network tools (ping / traceroute / dig / port-test / TLS-cert / whois / MAC-vendor / Wake-on-LAN + wake schedules, runs and calendars), integration mirrors (K8s / Docker / Proxmox / Tailscale / NetBird / UniFi / Cloud / OPNsense / Palo Alto / Fortinet / Meraki — plus the vendor-neutral firewall shadow-IPAM store, active block sync and firewall feeds), appliance fleet (firewall policies / LLDP neighbours / pairing / OS upgrades / upgrade images / etcd snapshots / host-config syslog + SSH + resolver), observability (DNS query / DHCP activity / metrics / Redis stats / global search), compliance (conformity policies + results + framework rollups), maintenance mode, typed-event webhooks (registry + event-type catalog + delivery history), multi-node rolling upgrade state (preflight / runs / lease), Windows-cutover plans (plan status / readiness blockers / live parity check), and Apply-gated write proposals — `propose_create_ip_address` / `propose_create_dns_record` / `propose_create_dhcp_static` / `propose_create_alert_rule` / `propose_run_nmap_scan` / `propose_run_packet_capture` / `propose_wake_host` / `propose_create_wol_schedule` / `propose_create_lg_peer` / `propose_archive_session` plus conformity / webhooks / DNSSEC / multicast / SNMP-NTP / DNS + DHCP import commits · MCP HTTP endpoint for Claude Desktop / Cursor / Cline · "Ask AI about this" affordances on every resource · per-provider editable system prompt · per-provider tool allowlist · OUI vendor enrichment baked in · live nmap results in chat · per-message token / latency footer · Markdown + GFM tables in replies · daily digest |
| 🔔 | **Alerts + forwarding** | rule-based alerts · `compliance_change` rule type (PCI / HIPAA / internet-facing audit-log scanner with 24 h auto-resolve, three disabled seed rules) · DNS query-anomaly rules (`dns_nxdomain_spike` / `dns_query_rate_spike`) · IP-hygiene rules (`ip_free_but_responding` / `stale_reservation` / `unknown_mac_in_static_range`) · `rogue_dhcp` (unexpected DHCP responder) · multi-target syslog (RFC 5424 / CEF / LEEF / RFC 3164) · HTTP webhooks · SMTP email · Slack / Teams / Discord chat |
| 📑 | **Conformity evaluations** | declarative policy library scheduled against PCI-DSS / HIPAA / SOC2 frameworks · 21 check kinds (`has_field` · `in_separate_vrf` · `no_open_ports` · `alert_rule_covers` · `last_seen_within` · `audit_log_immutable` · `voice_segment_not_internet_facing` · `no_multicast_collision` · `no_lanwide_control_plane_ports` · `av_flow_outside_reserved_range` · `av_flow_no_ptp_domain` · `bbmd_one_per_subnet` · `bacnet_duplicate_device_instance` · `bacnet_vendor_id_unknown` · `ot_device_crosses_purdue_boundary` · `ot_zone_missing_purdue_level` · `fragile_subnet_probed` · `dicom_ae_default_title` · `dicom_ae_title_convention` · `dicom_ae_outside_hipaa_scope` · `dicom_ae_no_tls`) · 19 disabled seed policies, opt-in toggle · pass→fail transitions emit alert events · auditor-facing PDF export with SHA-256 integrity hash · `Auditor` + `Compliance Editor` builtin roles |
| 🙋 | **Self-service request portal** | low-privilege users *ask* for an IP, subnet, DNS record or DHCP reservation they can't create themselves · a request provisions nothing on its own — an approver who must hold the underlying operation's own permission reviews it against that operation's real preview, and approving **runs it**, identically to a manual create · not a second state machine: portal rows reuse the approval spine (self-approval block, stale re-preview guard, apply-under-approver, both user IDs in the audit row) · `Requester` builtin role · default-off `governance.requests` module · block / subnet / zone / scope fields are **searchable pickers filtered to the requester's own read grants**, not raw UUID boxes — a scoped requester sees exactly their row and never an estate inventory |
| ⌨️ | **Keyboard shortcuts** | `?` opens a help overlay listing every binding, rendered from one shared map rather than a hand-written copy that goes stale — the global-search handler and its trigger keycap both read the same definition, so retuning a combo moves the handler, the keycap and the help together · stands down inside text inputs and won't stack over an open dialog |
| 🔖 | **Saved views** | per-user named filter / sort / column presets — *"every circuit with this provider whose term expires inside 90 days"* becomes one click · set a default per page · personal-only, never shared across users · wired into the Services / Circuits / Sites / Certificates list pages today; other pages opt in with two props |
| 🪝 | **Typed-event webhooks** | 144 typed events (39 resource namespaces × 3 verbs + 27 special-cased names) · HMAC-SHA256 signed · outbox-backed retry with backoff + dead-letter |
| 🐛 | **Diagnostics — captured uncaught exceptions** | every uncaught Python exception across API + Celery lands in a queryable `internal_error` table with **fingerprint dedup** (sha256 of class + top-2 frames), occurrence counter, last-seen-at bumping, redaction of headers + secret-shaped payload fields, `context_json` blob capped at 16 KB · admin viewer at `/admin/diagnostics/errors` with Acknowledge / Suppress (1 h / 1 d / 1 w) / Delete / **Submit-bug** (pre-filled GitHub-issue template URL) actions · daily prune sweep against the configured retention window |
| 🏷 | **Platform-wide tags + filter** | `tags JSONB` columns across IPAM (spaces / blocks / subnets / IPs) · Network modeling (ASNs / VRFs / circuits / services / overlays / customers / sites / providers) · DNS (zones / records) · DHCP (scopes / pools / statics) · `?tag=` filter on every REST list endpoint with multi-tag AND/OR semantics · `/api/v1/tags/autocomplete` ranked by occurrence · tag chips on every list view + clickable pills on the IP detail modal that navigate to a filtered IPAM view |
| 🔏 | **TLS certificate monitoring** | auto-discover certs serving from managed DNS A/AAAA records + IPAM `web` / `api` / `lb` roles · full-chain probe (leaf → intermediate(s) → root) via pyOpenSSL · expiring / chain-invalid / SAN-mismatch / unreachable / changed alerts · Network → Certificates page + Domain / DNS-zone Certs tabs · "Certs expiring ≤30d" dashboard KPI |
| 🔐 | **ACME DNS-01 provider** | `acme-dns`-compatible — certbot / lego / acme.sh issue public certs (wildcards included) |
| 🔐 | **ACME embedded client** | hand-rolled RFC 8555 — auto-issue a CA-trusted Let's Encrypt cert for SpatiumDDI's own Web UI · DNS-01 over managed + cloud zones · HTTP-01 · manual-TXT fallback · 12 h auto-renewal |
| 📋 | **Audit log** | every mutation logged, append-only, filterable in the UI · **tamper-evident SHA-256 hash chain** — every row carries `seq` + `prev_hash` + `row_hash`; verifier walks the table, re-hashes, and pinpoints the first break |
| 🗑 | **Soft-delete + 30-day Trash** | spaces / blocks / subnets / DNS zones / DNS records / DHCP scopes are recoverable for 30 days · cascade restore via `deletion_batch_id` (one click brings a subnet's DHCP scopes back together) · global ORM filter hides soft-deleted rows by default · nightly `trash_purge` Celery task hard-deletes past the retention window |
| 💾 | **Backup + restore** | full-system backup with passphrase-wrapped `secrets.enc` + 10 destination kinds (local volume · AWS S3 / S3-compatible · SCP/SFTP · Azure Blob · SMB/CIFS · FTP/FTPS · GCS · WebDAV · NFS · HTTPS PUT/POST) · scheduled cron + retention · selective per-section restore · cross-install secret rewrap so cross-install operators don't hand-copy `SECRET_KEY` · `alembic upgrade head` on restore with drift auto-recovery · exclude-secrets diagnostic mode for shareable debug snapshots · proxy archive download · **restore drills** — scheduled test-restores into a throwaway scratch database that prove an archive is actually restorable, on their own cadence, with a target that has never passed reported as *unverified* rather than healthy · `system.backup_*` typed-event fan-out via the existing webhook outbox |
| 🩺 | **Support bundle** | one-click scrubbed diagnostics archive for a bug report — superadmin, audited, and working on Compose / Kubernetes / appliance alike · **secrets are hard-excluded in every mode**, including the unscrubbed one (Fernet blobs, password hashes, PEM keys, JWTs, agent PSKs, credentials in a database URL — matched by field name *and* value shape) · identifiers are pseudonymised HMAC-deterministically off `SECRET_KEY`, so **topology survives**: one real /24 lands in one synthetic /24 with the host octet intact and zone grouping preserved, which is what keeps the archive worth reading for a DDI product · preview → review → download, with the decode map on a separate endpoint and **never inside the archive** · designed on the premise that **GitHub attachments are public**, so the answer is scrubbing rather than secrecy |
| 🎨 | **Operator branding** | acceptable-use **login banner** with an acknowledgement checkbox that gates the SSO buttons too (otherwise the notice is skipped by signing in through the IdP) · **custom logo**, stored in Postgres rather than on a volume so it survives a multi-node control plane, PNG-only validated by magic bytes (an SVG served same-origin would be stored XSS against anonymous visitors) · coloured **DEV / TEST / PROD strip** with a contrast warning · a real browser + product title · all of it readable before a session exists via an unauthenticated `GET /settings/public` allow-list, written superadmin-only because it renders to anonymous visitors |
| 🔁 | **Service control** | start / stop / restart SpatiumDDI's own services from **Admin → Platform Insights → Services** on Docker Compose, Helm *and* the appliance · **the capability is answered before anything is attempted** — the UI renders the buttons that exist instead of drawing one and learning from its error, because "this deployment cannot do that" and "the daemon is down" need opposite responses · the live inventory *is* the allowlist, scoped on Compose to the api container's own project label and failing closed if it can't identify itself · off by default except on the appliance, with the env gate and the RBAC as separate switches so each failure is reported as itself |
| 🧹 | **Factory reset** | per-section "wipe back to defaults" surface for superadmins — 12 sections (IPAM · DNS · DHCP · Network modeling · Integrations · AI · Compliance · Tools · Observability logs · Auth+RBAC · Settings · Everything) · password re-verification + per-section `DESTROY-*` confirm phrase + in-flight backup mutex + 6 h cooldown · audit anchor that survives `audit_log` wipes · calling superadmin + built-in roles preserved across every section |

### 🚀 Deployment

| | Path | |
|---|---|---|
| 🐳 | **Docker Compose** | `docker compose up -d` |
| ☸️ | **Kubernetes** | Helm umbrella chart, OCI-published |
| 🖥 | **Bare metal / OS appliance** | bare metal today · self-contained appliance ISO (beta — Debian 13 + full stack, hybrid USB/CD, see [Getting Started](#quick-start-with-the-os-appliance-iso-recommended)) |

---

## Full feature detail

The tables above are the elevator pitch. The bullets here are the same surface with the operational detail — what's stored, how it behaves, where the seams are.

### Core DDI

- 🗂 **Hierarchical IP management** — spaces, blocks, subnets, addresses in a visual tree.
  - IPv4 + full IPv6 auto-allocation (EUI-64 / random /128 / sequential)
  - Per-IP role: host / loopback / anycast / vip / vrrp / secondary / gateway
  - Reservation TTL with auto-expiry
  - Per-IP MAC observation history
  - **Bulk allocate** a contiguous range with a name template
    (`dhcp-{n}` / `host-{oct3}-{oct4}` / `web-{n:03d}`) — preview
    → commit, capped at 1024 IPs, skips dynamic DHCP pools, detects
    FQDN collisions, optionally creates A + PTR records
  - **IP table polish** — sticky column headers, shift-click range
    select, "Seen" recency dot per row (alive / stale / cold /
    never), subtle gap markers between non-contiguous IPs so a
    deleted hole doesn't go unnoticed

- ✂️ **Subnet operations** — preview-then-commit with typed-CIDR confirm.
  - Split, Merge, Find-Free workflows
  - Surfaced on the subnet detail header *and* via bulk-action toolbars on the block + space tables
  - Bulk-select 1 row to split, 2+ to merge
  - Block-detail tables reach parity with the space view — child blocks are bulk-selectable too, so leaf-empty blocks cascade-delete alongside subnets in one shot

- 🧮 **Subnet planner + planning tools** — design CIDR hierarchies before applying them.
  - `/ipam/plans` — draggable multi-level CIDR design surface (root + nested children, arbitrary depth)
  - Saved as `SubnetPlan` rows, validated live as the operator edits, applied in a single transaction
  - Per-node DNS-group / DHCP-group / gateway bindings (null = inherit, explicit = set + flip inherit off)
  - CIDR calculator at `/tools/cidr` — pure client-side IPv4 + IPv6 breakdown
  - Address planner — packs `{count, prefix_len}` requests into free space using largest-prefix-first ordering
  - Aggregation suggestion banner — surfaces clean-merge opportunities (10.0.0.0/24 + 10.0.1.0/24 → /23)
  - Free-space treemap toggleable from the Allocation map header — surfaces fragmentation hidden in the 1-D band

- 🗑 **Soft-delete + Trash recovery** — 30-day Trash with cascade restore.
  - Covers IP spaces, blocks, subnets, DNS zones / records, DHCP scopes
  - Cascade-stamped batch IDs — one Restore click brings back every dependent row atomically
  - Conflict detection on restore guards against clashing with live rows
  - Operator-configurable purge sweep (`soft_delete_purge_days`, default 30; `0` = keep forever)

- 🔁 **NAT mapping cross-reference** — operator-curated rules with FK links to IPAM.
  - 1:1 / PAT / hide-NAT supported
  - Per-IP modal lists every mapping that touches the address
  - Per-subnet "NAT" tab uses Postgres CIDR containment to find every mapping crossing into the subnet's range

- 📜 **DHCP lease history** — forensic trail of every lease lifecycle event.
  - Captures expiry, MAC reassignment, absence-delete
  - Operator retention window (default 90 days), daily prune task

- 🌐 **Built-in DNS server** — BIND9 *or* PowerDNS *or* Technitium container, auto-registers, syncs via RFC 2136.
  - **Three first-class drivers.** A server group is BIND9, PowerDNS or Technitium. Zones, records and pools are authored identically whichever you pick and the driver decides how they render — but the three are **not** feature-equivalent, and the difference is worth knowing before you pick:
    - **BIND9 only** — split-horizon **views** and **RPZ blocklists**. The PowerDNS and Technitium drivers both report `views: False` / `rpz: False`; a group on either will not serve them (Technitium has its own native blocking — below — but not RPZ)
    - **PowerDNS only** — **ALIAS** and **LUA** records (below)
    - **Technitium only** — native **DNS-over-QUIC**, and encrypted upstream forwarding over **HTTPS and QUIC** as well as TLS (BIND 9.20 has no client-side HTTP or QUIC transport at all). It also blocks natively from a per-domain set rather than via RPZ, so SpatiumDDI's blocklists map onto that instead — with two documented lossy edges: per-view lists collapse into one flat set, and `is_wildcard` is dropped because Technitium blocks a domain and its subdomains by default
    - **Online DNSSEC sign / unsign** — PowerDNS and Technitium. BIND9 signs from a rendered `dnssec-policy` instead
    - **Catalog zones** — BIND9 and Technitium do producer *and* consumer; PowerDNS is **producer-only**
    - **Technitium ships in two shapes** — `technitium` is the container SpatiumDDI deploys and an agent drives over loopback; `technitium_api` is *agentless*, for an install the operator already runs, driven straight from the control plane over its HTTP API with nothing deployed. Zone and record CRUD plus topology pull on the agentless one; DNSSEC, encrypted transports, forwarders and blocklists stay agent-managed. A group is single-driver, so the two live in separate groups
    - Windows DNS, agentless Technitium and the eight cloud providers are agentless drivers behind the same abstraction — all nine credentialed ones now answer a **Test Connection** probe on a saved server, so "did that token work?" no longer means waiting for a sync to fail
  - Per-server zone-serial drift reporting
  - **Record-level drift report** — per zone, AXFR the live zone from every server in the group and diff it against the database: *extra on server* (someone edited the host by hand), *missing on server* (a change never landed), *in sync*. Strictly read-only — it never applies anything, and the Sync path stays the way you push. A changed value shows as a missing+extra pair, because the diff key includes the value. Split-horizon zones carry a caveat banner: a transfer is addressed by zone *name*, so the server answers from whichever view matches the control plane's source address. **Driver coverage: every driver except PowerDNS**, which implements no record pull at all. Windows Path B, the cloud drivers and agentless Technitium (`technitium_api`) pull over an API; agent-managed BIND9 and Technitium use a TSIG-signed AXFR, because their agents grant transfer to the group's key rather than to an address ([#734](https://github.com/spatiumnorth/spatiumddi/issues/734)) — a group with no TSIG key reports that rather than a bare refusal
  - **PowerDNS-only record types** — synthesised at query time by `pdns_server`, so they have no BIND9 equivalent:
    - **ALIAS** — an apex CNAME-equivalent. Lets `example.com` itself point at a cloud load balancer's hostname, which a real CNAME can't do at the apex without breaking the SOA / NS rrset
    - **LUA** — scripted answers (health-aware, client-aware, arithmetic). **Security boundary worth stating plainly:** LUA record scripts execute inside the `pdns_server` process, so anyone who can author one has code execution in your DNS daemon. Authoring is gated on the usual DNS write permission — scope that permission accordingly, and treat it as more privileged than authoring an A record
  - **DNSSEC** — two signing models behind one UI, and SpatiumDDI holds **no private key material** in either
    - **BIND9 inline-signing** — the zone references a `dnssec-policy` and BIND generates, rotates and retires keys itself in its key directory. SpatiumDDI stores only the public key state it reads back
    - **PowerDNS online signing** — sign / unsign a zone from the zone page (`pdnsutil secure-zone` semantics); pdns signs responses on the fly rather than writing a signed zone file
    - **Technitium online signing** — same zone-page sign / unsign, defaulting to ECDSA P256 with NSEC. DS records are assembled from the KSK's own DNSKEY digests and reported with per-key state; Technitium rolls keys on its own schedule, so manual rollover stays BIND9-only
    - **Reusable policy library** — KSK + ZSK algorithm / size / lifetime, and **NSEC or NSEC3** with iterations, salt length and opt-out. One policy applies to many zones
    - **DS export** — the delegation-signer record to hand to the parent zone's registrar, which is the step that actually turns validation on. Copy it out of the zone's DNSSEC panel
    - Manual and scheduled **key rollover**, with per-zone key state (active / published / retired) visible per server
  - **Zone authoring**:
    - Delegation wizard — auto-stamps NS + glue in the parent zone
    - Four starter templates: Email (MX / SPF / DMARC), Active Directory (LDAP / Kerberos / GC SRV), Web (apex + www), k8s external-dns target
    - Conditional forwarders as a first-class zone type
  - **TSIG keys** — full CRUD with Fernet-encrypted secrets
    - One-shot "copy this secret now" reveal modal
    - Rows distribute through the existing `tsig_keys` ConfigBundle block
  - **RPZ blocklists** — 19-source curated catalog with one-click subscribe + immediate refresh
    - Sources: AdGuard, StevenBlack, OISD, Hagezi, 1Hosts, Phishing Army, URLhaus, EasyPrivacy, …
    - **Content filtering / family filter** — a one-click **Family filter** profile pairs the adult + gambling feeds with the DoH / VPN / proxy bypass lists, because a filter a browser can route around is not one
    - **SafeSearch enforcement** — a built-in template that rewrites each engine to its own filtered endpoint (all 194 Google country domains, the five YouTube hostnames Google documents and no others, Bing including the Edge sidebar entry point, DuckDuckGo / Brave / Ecosia / Pixabay / Qwant, Yandex opt-in)
    - **Scope a list to a view, not just a server group** — which is what makes "filter the kids' VLAN and not the server one" a real setting: the Views tab is full CRUD with an *Add subnets…* picker that turns IPAM prefixes into `match_clients`, and each list carries a scope modal writing group + view assignment in one call. Everything an operator types there (`match_clients`, `match_destinations`, the view name — which also becomes a directory on the agent) is validated server-side, because it is interpolated verbatim into `named.conf`: an accepted-but-invalid value does not break one view, it stops the whole group's config converging, silently
    - Applying a profile assigns it to **nothing** — auto-scoping would filter the server VLAN along with the kids' one, so assignment stays a deliberate second step
  - **Rate limiting (RRL) + amplification defenses** — BIND9 Response Rate Limiting (responses-per-second / window / slip / qps-scale / exempt-clients) with a `log-only` dry-run, plus `minimal-responses` / `tcp-clients` / `clients-per-query` toggles; group-level, default-off (no-op until opted in)
    - **RRL drop observability** — `RateDropped` / `RateSlipped` charted as an "RRL drops/s" line on the server Stats tab + a default-off `dns_rate_limit_dropping` alert (fires when the server is actively shedding a flood)
    - **dnsdist front for PowerDNS** — opt-in front container (PowerDNS auth has no RRL of its own) forwarding to pdns: per-source-IP QPS cap (truncate / drop) + sustained-rate dynamic blocking, on a `dns-powerdns-with-dnsdist` compose profile (docker-compose for now)
  - **Encrypted transports (DoT / DoH / DoQ)** — two independent halves, both per-group and default-off so an existing install renders a byte-identical `named.conf` until you opt in
    - **Inbound** — serve DNS-over-TLS (RFC 7858, :853) and DNS-over-HTTPS (RFC 8484, `/dns-query`) alongside plain Do53, which is unaffected. Technitium adds **DNS-over-QUIC**, which defaults to :853 alongside DoT — not a copy-paste slip: DoQ is UDP and DoT is TCP, so they do not collide (the firewall opens both)
    - **Outbound** — forward to upstream resolvers over DoT instead of cleartext :53, with `remote-hostname` validation that fails closed (SERVFAIL, never a silent downgrade); opportunistic mode available for upstreams that publish no DoT hostname. Technitium also forwards over **DoH and DoQ**. Encrypted forwarding needs a hostname rather than an IP — there would be nothing to validate the upstream's certificate against — so the group's `forward_tls_hostname` is required and wins over the forwarder IPs
    - **Upstream resolver presets** — 16 across 7 providers (Cloudflare, Google, Quad9, Cisco OpenDNS, AdGuard, Mullvad, DNS4EU), each carrying the addresses **and the certificate name those addresses actually present**, because the two cannot be filled in inconsistently without the group resolving nothing. The unit is the preset, not the brand: `1.1.1.1` is `cloudflare-dns.com` and `1.1.1.3` is `family.cloudflare-dns.com`, so mixing them breaks exactly like mixing two vendors while looking entirely deliberate — that combination is a 422, as is an encrypted-only upstream selected with Do53. A merely-undocumented hostname is a UI advisory, never a refusal, and manual entry is unconstrained: the catalogue is a convenience, never a whitelist
    - **Certificates** reuse the appliance cert store — upload one or issue it from Let's Encrypt with the built-in ACME client; renewals reach the agents automatically. A listener whose cert is deleted degrades to Do53 rather than taking the daemon down
    - BIND9 and Technitium serve natively; PowerDNS gets inbound-only via the dnsdist front (pdns auth speaks neither protocol and doesn't forward). On Technitium the agent converts the stored PEM to a PKCS #12 bundle, which is the only format the daemon accepts
    - Ports are operator-chosen and flow through to the appliance firewall automatically. DoH defaults to 443, which the appliance rejects because the web UI owns it there — use 8443
  - **Named ACLs** — reusable address-match lists rendered into `named.conf` **above `options`**, which is the correctness property rather than a style choice: BIND resolves an `acl` where it is written, so a definition below its first use is an error and not a forward declaration. Nested references are emitted dependency-ordered, and a cycle is refused at the commit by a graph check, since `a → b → a` is two individually legal edges no per-field validation can see. Deleting or renaming an ACL something still cites is a 409 naming the citers; an entry-less one renders `{ none; }` rather than vanishing, because omitting a definition that may already be cited is what takes a whole group's config down
  - **Catalog zones (RFC 9432)** — producer / consumer roles auto-derived from the group's primary
    - RFC-compliant SHA-1 hashing of zone names
  - **Operator tools**:
    - Multi-resolver propagation check (Cloudflare / Google / Quad9 / OpenDNS in parallel) on every record row
    - Clickable analytics strip on the Logs page (top qnames + top clients + qtype distribution)
    - Per-server detail modal — Overview / Zones / Sync / Events / Logs / Stats / Config tabs + a live `rndc status` panel — answers "is this server actually running the config we sent?" without SSHing in

- ⚖️ **DNS pools (GSLB-lite)** — health-checked DNS round-robin.
  - One DNS name returns one record per healthy + enabled member; members flip in / out of the rrset as state changes
  - **Health checks**:
    - `tcp` — open-connection probe
    - `http` / `https` — status-code match with optional TLS verification
    - `icmp` — echo-request via `iputils-ping`
    - `none` — always healthy (for pools that just want manual-enable + multi-RR semantics)
  - Per-pool interval (default 30 s), timeout, and consecutive-failure / consecutive-success thresholds so single flapping checks don't churn records
  - **Operator UX**:
    - Top-level `/dns/pools` page — every pool across every zone with live health summary
    - Per-zone Pools tab on the zone detail page
    - Manual enable / disable per member, like a load-balancer pool
  - **Driver-agnostic** — members render as regular A/AAAA records via the normal record pipeline, so BIND9 + Windows DNS serve them unchanged
  - **Tradeoff (UI-warned)** — TTL races. DNS is cached client-side; a member dropping out doesn't take effect until TTL expires. This is not a real L4/L7 load balancer. Default TTL is 30 s with an inline pointer to the LB-mapping roadmap item.

- 🔄 **DHCP server management** — Kea container + agent with lease tracking.
  - Group-centric HA (hot-standby + load-balancing) with live state reporting
  - Self-healing peer-IP drift
  - Supervised daemons for crash-loop-safe restarts
  - **Scope authoring**:
    - 95-entry RFC 2132 + IANA option-code library with autocomplete on the custom-options row (search by code or name, description shown inline)
    - Named option templates (group-scoped, e.g. "VoIP phones", "PXE BIOS clients") — apply to a scope in one click; apply is a stamp not a binding, so later template edits don't propagate
  - **PXE / iPXE provisioning profiles** — netboot a mixed-architecture estate without hand-writing Kea client classes
    - A profile is group-scoped and reusable; a scope selects one via `pxe_profile_id`. It carries the `next_server` (TFTP / HTTP boot host) and N **architecture matches**
    - Each match pairs a vendor-class + DHCP arch-code filter with the boot file that architecture should pull — `undionly.kpxe` for BIOS, `ipxe.efi` for UEFI x64, the arm64 or ia32 equivalents, or a chained iPXE config URL
    - **iPXE chainloading** is the case that makes this worth modelling: the classic two-stage boot needs a class guarded on `dhcp.user-class` matching the iPXE signature, so the second request (from iPXE itself) is answered with a script URL instead of the binary it already loaded — otherwise the client loops
    - Profiles can be **disabled** rather than deleted; a disabled profile renders no classes at all, so an operator can A/B-test boot files and roll back by flipping one switch

- 🪟 **Windows Server DNS + DHCP** — agentless management of existing Windows DCs.
  - RFC 2136 + WinRM for DNS
  - Near-real-time WinRM lease-mirroring for DHCP
  - No software installed on the Windows side

- 📥 **DNS configuration importer** — one-shot migration tool that turns existing zone data into native SpatiumDDI zones + records.
  - Four sources, one canonical IR + commit pipeline:
    - **BIND9** — upload a `.zip` / `.tar.gz` of the `named.conf` tree; the parser walks `include` directives, resolves zone files via four strategies (relative path, absolute path, `directory` option, search), tolerates `view {}` blocks, and feeds the same canonical-zone shape the other sources do
    - **Windows DNS** — live pull over WinRM via the existing `WindowsDNSDriver`; honours system zones (TrustAnchors / `_msdcs.*`) by routing them through a dedicated branch instead of trying to migrate them
    - **PowerDNS** — live pull over the authoritative REST API (`X-API-Key` auth, hard cap of 5000 zones / 60 s socket timeout); hoists SOA from rrset content, splits MX / SRV priority into the dedicated columns, drops disabled records + DNSSEC + LUA / ALIAS with distinct warnings
    - **Technitium** — live pull over the console REST API (token auth); only `Primary` zones import, with secondary / stub / forwarder / catalog reported as warnings rather than minted as rows SpatiumDDI would then serve authoritatively. Technitium returns structured `rData` whose field names differ from its own *write* API and which renders numeric rdata as enum names, so the importer inverts that back to wire values (`DANE-EE` / `SPKI` / `SHA2-256` → `3 1 1 <hex>`), passing unknown enum members through unchanged
  - Preview-before-commit on every source — operator sees the conflict picker (overwrite / skip / merge) before any rows are written
  - Per-zone savepoint commit so a failure on zone N rolls back N but keeps zones 1..N-1 — no all-or-nothing import abort
  - Provenance stamping — `import_source` + `imported_at` columns on `dns_zone` + `dns_record` flag everything that came in from the importer (UI surfaces a chip)
  - Tabbed admin page at `/admin/dns/import` — one tab per source (plus a Cloud tab that pulls from a registered cloud-DNS server row), all rendered by a shared preview panel + commit-result panel
  - Once imported, SpatiumDDI is the source of truth — there is no continuous two-way mirror

- 🪟 **Windows → SpatiumDDI cutover** — the importers land a *copy* of the Windows estate and prove nothing about what happens next: the Windows server is still running, still authoritative, and still the thing clients actually talk to. This is the other half of the journey, and it is emphatically **not** a fifth importer — it creates no zones, scopes, pools or records. Its only writes are TTL reductions on a zone SpatiumDDI already owns, reservations synthesised from live Windows leases, and the `is_active` flag on a managed scope.
  - The unit of work is a **plan** — a source Windows DNS and/or DHCP server, a target server group, and a list of **items**. One item is one zone or one scope. Items are independent: they can be cut over on different days and each rolls back on its own. There is no big-bang step anywhere
  - **Phase 1 — parity.** Diff each object against the live Windows server, classifying every difference by *why* the two sides differ: `value_mismatch` / `drifted_since_import` / `never_imported` / `intentionally_diverged`. A changed record pairs into one decision rather than the missing+extra pair the drift report produces. A Path-B PowerShell pull can't emit CAA / TLSA / SSHFP, so those report `not_compared` rather than missing; an unparseable response reports `unverified` rather than "everything diverged"
  - **Phase 2 — parallel run.** Replay recently-observed queries from the query log against both sides and compare answers, so parity is *demonstrated against production traffic* rather than asserted from config equality. Queries go out with RD=0, so a cached answer from somewhere else can't stand in for the server under test
  - **Phase 3 — the switch.** A TTL pre-flight that snapshots the originals once and restores them exactly; a DHCP lease handover that promotes live Windows leases to reservations, so a renewing client keeps the address it already holds instead of meeting a Kea with an empty lease database; then the switch itself, which deactivates the Windows scope **before** activating the managed one and puts the old one back if the new side fails to come up
  - **Phase 4 — a 15-item decommission checklist**, three of them advisory-evaluated from SpatiumDDI's own data (DC SRV registration, reverse-zone ownership, zone-transfer ACLs — the three an operator is most likely to get wrong). None is ever auto-ticked
  - **Readiness blockers, and one refusal that `force` can't bypass** — an AD-integrated zone set to "Secure only" dynamic updates is a hard block, because GSS-TSIG is unimplemented and a domain controller that can't register its SRV records turns a DNS migration into a domain outage. It fails closed: a dynamic-update mode we can't interpret on an AD-integrated zone is treated as Secure
  - **A markdown runbook** to paste into a change ticket — deliberately not a summary of what SpatiumDDI already did. It carries the Windows-side PowerShell SpatiumDDI won't run for you (lowering the *authoritative* TTLs resolvers actually cache — lowering only our side is worse than lowering neither, because it promises a five-minute rollback while the world holds hour-long answers), the order of operations, and a rollback with a real number attached
  - Behind the `migration.cutover` feature module (ships **disabled**), **superadmin on every endpoint** — a cutover is strictly more dangerous than an import, so inventing a grantable permission for it would be a *weaker* posture than the surface it extends

- 📡 **Multicast group registry** — IPv4 + IPv6 multicast groups as first-class entities.
  - RFC 5771 IANA registry seeded as platform-provided rows (e.g. `224.0.0.1` All-Hosts, `224.0.0.5` OSPF, …)
  - Operator catalog of business-defined groups (per-IPSpace) with description, owner, scope (link-local / admin-local / org-local / global)
  - **PIM rendezvous-point domains** — `pim_rp_domain` table tracking RP routers + group ranges they serve
  - **IPAM tree integration** — creating a group in an IPSpace auto-creates the enclosing `224.0.0.0/4` (v4) or `ff00::/8` (v6) IPBlock when none exists; a startup hook backfills blocks for pre-existing groups so the upgrade is seamless
  - **Tree rendering** — multicast IPBlocks render with a violet 📡 Radio icon in both the tree row and BlockDetailView identity row; inside a multicast block, a "Multicast Groups" panel surfaces the streams whose addresses fall within the block's CIDR (queries `multicast_group` directly — no mirror IPAddress rows)
  - **Click-through** opens the multicast page pre-scoped to the IPSpace via `?space=<uuid>`
  - **Bulk-allocate** from RFC 2365 admin-scoped ranges with name templating
  - Per-IP collision conformity check — flags addresses that overlap a known multicast registration before allocation

### Network entities

- 🌐 **ASN management** — first-class autonomous-system entity.
  - Data model: `asn` table with BigInteger `number` (full 32-bit range), auto-derived `kind` (public / private per RFC 6996 + RFC 7300), auto-derived `registry` (RIR — arin / ripe / apnic / lacnic / afrinic) from a hand-curated IANA delegation snapshot
  - **RDAP holder refresh** — per-RIR routing via IANA bootstrap; per-row Refresh button + scheduled hourly task (`asn_whois_interval_hours`, default 24 h)
  - **RPKI ROA pull** — Cloudflare or RIPE NCC source (operator-tunable via `rpki_roa_source`); cached for 5 min in-memory so a sweep of 50 ASNs makes one HTTP call; per-row Refresh RPKI button
  - **Holder-drift diff viewer** — `previous_holder` persisted on every refresh so the WHOIS tab can render a side-by-side without consulting the audit log
  - **Alert rules** — `asn_holder_drift`, `asn_whois_unreachable`, `rpki_roa_expiring`, `rpki_roa_expired`
  - **BGP Footprint tab** — what the *rest of the internet* sees for this AS, alongside what you've recorded. RIPEstat supplies announced prefixes, prefix-overview and routing history; PeeringDB supplies the peering profile and IXP presence. Read-only, REST + MCP, with an in-process TTL cache (RIPEstat 6 h, PeeringDB 24 h) so an open tab doesn't hammer either service
  - Detail page tabs: WHOIS · RPKI ROAs · **BGP Footprint** · BGP Monitoring · Learned Routes (only when the Looking Glass module is on) · BGP Peering · Communities · IP Spaces / Blocks · Alert History

- 🤝 **BGP peering + communities** — operator-curated relationship graph + community catalog.
  - **Peerings** — `bgp_peering` table with `peer | customer | provider | sibling`; both endpoints FK ON DELETE CASCADE; unique on `(local, peer, relationship_type)`. Form lets the operator pick either side as "local"; modal normalises to canonical shape on submit
  - **`Router.local_asn_id` FK** — stamps which AS a router originates routes from
  - **Communities catalog** — 7 RFC 1997 / 7611 / 7999 well-knowns seeded as platform rows (no-export, no-advertise, no-export-subconfed, local-as, graceful-shutdown, blackhole, accept-own); per-AS catalog with `kind` validation (`standard` / `regular` `ASN:N` / `large` `ASN:N:M`)
  - "Use on this AS" button per standard row pre-fills the form with the well-known value

- 🛣 **VRFs as first-class entities** — replaces the freeform `vrf_name` / `route_distinguisher` / `route_targets` text fields on IPSpace.
  - Data model: `vrf` table with name, description, optional `asn_id` FK, RD (with format validation), split import / export RT lists, tags, custom_fields
  - `ip_space.vrf_id` + `ip_block.vrf_id` FKs ON DELETE SET NULL
  - **Cross-cutting RD / RT validator** — each `ASN:N` entry whose ASN portion does not match `vrf.asn.number` produces a non-blocking warning; `vrf_strict_rd_validation` toggle escalates to 422
  - `IPBlock.vrf_warning` flags when a block's pinned VRF differs from its parent space's VRF (intentional in hub-and-spoke designs but worth a heads-up)
  - **VRF picker** on the New / Edit IPSpace and Create / Edit IPBlock modals (replaces the freeform text inputs)
  - Migration backfills existing freeform values into VRF rows so nothing is lost

- 📛 **Domain registration tracking** — distinct from DNSZone (records SpatiumDDI serves vs. registry-side metadata).
  - Data model: `domain` table tracking registrar / registrant / expiry / DNSSEC status / nameservers
  - **RDAP refresh** — TLD → RDAP-base lookup driven by the IANA bootstrap registry (`data.iana.org/rdap/dns.json`), cached 6 h; routes `.com` → `rdap.verisign.com/com/v1/`, etc.
  - **Nameserver drift** — operator-pinned expected list vs. registry-advertised list, with a side-by-side diff panel
  - **Alert rules** — `domain_expiring` (severity escalation around `threshold_days`), `domain_nameserver_drift`, `domain_registrar_changed`, `domain_dnssec_status_changed`
  - Per-row expiry countdown badges (green > 90 d / amber 30–90 d / red < 30 d / dark-red expired)
  - **Explicit `dns_zone.domain_id` linkage** with sub-zone suffix-match fallback — `test.example.com` shows up under `example.com`'s linked-zones tab; `example.com.au` correctly does NOT

- 🏢 **Customer / Site / Provider** — three first-class logical ownership rows that cross-cut IPAM / DNS / DHCP / Network.
  - **`Customer`** — soft-deletable; account number / contact info / status (active / inactive / decommissioning) / tags
  - **`Site`** — hierarchical via `parent_site_id`; unique-per-parent `code` (NULLS NOT DISTINCT for top-level deduping); kinds (datacenter / branch / pop / colo / cloud_region / customer_premise) + free-form region label
  - **`Provider`** — kinds (transit / peering / carrier / cloud / registrar / sdwan_vendor) + optional `default_asn_id` FK
  - **Cross-reference FKs** added on subnet / ip_block / ip_space / vrf / dns_zone / asn / network_device / domain / circuit / network_service / overlay_network — every column is `ON DELETE SET NULL` so re-tagging is safe and operators never lose data
  - Shared `CustomerPicker` / `SitePicker` / `ProviderPicker` (with optional kind filter) + matching Chip components plug into every IPAM / DNS / circuit / overlay create + edit modal

- 🛤 **WAN circuits** — carrier-supplied logical pipe distinct from the equipment that lights it up.
  - Data model: `circuit` table with `provider_id` (RESTRICT), optional `customer_id` (SET NULL), 4 endpoint refs (a/z-end site + subnet, all SET NULL), `transport_class` enum (mpls / internet_broadband / fiber_direct / wavelength / lte / satellite / direct_connect_aws / express_route_azure / interconnect_gcp), asymmetric `bandwidth_mbps_down` / `bandwidth_mbps_up`, `term_start_date` / `term_end_date`, `monthly_cost` + 3-letter ISO 4217 currency
  - **Soft-deletable** — `status='decom'` is the operator-visible end-of-life flag; row stays restorable for "what carrier did Site-X use in 2024?" audits
  - List page at `/network/circuits` with bulk-action table + tabbed editor modal (General / Endpoints / Term + cost / Notes) + colour-coded term-end badge
  - **Alert rules** — `circuit_term_expiring` (severity escalates around `threshold_days`), `circuit_status_changed` (only fires on `suspended` / `decom` transitions; auto-resolves after 7 d)

- 📦 **Service catalog** — bundles network resources into a customer-deliverable.
  - `NetworkService` is one row per thing the operator delivers; polymorphic `NetworkServiceResource` join row binds to VRF / Subnet / IPBlock / DNSZone / DHCPScope / Circuit / Site / OverlayNetwork
  - **Kinds in v1**: `mpls_l3vpn` (with hard at-most-one-VRF rule + soft warnings for missing VRF, fewer than 2 edge sites, edge subnet's enclosing block in a different VRF) and `custom`. `sdwan` lit up alongside the SD-WAN overlay roadmap. Future kinds reserved in the column: `mpls_l2vpn` / `vpls` / `evpn` / `dia` / `hosted_dns` / `hosted_dhcp`
  - **Kind-aware `/summary` endpoint** — L3VPN view returns canonical VRF + edge sites + edge circuits + edge subnets + warnings
  - **Reverse lookup** — `GET /by-resource/{kind}/{id}` returns every service referencing a given resource
  - **Alert rules** — `service_term_expiring` (mirrors circuit shape), `service_resource_orphaned` (sweep over join rows whose target was deleted; auto-resolves on detach)
  - List page at `/network/services` (bulk-action table) + tabbed editor modal (General / Resources / Term + cost / Notes / Summary)

- 🌐 **SD-WAN overlays** — vendor-neutral source of truth for overlay topology and routing-policy intent.
  - Vendor config push (vManage / Meraki Dashboard / FortiManager / Versa Director) and real-time path telemetry are **explicitly out of scope** — those stay NCM / observability concerns
  - Data model: `overlay_network` (six kinds: sdwan / ipsec_mesh / wireguard_mesh / dmvpn / vxlan_evpn / gre_mesh), `overlay_site` (m2m binding sites with role hub / spoke / transit / gateway, edge device, loopback subnet, ordered `preferred_circuits` jsonb — first wins, fall through on outage), `routing_policy` (priority + match-kind + match-value + action + action-target + enabled), `application_category` (curated SaaS catalog seeded with 33 well-known apps — Office365 / Teams / Zoom / Slack / Salesforce / GitHub / AWS / Azure / GCP / SIP voice / OpenAI / Anthropic / …)
  - **`/topology` endpoint** — nodes (sites + roles + device + loopback + preferred-circuits) + edges (site pairs whose `preferred_circuits` lists overlap; `shared_circuits` is the intersection so the UI can colour by transport class) + policies
  - **`/simulate` endpoint** — pure read-only what-if; body specifies `down_circuits`, response shows per-site fallback resolution + per-policy effective-target with `impacted` flag and human-readable note
  - List page at `/network/overlays` + detail page with five tabs: Overview / Topology (SVG circular layout with role-coloured nodes + transport-coloured edges) / Sites / Policies (priority-ordered with per-kind editors) / Simulate

### Discovery & visibility

- 📡 **SNMP discovery** — v1 / v2c / v3 polling via standard MIBs.
  - MIBs walked: IF-MIB, IP-MIB, Q-BRIDGE-MIB, LLDP-MIB
  - Surfaces interfaces, ARP, FDB, LLDP neighbours
  - Per-IP switch-port + VLAN visibility in IPAM
  - Neighbours tab on each device

- 🎯 **Nmap scanner** — on-demand scans from the browser.
  - Per-IP "Scan with Nmap" launcher · per-subnet "Scan with nmap"
    in the IPAM Tools dropdown (pre-fills CIDR target +
    `subnet_sweep` preset) · standalone `/tools/nmap` page for
    ad-hoc targets
  - Presets: quick, service+version, **service+OS**, OS,
    default-scripts, **subnet_sweep** (-sn ping sweep capped at
    /16 worth of hosts), UDP top-100, aggressive, custom
  - Live SSE output streams while the scan runs; results render
    single-host or multi-host (CIDR) summaries
  - **Stamp alive hosts → IPAM** action on a CIDR scan claims
    responding IPs as `discovered` rows with `last_seen_at` set;
    `Copy alive IPs` for clipboard handoff
  - History page with bulk-delete (cancels in-flight scans + drops
    terminal ones) and a 3-tab right panel (Live / History / Last
    result) that auto-switches as a scan completes

- 🛰 **Device profiling** — answer "what kind of device is on every IP" without
  asking. Two layers feeding one consolidated panel in the IP detail modal.
  - **Passive — DHCP fingerprinting.** scapy `AsyncSniffer` thread on the DHCP
    agent reads option-55 / option-60 / option-77 / client-id from every
    DISCOVER + REQUEST, batches per-MAC, ships to the control plane
  - **Enrichment — fingerbank.** Optional API key in Settings → IPAM →
    Device Profiling turns raw signatures into Type / Class / Manufacturer
    (`HP iLO`, `Aruba AP`, `Cisco IP Phone 8841`, `iOS device`, …); 7-day
    cache; works offline-degraded
  - **Active — auto-nmap on new DHCP lease.** Per-subnet opt-in toggle picks a
    preset; refresh-window dedupe (default 30 days) means churning Wi-Fi
    leases don't fan out; per-subnet 4-scan concurrency cap
  - **"Re-profile now"** button on the IP detail modal for ad-hoc rescan
  - Default-off everywhere — IDS-aware (nmap is loud; passive collection
    needs `cap_add: NET_RAW`)

- 🎨 **Dashboard-at-a-glance** — nine sub-tabs: Overview / IPAM / DNS / DHCP / **Network** (ASN drift + RPKI expiry + circuit alerts + service orphans) / **Integrations** (per-mirror counts + last-sync staleness) / **Security** (lockout state + active sessions + audit-chain status + MFA enrolment) / **Compliance** (PCI / HIPAA / internet-facing flag counts) / **Conformity** (per-framework status + auditor PDF download).
  - Platform health card (API / Postgres / Redis / workers / beat)
  - Live DNS query rate + DHCP traffic charts — self-contained, no Prometheus needed
    - Sources: BIND9 statistics-channels + Kea `statistic-get-all`
  - Subnet utilization heatmap
  - Live activity feed

- 📊 **Platform Insights admin page** — native diagnostics, no extra agents.
  - Postgres: DB size, cache hit ratio, WAL position, slow queries via `pg_stat_statements`, table sizes, idle-in-transaction watch
  - Containers: per-container CPU / memory / network / IO from the local Docker socket

- 🏷 **IEEE OUI vendor lookup** — opt-in MAC vendor display.
  - Surfaces in IP tables and DHCP leases
  - Filter-by-vendor support

### Integrations

- 🧩 **Read-only integrations** — auto-mirror cluster / hypervisor / overlay state into IPAM.
  - **Kubernetes** — CIDRs, nodes, LoadBalancer VIPs, Ingress → DNS
  - **Docker** — networks, optional container IPs
  - **Proxmox VE** — bridges, SDN VNets + subnets, VMs, LXC guests (runtime IPs via QEMU guest-agent); one row per cluster
  - **Tailscale** — device mirror + synthetic `*.ts.net` DNS zone
  - **NetBird** — managed-WireGuard mesh peers (OS / version / groups / connection state) + optional synthetic mesh DNS zone; one row per NetBird deployment, operator-supplied management URL (self-hosted or cloud)
  - **UniFi Network** — per-controller sites, networks (VLAN ID + CIDR → IPAM subnets), connected clients (hostname + MAC + IP); one row per controller
  - **Palo Alto PAN-OS / Panorama** — address objects + groups → a vendor-neutral *shadow IPAM* store with a two-way drift report, NAT rules → live NAT mappings, opt-in zones / interfaces → subnets and DHCP leases → addresses; one row per `vsys` or Panorama `device-group`
  - **Fortinet FortiGate** — address objects + groups → shadow IPAM, VIPs (destination NAT), opt-in interfaces + DHCP leases; one row per VDOM, over the FortiOS REST API
  - **Cisco Meraki MX** — appliance VLANs → subnets, DHCP fixed-IP reservations, org policy objects → shadow IPAM, 1:1 NAT + port-forward, opt-in clients; one row per organization, over the cloud Dashboard API (rate-limit aware)
  - One-click setup guides per integration
  - Opt-in VNet-CIDR inference from guest NICs (for SDN deployments where PVE is L2-only)
  - Per-endpoint "Discovery" modal — which VMs aren't reporting IPs + copy-ready fix hints
  - Settings toggle gates each; per-target sync interval + on-demand Sync Now
  - Supernet auto-creation for RFC 1918 / CGNAT ranges keeps the tree tidy

- 🚫 **Active block sync** — the one write path, and the deliberate exception to the read-only stance. SpatiumDDI could already *see* a rogue DHCP responder or an unknown MAC and starve it of a lease, but a device that self-assigns a static IP walked straight past that. Block sync pushes a real block at the natural enforcement point.
  - A SpatiumDDI-owned block set (IP or MAC, with reason / source / optional auto-expiry) that an idempotent reconciler converges onto every *armed* target — and lifts when a block is disabled, expires, or is deleted
  - **OPNsense** — firewall table-alias membership (by IP); never rule CRUD
  - **UniFi** — L2 client quarantine (by MAC)
  - **Palo Alto** — Dynamic Address Group `IP → tag` register via the User-ID API; no policy commit, enforced near-instantly
  - **Cisco Meraki** — per-client built-in `Blocked` device policy; the cloud applies it immediately, no on-prem deploy
  - **Fortinet — the feed inversion**: instead of SpatiumDDI holding write credentials on your firewall, it *serves* a token-scoped `blocklist.txt` that the FortiGate polls as an External Threat Feed. Zero write credentials on the device
  - Convergence is non-destructive — SpatiumDDI only ever removes values it added, never alias members or blocked clients it doesn't own
  - Guardrails: off by default behind a feature module, a per-target enforcement master switch (independent of the mirror), distinct write-scoped credentials, a per-target preview diff, full audit on every push, dedicated `manage_block_sync` / `manage_firewall_enforcement` permissions, and two-person approval
  - The New Devices review queue's **Block** action grows an "also quarantine upstream" option

### Identity & ops

- 🔒 **Group-based RBAC + external identity** — multi-protocol auth.
  - LDAP, OIDC, SAML, RADIUS, TACACS+
  - Backup-server failover for every protocol
  - Delegate IP ranges and zones by role
  - API tokens with auto-expiry
  - **Scoped API tokens** — `scopes` JSONB column on `api_token` lists the resource_types the token is allowed to touch (vs. inheriting all of the user's permissions). Permission-name granularity (`subnet:read`, `subnet:admin`, `*` for full inheritance). Authorization enforces scope intersection — token can do at most what the scope set allows AND what the user has permission for.
  - **Resource-scoped API tokens** (#374) — a `resource_grants` list binds a token to specific instances (`{action, resource_type, resource_id}`, resource_type ∈ `subnet` / `dns_zone`) so a leaked CI / Terraform secret can only touch the one subnet or zone it was minted for. The binding only ever *narrows* the owner: the effective permission is the intersection of the owner's RBAC and the token grants, validated at create time to be a subset of what the issuer holds (you can't mint a token more powerful than yourself). Enforced per-row at the IP-create/edit/delete + DNS-record CRUD handlers.

- 🛡 **TOTP MFA** — second factor on local logins; SSO accounts can also enrol to re-confirm sensitive secret reveals (appliance kubeconfig, pairing codes, agent keys, SNMP community) when they have no local password (#408).
  - Enrolment flow: Settings → Security → "Enable MFA" → scan QR (`pyotp` + `qrcode` libraries) → enter 6-digit code → backup codes shown once
  - Login flow gains a second step when MFA is enabled — JWT pre-token issued on username+password, exchanged for full token after TOTP code or backup code accepted
  - Backup codes are single-use and persisted hashed
  - Admin can force-disable MFA per user (audit-logged)

- 🏷 **Subnet classification tags** — first-class compliance flags on every subnet.
  - `pci_scope` / `hipaa_scope` / `internet_facing` boolean columns, each individually indexed (partial index `WHERE col = true`) so the auditor's "show me every PCI subnet" filter hits an index without competing
  - List filters across the IPAM page + the API
  - Compliance dashboard at `/admin/compliance` shows the three buckets side-by-side
  - Feeds the compliance-change alert + conformity policy filters described below

- 🛂 **Compliance change alerts** — reactive: catch every mutation against PCI / HIPAA / internet-facing scope.
  - New `compliance_change` rule type with two params: `classification` (which Subnet flag the rule watches) and `change_scope` (`any_change` / `create` / `delete`)
  - Audit-log scanner runs on the existing 60 s alert tick. Watermark column on the rule baselines to `now()` on first run so historical audit history doesn't retro-page operators when a rule is first enabled
  - Resolves IP-address / DHCP-scope audit rows back to their parent subnet for classification lookup; deletes fall back to `audit_log.old_value.subnet_id` so a delete still resolves the originating subnet
  - One event per matching audit row, auto-resolves after 24 h, fans through the existing audit-forward syslog / webhook / SMTP targets
  - Three disabled seed rules ship at first boot: PCI scope changes, HIPAA scope changes, internet-facing scope changes — operator opts in by toggling enabled

- 📑 **Conformity evaluations** — proactive: prove steady state and produce the auditor PDF.
  - Declarative `ConformityPolicy` rows pin a `check_kind` against a target set (subnet / IP address / DNS zone / DHCP scope / platform). Beat-driven engine ticks every 60 s and runs every enabled policy on its `eval_interval_hours` cadence (default 24 h). On-demand re-eval via `POST /conformity/policies/{id}/evaluate`
  - 16 check kinds:
    - `has_field` — non-empty value on a named target column (e.g. PCI subnet must have `customer_id`)
    - `in_separate_vrf` — subnet's effective VRF holds only classification-matched siblings (no PCI ↔ non-PCI mixing)
    - `no_open_ports` — latest nmap scan within N days didn't expose forbidden ports (`warn` when no recent scan; never silent-pass)
    - `alert_rule_covers` — at least one enabled alert rule of the named type covers this scope (positive coverage signal — confirms the reactive #105 channel is wired)
    - `last_seen_within` — IP / subnet recency check (catches rows that should be decommissioned)
    - `audit_log_immutable` — platform-level positive-presence signal for the auditor checkbox
    - `voice_segment_not_internet_facing` — a voice / VoIP-classified subnet must not also carry the `internet_facing` flag
    - `no_multicast_collision` — no two multicast group registrations in an IPSpace claim the same address
    - `no_lanwide_control_plane_ports` — no appliance exposes k3s control-plane ports (etcd / kubelet / apiserver) to the LAN
    - `av_flow_outside_reserved_range` — an AV-over-IP flow sits outside every multicast range declared for its protocol (not applicable when no range is declared — absence of policy isn't a violation)
    - `av_flow_no_ptp_domain` — advisory; an AV flow with no PTP clock domain recorded (PTP misconfig is the top AoIP failure mode)
    - `bbmd_one_per_subnet` — a BACnet-bearing subnet has exactly one BBMD; fails on 0 (devices unreachable across routers) and on >1 (duplicated broadcasts)
    - `bacnet_duplicate_device_instance` — no two BACnet devices share an internetwork-unique device instance number
    - `bacnet_vendor_id_unknown` — advisory; BACnet devices reporting vendor id 0 or none (usually a cloned or misconfigured controller)
    - `ot_device_crosses_purdue_boundary` — an OT device's Purdue level differs from the level its subnet is zoned for
    - `ot_zone_missing_purdue_level` — advisory; a subnet carrying OT devices but declaring no OT zone
    - `fragile_subnet_probed` — works *backwards* from the OT / DICOM / `bmc`-role registries: a subnet holding devices known to be probe-fragile that nobody marked do-not-probe
    - `dicom_ae_default_title` — no DICOM AE is still on a vendor default title (`AE_TITLE`, `DICOM_SCP`, …)
    - `dicom_ae_title_convention` — AE Titles match an operator-supplied regex, so the estate's naming scheme is enforceable
    - `dicom_ae_outside_hipaa_scope` — AEs sit in subnets actually flagged `hipaa_scope`
    - `dicom_ae_no_tls` — AEs are recorded as TLS-enabled
  - 19 disabled seed policies covering PCI-DSS / HIPAA / SOC2 + the vertical registries: PCI dedicated VRF, PCI owner_assigned, PCI no admin ports, PCI alert coverage, PCI no stale IPs, HIPAA dedicated VRF, internet-facing alert coverage, voice-not-internet-facing, multicast-collision-free, audit log immutable, no LAN-wide control-plane ports, AV flows in declared range, AV flows record PTP domain, one BBMD per subnet, unique BACnet device instances, plausible BACnet vendor ids, OT devices match subnet Purdue level, OT subnets declare a zone, fragile subnets marked do-not-probe
  - `pass→fail` transitions emit `AlertEvent` rows against the policy's wired alert rule when set, so conformity drift surfaces in the existing alerts dashboard
  - Append-only `ConformityResult` history indexed twice (by policy and by resource) so both natural drilldowns hit an index — answers "every result for this policy" + "every policy that touched this resource" in O(log n)
  - Auditor-facing **PDF export** via `reportlab` — per-framework summary table, per-policy section with pass / warn / fail counts, enumerated failing rows with diagnostic JSON pretty-printed beneath, trailer with a SHA-256 hash over `(result_id, status)` tuples so the auditor can verify post-generation tampering. `GET /conformity/export.pdf` with optional `?framework=` filter
  - New `conformity` permission resource type plus two new built-in roles: **Auditor** (read-only) suitable for an external auditor account, **Compliance Editor** (admin) for the team that authors and tunes policies
  - Frontend `/admin/conformity` page with per-framework summary cards, policies table (toggle / re-eval / edit / delete inline), filterable results panel with diagnostic JSON drill-in. Platform Insights gains a Conformity card with deep-link

- 🗑 **Soft-delete + 30-day Trash** — accidental deletes are recoverable; the `Delete` button moves rows to a holding area, not the void.
  - Scope: `IPSpace`, `IPBlock`, `Subnet`, `DNSZone`, `DNSRecord`, `DHCPScope` rows inherit a `SoftDeleteMixin` (`deleted_at`, `deleted_by_user_id`, `deletion_batch_id`). IP addresses are intentionally NOT soft-deletable — they cascade-delete with their parent subnet, and the parent subnet is the recoverable unit
  - **Global ORM filter** — a `do_orm_execute` event listener injects `Model.deleted_at IS NULL` into every SELECT touching one of these models, so the rest of the codebase doesn't need to remember. Callers that need to see the trash opt in via `execution_options(include_deleted=True)`
  - **Cascade-aware restore** — when you delete a subnet its DHCP scopes are stamped under the same `deletion_batch_id`; one click on Restore brings the whole batch back atomically, with a pre-flight conflict check (rejects 409 when a live row would clash on a uniqueness key)
  - Admin page at `/admin/trash` lists soft-deleted rows newest-first with type / since / substring filters and "Restore" / "Delete permanently" per row. Sidebar entry under Admin
  - **Nightly purge** — `trash_purge` Celery beat task hard-deletes rows older than `PlatformSettings.soft_delete_purge_days` (default 30; set 0 to disable forever). The retention window is operator-tunable in Settings → Security
  - Endpoints: `GET /admin/trash` · `POST /admin/trash/{type}/{id}/restore` · `DELETE /admin/trash/{type}/{id}` (hard-delete a soft-deleted row before the purge sweep)

- 📋 **Audit log + tamper-evident hash chain** — append-only, SHA-256 chained, machine-verifiable.
  - Every mutation across IPAM / DNS / DHCP / Network / auth / ownership / integrations writes an `AuditLog` row before the response is returned. Filterable in the UI by user / action / resource type / time range; full row diff (`old_value` / `new_value` / `changed_fields` JSONB) so an audit shows you exactly what changed
  - **Hash chain** — each row carries `seq` (monotonically-increasing position), `prev_hash` (the previous row's hash), and `row_hash = sha256(prev_hash || canonical_json(row))`. A `before_flush` SQLAlchemy listener takes a Postgres transaction-scoped advisory lock so concurrent transactions can't interleave their "fetch previous hash, hash my row, write it" sequence — you can't fork the chain by racing
  - **Verifier** — `verify_chain` walks the table in `seq` order, recomputes the hash for each row, and returns the first break with `reason=row_hash_mismatch` (someone edited the row's content) or `reason=prev_hash_mismatch` (someone deleted or inserted a row mid-stream). One verification pass shows the offending row + the position in the chain
  - **Conformity hookup** — the `audit_log_immutable` conformity check kind runs the verifier on its scheduled tick and emits a `pass` / `fail` result, so the auditor's PDF export carries a positive-presence signal that nothing has been tampered with since the last evaluation
  - **Backfill migration** — `d92f4a18c763_audit_chain_hash` populates `seq`, `prev_hash`, and `row_hash` for every existing row in chronological order on upgrade, so the chain is unbroken from day one

- 💾 **Backup + restore** — full-system snapshot with passphrase-wrapped secrets and 10 destination kinds.
  - **Format** — single `.zip` archive carrying `manifest.json` (app version, schema head, hostname, dump format), `database.dump` (custom-format `pg_dump`), `secrets.enc` (PBKDF2-HMAC-SHA256 + AES-256-GCM envelope wrapping the install's `SECRET_KEY`), and `README.txt`. The operator passphrase NEVER lands on disk or in the API logs
  - **Ten destination kinds** — `local_volume` (filesystem path mounted as a docker / k8s volume), `s3` (AWS + S3-compatible: MinIO, Wasabi, Backblaze B2, Cloudflare R2 — via `endpoint_url`), `scp` (SFTP with password OR PEM private key, three host-key check modes), `azure_blob` (shared-key OR connection-string), `smb` (NTLM with optional domain + SMB3 encryption), `ftp` (plain ftp / ftps_explicit / ftps_implicit + passive/active + verify_tls toggle), `gcs` (service-account JSON key), `webdav` (Nextcloud / ownCloud / mod_dav / IIS WebDAV via PUT/GET/PROPFIND/DELETE — no SDK dep), `nfs` (an NFSv4 or v3 export, spoken in userspace — no kernel mount, so it works on the appliance too), `https_put` (PUT or POST to an HTTPS receiver — Artifactory / Nexus generic repositories, a presigned URL — with none / bearer / basic / header auth; write-only, so no listing, restore-from-destination or drill). Same `BackupDestination` ABC + module registry; the kind picker reflects on `GET /backup/targets/kinds` so adding a new driver requires no frontend changes
  - **Scheduled cron + retention** — 5-field UTC cron with friendly presets (hourly / 6h / 12h / daily 02:00 / 04:00 / weekly Sun 03:00 / monthly 1st 03:00) + custom; retention as `keep_last_n` OR `keep_for_days`; per-target last-run state surfaced inline; 60s beat sweep with `last_run_status='in_progress'` per-target mutex
  - **Selective restore** — operators tick which sections to restore (IPAM only / DNS only / etc.) on both upload-restore and restore-from-destination flows. 17-section catalog mapping all 110 schema tables; volatile sections (DHCP leases, DNS query log, DHCP activity log, nmap scan history, metric samples) skipped by default. TRUNCATE … RESTART IDENTITY CASCADE + `pg_restore --data-only --disable-triggers --table=…`; `platform_internal` (alembic_version + oui_vendor) always rides along
  - **Cross-install secret rewrap** — restoring onto an install with a different `SECRET_KEY` rewraps every Fernet-encrypted column (22 columns across 16 tables + the `backup_target.config` JSONB blob). Same-install restores short-circuit. Closes the manual `SECRET_KEY` copy step that Phase 1 needed
  - **Alembic upgrade-on-restore + drift recovery** — restore detects schema-version skew and runs `alembic upgrade head` automatically when the source is on an older head. Drift-recovery branch handles the case where the dump's alembic_version row is stale relative to the dump's own schema (operator stamped head later, then restored an older backup): canonical "table already exists" error pattern is detected and recovered via `alembic stamp head`
  - **Exclude-secrets diagnostic mode** — checkbox on the build form switches to plain-format dump and post-processes the SQL text in memory to scrub every Fernet-encrypted column + `__enc__:`-prefixed JSONB field. Live database is never touched. For sharing snapshots with support / consultants without leaking integration credentials
  - **Restore from any archive at any destination** — pick destination → expand drawer → click Restore icon. Driver fetches the bytes via `download(filename)`; standard restore path takes over. Plus `GET /backup/targets/{id}/archives/{filename}/download` for proxy-download (operator pulls a remote archive without ever holding the destination's credentials) and `…/archives/latest/download` for one-shot "give me the newest" automation
  - **Audit + observability** — every backup creates / fails / restore-performed lands an audit row; `system.backup_completed` / `system.backup_failed` / `system.restore_performed` typed events fire via the existing webhook event-outbox + HMAC-signed POST + retry pipeline
  - **Restore drills** — scheduled proof that the archives are actually restorable, which is the failure nobody discovers until recovery day. A drill downloads a target's newest archive, replays it into a throwaway scratch database, runs a fixed assertion set (archive readable and a supported format version · the stored passphrase opens `secrets.enc` · the dump replays · the alembic head is one this build knows · core tables are populated · the audit chain verifies), then drops the scratch database. **The live database is never written to** — the scratch name is generated from a fixed prefix plus random hex, never from operator input, and is checked against the live database name before anything runs. Deliberately not built on the operator restore path, which takes a pre-restore safety dump and disposes the live engine's pool: correct for a deliberate restore, wrong for an unattended background check
    - Cadence is **separate from the backup schedule**, because replaying a full dump costs far more than taking a backup — weekly drills against nightly backups is the expected shape
    - Bounded and self-cleaning: a size ceiling (`SPATIUM_DRILL_MAX_DB_BYTES`, 20 GiB default) so a verification job can never fill the production volume, a stale-mutex escape so a killed worker can't stop a target drilling forever, and a reaper that drops orphaned scratch databases with no backend attached
    - `restore_drill_failed` alert fires only on a verdict *about the archive* — never on "the drill couldn't run at all", which would train operators to ignore the rule. A target with drills switched off reports as **unverified**, not healthy
    - Restore Drills tab on the Backup admin page, `GET/POST /backup/drills` (list · get · run-now · readiness), 2 Copilot tools
  - Endpoints: `POST /backup/create-and-download` · `POST /backup/restore` · `POST /backup/targets` (CRUD + run-now + test) · `POST /backup/targets/{id}/archives/restore` · `GET /backup/targets/{id}/archives/{filename}/download` · `GET /backup/targets/{id}/archives/latest/download` · `GET /backup/drills`. UI lives at **Administration → Backup**

- 🧹 **Factory reset** — per-section "wipe back to defaults" surface for superadmins.
  - 12 sections mapped from the operator's mental model: IPAM · DNS · DHCP · Network modeling · Integrations · AI/Copilot · Compliance · Tools · Observability logs · Auth+RBAC · Settings+branding · Everything. Per-section confirm phrase (`DESTROY-IPAM` / `DESTROY-DNS` / … / `FACTORY-RESET-ALL`) typed exactly to commit
  - Three dispatch kinds: `truncate` (9 sections — straight `TRUNCATE … RESTART IDENTITY CASCADE`), `auth_rbac` (partial wipe preserving the calling user, every other superadmin, and built-in roles), `settings_reset` (DELETE platform_settings; recreated with model defaults). Tables intentionally untouchable: `alembic_version`, `oui_vendor`, `backup_target`, `feature_module`, `event_outbox`, `internal_error`, `audit_forward_target` — the schema head, OUI cache, recovery path, module toggles, and audit-forward shipping channels survive every reset
  - Hard guardrails server-side: superadmin gate · fresh bcrypt password re-check (NOT bearer-token check) · exact-match per-section confirm phrase · refuses 409 when any backup target is mid-run · Redis lock against concurrent resets · 6-hour cooldown · audit anchor written via fresh AsyncSessionLocal post-truncate so the trail of evidence survives an `audit_log` wipe · `system.factory_reset` typed event fans through the existing webhook outbox
  - **Pre-flight backup as warn-only with override** — if no enabled backup target exists, `POST /system/factory-reset/execute` returns 412 unless the operator passes `acknowledge_no_backup=true`. The Backup admin tab surfaces the warning + checkbox up front
  - UI lives as a third tab on the Backup admin page (after Manual + Destinations) — backup snapshots state, factory reset wipes it, two ends of the same lifecycle. Per-section cards in a 2-col grid + red-bordered "Reset everything" card. Modal gates the password field on a green-border phrase match

- 🤖 **Operator Copilot** — AI assistant grounded in your live IPAM / DNS / DHCP / Network data. Hosted-API or fully on-prem (Ollama). One provider config, **hundreds of tools**, real conversations about your network.

  **Provider + model**

  - **Multi-vendor** — OpenAI, Anthropic (Claude), Azure OpenAI, Google Gemini, plus OpenAI-compat (Ollama, OpenWebUI, vLLM, LM Studio, llama.cpp server, LocalAI, Together, Groq, Fireworks). Add multiple providers in priority order; orchestrator picks the highest-priority enabled one
  - **Automatic failover chain** — on transient failure (5xx / timeout / rate-limit) the orchestrator walks remaining providers; first successful chunk wins. Permanent errors (4xx / auth) surface immediately
  - **Per-provider system prompt override** — admin-editable inside the AI Provider modal; baked-in default is also viewable inline so you can fork it. Snapshotted onto each session at creation so live edits don't break in-flight chats
  - **Per-provider tool allowlist** — new "Tools" tab on the AI Provider modal, category-grouped checkbox list with "write" badges on `propose_*` rows. NULL = "use whatever the registry has"; non-empty list pins exactly those tools. Right call for small Ollama models that struggle with a large tool set, kiosk providers limited to read-only, and per-provider compliance posture
  - **Reasoning-channel fallback** — `qwen3.5` / DeepSeek-R1 / o1 / o3 family that route their answer to `reasoning` instead of `content` are handled transparently by the driver
  - **Ollama context-window forwarding** — driver forwards `options.num_ctx` / `num_predict` / `extra_body` so Ollama respects the configured context window. Operators can also set `OLLAMA_CONTEXT_LENGTH` env var on the server side (recommended); without one or the other, Ollama silently truncates to 2048 tokens and small models hallucinate tool names from a half-cut tool list

  **Tool registry (hundreds of tools — highlights below)**

  Each tool is gated by both the `feature_module` it belongs to (`integrations.unifi` off → UniFi tool disappears from the registry) and an admin-controlled per-tool allowlist at **Admin → AI → Tools**, so operators can trim what the model can see without touching code. Every tool can also be flipped per-provider via the AI Provider modal's Tools tab — the right call for small Ollama models that struggle with hundreds of tool schemas.

  The per-category bullets below are a representative tour, not an exhaustive enumeration — the canonical inventory is `backend/app/services/ai/tools/` (one module per category, every `@register_tool(...)` decorator is a live entry) and the live `/api/v1/ai/tools` endpoint on a running install. Categories not surfaced here (multicast, host-config firewall / LLDP / syslog / SSH, …) round out the full registry.

  - **IPAM** — `list_ip_spaces`, `list_ip_blocks`, `list_subnets`, `get_subnet_summary`, `find_ip` (returns MAC + **vendor**), `find_ip_addresses` (cross-subnet paginated search), `find_by_tag`, `count_ipam_resources`, `find_devices_by_vendor`, `count_devices_by_vendor`, `propose_create_ip_address`. Name-or-UUID resolution on `space_id` / `block_id` so the model can pass `"home"` directly without a UUID-lookup hop
  - **DNS** — `list_dns_server_groups`, `list_dns_zones`, `list_dns_views`, `list_dns_records` (cross-zone substring search), `list_dns_pools` (GSLB pools + per-member health), `list_dns_blocklists` (RPZ rows + sync state), `list_blocklist_templates` (the catalog's inline templates + profiles, e.g. SafeSearch and Family filter), `list_resolver_presets` (each upstream's addresses **with** the certificate name they present, which is what a DoT forwarder has to match), `query_dns_records`, `forward_dns`, `reverse_dns`, `propose_create_dns_record`
  - **DHCP** — `list_dhcp_server_groups`, `list_dhcp_servers`, `list_dhcp_scopes`, `list_dhcp_pools` (dynamic / excluded / reserved), `list_dhcp_statics` (MAC → IP reservations), `list_dhcp_client_classes`, `list_dhcp_option_templates`, `list_pxe_profiles`, `list_dhcp_mac_blocks`, `find_dhcp_leases` (returns MAC + **vendor**), `find_ra_subnets` / `find_observed_ra_routers` / `count_rogue_ra_routers` / `propose_allowlist_ra_router` (IPv6 RA + rogue-RA), `propose_create_dhcp_static`
  - **Network modeling** — `list_asns` + `get_asn` (RDAP holder, RPKI ROAs, BGP peerings), `find_bgp_hijacks` / `count_bgp_hijacks` / `find_tracked_prefixes` / `propose_allowlist_bgp_origin` (prefix-hijack detection), `list_domains` (registrar / expiry / DNSSEC / NS drift), `list_vrfs` (RDs + RTs + ASN linkage), `list_circuits` (transport + bandwidth + cost + endpoints), `trace_circuit_impact` (down-circuit blast radius across services + sites), `list_network_services` + `get_network_service_summary` (service-catalog deliverables — MPLS L3VPN, etc.), `list_overlay_networks` + `get_overlay_topology` (SD-WAN sites + policies), `list_application_categories` (RFC 4594 DSCP catalog), `list_network_devices`, `find_switchport`, `ping_host`, `list_nmap_scans`, `get_nmap_scan_results`, `propose_run_nmap_scan`
  - **BGP Looking Glass** — `find_bgp_lg_sessions` (peer state + uptime), `find_bgp_routes` / `count_bgp_routes` / `get_bgp_route` (the collector's live RIB, filterable by prefix, origin ASN, community, or a Cisco / Juniper as-path regexp), `find_bgp_route_for_ip` (which learned prefix covers this address), `find_vrf_learned_routes` (Route-Target matched VPNv4 / VPNv6 routes), `find_multicast_bgp_reachability`, `propose_create_lg_peer`
  - **Scheduled Wake-on-LAN** — `find_wol_schedules` / `get_wol_schedule` / `count_wol_schedules`, `preview_wol_schedule_targets` (which hosts would this fire wake, right now), `find_wol_runs` (history + per-host verify rollup), `find_wol_wake_failures` / `count_wol_wake_failures` (hosts that didn't come up, with the per-source evidence trail), `find_wol_calendars` / `get_wol_calendar` / `find_wol_calendar_events`, `propose_create_wol_schedule` / `propose_run_wol_schedule_now` / `propose_set_wol_schedule_enabled`
  - **Ownership** — `list_customers`, `list_sites`, `list_providers`, `get_customer_summary` (per-customer rollup of subnets / blocks / spaces / circuits / services / ASNs / zones / domains / overlays in one call)
  - **Admin** — `list_users`, `list_groups`, `list_roles` (superadmin-gated inline; the orchestrator returns an error dict for non-admins)
  - **Appliance fleet config** — `find_snmp_settings`, `find_ntp_settings`, `find_pairing_codes`. All three superadmin-gated; pairing codes also redact the cleartext code + sha256 hash, only the last two digits ever leave the database. No `propose_*` write companions by design — the create response for a pairing code carries the cleartext code, which we don't want in chat transcripts
  - **Backup + factory-reset** — `list_backup_targets` (every configured destination with last-run state, schedule, retention; `config` blob deliberately omitted so destination credentials stay out of the LLM context), `list_backup_archives_at_target` (calls the driver's `list_archives` so the result matches the Backup admin Archives drawer), `find_backup_audit_history` (windowed timeline of backup_created / target-run-success/failed / backup_restored / factory_reset_performed audit rows). All three superadmin-gated. **No `propose_*` writes by design** — restore + factory-reset are password-gated + confirm-phrase-gated, an LLM intermediary in "should I restore?" adds friction without value
  - **Integration mirrors** — `list_kubernetes_targets`, `list_docker_targets`, `list_proxmox_targets`, `list_tailscale_targets`, `list_netbird_targets`, `list_unifi_targets`, `list_cloud_targets`, `list_opnsense_targets`, `list_panos_targets`, `list_fortinet_targets`, `list_meraki_targets` (each tagged with the matching `integrations.*` module so disabling the integration removes the tool in lock-step with the sidebar entry; credentials never enter the response)
  - **Firewall objects, block sync + feeds** — `find_firewall_objects` / `count_firewall_objects` (vendor-neutral over the Palo Alto / Fortinet / Meraki shadow-IPAM store, filterable by `source_kind`), `find_network_blocks` / `count_network_blocks`, `list_firewall_feeds`, and the default-disabled `propose_create_network_block` write proposal. Gated on the `security.block_sync` / `security.firewall_feeds` modules; write-scoped target credentials never enter the response
  - **Ops, observability + audit** — `list_alerts`, `list_alert_rules`, `get_audit_history`, `audit_walk` (paginated chronology), `current_state` (platform health snapshot), `query_dns_query_log`, `query_dhcp_activity_log`, `query_logs`, `get_dns_query_rate` / `get_dhcp_lease_rate` (24-bucket timeseries), `global_search`, `lookup_whois_asn` / `lookup_whois_domain` / `lookup_whois_ip`, `tls_cert_check`, `find_nonconforming_names` (audit pre-existing hostnames / record owners / zone names against the DNS standards), `help_write_permission`, `find_agents_with_config_failures` (which DNS / DHCP / looking-glass agents rejected their last config and reverted — the one state where `status`, the health check and `last_seen_at` all read normal while the saved config is live nowhere), `find_branding_settings`, `get_support_bundle_preview` (default **off** — a broad read), `propose_create_alert_rule`, `propose_archive_session`
  - **Reputation (DNSBL)** — `find_blocklisted_ips`, `count_blocklisted_ips`, `find_dnsbl_lists` (curated catalog + per-list sweep state), `propose_pin_ip_for_dnsbl` (add an IP to the monitored set). Gated on the `security.dnsbl` module
  - **Compliance** — `list_conformity_policies` (per-framework registry filter), `find_conformity_results` (append-only evaluation history), `get_conformity_summary` (per-framework rollup of policy + result counts)
  - **Typed-event webhooks** (superadmin-gated) — `list_webhooks` (registry; secrets NEVER returned, `secret_set` boolean only), `get_webhook_event_types` (the full typed-event vocabulary so the LLM can validate `event_types[]` references before proposing a subscription), `find_webhook_deliveries` (outbox history — state / attempts / last_error / last_status_code)
  - **Rolling upgrade orchestrator** — `find_upgrade_preflight`, `find_upgrade_runs`, `find_upgrade_lease` — read state of the multi-node A/B slot rolling upgrade so the LLM can answer "what's in flight?" without operator copy-paste
  - **Windows cutover** (superadmin-gated, tagged `migration.cutover`) — `find_cutover_plans`, `find_cutover_plan_status`, `count_cutover_blockers` read plan and item state straight from the database. `find_cutover_parity_check` is the one **default-off** member of the set, because it runs a live WinRM pull against the Windows server rather than reading a stored report
  - **Write proposals** (Apply-gated, default-off, double-validated in the Tool Catalog UI) — every `propose_*` returns a planned diff first; the operator clicks Apply in the chat drawer to actually write. Apply lands an audit row with `via=ai_proposal` so the trail distinguishes operator vs. AI-driven mutations

  **MCP integration**

  - **MCP HTTP endpoint** at `/api/v1/ai/mcp` exposes the full read-only tool set so external MCP clients (Claude Desktop, Cursor, Cline, Continue.dev) can drop SpatiumDDI in as a tool source — no Copilot UI required

  **Chat surface**

  - **Floating chat drawer** — slide-in panel with sessionStorage-backed state (close + reopen lands on the same conversation, draft text survives), Markdown + GFM tables + code blocks, blinking caret during streaming. Opens via the floating "Ask AI" button, the Cmd-K palette entry, or the per-row "Ask AI about this" affordances on every IPAM / DNS / DHCP / alerts row
  - **Per-message footer** — token-count + copy + info popover (sent timestamp, tokens in / out, latency, role) on every assistant reply; matches the OpenWebUI footer pattern
  - **Daily token + cost chip** — live in the drawer header; refetches automatically when you delete chats
  - **Multi-select session history** — checkbox column on every history row; "Select all" + "Delete N" + "Delete all" toolbar; bulk delete fans out per-id and updates the daily tally on success
  - **Live nmap proposal results** — when a `propose_run_nmap_scan` Apply lands, the proposal card polls `GET /nmap/scans/{id}` every 2 s and renders the full results table (alive flag, open ports + service / version, OS guess, CIDR-host list) inline once status flips to `completed`
  - **Custom prompts library** — operator-curated templates persisted per platform; built-in starter pack (Find unused IPs, Audit recent changes, Summarize subnet utilization, Triage open alerts)
  - **Cmd-K palette "Ask AI" entry** — top entry in the global palette, pre-fills with the current page's context

  **Reliability + safety**

  - **Per-turn dedup loop guard** — if the model emits the exact same tool call twice in a turn (a known failure mode of smaller open-weight models), the orchestrator skips re-execution and feeds back a synthetic warning telling the model the result is already in context
  - **Tool-not-found auto-correction** — when the model hallucinates a tool name, the error response includes the full list of real tool names + a hint, so the next iteration self-corrects rather than giving up
  - **Scope rules in the system prompt** — Copilot is explicitly *not* a general-purpose coding assistant; refuses code-generation requests outside narrow platform-config contexts
  - **Audit everything** — every tool call, every Apply, every chat turn writes through to the append-only audit log

  **Token / cost observability + per-user caps**

  - Per-request usage tracked in `ai_chat_message`; pricing table covers the major hosted models; per-user daily token + cost caps; AI usage card on Platform Insights aggregates the last 7 days by provider + model
  - **Daily digest** — optional 0900 local Operator Copilot summary fired through audit-forward / SMTP / webhook channels

  **Self-host with Ollama in five minutes**

  ```bash
  # On the Ollama host:
  docker run -d --gpus all -p 11434:11434 \
    -e OLLAMA_CONTEXT_LENGTH=32768 \
    -e OLLAMA_KEEP_ALIVE=30m \
    -v ollama:/root/.ollama --name ollama ollama/ollama:latest

  docker exec ollama ollama pull qwen3.5:latest
  ```

  Then in SpatiumDDI: **Admin → AI Providers → New** → `kind: openai_compat`, `base_url: http://<ollama-host>:11434/v1`, `default_model: qwen3.5:latest`, save → click the floating "Ask AI" button. `OLLAMA_CONTEXT_LENGTH` is **required** — Ollama defaults to 2048 tokens which silently truncates the system prompt + tool schemas; the result is a model that hallucinates tool names. We recommend `qwen3.5:latest` for tool calling on the small open-weight class.

- 🔔 **Alerts + audit forwarding** — multi-target delivery with pluggable wire formats.
  - Rule-based alerts framework (subnet utilization, server unreachable)
  - Multi-target syslog (UDP / TCP / TLS), HTTP webhook, SMTP email, Slack / Teams / Discord chat
  - Wire formats: RFC 5424 JSON, CEF, LEEF, RFC 3164, JSON lines
  - Per-target filters

- 🪝 **Typed-event webhooks** — curated automation surface for downstream consumers.
  - 144 typed events covering every resource × verb (e.g. `subnet.created`, `dns.zone.updated`, `ip.allocated`)
  - HMAC-SHA256 signed POSTs with reserved `X-SpatiumDDI-*` headers
  - Outbox-backed at-least-once delivery with exponential backoff + dead-letter
  - Per-subscription manual retry, custom headers, and one-time secret reveal

- 🔐 **ACME DNS-01 provider** — `acme-dns`-compatible HTTP surface.
  - certbot / lego / acme.sh issue public certs (wildcards included)
  - For any FQDN delegated to a SpatiumDDI-managed zone

- 📋 **Full audit trail** — every mutation logged, append-only.
  - Viewable in the UI with per-column filters

### Deployment

- 🚀 **Flexible deployment** — same control plane, multiple paths.
  - Docker Compose
  - Kubernetes — Helm umbrella chart, OCI-published
  - Bare metal
  - OS appliance ISO — beta (Debian 13 + k3s + full stack pre-installed, dedicated `/appliance` management hub (Fleet · Cluster · Firewall · Logs & Diagnostics · Maintenance · Network & Host) with TLS cert upload, GitHub releases, atomic A/B + rolling cluster upgrades, and host config — SNMP / NTP / **LLDP** / timezone driven from the UI; **declarative fleet firewall** — per-role nftables policy with posture presets, staged-preview diffs, an enforcement master switch that cuts LAN-wide etcd / kubelet exposure, and source-scopable Web UI; **multi-node control-plane HA** — promote appliances to a 3/5/7-node cluster with CloudNativePG + Redis Sentinel + a MetalLB VIP; see [Getting Started](#quick-start-with-the-os-appliance-iso-recommended) + [`docs/deployment/APPLIANCE.md`](docs/deployment/APPLIANCE.md))

---

## Screenshots

_Click any image to open the full-size version._

| [Dashboard](docs/assets/screenshots/dashboard.png) | [IPAM](docs/assets/screenshots/ipam.png) |
| :---: | :---: |
| [<img src="docs/assets/screenshots/dashboard.png" alt="Dashboard" width="450"/>](docs/assets/screenshots/dashboard.png) | [<img src="docs/assets/screenshots/ipam.png" alt="IPAM" width="450"/>](docs/assets/screenshots/ipam.png) |
| Utilisation, VLAN, DNS &amp; DHCP status at a glance | Hierarchical space / block / subnet tree with per-IP DNS sync |

| [DNS](docs/assets/screenshots/dns.png) | [DHCP](docs/assets/screenshots/dhcp.png) | [VLANs](docs/assets/screenshots/vlans.png) |
| :---: | :---: | :---: |
| [<img src="docs/assets/screenshots/dns.png" alt="DNS" width="300"/>](docs/assets/screenshots/dns.png) | [<img src="docs/assets/screenshots/dhcp.png" alt="DHCP" width="300"/>](docs/assets/screenshots/dhcp.png) | [<img src="docs/assets/screenshots/vlans.png" alt="VLANs" width="300"/>](docs/assets/screenshots/vlans.png) |
| Zones, records, server groups | Scopes, pools, static reservations | Routers &amp; VLANs linked to subnets |

---

## Architecture

<p align="center">
  <img src="docs/assets/architecture.svg" alt="SpatiumDDI architecture" width="900"/>
</p>

**Control plane** — FastAPI + PostgreSQL 16 + Redis 7 + Celery. Single source of truth for everything (IPAM tree, DNS records, DHCP scopes, auth, audit log). Exposes a REST API; the web UI and any Terraform / Ansible / CLI / MCP integration all speak the same API. Runs single-node by default; on the OS appliance it can **scale to a 3/5/7-node HA cluster** — replicated PostgreSQL (CloudNativePG), Redis Sentinel, k3s embedded-etcd quorum, and a MetalLB control-plane VIP. The **Operator Copilot** (multi-vendor LLM + hundreds of tools in the registry + MCP HTTP endpoint) is grounded in this same live data.

**Data plane — four independent shapes (mix freely):**

- **Agented, on-prem** (BIND9 *or* PowerDNS *or* Technitium, plus Kea) — one container per service. Each bakes in a sidecar agent (`spatium-dns-agent` / `spatium-dhcp-agent`) that (1) bootstraps with a PSK or pairing code → rotating JWT, (2) long-polls `/config` with an ETag (woken over a Redis pub/sub channel), (3) caches the last-known-good bundle on disk so the service keeps serving if the control plane is unreachable — and **reverts to it, quarantines the bad etag and reports that upward** when a bundle renders config the daemon rejects, because a reverted agent otherwise keeps serving and keeps heartbeating while the zone or scope you saved is live nowhere, (4) drains record / config ops over loopback (nsupdate + TSIG for BIND9; REST API for PowerDNS / Technitium; REST Control Agent for Kea). Structural changes reload the daemon; record changes do not. The DNS engine is mutually exclusive per server group.

- **Agentless, on-prem** (Windows DNS, Windows DHCP, Technitium) — no software on the managed host. The control plane speaks directly: RFC 2136 over UDP/TCP 53 (DNS record writes + AXFR), WinRM + PowerShell over 5985/5986 (DNS zone CRUD, DHCP lease / scope reads), and for `technitium_api` the server's own HTTP API with a permanent bearer token. Credentials are Fernet-encrypted on the server row.

- **Agentless, cloud DNS** (Cloudflare, Route 53, Azure DNS, Google Cloud DNS, plus DigitalOcean / Hetzner / Linode / Vultr) — first-class drivers that call the provider's REST API / SDK directly, with import-existing-zones. No agent, no daemon.

- **Read-only integration mirrors** (Kubernetes, Docker, Proxmox VE, Cloud AWS/Azure/GCP, Tailscale, NetBird, UniFi, OPNsense, Palo Alto, Fortinet, Meraki) — scheduled pulls reconcile external state into IPAM; never written back. The single exception is **active block sync**, an opt-in, off-by-default enforcement path that pushes a SpatiumDDI-owned block set (and only that) to an OPNsense alias / UniFi client / Palo Alto DAG / Meraki client policy, or serves it as a feed the firewall polls.

On the **OS appliance**, a host-side **`spatium-supervisor`** (Ed25519 identity, pairing-code onboarding, heartbeat long-poll) orchestrates the local k3s node — it picks up role assignments, atomic A/B OS upgrades, and firewall + host-config (SNMP / NTP / LLDP / syslog / SSH) from the control plane and enforces them on the host.

The driver abstraction is backend-neutral — services speak to `DNSDriver` / `DHCPDriver`, never to BIND9 / PowerDNS / Technitium / Kea / PowerShell / cloud-SDK specifics.

**Tech stack**: Python 3.12 · FastAPI · SQLAlchemy 2.x (async) · PostgreSQL 16 · Redis 7 · Celery · React 18 · TypeScript · Tailwind · shadcn/ui · pywinrm · dnspython · cloud provider SDKs · Docker · Kubernetes + Helm · k3s (appliance)

---

## Getting Started

> ⚠️ SpatiumDDI is **beta**. The alpha cut on `2026.04.16-1` (first release) and the project has since stabilised across IPAM / DNS / DHCP / appliance surfaces. Commands and APIs may still shift between releases.

> 📘 For the full setup order (servers → zones/scopes → subnets → addresses) see **[docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)**. For Windows DC integration see **[docs/deployment/WINDOWS.md](docs/deployment/WINDOWS.md)**.

### Try the demo in GitHub Codespaces

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/spatiumnorth/spatiumddi)

One click brings up a full SpatiumDDI stack in a fresh Codespace, builds the images from `main`, runs migrations, and seeds realistic IPAM / DNS / DHCP / network-modeling demo data so every screen has something to look at. Sign in with **`admin / admin`**.

The demo Codespace runs in **DEMO_MODE** — abusable surfaces are server-side locked: nmap, packet capture, the AI Copilot, every read-only integration mirror (Kubernetes / Docker / Proxmox / Tailscale / NetBird / UniFi / Cloud / OPNsense / Palo Alto / Fortinet / Meraki), active block sync and firewall feeds, webhook subscriptions, backup target creation, factory reset, and password change all return 403. IPAM / DNS / DHCP CRUD on the seeded data stays open so you can play with it.

Cold start is ~5–8 minutes (image build) on a 4-core machine; the Codespace's free-tier hours come from your own GitHub account, and trashing the data only affects your own copy. To start fresh, delete the Codespace and click the badge again.

### Quick start with the OS appliance ISO (recommended)

The fastest way to a working SpatiumDDI install. Boot a single
ISO, answer a handful of wizard prompts, and you're on **HTTPS with the
full stack running** in 2-5 minutes. No Docker setup, no
Kubernetes setup, no Python virtualenv. The ISO is a
self-contained Debian 13 image with [k3s](https://k3s.io/)
embedded — a single-binary Kubernetes distribution — so the same
SpatiumDDI containers that ship as a Helm chart deploy on the
appliance via [HelmChart CRDs](https://docs.k3s.io/helm).
Operators get a real Kubernetes node without managing one.

> **New to Kubernetes? Don't let that stop you.** You never have to
> touch it — the guided installer, the `/appliance` web UI, and
> one-click atomic upgrades hide k3s completely; there are no `kubectl`
> or `docker` commands to learn. If you're curious *why* we picked
> embedded k3s over plain Docker Compose — flexibility, growing a single
> box into a real high-availability cluster, and never hand-running
> container commands — here's the plain-English rationale:
> [**Why k3s, not Docker Compose?**](appliance/README.md#why-k3s-not-docker-compose)

#### What you get out of the box

- Single-node [k3s](https://k3s.io/) cluster (~70 MB static
  binary, no daemons to chase).
- SpatiumDDI control plane (API, frontend, worker, beat,
  PostgreSQL, Redis, migrate Job) running as Pods.
- HTTPS on `:443` from first boot — a self-signed cert with the
  host's globally-scoped IPs in the SAN list. Replace with
  your own pasted PEM / CSR-on-server / Let's Encrypt cert
  whenever you're ready.
- A **dedicated `/appliance` management hub** that handles
  everything you'd otherwise need SSH for: a live **Cluster
  health dashboard** (pod inspection + log streaming + node
  vitals + etcd snapshots), TLS cert manager, atomic A/B OS
  slot upgrades, firmware-pending banner, fleet management for
  remote agents, NTP / SNMP host config, a realtime
  **firewall-log viewer**, journalctl viewer, self-test
  runner, one-click diagnostic bundle, maintenance mode, host
  reboot / shutdown.
- A Talos-style **operations cockpit** on the appliance's
  physical / serial console — a KPI ribbon (cluster / etcd /
  Postgres / API / platform / slot), live vitals, pod health,
  a journalctl tail, and an F7 health drill-down with guarded
  recovery actions — useful when the web UI is down.
- **Atomic A/B slot OS upgrades**: every appliance has two
  identical root partitions; an upgrade dd's the new image
  into the inactive one, reboots, and auto-reverts on
  `/health/live` failure. Worst case is one wasted reboot.
- **Scale to a 3/5/7-node HA control plane** by promoting more
  appliances from the Fleet UI — embedded-etcd quorum, replicated
  PostgreSQL (CloudNativePG) + Redis Sentinel, and a MetalLB
  control-plane VIP, all configured from the web UI (see below).

#### Get the ISO

- **Pre-built:** grab the ISO for your architecture from the
  [latest release](https://github.com/spatiumnorth/spatiumddi/releases):

  | Architecture | ISO | Firmware |
  |---|---|---|
  | x86-64 (Intel/AMD) | `spatiumddi-appliance-<version>-amd64.iso` | BIOS **or** UEFI |
  | arm64 (Apple Silicon, Graviton, Ampere) | `spatiumddi-appliance-<version>-arm64.iso` | **UEFI only** |

  The arm64 image is UEFI-only because AArch64 has no BIOS boot path —
  there is no legacy firmware mode to fall back to, and the installer
  refuses rather than completing an install that could never boot. Both
  are also published under un-versioned names
  (`spatiumddi-appliance-<arch>.iso`) that
  `releases/latest/download/…` always points at.
- **Nightly:** every night that `main` moves, a pre-release tagged
  `nightly-YYYY.MM.DD` ships the same artifacts a real release does —
  container images, the appliance ISO and the A/B slot image, assembled
  by the *same* reusable workflow the release runs, so a break in the
  assembly surfaces the next morning rather than at the cut. Kept for 7
  days. Useful for testing a fix before it's tagged; not for production
  — nightlies are never tagged `:latest`.
- **Build from source:** `make appliance-dev-iso` produces an
  ISO in `appliance/build/`. Add `APPLIANCE_ARCH=linux/arm64` for the
  arm64 image — on an Apple Silicon Mac that is a NATIVE build, which
  is also the quickest way to test the appliance locally (UTM, Apple
  Virtualization backend). See
  [`docs/deployment/APPLIANCE.md`](docs/deployment/APPLIANCE.md)
  for prerequisites.

#### Install

1. Attach the ISO as a CD-ROM in your hypervisor (Proxmox /
   VMware / Hyper-V / QEMU), or `dd` it to a USB stick for
   bare metal. **amd64** (arm64 ISO is planned).

   **Hard floor (installer refuses below this): 32 GiB disk** —
   the A/B atomic-upgrade layout needs two 8 GiB OS slots that
   each carry the full container image set for air-gapped boot,
   and `/var` must hold the k3s image store + database + logs.
   (The floor was 24 GiB; it was raised to 32 because the
   Control plane's first boot otherwise tipped the kubelet
   DiskPressure threshold into an eviction storm — issue #312.)

   **Recommended per role:**

   | Role | vCPU | RAM | Disk |
   |---|---|---|---|
   | **Control plane** (api + worker + frontend + Postgres + Redis + k3s etcd) | 4 | 8 GiB | 40 GiB SSD |
   | **Appliance** (DNS / DHCP agent box) | 2 | 4 GiB | 32 GiB SSD |

   Each control-plane HA node sizes the same as a single control
   plane (4 vCPU / 8 GiB) — every member runs a full api / worker /
   Postgres replica / Redis. SSD strongly preferred for the
   etcd + Postgres write path. When you pick the **Control plane**
   role on a box below the recommended 40 GiB / 8 GiB, the installer
   shows a sizing warning before proceeding.
2. Boot. The installer wizard asks for:
   - **Role** — *Control plane* (the required first install:
     control plane on this box + the k3s etcd seed; DNS / DHCP
     are off at install and enabled later per node from the
     Fleet UI) or *Appliance* (DNS / DHCP agent box; pairs
     against a remote control plane and can later be promoted
     to join the control-plane cluster).
   - **Target disk**, **hostname**, **admin password**,
     **network** (DHCP or static), **timezone**.
   - For *Appliance*, also **control plane URL** and a
     **bootstrap method** — see "Joining DNS / DHCP agents"
     below.
3. The installer partitions, installs GRUB, and reboots.
   First boot generates secrets, bakes a self-signed cert,
   and starts k3s + the helm-controller. The helm-controller
   reconciles the baked HelmChart CR; in 30-90 s every
   spatium pod is in Running state.

#### Access

Browse to `https://<appliance-ip>/`. Accept the self-signed
cert warning (you'll replace it through **Appliance → Web UI
Certificate** as soon as you're logged in). Sign in with
`admin / admin` — you'll be forced to set a real password on
first login.

The default port is `:443` (HTTPS); `:80` redirects to it. If
you replace the cert with Let's Encrypt or a corp-CA cert, the
nginx pod reloads automatically — no operator action needed
beyond pasting the new cert in the UI.

#### Joining DNS / DHCP agents

For distributed deployments (control plane on one box, DNS
and DHCP on others), install the **Appliance** role on
each agent box. Each agent needs a bootstrap secret to
register with the control plane. Two ways to provide it:

> **Point agents at the VIP, not a node IP.** When the
> installer asks for the control-plane URL, and the control
> plane is (or will become) a multi-node HA cluster, use the
> **MetalLB control-plane VIP** — not any single node's
> address. An agent pinned to one node's IP loses its control
> plane whenever that node is down, even though the cluster is
> healthy on the survivors. (Control-plane *cluster members*
> need no such care — their supervisor automatically heartbeats
> the in-cluster API Service rather than any fixed node IP.)

**Pairing code (recommended).** Easy to type, even over an
IPMI / serial console.

1. On the control plane, open **Appliance → Pairing** and
   click **New pairing code**. Pick the agent kind (DNS /
   DHCP / DNS + DHCP for combined boxes), an optional server
   group, and an expiry (15 min default).
2. The UI shows an 8-digit code with a live countdown.
3. On the agent appliance's installer, pick "Pairing code"
   at the **Bootstrap method** prompt and type the 8 digits.
   The agent redeems the code for the real key on first
   boot and registers itself.

**Bootstrap key (advanced).** For re-installs, air-gapped
sites with a saved key, or when a pairing code expired
before you got to the installer. Reveal the 64-char hex key
on the control plane via **Settings → Security → Agent
bootstrap keys** and paste it.

The agent appliance's console dashboard shows a **Pairing**
row — green ✓ when registered, yellow while in progress,
red with a regenerate-the-code hint on failure.

Once paired, the agent shows up on **Appliance → Fleet**.
The operator approves the row (signs the agent's cert),
then picks roles (`dns-bind9` / `dns-powerdns` /
`dns-technitium` / `dhcp` — DNS engines are mutually
exclusive). The supervisor on the
agent labels the k3s node (`spatium.io/role-<role>=true`)
and the matching DaemonSet schedules the role pod. Total
time from click to running pod: typically 25-35 s.

#### Control-plane high availability (multi-node)

A single appliance is a one-node control plane. To survive a
node loss, **promote** more appliances into the control-plane
cluster from **Appliance → Fleet → Manage control plane
cluster…**. Pick the boxes to add and confirm — embedded-etcd
HA wants an **odd** member count, so you grow 1 → 3 → 5 → 7
(the API refuses a batch that would land on an even total).

Promotion is hands-off. The supervisor on each promoted node
does a full k3s cluster-identity reset and rejoins the seed's
embedded-etcd cluster; within ~60 s the data layer scales
itself to the new member count:

- **PostgreSQL** ([CloudNativePG](https://cloudnative-pg.io/))
  grows from one instance to a primary + streaming replicas
  with automatic failover.
- **Redis** runs in Sentinel mode — each member pairs a
  redis-server with a sentinel that elects a master and fails
  over; the app resolves the live master via a `sentinel://` URL.
- **api / frontend / worker** spread to one replica per node.

**One Web UI, one address.** Set a [MetalLB](https://metallb.io/)
L2 address pool + a floating **control-plane VIP** in **Appliance →
Network & Host**; the frontend Service moves onto the VIP so the
UI (and every agent heartbeat) hits one stable address
regardless of which node is up. The self-signed Web UI cert
auto-grows its SAN list to cover every member's hostname + IP
and the VIP, so it validates on any node — unless you've
uploaded your own cert, which is never touched.

Roll back by **demoting** members the same way (the etcd seed
can't be demoted, and demoting to an even count is refused). A
control-plane node can't be revoked until it's been demoted —
revoking a live etcd member would break quorum. Control-plane
workloads are pinned to control-plane nodes by a per-role node
label, so promoting a DNS-only appliance never accidentally
schedules Postgres onto it.

> Multi-node HA shipped in
> [#272](https://github.com/spatiumnorth/spatiumddi/issues/272);
> the live shake-out validated a 1 → 3 promote end-to-end. See
> [`docs/deployment/APPLIANCE.md`](docs/deployment/APPLIANCE.md)
> for the architecture + the
> [HA topologies in `docs/deployment/TOPOLOGIES.md`](docs/deployment/TOPOLOGIES.md).

#### Managing the appliance

The **Appliance** section in the sidebar opens a management
hub with six tabs:

- **Fleet** — the heart of it: a roster of every registered
  appliance (control-plane nodes + service agents). Approve /
  reject pending pairings, assign DNS / DHCP roles + server
  groups, watch per-service health, schedule per-box atomic
  A/B OS slot upgrades + reboots, re-key, and delete. Promote
  / demote control-plane cluster members and set the MetalLB
  control-plane VIP from the roster drilldown (see HA above).
  A left sidebar holds the fleet-wide config surfaces:
  **Pairing codes** (single-use onboarding codes), **Rolling
  Upgrade** (coordinated one-node-at-a-time OS+app upgrade of
  the whole cluster — preflight → CNPG switchover → drain →
  slot apply → reboot → health-gate → uncordon → chart
  `image.tag` bump → migrate Job; air-gap mirror PVC or
  GitHub-release source; Halt / Resume / Abort — plus the
  GitHub release catalog), **Upgrade images** (air-gap
  slot-image mirror), **Web UI Certificate** (pasted PEM +
  key, in-server CSR, or Let's Encrypt — nginx reloads in
  ~15 s), **NTP** (chrony, propagates to every agent), and
  **SNMP** (v2c community + CIDR allowlist, or v3 USM).
- **Cluster** — the k3s cluster underneath: a **Pods** view
  (running workloads with per-pod restart + SSE live logs)
  and **etcd snapshots** (disaster-recovery state + guided
  single-node restore), both driven off the in-cluster
  kube-API via the api pod's ServiceAccount. *(Appliance
  host only.)*
- **Firewall** — declarative per-role / per-appliance
  nftables policy compiled into each node's drop-in, with a
  staged-preview diff of any node's effective merged ruleset,
  an enforcement master switch that cuts LAN-wide etcd /
  kubelet exposure, and a realtime firewall-log viewer.
  *(Module-gated on `appliance.firewall`.)*
- **Logs & Diagnostics** — host-log viewer, the self-test
  runner (DNS resolution + kube-API reachability + pod
  health + role presence), and a one-click diagnostic bundle
  (secrets redacted). *(Appliance host only.)*
- **Web UI reachability self-check** — the appliance answers
  the one question a self-`curl` can't: would a **new,
  off-box** TCP connection to 443 (and 80) actually be
  accepted? Curling your own LAN IP rides `iif lo accept`
  and succeeds even when the port is firewalled, which is
  how "the UI is down" turns into an hour of confirming
  healthy pods. It reads the live nftables ruleset at first
  boot, every 5 minutes, and after every firewall apply. An
  accept scoped by `web_ui_allowed_cidrs` reports *scoped*,
  never *blocked* — a hardened appliance must not be
  reported as broken — and anything the model can't reason
  about degrades to *indeterminate* rather than a confident
  wrong answer. Only a genuine block renders: bold red on
  the console next to the Web UI URL it invalidates.
  *(Appliance host only.)*
- **Maintenance** — maintenance-mode toggle (drains DNS /
  DHCP traffic before host work) plus reboot / shutdown with
  confirmation. *(Appliance host only.)*
- **Network & Host** — hostname, DNS resolvers, IPv4 / IPv6
  mode (DHCP or static), the nftables drop-in editor, SSH-key
  upload, proxy config, console-mode selector, and a
  reboot-pending banner. *(Appliance host only.)*

> On docker / k8s control planes the host-only tabs hide;
> **Fleet** stays so operators can still drive remote
> appliance agents.

The **console cockpit** on the appliance's physical or
serial console shows a 6-box KPI ribbon (cluster / etcd /
Postgres / API / platform / slot), live vitals, pod health,
and a journalctl tail. F-keys give you local-login (F1),
htop (F2), `kubectl get pods -A` (F3 — pod log viewer),
`nmtui` for networking (F4), confirmed reboot / shutdown
(F5 / F6), and a health drill-down with guarded recovery
actions (F7). The post-boot console (dashboard / verbose
dashboard / plain login) is selectable from **Appliance →
Network & Host**.

Stuck without a working web UI? SSH in as the OS admin user
you created during install. `kubectl` is on PATH (with bash
completion + a `k` alias); `kubectl get pods -A` is the
fastest "what's broken" diagnostic. `journalctl -u
spatiumddi-firstboot` shows the first-boot setup log; `kubectl
-n spatium logs <pod>` for any pod's stdout/stderr.

> The appliance is beta — see issue
> [#134](https://github.com/spatiumnorth/spatiumddi/issues/134)
> + [#183](https://github.com/spatiumnorth/spatiumddi/issues/183)
> for the roadmap and
> [`docs/deployment/APPLIANCE.md`](docs/deployment/APPLIANCE.md)
> for the full design, build pipeline, k3s architecture, and
> known limitations.

### Quick start with Docker Compose

If you'd rather run on existing Docker infrastructure, the
same SpatiumDDI containers ship as a docker-compose stack.
Useful for dev work, small single-host production where you
want full control of the OS, or environments where Kubernetes
overhead is unwanted.

```bash
git clone https://github.com/spatiumnorth/spatiumddi.git
cd spatiumddi
cp .env.example .env
# Required env vars in .env:
#   POSTGRES_PASSWORD=<set this>
#   SECRET_KEY=$(openssl rand -hex 32)
#   DNS_AGENT_KEY=$(openssl rand -hex 32)   # needed if running the DNS container
docker compose build
docker compose run --rm migrate
docker compose up -d
```

Open `http://localhost:8077` and log in with `admin` / `admin` (you're forced to change the password on first login).

### Seeding demo data

To populate a fresh install with a representative dataset (DNS group + zones + records, DHCP scope + pool, ASNs + BGP peerings, VRFs, IP space + blocks + subnets + ~30 IPs, SNMP-stubbed network devices, VLANs, domains, custom fields, IPAM templates, alert rules, and a few shared AI prompts) — useful for screenshots, demos, or kicking the tyres on the AI Copilot:

```bash
python3 scripts/seed_demo.py http://localhost:8000 admin <your-password>
```

Idempotent — re-running the seed swallows 409s and PATCHes existing rows so foreign-key pointers converge as new entities are added in later releases. Out of scope: AI providers (secrets), webhooks (per-deployment URLs), audit-forward targets, API tokens — those need real credentials from you.

### Upgrading

SpatiumDDI uses CalVer (`YYYY.MM.DD-N`) and ships every component
(api, worker, beat, frontend, dns-bind9, dhcp-kea) at the same tag.
The image tag is controlled by `SPATIUMDDI_VERSION` in your `.env`.

**Track latest** (default — your `.env` ships with `SPATIUMDDI_VERSION=latest`):

```bash
cd spatiumddi
git pull                              # refresh docker-compose.yml + .env.example for any new fields
docker compose pull                   # fetch the newest images
docker compose run --rm migrate       # apply any new alembic migrations (idempotent — no-op if up to date)
docker compose up -d                  # recreate api/worker/beat/frontend on the new images
```

**Pin to a specific release** (recommended for production — reproducible, no surprise upgrades):

```bash
# In your .env:
SPATIUMDDI_VERSION=2026.06.25-1

# Then:
docker compose pull
docker compose run --rm migrate
docker compose up -d
```

Bump the pinned version when you're ready to upgrade and re-run the same three commands.

**Notes:**
- **Take a backup before upgrading.** Click `Administration → Backup → Build + download` and save the archive somewhere off the host (or pick a configured remote destination's `Run now`). If the upgrade goes sideways the archive is your one-click rollback. Ten destination kinds ship today — local volume / S3 / SCP / Azure Blob / SMB / FTP / GCS / WebDAV / NFS / HTTPS PUT — plus selective per-section restore + cross-install secret rewrap + alembic upgrade-on-restore. See the in-app page for the security-model details.
- `docker compose run --rm migrate` runs alembic against your current schema — safe to run every upgrade. It exits as a no-op if there are no new migrations.
- Downgrades are **not** supported. Database migrations are forward-only; if a release introduces a schema change you can't roll back to a tag that predates it without restoring a database backup. Always snapshot Postgres before a major-version upgrade you're not sure about.
- Watch the **CHANGELOG.md** entry for your target version for any release-specific upgrade notes (e.g. "operators on Kea HA must read this before upgrading").
- The sidebar shows the running version in the bottom-left corner and surfaces an `update available` badge when a newer GitHub release exists — the version probe runs hourly.

### Running the built-in BIND9 / PowerDNS / Technitium / Kea containers

The managed-service containers ship under Compose profiles — opt in when you want them:

```bash
docker compose --profile dns-bind9 up -d                 # BIND9 (default)
docker compose --profile dns-powerdns up -d              # PowerDNS (issue #127)
docker compose --profile dns-technitium up -d            # Technitium (issue #746)
docker compose --profile dns-bind9 --profile dhcp up -d  # BIND9 + DHCP
```

`--profile dns` still works as a back-compat alias for `dns-bind9`. Pick whichever DNS driver matches the server group on the control plane — every driver-specific feature (PowerDNS ALIAS / LUA, Technitium DoQ and encrypted-HTTPS/QUIC forwarding, BIND9 views and RPZ) gates on every server in the group running that driver.

Or set `COMPOSE_PROFILES=dns-bind9,dhcp` in your `.env` so plain `docker compose up -d` enables both automatically.

That starts `dns-bind9` bound to host port `1053` (udp + tcp), `dns-powerdns` on `5453`, or `dns-technitium` on `6053`. The agent registers with the control plane automatically using `DNS_AGENT_KEY` from your `.env` and appears in the UI under **DNS → Server Groups**.

> **Upgrading from a release that used port 5353?** The DNS host port default changed from `5353` to `1053` in release `2026.05.11-1` because 5353 is the well-known mDNS port and collides with avahi (default-on in Ubuntu desktop / Fedora / most lab distros). Either point your clients at the new port (`dig -p 1053 …`), or pin the old behaviour with `DNS_HOST_PORT=5353` in your `.env` and recreate the container.

Create a zone + record in the UI, then verify with `dig`:

```bash
dig @127.0.0.1 -p 1053 <your-record>.<your-zone> A +short
dig @127.0.0.1 -p 1053 -x <your-ip> +short    # reverse (PTR)
```

Record changes propagate to BIND9 via RFC 2136 — typically sub-second, no daemon restart. Zone / ACL / view changes trigger a config reload.

**Production**: point the agent at your real control plane, expose `53/udp` + `53/tcp`, and run one container per DNS server you want in the cluster. All servers in a group share the same TSIG key for dynamic updates.

#### Encrypted DNS (DoT / DoH)

Turn it on per group under **DNS → Server Groups → Options → Encrypted
transports**, after linking a TLS certificate (upload one, or issue it
from Let's Encrypt under **Appliance → Web UI Certificate**). Both
listeners are additive — plain DNS on `:53` keeps working.

The listener port lives in the database; what you change to make it
*reachable* depends on how you deploy:

| Deployment | What to do |
|---|---|
| **OS appliance** | Nothing. The DNS workload is `hostNetwork` and the supervisor opens the firewall port automatically when you enable a listener. |
| **Docker Compose** | Add the overlay: `-f docker-compose.dns-encrypted.yml`. It publishes `1853→853` (DoT) and `8443→443` (DoH); tune with `DNS_DOT_HOST_PORT` / `DNS_DOH_HOST_PORT`, and if you changed the port *in the UI* match it with `DNS_DOT_PORT` / `DNS_DOH_PORT`. |
| **Kubernetes / Helm** | Set `dnsBind9.dotPort` / `dnsBind9.dohPort` (appliance chart) or per-server `dotPort` / `dohPort` (umbrella chart). |

```bash
docker compose -f docker-compose.yml \
               -f docker-compose.dns-encrypted.yml \
               --profile dns-bind9 up -d
```

The ports live in an overlay rather than the base file because Compose
can't publish conditionally — binding 853/443 unconditionally would break
`up -d` on any host already using them, for a feature that ships off.

```bash
# DoT
dig +tls +tls-hostname=dns.example.com @127.0.0.1 -p 1853 www.example.com A +short
# DoH
dig +https=/dns-query +tls-hostname=dns.example.com @127.0.0.1 -p 8443 www.example.com A +short
```

> **DoH and port 443.** 443 is the RFC 8484 default and is what the UI
> starts with, but on an **appliance** the web UI already owns it — the
> API rejects `443` there, so pick `8443` and hand clients a DoH URL with
> the port in it. On Compose there's no clash: the frontend publishes
> `8077→80` and never binds 443, and the container-side 443 is private to
> the DNS container.

**PowerDNS**: pdns Authoritative speaks neither protocol, so DoT/DoH runs
on the dnsdist front — bring up both the `dns-powerdns` and
`dns-powerdns-with-dnsdist` profiles and point clients at the front
(`5853` / `5444`). The standalone `docker-compose.agent-dns-powerdns.yml`
has no front, so encrypted transports aren't available there.

**BIND9 and Technitium** need no sidecar — both serve natively. Upstream
forwarding is where they part: BIND9 forwards over DoT only (9.20 has no
client-side HTTP or QUIC transport), Technitium forwards over **DoT, DoH
and DoQ**, and pdns doesn't forward at all.

### API & interactive docs

The FastAPI backend auto-generates OpenAPI / Swagger:

| Path | What |
|---|---|
| `http://localhost:8077/api/docs` | Swagger UI — try endpoints directly from the browser |
| `http://localhost:8077/api/redoc` | ReDoc — cleaner reference layout |
| `http://localhost:8077/api/openapi.json` | Raw OpenAPI 3 spec (for code generators) |

**The same document is attached to every release** as `openapi.json`, so an out-of-repo client can generate against an exact server version instead of whatever `main` happens to be:

```bash
curl -LO https://github.com/spatiumnorth/spatiumddi/releases/download/<tag>/openapi.json
make openapi VERSION=<tag>     # reproduces the identical bytes locally
```

Two things the published document guarantees, both because a generated client fails *quietly* rather than loudly: nullable properties are the plain schema with the property absent from `required` — not OpenAPI 3.1's `null` union, whose unmodellable arm makes strict generators drop the **whole property** with a warning — and timestamps are RFC 3339 with exactly three fractional digits, since the six Python emits (and the none it emits on a whole second) are what most generated decoders reject. See [`docs/API.md`](docs/API.md) §2.

Every UI action is a REST call, so anything you do in the UI you can do via `curl`, Terraform, or your own client. Log in to the UI first to obtain a bearer token, then use `Authorization: Bearer <token>`.

### Reset the admin password

```bash
docker compose exec api python - <<'EOF'
import asyncio
from sqlalchemy import update
from app.core.security import hash_password
from app.db import AsyncSessionLocal
from app.models.auth import User

async def reset():
    async with AsyncSessionLocal() as db:
        await db.execute(update(User).where(User.username == "admin")
            .values(hashed_password=hash_password("NewPass!"), force_password_change=True))
        await db.commit()

asyncio.run(reset())
EOF
```

### Requirements

- Docker 24+ and Docker Compose v2, **or**
- Kubernetes 1.31+ with Helm 3, **or**
- Ubuntu 22.04 / Debian 12 / Alpine 3.20+ for bare metal

---

## Deployment Options

| Method | Use case | Status |
|---|---|---|
| **Docker Compose** | Dev, small single-host production | ✅ Supported |
| **Kubernetes + Helm** | Multi-node production, scalable | ✅ Umbrella chart (`charts/spatiumddi`, published OCI to `ghcr.io/spatiumnorth/charts/spatiumddi`). See [`docs/deployment/KUBERNETES.md`](docs/deployment/KUBERNETES.md) |
| **Bare metal / VM (Ansible)** | On-prem without containers | 📋 Planned — no Ansible playbooks yet. For bare-metal today use Docker Compose on a host or the OS appliance: see [`docs/deployment/BAREMETAL.md`](docs/deployment/BAREMETAL.md) |
| **OS Appliance (ISO / qcow2)** | Easiest deploy, air-gapped, dedicated `/appliance` management hub | 🔄 Beta — Debian 13 + embedded [k3s](https://k3s.io/) + full stack as HelmChart CRs, hybrid USB/CD, installer wizard, atomic A/B slot upgrades, in-UI TLS / releases / pods / logs / diagnostics / maintenance. Build with `make appliance-dev-iso`. See [`docs/deployment/APPLIANCE.md`](docs/deployment/APPLIANCE.md) + issues [#134](https://github.com/spatiumnorth/spatiumddi/issues/134) / [#183](https://github.com/spatiumnorth/spatiumddi/issues/183) |

---

## Documentation

Full docs at **[www.spatiumddi.com](https://www.spatiumddi.com)** — republished automatically on every push to `main`.

| Document | Description |
|---|---|
| [Getting Started](docs/GETTING_STARTED.md) | Recommended setup order — from server groups down to allocating an IP |
| [Architecture](docs/ARCHITECTURE.md) | System topology, control plane / data plane split, agent contract, HA design |
| [Data Model](docs/DATA_MODEL.md) | Database models grouped by domain, key relationships, shared conventions |
| [REST API](docs/API.md) | API conventions — pagination, filtering, error format, auth, versioning |
| [Development Guide](docs/DEVELOPMENT.md) | Coding standards, lint/test stack, CI gate, migration workflow |
| [IPAM Features](docs/features/IPAM.md) | IP space, block, subnet, address management |
| [DHCP Features](docs/features/DHCP.md) | DHCP server management — Kea, Windows DHCP |
| [DNS Features](docs/features/DNS.md) | DNS zones, views, server groups, blocking lists, Windows DNS, PowerDNS, Technitium, Cloud DNS |
| [Integrations](docs/features/INTEGRATIONS.md) | Read-only mirrors — Kubernetes, Docker, Proxmox, Cloud, Tailscale, NetBird, UniFi, OPNsense, Palo Alto, Fortinet, Meraki — plus active block sync + firewall feeds (the one write path) |
| [Migration / Import](docs/features/MIGRATION.md) | One-shot DNS + DHCP + NetBox importers (BIND9 / Windows / PowerDNS / Technitium / Kea / ISC dhcpd), plus the guided Windows → SpatiumDDI cutover |
| [ACME DNS-01](docs/features/ACME.md) | acme-dns-compatible provider for Let's Encrypt / public-CA cert issuance |
| [Vertical network awareness](docs/features/VERTICALS.md) | AV-over-IP (Dante / AES67 / SMPTE 2110), BACnet/IP device-instance registry + BBMD conformity, Industrial-OT inventory + Purdue zoning, DICOM AE Title registry + peer-association map — plus the un-gated fragile-device `do_not_probe` flag |
| [Auth & Permissions](docs/features/AUTH.md) | LDAP, OIDC, SAML, RADIUS, TACACS+, roles, scoped permissions |
| [Permissions (RBAC)](docs/PERMISSIONS.md) | Permission grammar, builtin roles, wildcards, group-scoped access |
| [System Admin](docs/features/SYSTEM_ADMIN.md) | Health dashboard, backup, notifications |
| [Observability](docs/OBSERVABILITY.md) | Logging, metrics, alerting |
| [Deployment Topologies](docs/deployment/TOPOLOGIES.md) | Six reference topologies — single VM through HA cloud + on-prem hybrid — with diagrams |
| [Windows Server Setup](docs/deployment/WINDOWS.md) | WinRM, service accounts, firewall — Windows-side checklist |
| [DNS Agent Design](docs/deployment/DNS_AGENT.md) | Agent protocol, auto-registration, config sync |
| [DNS Driver Spec](docs/drivers/DNS_DRIVERS.md) | BIND9 + PowerDNS + Technitium (agent-managed *and* agentless) + Windows DNS + cloud (Route 53 / Azure DNS / Cloudflare / Google) driver internals |
| [DHCP Driver Spec](docs/drivers/DHCP_DRIVERS.md) | Kea + Windows DHCP driver internals |
| [Docker Compose](docs/deployment/DOCKER.md) | Compose setup, ports, first-time setup, TLS, HA, password reset |
| [Kubernetes](docs/deployment/KUBERNETES.md) | Umbrella Helm chart walkthrough — HPA, Ingress / LoadBalancer, CloudNativePG + Redis Sentinel HA |
| [Bare Metal](docs/deployment/BAREMETAL.md) | Bare-metal / VM paths — Docker Compose on a host, Patroni HA Postgres overlay, OS appliance |
| [Appliance Deployment](docs/deployment/APPLIANCE.md) | OS appliance ISO — base OS selection, build pipeline, first-boot orchestration, `/appliance` management hub spec |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Recovery recipes — deleted agent rows, password reset, subnet-delete refused |
| [Third-Party Components](docs/THIRD_PARTY.md) | Every bundled engine, library and OS package — license, artifact it ships in, and why it's there |

---

## Project Status

| Phase | Focus | Status |
|---|---|---|
| Phase 1 | Core IPAM, auth, user management, audit log, Docker Compose | ✅ Done — LDAP/OIDC/SAML + RADIUS/TACACS+, group-based RBAC, bulk-edit, inheritance, mobile-responsive UI, and full IPv6 `/next-address` (EUI-64 + random /128 + sequential) all shipped |
| Phase 2 | DHCP (Kea), DNS (BIND9), DDNS, zone/subnet tree UI | ✅ Done — DNS, Kea DHCPv4, subnet-level DDNS, agent-side Kea DDNS, block/space DDNS inheritance, per-server zone serial reporting all shipped |
| Phase 3 | DNS views, server groups, blocking lists, VLAN/VXLAN, system admin, Kea HA | ✅ Done — DNS features + health dashboard + alerts framework + group-centric Kea HA (self-healing peer-IP drift + supervised daemons) + DNS Views end-to-end split-horizon + **multi-node control-plane HA** (CloudNativePG + Redis Sentinel + MetalLB VIP, operator promote/demote) all shipped |
| Phase 4 | OS appliance, Terraform provider, SAML, backup/restore, ACME | 🔄 SAML + full backup/restore + factory-reset + OS appliance beta (Debian 13 ISO + embedded [k3s](https://k3s.io/) + Helm orchestration, `/appliance` management hub with TLS upload + CSR-on-server, GitHub release apply, kubeapi-driven Pods tab + live SSE logs, host log viewer + self-test + diagnostic bundle, maintenance mode + reboot, web first-boot wizard, atomic A/B slot upgrades, **multi-node rolling cluster upgrade** with CNPG switchover + lease-mutex + preflight + air-gap mirror PVC, consolidated **Cluster tab** (Pods + etcd + live SSE health dashboard), realtime **firewall-log viewer**, Talos-style **console cockpit**) + the **ACME DNS-01 provider** (acme-dns-compatible, for external certbot / lego / acme.sh clients) + the **ACME *embedded client*** (hand-rolled RFC 8555 — auto-issues a CA-trusted Let's Encrypt cert for SpatiumDDI's own Web UI via DNS-01 / HTTP-01, with auto-renewal) all landed. Terraform / Ansible providers still pending |
| Phase 5 | Multi-tenancy, IP request workflows, advanced reporting | 📋 Planned |

See [CHANGELOG.md](CHANGELOG.md) for the per-release feature list and
[CLAUDE.md](CLAUDE.md) for the authoritative spec.

---

## Contributing

Contributions are welcome.

- Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a PR
- Good first tasks are tagged on the [issue tracker](https://github.com/spatiumnorth/spatiumddi/issues)
- Design discussion happens in [GitHub Discussions](https://github.com/spatiumnorth/spatiumddi/discussions)

---

## Contributors

Thanks to everyone who has opened a pull request against SpatiumDDI.

| | Contributor | Area |
|---|---|---|
| <img src="https://github.com/mzac.png" width="48" alt=""> | [@mzac](https://github.com/mzac) | Maintainer |
| <img src="https://github.com/amoona6.png" width="48" alt=""> | [@amoona6](https://github.com/amoona6) | Appliance unattended installer, firewall sole-etcd-member fix, control-plane node-loss HA recovery |
| <img src="https://github.com/tristanbob.png" width="48" alt=""> | [@tristanbob](https://github.com/tristanbob) | `authlib.jose` → `joserfc` migration, pairing-code prune fix |
| <img src="https://github.com/Cmonnich.png" width="48" alt=""> | [@Cmonnich](https://github.com/Cmonnich) | Technitium DNS driver |
| <img src="https://github.com/waza-ari.png" width="48" alt=""> | [@waza-ari](https://github.com/waza-ari) | Agentless FortiGate cloud DHCP driver |

Opened a PR and not listed? That is an oversight, not a judgement — please
say so on the [issue tracker](https://github.com/spatiumnorth/spatiumddi/issues)
and it will be fixed. This list is maintained by hand, so it is added to as
part of merging each contributor's first PR.

---

## License

Released under the [Apache 2.0 License](LICENSE).

Bundled components (BIND9, PowerDNS, Technitium, ISC Kea, k3s, and the appliance's Debian userland) are distributed under their own licenses. See [NOTICE](NOTICE) for the attribution manifest, and [Third-Party Components](https://www.spatiumddi.com/THIRD_PARTY.html) for the full catalogue — what each component is, which artifact it ships in, and what its license means in practice.

---

<p align="center">
  Built with ❤️ by <a href="https://www.spatiumnorth.com">SpatiumNorth</a> and the SpatiumDDI community · <a href="https://www.spatiumddi.com">docs</a> · <a href="https://www.spatiumnorth.com">spatiumnorth.com</a>
</p>
