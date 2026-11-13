# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **GitHub Org:** https://github.com/spatiumnorth  
> **Docs:** https://www.spatiumddi.com  
> **License:** Apache 2.0  
> **Package:** `spatiumddi` on PyPI  
> **Container registry:** `ghcr.io/spatiumnorth/*`  

> **Read this file first.** This is the entry point for all Claude Code sessions on the SpatiumDDI project. It defines the project scope, the document map, and the non-negotiable conventions every generated file must follow.

---

## What Is SpatiumDDI?

SpatiumDDI is a production-grade, open-source **all-in-one DDI (DNS, DHCP, IPAM)** platform. It does not merely configure external DDI servers — it manages and runs the DHCP and DNS service containers directly. The control plane (FastAPI + PostgreSQL) is the source of truth; all managed service containers (Kea, BIND9) are deployed and configured by SpatiumDDI.

It can be deployed as individual containers, a full Docker Compose stack, a Kubernetes application, or as a **self-contained OS appliance image**. Supported on `linux/amd64` and `linux/arm64` (all Docker images must be built multi-arch).

It is designed to serve both power users (network engineers) and delegated department admins via a granular, group-based permission system. Every feature available in the UI is also available via REST API.

---

## Document Map

Always read the relevant spec doc(s) before writing code for a feature area.

| Document | What It Covers |
|---|---|
| `CLAUDE.md` | Index, conventions, non-negotiables, **pending** roadmap |
| `docs/SHIPPED.md` | Full design context for shipped roadmap items (migration ids, file paths, deferred follow-ups) — moved out of CLAUDE.md to keep the working list scannable |
| `docs/GETTING_STARTED.md` | Recommended setup order — server groups → zones / scopes → subnets → addresses |
| `docs/ARCHITECTURE.md` | System topology, component relationships, HA design |
| `docs/DATA_MODEL.md` | All database models, relationships, field definitions |
| `docs/API.md` | REST API conventions, pagination, error format, versioning |
| `docs/DEVELOPMENT.md` | Coding standards, test requirements, CI pipeline |
| `docs/OBSERVABILITY.md` | Logging (centralized + UI viewer), metrics, health dashboard, alerting |
| `docs/TROUBLESHOOTING.md` | Recovery recipes: accidentally deleted agent rows, password reset, subnet delete refused |
| `docs/THIRD_PARTY.md` | Catalogue of every bundled/shipped third-party component — engine, library, OS package — with license, the artifact it ships in, and the rationale. Operator-facing companion to the root `NOTICE` (which stays authoritative for license text). **When you add a shipped component, update BOTH** — and if you add a version pin, `versions.json` too (see below) |
| `versions.json` | Root manifest of every version pin **neither Dependabot nor a lockfile owns** — Helm, chart `values.yaml`, Dockerfile `ARG`s, action `with:` inputs, CI script defaults, the appliance bake arrays. One entry per component: the canonical `version`, every file carrying a copy (with an exact occurrence count where the copies must be exhaustive), the `upstream` to check it against, and — for pins deliberately behind — a `hold` field carrying the reason. `scripts/lint_versions.py` fails CI when a file and the manifest disagree, so a bump is one edit plus whatever the lint reports ([#975](https://github.com/spatiumnorth/spatiumddi/issues/975)) |
| `docs/PRIVACY.md` | The privacy statement — no telemetry, no analytics, no phone-home — plus the **normative table of every outbound connection** the backend can make, its default, and what it sends. `backend/tests/test_outbound_hosts_documented.py` fails CI when a hostname literal in `backend/app` or a shipped agent package (`agent/*/spatium_*`), or a public IP literal in an agent package, is absent from it. **When you add an outbound call, update this page in the same PR** (see non-negotiable #17) |
| `docs/features/IPAM.md` | IP Space/Block/Subnet/Address management, VLAN/VXLAN, custom fields, import/export, tree UI |
| `docs/features/DHCP.md` | DHCP servers, scopes, pools, static assignments, DDNS, caching, Windows DHCP (Path A) |
| `docs/features/DNS.md` | DNS servers, zones, records, views, server groups, blocking lists, DDNS, zone tree, Windows DNS (Path A + B), Technitium, encrypted transports (DoT / DoH / DoQ), DNS threat analytics, sync-with-servers reconciliation |
| `docs/features/AUTH.md` | Authentication, LDAP/OIDC/SAML, roles, group-scoped permissions, API tokens |
| `docs/features/ACME.md` | ACME DNS-01 provider — acme-dns-compatible HTTP surface for LE / public-CA cert issuance |
| `docs/features/INTEGRATIONS.md` | Read-only Kubernetes + Docker mirror integrations; setup, semantics, dashboard surface |
| `docs/features/MIGRATION.md` | One-shot importers — DNS (BIND9 / Windows DNS / PowerDNS / Technitium) + DHCP (Kea / Windows DHCP / ISC dhcpd.conf) + NetBox → IPAM, into native rows; preview → commit, provenance, IPAM linkage. Also the **Windows → SpatiumDDI cutover** (#756), which is *not* an importer — parity → parallel run → per-item switch + rollback → decommission |
| `docs/features/LOOKING_GLASS.md` | BGP Looking Glass — receive-only GoBGP collector peering with operator routers; Sessions + Routes grid, IPAM/ASN/VRF linkage at ingest, `bgp_lg_*` alerts, as-path Query tab + collector-vantage tools; distinct from the #527 public-table hijack monitor. The MetalLB BGP-mode VIP advertiser (#566 D1) ships alongside it, opt-in (`bgp.enabled=false`, `frrk8s.enabled=false` by default; enabling pulls in FRRouting / GPL-2.0) |
| `docs/features/VERTICALS.md` | Vertical network awareness — AV-over-IP (Dante / AES67 / SMPTE 2110) flow descriptors + reserved multicast ranges, BACnet/IP device-instance registry + BBMD conformity, Industrial-OT device inventory + Purdue zoning, DICOM AE Title registry + peer-association map. Four default-on Network feature modules (`network.av` / `network.bacnet` / `network.ot` / `network.dicom`); registry + conformity only, no network probing (and why each discovery phase is deferred). Also the un-gated fragile-device `do_not_probe` flag (#722) that suppresses SpatiumDDI's own active probes |
| `docs/features/E911.md` | E911 dispatchable location — SpatiumDDI as a Location Information Server. Emergency Response Locations as the 31 separate RFC 5139 civic elements, bindings from switch port / subnet / VLAN / device to an ERL at a **fixed** precedence, and a resolver whose load-bearing rule is that a stale precise answer is worse than a fresh coarse one. RAY BAUM'S Act §506 puts the duty on the enterprise; this is a location *source* only — no call routing, no ALI upload, no PSAP, and it never asserts an address is valid on its own say-so |
| `docs/features/COPILOT.md` | Operator Copilot reference — provider failover, per-provider system prompt + tool allowlist, the tool registry by category, MCP HTTP endpoint, chat surface, reliability guards (dedup loop guard, tool-not-found correction), token / cost caps, Ollama self-host |
| `docs/PERMISSIONS.md` | RBAC permission grammar (`{action, resource_type, resource_id?}`), builtin roles, wildcards |
| `docs/features/SYSTEM_ADMIN.md` | System config, health dashboard, notifications, backup/restore, service control |
| `docs/deployment/APPLIANCE.md` | OS appliance build, base OS selection, licensing |
| `docs/deployment/DNS_AGENT.md` | DNS agent/container architecture — image layout, auto-registration, config sync, K8s shape |
| `docs/deployment/DOCKER.md` | Docker Compose setup, ports, first-time setup, TLS, HA, password reset |
| `docs/deployment/TOPOLOGIES.md` | Six reference deployment topologies — single VM, separated agents, DNS+DHCP HA, HA control plane (Patroni / Redis Sentinel), hybrid cloud, K8s — with SVG diagrams + sizing notes |
| `docs/deployment/REVERSE_PROXY.md` | Running behind your own reverse proxy — supported topology (root of its own hostname, no sub-paths), External URL + `FRONTEND_TRUSTED_PROXY_CIDRS` + `TRUSTED_HOSTS`, required headers, SSE settings, nginx / Caddy / Traefik / HAProxy / NPM / K8s Ingress examples, troubleshooting table |
| `docs/deployment/KUBERNETES.md` | Umbrella Helm chart walkthrough — HPA, Ingress / LoadBalancer, CloudNativePG + Redis Sentinel HA (see also `k8s/README.md` + `charts/spatiumddi/README.md`) |
| `docs/deployment/BAREMETAL.md` | Bare-metal/VM paths — Docker Compose on a host, OS appliance; the Compose Patroni overlay is documented as non-functional in 1.0 (#1236, real Compose HA is #137). No Ansible playbooks; that path is planned, not implemented |
| `docs/deployment/WINDOWS.md` | Windows Server prerequisites — WinRM, service accounts (DnsAdmins / DHCP Users), firewall, zone dynamic-updates; shared by Windows DNS + Windows DHCP |
| `k8s/README.md` | Kubernetes manifest usage, HA PostgreSQL (CloudNativePG), Redis Sentinel |
| `k8s/base/` | Core K8s manifests (namespace, API, worker, frontend, migrate job) |
| `k8s/ha/` | HA add-ons: CloudNativePG cluster, Redis Sentinel, and a Patroni Compose overlay that does not work (#1236) |
| `docs/drivers/DHCP_DRIVERS.md` | Kea + Windows DHCP driver internals |
| `docs/drivers/DNS_DRIVERS.md` | BIND9 + PowerDNS + Technitium (agent-managed + agentless `technitium_api`) + Windows DNS (Path A + B) driver internals, incremental update strategy |

---

## Technology Stack (Summary)

| Layer | Technology |
|---|---|
| Backend API | Python 3.12+, FastAPI, SQLAlchemy 2.x (async), Alembic |
| Task Queue | Celery + Redis |
| Frontend | React 18 + TypeScript, Vite, shadcn/ui, Tailwind, React Query, vitest (`npm test`, run by CI's Frontend Lint job) |
| Database | PostgreSQL 16 (HA via Patroni or CloudNativePG) |
| Cache / Sessions | Redis 7 |
| Auth | python-jose + bcrypt (local), ldap3 (LDAP), joserfc (OIDC ID-token / JWKS), python3-saml (SAML), pyrad (RADIUS), tacacs_plus (TACACS+); Fernet for secrets at rest |
| Logging | structlog → JSON → centralized log store (Loki / Elasticsearch) |
| Metrics | Prometheus + Grafana; InfluxDB v1 / v2 / v3 push export ([#889](https://github.com/spatiumnorth/spatiumddi/issues/889)) |
| Containerization | Docker (multi-stage, amd64+arm64), Docker Compose, Kubernetes + Helm |
| Appliance OS | Alpine Linux (containers/appliance), Debian Stable (bare-metal ISO) |
| Logo / Assets | `docs/assets/logo.svg`, `docs/assets/logo-icon.svg` — also copied to `frontend/src/assets/` |

---

## Repo Layout

```
backend/app/            FastAPI app
  api/v1/               HTTP route handlers (ipam/, dns/, dhcp/, auth/, ...)
  models/               SQLAlchemy 2.x async models
  services/             Business logic (dns/, dhcp/, dns_io/, ipam_io/)
  drivers/dns/          DNS backend abstraction + BIND9 / PowerDNS / Technitium (agent + API) / Windows DNS impls
  drivers/dhcp/         DHCP backend abstraction + Kea impl
  tasks/                Celery tasks (dns_health, dhcp_health, sweep_expired_leases, …)
  core/, db.py, config.py, celery_app.py
backend/alembic/        Migrations (tracked in git — do not re-add to .gitignore)
frontend/src/
  pages/                Top-level routes (ipam/, dns/, dhcp/, admin/, settings/)
  components/           Shared UI; shadcn/ui primitives under components/ui/
  lib/api.ts            All API clients (ipamApi, dnsApi, dhcpApi, …)
  hooks/                Incl. useSessionState (sessionStorage-backed useState)
agent/dns/              Standalone DNS agent (Python) + BIND9 / PowerDNS container images
agent/dhcp/             Standalone DHCP agent (Python) + Kea container image
agent/supervisor/       Spatium supervisor (Python) + container image — host-side controller
                        for the upcoming Application install role (#170 Wave A — scaffolding
                        only, dormant on every existing install)
k8s/base/               Core manifests (api, worker, frontend, migrate)
k8s/{dns,dhcp}/         Per-service StatefulSets + services
k8s/ha/                 CloudNativePG, Redis Sentinel, Patroni
charts/spatiumddi/      Umbrella Helm chart (API + FE + worker + beat + migrate + Postgres/Redis subcharts + optional DNS/DHCP agents)
scripts/seed_demo.py    Demo data seeder
docs/                   Specs + Jekyll docs site — documentation ONLY, no landing page (published to BOTH Pages sites — see Documentation sites note below)
website/                Reserved for the marketing / company site source if it ever lands in this repo — currently absent; the company site is a separate project (see Marketing Website note below)
```

> **Docs site (`/docs`) and marketing site.** `docs/` is Jekyll, **documentation only** ([#1070](https://github.com/spatiumnorth/spatiumddi/issues/1070)) — no product copy. It is published to two Pages sites (org site `www.spatiumddi.com`, mirrored from `main` by `docs-publish.yml`; project site `/spatiumddi/`). **Never add a `CNAME` to `docs/`** and **never set `baseurl`** in `docs/_config.yml`; never hand-edit the site repo. The marketing site is a separate project (`website/` reserved, #754). Full text: [docs/SHIPPED.md](docs/SHIPPED.md#repo-layout-notes).

---

## Absolute Non-Negotiables

These rules apply to every file Claude Code generates. No exceptions.

1. **API-first**: Every UI action must work via REST API
2. **Async throughout**: No synchronous DB or network calls in request handlers
3. **Permissions enforced server-side**: The API always validates authorization independently of the UI
4. **Audit everything**: Every mutation is written to the append-only `audit_log` before the response is returned
5. **Config caching on agents**: DHCP and DNS containers must cache their last-known-good config locally and operate from cache if the control plane is unreachable
6. **No hardcoded secrets**: All credentials via env vars or mounted secrets
7. **Structured logs always**: Every log line is valid JSON with `timestamp`, `level`, `service`, `request_id`
8. **Incremental DNS updates**: DNS record changes use RFC 2136 DDNS or driver API — never a full server restart
9. **Idempotent tasks**: All Celery tasks must be safe to retry
10. **Driver abstraction**: DHCP and DNS backend logic never leaks into the service layer
11. **Multi-arch builds**: All Docker images must support `linux/amd64` and `linux/arm64`
12. **K8s manifests stay current**: When adding or changing services, update `k8s/base/` manifests and `k8s/README.md` to reflect the change
13. **MCP coverage for new features**: When adding a resource or feature with REST endpoints, also expose matching MCP tools for the operator copilot (`find_*` / `count_*` reads, plus `propose_*` writes where mutation makes sense). Each tool's default-enabled state must be an explicit decision — default to enabled so admins discover what exists, *unless* the surface exposes secrets, has broad-blast-radius writes, or makes off-prem calls (those default to disabled and the operator opts in)
14. **Feature-module gating for new top-level surfaces**: When adding a new top-level resource family (sidebar section, REST router prefix, MCP tool cluster), evaluate whether it should be a togglable feature module. If yes: (a) add a `ModuleSpec` to `app.services.feature_modules.MODULES`, (b) declare its shipped default in `backend/tests/test_feature_module_defaults.py` — **do not seed a row in a migration**, (c) apply `dependencies=[Depends(require_module("…"))]` to the router include in `app/api/v1/router.py`, (d) tag MCP tools with `module="…"` in their `register_tool(...)` call, (e) carry `module: "…"` on the matching sidebar `NavItem` definition.

    **Which way it ships ([#1069](https://github.com/spatiumnorth/spatiumddi/issues/1069)):** default-**on** only if it is part of the core IPAM / DNS / DHCP workflow, a zero-footprint UI convenience, or a read-only diagnostic the operator invokes by hand. Default-**off** for a domain-specific registry most installs will never populate, anything that emits traffic or writes to infrastructure once armed, anything that calls off-prem, and one-shot migration tooling — day-one importers excepted, since a fresh install is exactly when an estate gets imported. This replaced "default-on so operators discover what exists", which is #13's argument for *tools* and does not transfer: a disabled tool is invisible, whereas Settings → Features lists every module with its description whether or not it is on, so the sidebar does not have to. 16 of 57 modules ship enabled.

    **Depending on another module ([#1068](https://github.com/spatiumnorth/spatiumddi/issues/1068)):** a `ModuleSpec` may declare `requires=("parent.id",)`, and `get_enabled_modules` then resolves it enabled only when its whole ancestry is. That is a REAL gate, not a display hint — a child left independently on under a disabled parent keeps a router mounted and a sidebar row visible, pointing at a subsystem the operator turned off — so a child needs no `require_module` of its own for the parent. The frontend `resolveEnabled` in `hooks/useFeatureModules.ts` mirrors it exactly and must keep doing so; the sidebar reading a child as on while the router has resolved it off is a nav row whose page 404s. `core.dns` and `core.dhcp` are the roots, so the whole DNS or DHCP surface is one toggle; their agent routers are mounted OUTSIDE the gate on purpose, because `require_module` answers 404 and 404 is what makes an agent discard its JWT and re-bootstrap from its PSK. Disabling either is refused while it still owns servers, zones or scopes.

    **Never seed the row.** A `feature_module` row means "an operator changed this" and nothing else. Seeding one at the shipped default — which #14 used to mandate — makes the catalog's `default_enabled` dead code on every install, because a row always wins and a fresh install runs the same seed migrations an upgrade does. That is the #1069 defect; migration `a9f2c71e34b8` clears the historical seeds on fresh installs only, and a guard test fails any new migration that touches the table
15. **New integrations show up on the Dashboard — both surfaces**: When adding an integration mirror (Kubernetes / Docker / Proxmox / Tailscale / UniFi shape — read-only pull reconciler with per-target rows), wire it into BOTH dashboard surfaces: (1) the `IntegrationsPanel` inside the IPAM tab on `frontend/src/pages/DashboardPage.tsx` — add the `useQuery` gated on the `integration_*_enabled` flag, thread `enabled` + row list through props, extend column-count + grid cn() case, add a panel block following the existing icon + name + count + view-all + per-row `IntegrationRow` pattern; (2) the dedicated **Integrations dashboard tab** at `backend/app/api/v1/dashboards/integrations.py` — append a target query, add a `_build_panel(...)` entry to the `panels` list, register the new resource_type string in `_INTEGRATION_RESOURCE_TYPES` so reconciler error-audit rows surface in the recent-errors list, and extend the frontend `IntegrationDashboardKind` union in `lib/api.ts`. Both surfaces are operator-facing health rollups; missing either one means a new integration is invisible somewhere it should be obvious
16. **Per-role node-label gating for every new workload**: Every new top-level workload (Deployment / StatefulSet / DaemonSet) added to `charts/spatiumddi/` or `charts/spatiumddi-appliance/` gates scheduling on a per-role node label (`spatium.io/role-<service>=true`), not on chart-render `values.<svc>.enabled` toggles. The `nodeSelector` block merges `global.nodeSelector` (the umbrella `spatium.io/role=appliance` gate) AND a per-role label. Labels are stamped by two paths that already exist: install-time bake in `appliance/mkosi.extra/usr/local/bin/spatium-install`'s `config.yaml.d/spatium-roles.yaml` drop-in for `full-stack` / `control-only` variants; dynamic apply via the supervisor's `kubectl label` (`agent/supervisor/spatium_supervisor/k8s_api.py`) for `application` variants on role-assignment changes. `enabled: false` values stay as a global suppression knob; the per-role label is the source of truth for *which* node a workload lands on. Reference pattern: `charts/spatiumddi-appliance/templates/{dns-bind9,dhcp-kea}.yaml`. Without this, multi-node HA (#272) silently schedules control-plane workloads on DNS-only nodes — invisible misplacement that won't surface until the first node loss.

17. **No telemetry.** SpatiumDDI has no phone-home, no usage analytics, no crash reporting, and no project-controlled endpoint — and there is never to be one. Never add an outbound connection that is not operator-configured and documented in [`docs/PRIVACY.md`](docs/PRIVACY.md) with its default and its payload; a hostname literal in `backend/app` or a shipped agent package, or a public IP literal in an agent package, that is absent from that page fails CI (`backend/tests/test_outbound_hosts_documented.py`). Anything **default-on** needs an issue and a decision, not a PR: today exactly one connection is enabled out of the box (the daily anonymous GitHub release check), the README and the Settings copy both say so in those words, and a second one makes both false at once

---

## Cross-cutting Patterns

Three patterns recur across the DNS and DHCP subsystems. Know these before adding a backend feature.

1. **Driver abstraction.** `backend/app/drivers/{dns,dhcp}/base.py` defines an ABC + neutral dataclasses (`ScopeDef`, `ZoneDef`, `ConfigBundle`, etc). Concrete drivers (`bind9.py`, `kea.py`) render backend-specific config from those dataclasses. The services layer only speaks to the ABC via the driver registry — never import a concrete driver from a service.

2. **ConfigBundle + ETag long-poll.** The control plane assembles a `ConfigBundle` from DB state and hashes it to a sha256 ETag (`backend/app/services/{dns,dhcp}/config_bundle.py`). The agent long-polls `/config` with its last-seen ETag; the server blocks until the ETag changes (or timeout) and only then returns a new bundle. When you add a field that affects rendered config, verify it flows into the bundle so the ETag shifts — otherwise agents will not pick up the change. **Redis wake (#358):** the long-poll no longer blind-polls the DB every 2 s — it waits on a Redis pub/sub channel (`backend/app/core/agent_wake.py`) that config-mutating handlers publish to *after commit* (DNS records via the `enqueue_record_op` chokepoint + the `wake_publishing` router dependency that flushes `collect_wake`; DHCP/structural handlers call `collect_wake` directly; Celery workers call `publish_wake` over `settings.redis_url`). So when you add a new config-mutating endpoint, also `collect_wake(...)` the affected `dns_group`/`dhcp_group`/`dhcp_server` channel (or it converges only on the 12 s `WAKE_TICK_SECONDS` safety tick). The ETag compare stays the source of truth — the wake is advisory; if Redis is down the loop falls back to the 2 s poll, so the wake is never the sole delivery path (non-negotiable #5). **Supervisor heartbeat (#358 Phase 1):** the same bus also wakes the supervisor heartbeat long-poll — per-appliance desired-state changes (fleet upgrade / reboot / role-assign via `update_appliance_roles`, per-appliance firewall, plus the shared `HOSTCONFIG_ALL` broadcast) `publish_wake(appliance_channel(id))` after commit, and the heartbeat holds on `appliance_wake_channels(row) + [HOSTCONFIG_ALL]` when the supervisor opts in via `wait_seconds` (HTTP-only on the agent side — remote supervisors that can't reach `sentinel://` just fall back to the heartbeat interval). So a new per-appliance desired-state endpoint should also `publish_wake(appliance_channel(id))` after its commit. Phases 2–3 (the fleet-scale broker threshold + the Mosquitto escalation seam, both deferred) are written up in `docs/OBSERVABILITY.md` — Redis stays the transport until the documented threshold is crossed.

3. **Agent bootstrap + reconnection.** The agent joins with a pre-shared key (the DNS agent reads `DNS_AGENT_KEY`; the DHCP agent reads `SPATIUM_AGENT_KEY` — `DHCP_AGENT_KEY` is the control-plane-side env that gets interpolated into the agent's `SPATIUM_AGENT_KEY` at deploy time), exchanges it for a rotating JWT, and caches the JWT on disk. On **401 or 404** the agent re-bootstraps from the PSK (the 404 case covers stale server rows after a control-plane reset). The local config cache under `/var/lib/spatium-{dns,dhcp}-agent/` lets the service keep running if the control plane is unreachable (non-negotiable #5).

---

## Project Phase Roadmap

| Phase | Focus | Status |
|---|---|---|
| 1 | Core IPAM, local auth, user management, audit log, Docker Compose | **Done** — LDAP/OIDC/SAML + RADIUS/TACACS+ auth, group-based RBAC enforcement, bulk-edit tags/CF, inherited-field placeholders, mobile-responsive UI, and full IPv6 allocation all landed |
| 2 | DHCP (Kea), DNS (BIND9), DDNS, zone/subnet tree UI | **Done** — DNS core, Kea DHCPv4, subnet-level DDNS, agent-side Kea DDNS, block/space DDNS inheritance, and per-server zone serial reporting all landed |
| 3 | DNS views, server groups, blocking lists, VLAN/VXLAN, system admin panel, health dashboard | **Done** — DNS views storage, groups, blocklists, health checks, Trivy-clean + kind-AXFR acceptance tests landed; end-to-end split-horizon view rendering ([#24](https://github.com/spatiumnorth/spatiumddi/issues/24)) closed the last gap in `2026.06.04-1` |
| 4 | OS appliance image, Terraform/Ansible providers, SAML, notifications, backup/restore, ACME (DNS-01 provider + embedded client) | **In Progress** (SAML SP landed in Wave A.4; alerts framework, OS appliance image, backup/restore, and ACME — both the DNS-01 provider and the embedded Let's Encrypt client (#438) — all landed; Terraform/Ansible providers still pending) |
| 5 | Multi-tenancy, IP request workflows, import/export, advanced reporting | **In Progress** — import/export (DNS + DHCP + NetBox importers, IPAM CSV/JSON/XLSX, plus the guided Windows cutover [#756](https://github.com/spatiumnorth/spatiumddi/issues/756)), advanced reporting (Top-N #47, utilization history #44, compliance PDF #48) and the self-service request portal ([#696](https://github.com/spatiumnorth/spatiumddi/issues/696)) landed; multi-tenancy still pending |

### Current state

SpatiumDDI has been shipping CalVer releases since its alpha `2026.04.16-1`, and the working set is large: IPAM, DNS (BIND9 / PowerDNS / Windows / four cloud providers), DHCP (Kea / Windows), the OS appliance with atomic A/B upgrades and multi-node control-plane HA, ~20 read-only integration mirrors, the Operator Copilot, and the compliance loop.

**Where to look up what shipped, and when:**

| Question | Source |
|---|---|
| What landed in release X? | [`CHANGELOG.md`](CHANGELOG.md) — one section per release, authoritative |
| How does shipped feature Y work, and why was it built that way? | [`docs/SHIPPED.md`](docs/SHIPPED.md) — design context, migration ids, file paths, deferred follow-ups |
| What is still pending? | The ⬜ / 🟡 roadmap sections below, which ARE kept current |

> **Why there is no prose summary of shipped work here.** There used to be: a single ~73,000-character paragraph, 52% of this entire file. It was not maintained per-release (release prep updates `CHANGELOG.md` and flips the 🟡→✅ markers below, not that paragraph), so it drifted; and because it mentioned nearly every identifier in the project, any `grep` against `CLAUDE.md` returned it and buried the real hit. Both problems are solved by pointing at the files that are actually kept current. Keep it that way: **record new work in a `changelog.d/` fragment (folded into `CHANGELOG.md` at release prep, [#2431](https://github.com/spatiumnorth/spatiumddi/issues/2431)) and flip the marker below — do not start a new narrative here.**

### Historical narrative (moved)

The landing-by-landing narrative that used to live here (auth waves, IPAM polish, the 2026.04.19 / 2026.04.20 landings, the #170 appliance pivot) is in [`docs/SHIPPED.md`](docs/SHIPPED.md), verbatim:

- Auth waves A–D: [docs/SHIPPED.md](docs/SHIPPED.md#auth-waves)
- IPAM polish: [docs/SHIPPED.md](docs/SHIPPED.md#ipam-polish)
- 2026.04.19-1 landings: [docs/SHIPPED.md](docs/SHIPPED.md#landings-20260419)
- 2026.04.20 roadmap completions: [docs/SHIPPED.md](docs/SHIPPED.md#landings-20260420)
- Appliance architecture pivot (#170): [docs/SHIPPED.md](docs/SHIPPED.md#appliance-pivot-170)

### Major roadmap items

Feature-level tracker for the IPAM / DNS / DHCP core — each entry is
the design context to start from when picking the item up, and each
carries a status marker (below). Older shipped items had their full
bodies moved to
[`docs/SHIPPED.md`](docs/SHIPPED.md), and their "Deferred follow-ups"
blocks (pending sub-items still attached to a shipped parent) stay
alongside the parent in that file rather than getting hoisted here.
Pure-greenfield ideas from the 2026.04.26 brainstorm pass live in
their own categorised section further down.

**Markers:** ⬜ pending · 🟡 partially shipped (what's left is stated
inline) · ✅ shipped, with the closing release · ❌ closed as not
planned. When an item ships, flip its marker here and add the release
in the same edit — a wrong marker misdirects the next session, which
is what [#534](https://github.com/spatiumnorth/spatiumddi/issues/534)
was filed for. Last swept against live issue state **2026-07-28**.

- ✅ [**Windows DNS — Path B (WinRM + PowerShell)**](docs/SHIPPED.md#issue-21) (#21) — agentless WinRM + PowerShell path in backend/app/drivers/dns/windows.py (enabled per-server when…
- ✅ [**Windows DHCP — Path B (WinRM + PowerShell, full CRUD)**](docs/SHIPPED.md#issue-22) (#22) — despite the legacy WindowsDHCPReadOnlyDriver class name, capabilities() reports read_only=False and…
- ✅ [**IP discovery**](docs/SHIPPED.md#issue-23) (#23) — shipped `2026.06.04-1`: opt-in per-subnet scheduled ping / ARP sweep + reconciliation (unprivileged SOCK_DGRAM ICMP with…
- ✅ [**DNS Views — end-to-end split-horizon wiring**](docs/SHIPPED.md#issue-24) (#24) — shipped `2026.06.04-1`: the BIND9 agent now emits one view "‹name›" { match-clients …; } block per view with per-view zone…
- ✅ [**ACME embedded client — certs for SpatiumDDI's own services**](docs/SHIPPED.md#issue-28) (#28) — shipped `2026.06.19-1`: a hand-rolled RFC 8555 ACME client (backend/app/services/acme_client/ — engine.py manual JWS over…
- 🟡 [**Cloud DNS driver family — Route 53 / Azure DNS / Cisco DNA**](https://github.com/spatiumnorth/spatiumddi/issues/29) — Route 53 + Azure DNS + Cloudflare + Google Cloud DNS landed as agentless first-class drivers via #37 Part B, **shipped `2026.06.04-1`**; `2026.06.11-1` then dropped the `dnssec_online` / `alias_records` capability advertisements so the UI stops offering cloud DNSSEC sign / ALIAS authoring that the server-side gates 422 anyway. **Still open:** real cloud DNSSEC + ALIAS support. Cisco DNA stays out of scope (SD-Access controller, not a hosted-DNS service).
- ✅ [**DHCP configuration importer — ISC DHCP, Kea, Windows DHCP**](docs/SHIPPED.md#issue-129) (#129) — shipped `2026.06.04-1`: one-shot import-to-evaluate (sister to the DNS importer #128) behind one canonical IR + preview →…
- ✅ [**Windows → SpatiumDDI cutover (guided migration)**](docs/SHIPPED.md#issue-756) (#756) — shipped `2026.08.12-1`: the half the #128 / #129 importers stop short of.
- ✅ [**Technitium — agentless driver for an install the operator already runs**](docs/SHIPPED.md#issue-810) (#810) — shipped `2026.08.12-1`: new technitium_api driver (backend/app/drivers/dns/technitium_api.py), agentless like Windows Path B…

### Integration roadmap

Same read-only-pull reconciler shape as Kubernetes/Docker — each
one gets a `*Target` row type, Settings → Integrations toggle,
sidebar entry, and 30 s beat sweep with per-target interval
gating. Ranked by homelab/SMB test accessibility + IPAM value so
operators can exercise them in their own lab without standing up
cloud accounts. Shipped integrations (Kubernetes, Docker,
Proxmox, Tailscale Phase 1+2) live in
[`docs/SHIPPED.md`](docs/SHIPPED.md). The ServiceNow CMDB item in
the brainstorm section follows a different shape — bidirectional
write surface, not a read-only pull mirror.

- ✅ [**UniFi Network Application**](docs/SHIPPED.md#issue-30) (#30) — read-only mirror of UniFi networks + clients into IPAM (local + cloud-hosted controllers) behind the…
- ✅ [**OPNsense (tier 1 — firewall-of-choice for labs)**](docs/SHIPPED.md#issue-31) (#31) — read-only mirror of OPNsense interfaces + DHCP leases + reservations into IPAM behind the…
- ⬜ [**pfSense (tier 1 — paired with OPNsense)**](https://github.com/spatiumnorth/spatiumddi/issues/32)
- ✅ [**Palo Alto PAN-OS / Panorama (enterprise-firewall family reference vendor)**](docs/SHIPPED.md#issue-605) (#605) — shipped `2026.07.11-1`: read-only mirror of address objects/groups → a new firewall_endpoint_object "shadow IPAM" store (with…
- 🟡 [**Enterprise firewall family — Fortinet / Check Point / Cisco FTD / Meraki + policy-aware conformity**](docs/SHIPPED.md#issue-606) (#606) — **Phase 1 (Fortinet + Meraki) shipped `2026.07.11-1`:** shared mirror engine `services/firewall_mirror.py`, FortiGate + Meraki MX read-only mirrors, Threat-Feed enforcement. **Deferred:** FortiManager JSON-RPC centralization; Phase 2 (Check Point + Cisco FTD/FMC, both leading with feed-based enforcement); and the cross-cutting **policy-aware conformity checks** (`pci_scope`/`internet_facing` subnets asserted against live firewall policy, plugging into #106).
- ✅ [**NetBird (managed WireGuard mesh)**](docs/SHIPPED.md#issue-603) (#603) — shipped `2026.07.11-1`: read-only mirror of NetBird peers into IPAM behind the integrations.netbird feature module…
- ⬜ [**MikroTik RouterOS 7 (tier 2)**](https://github.com/spatiumnorth/spatiumddi/issues/33)
- ⬜ [**Incus / LXD (tier 2 — Docker-adjacent)**](https://github.com/spatiumnorth/spatiumddi/issues/34)
- ⬜ [**HashiCorp Nomad (tier 2 — Kubernetes alt)**](https://github.com/spatiumnorth/spatiumddi/issues/35)
- ✅ [**NetBox read-only import (one-shot)**](docs/SHIPPED.md#issue-36) (#36) — shipped `2026.06.28-1`: One-shot migration importer (not a continuous reconciler): live-pulls prefixes / addresses / VRFs /…
- ✅ [**Cloud connectors — unified "Cloud" integration with per-provider picker (Azure / AWS / GCP)**](docs/SHIPPED.md#issue-37) (#37) — shipped `2026.06.04-1`: Part A: read-only infra mirror (cloud_endpoint + AWS/Azure/GCP connectors → IPBlock/Subnet/IPAddress…
- ⬜ [**Load balancer family (F5 BIG-IP, HAProxy, nginx, KEMP, A10, Citrix ADC)**](https://github.com/spatiumnorth/spatiumddi/issues/38)
- **VMware vCenter / ESXi.** Bigger enterprise audience, but
  vCenter's SOAP-heavy + licensed API makes it a significantly
  bigger dev effort than the tier 1 candidates. Revisit only if
  a deployment specifically needs it.
- **SNMP device polling** as an integration. Already tracked as
  its own line item above (IPAM ARP discovery); belongs with
  ping-sweep / ARP-scan, not the read-only integration shelf.
- **WireGuard raw config.** No API — config files only. Belongs
  in a manual-import flow if at all. Managed WireGuard meshes that
  *do* expose an API are covered: Tailscale (shipped) and NetBird
  (#603, above).

### Future ideas — categorised (added 2026.04.26)

Brainstorm pass that catalogues standard IPAM / DDI features
operators of comparable tools (Infoblox, EfficientIP, NetBox,
phpIPAM, SolarWinds IPAM) expect but SpatiumDDI doesn't yet
ship. Sketched at enough depth to start work without
re-deriving the design — pick by impact, not by section order.
Markers below follow the same key as the Major-roadmap section
above. Brainstorm items whose full design body was moved out
(Switch-port mapping, OUI lookup, SNMP polling,
LLDP collection, nmap, CIDR calculator + Subnet planner +
Address planner, DNS templates / propagation check / catalog
zones / RPZ, DHCP option library, ACME provider, alerts
framework, dashboard time-series, …) live in
[`docs/SHIPPED.md`](docs/SHIPPED.md) under the matching
sub-headings.

#### Discovery & network awareness

- ⬜ [**NetFlow / sFlow ingestion**](https://github.com/spatiumnorth/spatiumddi/issues/39)
- ❌ [**mDNS / Bonjour / WSD passive discovery**](https://github.com/spatiumnorth/spatiumddi/issues/40)
  — **closed as not planned** (feasibility + merit review). Link-local
  multicast is only audible to a host-networked, on-segment agent, and
  the agent↔subnet binding that needs isn't modelled. Kept listed
  because #540/#541/#542 named it as their shared discovery primitive;
  its closure is why every one of their discovery phases is deferred.
- ✅ [**Reverse-DNS auto-population**](docs/SHIPPED.md#issue-41) (#41) — shipped `2026.06.04-1`: scheduled, platform-opt-in sweep that PTR-resolves hostname IS NULL rows against configured resolvers…
- ✅ [**CGNAT (RFC 6598) awareness**](docs/SHIPPED.md#issue-42) (#42) — shipped `2026.06.04-1`: amber "CGNAT" badge on subnet detail + a New-Subnet advisory hint when the typed network falls in…

#### Vertical network awareness

Umbrella [#543](https://github.com/spatiumnorth/spatiumddi/issues/543) —
four IP-native domains a generic IPAM doesn't speak, built on the same
DDI primitives (uniqueness registry + segmentation documentation +
conformity). See [`docs/features/VERTICALS.md`](docs/features/VERTICALS.md).
The first three children closed 2026-07-28; the umbrella stays open for
the deferred discovery phases listed per-item below. The healthcare pass
concluded there is **no** `network.healthcare` catch-all — it splits into
separable pieces, of which DICOM (#723) is the anchor and the
probe-safety fix (#722) is not a vertical at all.

- ✅ [**AV / Audio-Video-over-IP — Dante · AES67 · SMPTE 2110 · NDI**](docs/SHIPPED.md#issue-540) (#540) — shipped `2026.07.30-1`: network.av module, av_flow_profile 1:1 AV descriptor on multicast_group + operator-declared…
- ✅ [**BACnet/IP building automation**](docs/SHIPPED.md#issue-541) (#541) — shipped `2026.07.30-1`: network.bacnet module, bacnet_device with the internetwork-wide uq_bacnet_device_instance constraint…
- ✅ [**Industrial / OT — PROFINET · EtherNet/IP · Modbus TCP · OPC UA**](docs/SHIPPED.md#issue-542) (#542) — shipped `2026.07.30-1`: network.ot module, ot_device 1:1 descriptor + ot_zone Purdue zoning (Numeric(2,1) so level 3.5 / the…
- ✅ [**DICOM AE Title registry + peer-association map**](docs/SHIPPED.md#issue-723) (#723) — shipped `2026.07.30-1`: `network.dicom`: AE Title registry with institution-wide uniqueness, peer map, CSV import, 4 conformity checks (#731).
- ✅ [**Fragile-device "do not probe" flag**](docs/SHIPPED.md#issue-722) (#722) — shipped `2026.07.30-1`: Not a vertical and not behind a feature module: a constraint on our own behaviour and a correctness…

#### Reporting & analytics

- ⬜ [**Capacity forecasting**](https://github.com/spatiumnorth/spatiumddi/issues/43)
- ✅ [**Per-subnet utilization history**](docs/SHIPPED.md#issue-44) (#44) — shipped `2026.06.11-1`: daily beat task snapshots each subnet's allocated / total IP counts (pruned › 90 d); Trend tab on…
- ✅ [**Stale-IP report**](docs/SHIPPED.md#issue-45) (#45) — shipped `2026.06.04-1`: over the #23 discovery last_seen_at signal — which allocated IPs has nothing answered for in N days.
- ✅ [**Decom-date awareness**](docs/SHIPPED.md#issue-46) (#46) — shipped `2026.06.11-1`: first-class decom_date on subnet + IP, a decom_expiring alert rule (severity escalation reused from…
- ✅ [**Top-N reports**](docs/SHIPPED.md#issue-47) (#47) — shipped `2026.06.11-1`: a /reports surface (top subnets by utilization, owners by IP count, most-modified resources via…
- ✅ [**Compliance / change report PDF**](docs/SHIPPED.md#issue-48) (#48) — shipped `2026.06.11-1`: GET /api/v1/audit/export.pdf renders an auditor-facing PDF of every audit_log mutation in a date…
- ✅ [**InfluxDB push export**](docs/SHIPPED.md#issue-889) (#889) — shipped `2026.09.04-1`: The writer the tech-stack table claimed for months while grep -ri influx over backend/ returned nothing.

#### Subnet planning & calculation tools

All shipped — see `Subnet planning & calculation tools` in
[`docs/SHIPPED.md`](docs/SHIPPED.md): CIDR calculator,
Subnet planner workspace, address planner, aggregation
suggestion, free-space treemap.

#### DNS-specific

- ✅ [**DNSSEC**](docs/SHIPPED.md#issue-49) (#49) — shipped `2026.06.04-1`: BIND9 inline-signing, policies, DS export, rollover.
- ✅ [**DoT / DoH — inbound listener + encrypted upstream forwarding**](docs/SHIPPED.md#issue-50) (#50) — shipped `2026.07.30-1`: Serves DoT (853) / DoH (/dns-query) to local clients *and* forwards to upstream resolvers over TLS…

- ✅ [**Upstream resolver presets**](docs/SHIPPED.md#issue-877) (#877) — 16 verified resolver presets across 7 providers, each with the certificate name it presents (PR #893).
- ✅ [**Family filter — adult-content blocking bundle + SafeSearch enforcement**](docs/SHIPPED.md#issue-878) (#878) — the catalog gains templates (entry sets shipped inline, for rules with no upstream feed) and profiles…
- ✅ [**Per-subnet DNS blocklist scoping — surface it in the UI**](docs/SHIPPED.md#issue-876) (#876) — the backend has scoped a blocklist to a view *or* a server group since #24 (dns_blocklist_view_assoc…
- ✅ [**Blocklist feed wildcard semantics are per-list**](docs/SHIPPED.md#issue-894) (#894) — #878 made every feed row is_wildcard=True, right for all 19 catalog sources but a global constant…

- ✅ [**DNS agent never renders `acl {}` definitions**](docs/SHIPPED.md#issue-899) (#899) — DNSAcl rows were stored, listed and editable on the ACLs tab and applied to nothing: the bundle…

- ✅ [**A DNS server cannot be moved between server groups**](docs/SHIPPED.md#issue-934) (#934) — shipped `2026.09.04-1`: Reported in discussion #933 the obvious way: an auto-registered BIND9 agent lands in default, the…

- ✅ [**A DNS zone cannot be moved between server groups**](docs/SHIPPED.md#issue-935) (#935) — shipped `2026.09.04-1`: The other half of discussion #933, and a much sharper tool than the #934 server move.

- ✅ [**Zone name scope — classify zones by TLD against the IANA root list**](docs/SHIPPED.md#issue-986) (#986) — shipped `2026.10.02-1`: validate_fqdn said a zone name was *syntactically* a domain and stopped, so corp.example.com…

#### DHCP-specific

- ✅ [**DHCPv6 stateful + SLAAC config UI**](docs/SHIPPED.md#issue-52) (#52) — shipped `2026.06.04-1`: DHCPScope.v6_address_mode + ra_managed_flag / ra_other_flag; the Kea driver renders subnet6 by mode…
- ⬜ [**Lease histogram by hour**](https://github.com/spatiumnorth/spatiumddi/issues/53)
- ⬜ [**Option 82 (relay agent info) class matching**](https://github.com/spatiumnorth/spatiumddi/issues/54)
- ⬜ [**DHCP test client**](https://github.com/spatiumnorth/spatiumddi/issues/55)
- ✅ [**Fingerprint-driven DHCP policy — compile device profiles into Kea client-classes**](docs/SHIPPED.md#issue-700) (#700) — shipped `2026.09.04-1`: Device profiling told us what a device *is*; client classes let us treat kinds of device differently…
- ✅ [**Windows DHCP failover relationships — two Windows members of one group no longer serve a scope uncoordinated**](docs/SHIPPED.md#issue-1110) (#1110) — shipped `2026.10.02-1`: Windows DHCP failover detection + classifier; scope writes no longer hit uncoordinated partners. Live-pair verification remains.
- ⬜ [**Kerberos WinRM transport for Windows DNS / DHCP**](https://github.com/spatiumnorth/spatiumddi/issues/1128)
  — **removed, not built** (in `2026.10.02-1`): the forms offered `kerberos` while
  the images carried no GSSAPI stack, so it failed on every call. The API now
  refuses it at save (`drivers/_winrm.validate_transport`, shared by the DNS
  and DHCP credential inputs; `SUPPORTED_TRANSPORTS` is ntlm / credssp /
  basic), and a stored `kerberos` row fails in `run_ps` with the reason. To
  build it for real: `gssapi` has **no Linux wheel**, so it compiles in the
  builder stage against `libkrb5-dev` on amd64 + arm64 and the runtime needs
  `libgssapi-krb5-2` (Trivy, `NOTICE`, `THIRD_PARTY.md`); the control plane
  is not domain-joined, so it needs a `krb5.conf` (realm / KDC) from env or a
  mounted secret — chart values and appliance included, non-negotiable #12 —
  and a ticket from the stored password (pyspnego + gssapi can, verify it) or
  a keytab. Kerberos with constrained delegation would also give Windows DHCP
  failover management (#1110) a second hop without CredSSP. Untestable
  without an AD KDC, which is why it waits.

#### Operational tooling

- ⬜ [**Time-travel queries**](https://github.com/spatiumnorth/spatiumddi/issues/56)
- ✅ [**Maintenance mode**](docs/SHIPPED.md#issue-57) (#57) — shipped `2026.06.11-1`: middleware 503s mutating requests during a change window (Retry-After, superadmin bypass, agent /…
- ✅ [**Built-in network tools page**](docs/SHIPPED.md#issue-58) (#58) — shipped `2026.06.11-1`: a /tools page (ping / traceroute / mtr / dig / whois over sandboxed argv, port-test / TLS-cert over…
- ✅ [**PCAP capture trigger**](docs/SHIPPED.md#issue-59) (#59) — shipped `2026.06.15-1`: on-demand tcpdump as an RBAC-gated/audited Tools page, both server-container and appliance-host…
- ❌ [**ACL / prefix-list generator**](https://github.com/spatiumnorth/spatiumddi/issues/60) — **closed as not planned** 2026-06-17, in the same triage pass that closed #40. No rationale was recorded on the issue; re-open it rather than re-filing if the need comes back.
- ✅ [**Config-drift report (full record diff)**](docs/SHIPPED.md#issue-61) (#61) — shipped `2026.06.11-1`: GET …/zones/{id}/drift AXFRs the live zone from every server in the group and diffs it against the DB…
- ✅ [**Support bundle**](docs/SHIPPED.md#issue-875) (#875) — platform-wide scrubbed diagnostics export at POST /system/support-bundle{,/preview,/decode-map}…
- ✅ [**Agents never read the `previous.json` they write**](docs/SHIPPED.md#issue-882) (#882) — non-negotiable #5's cached config protects against a *dead* control plane; this closes the other…
- ✅ [**Agents spool and replay what they collect during a control-plane outage**](docs/SHIPPED.md#issue-1077) (#1077) — shipped `2026.10.02-1`: the *reporting* half of non-negotiable #5.
- ⬜ [**Config snapshots + rollback**](https://github.com/spatiumnorth/spatiumddi/issues/883) — audit-log-driven revert
  of a single change plus scoped named snapshots. Distinct from #882,
  which is an agent-side safety net rather than an operator action.
- ✅ [**Service restart from the GUI**](docs/SHIPPED.md#issue-890) (#890) — shipped `2026.09.04-1`: closing the #111 gap on docker-compose and Helm, where the appliance's pod restart had no equivalent.

#### Workflow & RBAC

- ✅ [**Approval workflows for risky ops — P1**](docs/SHIPPED.md#issue-62) (#62) — shipped `2026.06.25-1`: two-person rule over the 6 delete handlers behind the default-off governance.approvals module + a…
- ⬜ [**Approval workflows — P2 (bulk ops / factory reset / import gating + approval notifications)**](https://github.com/spatiumnorth/spatiumddi/issues/717) — build on the shipped `governance.approvals` module + change-request lifecycle, not a parallel mechanism.
- ✅ [**Self-service request portal — IP / subnet / DNS / DHCP requests with approve-and-provision**](docs/SHIPPED.md#issue-696) (#696) — shipped `2026.07.30-1`: the Phase 5 "IP request workflows" item. #62's approval engine pointed the other way: a low-privilege…
- ⬜ [**Resource locking**](https://github.com/spatiumnorth/spatiumddi/issues/63)
- ⬜ [**Per-resource ACLs**](https://github.com/spatiumnorth/spatiumddi/issues/64)
- ✅ [**Time-bound permissions**](docs/SHIPPED.md#issue-65) (#65) — shipped `2026.06.11-1`: a time_bound_grant table of auto-expiring *additive* RBAC grants ({action, resource_type…
- ⬜ [**Comments / activity feed per resource**](https://github.com/spatiumnorth/spatiumddi/issues/66)

#### Notifications & external integrations

- ✅ [**Ansible dynamic-inventory endpoint**](docs/SHIPPED.md#issue-67) (#67) — shipped `2026.06.11-1`: GET /api/v1/ansible/inventory returns standard Ansible dynamic-inventory JSON built from IPAM — hosts…
- ⬜ [**ServiceNow CMDB integration**](https://github.com/spatiumnorth/spatiumddi/issues/68)

#### Security & compliance

- ✅ [**Password policy enforcement**](docs/SHIPPED.md#issue-70) (#70) — shipped `2026.05.07-1`: configurable complexity / history / max-age rules applied to every local-auth password set, over…
- ✅ [**Account lockout after N failed logins**](docs/SHIPPED.md#issue-71) (#71) — shipped `2026.05.07-1`: windowed-counter lockout for local-auth users over user.failed_login_count /…
- ✅ [**Active session viewer + force-logout**](docs/SHIPPED.md#issue-72) (#72) — shipped `2026.05.07-1`: live JWT registry the operator can browse and revoke from — access tokens carry a jti, and…
- ✅ [**Internal cert + secret expiry monitoring**](docs/SHIPPED.md#issue-76) (#76) — shipped `2026.06.11-1`: one secret_expiring alert rule that fires per internal credential expiring within threshold_days —…
- ✅ [**Privacy statement — no telemetry, no analytics, your data stays in your install**](docs/SHIPPED.md#issue-976) (#976) — shipped `2026.10.02-1`: SpatiumDDI has been privacy-first by construction since the first commit and said so nowhere, so an…
- ⬜ [**FIPS 140-3 posture**](https://github.com/spatiumnorth/spatiumddi/issues/880) — crypto audit plus a tiered
  roadmap for a FIPS-capable build (containers / Kubernetes /
  appliance). Gate for government deployments; the audit comes first
  because the answer may be "these three libraries block it".
- ⬜ [**Appliance full-disk encryption**](https://github.com/spatiumnorth/spatiumddi/issues/881) — LUKS2 at install for
  STATE + `/var`, TPM2 auto-unlock, and a recovery key the installer
  has to present exactly once without writing it anywhere it protects.

- 🟡 [**E911 dispatchable location — SpatiumDDI as a Location Information Server**](docs/SHIPPED.md#issue-972) (#972) — **Phases 1a–3 shipped `2026.10.02-1`** (resolver, HELD/PIDF-LO, DHCP options 99/123, 3 conformity policies). **Still open:** provider validation calls + push reconcilers (#1048 RedSky, #1049 Bandwidth, #1050 Intrado — not implementable without vendor docs), bulk CSV import of ERLs/bindings, HELD `locationURI`, DHCPv6 options 36/63, Kari's Law notification, historical lookup, wireless AP rule.

#### UX polish

- ✅ [**Saved searches / saved views**](docs/SHIPPED.md#issue-77) (#77) — shipped `2026.06.19-1`: per-user SavedView(user_id, page, name, payload, is_default) table + /api/v1/saved-views CRUD (scoped…
- ⬜ [**Personal pinned dashboard**](https://github.com/spatiumnorth/spatiumddi/issues/78)
- ⬜ [**Field-level history**](https://github.com/spatiumnorth/spatiumddi/issues/79)
- ⬜ [**Recent items / favourites sidebar**](https://github.com/spatiumnorth/spatiumddi/issues/80)
- ✅ [**Keyboard shortcut help overlay**](docs/SHIPPED.md#issue-81) (#81) — shipped `2026.07.30-1`: ? opens a modal listing every binding, from a new frontend/src/lib/shortcuts.ts mounted via Header.
- ✅ [**Print / PDF export for IPAM tree + subnet detail**](docs/SHIPPED.md#issue-82) (#82) — shipped `2026.07.30-1`: GET /ipam/export.pdf takes the same scope selector as the CSV/JSON/XLSX exporter (and reuses its…
- ✅ [**Global search v2**](docs/SHIPPED.md#issue-879) (#879) — all six gaps closed.
- 🟡 [**Native mobile app**](docs/SHIPPED.md#issue-884) (#884) — PWA groundwork + iOS app in its own repo ([spatiumddi-mobile](https://github.com/spatiumnorth/spatiumddi-mobile)); server side shipped here (#906 #903 #917 #907 #913 #914). **Still open:** the app.
- ✅ [**Login banner**](docs/SHIPPED.md#issue-885) (#885) — acceptable-use login banner, uploaded logo, DEV/TEST/PROD strip, real `app_title` (+ #886 / #887 / #888, PR #892).
- ✅ [**Conformance-fuzz sweep — undeclared media types, FK 500s, and tools that never ran**](docs/SHIPPED.md#issue-921) (#921) — shipped `2026.09.04-1`: Three QA reports that turned out to be three *classes*, each fixed at class scope with a guard so the…
- ✅ [**Agent-managed BIND9 AXFR fails PeerBadKey on operator-key-only groups**](docs/SHIPPED.md#issue-920) (#920) — shipped `2026.10.02-1`: closed by #1133: drift and Sync with Servers now read each zone from the view that holds it.

- ✅ [**Kea drops relayed DHCP requests before it reads them under CPU pressure**](docs/SHIPPED.md#issue-980) (#980) — shipped `2026.10.02-1`: a QA report whose *observation* was exact and whose three proposed fixes were all wrong, in ways only…

- ✅ [**celery-beat reported unhealthy forever after a slot upgrade**](docs/SHIPPED.md#issue-925) (#925) — shipped `2026.09.04-1`: The rollup was right that something was broken and wrong about what.

- ✅ [**Appliance role chart never installed since #988 — two Helm releases both claimed the PriorityClasses**](docs/SHIPPED.md#issue-992) (#992) — shipped `2026.10.02-1`: the appliance chart is installed twice per appliance, under two release names, and #988's…
- ✅ [**Direct kubelet transport (#990) was firewalled shut on every appliance**](docs/SHIPPED.md#issue-993) (#993) — shipped `2026.10.02-1`: the supervisor's input chain is policy drop and opened 10250 to *cluster peers* only, an empty set on…
- ✅ [**Boot cosmetics — a failed console unit and a Warning event on every healthy first boot**](docs/SHIPPED.md#issue-994) (#994) — shipped `2026.10.02-1`: both make systemctl --failed and the events feed lie about a healthy node, which is how operators…
- ✅ [**DNS zone detail clipped its own primary action — eleven header buttons in one row**](docs/SHIPPED.md#issue-996) (#996) — shipped `2026.10.02-1`: at ~1,460 px with the sidebar open, + Add Record rendered as a + sliver at the right edge.

- ✅ [**Installer wizard review — 28 fixes in five phases**](docs/SHIPPED.md#issue-995) (#995) — shipped `2026.10.02-1`: a review of spatium-install (2,723 lines, 19 screens) prompted by a fresh install of the #988 ISO.

- ✅ [**Three host runners discard their piped input — `python3 -` reads the program from stdin**](docs/SHIPPED.md#issue-1001) (#1001) — shipped `2026.10.02-1`: one bug, three call sites, and the blast radius was decided entirely by whichever except clause each…

- ✅ [**Blanking the installer's Time source did not disable NTP**](docs/SHIPPED.md#issue-1002) (#1002) — shipped `2026.10.02-1`: Debian's /etc/chrony/chrony.conf carries its own pool directive and sourcedir is additive, so…

- ✅ [**Change Password accepted a password the server then refused**](docs/SHIPPED.md#issue-1004) (#1004) — shipped `2026.10.02-1`: two minimums were in play on the forced first-login screen, a hardcoded 8 and the configured 12, and…

- ✅ [**Every control-plane first boot wrote a second helm revision**](docs/SHIPPED.md#issue-1005) (#1005) — shipped `2026.10.02-1`: helm-controller MERGES a HelmChartConfig on top of the same-named HelmChart, and since #1003 item 4…

- ✅ [**SSH source-CIDR allowlist was dead code on port 22**](docs/SHIPPED.md#issue-1009) (#1009) — shipped `2026.10.02-1`: the second of the two independent reasons the allowlist did nothing, and the one #1001 deliberately…

- ✅ [**Storage redundancy — RAID1 + multipath: fleet monitoring, management, and install support**](docs/SHIPPED.md#issue-999) (#999) — shipped `2026.10.02-1`: Split out of #995 items 23 + 24, whose *refusal* half shipped there.

- ✅ [**Alert forwarding filtered — and rendered — against keys alert payloads never carry**](docs/SHIPPED.md#issue-1031) (#1031) — shipped `2026.10.02-1`: three payload shapes go through one delivery path, and only one of them was handled.

- ✅ [**Three build-guard defects that each made a guard useless in its own way**](docs/SHIPPED.md#issue-1028) (#1028) — shipped `2026.10.02-1`: all three found while cutting the #999 ISO, and they share a lesson the repo has now recorded four…

- ✅ [**Appliance ISO + upgrade image for arm64 — with an architecture gate on the slot-upgrade path first**](docs/SHIPPED.md#issue-1026) (#1026) — shipped `2026.10.02-1`: three parts, and the ordering is the issue's own: part 1 (the gate) shipped alone, before any arm64…

#### CLI tool

- ⬜ [**`spddi` CLI**](https://github.com/spatiumnorth/spatiumddi/issues/83)

## Version Scheme

SpatiumDDI uses **CalVer**: `YYYY.MM.DD-N` where N is the release number for that date (starting at 1).

- `2026.04.13-1` — first release on April 13, 2026
- `2026.04.13-2` — hotfix on the same day
- Git tags and Docker image tags follow this scheme exactly
- Release is triggered by pushing a tag (see `.github/workflows/release.yml`). It publishes nothing until three gates pass ([#1226](https://github.com/spatiumnorth/spatiumddi/issues/1226)): the tag is a release tag on `main` and `ci.yml` passed on that commit (it waits up to an hour for a running CI); every image is built once, pushed by digest, and both architectures pass Trivy + `trivy-gate.sh` before that digest is tagged; and `:latest` moves last, all images or none, only after the GitHub release exists. The tag decisions (validity, previous release, whether it becomes latest) live in `scripts/release_version.py`, on top of `backend/app/core/versions.py`'s ordering, and rank only tags on `main` with a published release (`.github/scripts/release-tags.sh`). The shipped image list is `.github/images.json`, shared by `release.yml`, `nightly.yml` and `scripts/lint_image_upgrades.py`
- PRs add a `changelog.d/<issue>-<slug>.md` fragment, never an edit to `CHANGELOG.md` ([#2431](https://github.com/spatiumnorth/spatiumddi/issues/2431)): every PR used to insert at the same `## Unreleased` spot, so open PRs conflicted pairwise and a merge queue drops a conflicting entry. **Release prep runs `make changelog` first** (folds the fragments into `## Unreleased` and deletes them), then renames the section; `release.yml` refuses a tag whose tree still has a fragment

**Switching to SemVer at 1.0.0** ([#1182](https://github.com/spatiumnorth/spatiumddi/issues/1182)). Releases stay CalVer up to and including the **bridge** (the last CalVer release); from 1.0.0 they are `MAJOR.MINOR.PATCH`, with candidates tagged `1.0.0-rc.N` and published as GitHub pre-releases. Every SemVer release is newer than every CalVer one (`1.0.0` > `2026.09.04-1`), so **never compare versions as strings**: use `backend/app/core/versions.py` (`parse_release`, `includes_release`, `upgrade_direction`), its frontend mirror `frontend/src/lib/versions.ts` (keep the two in step; `versions.test.ts` runs the same cases), and, for tag decisions in CI, `scripts/release_version.py`. A build that is not a release (`dev`, `latest`, a nightly's `0.0.0-nightly-YYYYMMDD+sha`, a `0.x` placeholder) is an *unknown* version, never an old one. The bridge must ship before `1.0.0` is tagged: every "is this newer?" decision runs in the version being upgraded *from*, so only the bridge and later can see that 1.0.0 is newer. Every CalVer Helm chart is a SemVer pre-release, so a helm command for one needs an explicit `--version`.

---

## Issue tracking

Every open issue is on the public org project **[SpatiumDDI](https://github.com/orgs/spatiumnorth/projects/2)**. Anyone can view it; only org owners can change it. Its README has the full triage procedure. Keep private material off it: draft issues on a public project are visible to everyone. Each piece of state has exactly one home:

| What | Where | Values |
|---|---|---|
| Release scope | milestone | 1.0.0 ships in drops: `1.0.0-beta.4` (4 Nov), `1.0.0-beta.5` (7 Nov, feature freeze), `1.0.0-rc.1` (10 Nov, code freeze), then `rc.N` until a clean soak. Until rc.1 every new bug and QA / Academy finding, P0 to P3, goes on the open drop with the earliest due date; from rc.1, P0 and P1 go on the current rc and P2 and P3 on `1.0.1`. The plain `1.0.0` milestone holds only the tracking issues. A feature is in only when a maintainer adds a milestone. The ship criteria are in [#1181](https://github.com/spatiumnorth/spatiumddi/issues/1181) |
| Urgency | project field **Priority** | **P0** data loss, a security hole, wrong DNS / DHCP / IPAM answers, or an install or upgrade that never converges · **P1** fix before the release, or move it out with a reason · **P2** may slip to a patch release · **P3** polish |
| Where it was found | label | `source:qa` (the ddi-pg proving ground) · `source:academy` (building the Academy course) · `source:community` |
| State | project field **Status** | Triage → Backlog or Todo → In progress → In review → Done. The project's workflows move most of these |
| Kind and area | issue type and `area:*` / `theme:*` labels | the existing taxonomy |

**PR milestones are automatic.** `.github/workflows/pr-milestone.yml` gives a PR the milestone its closing issues share, and at merge falls back to the next release (the lowest-versioned open milestone); it never changes one already set. A PR whose issues disagree, or one stacked on another branch (GitHub does not link its `Fixes #N`), gets the fallback.

The QA loop (`spatiumnorth/ddi-pg`) reads two things from issues, and both are easy to break by accident:

- **Assigning an issue to amoona6 hands it to QA.** `/issues-fix-check` works every open issue assigned to that account: it reproduces the issue, fixes it, proves the fix on a stacked build, and opens the PR. Don't assign there as a courtesy.
- **ddi-pg classifies issues by label.** It reads `roadmap`, `enhancement`, `feature` and `epic` as "not a defect", and a label named exactly `qa` or `harness` as "our harness". So triage only ever *adds* labels, and never creates `qa` or `harness`. Dropping `enhancement` from a QA issue, for example, turns it into a defect the loop will try to fix.

**Merging.** PRs are squash-merged, and the squash message is built from the commit messages, so a commit message becomes permanent history. main requires a PR to be up to date and every review thread resolved, the code-quality bot's included, so bring a PR up to date just before merging it; every merge makes the other open PRs stale again. Once the `merge_queue` rule is on `protect-main` ([#2431](https://github.com/spatiumnorth/spatiumddi/issues/2431)), the queue does the updating: `gh pr merge N` enqueues, and the PR is never pushed to again; `docs/DEVELOPMENT.md` §12 has the details. The merged branch is deleted automatically. When a PR that adds a migration merges, any other open PR with a migration must re-point its `down_revision` at the new head, or CI sees two Alembic heads.

**Release branches ([#3948](https://github.com/spatiumnorth/spatiumddi/issues/3948)).** While `main` is frozen for a release candidate, the next releases' work goes on long-lived `release/X.Y.Z` branches (`release/1.0.1`, `release/1.1.0`): an issue on milestone X.Y.Z gets its `issue-NNN` branch and its PR off `release/X.Y.Z`, CI runs as for `main`, and the PR takes milestone X.Y.Z by itself. Tags stay on `main`: a release branch is squash-merged into `main` through a PR (`protect-main` requires linear history) once the release before it ships, and the release is tagged on that commit. Merge `main` into the release branches after each rc fix, and `release/1.0.1` into `release/1.1.0`; re-point `down_revision` when a merge brings migrations from both sides. `docs/DEVELOPMENT.md` §12 has the details.

```bash
gh issue list --milestone 1.0.0-beta.4                  # the current drop
gh project item-list 2 --owner spatiumnorth --limit 500 --format json \
  --jq '.items[] | select(.priority=="P0" and .status!="Done") | "#\(.content.number) \(.status) \(.content.title)"'
```

---

## Development Commands

```bash
# First-time setup
cp .env.example .env          # set POSTGRES_PASSWORD + SECRET_KEY (openssl rand -hex 32)
make build
make migrate
make up                       # production images  —  or:  make dev  (hot-reload)

# Default login: admin / admin (force_password_change=True)

# Run DNS and/or DHCP service containers too (via compose profiles):
COMPOSE_PROFILES=dns,dhcp make up

# Migrations
make migration MSG="add foo column"    # generate (autogenerate against models)
make migrate                           # apply

# Lint, typecheck, test
make lint                              # ruff + black + mypy, eslint + prettier
make ci                                # the lint/build/chart/perf jobs CI runs (backend-lint + frontend-lint + frontend-build
                                       #   + charts-lint + perf-test + versions-check + workflow-shell-check).
                                       #   Run before pushing.
make versions-check                    # Version-pin manifest (#975) — asserts every pin declared in the root versions.json
                                       #   still appears, at that version, in each file carrying a copy of it. Bumping a
                                       #   component is ONE edit (its `version` field) plus whatever this then reports.
                                       #   Covers what Dependabot cannot see: Helm's five copies, chart values.yaml,
                                       #   Dockerfile ARGs, action `with:` inputs, CI script defaults, the appliance bake
                                       #   arrays, and the version column of docs/THIRD_PARTY.md. Part of `make ci`.
make workflow-shell-check              # Workflow shell-status guard (#1036) — refuses `$?` captured after a bare command
                                       #   in a `run:` block. Actions supplies `bash -e` and `set -uo pipefail` does NOT
                                       #   clear it, so `cmd; rc=$?` is dead code on exactly the failure it handles; that
                                       #   silently disarmed the weekly CVE scan. Neither actionlint nor shellcheck flags
                                       #   the shape. Part of `make ci`.
make versions-upstream                 #   ...the other half: resolve each declared upstream and print a current-vs-latest
                                       #   table. Advisory + network-bound, so NOT part of `make ci`; the weekly
                                       #   trivy-scheduled workflow runs it and files the delta. `hold` entries in the
                                       #   manifest carry the reason a pin is behind on purpose, and report separately.
make trivy                             # container-image CVE scan — run before pushing ANY agent Dockerfile change.
make openapi VERSION=2026.08.22-1      # export the OpenAPI contract the release attaches (#903). Byte-identical
                                       #   to the release asset at the same tag; runs --network none, so it also proves
                                       #   the export needs no database, Redis or outbound access.
make tld-registry-check                # is the bundled IANA TLD list (#986) behind IANA? Exit 1 = stale. Run at
                                       #   release-prep; `make tld-registry` rewrites backend/app/data/iana_tlds.json.
                                       #   A stale list makes recently-delegated TLDs read as "Undelegated" on every
                                       #   install that never clicks Settings → DNS → TLD Registry → Refresh.
make docs                              # local Jekyll preview of docs/ on :4000 (DOCS_PORT to override); docs-down stops it.
make docs-verify                       # diagram-geometry gate — same check CI's "Docs — Diagram Geometry" job runs.
                                       #   Run before pushing ANY docs/assets/**.svg change. Needs chromium on PATH.
make charts-lint                       # Charts — Lint & Template gate (#966), via a helm container: helm lint + template
                                       #   with every toggle on + kubeconform -strict + the no-BestEffort check (#965)
                                       #   + the pod-posture check (#983 — seccomp everywhere, a PriorityClass on every
                                       #   appliance pod). Covers ALL THREE charts: #983 added spatiumddi-metallb, which
                                       #   nothing had ever rendered on a PR. Run before pushing ANY charts/** change;
                                       #   renders land in .charts-render/.
make perf-test                         # Perf — Tests (#968), via Docker. perf/ is denied by the backend path filter,
                                       #   so a perf-only PR runs this and NOT the 8 backend shards.
make trivy IMAGE=kea                   #   ...one image only. Same gate CI uses (HIGH/CRITICAL, ignore-unfixed).
                                       #   CI's Trivy is path-filtered + PR-only, so touching a Dockerfile can surface a
                                       #   PRE-EXISTING CVE. Note golang:X.Y.Z pins are SECURITY pins — Go static-links its
                                       #   stdlib into the binary, so no apk upgrade can fix a stdlib CVE.
# ⚠️  DO NOT use `make test` on a small dev box. It runs `-n auto` (pytest-xdist),
#     one worker per CPU, each importing the full app and carving its own
#     `spatiumddi_test_gw<N>` database. On 8 cores / 7 GB that exhausts RAM and
#     `max_locks_per_transaction` partway through, and the failure DOES NOT look
#     like OOM — it looks like thousands of ERRORs at *fixture setup* on files
#     unrelated to your change (2655 then 2839 in one session, every affected
#     file passing serially). Budget a wasted debugging cycle if you trust it.
#     Also: only ever ONE pytest session at a time — conftest TRUNCATEs every
#     mapped table between tests, so two runs deadlock on the same locks.
#     Reach for `-n auto` only in CI or on a bigger machine.
make test                              # backend pytest, -n auto — CI / big-machine only; see warning above
make test-cov                          # the same, WITH coverage — the only place it runs since #1019 (addopts used
                                       #   to force it onto every CI shard + every test-one: 15-30 % overhead nothing read)
make test-durations                    # refresh backend/.test_durations from the latest main CI run's artifact (#1019).
                                       #   pytest-split balances the 12 CI shards with it; commit at release-prep or when
                                       #   the Backend — Tests aggregator warns. Stale = imbalanced shards, never wrong.
cd frontend && npm test                # vitest (#906) — the QR tests DECODE what the component renders, since a
                                       #   transposed row scans as nothing and neither review nor tsc can see it.
make test-one T=tests/test_health.py::test_liveness   # ← PREFER THIS LOCALLY. Serial, ~5 min per ~110 tests.
                                       #   Or several files at once, still serial:
                                       #   docker compose -f docker-compose.dev.yml exec -T api \
                                       #     python -m pytest tests/test_a.py tests/test_b.py -q --no-cov

# Logs
docker compose logs -f api worker
docker compose logs -f dns-bind9-dev dhcp-kea   # requires the profile to be on

# Frontend-only dev loop (outside Docker — Node 20+)
cd frontend && npm install && npm run dev

# Reset admin password (if locked out)
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

Frontend theme: dark/light/system toggle; CSS vars in `frontend/src/index.css`; toggle in Header component.

---
*See individual docs for full specifications.*
