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
| `docs/PRIVACY.md` | The privacy statement — no telemetry, no analytics, no phone-home — plus the **normative table of every outbound connection** the backend can make, its default, and what it sends. `backend/tests/test_outbound_hosts_documented.py` fails CI when a hostname literal in `backend/app` is absent from it. **When you add an outbound call, update this page in the same PR** (see non-negotiable #17) |
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
| `docs/PERMISSIONS.md` | RBAC permission grammar (`{action, resource_type, resource_id?}`), builtin roles, wildcards |
| `docs/features/SYSTEM_ADMIN.md` | System config, health dashboard, notifications, backup/restore, service control |
| `docs/deployment/APPLIANCE.md` | OS appliance build, base OS selection, licensing |
| `docs/deployment/DNS_AGENT.md` | DNS agent/container architecture — image layout, auto-registration, config sync, K8s shape |
| `docs/deployment/DOCKER.md` | Docker Compose setup, ports, first-time setup, TLS, HA, password reset |
| `docs/deployment/TOPOLOGIES.md` | Six reference deployment topologies — single VM, separated agents, DNS+DHCP HA, HA control plane (Patroni / Redis Sentinel), hybrid cloud, K8s — with SVG diagrams + sizing notes |
| `docs/deployment/KUBERNETES.md` | Umbrella Helm chart walkthrough — HPA, Ingress / LoadBalancer, CloudNativePG + Redis Sentinel HA (see also `k8s/README.md` + `charts/spatiumddi/README.md`) |
| `docs/deployment/BAREMETAL.md` | Bare-metal/VM paths — Docker Compose on a host, Patroni HA Postgres overlay, OS appliance (no Ansible playbooks; that path is planned, not implemented) |
| `docs/deployment/WINDOWS.md` | Windows Server prerequisites — WinRM, service accounts (DnsAdmins / DHCP Users), firewall, zone dynamic-updates; shared by Windows DNS + Windows DHCP |
| `k8s/README.md` | Kubernetes manifest usage, HA PostgreSQL (CloudNativePG), Redis Sentinel |
| `k8s/base/` | Core K8s manifests (namespace, API, worker, frontend, migrate job) |
| `k8s/ha/` | HA add-ons: CloudNativePG cluster, Redis Sentinel, Patroni Compose |
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

> **Documentation sites (`/docs`).** The Jekyll docs in `docs/` are **documentation only** ([#1070](https://github.com/spatiumnorth/spatiumddi/issues/1070)): `index.md` is the documentation index, every page uses the one `default` layout, and there is no hero, feature grid, screenshot gallery or install pitch — the product / company site is a separate project, and a link to it will be added to the nav once it exists. Do not reintroduce product copy here. The site is served from **two** GitHub Pages sites, and it matters which one you are looking at:
>
> | URL | Pages site type | Source | Tracks |
> |---|---|---|---|
> | `www.spatiumddi.com` | organization site | repo `spatiumnorth/spatiumnorth.github.io` | **`main`** (published by CI) |
> | `www.spatiumddi.com/spatiumddi/` | project site | this repo, `main` branch, `/docs` path | **`main`** |
>
> The custom domain `www.spatiumddi.com` is configured on the **org-site repo** (its `CNAME` file), which is why *both* URLs live under it — setting a custom domain on an organization site moves its project sites too. The repo must be named `spatiumnorth.github.io` — matching the org — because that name is what makes GitHub serve it as the org site at all; the domain sits on top. `spatiumnorth.github.io` 301s to the custom domain. **Never add a `CNAME` to `docs/`** — it would be mirrored to the site repo *and* applied to the project site, pointing the domain at the wrong one; `docs-publish.yml` excludes `CNAME` from its `rsync --delete` so the real one survives releases. There is **no `gh-pages` branch** — both sites build from a `/docs` path, and the project site needs no workflow at all. The org-root site exists because GitHub only ever serves an org's root Pages site from a repo named `<org>.github.io`; that repo holds **no sources of its own** and is mirrored from `docs/` by `.github/workflows/docs-publish.yml` on every `main` push and release tag (auth: the `DOCS_DEPLOY_KEY` secret, an SSH deploy key with write access to the site repo — `GITHUB_TOKEN` cannot push cross-repo). Never hand-edit the site repo; the next release overwrites it. Both sites therefore serve the same content; the root is the canonical one, and the one the README badge, `docs/sitemap.xml` and `docs/robots.txt` advertise. The root was originally release-pinned, but that let a docs fix sit unpublished behind the release cadence — the wrong trade for documentation, so it now publishes on every `main` push (and on release tags, which is a redundant-but-deterministic republish). `docs/_config.yml` deliberately sets **no `baseurl`**, and none should be added: GitHub Pages injects the correct one per build (empty for the org site, `/spatiumddi` for the project site), and hardcoding either value overrides that and breaks the other site. The layouts in `docs/_layouts/` address assets by a **relative prefix** computed from page depth rather than by `baseurl`, because baseurl is empty for a local `jekyll build` — that is what makes the site previewable before publishing. See [#751](https://github.com/spatiumnorth/spatiumddi/issues/751).

> **Marketing website.** The company / product site is being built as a **completely separate project**, outside this repository; the docs site above carries none of it (#1070 removed the landing page that used to stand in for it). `www.spatiumddi.com` — the domain this note originally earmarked for it — serves the **docs**, so the marketing site needs either a different hostname or a decision to move the docs to `docs.spatiumddi.com` and give it the apex. Should its source ever land in this monorepo, `website/` is the reserved location. Cloudflare Pages can build it straight from `website/` in this monorepo, needing no second repo and no cross-repo sync. Tracked in [#754](https://github.com/spatiumnorth/spatiumddi/issues/754). When editing the marketing site, leave the Jekyll docs alone; when editing the Jekyll docs, leave the marketing site alone. Both can ship in the same PR but never as the same artifact. Open questions: which static-site generator to lock in (raw HTML / Astro / Next.js static), whether to mirror the README screenshots / feature table here, and the CI pipeline (separate workflow that builds + publishes to a `marketing` branch / Cloudflare Pages on every `website/**` change). See `website/README.md` (once it lands) for the deployment recipe.

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

    **Which way it ships ([#1069](https://github.com/spatiumnorth/spatiumddi/issues/1069)):** default-**on** only if it is part of the core IPAM / DNS / DHCP workflow, a zero-footprint UI convenience, or a read-only diagnostic the operator invokes by hand. Default-**off** for a domain-specific registry most installs will never populate, anything that emits traffic or writes to infrastructure once armed, anything that calls off-prem, and one-shot migration tooling — day-one importers excepted, since a fresh install is exactly when an estate gets imported. This replaced "default-on so operators discover what exists", which is #13's argument for *tools* and does not transfer: a disabled tool is invisible, whereas Settings → Features lists every module with its description whether or not it is on, so the sidebar does not have to. 16 of 55 modules ship enabled.

    **Depending on another module ([#1068](https://github.com/spatiumnorth/spatiumddi/issues/1068)):** a `ModuleSpec` may declare `requires=("parent.id",)`, and `get_enabled_modules` then resolves it enabled only when its whole ancestry is. That is a REAL gate, not a display hint — a child left independently on under a disabled parent keeps a router mounted and a sidebar row visible, pointing at a subsystem the operator turned off — so a child needs no `require_module` of its own for the parent. The frontend `resolveEnabled` in `hooks/useFeatureModules.ts` mirrors it exactly and must keep doing so; the sidebar reading a child as on while the router has resolved it off is a nav row whose page 404s. `core.dns` and `core.dhcp` are the roots, so the whole DNS or DHCP surface is one toggle; their agent routers are mounted OUTSIDE the gate on purpose, because `require_module` answers 404 and 404 is what makes an agent discard its JWT and re-bootstrap from its PSK. Disabling either is refused while it still owns servers, zones or scopes.

    **Never seed the row.** A `feature_module` row means "an operator changed this" and nothing else. Seeding one at the shipped default — which #14 used to mandate — makes the catalog's `default_enabled` dead code on every install, because a row always wins and a fresh install runs the same seed migrations an upgrade does. That is the #1069 defect; migration `a9f2c71e34b8` clears the historical seeds on fresh installs only, and a guard test fails any new migration that touches the table
15. **New integrations show up on the Dashboard — both surfaces**: When adding an integration mirror (Kubernetes / Docker / Proxmox / Tailscale / UniFi shape — read-only pull reconciler with per-target rows), wire it into BOTH dashboard surfaces: (1) the `IntegrationsPanel` inside the IPAM tab on `frontend/src/pages/DashboardPage.tsx` — add the `useQuery` gated on the `integration_*_enabled` flag, thread `enabled` + row list through props, extend column-count + grid cn() case, add a panel block following the existing icon + name + count + view-all + per-row `IntegrationRow` pattern; (2) the dedicated **Integrations dashboard tab** at `backend/app/api/v1/dashboards/integrations.py` — append a target query, add a `_build_panel(...)` entry to the `panels` list, register the new resource_type string in `_INTEGRATION_RESOURCE_TYPES` so reconciler error-audit rows surface in the recent-errors list, and extend the frontend `IntegrationDashboardKind` union in `lib/api.ts`. Both surfaces are operator-facing health rollups; missing either one means a new integration is invisible somewhere it should be obvious
16. **Per-role node-label gating for every new workload**: Every new top-level workload (Deployment / StatefulSet / DaemonSet) added to `charts/spatiumddi/` or `charts/spatiumddi-appliance/` gates scheduling on a per-role node label (`spatium.io/role-<service>=true`), not on chart-render `values.<svc>.enabled` toggles. The `nodeSelector` block merges `global.nodeSelector` (the umbrella `spatium.io/role=appliance` gate) AND a per-role label. Labels are stamped by two paths that already exist: install-time bake in `appliance/mkosi.extra/usr/local/bin/spatium-install`'s `config.yaml.d/spatium-roles.yaml` drop-in for `full-stack` / `control-only` variants; dynamic apply via the supervisor's `kubectl label` (`agent/supervisor/spatium_supervisor/k8s_api.py`) for `application` variants on role-assignment changes. `enabled: false` values stay as a global suppression knob; the per-role label is the source of truth for *which* node a workload lands on. Reference pattern: `charts/spatiumddi-appliance/templates/{dns-bind9,dhcp-kea}.yaml`. Without this, multi-node HA (#272) silently schedules control-plane workloads on DNS-only nodes — invisible misplacement that won't surface until the first node loss.

17. **No telemetry.** SpatiumDDI has no phone-home, no usage analytics, no crash reporting, and no project-controlled endpoint — and there is never to be one. Never add an outbound connection that is not operator-configured and documented in [`docs/PRIVACY.md`](docs/PRIVACY.md) with its default and its payload; a hostname literal in `backend/app` that is absent from that page fails CI (`backend/tests/test_outbound_hosts_documented.py`). Anything **default-on** needs an issue and a decision, not a PR: today exactly one connection is enabled out of the box (the daily anonymous GitHub release check), the README and the Settings copy both say so in those words, and a second one makes both false at once

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

> **Why there is no prose summary of shipped work here.** There used to be: a single ~73,000-character paragraph, 52% of this entire file. It was not maintained per-release (release prep updates `CHANGELOG.md` and flips the 🟡→✅ markers below, not that paragraph), so it drifted; and because it mentioned nearly every identifier in the project, any `grep` against `CLAUDE.md` returned it and buried the real hit. Both problems are solved by pointing at the files that are actually kept current. Keep it that way: **record new work in `CHANGELOG.md` and flip the marker below — do not start a new narrative here.**

### Auth waves A–D (landed after `2026.04.16-2`)

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

### IPAM polish (shipped alongside the waves)

- **Block overlap validation** — `_assert_no_block_overlap` rejects same-level duplicates and CIDR overlaps in `create_block` + the reparent path in `update_block`.
- **Scheduled IPAM ↔ DNS auto-sync** — opt-in Celery beat task `app.tasks.ipam_dns_sync.auto_sync_ipam_dns`. Beat fires every 60 s; the task itself gates on `PlatformSettings.dns_auto_sync_enabled` + `dns_auto_sync_interval_minutes`, so cadence changes in the UI take effect without restarting beat. Optionally deletes stale auto-generated records.
- **Shared `ZoneOptions` dropdown** (`frontend/src/pages/ipam/IPAMPage.tsx`) — renders primary zone first, `<optgroup label="Additional zones">` below; applied in Create / Edit / Bulk-edit IP modals. Zone picker is restricted to the subnet's explicit primary + additional zones when any are pinned.
- **Bulk-edit DNS zone** — new `dns_zone_id` field on `IPAddressBulkChanges`; each selected IP routes through `_sync_dns_record` for move / create / delete.

### 2026.04.19-1 landings (performance, polish, visibility)

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

### 2026.04.20 roadmap completions

Phase 1 IPv6 closure + the Phase 2/3 DDNS / zone-state / CI-hardening items all landed in this window.

- **Full IPv6 `/next-address`** — EUI-64 + random /128 + sequential modes selected via `Subnet.ipv6_allocation_policy`; `_eui64_from_mac` in `backend/app/api/v1/ipam/router.py` implements RFC 4291 §2.5.1 Modified EUI-64 (u/l bit flip + `fffe` insertion); random /128 uses `secrets.randbits` with collision retry; dynamic-pool respect applies on v6 too. Test coverage in `backend/tests/test_ipv6_allocation.py` includes the RFC 4291 Appendix A worked example. Closes Phase 1.
- **DDNS pipeline (subnet-level)** — `Subnet.ddns_enabled` / `ddns_hostname_policy` / `ddns_domain_override` / `ddns_ttl`; `services/dns/ddns.py` resolves hostname per policy and calls the same `_sync_dns_record` path static allocations use; `pull_leases.py` + `dhcp_lease_cleanup.py` are the two integration points.
- **Agent-side lease-event DDNS for Kea** — `apply_ddns_for_lease` + `revoke_ddns_for_lease` wired into `POST /api/v1/dhcp/agents/lease-events` (commit `bad8cf3`), so Kea lease events drive DNS updates with the same semantics as the poll-based Windows DHCP path.
- **Block/space inheritance for DDNS settings** — `IPSpace` + `IPBlock` carry the four DDNS fields; `Subnet` / `IPBlock` carry `ddns_inherit_settings`; `services/dns/ddns.resolve_effective_ddns` walks subnet → block → space and is consulted by both the hostname resolver and the apply path (commit `a29d4fe`).
- **Per-server zone serial reporting** — `DNSServerZoneState` table + `POST /dns/agents/zone-state` for agents (agent reports after each successful apply in `agent/dns/spatium_dns_agent/sync.py`) + `GET /dns/groups/{gid}/zones/{zid}/server-state` for the UI + `ZoneSyncPill` on the zone detail header showing per-server convergence against the current SOA serial.
- **Trivy-clean + kind-AXFR acceptance tests for the agent images** — Trivy now enforces HIGH/CRITICAL (with `ignore-unfixed: true`) on both `build-dns-images.yml` and `build-dhcp-images.yml`; kind-based installation + `dig version.bind CH TXT` smoke test runs on PR via the new `.github/workflows/agent-e2e.yml` — spins up a kind cluster via `helm/kind-action@v1`, installs the umbrella chart with `dnsAgents.enabled=true`, port-forwards the API for `/health/live`, and checks the DNS agent pod isn't crash-looping.

### Appliance architecture pivot (#170, 2026-05-14)

The Application appliance role + `spatium-supervisor` + approval workflow shipped in [#170](https://github.com/spatiumnorth/spatiumddi/issues/170) waves A–D on 2026-05-14:

- **Wave A** — scaffolding. New `spatium-supervisor` container in `agent/supervisor/spatium_supervisor/`; supervisor identity (Ed25519 keypair on `/var/persist/spatium-supervisor/`, appliance row in `pending_approval` state); pairing codes reshape (drops `deployment_kind`, adds `persistent` + `enabled` + `max_claims` + Fernet-encrypted reveal); container images baked into the appliance OS rootfs (`/usr/lib/spatiumddi/images/*.tar.zst`) for air-gap-ready installs; A/B slots bumped from 4 GiB to 8 GiB each.
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

- ✅ [**Windows DNS — Path B (WinRM + PowerShell)**](https://github.com/spatiumnorth/spatiumddi/issues/21) — shipped: agentless WinRM + PowerShell path in `backend/app/drivers/dns/windows.py` (enabled per-server when `DNSServer.credentials_encrypted` is set) drives zone CRUD (`Add-DnsServerPrimaryZone` / `Remove-...`), an AXFR-free record pull (`Get-DnsServerResourceRecord`), and server-level probes over the `DnsServer` module. Record-level writes still ride RFC 2136 to avoid the PowerShell-per-record cost. Remaining literal-scope items — zone *edit* via `Set-DnsServerZone`, server-level option writes, DNS view config, GSS-TSIG for "Secure only" AD zones — were re-homed to [#444](https://github.com/spatiumnorth/spatiumddi/issues/444) (open). See [`docs/features/DNS.md`](docs/features/DNS.md) §13.
- ✅ [**Windows DHCP — Path B (WinRM + PowerShell, full CRUD)**](https://github.com/spatiumnorth/spatiumddi/issues/22) — shipped: despite the legacy `WindowsDHCPReadOnlyDriver` class name, `capabilities()` reports `read_only=False` and the driver does scope / reservation / exclusion write CRUD + scope-option reconcile + MAC deny-filter over WinRM, wired through `backend/app/services/dhcp/windows_writethrough.py` (batched, transactional, multi-server). Remaining gaps — client-class CRUD, a broader option-code map, and the stale "read-only" naming/docs — were re-homed to [#444](https://github.com/spatiumnorth/spatiumddi/issues/444) (open).
- ✅ [**IP discovery**](https://github.com/spatiumnorth/spatiumddi/issues/23) — shipped `2026.06.04-1`: opt-in per-subnet scheduled ping / ARP sweep + reconciliation (unprivileged `SOCK_DGRAM` ICMP with TCP-connect fallback, `/proc/net/arp` scan for ICMP-silent hosts, `status="discovered"` rows for live IPs with no row). Producer of the #45 / #41 hygiene loop. Migration `a7e3c1f49d20`.
- ✅ [**DNS Views — end-to-end split-horizon wiring**](https://github.com/spatiumnorth/spatiumddi/issues/24) — shipped `2026.06.04-1`: the BIND9 agent now emits one `view "<name>" { match-clients …; }` block per view with per-view zone files (`view_id IS NULL` records render into every view). Storage + CRUD + record-form picker had shipped earlier. Full body in [`docs/SHIPPED.md`](docs/SHIPPED.md).
- ✅ [**ACME embedded client — certs for SpatiumDDI's own services**](https://github.com/spatiumnorth/spatiumddi/issues/28) — [#438](https://github.com/spatiumnorth/spatiumddi/issues/438) **shipped 2026.06.19-1**, **Phases 1–5 implemented + Phase 6 resolved N/A**: a hand-rolled RFC 8555 ACME client (`backend/app/services/acme_client/` — `engine.py` manual JWS over `cryptography` + `httpx`, `dns01.py` self-solve over SpatiumDDI's own managed zones via the `record_ops` pipeline, `orchestrator.py` end-to-end driver) that issues a CA-trusted Web UI TLS cert from Let's Encrypt, landing the chain in the existing `ApplianceCertificate` storage + deploy path with `source="letsencrypt"`. Surface at `/api/v1/appliance/acme` (account upsert + `POST /preview` + `POST /issue` → `app.tasks.acme.run_acme_order` + orders list/get/cancel) behind the default-enabled `security.certificates` feature module (group Security), plus the unauthenticated root route `GET /.well-known/acme-challenge/{token}` for HTTP-01 (nginx-proxied). Account key + EAB HMAC are Fernet-encrypted + never returned (`eab_hmac_set` boolean only). **Phase 1** DNS-01 over managed zones; **Phase 2** 12h beat task `app.tasks.acme.renew_due_certificates` (re-issues active LE certs within 30d of `valid_to`, idempotent + advisory-locked, gated on `acme_enabled`+`acme_auto_renew`) + the `secret_expiring` alert now covers the LE Web-UI cert (`appliance_cert_tls:<id>`); **Phase 3** cloud-hosted DNS-01 auto-solve via the Cloudflare/Route53/Azure/Google agentless drivers (creds configured under DNS, not the ACME screen) + `POST /preview` per-domain managed/manual report + `allow_manual` manual-TXT fallback (`manual_challenges[]` + public-DNS polling converges the order); **Phase 4** http-01 (`challenge_type:"http-01"`, CA fetches the well-known route, appliance must be reachable on :80/:443 at the FQDN, no wildcards); **Phase 5** `tls-alpn-01` → 422 (not supported on the nginx/k3s topology, UI shows it disabled); **Phase 6** per-appliance certs resolved N/A (Web UI is control-plane-only behind one shared VIP cert = fleet-singleton). MCP: `find_certificates` / `count_certificates_expiring` (default on) + `get_acme_account` (default off). See `docs/features/ACME.md`. Distinct from the shipped ACME *provider* (`/api/v1/acme/`).
- 🟡 [**Cloud DNS driver family — Route 53 / Azure DNS / Cisco DNA**](https://github.com/spatiumnorth/spatiumddi/issues/29) — Route 53 + Azure DNS + Cloudflare + Google Cloud DNS landed as agentless first-class drivers via #37 Part B, **shipped `2026.06.04-1`**; `2026.06.11-1` then dropped the `dnssec_online` / `alias_records` capability advertisements so the UI stops offering cloud DNSSEC sign / ALIAS authoring that the server-side gates 422 anyway. **Still open:** real cloud DNSSEC + ALIAS support. Cisco DNA stays out of scope (SD-Access controller, not a hosted-DNS service).
- ✅ [**DHCP configuration importer — ISC DHCP, Kea, Windows DHCP**](https://github.com/spatiumnorth/spatiumddi/issues/129) — shipped `2026.06.04-1`: one-shot import-to-evaluate (sister to the DNS importer #128) behind one canonical IR + preview → commit pipeline — Kea JSON-with-comments upload, Windows live-pull (reuses the Path A driver), ISC `dhcpd.conf` parse. Provenance columns via migration `c7f1a3e58b94`. See [`docs/features/MIGRATION.md`](docs/features/MIGRATION.md).
- ✅ [**Windows → SpatiumDDI cutover (guided migration)**](https://github.com/spatiumnorth/spatiumddi/issues/756) — shipped `2026.08.12-1`: the half the #128 / #129 importers stop short of. **Not a fifth importer** — it creates no zones, scopes, pools or records; its only writes are TTL reductions on a zone SpatiumDDI already owns, reservations synthesised from live Windows leases, and `is_active` on a managed scope. Unit of work is a `cutover_plan` holding independent `cutover_item`s (one zone or one scope), each cut over and rolled back on its own — no big-bang step. Four phases: **parity** (diff vs live Windows, classified by *why* the sides differ — `value_mismatch` / `drifted_since_import` / `never_imported` / `intentionally_diverged`; CAA/TLSA/SSHFP are `not_compared` because a Path-B pull can't emit them, and an unparseable response is `unverified`, never "everything diverged"), **parallel run** (replay query-log traffic at both sides, RD=0, IP literal not hostname), **the switch** (TTL pre-flight snapshot/restore, DHCP lease→reservation handover, deactivate-Windows-before-activate-managed with compensating rollback sealed inside the transaction), **decommission checklist** (15 items, 3 advisory-evaluated, none auto-ticked). Plus a markdown runbook carrying the Windows-side PowerShell we deliberately don't run. **Load-bearing refusal:** an AD-integrated zone with "Secure only" dynamic updates is a hard block `force` cannot bypass (GSS-TSIG unimplemented — #444), failing closed. Behind the default-on `migration.cutover` module (group Tools), **superadmin on every endpoint**; router `/api/v1/migration/cutover`; 4 MCP tools (`find_cutover_parity_check` default-off — live WinRM pull). Migration `a4f1c93d7e28`. See [`docs/features/MIGRATION.md`](docs/features/MIGRATION.md). **Deferred:** auto-approve of parity warnings, and a non-Windows (BIND9 / ISC) cutover source.
- ✅ [**Technitium — agentless driver for an install the operator already runs**](https://github.com/spatiumnorth/spatiumddi/issues/810) — shipped `2026.08.12-1`: new `technitium_api` driver (`backend/app/drivers/dns/technitium_api.py`), agentless like Windows Path B: operator pastes an API URL + permanent bearer token, control plane drives Technitium's HTTP API directly, nothing deployed. Coexists with the agent-managed `technitium` (a group is single-driver). **No migration** — credentials ride the existing `DNSServer.credentials_encrypted`. Zone + record CRUD and topology pull only; DNSSEC / forwarders / blocklists stay agent-managed and `technitium_api` is deliberately absent from `_DRIVER_GATED_OPERATIONS["dnssec_sign"]`. Also extracted the rdata translation both drivers and the #744 importer need into `app/services/technitium/rdata.py` (the agent keeps a third copy it can't share — separate package), and replaced two inline `windows_dns or CLOUD_DNS_DRIVERS` topology gates with `TOPOLOGY_PULL_DRIVERS` / `supports_topology_pull()`. See [`docs/drivers/DNS_DRIVERS.md` §4C](docs/drivers/DNS_DRIVERS.md). **Deferred:** query-log polling (#742's shape, easier here than on the agent path), Technitium's DHCP API as a DHCP driver, and clustering awareness.

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

- ✅ [**UniFi Network Application**](https://github.com/spatiumnorth/spatiumddi/issues/30) — read-only mirror of UniFi networks + clients into IPAM (local + cloud-hosted controllers) behind the `integrations.unifi` feature module (`backend/app/services/unifi/`, model `models/unifi.py`, task `tasks/unifi_sync.py`, router `api/v1/unifi/`).
- ✅ [**OPNsense (tier 1 — firewall-of-choice for labs)**](https://github.com/spatiumnorth/spatiumddi/issues/31) — read-only mirror of OPNsense interfaces + DHCP leases + reservations into IPAM behind the `integrations.opnsense` feature module (`backend/app/services/opnsense/`, model `models/opnsense.py`, task `tasks/opnsense_sync.py`, router `api/v1/opnsense/`).
- ⬜ [**pfSense (tier 1 — paired with OPNsense)**](https://github.com/spatiumnorth/spatiumddi/issues/32)
- ✅ [**Palo Alto PAN-OS / Panorama (enterprise-firewall family reference vendor)**](https://github.com/spatiumnorth/spatiumddi/issues/605) — shipped `2026.07.11-1`: read-only mirror of address objects/groups → a new `firewall_endpoint_object` "shadow IPAM" store (with IPAM drift report), NAT rules → `nat_mapping` provenance rows, + opt-in zones/interfaces + DHCP leases, behind the `integrations.paloalto` feature module (`backend/app/services/panos/`, model `models/panos.py`, task `tasks/panos_sync.py`, router `api/v1/panos/` at the `/paloalto` prefix). Also a commit-free **Dynamic Address Group** enforcement tier extending Active block sync (#601) — `paloalto` target kind registers `IP → tag` via the User-ID API, gated by the new `manage_firewall_enforcement` permission. Fortinet / Check Point / Cisco FTD / Meraki follow this pattern.
- 🟡 [**Enterprise firewall family — Fortinet / Check Point / Cisco FTD / Meraki + policy-aware conformity**](https://github.com/spatiumnorth/spatiumddi/issues/606) — **Phase 1 (Fortinet + Meraki) shipped `2026.07.11-1`.** Both follow the #605 shape via a new shared mirror engine `backend/app/services/firewall_mirror.py` (the #605 PAN-OS reconciler was migrated onto it; `firewall_endpoint_object` generalized to one-of-three vendor owners with a `num_nonnulls=1` CHECK). **Fortinet FortiGate** — read-only FortiOS-REST mirror (address objects/groups → shadow IPAM, VIPs → `nat_mapping`, opt-in interfaces + DHCP leases) behind `integrations.fortinet` (`services/fortinet/`, `models/fortinet.py`, `tasks/fortinet_sync.py`, `api/v1/fortinet/`); enforcement is the credential-free **Threat-Feed inversion** — new `FirewallFeed` (`models/firewall_feed.py`, `services/firewall_feeds/`, `api/v1/firewall_feeds/`) serves a token-scoped `blocklist.txt` the FortiGate polls (module `security.firewall_feeds`, default-on). **Cisco Meraki MX** — read-only Dashboard-API mirror (VLANs → subnets, DHCP fixed-IP reservations → IPAM, org policy objects → shadow IPAM, 1:1-NAT/port-forward → `nat_mapping`, opt-in clients) behind `integrations.meraki` (`services/meraki/`, `models/meraki.py`, `tasks/meraki_sync.py`, `api/v1/meraki/`); enforcement is a `meraki` block-sync target (kind=`mac`, per-client `Blocked` device policy via the Dashboard API, gated by `manage_firewall_enforcement`). 3 MCP tools (`list_fortinet_targets` / `list_meraki_targets` / `list_firewall_feeds`); `find/count_firewall_objects` made vendor-neutral. **Deferred:** FortiManager JSON-RPC centralization; Phase 2 (Check Point + Cisco FTD/FMC, both leading with feed-based enforcement); and the cross-cutting **policy-aware conformity checks** (`pci_scope`/`internet_facing` subnets asserted against live firewall policy, plugging into #106).
- ✅ [**NetBird (managed WireGuard mesh)**](https://github.com/spatiumnorth/spatiumddi/issues/603) — shipped `2026.07.11-1`: read-only mirror of NetBird peers into IPAM behind the `integrations.netbird` feature module (`backend/app/services/netbird/`, model `models/netbird.py`, task `tasks/netbird_sync.py`, router `api/v1/netbird/`), cloned from the Tailscale shape — NetBird's real management API is what makes it a legitimate pull mirror where raw WireGuard isn't. Phase 1 mirrors each peer's overlay IP (OS / version / groups / connection state in custom fields) under an auto-created overlay block + subnet; Phase 2 adds an optional synthetic read-only DNS zone for the mesh domain. Per-instance operator-supplied management URL + `verify_tls` toggle (SSRF-guarded at the test-connection boundary), Token auth, and a cross-integration ownership guard — NetBird and Tailscale both default to `100.64.0.0/10`, so neither reconciler will claim the other's rows. 1 MCP tool (`list_netbird_targets`).
- ⬜ [**MikroTik RouterOS 7 (tier 2)**](https://github.com/spatiumnorth/spatiumddi/issues/33)
- ⬜ [**Incus / LXD (tier 2 — Docker-adjacent)**](https://github.com/spatiumnorth/spatiumddi/issues/34)
- ⬜ [**HashiCorp Nomad (tier 2 — Kubernetes alt)**](https://github.com/spatiumnorth/spatiumddi/issues/35)
- ✅ [**NetBox read-only import (one-shot)**](https://github.com/spatiumnorth/spatiumddi/issues/36) — **shipped 2026.06.28-1**. One-shot migration importer (not a continuous reconciler): live-pulls prefixes / addresses / VRFs / tenants→Customers / sites / VLANs out of a NetBox install and stamps them into native IPAM rows via a stateless preview → commit flow (`backend/app/services/netbox_import/`, router at `/api/v1/ipam/import/netbox/{test-connection,preview,commit}`). Provenance `import_source="netbox"` + `netbox_id` makes re-runs idempotent (default-skip-on-conflict); `per_vrf` (one IPSpace per VRF + Global) vs `single` (collapse into a chosen space) strategy; connection + token supplied per-request, never persisted. Behind the default-on `ipam.import.netbox` feature module; 2 MCP tools (`find_netbox_import_preview` + `propose_commit_netbox_import`). See `docs/features/MIGRATION.md`.
- ✅ [**Cloud connectors — unified "Cloud" integration with per-provider picker (Azure / AWS / GCP)**](https://github.com/spatiumnorth/spatiumddi/issues/37) — shipped `2026.06.04-1`. Part A: read-only infra mirror (`cloud_endpoint` + AWS/Azure/GCP connectors → IPBlock/Subnet/IPAddress, `services/cloud/`, feature module `integrations.cloud`). Part B: Cloudflare / Route 53 / Azure DNS / Google Cloud DNS as agentless first-class DNS drivers (`drivers/dns/{cloudflare,route53,azuredns,googledns}.py`) with import-existing-zones (`services/dns_import/cloud.py`). See `docs/features/INTEGRATIONS.md` + `docs/drivers/DNS_DRIVERS.md`. Stretch token-only DNS providers (DigitalOcean / Hetzner / Linode / Vultr) deferred.
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
- ✅ [**Reverse-DNS auto-population**](https://github.com/spatiumnorth/spatiumddi/issues/41) — shipped `2026.06.04-1`: scheduled, platform-opt-in sweep that PTR-resolves `hostname IS NULL` rows against configured resolvers (bounded concurrency, per-run cap), filling the short label into `hostname` and the FQDN into `description` only when blank. Migration `d7a3f2b9c1e4`.
- ✅ [**CGNAT (RFC 6598) awareness**](https://github.com/spatiumnorth/spatiumddi/issues/42) — shipped `2026.06.04-1`: amber "CGNAT" badge on subnet detail + a New-Subnet advisory hint when the typed network falls in `100.64.0.0/10` — the one reserved IPv4 range overlays actively carve, so reaching for it as an on-prem LAN silently overlaps overlay space.

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

- ✅ [**AV / Audio-Video-over-IP — Dante · AES67 · SMPTE 2110 · NDI**](https://github.com/spatiumnorth/spatiumddi/issues/540)
  — shipped `2026.07.30-1` (#714): `network.av` module,
  `av_flow_profile` 1:1 AV descriptor on `multicast_group` + operator-declared `av_reserved_range` per
  protocol, allocation-conflict preview, 2 conformity checks, 3 MCP
  tools. **Phase 2 (Dante mDNS) blocked** — #40 closed not-planned.
  **Phase 3 (NMOS IS-04 mirror) deferred** — a full pull integration
  with both dashboard surfaces, separable into its own change.
- ✅ [**BACnet/IP building automation**](https://github.com/spatiumnorth/spatiumddi/issues/541)
  — shipped `2026.07.30-1` (#714): `network.bacnet` module,
  `bacnet_device` with the internetwork-wide
  `uq_bacnet_device_instance` constraint (the differentiating hook),
  BBMD flag + BDT/FDT snapshots, 3 conformity checks incl.
  `bbmd_one_per_subnet` failing in both directions, 3 MCP tools.
  **Phase 2 (`Who-Is` sweep) deferred** — needs a UDP broadcast
  carrying a real payload; the only generic prober sends an empty
  datagram.
- ✅ [**Industrial / OT — PROFINET · EtherNet/IP · Modbus TCP · OPC UA**](https://github.com/spatiumnorth/spatiumddi/issues/542)
  — shipped `2026.07.30-1` (#714): `network.ot` module, `ot_device`
  1:1 descriptor + `ot_zone` Purdue zoning (`Numeric(2,1)` so level 3.5 / the DMZ is representable), CSV import
  of engineering-tool exports, 2 conformity checks, 3 MCP tools.
  Read-only identification only — control-protocol writes are
  permanently out of scope. **Phase 2 (routable probes) deferred** —
  nmap runs NSE but nothing parses `<script>` output. **Phase 3
  (PROFINET DCP) deferred** — raw L2, needs a container capability grant.
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

#### Reporting & analytics

- ⬜ [**Capacity forecasting**](https://github.com/spatiumnorth/spatiumddi/issues/43)
- ✅ [**Per-subnet utilization history**](https://github.com/spatiumnorth/spatiumddi/issues/44) — shipped `2026.06.11-1`: daily beat task snapshots each subnet's allocated / total IP counts (pruned > 90 d); Trend tab on subnet detail renders a 30 / 90-day % used line chart; `get_subnet_utilization_trend` MCP tool. Migration `c7a3e1f90d24`.
- ✅ [**Stale-IP report**](https://github.com/spatiumnorth/spatiumddi/issues/45) — shipped `2026.06.04-1`: over the #23 discovery `last_seen_at` signal — which allocated IPs has nothing answered for in N days. Paginated report (optional space / block / subnet scope) + one-click bulk-deprecate of selected or all-matching (capped, reversible).
- ✅ [**Decom-date awareness**](https://github.com/spatiumnorth/spatiumddi/issues/46) — shipped `2026.06.11-1`: first-class `decom_date` on subnet + IP, a `decom_expiring` alert rule (severity escalation reused from the other `*_expiring` rules), a dashboard widget, and a `find_subnets_decommissioning` MCP tool. Migration `a3f7c1e92b48`.
- ✅ [**Top-N reports**](https://github.com/spatiumnorth/spatiumddi/issues/47) — shipped `2026.06.11-1`: a `/reports` surface (top subnets by utilization, owners by IP count, most-modified resources via `audit_log`, noisiest DNS clients), feature-module-gated with 4 MCP read tools.
- ✅ [**Compliance / change report PDF**](https://github.com/spatiumnorth/spatiumddi/issues/48) — shipped `2026.06.11-1`: `GET /api/v1/audit/export.pdf` renders an auditor-facing PDF of every `audit_log` mutation in a date range, grouped by user / resource / action, with a per-row SHA-256 tamper-evidence trailer.
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

#### Subnet planning & calculation tools

All shipped — see `Subnet planning & calculation tools` in
[`docs/SHIPPED.md`](docs/SHIPPED.md): CIDR calculator,
Subnet planner workspace, address planner, aggregation
suggestion, free-space treemap.

#### DNS-specific

- ✅ [**DNSSEC**](https://github.com/spatiumnorth/spatiumddi/issues/49) — shipped `2026.06.04-1`: BIND9 inline-signing, policies, DS export, rollover. `DNSSECPolicy` (reusable `dnssec-policy`) + `DNSKey` (public per-zone key state — no private-key custody; BIND owns + auto-rotates keys), config-driven `dnssec-policy { … }` + per-zone `inline-signing yes;`. Migration `f2b6d4a91c37`. PowerDNS online-signing landed separately in `2026.05.11-1`.
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
  DoQ, and a k8s dnsdist front to unblock PowerDNS DoT/DoH off compose.
  Not to be confused with `PlatformSettings.resolver_dns_over_tls`, which
  is the appliance host's own systemd-resolved stub resolver.

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

- ✅ [**Zone name scope — classify zones by TLD against the IANA root list**](https://github.com/spatiumnorth/spatiumddi/issues/986)
  — `validate_fqdn` said a zone name was *syntactically* a domain and stopped,
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

#### DHCP-specific

- ✅ [**DHCPv6 stateful + SLAAC config UI**](https://github.com/spatiumnorth/spatiumddi/issues/52) — shipped `2026.06.04-1`: `DHCPScope.v6_address_mode` + `ra_managed_flag` / `ra_other_flag`; the Kea driver renders `subnet6` by mode (stateful → pools + options; stateless / SLAAC → options only). Migration `e4c1a8f63b29`.
- ⬜ [**Lease histogram by hour**](https://github.com/spatiumnorth/spatiumddi/issues/53)
- ⬜ [**Option 82 (relay agent info) class matching**](https://github.com/spatiumnorth/spatiumddi/issues/54)
- ⬜ [**DHCP test client**](https://github.com/spatiumnorth/spatiumddi/issues/55)
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
- 🟡 [**Windows DHCP failover relationships — two Windows members of one group no longer serve a scope uncoordinated**](https://github.com/spatiumnorth/spatiumddi/issues/1110)
  — **implemented in full (unreleased); only live verification against a
  real failover pair remains.** The write-through sent every scope / pool /
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
- ⬜ [**Kerberos WinRM transport for Windows DNS / DHCP**](https://github.com/spatiumnorth/spatiumddi/issues/1128)
  — **removed, not built** (unreleased): the forms offered `kerberos` while
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
- ✅ [**Maintenance mode**](https://github.com/spatiumnorth/spatiumddi/issues/57) — shipped `2026.06.11-1`: middleware 503s mutating requests during a change window (`Retry-After`, superadmin bypass, agent / auth / health exempt per non-negotiable #5); PlatformSettings-driven, audited, with a global banner + Settings surface. Migration `d1b8f4a92c30`.
- ✅ [**Built-in network tools page**](https://github.com/spatiumnorth/spatiumddi/issues/58) — shipped `2026.06.11-1`: a `/tools` page (ping / traceroute / mtr / dig / whois over sandboxed argv, port-test / TLS-cert over sockets, DNS-propagation, MAC-vendor), permission-gated + Redis rate-limited, with 7 MCP tools.
- ✅ [**PCAP capture trigger**](https://github.com/spatiumnorth/spatiumddi/issues/59) — shipped `2026.06.15-1`: on-demand tcpdump as an RBAC-gated/audited Tools page, both server-container and appliance-host (real-NIC) vantages, keep-partial-on-Stop, `.pcap` download, 4 Operator Copilot tools.
- ❌ [**ACL / prefix-list generator**](https://github.com/spatiumnorth/spatiumddi/issues/60) — **closed as not planned** 2026-06-17, in the same triage pass that closed #40. No rationale was recorded on the issue; re-open it rather than re-filing if the need comes back.
- ✅ [**Config-drift report (full record diff)**](https://github.com/spatiumnorth/spatiumddi/issues/61) — **backend shipped `2026.06.11-1`**: `GET …/zones/{id}/drift` AXFRs the live zone from every server in the group and diffs it against the DB — extra-on-server (manual host change) / missing-on-server / in-sync, per server, read-only — plus a `find_dns_zone_drift` MCP tool. **UI shipped `2026.07.30-1` (#735)** — a Drift tab on the zone detail, fetched on demand because one call fans out an AXFR to every server in the group. That PR also fixed the reason nothing had ever consumed the endpoint: `dns.query.xfr` takes an IP *literal* and raises a bare, message-less `ValueError` for a hostname before sending a packet, so every hostname-addressed server failed 100% of the time reporting `""` as the error. **[#734](https://github.com/spatiumnorth/spatiumddi/issues/734) closed the last gap** — agent-managed BIND9 / Technitium reached the server but got `REFUSED`, because the control plane transferred unsigned while the agent granted `allow-transfer` only to the group key and only on *dynamic* zones; separately, `DNSServerOptions.allow_transfer` and `DNSZone.allow_transfer` were both settable, persisted and **never rendered at all** (a silent no-op). Now: the shared AXFR helper takes an optional `TsigKey`, `resolve_group_transfer_key` picks the same key the agent granted (legacy group key first, then operator `DNSTSIGKey` rows by name — matching the bundle's ordering, which is why `op_keys` is now `order_by(name)`), the BIND9 agent renders the grant in the **options** block so it covers every zone type, Technitium falls back to `Allow` + `zoneTransferTsigKeyNames` (verified against upstream `DnsServer.cs`: the two gates AND, so naming keys makes a signature *required*), and a keyless group reports `unsupported` naming the missing key instead of a misleading ACL error. Windows Path A is deliberately excluded from `AXFR_TSIG_DRIVERS` — it authorises by address, so signing would break a working pull. **Drift now works on every driver except PowerDNS**, which implements no record pull.
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
- ⬜ [**Config snapshots + rollback**](https://github.com/spatiumnorth/spatiumddi/issues/883) — audit-log-driven revert
  of a single change plus scoped named snapshots. Distinct from #882,
  which is an agent-side safety net rather than an operator action.
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

#### Workflow & RBAC

- ✅ [**Approval workflows for risky ops — P1**](https://github.com/spatiumnorth/spatiumddi/issues/62) — shipped `2026.06.25-1`: two-person rule over the 6 delete handlers behind the default-off `governance.approvals` module + a self-governance lock; lifecycle API + Change Requests admin page + 4 MCP tools + Change Approver builtin role. The issue closed on P1, so its P2 scope was re-filed ↓.
- ⬜ [**Approval workflows — P2 (bulk ops / factory reset / import gating + approval notifications)**](https://github.com/spatiumnorth/spatiumddi/issues/717) — build on the shipped `governance.approvals` module + change-request lifecycle, not a parallel mechanism.
- ✅ [**Self-service request portal — IP / subnet / DNS / DHCP requests with approve-and-provision**](https://github.com/spatiumnorth/spatiumddi/issues/696) — shipped `2026.07.30-1` (#721): the Phase 5 "IP request workflows" item. #62's approval engine pointed the other way: a low-privilege user asks for something they cannot do themselves, an approver reviews it with the operation's own preview, and approving **provisions** it. Deliberately **not** a second state machine — portal rows live in `change_request` under `origin="portal"` and reuse the entire #62 approve spine (FOR UPDATE guard, self-approval block, approver must hold the operation's own permission, re-preview stale guard, `apply()` under the approver, audit rows, expiry sweep), so provisioning behaves identically to a manual create. A catalog allow-list (`services/requests/catalog.py`) maps four kinds onto existing `Operation`s — that allow-list is load-bearing security, because submit intentionally skips the operation's permission check. Behind the default-off `governance.requests` module; new `provisioning_request` permission (`write` + `read`) + `Requester` builtin role; 3 MCP tools. **Auto-approve rules are designed for but not built** — the seam is in `submit_request`. Pairs with multi-tenancy and #64.
- ⬜ [**Resource locking**](https://github.com/spatiumnorth/spatiumddi/issues/63)
- ⬜ [**Per-resource ACLs**](https://github.com/spatiumnorth/spatiumddi/issues/64)
- ✅ [**Time-bound permissions**](https://github.com/spatiumnorth/spatiumddi/issues/65) — shipped `2026.06.11-1`: a `time_bound_grant` table of auto-expiring *additive* RBAC grants (`{action, resource_type, resource_id?}` to a group until `expires_at`), consulted live by `user_has_permission` and soft-revoked by a 60 s beat sweep. Migration `d5e9b2c14a07`.
- ⬜ [**Comments / activity feed per resource**](https://github.com/spatiumnorth/spatiumddi/issues/66)

#### Notifications & external integrations

- ✅ [**Ansible dynamic-inventory endpoint**](https://github.com/spatiumnorth/spatiumddi/issues/67) — shipped `2026.06.11-1`: `GET /api/v1/ansible/inventory` returns standard Ansible dynamic-inventory JSON built from IPAM — hosts grouped by space / block / subnet / tag / custom-field, with `_meta.hostvars`. Read-only.
- ⬜ [**ServiceNow CMDB integration**](https://github.com/spatiumnorth/spatiumddi/issues/68)

#### Security & compliance

- ✅ [**Password policy enforcement**](https://github.com/spatiumnorth/spatiumddi/issues/70) — shipped `2026.05.07-1`: configurable complexity / history / max-age rules applied to every local-auth password set, over seven `platform_settings.password_*` knobs; `password_changed_at` + Fernet-wrapped `password_history_encrypted` on `user`.
- ✅ [**Account lockout after N failed logins**](https://github.com/spatiumnorth/spatiumddi/issues/71) — shipped `2026.05.07-1`: windowed-counter lockout for local-auth users over `user.failed_login_count` / `failed_login_locked_until` / `last_failed_login_at`, reset on any success. Defaults to disabled (`threshold=0`). Migration `a7b3c8d92e14`.
- ✅ [**Active session viewer + force-logout**](https://github.com/spatiumnorth/spatiumddi/issues/72) — shipped `2026.05.07-1`: live JWT registry the operator can browse and revoke from — access tokens carry a `jti`, and `user_session` gains `auth_source` / `last_seen_at` / `revoked` + a `(revoked, expires_at)` index. Migration `c8e4f7a91d36`.
- ✅ [**Internal cert + secret expiry monitoring**](https://github.com/spatiumnorth/spatiumddi/issues/76) — shipped `2026.06.11-1`: one `secret_expiring` alert rule that fires per internal credential expiring within `threshold_days` — supervisor mTLS certs (`appliance.cert_expires_at`) + API tokens (`api_token.expires_at`). Extended in `2026.06.19-1` to cover the Let's Encrypt Web-UI cert (#438).
- ✅ [**Privacy statement — no telemetry, no analytics, your data stays in your install**](https://github.com/spatiumnorth/spatiumddi/issues/976)
  — SpatiumDDI has been privacy-first by construction since the first commit
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
- ⬜ [**FIPS 140-3 posture**](https://github.com/spatiumnorth/spatiumddi/issues/880) — crypto audit plus a tiered
  roadmap for a FIPS-capable build (containers / Kubernetes /
  appliance). Gate for government deployments; the audit comes first
  because the answer may be "these three libraries block it".
- ⬜ [**Appliance full-disk encryption**](https://github.com/spatiumnorth/spatiumddi/issues/881) — LUKS2 at install for
  STATE + `/var`, TPM2 auto-unlock, and a recovery key the installer
  has to present exactly once without writing it anywhere it protects.

- 🟡 [**E911 dispatchable location — SpatiumDDI as a Location Information Server**](https://github.com/spatiumnorth/spatiumddi/issues/972)
  — **Phases 1a–3 shipped.** Given a phone's IP, MAC or LLDP
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

#### UX polish

- ✅ [**Saved searches / saved views**](https://github.com/spatiumnorth/spatiumddi/issues/77) — **shipped 2026.06.19-1**: per-user `SavedView(user_id, page, name, payload, is_default)` table + `/api/v1/saved-views` CRUD (scoped by user, audited) behind the default-enabled `ui.saved_views` feature module, 2 read-only MCP tools (`find_saved_views` / `count_saved_views`), and a reusable `SavedViewsMenu` header dropdown (save / load / set-default / delete) wired into the Services / Circuits / Sites list pages. New pages opt in with two props (`currentPayload` + `onApply`).
- ⬜ [**Personal pinned dashboard**](https://github.com/spatiumnorth/spatiumddi/issues/78)
- ⬜ [**Field-level history**](https://github.com/spatiumnorth/spatiumddi/issues/79)
- ⬜ [**Recent items / favourites sidebar**](https://github.com/spatiumnorth/spatiumddi/issues/80)
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
- ✅ [**Print / PDF export for IPAM tree + subnet detail**](https://github.com/spatiumnorth/spatiumddi/issues/82) — shipped `2026.07.30-1` (#739): `GET /ipam/export.pdf` takes the same scope selector as the CSV/JSON/XLSX exporter (and reuses its `_collect`, so the two can't disagree about the subtree) and renders one of two shapes — a **tree** report for a space / block, or a **detail** report for a subnet. Surfaced as *Print / PDF* in both Export dropdowns. **reportlab, not the weasyprint the issue text proposed** — two reportlab PDFs already ship and a second engine would add Cairo / Pango to every image for no new capability. Unlike #48 and the conformity report, this one paginates: `repeatRows=1` plus a two-pass `_NumberedCanvas` for "Page N of M". Two things worth knowing if you touch it: reportlab's `Paragraph` parses mini-XML, so **all** DB-sourced text must go through `_para()` (an unescaped `a<b>c` space name 500s the export, and `<legacy> net` silently renders as "net"); and the tree indent must stay inside WinAnsiEncoding, or reportlab swaps in ZapfDingbats and nested blocks render as `■■`. Both have regression tests. *(GitHub auto-closed this issue on 2026-06-18 in error — PR [#446](https://github.com/spatiumnorth/spatiumddi/pull/446) said `CodeQL #82`, meaning alert 82. Reopened 2026-07-28, genuinely shipped now.)*
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
- 🟡 [**Agent-managed BIND9 AXFR fails PeerBadKey on operator-key-only groups**](https://github.com/spatiumnorth/spatiumddi/issues/920)
  — **not reproduced; one real latent defect in that path fixed, and the
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
  operator-key-only case #920 asks for. **Still open:** the reported failure
  itself, which needs `rndc tsig-list` (or the effective `named.conf` plus
  includes) from an affected node to say what named actually loaded.

- ✅ [**Kea drops relayed DHCP requests before it reads them under CPU pressure**](https://github.com/spatiumnorth/spatiumddi/issues/980)
  — a QA report whose *observation* was exact and whose three proposed fixes
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

- ✅ [**Appliance role chart never installed since #988 — two Helm releases both claimed the PriorityClasses**](https://github.com/spatiumnorth/spatiumddi/issues/992)
  — the appliance chart is installed **twice per appliance**, under two
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
- ✅ [**Direct kubelet transport (#990) was firewalled shut on every appliance**](https://github.com/spatiumnorth/spatiumddi/issues/993)
  — the supervisor's `input` chain is `policy drop` and opened 10250 to
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
- ✅ [**Boot cosmetics — a failed console unit and a Warning event on every healthy first boot**](https://github.com/spatiumnorth/spatiumddi/issues/994)
  — both make `systemctl --failed` and the events feed lie about a healthy
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
- ✅ [**DNS zone detail clipped its own primary action — eleven header buttons in one row**](https://github.com/spatiumnorth/spatiumddi/issues/996)
  — at ~1,460 px with the sidebar open, `+ Add Record` rendered as a `+`
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

- ✅ [**Installer wizard review — 28 fixes in five phases**](https://github.com/spatiumnorth/spatiumddi/issues/995)
  — a review of `spatium-install` (2,723 lines, 19 screens) prompted by a
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

- ✅ [**Three host runners discard their piped input — `python3 -` reads the program from stdin**](https://github.com/spatiumnorth/spatiumddi/issues/1001)
  — one bug, three call sites, and the blast radius was decided entirely by
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

- ✅ [**Blanking the installer's Time source did not disable NTP**](https://github.com/spatiumnorth/spatiumddi/issues/1002)
  — Debian's `/etc/chrony/chrony.conf` carries its own `pool` directive and
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

- ✅ [**Change Password accepted a password the server then refused**](https://github.com/spatiumnorth/spatiumddi/issues/1004)
  — two minimums were in play on the forced first-login screen, a hardcoded 8
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

- ✅ [**Every control-plane first boot wrote a second helm revision**](https://github.com/spatiumnorth/spatiumddi/issues/1005)
  — helm-controller MERGES a `HelmChartConfig` on top of the same-named
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

- ✅ [**SSH source-CIDR allowlist was dead code on port 22**](https://github.com/spatiumnorth/spatiumddi/issues/1009)
  — the second of the two independent reasons the allowlist did nothing, and
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

- 🟡 [**Storage redundancy — RAID1 + multipath: fleet monitoring, management, and
  install support**](https://github.com/spatiumnorth/spatiumddi/issues/999) — split out
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
  → start-limit → the path unit itself dead). **Still open: a
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

- ✅ [**Alert forwarding filtered — and rendered — against keys alert payloads never carry**](https://github.com/spatiumnorth/spatiumddi/issues/1031)
  — three payload shapes go through one delivery path, and only one of them was
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

- ✅ [**Three build-guard defects that each made a guard useless in its own way**](https://github.com/spatiumnorth/spatiumddi/issues/1028)
  ([#1029](https://github.com/spatiumnorth/spatiumddi/issues/1029),
  [#1030](https://github.com/spatiumnorth/spatiumddi/issues/1030)) — all three found
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

- ✅ [**Appliance ISO + upgrade image for arm64 — with an architecture gate on the slot-upgrade path first**](https://github.com/spatiumnorth/spatiumddi/issues/1026)
  — three parts, and the ordering is the issue's own: **part 1 (the gate) shipped
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

#### CLI tool

- ⬜ [**`spddi` CLI**](https://github.com/spatiumnorth/spatiumddi/issues/83)

## Version Scheme

SpatiumDDI uses **CalVer**: `YYYY.MM.DD-N` where N is the release number for that date (starting at 1).

- `2026.04.13-1` — first release on April 13, 2026
- `2026.04.13-2` — hotfix on the same day
- Git tags and Docker image tags follow this scheme exactly
- Release is triggered by pushing a tag matching `[0-9]{4}.[0-9]{2}.[0-9]{2}-*` (see `.github/workflows/release.yml`)

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
