---
layout: default
title: Third-Party Components
description: Every third-party component SpatiumDDI bundles, ships or runs — grouped by artifact, with licenses and where each one comes from.
---

# Third-Party Components

SpatiumDDI is an assembly job as much as it is a codebase. It does not
reimplement DNS or DHCP — it runs BIND9, PowerDNS, Technitium and Kea, and it
runs them on a Kubernetes distribution it did not write, on an operating system
it did not write. This page is the catalogue of everything in that stack: what
it is, which artifact it ships in, what license it carries, and why it is there.

**Two files cover this ground, and they are not the same thing.**

| File | Purpose | Authoritative for |
|---|---|---|
| [`NOTICE`](https://github.com/spatiumnorth/spatiumddi/blob/main/NOTICE) | Legal attribution notice, shipped in the repo root and in every image | License obligations |
| This page | Operator-facing catalogue — versions, artifact placement, rationale | Understanding what runs where |

If the two ever disagree about a license, `NOTICE` wins and the discrepancy is
a bug worth [filing](https://github.com/spatiumnorth/spatiumddi/issues).

Neither file enumerates every transitive dependency. They cover components that
are **bundled, shipped, or directly depended on** — the things an operator can
point at in a running system, and the things a license auditor asks about. The
full transitive set for the Python and npm layers lives in
`backend/pyproject.toml` + `frontend/package-lock.json`; for the OS layer, ask
the package manager on a running appliance (see
[Verifying a running system](#verifying-a-running-system)).

## Artifacts

The "Where" column throughout this page refers to these:

| Artifact | What it is |
|---|---|
| **API image** | `ghcr.io/spatiumnorth/spatiumddi-api` — FastAPI control plane, Celery worker, Celery beat, and the migrate job. One image, four roles |
| **Frontend image** | `ghcr.io/spatiumnorth/spatiumddi-frontend` — the built React SPA behind nginx |
| **DNS agent images** | `dns-bind9`, `dns-powerdns`, `dns-technitium`, `dns-dnsdist` — each pairs a DNS engine with the Python sync agent |
| **DHCP agent image** | `dhcp-kea` — Kea DHCPv4 + DHCPv6 + radvd + the Python sync agent |
| **Looking Glass image** | `looking-glass` — GoBGP collector + agent |
| **Supervisor image** | `spatium-supervisor` — host-side controller on the OS appliance |
| **Appliance OS** | The bootable Debian image, including its baked k3s |
| **Helm charts** | `charts/spatiumddi` (generic Kubernetes) and `charts/spatiumddi-appliance` (on-appliance k3s) |

Versions below are the pins on `main` at the time of writing, and the
**Pinned in** column names the file each one lives in.

Since [#975](https://github.com/spatiumnorth/spatiumddi/issues/975) this table no
longer drifts on its own: the pins that neither Dependabot nor a lockfile owns
are declared in
[`versions.json`](https://github.com/spatiumnorth/spatiumddi/blob/main/versions.json),
and `scripts/lint_versions.py` — which runs on every CI build — fails when the
version column here disagrees with it. So the numbers below for k3s, MetalLB,
CloudNativePG, GoBGP, Technitium, Redis, PostgreSQL, HAProxy, Alpine,
node-exporter and kube-state-metrics are checked, not merely written down.
Rows the lint does not cover (an Alpine package version such as BIND's, which
moves with the base image) are still "at the time of writing".

## DNS, DHCP and routing engines

The reason the project exists. Every one of these is a separate upstream daemon
running as its own process — SpatiumDDI generates their configuration and talks
to their control channels, it does not link against them.

| Component | Version | License | Where | Pinned in |
|---|---|---|---|---|
| [ISC BIND 9](https://www.isc.org/bind/) | `>= 9.20.26` (Alpine) | MPL 2.0 | DNS agent image | `agent/dns/images/bind9/Dockerfile` |
| [PowerDNS Authoritative Server](https://www.powerdns.com/) | Alpine `pdns` | GPL v2 | DNS agent image | `agent/dns/images/powerdns/Dockerfile` |
| [Technitium DNS Server](https://technitium.com/dns/) | 15.4.0 (digest-pinned) | GPL v3 | DNS agent image | `agent/dns/images/technitium/Dockerfile` |
| [PowerDNS dnsdist](https://dnsdist.org/) | Alpine `dnsdist` | GPL v2 | DNS agent image | `agent/dns/images/dnsdist/Dockerfile` |
| [ISC Kea DHCP](https://www.isc.org/kea/) | Alpine `kea`, v4 + v6 | MPL 2.0 | DHCP agent image | `agent/dhcp/images/kea/Dockerfile` |
| [radvd](https://radvd.litech.org/) | Alpine `radvd` | BSD-style | DHCP agent image | `agent/dhcp/images/kea/Dockerfile` |
| [GoBGP](https://github.com/osrg/gobgp) | 4.9.0 (built from source) | Apache 2.0 | Looking Glass image | `agent/looking-glass/images/gobgp/Dockerfile` |
| [BIND `dig` / `nsupdate`](https://www.isc.org/bind/) | `bind-tools` | MPL 2.0 | DNS + supervisor + API images | several Dockerfiles |

Notes worth carrying:

- **Technitium runs on .NET.** Its image is Ubuntu-based (upstream's own base),
  not Alpine like the other agents, and it pulls in the ASP.NET Core runtime.
  It is the one DNS engine whose base image SpatiumDDI does not choose.
- **dnsdist is not a general DNS server here.** It exists to give PowerDNS
  inbound DoT/DoH, which pdns-auth does not speak natively. See
  [DNS](features/DNS.md).
- **Kea 3.0 imposes path restrictions** on hook libraries and socket paths as a
  result of CVE-2025-32801/2/3. The Dockerfile carries a prominent warning
  about this; the paths in it are load-bearing, not stylistic.

## Kubernetes and orchestration

| Component | Version | License | Where | Pinned in |
|---|---|---|---|---|
| [k3s](https://k3s.io/) | v1.36.4+k3s1 | Apache 2.0 | Appliance OS | `appliance/scripts/fetch-k3s.sh` |
| [containerd](https://containerd.io/) + [runc](https://github.com/opencontainers/runc) | embedded in k3s | Apache 2.0 | Appliance OS | (k3s bundle) |
| [CoreDNS](https://coredns.io/) | k3s airgap bundle | Apache 2.0 | Appliance OS | (k3s bundle) |
| [Flannel](https://github.com/flannel-io/flannel) | embedded in k3s, `host-gw` backend | Apache 2.0 | Appliance OS | `appliance/mkosi.extra/etc/rancher/k3s/config.yaml` |
| [local-path-provisioner](https://github.com/rancher/local-path-provisioner) | k3s airgap bundle | Apache 2.0 | Appliance OS | (k3s bundle) |
| [etcd](https://etcd.io/) | embedded in k3s | Apache 2.0 | Appliance OS | (k3s bundle) |
| [Helm](https://helm.sh/) | k3s helm-controller | Apache 2.0 | Appliance OS | (k3s bundle) |
| [Traefik](https://traefik.io/) | in k3s bundle, **disabled** | MIT | Appliance OS | `config.yaml` `disable:` list |
| [metrics-server](https://github.com/kubernetes-sigs/metrics-server) | in k3s bundle, **disabled** | Apache 2.0 | Appliance OS | `config.yaml` `disable:` list |
| [MetalLB](https://metallb.io/) | chart + images 0.15.3 | Apache 2.0 | Helm chart (opt-in) | `charts/spatiumddi-metallb/Chart.yaml` |
| [FRRouting](https://frrouting.org/) | via MetalLB frr-k8s | GPL v2 | Helm chart (opt-in) | `charts/spatiumddi-metallb` values |
| [CloudNativePG](https://cloudnative-pg.io/) | chart 0.29.0 (operator 1.30.0) | Apache 2.0 | Helm chart (opt-in) | `charts/spatiumddi-appliance/Chart.yaml` |
| [Patroni](https://github.com/patroni/patroni) | `k8s/ha/` overlay | MIT | Bare-metal HA overlay | `k8s/ha/` |
| [HAProxy](https://www.haproxy.org/) | 3.4-alpine | GPL v2 (+ LGPL libs) | Patroni HA overlay | `k8s/ha/` |

Three of these deserve a sentence, because their state is not what you would
assume from their presence:

- **Traefik and metrics-server ship but are disabled.** They arrive inside the
  k3s airgap image tarball, which is a single artifact — you cannot fetch a k3s
  release without them. The appliance disables both in `config.yaml`: operator
  TLS goes through the existing nginx reverse proxy, and metrics-server costs
  ~80 MiB RSS for something not yet surfaced.
- **MetalLB is pinned to 0.15.3 deliberately**, chart and images together. 0.16.0
  regressed the speaker into an apiserver-flooding reconcile loop
  ([metallb#3063](https://github.com/metallb/metallb/issues/3063)), and pinning
  only the images while keeping the newer chart crashloops on a health probe the
  older binary does not serve.
- **FRRouting is GPL v2** and only enters the picture when an operator opts into
  BGP-mode MetalLB. Both `bgp.enabled` and `frrk8s.enabled` default to false.

## Data services

| Component | Version | License | Where | Pinned in |
|---|---|---|---|---|
| [PostgreSQL](https://www.postgresql.org/) | 16-alpine | PostgreSQL License | Compose + Helm chart | `docker-compose.yml` |
| [Redis](https://redis.io/) | 8.10.1-alpine | RSALv2 / SSPLv1 / AGPLv3 (Redis 8+) | Compose + Helm chart | `docker-compose.yml` |
| [Prometheus node-exporter](https://github.com/prometheus/node_exporter) | v1.12.1, **default off** | Apache 2.0 | Appliance chart | `charts/spatiumddi-appliance/values.yaml` |
| [kube-state-metrics](https://github.com/kubernetes/kube-state-metrics) | v2.20.0, **default off** | Apache 2.0 | Appliance chart | `charts/spatiumddi-appliance/values.yaml` |
| [prometheus-client](https://github.com/prometheus/client_python) | see manifest | Apache 2.0 AND BSD 2-Clause | API image | `backend/pyproject.toml` |

**On Redis's license:** Redis relicensed away from BSD at 7.4 (RSALv2 + SSPLv1)
and added an AGPLv3 option at 8.0. SpatiumDDI ships the stock upstream
`redis:8.10.1-alpine` image unmodified and talks to it as a network service over
its own protocol — no Redis code is linked into or vendored by SpatiumDDI.

Operators who would rather not run that license family can point the deployment
at any Redis-protocol-compatible server via the connection URL. The control
plane uses only `GET` / `SET` / `DEL` / `INCR` / `EXPIRE` / `SCAN` and pub/sub —
no modules, no Lua, no streams — and Celery's Redis broker is the other
consumer. This is an untested configuration rather than a supported one; if you
run SpatiumDDI on a Redis alternative,
[tell us how it went](https://github.com/spatiumnorth/spatiumddi/issues).

The Helm chart used to bundle Bitnami's PostgreSQL and Redis subcharts. Bitnami
pruned its Docker Hub namespace in late 2025 in favour of paid images, so the
pinned tags stopped resolving; the chart now ships plain StatefulSets using the
official upstream images instead.

## Control-plane backend (Python)

Runs in the **API image**. Authoritative list, with versions:
`backend/pyproject.toml`. The two API-docs bundles are not Python
packages: they are vendored in `backend/app/static/api-docs/` and pinned in
`versions.json`.

| Component | License | What it does here |
|---|---|---|
| [Python](https://www.python.org/) 3.12 | PSF | Runtime |
| [FastAPI](https://fastapi.tiangolo.com/) / [Starlette](https://www.starlette.io/) | MIT / BSD 3-Clause | HTTP framework |
| [Swagger UI](https://github.com/swagger-api/swagger-ui) 5.33.0, vendored | Apache 2.0 | The interactive API docs at `/api/docs`, served by the api with no CDN |
| [ReDoc](https://github.com/Redocly/redoc) 2.5.4, vendored | MIT | The reference API docs at `/api/redoc`, served by the api with no CDN |
| [Uvicorn](https://www.uvicorn.org/) | BSD 3-Clause | ASGI server |
| [SQLAlchemy](https://www.sqlalchemy.org/) / [Alembic](https://alembic.sqlalchemy.org/) | MIT | ORM + migrations |
| [asyncpg](https://github.com/MagicStack/asyncpg) | Apache 2.0 | Async PostgreSQL driver |
| [Pydantic](https://pydantic.dev/) / pydantic-settings | MIT | Schema validation, settings |
| [Celery](https://docs.celeryq.dev/) | BSD 3-Clause | Task queue |
| [redis-py](https://github.com/redis/redis-py) + hiredis | MIT | Redis client |
| [structlog](https://www.structlog.org/) | MIT OR Apache 2.0 | Structured JSON logging |
| [cryptography](https://cryptography.io/) | Apache 2.0 OR BSD 3-Clause | Fernet secrets at rest, cert handling |
| [pyOpenSSL](https://www.pyopenssl.org/) | Apache 2.0 | TLS chain capture (stdlib `ssl` cannot on 3.12) |
| [python-jose](https://github.com/mpdavis/python-jose) / [joserfc](https://jose.authlib.org/) | MIT / BSD 3-Clause | JWT issue + verify |
| [bcrypt](https://github.com/pyca/bcrypt) | Apache 2.0 | Local password hashing |
| [pyotp](https://github.com/pyauth/pyotp) | MIT | TOTP second factor |
| [ldap3](https://github.com/cannatag/ldap3) | **LGPL v3** | LDAP authentication |
| [python3-saml](https://github.com/SAML-Toolkits/python3-saml) | MIT | SAML SP flow |
| [pyrad](https://github.com/pyradius/pyrad) | BSD 3-Clause | RADIUS authentication |
| [tacacs_plus](https://github.com/ansible/tacacs_plus) | BSD | TACACS+ authentication |
| [httpx](https://www.python-httpx.org/) | BSD 3-Clause | HTTP client (all outbound integrations) |
| [dnspython](https://www.dnspython.org/) | ISC | DDNS, AXFR, resolution |
| [Jinja2](https://jinja.palletsprojects.com/) | BSD 3-Clause | Config rendering |
| [pywinrm](https://github.com/diyan/pywinrm) | MIT | Windows DNS/DHCP over WinRM |
| [requests-credssp](https://github.com/jborean93/requests-credssp) | MIT | CredSSP transport for WinRM — required to manage Windows DHCP failover relationships (second hop) |
| [pysnmp](https://github.com/lextudio/pysnmp) | BSD 2-Clause | SNMP polling |
| [paramiko](https://www.paramiko.org/) | **LGPL 2.1** | SSH transport |
| [smbprotocol](https://github.com/jborean93/smbprotocol) | MIT | SMB backup targets |
| [openpyxl](https://openpyxl.readthedocs.io/) | MIT | XLSX import/export |
| [reportlab](https://www.reportlab.com/) | BSD | PDF reports (audit, compliance, IPAM) |
| [croniter](https://github.com/kiorky/croniter) | MIT | Schedule parsing |
| [icalendar](https://github.com/collective/icalendar) / [caldav](https://github.com/python-caldav/caldav) / [python-dateutil](https://github.com/dateutil/dateutil) | BSD 2-Clause / Apache 2.0 (dual with GPL v3) / dual | Wake-on-LAN calendar gate |
| [idna](https://github.com/kjd/idna) | BSD 3-Clause | IDNA2008 name normalization |
| [boto3](https://github.com/boto/boto3) | Apache 2.0 | AWS mirror + Route 53 DNS + S3 backups |
| [azure-identity / azure-mgmt-\*](https://github.com/Azure/azure-sdk-for-python) | MIT | Azure mirror + Azure DNS + Blob backups |
| [google-cloud-\* / google-auth](https://github.com/googleapis/google-cloud-python) | Apache 2.0 | GCP mirror + Cloud DNS + GCS backups |
| [docker](https://github.com/docker/docker-py) | Apache 2.0 | Cert-reload signal on non-k3s appliances |
| [PyYAML](https://pyyaml.org/) | MIT | HelmChartConfig rewriting |
| [openai](https://github.com/openai/openai-python) / [anthropic](https://github.com/anthropics/anthropic-sdk-python) | Apache 2.0 / MIT | Operator Copilot model clients |

**Cloudflare has no SDK entry on purpose.** The Cloudflare DNS driver speaks
plain REST over `httpx` rather than pulling in the official SDK, which ships a
pydantic-v1 compatibility shim.

**On the two copyleft Python libraries:** `ldap3` (LGPL v3) and `paramiko`
(LGPL 2.1) are imported as libraries into an Apache-2.0 application. LGPL
permits this; what it requires is that a recipient can replace the library. They
are installed as ordinary, separately-replaceable site-packages in the image —
nothing is statically linked or vendored.

## Agent runtimes (Python)

The DNS, DHCP, Looking Glass and supervisor agents each carry a much smaller
dependency set than the control plane. Common to all: `httpx`, `structlog`,
`pydantic`.

| Agent | Additional | License | Why |
|---|---|---|---|
| DNS | dnspython, cryptography | ISC, Apache 2.0 OR BSD 3-Clause | DDNS + TSIG |
| DHCP | [Scapy](https://scapy.net/) | GPL v2 | Passive DHCP fingerprinting — opt-in at runtime, installed unconditionally so the toggle needs no second image |
| Supervisor | cryptography, PyYAML | Apache 2.0 OR BSD 3-Clause, MIT | Ed25519 identity, chart values |
| Looking Glass | — | — | Talks to GoBGP over its API |

## Frontend

Runs in the **frontend image**. Authoritative list:
`frontend/package.json`.

| Component | License | What it does here |
|---|---|---|
| [React](https://react.dev/) + react-dom 18 | MIT | UI framework |
| [TypeScript](https://www.typescriptlang.org/) | Apache 2.0 | Language |
| [Vite](https://vite.dev/) | MIT | Build tool + dev server |
| [Tailwind CSS](https://tailwindcss.com/) + tailwindcss-animate | MIT | Styling |
| [shadcn/ui](https://ui.shadcn.com/) | MIT | Component patterns (vendored source, not a dependency) |
| [Radix UI](https://www.radix-ui.com/) context-menu | MIT | Accessible primitive |
| [TanStack Query](https://tanstack.com/query) | MIT | Server-state cache |
| [React Router](https://reactrouter.com/) | MIT | Routing |
| [axios](https://axios-http.com/) | MIT | HTTP client |
| [Recharts](https://recharts.org/) | MIT | Charts |
| [lucide-react](https://lucide.dev/) | ISC | Icons |
| [react-markdown](https://github.com/remarkjs/react-markdown) + remark-gfm | MIT | Copilot message rendering |
| [dnd-kit](https://dndkit.com/) | MIT | Drag-and-drop |
| clsx, tailwind-merge | MIT | Class composition |
| [nginx](https://nginx.org/) 1.31-alpine | BSD 2-Clause | Static serving + API reverse proxy |

## Appliance operating system

The bootable image is Debian 13 (trixie), built with
[mkosi](https://github.com/systemd/mkosi). The full package list is
`appliance/mkosi.conf` — this is the operator-meaningful subset.

| Component | License | Why it is on the image |
|---|---|---|
| [Linux kernel](https://kernel.org/) | GPL v2 | `linux-image-amd64`, not the cloud variant — the cloud kernel strips KMS, leaving an 80x25 console instead of the dense one the dashboard needs |
| [Debian](https://www.debian.org/) base | DFSG (mixed) | Base distribution |
| [systemd](https://systemd.io/) + udev + systemd-resolved | LGPL 2.1+ | Init, device management, host resolver |
| [GRUB 2](https://www.gnu.org/software/grub/) | GPL v3 | Hybrid BIOS + UEFI boot |
| [NetworkManager](https://networkmanager.dev/) | GPL v2+ | Interface configuration |
| [nftables](https://netfilter.org/) | GPL v2 | Default-deny inbound firewall, per-role drop-ins |
| [chrony](https://chrony-project.org/) | GPL v2 | NTP |
| [Net-SNMP](https://net-snmp.org/) | BSD-style | `snmpd` — needs unfiltered `/proc` and `/sys`, which is why it runs on the host and not in a container |
| [lldpd](https://lldpd.github.io/) | ISC | Neighbour discovery |
| [rsyslog](https://www.rsyslog.com/) + rsyslog-gnutls | GPL v3 / LGPL v3 | Syslog forwarding, TLS transport |
| [OpenSSH](https://www.openssh.com/) | BSD-style | Operator access |
| [cloud-init](https://cloud-init.io/) | GPL v3 / Apache 2.0 | First-boot provisioning |
| [unattended-upgrades](https://github.com/mvo5/unattended-upgrades) | GPL v2 | Security patches (no kernel upgrades) |
| [newt / whiptail](https://pagure.io/newt) | LGPL v2 | Install wizard dialogs |
| [gdisk](https://www.rodsbooks.com/gdisk/), dosfstools, e2fsprogs, parted | GPL v2 / GPL v3 | Disk partitioning + filesystems |
| [mdadm](https://git.kernel.org/pub/scm/utils/mdadm/mdadm.git/) | GPL v2 | Builds + manages the software-RAID1 mirror install (#999 Part C); also what makes an array creatable at all, since `/proc/mdstat` is a kernel interface but creating one needs the userspace tool |
| [multipath-tools](https://github.com/opensvc/multipath-tools) (incl. kpartx) | LGPL v2.1 (library), GPL v2 (tools) | Presents a SAN LUN's paths as one `/dev/mapper/mpathX` device so it can be an install target with failover, and maps the partitions inside it (#999 Part C3) |
| [lvm2](https://sourceware.org/lvm2/) | GPL v2 / LGPL v2.1 | Device-mapper userspace that multipath-tools depends on |
| [exfatprogs](https://github.com/exfatprogs/exfatprogs) | GPL v2 | `fsck.exfat` / `mkfs.exfat` for removable USB backup disks (#989 item 3). The kernel mounts exFAT with no userspace helper, but a disk yanked without ejecting can come back dirty and only `fsck.exfat` can say so — without it an operator's only recourse at the console is to reformat |
| [rsync](https://rsync.samba.org/) | GPL v3 | Rootfs mirror to target disk |
| [qemu-guest-agent](https://www.qemu.org/) / [open-vm-tools](https://github.com/vmware/open-vm-tools) | GPL v2 / GPL v2 + BSD | Hypervisor integration; both no-op off their platform |
| [zstd](https://facebook.github.io/zstd/) | BSD 3-Clause / GPL v2 | Image + airgap tarball compression |
| [jq](https://jqlang.github.io/jq/), [curl](https://curl.se/), less, htop, tcpdump, dnsutils | MIT / curl / GPL / BSD / MPL 2.0 | Operator diagnostics |
| [Rich](https://github.com/Textualize/rich) + [psutil](https://github.com/giampaolo/psutil) (python3-rich, python3-psutil) | MIT / BSD 3-Clause | The console dashboard on tty1 |

**There is no Docker on the appliance.** It was removed in #183 Phase 7 — the
image is k3s-only, and k3s's static binary carries its own containerd plus
`kubectl` / `ctr` / `crictl` as argv symlinks.

## Operator tooling inside the API image

The Tools page (`/tools`) and PCAP capture shell out to real binaries, so they
ship in the API image rather than being reimplemented. All are invoked through a
sandboxed argv builder, never a shell string.

| Component | License | Used by |
|---|---|---|
| [nmap](https://nmap.org/) | NPSL (Nmap Public Source License) | Port/service scan tools |
| [tcpdump](https://www.tcpdump.org/) + libpcap | BSD 3-Clause | PCAP capture (#59), granted `cap_net_raw` |
| [mtr](https://www.bitwizard.nl/mtr/) (mtr-tiny) | GPL v2 | Path analysis |
| iputils-ping, traceroute | BSD / GPL v2 | Reachability |
| [whois](https://github.com/rfc1036/whois) | GPL v2 | Registration lookup |
| BIND `dig` (dnsutils) | MPL 2.0 | DNS query + propagation check |
| [PostgreSQL client 16](https://www.postgresql.org/) | PostgreSQL License | `pg_dump` / `pg_restore` for backup + restore |
| [xmlsec1](https://www.aleksey.com/xmlsec/) (libxmlsec1-openssl) | MIT | SAML assertion signature verification |
| [libnfs](https://github.com/sahlberg/libnfs) (libnfs14) | LGPL v2.1 | `nfs` backup destination ([#971](https://github.com/spatiumnorth/spatiumddi/issues/971)) |

**libnfs is LGPL and dynamically linked, deliberately.** The `nfs` backup
destination binds `libnfs.so.14` through `ctypes` at runtime — no compilation, no
static linking, and the Debian package is installed unmodified. That keeps the
LGPL v2.1 obligation to its simple case (§6's dynamic-linking allowance): an
operator can replace the shared library with their own build without touching
SpatiumDDI. Only the runtime package (`libnfs14`) ships; `libnfs-dev` is not in
either build stage. Note that this is the *only* entry in this table SpatiumDDI
links against rather than executing as a subprocess.

**nmap's license is not OSI-approved.** The NPSL is a GPL v2 derivative with
added restrictions on redistribution inside commercial products. SpatiumDDI is
Apache 2.0 and ships nmap as an unmodified, separately-installed Debian package
invoked as a subprocess — no linking, no derivative work. Anyone repackaging
SpatiumDDI commercially should read the NPSL themselves rather than assume the
Apache license covers it.

## Container bases and init

| Component | Version | License | Where |
|---|---|---|---|
| [Alpine Linux](https://alpinelinux.org/) | 3.24 | MIT (+ GPL v2 kernel) | BIND9 / PowerDNS / dnsdist / Kea / Looking Glass agent images, supervisor — **not** Technitium (see below) |
| [Debian slim](https://www.debian.org/) | trixie / bookworm | DFSG (mixed) | Appliance builder, Technitium agent build stage |
| [technitium/dns-server](https://hub.docker.com/r/technitium/dns-server) | 15.4.0 (digest-pinned; Ubuntu-based) | GPL v3 | Technitium agent image **runtime** — the one agent image that is not Alpine |
| [python:3.12-slim](https://www.python.org/) | 3.12 | PSF + Debian | API image |
| [node](https://nodejs.org/) | 22-alpine | MIT | Frontend build stage |
| [nginx](https://nginx.org/) | 1.31.5-alpine | BSD 2-Clause | Frontend runtime |
| [ASP.NET Core runtime](https://dotnet.microsoft.com/) | 10.0 | MIT | Technitium agent image |
| [tini](https://github.com/krallin/tini) | Alpine/Debian pkg | MIT | PID 1 in every agent image |
| [su-exec](https://github.com/ncopa/su-exec) / [gosu](https://github.com/tianon/gosu) | Alpine / Debian pkg | MIT / Apache 2.0 | Privilege drop at entrypoint |

Alpine is pinned at **3.23, not 3.24**, and that pin is load-bearing: 3.24 ships
Python 3.13 while the agent Dockerfiles install into 3.12 paths, which produces a
`ModuleNotFoundError` crashloop rather than a build failure. Dependabot is
configured to hold the pin.

## Build and test toolchain

Not shipped to operators — listed because a contributor will meet all of it, and
because CI gates depend on specific behaviour from several.

| Component | License | Role |
|---|---|---|
| [mkosi](https://github.com/systemd/mkosi) | LGPL 2.1 | Builds the appliance disk image |
| [Go](https://go.dev/) | BSD 3-Clause | Builds GoBGP from source in the Looking Glass image |
| [Trivy](https://trivy.dev/) | Apache 2.0 | Image CVE gate (HIGH/CRITICAL, `--ignore-unfixed`) |
| [pytest](https://pytest.org/) + pytest-asyncio / cov / xdist / split | MIT | Backend test suite |
| [ruff](https://docs.astral.sh/ruff/) / [black](https://black.readthedocs.io/) / [mypy](https://mypy-lang.org/) | MIT | Backend lint + typecheck |
| [ESLint](https://eslint.org/) / [Prettier](https://prettier.io/) / typescript-eslint | MIT | Frontend lint |
| [Playwright](https://playwright.dev/) | Apache 2.0 | README/docs screenshot generation |
| [Jekyll](https://jekyllrb.com/) + kramdown | MIT | This documentation site |
| [Helm](https://helm.sh/) | Apache 2.0 | Chart packaging |

## License obligations

SpatiumDDI itself is [Apache 2.0](https://github.com/spatiumnorth/spatiumddi/blob/main/LICENSE).
Everything above keeps its own license. The combination is distributed as
**separate, independently-installed programs** — container images built from
upstream distribution packages, and a disk image built by a distribution's own
package manager. Nothing copyleft is statically linked into, or vendored inside,
the Apache-2.0 codebase.

The practical consequences:

- **GPL components ship unmodified.** BIND9, PowerDNS, dnsdist, Technitium,
  Scapy, FRRouting, HAProxy and the Debian host userland are all upstream
  binaries installed from their distributions' repositories. Source for each is
  available from the distribution that packaged it, on the terms in that
  package's license.
- **The two LGPL Python libraries** (`ldap3`, `paramiko`) are imported, not
  linked or vendored, and are replaceable in place inside the image.
- **nmap's NPSL is the one license here that is not OSI-approved** and carries
  redistribution conditions Apache 2.0 does not. See the note above.
- **Technitium is GPL v3** and, unlike the other engines, runs from upstream's
  own container image with a digest pin. SpatiumDDI adds the sync agent as a
  separate process in that image; it does not patch the server.

If you are performing a license review and need something this page does not
answer, [open an issue](https://github.com/spatiumnorth/spatiumddi/issues) — that
is a documentation bug, not a support question.

## Verifying a running system

This page can drift. A running system cannot.

Python packages in the API image, with versions and licenses:

```bash
docker compose exec api python3 -m pip list
docker compose exec api python3 -m pip show ldap3 paramiko
```

OS packages on the appliance:

```bash
dpkg-query -W -f='${Package}\t${Version}\t${Homepage}\n' | sort
```

Packages inside an Alpine-based agent image:

```bash
docker compose exec dns-bind9 apk list --installed
```

What k3s actually bundles in the release you are running — the manifest is baked
onto the appliance at build time, alongside k3s's own LICENSE:

```bash
cat /usr/share/doc/k3s/k3s-images.txt
cat /usr/share/doc/k3s/LICENSE
```

Images running on the appliance's k3s cluster right now:

```bash
kubectl get pods -A -o jsonpath='{range .items[*].spec.containers[*]}{.image}{"\n"}{end}' | sort -u
```

## See also

- [`NOTICE`](https://github.com/spatiumnorth/spatiumddi/blob/main/NOTICE) — the shipped attribution notice
- [Architecture](ARCHITECTURE.md) — how these components fit together
- [DNS Drivers](drivers/DNS_DRIVERS.md) / [DHCP Drivers](drivers/DHCP_DRIVERS.md) — how SpatiumDDI drives the engines
- [OS Appliance](deployment/APPLIANCE.md) — how the image is built
- [Kubernetes](deployment/KUBERNETES.md) — the umbrella chart
