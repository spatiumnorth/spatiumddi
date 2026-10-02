---
layout: default
title: Privacy
description: SpatiumDDI collects no telemetry, no analytics and no account data — and this page lists every outbound connection the software can make, what each one sends, and how to turn it off.
---

# Privacy: your data stays yours

SpatiumDDI collects **no telemetry, no usage analytics, no crash
reports, and no account or registration data**. There is no
phone-home, no license server, no sign-up, and no project-controlled
endpoint the software talks to. Everything you put in it — zones,
records, leases, subnets, credentials, query logs, audit history —
lives in *your* PostgreSQL on *your* infrastructure, and the
maintainers have no way to see it and do not want it. The
documentation site and the web UI use no analytics or tracking
scripts.

The software makes no outbound connection you did not configure, with
one exception: a **daily anonymous check of GitHub for a newer
release** (an unauthenticated GET; GitHub sees your IP address and
nothing about your install). Turn it off under **Settings →
Application → Updates → Check for GitHub Releases**, or run fully
air-gapped — every feature works with no internet access at all,
except PowerDNS server groups for now (§3.5).
Optional features that do reach third parties (Fingerbank device
profiling, the Operator Copilot's LLM provider, Let's Encrypt,
blocklist feeds, cloud DNS / integration mirrors, the whois and RBL
tools) are off until you configure them,
and the table below lists exactly what each one sends and to whom.
Choosing **PowerDNS** for a server group adds a connection that is
not yet yours to configure: ALIAS records resolve their targets
through Cloudflare's and Google's public resolvers, which are
hardcoded today. That is a defect, not a design choice (§3.5,
[#1353](https://github.com/spatiumnorth/spatiumddi/issues/1353)).

There is no telemetry endpoint to opt out of, because there is no
telemetry endpoint. That is a design constraint, not a current state:
[CLAUDE.md](https://github.com/spatiumnorth/spatiumddi/blob/main/CLAUDE.md)
non-negotiable #17 forbids adding one, and a CI test
(`backend/tests/test_outbound_hosts_documented.py`) fails the build
when a hostname appears in the backend or the agents that is not
documented on this page.

---

## 1. What is never collected

| | |
|---|---|
| Usage analytics / product telemetry | None. No counters, no feature-usage pings, no "anonymous statistics" toggle, because there is nothing behind it. |
| Crash / error reporting | None. Errors go to your structured logs and the in-app diagnostics table. No Sentry, no Bugsnag, no third-party error sink. |
| Accounts / registration / licensing | None. SpatiumDDI has no account system of its own, no activation, no entitlement check, and no trial timer. Apache 2.0, run it. |
| Your DDI data | Never leaves your PostgreSQL unless you configure something that sends it (an integration to your own controller, a backup target you own, an alert webhook you point somewhere). |
| Web UI tracking | The frontend loads no external script, font, or CDN asset. `frontend/index.html` pulls exactly one file: the app bundle from your own server. |
| Docs site tracking | `www.spatiumddi.com` is a static Jekyll site with no analytics tag, no tracker pixel, and no third-party font or CDN include. |

## 2. The one connection that is on by default

**Daily GitHub release check** — `GET https://api.github.com/repos/spatiumnorth/spatiumddi/releases/latest`

Fired once a day by Celery Beat
(`backend/app/tasks/update_check.py`), so the UI can tell you a newer
release exists. It is:

* **unauthenticated** — no token, no identifier, no cookie;
* **empty in the outbound direction** — the request carries no version
  string, no install id, no counts, no hostnames. Nothing about your
  deployment is in it;
* **anonymous to us and visible only to GitHub** — GitHub sees the
  source IP address and an HTTP client User-Agent, exactly as it would
  if you loaded the releases page in a browser. SpatiumDDI's
  maintainers operate no server in this path and receive nothing.

It is on by default because it is genuinely empty and because an
operator who does not know a security fix shipped is worse off than
one whose firewall logged a daily GET to GitHub. If you would rather
it did not happen, one toggle stops it:

**Settings → Application → Updates → Check for GitHub Releases** (or
`PlatformSettings.github_release_check_enabled = false`). With it off,
the task returns immediately and opens no socket. Nothing else in the
product degrades — you simply do not get the "update available" pill.

## 3. Every outbound connection, in full

This table is normative. A hostname that appears in `backend/app` or
in an agent package under `agent/` — or a public IP address in an agent
package — and not here fails CI (see §8).

### 3.1 Enabled by default

| Connection | What is sent | Turn it off with |
|---|---|---|
| `api.github.com` — daily release check | Anonymous GET. GitHub sees your IP + User-Agent; nothing about the install. | Settings → Application → Updates → *Check for GitHub Releases* |

That is the whole list.

### 3.2 On demand — only when an operator clicks

| Connection | Feature | What is sent |
|---|---|---|
| `api.github.com` | The Releases view / Appliance → Fleet → Slot images (`services/appliance/releases.py`) | Anonymous GET for the release list and appliance-image asset names. |
| `data.iana.org`, `rdap.arin.net`, `rdap.db.ripe.net`, `rdap.apnic.net`, `rdap.lacnic.net`, `rdap.afrinic.net` | Domain + ASN registration lookup (#85) and its *Refresh now* button; Settings → DNS → TLD Registry → *Refresh now* (#986) | The domain name or ASN being looked up. RDAP is a public registry query — by nature the registry learns what you asked about. The TLD-registry refresh sends **nothing**: it is an unauthenticated GET of one public file, `data.iana.org/TLD/tlds-alpha-by-domain.txt`. |
| `crt.sh` | TLS certificate → *Certificate Transparency* cross-reference | The hostname being checked. Explicitly on-demand, never run by the scheduled probe, and the matching copilot tool ships disabled. |
| RBL / DNSBL zones (`zen.spamhaus.org`, `bl.spamcop.net`, …) | Tools → RBL check | A DNS query encoding the IP being checked, to the list operator's resolver. |
| Public resolvers | Tools → DNS propagation check | The name being queried, to each resolver in the chosen set. |
| Whois / RDAP servers | Tools → whois | The name or IP being looked up. |

Everything in this section is a per-click action with a visible result;
nothing here runs on a schedule.

### 3.3 Off until you configure them

| Connection | Feature | Default | What is sent |
|---|---|---|---|
| RBL / DNSBL zones | Scheduled DNSBL monitoring | off — `dnsbl_monitoring_enabled=false`, **and** every catalogue list ships disabled, so both a master switch and a per-list opt-in are required | A DNS query encoding each monitored IP, to the list operator's resolver. |
| `standards-oui.ieee.org` | MAC vendor database refresh | `oui_lookup_enabled=false` | Nothing — a CSV download. |
| `api.fingerbank.org` | DHCP device profiling | off; requires **your** Fingerbank API key | **Sends observed fingerprints**: DHCP option 55, option 60, and the client MAC address. The most identifying outbound call in the product — read `docs/features/DHCP.md` before enabling it. |
| `api.openai.com`, `generativelanguage.googleapis.com`, Azure OpenAI (`<your-resource>.openai.azure.com`), Anthropic | Operator Copilot | off; no provider is configured out of the box | **Sends prompts and tool results** — which can include hostnames, subnets and record data — to whichever provider you point it at. Can be fully on-prem: Ollama, vLLM and LocalAI all work through the `openai_compat` driver, in which case nothing leaves your network. |
| `acme-v02.api.letsencrypt.org`, `acme-staging-v02.api.letsencrypt.org`, or any ACME directory you name | Embedded ACME client (#438) | off | A standard ACME order: the domains you are requesting a certificate for. Those names end up in public Certificate Transparency logs — that is how public CAs work, not something SpatiumDDI adds. |
| Blocklist feed hosts (Hagezi, OISD, AdGuard, urlhaus, phishing.army, … — the catalogue is `backend/app/data/dns_blocklist_catalog.json`) | RPZ blocking lists | off per list | Nothing — an HTTPS download of the list, once per refresh interval, per list you subscribed to. |
| `api.cloudflare.com`, `dns.hetzner.com`, `api.linode.com`, `api.vultr.com`, `api.digitalocean.com`, plus the AWS / Azure / Google SDK endpoints | Agentless cloud DNS drivers | off; one server row per provider | Zone and record operations, with **your** credentials, to **your** tenant. |
| `api.meraki.com`, `api.netbird.io`, `api.tailscale.com`, `login.tailscale.com`, `api.ui.com` | Vendor-hosted integration mirrors (Meraki, NetBird, Tailscale, UniFi cloud) | off; one target row each | Read-only API calls with your credentials to your own tenant. Self-hosted integrations (Proxmox, OPNsense, PAN-OS, FortiGate, Kubernetes, Docker, …) reach only the address you type. |
| `stat.ripe.net`, `www.peeringdb.com`, `ris-live.ripe.net`, `rpki.cloudflare.com`, `rpki-validator.ripe.net` | BGP Looking Glass enrichment | off (`bgp.*` feature modules) | The ASN or prefix being enriched. |
| Your alert / notification endpoints (Slack webhook, generic webhook, SMTP relay) | Alerting | off until a channel is configured | The alert payload, to the URL or relay you entered. |
| Your audit-forward endpoint | Audit forwarding | off | Audit rows, to the URL you entered. |
| Your backup destination (S3, Azure Blob, GCS, WebDAV, SMB, FTP, SCP, NFS, or any HTTPS receiver you name) | Backup targets | off; local volume by default | The encrypted backup archive, to the destination you configured. The `https_put` kind sends it to a URL you type — an Artifactory or Nexus repository, a presigned S3 URL, an internal receiver — so it goes exactly where you point it and nowhere else; the URL is checked against the SSRF guard and redirects are not followed, so the archive cannot be re-sent to a third address. The `nfs` kind connects to the server and export you name, over AUTH_SYS, which is unauthenticated (see SYSTEM_ADMIN.md). |

### 3.4 Appliance host (OS-level, not the application)

The OS appliance is a Debian host, and a Debian host talks to the
network the way Debian hosts do:

| Connection | Default | Change it under |
|---|---|---|
| `pool.ntp.org` — time sync | on | The disk installer's **Time source** screen (or the `ntp_servers` preseed key) sets it at install; Appliance → Fleet → Services → NTP changes it afterwards. Point it at an internal server or a unicast peer. Leaving it blank at install means **no time source at all** ([#1002](https://github.com/spatiumnorth/spatiumddi/issues/1002)): the installer comments out Debian's own `pool` directive and the `/run/chrony-dhcp` sourcedir, and seeds the platform's server list empty so the control plane's first config push does not put the pool back. `chronyd` then runs with no sources and reports `Not synchronised`, which is what an air-gapped site with a trusted RTC is asking for. Clearing the server list under Appliance → Fleet → Services → NTP does the same thing on an appliance that is already running |
| `github.com` — SSH public keys, **only if you ask** | off | The disk installer's **SSH public key** screen: typing a bare username there fetches `https://github.com/<user>.keys`. Typing a URL fetches that URL instead, and picking "Paste" or "No key" fetches nothing. One `GET`, no request body, nothing about the install is sent |
| The control-plane URL you type — an `/api/v1/version` probe | off (Additional-node installs only) | The disk installer probes the URL you entered before it wipes the disk, so a typo is caught while it is still correctable. One `GET` to **your own** control plane |
| Your default gateway — one ICMP echo | on (pre-flight screen) | The installer's pre-flight check pings the LAN gateway to show whether it answers. LAN-local; there is deliberately no internet-reachability probe |
| Debian APT mirrors (`deb.debian.org`, `security.debian.org`) | host default | Appliance → Fleet → Services → APT sources — managed repositories, an internal mirror, or a proxy |
| `ghcr.io` — container image pulls at slot upgrade | only during an upgrade | Not needed at all if you upgrade from an uploaded slot image; the ISO already carries every image it runs |

None of this is SpatiumDDI-specific traffic and none of it carries
your DDI data.

### 3.5 DNS and DHCP servers SpatiumDDI runs

The connections above are made by the control plane or the appliance
host. The DNS and DHCP service containers otherwise reach the control
plane and the addresses you configure on them (forwarders, failover
peers, DDNS targets) — plus whatever answering your clients' queries
needs, since they are DNS servers: a recursive BIND9 group with no
forwarders resolves from the root servers, as any recursive resolver
does. The upstreams SpatiumDDI picks for you, rather than you or your
clients, are PowerDNS's. The agent renders `resolver=1.1.1.1,8.8.8.8`
into every PowerDNS server's `pdns.conf`
(`agent/dns/spatium_dns_agent/drivers/powerdns.py`). The setting #250
added on the agent side to change it was never wired to the control
plane, so **these addresses cannot be changed today**; making them
configurable is tracked in
[#1353](https://github.com/spatiumnorth/spatiumddi/issues/1353).
PowerDNS sends one kind of lookup through them:

| Connection | Feature | Default | What is sent |
|---|---|---|---|
| `1.1.1.1` (Cloudflare) and `8.8.8.8` (Google), plain DNS on port 53 | ALIAS records on a PowerDNS server group | Only on a PowerDNS group that serves an ALIAS record, when a client queries a name that has one | The **ALIAS target name** (A / AAAA queries for it), from the DNS server's own address, unencrypted. Cloudflare and Google see which names your ALIAS records point at, and when they were looked up. |

Even with no ALIAS record, the `resolver=` line is there, and PowerDNS
connects to it when it starts: on a host with **no network route** to
those addresses the shipped 5.0.7 image does not start
(`Unable to UDP connect to remote nameserver 1.1.1.1:53: Network
unreachable`). Whether it starts when a firewall drops the packets,
rather than having no route, has not been verified.

PowerDNS's own **security-status polling** (a TXT query for
`auth-<version>.security-status.secpoll.powerdns.com`, which names the
version you run) is turned off: SpatiumDDI renders an empty
`security-poll-suffix`. Builds before #1353 sent it from every
PowerDNS server at startup and periodically; the setting takes effect
the next time the PowerDNS container starts, which an upgrade does.
The optional **dnsdist front** (Docker Compose only) has the same
feature, also on by default, querying
`dnsdist-<version>.security-status.secpoll.powerdns.com` through the
container's system resolver; its entrypoint now writes an empty
`setSecurityPollSuffix("")`, which turns it off from the next restart.

To avoid the ALIAS lookups now, use BIND9 or Technitium rather than
PowerDNS, or block the two addresses at your firewall, which makes
ALIAS answers fail.

## 4. Air-gapped operation

Every feature works with all of the above blocked, with one
exception today: a PowerDNS server group, which needs a route to
`1.1.1.1` / `8.8.8.8` to start (§3.5,
[#1353](https://github.com/spatiumnorth/spatiumddi/issues/1353)). Use
BIND9 or Technitium on an air-gapped install. Apart from that, this is
not a claim about the happy path — it is non-negotiable #5 in the project's
own build rules: **DNS and DHCP service containers cache their
last-known-good config locally and keep serving when the control plane
is unreachable**, and by the same logic nothing in the control plane
requires an internet round-trip to function.

Concretely, on an air-gapped install:

* the appliance ISO ships every container image in its rootfs, so
  install and first boot need no registry;
* upgrades are an uploaded `.raw.xz` slot image, verified against its
  SHA-256 sidecar;
* the release check fails, logs a warning, and stamps
  `latest_check_error` — it does not retry in a loop or block anything.
  Turning it off removes even that;
* blocklists, OUI data and device profiling are simply features you do
  not enable.

## 5. The support bundle

`POST /system/support-bundle` (#875) produces the diagnostics archive
you would attach to a bug report. It is **generated locally and
uploaded nowhere** — the response is a download; SpatiumDDI has no
endpoint to send it to.

Because a bug report on a public repository is public, the bundle is
scrubbed in two tiers:

* **Secrets are hard-excluded in every mode**, including the
  unscrubbed one — Fernet-encrypted values, bcrypt/argon2 hashes, PEM
  blocks, JWTs, pre-shared keys and TSIG secrets, matched by field
  name *and* by value shape.
* **Identifiers are pseudonymised**, not deleted: IP addresses,
  hostnames, MAC addresses and usernames are replaced with stable
  synthetic values derived by HMAC from your install's `SECRET_KEY`.
  Topology survives (the same /24 maps to the same synthetic /24, with
  the host octet preserved) so the archive is still diagnosable, and
  the mapping is unguessable outside your install. Synthetic IPv4
  lands in `240.0.0.0/6`; the IPv6 interface identifier is discarded
  rather than mapped, because SLAAC embeds the MAC address.

The **decode map** — the only thing that can reverse the
pseudonymisation — is a separate endpoint and is **never included in
the archive**. It does not leave your install unless you deliberately
send it to someone.

## 6. The mobile app

The [SpatiumDDI mobile app](https://github.com/spatiumnorth/spatiumddi-mobile)
lives in its own repository and carries the same promise: it speaks
only to **your** control plane's REST API, at the address you enrol it
against. It has no backend of its own, no analytics SDK, and no
account. Enrolment is a QR code minted inside your authenticated
session (#906), carrying your control plane's address, an API token
you created, and the TLS certificate fingerprint the client pins.

## 7. Who can see what, inside your install

Privacy from the outside world is one half; the other half is that
SpatiumDDI is built to be delegated without handing over everything:

* group-based RBAC with per-resource grants — a department admin can
  hold one subnet or one zone (`docs/PERMISSIONS.md`);
* every mutation is written to an append-only, hash-chained audit log
  before the response returns (non-negotiable #4), so administrative
  access is recorded rather than assumed;
* credentials at rest (provider secrets, agent keys, cloud tokens) are
  Fernet-encrypted with your `CREDENTIAL_ENCRYPTION_KEY` (or a key
  derived from `SECRET_KEY` when you have not set one) and never
  returned by the API — endpoints report `*_set: true`, not the value.

## 8. Keeping this page true

A privacy statement rots the first time somebody adds a convenience
fetch. Two guards keep this one honest:

* **`backend/tests/test_outbound_hosts_documented.py`** walks
  `backend/app` and the four shipped agent packages
  (`agent/{dns,dhcp,looking-glass,supervisor}/spatium_*`) for hostname
  literals, and the agent packages for public IP addresses in string
  values, and asserts every one of them appears on this page. A new
  outbound host fails CI until it is documented here, with its default
  and its payload. Editing this file or an agent package runs that
  suite (both are declared carve-outs in
  `.github/scripts/ci-backend-must-run.txt`).
* **CLAUDE.md non-negotiable #17** — *No telemetry.* Never add an
  outbound connection that is not operator-configured and documented
  here; anything default-on needs an issue and a decision, not a PR.

The guard covers Python source under `backend/app` and the agent
packages; the agents' `tests/` directories are not shipped and are not
scanned. It looks for IP addresses in the agents only: in the backend
they are almost all example addresses in tool descriptions, and the
hardcoded PowerDNS resolvers in §3.5, which this page once missed,
are IP addresses in agent code, which a hostname scan cannot see.
Its hostname scan reads hosts out of `http://` and `https://` URLs, so
a hostname written bare (a resolver name, a `tls://` endpoint) is not
seen either. The things it cannot see, and which therefore need a
human: hostname literals in the appliance's **shell** scripts under
`appliance/mkosi.extra/usr/local/bin/` — the guard reads Python only, so
§3.4's rows were written by hand and the next `curl` added to the
installer will pass CI with nothing to catch it; the same for the
agent images' entrypoints and config files under `agent/*/images/`;
connections a bundled daemon (BIND9, PowerDNS, dnsdist, Technitium,
Kea, GoBGP) makes on its own built-in defaults, which appear in no
SpatiumDDI source at all; hosts assembled at runtime from operator
input (which is the point — those are *your* endpoints); public IP
addresses in the backend; and the feed catalogues in
`backend/app/data/`, whose entries are all opt-in downloads covered by
the blocklist row above.

If you find a connection this page does not describe, that is a bug —
please [open an issue](https://github.com/spatiumnorth/spatiumddi/issues/new).

## Appendix — hostnames in the source that are not connections

The guard in §8 matches text, so these appear in `backend/app` or an
agent package and are listed here to keep the check honest. **None of
them is contacted.**

**Documentation and homepage links** (shown in the UI or written in a
comment, never fetched): `github.com` (issue links in agent docstrings —
the installer's SSH-key fetch in §3.4 is a separate use),
`www.spatiumddi.com` (the ACME
client's User-Agent string, as RFC 8555 asks for), `fingerbank.org`,
`aistudio.google.com` (the "get an API key" link in an error message),
`bacnet.org`, `kea.readthedocs.io`, `schema.org` (a JSON-LD `@context`
identifier in a Teams-format webhook payload — a namespace URI, not a
URL that is dereferenced), `www.opengis.net` (the GML namespace in the
E911 PIDF-LO renderer — likewise an XML namespace identifier, written
into the document we *emit* and never fetched; the accompanying
`urn:ogc:def:crs:EPSG::4326` CRS reference is a URN precisely because it
names a coordinate system rather than locating a resource), and the DNSBL
catalogue's homepage fields:
`www.spamhaus.org`, `www.spamcop.net`, `www.barracudacentral.org`,
`www.uceprotect.net`, `www.sorbs.net`, `psbl.org`.

**Placeholders in examples, defaults and error messages** — these are
where *you* type your own address: `app.example.com`,
`ddi.example.com`, `dns.example.com`, `ipam.example.com`,
`netbox.example.com`, `nc.example.com`, `nextcloud.example`,
`nexus.example` (the example receiver URL on the `https_put` backup
destination's form — an address you replace with your own Artifactory,
Nexus or internal receiver), `my-resource.openai.azure.com`,
`pdns.internal`, `tdns.internal`,
`api.meraki.cn` (named in a docstring as the regional shard a
China-based operator would enter).

**In-cluster addresses**, which never leave the node:
`spatium-control-spatiumddi-api.spatium.svc.cluster.local` — the
Kubernetes service name an appliance supervisor uses to reach the
control plane it is already part of.

---

*Questions about anything on this page are welcome as a GitHub issue or
discussion. If a future release adds an outbound connection, it will be
in the table above and in the CHANGELOG before it is in your install.*
