---
layout: default
title: Air-Gapped Install
---

# Air-gapped install

This page is for sites where the SpatiumDDI hosts have no route to the
internet. It collects what to do on each deployment path (Docker Compose, the
OS appliance, Kubernetes), which defaults reach out and how to turn them off,
and what an isolated install still shows.

SpatiumDDI has no telemetry and nothing in the control plane needs an
internet round-trip to work. [`PRIVACY.md`](../PRIVACY.md) lists every
outbound connection the software can make and
[its air-gapped section](../PRIVACY.md#4-air-gapped-operation) states the
guarantee. This page is the how-to.

## 1. Pick your path

| Path | What crosses the gap | Section |
|---|---|---|
| OS appliance | The ISO, then an uploaded slot image per upgrade | [2](#2-the-os-appliance) |
| Docker Compose | One `docker save` tar of the images | [3](#3-docker-compose-carrying-the-images-in) |
| Kubernetes | The chart's images, mirrored to an internal registry | [4](#4-kubernetes-an-internal-registry-mirror) |

Sections [5](#5-turn-off-or-replace-what-reaches-out) and
[6](#6-dns-recursion-and-forwarders) apply to all three.

## 2. The OS appliance

The ISO carries every container image the appliance runs, and k3s imports
them from the local disk at start. Nothing is pulled from a registry at
install or at boot.

- **Network.** Give the appliance's network a router (default route) address,
  even if that router forwards nothing. Today k3s refuses to start on a host
  with no default route, so on a network with no gateway the first boot never
  finishes and there is no web UI. DHCP that supplies a router, or a static
  address with a gateway, is enough. This is being fixed in 1.0.2 ([#4801](https://github.com/spatiumnorth/spatiumddi/issues/4801)); until
  you are on that release, use the workaround.
- **Time source.** The installer's **Time source** screen defaults to a public
  pool. Leave it blank for "no sources", or enter an internal NTP server (see
  [`APPLIANCE.md`](APPLIANCE.md)). After install, the fleet-wide chrony
  config is under **Appliance → Fleet → Services → NTP**. With no reachable
  source the node stays unsynchronised and the clock runs from the hardware
  clock, so set it correctly in the hypervisor or firmware.
- **APT.** The appliance's OS security updates come from Debian's mirrors by
  default, which an isolated host cannot reach. Under **Appliance → Fleet →
  Services → APT** you can point the fleet at an internal mirror, set an HTTP
  or HTTPS proxy, and add GPG keys. If you have neither, the daily unattended
  upgrades simply find nothing; they do not fail, and nothing tells you the
  updates are not arriving.
- **Upgrades.** Use an uploaded slot image: download the `.raw.xz` and its
  SHA-256 sidecar on a connected machine, carry them in, and use **Upload
  image...** under **Appliance → Fleet → Upgrade images**. The upload is
  verified against the sha256. See "Appliance Update Mechanism" in
  [`APPLIANCE.md`](APPLIANCE.md).
- **Web UI.** The UI and the `/api/docs` and `/api/redoc` pages load no
  external scripts or fonts; the one failed request is the ReDoc logo image
  ([`PRIVACY.md`](../PRIVACY.md)).

## 3. Docker Compose: carrying the images in

The image set depends on `COMPOSE_PROFILES` (the DNS, DHCP and
Looking Glass services are profile-gated in `docker-compose.yml`), so use the
same profiles on the connected host as on the target.

On a connected host with the same `docker-compose.yml` and `.env`:

```bash
export COMPOSE_PROFILES=dns,dhcp          # same value as the target's .env
docker compose pull
docker save $(docker compose config --images | sort -u) -o spatiumddi-images.tar
```

Move `spatiumddi-images.tar`, `docker-compose.yml` and `.env` to the isolated
host (set `SPATIUMDDI_VERSION` in `.env` to a release tag so both hosts
agree on it), then:

```bash
docker load -i spatiumddi-images.tar
docker compose run --rm migrate           # see DOCKER.md, "First-Time Setup"
docker compose up -d --pull never
```

`--pull never` makes a missing image an error instead of a registry
lookup. The first-time-setup steps are in [`DOCKER.md`](DOCKER.md); only
`docker compose pull` is replaced by the load.

To upgrade, repeat the pull, save and load on a new tag, then run the
migration and `up -d --pull never` again. Pass the same profiles to every
command or the profile's containers keep running the old image
([`DOCKER.md`](DOCKER.md#8-upgrading)).

## 4. Kubernetes: an internal registry mirror

Copy every image below to your registry, then point the chart at it. The
chart renders control-plane images as
`<image.registry>/<image.repository>/<name>:<tag>` (release 1.0.1 and later
append `image.tagSuffix`, empty by default), and the others from their own
`repository` and `tag`.

| What | Value to set | Default |
|---|---|---|
| API, worker, beat, migrate Job, init containers, slot-image mirror (`spatiumddi-api`) and frontend (`spatiumddi-frontend`) | `image.registry`, `image.repository`, `image.tag` | `ghcr.io`, `spatiumnorth`, chart `appVersion` |
| Pull credentials for the above | `image.pullSecrets` | `[]` |
| In-chart PostgreSQL | `postgresql.image.repository`, `postgresql.image.tag` | `postgres`, `16-alpine` |
| CloudNativePG pods (when `postgresql.kind` is `cnpg`) | `postgresql.cnpg.imageName` | `ghcr.io/cloudnative-pg/postgresql:16` |
| In-chart Redis, and Sentinel when used | `redis.image.repository`, `redis.image.tag` | `redis`, `8.10.2-alpine` |
| BIND9 agent (`dnsAgents.enabled`) | `dnsAgents.image.repository`, `dnsAgents.image.tag` | `ghcr.io/spatiumnorth/dns-bind9` |
| PowerDNS and Technitium agents | `dnsAgents.flavors.powerdns.repository` and `.tag`; `dnsAgents.flavors.technitium.repository` and `.tag` | `ghcr.io/spatiumnorth/dns-powerdns`, `.../dns-technitium` |
| Kea agent (`dhcpAgents.enabled`) | `dhcpAgents.image.repository`, `dhcpAgents.image.tag` | `ghcr.io/spatiumnorth/dhcp-kea` |

The agent `repository` values are full paths including the registry host, so
they do not follow `image.registry`; set each one. An empty agent `tag`
uses the chart's `appVersion`. Mirror the same tag for every SpatiumDDI image,
since they release together.

Two things sit outside the chart: the CloudNativePG operator, when you use
`postgresql.kind: cnpg`, is installed separately and its images need
mirroring too; and `externalDatabase` / `externalRedis` replace the in-chart
Postgres and Redis if you already run them inside the site.

**OpenShift and the UBI images (release 1.0.1 and later).** `values-openshift-certified.yaml` sets
`global.platform: openshift`, `image.tagSuffix: "-ubi"` (the Red Hat UBI build
of `spatiumddi-api`, `spatiumddi-frontend`, `dns-bind9` and `dhcp-kea`), and
points `postgresql.image` and `redis.image` at `registry.redhat.io` with
`flavor: rhel`. To mirror, copy those `-ubi` tags and the two Red Hat images
to your registry, and override `image.registry`, `image.repository`, the
agent `repository` values and the `postgresql.image` / `redis.image`
repositories in a values file layered after it. Keep `image.tagSuffix` and
each `flavor`, because they change how the pods run, not just where the
image comes from. See [`KUBERNETES.md`](KUBERNETES.md) for the install.

Chart upgrades: mirror the new tag first, then `helm upgrade`.
Upgrades of the appliance's own chart go through the slot image (section 2).

## 5. Turn off or replace what reaches out

Only one connection is on by default. The rest are off until you enable them.

| Feature | Default | What to do |
|---|---|---|
| Daily GitHub release check | **On** | Turn it off under **Settings → Application → Updates → Check for GitHub Releases** (the `github_release_check_enabled` setting, superadmin). Left on, it fails once a day, shows an amber "check failed" chip in the sidebar and a banner on the Updates page, and does nothing else. |
| Rolling Upgrade release list (appliance) | Reads GitHub | Shows "No releases found" with a rate-limit hint when GitHub is unreachable. That is the offline state; use **Upload image...** instead. The Upgrade images table says so plainly. |
| MAC vendor list (OUI) | Off | Leave **Settings → IPAM → OUI Vendor Lookup** off. If you turn it on, the download from the IEEE fails and the vendor count stays 0; the worker logs a warning about hourly. There is no way to load the list by hand today. |
| TLD registry | Bundled copy | The IANA root-zone list ships with each release and is used as is. **Settings → DNS → TLD Registry → Refresh now** fails with a message that nothing was stored and the previous list is still in effect. It never refreshes on a schedule. |
| DNS blocklist feeds | None subscribed | Do not subscribe URL feeds from the catalog; each fetches from the internet. Host a feed on an internal web server and subscribe to that URL instead. |
| Operator Copilot | No provider | Add only providers you can reach: an on-prem Ollama or vLLM server through an OpenAI-compatible provider on the AI Providers page (`/admin/ai/providers`). Cloud providers call off-site. |
| Integration mirrors, cloud connectors, ACME, Looking Glass peers | Off | Enable only those whose target is reachable from the site. |

Everything else outbound is listed in [`PRIVACY.md`](../PRIVACY.md) with its
default; check it before you enable a feature.

## 6. DNS: recursion and forwarders

A DNS server group recurses by default, and from an isolated network the root
servers are unreachable. A recursive query for an outside name then returns
`SERVFAIL` after about 10 seconds; a client with a short timeout reports it
as "no servers could be reached". Names the group is authoritative for are
not affected. Pick one:

- **Forwarders to an internal resolver.** In DNS, open the server group,
  **Options** tab, **Forwarders**, turn it on and list your resolver
  addresses. Set the forward policy to "only" so a failure does not fall back to
  the root servers.
- **No recursion, for an authoritative-only group.** Edit the server group and
  clear **Allow recursion**.

## 7. What to expect on an isolated install

A fresh isolated install works end to end: login, IPAM, DNS zones and records,
DHCP scopes, the Fleet and Cluster pages, and support and diagnostics bundles.
The messages below are normal offline. Some read as faults; 1.0.2 work
([#4799](https://github.com/spatiumnorth/spatiumddi/issues/4799),
[#4800](https://github.com/spatiumnorth/spatiumddi/issues/4800),
[#4801](https://github.com/spatiumnorth/spatiumddi/issues/4801)) covers part
of that, so treat them as known rather than as breakage.

- **Update check failed** chip and banner, until the check is turned off.
  This is being addressed in 1.0.2
  ([#4799](https://github.com/spatiumnorth/spatiumddi/issues/4799),
  [#4800](https://github.com/spatiumnorth/spatiumddi/issues/4800)); turning
  the check off removes the message today.
- **No default route** on the appliance: covered in section 2. Being fixed in 1.0.2
  ([#4801](https://github.com/spatiumnorth/spatiumddi/issues/4801)); until
  then give the network a router address.
- **Appliance self-test** (Logs & Diagnostics) reports a DNS resolution
  failure for a public registry name while the other checks pass. It is a
  public-name lookup, not a sign the host is unhealthy.
- **Time not synchronised.** With no reachable time source the node reports
  NTP as unsynchronised in the fleet data, and Debian's `chrony-wait` unit
  times out after three minutes at each boot and shows as failed in
  `systemctl --failed`. Nothing observed depends on it.
- **TLD Refresh** and **OUI refresh** failures, as in section 5.
- **Rolling Upgrade releases** empty, as in section 5.
- **Recursive DNS** `SERVFAIL`, as in section 6.

Anything not listed here and not on a feature you enabled is worth a bug
report.
