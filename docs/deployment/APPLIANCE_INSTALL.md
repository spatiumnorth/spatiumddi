---
title: Install the OS Appliance
description: Step-by-step install of the SpatiumDDI OS appliance — get the ISO, walk the installer, first boot, first login, and add DNS / DHCP nodes.
---

# Install the OS Appliance

The appliance is the quickest way to a working SpatiumDDI: boot one ISO,
answer the installer's questions, and the full stack is serving on HTTPS a
few minutes after the reboot. It is a self-contained Debian 13 image with
[k3s](https://k3s.io/) embedded, so the same containers that ship as a Helm
chart run here as pods — but you never have to touch Kubernetes. The
installer, the **Appliance** section of the web UI and the console cockpit
hide it completely; there is no `kubectl` or `docker` to learn.

This page is the walkthrough. The design — why k3s, the A/B slot layout,
the fleet firewall, control-plane HA internals — lives in
[APPLIANCE.md](APPLIANCE.md). Prefer containers you manage yourself? See
[Docker Compose](DOCKER.md) or [Kubernetes](KUBERNETES.md) instead.

> **Beta.** The appliance is stable enough for labs, homelabs and pilots in
> front of non-critical client populations. Pin to a tested release for
> anything business-critical, and snapshot the VM before an OS upgrade.

---

## Before you begin

**A machine to install onto** — a VM under Proxmox, VMware, Hyper-V, QEMU or
UTM, or a bare-metal box. Size it for the role you will pick in the wizard:

| Role | vCPU | RAM | Disk |
|---|---|---|---|
| **First node** (control plane: api, web UI, worker, PostgreSQL, Redis, k3s) | 4 | 8 GiB | 40 GiB SSD |
| **Additional node** (DNS / DHCP agent, promotable to the control plane later) | 2 | 4 GiB | 32 GiB SSD |

Size a node you mean to promote into the control plane like the first node.
Measured figures, the minimums, and the 48 GiB disk advice for a three-node
control plane are in [`SIZING.md`](SIZING.md).

The installer **refuses any disk under 32 GiB** — the A/B upgrade layout
needs two 8 GiB OS slots plus a `/var` that holds the image store, the
database and the logs. Below the recommended figures on a first node it
warns and lets you continue. SSD is strongly preferred; etcd and PostgreSQL
both live on the write path.

**Firmware.** The x86-64 image boots under BIOS or UEFI. The arm64 image is
UEFI-only, because AArch64 has no legacy boot path — the installer refuses
on a non-EFI arm64 machine rather than completing an install that could
never boot.

**Network.** DHCP is fine for an evaluation; for anything longer-lived have
a static address, prefix, gateway and resolver ready. If this node will
*serve* DHCP, its clients reach it by broadcast, so it needs a leg on their
layer-2 segment or an IP helper / relay on the router.

**A console.** The hypervisor console or a serial line — an 80×24 serial
console is a first-class install path. **Nothing is downloaded** during the
install or the first boot: the container images are baked into the ISO, so
an air-gapped install works. The one thing the appliance does want is a
reachable time source; a clock nothing corrects breaks TLS and pairing.

---

## 1. Get the ISO

Download the image for your architecture from the
[latest release](https://github.com/spatiumnorth/spatiumddi/releases/latest):

| Architecture | Asset | Firmware |
|---|---|---|
| x86-64 (Intel / AMD) | `spatiumddi-appliance-<version>-amd64.iso` | BIOS or UEFI |
| arm64 (Apple Silicon, Graviton, Ampere) | `spatiumddi-appliance-<version>-arm64.iso` | UEFI only |

Both are also published under un-versioned names that always point at the
current release:

```
https://github.com/spatiumnorth/spatiumddi/releases/latest/download/spatiumddi-appliance-amd64.iso
https://github.com/spatiumnorth/spatiumddi/releases/latest/download/spatiumddi-appliance-arm64.iso
```

Every night that `main` moves, a `nightly-YYYY.MM.DD` pre-release ships the
same artifacts, kept for seven days — useful for trying a fix before it is
tagged, never for production. To build the ISO yourself, `make
appliance-dev-iso` produces one in `appliance/build/`; see
[APPLIANCE.md](APPLIANCE.md#3-appliance-build-process) for prerequisites.

---

## 2. Run the installer

Attach the ISO as a CD-ROM in the hypervisor, or write it to a USB stick
with `dd` for bare metal, and boot from it. The wizard runs on the console.
Every screen has a **Back** button, and the final **Confirm** screen is a
menu of every answer, so a typo on screen three is fixed from the end rather
than by walking back through the wizard.

The screens, in order:

1. **Welcome** — lists what you will be asked. *Cancel* drops to a shell.
2. **Pre-flight** — everything the installer can learn before asking you
   anything: CPU and RAM, firmware mode, disks, which NICs have a link, the
   gateway and resolver, and whether the clock is sane. Informational only;
   the one hard gate in the wizard is the disk floor.
3. **Keyboard layout** — applied immediately, before the password screens,
   so the symbols in a good password land where you expect them.
4. **What is this node?** — the decision that shapes the rest:
   - **First node** creates a *new* SpatiumDDI: the control plane and the
     k3s seed. Pick this for a homelab, a single box, or the seed of a
     brand-new HA cluster. It asks you to confirm, because a second "first
     node" is a second, separate SpatiumDDI — not a cluster member.
   - **Additional node** (the default) joins an *existing* install. It runs
     DNS and DHCP roles an admin assigns from the Fleet UI, and can later
     be promoted into the control-plane cluster — this is how you add
     control-plane nodes for HA, never by installing "First node" again.
     It asks two more questions: the **control plane URL**, which the
     installer probes before the disk is touched (a typo landing on some
     other web server is caught here, not after the reboot), and an 8-digit
     **pairing code** from **Appliance → Fleet → Pairing codes** on the
     control plane. If the control plane is, or will become, an HA cluster,
     give the **control-plane VIP**, not a single node's address.
5. **Target disk** — pick from the disks that clear the 32 GiB floor. Each
   path of a multipath SAN LUN is refused rather than offered as a separate
   disk. With two disks of similar size you can **mirror the OS** (RAID1)
   across both. If the disk already holds a SpatiumDDI install, the
   installer offers a **reinstall** that keeps `/var` — the database, images
   and logs — and replaces only the OS slots.
6. **Confirm partition layout** — the exact GPT layout it is about to
   write, behind a checkbox. This is the last screen before the wipe that
   does not have *Install* as an option.
7. **Hostname.**
8. **Admin OS user + password** — your SSH account, with `sudo`. At least
   eight characters, not the username or hostname; anything weaker than
   that advises rather than refuses. The root account is **locked** unless
   you tick the box to keep it; `sudo -i` still works either way.
9. **SSH public key** — optional. Paste one, fetch from a URL, or give a
   bare GitHub username (fetched from `github.com/<user>.keys`, and only
   because you asked). With a key in place you can turn password SSH off.
10. **Network** — DHCP, or a static IPv4 address with optional static IPv6
    (a link-local gateway is accepted; that is how routers advertise
    themselves). On a multi-NIC box the interface picker shows which port
    has a cable in it and pins the one you choose.
11. **Timezone.**
12. **Time source** — NTP servers, pre-filled from what the DHCP lease
    offered. On a network with no route to the public pool, put your own
    server here. Leaving it blank means *no* time source at all — the
    Debian default pool is disabled too, not silently kept.
13. **k3s networking** *(first node only)* — the pod and service ranges,
    `10.42.0.0/16` and `10.43.0.0/16` by default. Press Enter through both
    unless your LAN already uses one of those ranges; the installer checks
    for an overlap with the address it just configured. These cannot be
    changed later without a reinstall.
14. **Review and Confirm** — every answer on one screen, then a menu of
    fields with *Install* deliberately last. Pick a field to change it, or
    *Install* to begin.

The install itself takes a few minutes with a progress bar. The **Done**
screen then shows where the web UI will be and asks you to **remove the
install media before the reboot** — an eject is sent, but a VM with the ISO
still attached boots straight back into the installer.

---

## 3. First boot

First boot takes **2–5 minutes**: it generates secrets, mints a self-signed
certificate, starts k3s and imports the baked container images. The console
shows the cockpit — a status ribbon, live vitals, pod health and the web UI
address — and until the API is serving, the web UI answers every page with
an auto-refreshing *"SpatiumDDI is initialising"* screen rather than errors.

An **additional node** has no web UI of its own. It registers with the
control plane on first boot and waits as *pending* until an admin approves
it; its console shows a **Pairing** row that goes green once registered.

---

## 4. Sign in

Browse to `https://<appliance-ip>/` — `:80` redirects. Accept the
self-signed certificate once; it is the same one the installer minted, and
it does not change under you mid-boot. Sign in as `admin` / `admin` and set
a real password when prompted.

Two things worth doing straight away:

- **Replace the certificate** under **Appliance → Fleet → Web UI Certificate** —
  paste a PEM and key, generate a CSR on the server, or issue one from
  Let's Encrypt with the built-in ACME client. The web tier reloads on its
  own.
- **Set the external URL** and the other platform settings — step 1 of
  [Getting Started](../GETTING_STARTED.md#1-platform-settings-first-login),
  which then walks the setup order: server groups → zones and scopes →
  subnets → addresses.

On a single box, DNS and DHCP are **off** after install. Turn them on for
this node from **Appliance → Fleet**: open the node, pick a DNS engine
(`dns-bind9` / `dns-powerdns` / `dns-technitium` — one per node) and / or
`dhcp`, and the role pod is running in about 30 seconds.

---

## 5. Add DNS / DHCP nodes

For a distributed layout — control plane in one place, DNS and DHCP where
the clients are — install **Additional node** on each service box:

1. On the control plane, open **Appliance → Fleet → Pairing codes** and
   create a code. A single-use code expires in 15 minutes by default; a
   persistent code can be claimed several times, for fleet installs.
2. In the installer on the new box, pick **Additional node** and enter the
   control plane URL and the code.
3. After its first boot the node appears in **Appliance → Fleet** as
   *pending*. **Approve** it — this signs the node's certificate — then
   assign its roles and server groups. The pod schedules within ~30 s.

The agents cache their last-known-good configuration on disk and keep
serving if the control plane is unreachable, so a control-plane restart is
not a DNS or DHCP outage.

---

## 6. Grow to a high-availability control plane

A single first node is a one-node control plane. To survive a node loss,
install more **Additional nodes**, then promote them from **Appliance →
Fleet → Manage control plane cluster…**. Membership grows 1 → 3 → 5 → 7 —
embedded etcd wants an odd count, and the API refuses a batch that would
land on an even one. Promotion is hands-off: PostgreSQL grows to a primary
with streaming replicas, Redis switches to Sentinel, and the api, worker and
web tier spread one replica per node. Give the cluster one stable address by
setting a MetalLB pool and a **control-plane VIP** under **Appliance →
Network & Host**, and point every agent at that VIP.

See [APPLIANCE.md](APPLIANCE.md#control-plane-high-availability-272) for how
a promotion settles and [TOPOLOGIES.md](TOPOLOGIES.md) for the reference
layouts.

---

## Upgrades

Every appliance has two identical OS slots. An upgrade writes the new image
into the inactive slot, and the node then boots it and reverts automatically
if the health check fails — the worst case is one wasted reboot. Scheduling
it per node from **Appliance → Fleet** only stages the image: the node keeps
running the old slot until you press **Reboot to boot new slot**.
**Rolling Upgrade** reboots each node itself, one node at a time. Air-gapped
sites mirror the slot image from **Upgrade images** instead of fetching it
from GitHub.

---

## If something goes wrong

- **It booted back into the installer.** The install media is still
  attached. Detach it (Proxmox: *Hardware → CD/DVD → Do not use*) and
  reboot.
- **The web UI never appears.** Give it five minutes on the first boot.
  Then, on the console, `F3` lists the pods; or SSH in as the admin user
  and run `kubectl get pods -A` — `kubectl` is on the PATH. The first-boot
  log is `journalctl -u spatiumddi-firstboot`.
- **The install failed.** The installer's logs survive the reboot at
  `/var/log/spatiumddi/install/`, and the answers you gave are at
  `/var/lib/spatium-state/spatium-preseed.yaml` (secrets omitted) — that
  file is a valid starting point for an unattended reinstall.
- **Something else.** [Troubleshooting](../TROUBLESHOOTING.md) has the
  recovery recipes, and **Admin → Support bundle** produces a scrubbed
  diagnostics archive for a bug report.

---

## Unattended installs

The wizard's answers can be supplied as a YAML answer file — on the kernel
command line as a URL, on the ISO, or as a cloud-init `CIDATA` volume — and
the installer runs without a console. `spatium-install --check-preseed
<file>` lints an answer file on any machine before you commit a box to it.
See [APPLIANCE.md](APPLIANCE.md#4-appliance-first-boot-setup).

---

## Where to go next

- [Getting Started](../GETTING_STARTED.md) — the setup order, with a worked
  example.
- [APPLIANCE.md](APPLIANCE.md) — the design: k3s, slots, firewall, HA.
- [TOPOLOGIES.md](TOPOLOGIES.md) — six reference layouts with sizing notes.
- [PRIVACY.md](../PRIVACY.md) — every outbound connection the appliance can
  make, and how to turn each off.
