# Headless / unattended install — SpatiumDDI appliance preseed

Issue #549. This directory holds the **answer-file preseed** that drives
the appliance's disk installer (`spatium-install`) non-interactively, so
a box can install to disk with **no console operator** — for fleet
rollouts, IPMI/PXE provisioning, cloud images, and CI boot-tests.

> **What changed (post-#183).** The install flow is the interactive
> **whiptail** installer `spatium-install` that partitions a disk
> (A/B slot layout) and installs SpatiumDDI onto it. The *old*
> `user-data.example` / `meta-data.example` in this directory only
> configured an already-running docker-compose all-in-one (the
> superseded pre-#183 flow) — it did **not** drive the disk installer.
> The `spatium-preseed-*.yaml.example` files here are the current path.

## How it works

On boot of the **installer media** (`spatium-mode=install` in the
kernel cmdline), `spatium-install` looks for a preseed answer file
*before* launching the whiptail wizard. If it finds one:

- Every field present in the answer file **skips** its interactive
  prompt.
- A **fully** preseeded run (disk + `confirm_wipe: true` + all fields)
  runs end-to-end with **zero** console interaction — no welcome, no
  confirm.
- A **partial** preseed falls through to the interactive prompt for
  **only the missing fields** (e.g. preseed everything-but-the-disk and
  let an operator pick the target).
- A field that is **present but invalid** (bad hostname, overlapping
  k3s CIDRs, malformed pairing code, …) **halts loudly** with a non-zero
  exit and a clear console message — it never silently picks a default
  on a disk wipe.

The installed system is identical to an interactively-installed one:
the preseed only replaces the wizard's question-and-answer step, then
hands the same values to the same `do_install`. A fully-preseeded box
presents no setup wizard afterwards (console or web).

## Answer-file schema

See the annotated examples:

- [`spatium-preseed-control-plane.yaml.example`](spatium-preseed-control-plane.yaml.example)
  — first node (api + db + web UI + k3s seed).
- [`spatium-preseed-appliance.yaml.example`](spatium-preseed-appliance.yaml.example)
  — additional node (supervisor pairs with an existing control plane).

Every field is optional; anything omitted falls through to interactive.
Summary:

| Field | Notes |
|---|---|
| `role` | `control-plane` (aka `first-node`) or `appliance` (aka `add-node` / `application`) |
| `confirm_wipe` | **Must be `true`** to auto-wipe a disk unattended |
| `target_disk` | Prefer `/dev/disk/by-id/…` or `by-path/…` (stable). Absent / unresolvable ⇒ interactive picker |
| `hostname` | RFC 1123 (alnum + hyphen, ≤ 63); the short name, no dots |
| `domain` | optional DNS domain (#4550), e.g. `corp.example.com`. Labels of letters, digits and hyphens; `hostname.domain` at most 253 characters. Written to `/etc/hosts` as the FQDN (`hostname -f` prints it) and added to the self-signed Web UI certificate's SANs |
| `dns_search` | optional resolver search domains, string or list, at most 6 and 256 characters in all (#4550). Written to `dns-search=` in the NetworkManager keyfile. Defaults to `domain` |
| `admin_user` | default `admin`. Must match `[a-z_][a-z0-9_-]*$?`, ≤ 32 chars, and not be an existing system account (`root`, `www-data`, …) |
| `admin_password` **or** `admin_password_hash` | plaintext, or a crypt(3) hash from `openssl passwd -6`. Plaintext is checked against the same floor the wizard applies (≥ 8 chars, not the username or hostname); a weak-but-allowed one becomes a `WARN` from `--check-preseed`. A hash cannot be checked — that is the point of a hash — so its strength is yours to own |
| `set_root_password` | default **`false`** — root is locked (`passwd -l`) and you use `sudo`. Set `true` for the pre-#995 behaviour, where root got the same password. sshd refuses root either way, so this only affects the physical / IPMI console |
| `timezone` | IANA name, default `UTC`. Must be a real compiled zone file — a traversal, a directory (`America`) and a non-zone file (`leapseconds`) are all refused |
| `ntp_servers` | string or list, default `pool.ntp.org`. Written to `/etc/chrony/sources.d/spatium-install.sources`; **empty means no time source** (#1002) — the installer additionally comments out Debian's own `pool` directive and the `/run/chrony-dhcp` sourcedir in `chrony.conf`, and seeds `platform_settings.ntp_pool_servers` empty so the control plane does not push a pool back on first boot. `chronyd` runs with no sources; `chronyc tracking` reports `Not synchronised`. Superseded and removed if the control plane later manages NTP (#154) |
| `keymap` | XKB layout code compiled by `ckbcomp` (`localectl list-x11-keymap-layouts`), default `us` — the image ships no console keymaps at all. A few console-style aliases are mapped for you (`uk`→`gb`, `br-abnt2`→`br`+`abnt2`, `jp106`, `dvorak`, `us-acentos`). Written as an XKB block to `/etc/default/keyboard`; `/etc/vconsole.conf` is a symlink to that file on this image, so it is written once, not twice. Shape-checked here; a layout `ckbcomp` cannot compile is caught on the live system, which is the only place that can know |
| `ssh_authorized_keys` | string or list of OpenSSH public keys for the admin account. Shape-checked here, `ssh-keygen`-checked interactively. A **bootstrap**, not a permanent grant: once the control plane manages SSH keys (#157), its list replaces this file |
| `ssh_disable_password` | default `false`. **Refused** (not warned) when no `ssh_authorized_keys` is set — an unattended install that turns off password SSH with no key produces a headless box nobody can reach |
| `network.mode` | `dhcp`, or `static` with `interface` + `ip` + `prefix` + `gateway` all required (optional `dns`) |
| `network.interface` | required for `static`; **optional for `dhcp`**, where it pins the lease to ONE port. Absent keeps the old behaviour — NetworkManager DHCPs every ethernet interface and the appliance answers on whichever replied first, which on a multi-NIC server is a coin toss |
| `network.ip6` / `network.prefix6` / `network.gateway6` | optional static IPv6 alongside the v4 address (`static` mode only). Default is RA / SLAAC. `prefix6` defaults to 64; a **link-local** `gateway6` (`fe80::…`) is normal and accepted, a global one must be inside the prefix. `prefix6` / `gateway6` without `ip6` is refused |
| `k3s.pod_cidr` / `k3s.service_cidr` | default `10.42.0.0/16` / `10.43.0.0/16`; validated ≤ /22, disjoint, no LAN overlap. **Ignored for `role: appliance`** (with a `WARN`): k3s compares these against the datastore when a node joins, a mismatch is fatal, and nothing removes the drop-in — so pinning them on an Additional node makes its later promotion impossible |
| `control_plane_url` | **required for `role: appliance`** — the control plane URL (VIP for HA) |
| `pairing_code` | **required for `role: appliance`** — 8-digit code from Appliance → Pairing |

### Secrets

`admin_password` and `pairing_code` in a plaintext answer file are the
usual preseed tradeoff. To keep the admin cleartext out of the file, use
`admin_password_hash` with a crypt(3) hash:

```sh
openssl passwd -6                       # prompts, prints $6$… SHA-512 hash
# or: mkpasswd --method=sha-512
```

The pairing code is single-use / short-TTL by default (mint a fresh one
per install). Neither secret is echoed to the console dashboard or logs,
and both are read from a mode-`0600` file during install.

## Delivery transports

The same answer file is consumed regardless of how it arrives. Sources,
first match wins:

1. **Kernel cmdline** — `spatium.preseed=<url|path>` (best for PXE /
   IPMI). A `http(s)://` value is fetched with curl; anything else is a
   path on the installer rootfs. **A plain `http://` URL is refused
   unless it is pinned with `spatium.preseed.sha256=<64-hex>`** — see
   [URL integrity](#url-integrity-http-and-sha256-pinning) below.
2. **NoCloud CIDATA volume** — a disk labelled `CIDATA` carrying
   `spatium-preseed.yaml` (or `.yml`, or a cloud-init `user-data`
   document with an embedded `spatium_preseed:` block). Best for VM /
   Proxmox.
3. **Install medium / rootfs** — `spatium-preseed.yaml` at
   `/run/live/medium/`, `/`, or `/etc/` on the installer image (best for
   sneakernet or a purpose-built ISO).

### Build a NoCloud CIDATA ISO

```sh
cd appliance/cloud-init
cp spatium-preseed-control-plane.yaml.example spatium-preseed.yaml
$EDITOR spatium-preseed.yaml            # set disk by-id, hostname, password
touch meta-data                          # NoCloud requires the file to exist
genisoimage -output cidata.iso -volid CIDATA -joliet -rock \
    spatium-preseed.yaml meta-data
```

`genisoimage` is in `cdrkit` (Debian/Ubuntu) or `cdrtools` (Alpine).
macOS: `hdiutil makehybrid -o cidata.iso -hfs -joliet -iso -default-volume-name CIDATA <dir>`.

Attach `cidata.iso` as a **second** CD/DVD/disk alongside the installer
ISO:

| Hypervisor | Recipe |
|---|---|
| **Proxmox** | Upload `cidata.iso` → VM hardware → Add → CD/DVD Drive → ISO image |
| **libvirt / virt-manager** | Add hardware → Storage → CDROM → `cidata.iso` |
| **QEMU CLI** | `-drive file=cidata.iso,if=virtio,format=raw,readonly=on` |
| **VMware ESXi** | Datastore browser → upload → VM Edit → CD/DVD → Datastore ISO |

### PXE / IPMI

Append to the installer boot cmdline (alongside `spatium-mode=install`):

```
spatium.preseed=https://provision.example.net/spatium/ddi-control-1.yaml
```

#### URL integrity (http and sha256 pinning)

The cmdline URL is the only transport that arrives over the network
from a party the installer cannot authenticate, and the answer file it
delivers authorises an unattended disk wipe and carries the admin
password (plus the pairing code on `role: appliance`). So a plain
`http://` URL with **no** integrity pin is refused before the fetch,
with a message naming both remedies:

```
# Option A — TLS authenticates the origin (preferred)
spatium.preseed=https://provision.example.net/spatium/ddi-control-1.yaml

# Option B — content-pinned, so the transport need not be trusted.
# For air-gapped / internal-CA PXE where https isn't practical.
spatium.preseed=http://pxe.internal/spatium/ddi-control-1.yaml
spatium.preseed.sha256=9f2c...64-hex-digest
```

Get the digest with `sha256sum spatium-preseed.yaml`. The pin is
verified whenever it is supplied (https or not); a mismatch halts the
install rather than acting on content that may have been modified in
transit, and a pin that cannot be checked fails closed. The `CIDATA`
and install-medium transports are physically attached and are not
subject to this gate.

Serve a per-host answer file from any HTTP server. This pairs well with
the console-redirect cmdline the appliance already sets
(`console=ttyS0,115200n8`), so an IPMI serial console shows the install
progress with no keyboard input.

## Cloud images (Azure / AWS) via cloud-init user-data

Public clouds hand your instance a **cloud-init user-data** document at
first boot. Because the installer reads a top-level `spatium_preseed:`
key directly (and cloud-init ignores that unknown key), you can put the
preseed **inside** the user-data document. The SpatiumDDI appliance
image ships with the NoCloud datasource; on Azure/AWS the platform
datasource presents user-data to the same on-disk path the installer's
CIDATA search covers.

> Cloud marketplace images are a **Phase 5** deliverable. Today this
> path is for operators building their own cloud image from the
> appliance raw disk (`make appliance-*`) and importing it (Azure
> Managed Image / AWS EBS snapshot + AMI). The user-data shape below is
> what those images consume once the platform datasource is wired.

### AWS EC2

`target_disk` should be the stable NVMe/Xen id the instance exposes
(e.g. `/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_vol…`). Pass the
document as the instance **User data** (console → Advanced details →
User data, or `--user-data file://user-data.yaml`):

```yaml
#cloud-config
# Optional cloud-init directives (SSH keys, etc.) can live here too;
# cloud-init ignores the spatium_preseed block below and the installer
# reads it directly.
spatium_preseed:
  role: control-plane
  confirm_wipe: true
  # AWS EBS root device — use the by-id path, not /dev/xvda / /dev/nvme0n1
  # which can renumber. `ls -l /dev/disk/by-id` on a running instance
  # shows the stable name.
  target_disk: /dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_vol0abc123
  hostname: ddi-control-1
  admin_user: admin
  admin_password_hash: "$6$rounds=4096$examplesalt$exhash..."
  timezone: UTC
  network:
    mode: dhcp        # EC2 hands out the private IP over DHCP
  k3s:
    pod_cidr: 10.42.0.0/16
    service_cidr: 10.43.0.0/16
```

```sh
aws ec2 run-instances \
  --image-id ami-0spatiumddi... \
  --instance-type t3.large \
  --user-data file://user-data.yaml \
  ...
```

### Azure VM

`target_disk` is the OS disk; use its `/dev/disk/by-id/` path (Azure
attaches the OS disk as LUN 0). Pass the document as `--custom-data`
(cloud-init user-data) — the CLI base64-encodes the file for you:

```yaml
#cloud-config
spatium_preseed:
  role: appliance
  confirm_wipe: true
  target_disk: /dev/disk/by-id/scsi-360022480000000000000000000000000
  hostname: dns-west-1
  admin_user: azureadmin
  admin_password_hash: "$6$rounds=4096$examplesalt$exhash..."
  timezone: UTC
  network:
    mode: dhcp
  k3s:
    pod_cidr: 10.42.0.0/16
    service_cidr: 10.43.0.0/16
  control_plane_url: https://ddi-control.example.net/
  pairing_code: "12345678"
```

```sh
az vm create \
  --resource-group spatium-rg \
  --name dns-west-1 \
  --image /subscriptions/…/spatiumddi-appliance \
  --custom-data user-data.yaml \
  --size Standard_D2s_v5 \
  ...
```

> **Azure caveat.** Azure's own provisioning agent also wants to set the
> hostname + admin user from the ARM request. Keep those consistent with
> the `spatium_preseed` values (or omit them from one side) so the two
> don't fight. On AWS there's no such overlap — user-data is the only
> channel.

## CI boot-test leverage

A fully-preseeded answer file (disk by-id + `confirm_wipe: true` + all
fields) turns an appliance ISO into an unattended install-to-disk that
finishes without a keypress — the basis for an automated in-VM boot test
per release (long-wanted in #134 Phase 1). Point a throwaway QEMU VM at
the installer ISO + a CIDATA ISO, wait for the reboot, and assert
`/health/live` comes up.

## Live progress

```sh
ssh admin@<appliance-ip>
sudo journalctl -u spatium-install -f          # install-time
sudo tail -f /var/log/spatium-install.log      # step log + preseed NOTEs
# after the install reboots into the running system:
sudo tail -f /var/log/spatiumddi/firstboot.log
```
