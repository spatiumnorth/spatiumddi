# SpatiumDDI OS Appliance

Self-contained bootable image: Debian 13 (trixie) amd64 + k3s +
SpatiumDDI's container set baked in as containerd-format `.tar.zst`
archives, wired together so the operator gets a working web UI on
first boot.

**Issue #183 Phase 7 (2026-05-16):** the appliance is **k3s-only**.
The pre-Phase-7 docker + docker-compose stack is gone; pods are
managed by k3s's bundled helm-controller via the `spatiumddi-
appliance` Helm chart. The supervisor runs as a privileged DaemonSet
pod; service roles (DNS / DHCP) come up via per-role chart values
the supervisor PATCHes onto the chart on heartbeat.

> **Why Debian, not Alpine?** mkosi ≥ 23 dropped Alpine as a supported
> distribution. Phase 1's job is the proving ground for cloud-init,
> boot orchestration, and the build pipeline — keeping it on a
> mkosi-native distro avoids dragging in `alpine-make-vm-image` as a
> second build tool. The bundled `ghcr.io` container images stay
> Alpine-based; only the host OS shifts. APPLIANCE.md already lists
> Debian as Option B for the bare-metal / VM track, so the spec
> covers it.

> **Status:** Phase 1 of the appliance roadmap (issue
> [#134](https://github.com/spatiumnorth/spatiumddi/issues/134)).
> Proving ground — feedback drives Phases 2–6 (ISO installer, arm64 +
> Pi, role-split images, cloud images, fleet management).
>
> Spec context: [`docs/deployment/APPLIANCE.md`](../docs/deployment/APPLIANCE.md).

## Why k3s, not Docker Compose?

Early appliance builds (pre-#183) ran the stack with `docker compose`
driven from a boot script. It was fine for one box doing one job — but
the whole point of the appliance is to *grow* with the operator, and
Compose fought that at every turn. We moved to **embedded k3s** (a single
~70 MB static Kubernetes binary) because it turns the appliance from "a
box running some containers" into "a node you can build a cluster out
of." Concretely:

- **A declarative target, not a script of CLI commands.** Under Compose,
  "make this box a DNS node" meant `docker compose down` one service,
  `up -d` another, juggle an `--env-file`, and pray nothing failed
  halfway (recovery was usually "delete the state file and reboot").
  Under k3s the desired state is a *document* — a HelmChart custom
  resource — and the bundled helm-controller continuously reconciles
  reality to match it. A crashed pod comes back on its own; a role change
  is a fact you assert once, not a sequence of imperative steps you have
  to babysit and unwind by hand when one fails.

- **One box today, a real HA cluster tomorrow — in place.** This is the
  big one. Docker Compose has no native concept of a multi-machine
  cluster; you'd be bolting on Swarm or hand-rolling orchestration. k3s
  ships embedded etcd, so a single-VM appliance can be **promoted** into
  a 3 / 5 / 7-node high-availability control plane (Postgres via
  CloudNativePG, Redis via Sentinel, a MetalLB virtual IP) right from the
  Fleet UI — no reinstall, no re-architecting. The same image that runs a
  homelab-in-a-box scales up to a fault-tolerant production control
  plane.

- **Roles are labels, not file edits.** Which services a node runs
  (control plane / DNS-BIND9 / DNS-PowerDNS / DNS-Technitium / DHCP) is decided by a
  per-node Kubernetes label. Flipping a role from the web UI is a single
  `kubectl label node` — the workload schedules or drains as a
  *consequence* of the label. No editing compose files on the box, no
  SSH, no remembering which `COMPOSE_PROFILES` were set where. HA agents
  run as DaemonSets, so "exactly one DNS pod per DNS-labelled node" is
  something the platform guarantees rather than something the operator
  maintains.

- **The operator never touches raw container CLI.** Everything is driven
  from the `/appliance` web surface (Fleet, Cluster, OS Versions tabs)
  talking to the kube-API, or through the pre-`KUBECONFIG`'d `kubectl`
  for anyone who wants a shell. Both are standard, documented, widely
  understood tools — versus a pile of project-specific `docker compose`
  incantations and hand-maintained `.env` / state files.

- **One deployment model everywhere.** The appliance installs the very
  same umbrella + appliance Helm charts that ship for standalone
  Kubernetes deployments. There is no separate Compose path to keep in
  sync: what we test on Kubernetes is what runs on the appliance, and
  what you learn operating the appliance transfers to any cluster.

- **Upgrades that can't drift.** k3s keeps its state in kine (SQLite)
  under `/var/lib/rancher/`, which lives on the persistent `/var`
  partition and so survives an atomic A/B slot swap. Container images are
  baked into the slot and reconciled by helm-controller, so an OS upgrade
  and a container upgrade land as **one unit** — gone is the Compose-era
  trap where a new rootfs carried a different compose schema while old
  containers were still running against the old one.

The cost is honest and small: k3s adds ~70 MB to the slot image and a
steady ~150 MB of RAM for the server process, both comfortably inside the
appliance's disk and memory floor. For a deeper, change-by-change account
of the migration, see the **"Why k3s"** section in
[`docs/deployment/APPLIANCE.md`](../docs/deployment/APPLIANCE.md).

## What it ships

- Debian 13 (trixie) amd64, `linux-image-cloud-amd64` kernel
- systemd + cloud-init (NoCloud datasource)
- **k3s** (pinned via `K3S_VERSION` in the top-level Makefile; baked
  as a single static binary at `/usr/local/bin/k3s` with `kubectl`,
  `crictl`, `ctr` as symlinks)
- `kubectl` pre-`KUBECONFIG`'d for admin + root login shells
- **Helm chart** at `/usr/lib/spatiumddi/charts/spatiumddi-appliance
  .tgz` — applied by k3s's helm-controller on first boot via the
  bootstrap manifest the firstboot orchestrator writes into
  `/var/lib/rancher/k3s/server/manifests/`
- **Preloaded containerd image set** in
  `/var/lib/rancher/k3s/agent/images/*.tar.zst` (k3s auto-imports
  on first start, no docker-load shell-out needed)
- First-boot orchestrator (`/usr/local/bin/spatiumddi-firstboot`)
  that generates secrets, renders the bootstrap HelmChart manifest,
  and waits for kubeapi `/readyz`

## Build prerequisites

- **Docker** with privileged-container support on the **build host
  only** — the appliance itself ships zero docker. mkosi + qemu-
  utils + apt keyring + grub variants live inside the published
  builder image (`ghcr.io/spatiumnorth/appliance-builder:latest`).
  The bake step uses host docker to `docker save` SpatiumDDI's
  service images into containerd-readable `.tar.zst` archives.
- **helm** + **zstd** on the build host — `make appliance-bake-
  chart` packages the Helm chart; `appliance/scripts/bake-images
  .sh` compresses image archives.
- ~2 GiB free disk in the build directory.
- On an **arm64 host** (Apple Silicon, an ARM server): nothing extra, but
  use `make appliance-baked-iso-cross` rather than `make appliance-baked-iso`
  — see *Building on Apple Silicon / any arm64 host* below.

The build runs `docker run --privileged` because mkosi needs loop
devices, kernel namespaces, and bind-mounts to bootstrap the rootfs.
Same constraint as `packer`, `live-build`, `diskimage-builder`.

## Build

From the repo root:

```sh
make appliance
```

Pulls `ghcr.io/spatiumnorth/appliance-builder:latest`, runs mkosi
inside it, and writes:

- `appliance/build/spatiumddi-appliance_0.1.0.raw`   (2.1 GiB sparse, 1.1 GiB consumed)
- `appliance/build/spatiumddi-appliance_0.1.0.qcow2` (~790 MiB compressed)

~5–10 min on a modern laptop with warm caches; first build is slower
because mkosi populates its apt cache.

### Building on Apple Silicon / any arm64 host

The ISO is x86-64 (`Architecture=x86-64` in `mkosi.conf`) and cross-builds
fine from arm64 — on an M4 the whole run is *faster* than the old amd64
Linux box (~3 min for `make build` with warm buildkit layers, ~11 min for
bake → mkosi → ISO → slot image). One command does it:

```sh
make appliance-baked-iso-cross
```

Three things that target handles, each of which is a real failure if you
drive the steps by hand:

**1. The builder must run NATIVE — the emulated path is a dead end.**
`ghcr.io/spatiumnorth/appliance-builder` is published for both
architectures (since #991), so on arm64 you get an arm64 builder and
mkosi cross-builds x86-64 inside it. Do *not* reach for
`--platform linux/amd64` on the builder: under qemu-user or Rosetta,
mkosi dies immediately with

```
mkosi was unable to invoke the mount_setattr() system call.
OSError: [Errno 38] Function not implemented: '…/mkosi-workspace-…/root'
```

`mount_setattr(2)` is part of the new mount API, which neither
translation layer implements. The kernel in the Docker Desktop VM is
fine; the syscall translation is not, and **no amount of `--privileged`
fixes it.** Cross-building works because the Docker Desktop VM registers
`x86_64` binfmt handlers with the `F` flag, so the amd64 dpkg maintainer
scripts mkosi chroots into run under emulation transparently. Loop mounts
and `mount -o loop,offset=` on files under the bind-mounted macOS volume
work too, which `wrap-iso.sh` and `build-slot-image.sh` both depend on.

**2. The two halves of the build need opposite environments.** App-image
builds and third-party pulls want `DOCKER_DEFAULT_PLATFORM=linux/amd64`;
mkosi, the ISO wrap and the slot image need it *unset* so the builder runs
native. A single `make appliance-baked-iso` runs both halves under one
environment, which is why the cross target sets the variable per recipe
line instead.

**3. `docker save` needs a platform under the containerd image store.**
Docker Desktop uses the containerd snapshotter, where `docker save` of a
registry image fails when its index lists platforms whose blobs were never
pulled:

```
Error response from daemon: unable to create manifests file:
NotFound: content digest sha256:… : not found
```

`BAKE_SAVE_PLATFORM` (which the cross target sets) adds
`docker save --platform` and an unconditional `docker pull --platform` for
third-party images. That second half matters as much as the first: on a
dev laptop `redis:8.10.2-alpine` and `nginx:…` are usually already present
**as arm64** from the dev compose stack, they satisfy
`docker image inspect`, and without the pin they would be baked silently —
the appliance's Redis then crash-loops with `exec format error`.
`make appliance-verify-arch` asserts this before the bake rather than
leaving it to be discovered on the appliance; the cross target runs it for
you.

Empty `BAKE_SAVE_PLATFORM` is CI's default and is byte-for-byte the old
behaviour.

**Verifying the result.** Check freshness by epoch (`stat -f %m` on macOS,
not `-c`), and check the contents by loop-mounting the raw — root is
partition 3, at offset `2101248*512` — then:

```sh
chroot /mnt dpkg --print-architecture      # must print: amd64
ls /mnt/var/lib/rancher/k3s/agent/images/  # the baked *.tar.zst archives
```

A byte-grep of the `.iso` proves nothing: the rootfs is compressed.

**Side effect worth knowing.** `make build` retags the `spatiumddi-*:dev`
images the dev compose stack uses, so after a cross-build the dev stack
would start amd64 images under emulation. Restore them with:

```sh
docker compose -f docker-compose.dev.yml build
```

### Iterating on the builder image

If you're modifying `appliance/builder/Dockerfile` (e.g. bumping mkosi)
and don't want to publish first:

```sh
make appliance-builder                                   # builds spatiumddi-appliance-builder:dev
make appliance APPLIANCE_BUILDER=spatiumddi-appliance-builder:dev
```

### Phase 2 — tri-mode hybrid live ISO

After Phase 1 produces a raw image, wrap it as a hybrid live ISO:

```sh
make appliance-iso
```

Output: `appliance/build/spatiumddi-appliance_0.1.0.iso` (~260 MiB —
the rootfs is squashfs-compressed with xz, much smaller than the
underlying raw).

The script extracts the kernel + initrd that mkosi staged alongside
the raw, mounts the raw's root partition by GPT type GUID
(`4F68BCE3-…` = root-x86-64), builds a squashfs of it, and drives
`grub-mkrescue` to produce a tri-mode hybrid ISO:

| Boot path     | Mechanism                                           |
|---            |---                                                  |
| BIOS-CD       | El Torito → `boot/grub/i386-pc/eltorito.img`        |
| UEFI-CD       | El Torito alt-boot → `/efi.img` (FAT ESP with grub) |
| USB-`dd`'d    | Hybrid MBR + GPT, boots via either MBR (BIOS) or GPT (UEFI) |

At runtime, **live-boot** (baked into the appliance's initrd by
`mkosi.conf` Packages=) detects the boot medium, loop-mounts
`/live/filesystem.squashfs` from the ISO, and overlays it with a
tmpfs so writes work in RAM. The `spatiumddi-firstboot` service
then runs the same way as on the qcow2: writes the variant-specific
HelmChart manifest into `/var/lib/rancher/k3s/server/manifests/`,
starts k3s, and polls `/health/live` until the api pod reports
ready.

Verify the boot records with `xorriso -indev <iso> -report_el_torito plain`.

### Cleaning

```sh
make appliance-clean
```
(may need sudo — mkosi's build artifacts are root-owned).

## Boot

The qcow2 is **hybrid BIOS + UEFI** — the same image boots on both
firmware modes. Pick whichever your hypervisor defaults to.

**BIOS (default for QEMU / Proxmox / older libvirt):**
```sh
qemu-system-x86_64 -enable-kvm -m 4G -smp 2 \
    -drive file=appliance/build/spatiumddi-appliance_0.1.0.qcow2,if=virtio \
    -drive file=appliance/cloud-init/cidata.iso,if=virtio,format=raw,readonly=on \
    -nic user,hostfwd=tcp::8080-:80,hostfwd=tcp::2222-:22 \
    -nographic
```

**UEFI (Hyper-V, modern QEMU, AWS/Azure cloud — Phase 5):**
```sh
qemu-system-x86_64 -enable-kvm -m 4G -smp 2 \
    -bios /usr/share/ovmf/OVMF.fd \
    -drive file=appliance/build/spatiumddi-appliance_0.1.0.qcow2,if=virtio \
    ...
```

(Build the `cidata.iso` first — see [cloud-init/README.md](cloud-init/README.md).)

After ~30 s for boot + ~60–120 s for the stack to come up, the web UI
is at <http://localhost:8080/>. Default login `admin / admin` (forces
password change on first login).

## Layout

```
appliance/
├── README.md                # this file
├── mkosi.conf               # top-level mkosi config (Debian trixie / amd64 / hybrid grub)
├── mkosi.postinst           # post-install hook: enable services, hardening (uses $BUILDROOT)
├── mkosi.extra/             # files copied into the rootfs after package install
│   ├── etc/
│   │   ├── systemd/system/spatiumddi-firstboot.service  # systemd unit
│   │   ├── motd                                         # console branding
│   │   └── spatiumddi/README                            # /etc/spatiumddi/ contract
│   └── usr/local/
│       ├── bin/
│       │   ├── spatiumddi-firstboot        # boot-time orchestrator
│       │   └── spatiumddi-stack-status     # operator status command
│       └── share/spatiumddi/
│           └── (k3s manifest templates rendered by firstboot)
├── builder/
│   ├── Dockerfile           # the appliance-builder image (mkosi + qemu-img + xorriso + ...)
│   └── .dockerignore
├── scripts/
│   └── wrap-iso.sh          # Phase 2 — wrap raw image as hybrid USB/CD ISO via xorriso
└── cloud-init/
    ├── README.md
    ├── user-data.example
    └── meta-data.example
```

## Customising the stack

The appliance is k3s-driven post-#183. `spatiumddi-firstboot` renders
one of three variant-specific HelmChart manifests (Application /
All-in-One / Core-only) into `/var/lib/rancher/k3s/server/manifests/`
on every boot and k3s's helm-controller installs the chart tarball
baked at `/usr/lib/spatiumddi/charts/`. Chart values are filled in
from `/etc/spatiumddi/.env` (secrets + agent keys + control-plane
URL + appliance role).

To customise an existing install:
- Operator-pasted overrides live in `/etc/spatiumddi/` (preserved
  across slot swaps via the `/etc` overlay → `/var/persist/etc`).
- Per-role firewall extras land in `appliance.firewall_extra` on the
  control plane — rendered by the supervisor into
  `/etc/nftables.d/spatium-role.nft`.

To pin a release tag, drop a `/etc/spatiumddi/release` file via
cloud-init `write_files` — see
[cloud-init/README.md](cloud-init/README.md).

## What this MVP does NOT do (yet)

Tracked in [#134](https://github.com/spatiumnorth/spatiumddi/issues/134):

- **arm64 / Raspberry Pi** (Phase 3) — builder image is amd64-only
- **Role-split images** (Phase 4) — single all-in-one only
- **Cloud images** (Phase 5) — no AWS/Azure/GCP datasource testing
- **Fleet management + A/B updates** (Phase 6)

Other gaps Phase 1 surfaces but doesn't close:
- No SBOM / GPG signing on the produced qcow2
- Stack health waits on `/health/live` only — does not verify DNS /
  DHCP agents finished registration
- No host-level Prometheus exporters baked in (the `observability`
  Helm chart values flag enables kube-state-metrics + node-exporter
  on-demand; both images are baked into the slot)
