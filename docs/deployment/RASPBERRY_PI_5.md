# Raspberry Pi 5 appliance

The arm64 appliance runs on a Raspberry Pi 5, booting under UEFI (community EDK2)
from an NVMe SSD. Because the Pi 5's **onboard Ethernet** lives behind the RP1
south-bridge and needs the Raspberry Pi RP1 driver stack — which Debian trixie's
generic `linux-image-arm64` (6.12) does not carry (RP1 Ethernet matured upstream
around 6.13→6.18) — Pi 5 images are built with the **`rpi5` profile**, which uses
the Raspberry Pi downstream kernel instead. Default arm64 builds (Graviton, Ampere,
Apple) are unaffected and keep the generic kernel.

> Without the `rpi5` profile the appliance still installs and boots on a Pi 5, but
> the onboard NIC never comes up (`ip link` shows no `end0`). A USB Ethernet dongle
> (r8152 / ax88179) is the only alternative on the generic kernel.

## Build

Native on an arm64 host (a Pi is fine); the build runs in the repo's Docker builder.

```sh
# Air-gap (baked) ISO + slot image, with the Pi 5 kernel:
make appliance-baked-iso \
    APPLIANCE_ARCH=linux/arm64 \
    APPLIANCE_PROFILE=rpi5 \
    BAKE_SOURCE=ghcr SPATIUMDDI_VERSION=<version>

# ...or just the OS ISO (services pull on first boot):
make appliance-dev-iso APPLIANCE_ARCH=linux/arm64 APPLIANCE_PROFILE=rpi5
```

Notes:
- On a classic-Docker host (no containerd image store) do **not** set
  `BAKE_SAVE_PLATFORM` — `docker save --platform` is unknown there, and on a native
  arm64 host the pulled images are already arm64.
- The `rpi5` profile adds `archive.raspberrypi.com` (key shipped in the profile's
  `mkosi.pkgmngr`) and installs `linux-image-rpi-2712` + `raspi-firmware`.

## Firmware (EDK2) — required, and which fork

The Pi 5 has no onboard UEFI; you supply community EDK2 (rpi5-uefi). **Match the fork
to your board's SoC stepping** (`cat /proc/cpuinfo` → `Revision`):

| Board | Fork |
|---|---|
| Rev 1.0 (e.g. `d04170`) — **BCM2712 C1** | `worproject/rpi5-uefi` (C1-tested; archived Feb 2025) |
| **D0** steppings (16 GB / 2 GB / newer, CM5) | `NumberOneGit/rpi5-uefi` (D0-only — will not boot C1) |

Put the firmware (`config.txt`, `RPI_EFI.fd`) on a FAT boot medium, and replace the
bundled `bcm2712-rpi-5-b.dtb` with the one from **this image's kernel**
(`/usr/lib/linux-image-*-rpi-2712/broadcom/bcm2712-rpi-5-b.dtb`).

In the EDK2 setup (Device Manager → Raspberry Pi Configuration):

- **ACPI / Device Tree → System Table Mode = _Device Tree_** — required; the RPi
  kernel drives the onboard NIC via the device tree. (ACPI mode does not expose the
  RP1 Ethernet.)
- **ACPI / Device Tree → ECAM Compatibility Mode = _AMAZON GRAVITON_** — only needed
  if you boot in ACPI mode for NVMe; in Device Tree mode the DTB describes PCIe.
- If a distro boot throws a *Synchronous Exception*: EFI Memory Attribute Protocol →
  untick *Enable Protocol*.

**Headless (no monitor):** both settings above can be preset offline in `RPI_EFI.fd`
with [`virt-fw-vars`](https://gitlab.com/kraxel/virt-firmware) — `SystemTableMode`
(GUID `677a7ac5-7d92-4288-8bf0-97048102d11c`) = `2` (Device Tree), and
`MemoryAttributeManagerData` (GUID `efab3427-4793-4e9e-aa29-880c9a775b5f`) = `0`. Note
EDK2 v0.3 is community firmware and has been seen **not to reach the kernel on some
boards when headless** (no serial output, no NVRAM write-back); a serial console helps
diagnose, otherwise prefer a board/firmware combination you can drive, or native boot
(tracked for this profile).

## Third-party M.2 HATs and quirky NVMe

The official HAT+ works with the settings above. Third-party HATs and some DRAM-less
drives need extra `config.txt` / EEPROM tuning — all operator-settable on the firmware
boot medium, no image change:

- **Link stays down on a third-party HAT** (e.g. 52Pi P33): set EEPROM `PCIE_PROBE=1`
  and `config.txt` `dtparam=pciex1`; for NVMe boot, EEPROM `BOOT_ORDER=0xf416`.
- **Controller drops off the bus after ~30 s at Gen 2** (`nvme … CSTS=0xffffffff`,
  even idle and with a good PSU): force Gen 1 with `config.txt` `dtparam=pciex1_gen=1`.
  Hardware-dependent (HAT, cable, drive); Gen 1 is the reliable fallback.
- **Still unstable:** the kernel args `pcie_aspm=off pcie_port_pm=off
  nvme_core.default_ps_max_latency_us=0` help — but there is no supported knob for extra
  kernel cmdline args yet (`spatium-grub-render` fixes the cmdline), tracked as a
  follow-up; until then they need a renderer patch. Gen 1 alone is often enough.

## Install

Boot the installer ISO (USB) via EDK2 and install to the NVMe as usual
(`spatium-install`). The onboard NIC (`end0`) comes up under DHCP; pin its address by
MAC on your DHCP server.

## Stick-free NVMe boot

To boot from the NVMe alone (no SD/USB firmware carrier), copy the firmware into the
appliance's ESP after install:

```sh
# from the running appliance (ESP is mounted at /boot/efi):
sudo mount LABEL=<firmware-fat> /mnt
sudo cp /mnt/config.txt /mnt/RPI_EFI.fd /mnt/bcm2712-rpi-5-b.dtb /boot/efi/
sync
```

`RPI_EFI.fd` carries the EDK2 NVRAM, so copy the one on which you saved *Device Tree*
mode — otherwise re-select Device Tree mode once after the first NVMe-only boot. The
Pi bootloader then chains EEPROM → NVMe ESP `config.txt` → `RPI_EFI.fd` → GRUB.

## Installing without booting the installer (unsupported, but handy)

`spatium-install` can be run in a chroot from Raspberry Pi OS instead of booting the
installer ISO. Caveats:

- The generic kernel's `/lib/modules` must be removed first — the installer picks the
  kernel with `ls /lib/modules | head -1`, which sorts `6.12` before `6.18` (a `sort -V`
  fix is tracked).
- Fake an empty `/sys/firmware/efi` so the arm64 EFI-boot assertion passes.
- The installer ends with `systemctl reboot`.

## Verified

Pi 5 (BCM2712 C1, 8 GB) + NVMe: built via this profile, installed to NVMe (A/B),
`end0` up, standalone NVMe boot, baked stack serving (web UI). See the related PR for
the full command transcript.
