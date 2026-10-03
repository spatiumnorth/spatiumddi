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

## Verified

Pi 5 (BCM2712 C1, 8 GB) + NVMe: built via this profile, installed to NVMe (A/B),
`end0` up, standalone NVMe boot, baked stack serving (web UI). See the related PR for
the full command transcript.
