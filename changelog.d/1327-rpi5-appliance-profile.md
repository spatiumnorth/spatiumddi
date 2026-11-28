### Added

- **Raspberry Pi 5 appliance profile (#1327).** `APPLIANCE_PROFILE=rpi5`
  builds the arm64 appliance with the Raspberry Pi downstream kernel
  (`linux-image-rpi-2712`) and `raspi-firmware`, so the Pi 5's onboard
  NIC works; Debian's generic arm64 kernel has no RP1 Ethernet driver.
  The profile is opt-in, and default amd64 / arm64 builds are unchanged.
  `spatium-upgrade-slot` now refuses a slot upgrade that would change
  the flavour (a generic image onto an `rpi5` node, or the reverse), in
  the same post-write, pre-bootloader window as the architecture gate.
  See `docs/deployment/RASPBERRY_PI_5.md`.
