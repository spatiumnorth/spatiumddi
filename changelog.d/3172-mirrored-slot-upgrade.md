### Fixed

- **A mirrored (RAID1) appliance can slot-upgrade and roll back again
  (#3172).** On a box installed across two disks, every
  `spatium-upgrade-slot` subcommand (`status`, `apply`, `rollback`,
  `set-next-boot`, `sync-versions`) exited with "couldn't detect A/B
  slots", so neither a Fleet upgrade nor a rollback could run, and Fleet
  showed the node's active slot as unknown. A slot on a mirror is now the
  md array its two `root_A` / `root_B` members belong to, everywhere the
  booted slot is read: the upgrade tool, the console, the supervisor's
  Fleet telemetry, and firstboot, which would otherwise never have
  committed a trial boot, so every upgrade would have reverted on the
  next reboot. `apply` writes the inactive array, never one of its
  members. Because the array is 9 MiB smaller than the image, the image
  is written through a temporary device-mapper overflow and its
  filesystem shrunk into the array with `resize2fs`, then checked with
  `e2fsck` before the bootloader is pointed at it. The overflow mapping
  is removed even when the write fails or the upgrade is stopped, and an
  image too old to carry `mdadm` is refused on a mirror, since its initrd
  could not assemble the array. `rollback` now also
  copies the boot config to the second disk's ESP, as the other slot
  commands already did, and so does firstboot when it commits a trial
  boot, so the second disk no longer boots the slot just upgraded away
  from if the first disk fails. Single-disk appliances are unchanged.
