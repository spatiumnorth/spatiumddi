### Fixed

- **An appliance switched back to a slot that an upgrade wrote gets that
  slot's container images again (#3169).** k3s imports images from one shared
  directory on `/var`, which holds the tarballs of whichever slot was last
  upgraded to. A rollback, a Fleet "set default" to the other slot, or a
  "boot this slot next" now copies the target slot's own tarballs into that
  directory first, stamped with the current time so k3s re-imports them (it
  skips a same-size file with an older timestamp). The running k3s imports
  them straight away, and the target slot's k3s imports any it had not
  finished when the node rebooted, so the rolled-back slot's pods no longer come
  up `ErrImageNeverPull` on a node whose image store was wiped by a cluster
  join, promote or demote, or trimmed by image garbage collection. A reboot
  requested while that copy runs (about 1 GB) waits for it, up to 15 minutes,
  instead of cutting it off before the switch is made, and the console's
  slot-rollback action now allows 15 minutes instead of 30 seconds. A slot
  holding another architecture's image is not copied. The installer
  now also keeps the tarballs on the first slot's own filesystem (an install
  that cannot fit them fails instead of leaving a partial set), so switching
  back to a node's original slot restores them too; a node installed before
  this still carries none there, the switch goes ahead, the log says so, and
  `docs/TROUBLESHOOTING.md` has the recovery. An upgrade still copies
  the new slot's images once, as before.
