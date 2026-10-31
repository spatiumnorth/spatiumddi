### Fixed

- **An appliance rolled back to its previous slot can rebuild that slot's
  container images again (#3169).** k3s imports images from one shared
  directory on `/var`, which holds the tarballs of whichever slot was last
  upgraded to. A rollback, a Fleet "set default" to the other slot, or a
  "boot this slot next" now copies the target slot's own tarballs into that
  directory first, stamped with the current time so k3s re-imports them
  (it skips a same-size file with an older timestamp). The images are in
  containerd before the reboot, so the rolled-back slot's pods no longer
  come up `ErrImageNeverPull` on a node whose image store was wiped by a
  cluster join, promote or demote, or trimmed by image garbage collection.
  If the copy fails, the switch still goes ahead and the log says what
  failed and how to recover by hand. The console's slot-rollback action
  now allows 15 minutes instead of 30 seconds, since the copy can take a
  minute or more. An upgrade still copies the new slot's images once, as
  before.
