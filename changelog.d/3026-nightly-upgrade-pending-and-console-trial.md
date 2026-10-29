### Fixed

- **A finished nightly upgrade no longer shows as "Upgrade pending" again,
  and the console no longer says "trial boot" after the slot was committed
  (#3026).** A nightly's release tag is `nightly-YYYY.MM.DD` while the slot
  it installs reports `0.0.0-nightly-YYYYMMDD+<sha>`, and the control plane
  compared the two as strings, so the desired version was never cleared
  after the upgrade landed. The Fleet card came back, and the supervisor
  would have fired the same slot write again over the inactive slot, the
  only rollback. The control plane (supervisor, DNS and DHCP agent
  heartbeats, the rolling upgrade steps, the disk pre-flight, the upgrade
  image table's "installed on" column and the image reclaim sweep) now
  recognises a nightly tag as the night it names, and the supervisor never
  fires a target the booted slot already is, including on a trial boot of
  it. A nightly rolling upgrade's shared-chart hold had the same compare,
  so a node already on the target could write the shared role chart
  mid-roll (#1710's outage); it now holds. Releases, where tag and version
  are equal, behave as before, and a target spelled as a full nightly
  version (`+<sha>` included) still matches only that build. Separately, the tty1 console cached
  grubenv's `saved_entry` for the life of the process, so it kept
  "DEGRADED - trial boot - reboot reverts" after firstboot committed the
  new slot, until the next reboot; it now re-reads it every 5 seconds.
  Thanks to @Airshipduck for the report and diagnosis.
