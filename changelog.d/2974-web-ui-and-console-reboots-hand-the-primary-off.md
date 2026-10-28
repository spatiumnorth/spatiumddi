### Fixed

- **A reboot from the web UI, and a reboot or power-off from the
  appliance console, now hand the database primary off first (#2974).**
  Only the Fleet reboot did since #2849; the other paths rebooted the
  node holding the PostgreSQL primary directly and kept the API gap that
  fix removes. The web-UI local reboot and the console's F5 / F6 now run
  one wrapper, `spatium-power-action`, which runs the same handoff
  (same budgets, and a handoff that cannot be done never holds the
  reboot or power-off), then `systemctl reboot` or `poweroff`. If that
  fails, or the pending reboot is cancelled, the cordon is undone; after
  a power-off the node uncordons itself at its next boot. The Fleet
  reboot is unchanged.
