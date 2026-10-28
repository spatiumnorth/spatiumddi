### Fixed

- **A reboot from the web UI, and a reboot or power-off from the
  appliance console, now hand the database primary off first (#2974).**
  Only the Fleet reboot did since #2849; the other paths rebooted the
  node holding the PostgreSQL primary directly and kept the API gap that
  fix removes. The web-UI local reboot and the console's F5 / F6 now run
  one wrapper, `spatium-power-action`, which runs the same handoff
  (same budgets, and a handoff that cannot be done never holds the
  reboot or power-off), then `systemctl reboot` or `poweroff`. On the
  primary's node that takes up to a few minutes longer; the handoff is
  capped at 240 s, after which the reboot goes on. The console starts
  it as a systemd unit rather than waiting on it, so the dashboard keeps
  rendering, shows `REBOOT under way — handing off DB primary`, and F9
  cancels it; a cancel, or a failed `systemctl`, undoes the handoff's
  cordon, while the stop that the shutdown itself sends does not. After
  a reboot or power-off the node uncordons itself at its next boot; a
  node powered off for good stays cordoned in the cluster until it is
  removed. The Fleet reboot is unchanged.
