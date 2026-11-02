### Fixed

- **A Boot once trigger left behind by a reboot no longer blocks every later Boot once on the node (#3283).**
  A reboot while the host runner was arming the slot left the trigger file in
  place, and the watcher does not fire for a file already there at boot, so
  every later Boot once answered success and never ran. The supervisor now
  writes a new request over a trigger left by an earlier boot, so the runner
  picks it up.
