### Fixed

- **A failed install keeps its logs on the target even when the root
  copy stopped before `/var/log` existed (#2405).** `on_failure`
  saved the installer logs only if `$MOUNT/var/log` was already
  there, so a copy that failed early (rsync exit 11 filling the
  target in `/usr/lib/modules`) kept nothing and said nothing, and
  re-running the installer then truncated the live logs. It now
  saves whenever the target is mounted, creating the directory
  itself, and when the logs cannot be saved it prints a WARN naming
  the live paths they remain at so they can be copied before a
  reboot.
