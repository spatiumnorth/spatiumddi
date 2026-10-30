### Fixed

- **The console footer stops announcing a cancelled reboot (#3101).** After
  F9 cancelled a console reboot or power-off, the footer went back to
  "Rebooting · F9 cancels" (or "Powering off …") for up to 14 s, until the
  action's 20 s flash ran out. The cancel now replaces it with "Reboot
  cancelled".
