### Fixed

- **The console footer stops announcing a cancelled reboot (#3101).** After
  F9 cancelled a console reboot or power-off, the footer went back to
  "Rebooting · F9 cancels" (or "Powering off …") for up to 14 s, until the
  action's 20 s flash ran out. The cancel now replaces it with "Reboot
  cancelled".

  The flash now counts its time from the first frame that draws it, so a
  slow redraw on a loaded node no longer swallows it, and cancelling a
  power-off says "Power-off" in the question, the note and the footer
  instead of "reboot".
