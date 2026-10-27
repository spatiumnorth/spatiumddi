### Fixed

- **A BIND9 zone's serial no longer steps back across an agent start
  (#2864).** With named stopped, nothing froze the zone or moved the
  render past the serial named had served, so a zone that an RFC 2136
  update, or an earlier apply, had taken past the control plane's
  serial restarted at the lower one. A secondary already holding the
  higher serial then stopped transferring the zone until the primary
  caught up, so changes silently did not reach it. At a start the
  agent now reads the serial named last served from the previous zone
  file and its journal (the signed copy for an inline-signed zone).
  The zone keeps that serial when its data is unchanged and moves one
  past it otherwise. A serial that cannot be read leaves the render's.
