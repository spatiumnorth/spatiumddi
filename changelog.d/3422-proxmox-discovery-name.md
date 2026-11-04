### Fixed

- **A Proxmox endpoint's Discovery button is named "Discovery"
  (#3422).** The icon-only button took its name from its tooltip, so
  until the endpoint had synced once a screen reader announced it as
  "Sync at least once to populate discovery", an instruction rather
  than the control, and after that as the whole tooltip. It is named
  for its action in either state now, and the tooltip still says why
  it is unavailable before the first sync.
