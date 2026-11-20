### Fixed

- A Technitium agent whose state directory was lost no longer refuses Secondary, Stub and Forwarder zones that already exist on the daemon until `TECHNITIUM_ADOPT_EXISTING_ZONES` is set; those zones hold no operator-authored records, so they converge. A same-named Primary is still refused (#4441).
