### Fixed

- A Technitium agent no longer takes over a zone of the same name that an operator created on the daemon itself: it used to delete every record the bundle did not list and later delete the zone. The zone is left untouched, reported as a refused zone, and can be adopted deliberately with `TECHNITIUM_ADOPT_EXISTING_ZONES=true` on the agent (the agentless driver already refuses non-empty and non-Primary zones, #1784).
