### Fixed

- A BIND9 or PowerDNS secondary or stub zone its server holds no copy of (serial 0) no longer reads "in sync": the DNS agent now reports the serial named actually serves (or nothing if unreadable), and the control plane counts a secondary serving 0 as not synced. A transferred secondary reads synced at the serial it serves, from agents of any release (an older agent's start-up report already carries it), and the zone sync pill and zone header show that served serial instead of the target 0 (#3940).
