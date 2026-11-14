### Fixed

- A BIND9 secondary zone's served serial is now re-read about every minute, so a newer transferred serial, or a first transfer that lands after the zone was set up, shows in the zone's sync pill without waiting for another zone change or an agent restart (#4065).
