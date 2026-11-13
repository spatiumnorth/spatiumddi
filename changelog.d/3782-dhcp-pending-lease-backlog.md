### Fixed

- A DHCP agent that is minutes behind posting its lease events no longer shows an empty spool: the heartbeat now also reports the events it has read but not yet delivered, their age, and the lease-file bytes still unread, and the servers page shows a "Behind" chip with that lag (#3782).
