### Fixed

- A BIND9 secondary or stub zone its server holds no copy of no longer reads "in sync" (serial 0): the DNS agent now reports the serial named actually serves (or nothing if unreadable), and the control plane counts a BIND9 secondary serving 0 as not synced (#3940).
