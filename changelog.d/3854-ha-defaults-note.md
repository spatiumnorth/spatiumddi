### Fixed

- The DHCP server group dialog's HA Hook Tuning note no longer calls every default Kea's own recommendation: it now says the 2 s Heartbeat Delay is SpatiumDDI's choice (Kea documents 10 s), so a config reload costs seconds (#3854).
