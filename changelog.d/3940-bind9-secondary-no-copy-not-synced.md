### Fixed

- A BIND9 secondary or stub zone its server holds no copy of no longer reads "in sync" (serial 0): the DNS agent now reports the serial named actually serves (or nothing if unreadable) and says so in `X-Spatium-Agent-Features` (`served-serials`), and the control plane counts a secondary serving 0 as not synced for such an agent. An agent not yet upgraded keeps the previous verdict instead of reading every secondary as not synced (#3940).
