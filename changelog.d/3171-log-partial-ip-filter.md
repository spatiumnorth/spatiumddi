### Fixed

- Logs → DNS Queries (and the DHCP Activity log, the RPZ hits list and the matching Copilot tools): typing a partial address into an IP filter no longer fails with "A supplied value cannot be stored as sent". A leading part (`127`, `192.168.0.`, `fd00:`) now filters as you type, a whole address matches exactly, a CIDR (`192.168.0.0/24`) matches the clients inside it, and the DHCP MAC filter accepts a leading part with any separator. A value that cannot be an address answers a 422 naming the field.
