### Fixed

- The UniFi, Meraki, Fortinet and PAN-OS integration mirrors now give each subnet they own the same reserved `Gateway` row New Subnet creates, and move it when the controller reports a new gateway, so Next available no longer offers the subnet's router address to a host. An address another row already holds is never taken over: the sync leaves that row alone and lists it in its warnings.
