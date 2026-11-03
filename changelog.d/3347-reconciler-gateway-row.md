### Fixed

- The UniFi, Meraki, Fortinet and PAN-OS integration mirrors now give each subnet they own the same reserved `Gateway` row New Subnet creates, and move it when the controller reports a new gateway, so Next available no longer offers the subnet's router address to a host. An address another row already holds is never taken over: the sync leaves that row alone and lists it in its warnings.
- The Meraki, Fortinet and PAN-OS mirrors no longer fail the whole sync when a DHCP lease or reservation they report sits on an address another row already holds, such as the subnet's gateway: that address is skipped and listed in the sync's warnings.
