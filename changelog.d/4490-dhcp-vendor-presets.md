### Added

- DHCP option 43 vendor presets: in a phone profile, "Add vendor preset..." takes a vendor (UniFi, Cisco WLC, Ruckus SmartZone / ZoneDirector) and the controller address(es), previews the encoded option 43 hex, and fills the option row and the option 60 match, instead of hand-encoding a raw `code:43` row. Also available over REST and to the Copilot (`find_dhcp_vendor_presets`). (#4490)
