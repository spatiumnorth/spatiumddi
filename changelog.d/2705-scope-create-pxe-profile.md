### Fixed

- **DHCP:** a PXE profile picked in New DHCP Scope is now kept on the created scope. The create body dropped `pxe_profile_id` silently, so a scope made for network boot handed out no boot file. The same-group rule from #2650 applies at create (422 for another group's profile). (#2705)
