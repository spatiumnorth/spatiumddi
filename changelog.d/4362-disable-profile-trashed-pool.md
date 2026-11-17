### Fixed

- DHCP: disabling a PXE profile, a phone profile or a device policy is now refused while a pool (live, or in a scope in the Trash) is restricted to its class, and restoring a scope or pool from the Trash is refused when its class restriction names a class that is no longer rendered (a disabled profile or policy), so nothing silently serves no client (#4362).
