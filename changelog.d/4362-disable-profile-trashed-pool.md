### Fixed

- DHCP: disabling a PXE or phone profile is now refused while a pool of a scope in the Trash is restricted to its class, and restoring a scope or pool from the Trash is refused when its class restriction names a class that is no longer rendered (a disabled profile), so a restore no longer brings back a pool that silently serves no client (#4362).
