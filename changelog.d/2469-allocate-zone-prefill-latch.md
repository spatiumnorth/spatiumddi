### Fixed

- Allocate IP pre-selects the subnet's primary DNS zone even when another DNS group's zones load first, so an untouched DNS Zone no longer stores the address in an additional zone (#2469).
