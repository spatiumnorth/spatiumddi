### Fixed

- The Kea importer now names what it cannot take. A reservation whose address is not an IP address, is the wrong family or lies outside its scope's subnet is dropped with a warning in the preview and the commit (it used to be stored, or fail the whole scope in generic words), and subnets under `shared-networks` are imported as scopes with a warning that the grouping was flattened (they used to be left out silently, and a config of shared networks alone was refused as not a Kea config). A Dhcp6 reservation's extra addresses and prefixes are named as not imported.
