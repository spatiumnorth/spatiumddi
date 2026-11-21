### Fixed

- The BIND9 catalog zone, which lists every zone in the group, is no longer transferable or queryable by anyone: it now carries the same grant as the group's zones (the group TSIG key plus the group's `allow_transfer`). An external secondary that pulled the catalog unsigned from an address not in `allow_transfer` is refused after the upgrade and keeps its last copy until it signs with the group key or the address is added. A group with catalog zones on and DNS views now shows a warning, since BIND9 publishes no catalog next to views (#3578).
