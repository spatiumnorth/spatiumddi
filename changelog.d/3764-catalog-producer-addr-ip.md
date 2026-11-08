### Fixed

- DNS catalog zones on BIND9: a consumer server's config no longer fails `named-checkconf`, which made it decline its whole config. It now declares the catalog zone it consumes, points `default-masters` at the producer's IP (the producer's host if that is an address, otherwise the address its agent last connected from) instead of its hostname, and signs member-zone transfers with the group key. When the producer has no usable address the catalog is left out and a warning is logged. Technitium consumers keep the producer's host name, which Technitium accepts (#3764).
