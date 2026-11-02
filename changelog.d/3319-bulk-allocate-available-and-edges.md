### Fixed

- **Bulk allocate takes over an `available` address, and no host sits
  on a network or broadcast address (#3319, #3321).** Bulk allocate
  called an address held as `available` "in use" and skipped it (or
  refused the whole range on abort), while Next available offered it.
  It now takes the row over under the template's hostname. A subnet
  made with skip auto addresses no longer stores hosts on its IPv4
  network and broadcast addresses, which read 8 of 6, 133%: a single
  create answers 409 and a bulk range over one answers 422.
