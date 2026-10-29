### Fixed

- **A new subnet can be deleted permanently again (#3042).** The not-empty
  check counted the reserved "Gateway" row the subnet's own create added,
  so a subnet nobody had touched was refused with "1 allocated IP address".
  That row is now left out while it is still the untouched placeholder; a
  Gateway row that was renamed, given a MAC, DNS records or an owner, or
  turned into a real allocation still blocks the delete, and so does one at
  any other address.
