### Fixed

- **A new subnet can be deleted permanently again (#3042).** The not-empty
  check counted the reserved "Gateway" row the subnet's own create added,
  so a subnet nobody had touched was refused with "1 allocated IP address".
  That row is now left out while it is still the untouched placeholder,
  including when the create published its PTR record or a discovery sweep
  has seen the gateway answer. A Gateway row that an operator edited (name,
  status, MAC, DNS zones, owner, tags, custom fields), that an integration
  or import owns, or that a BACnet / OT / E911 / multicast record points at
  still blocks the delete, and so does one at any other address.
