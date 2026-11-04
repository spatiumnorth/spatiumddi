### Fixed

- **A DHCP pool restricted to a PXE boot rule's class serves that
  rule's clients again (#3404).** Since #2731 each PXE rule's class
  was one that Kea evaluates only after it has picked the pool, so a
  pool restricted to it never handed out an address: the PXE clients
  it was meant for got one from another pool of the scope, or none.
  Each rule now renders as a selector class, which pools match, and a
  boot class that carries the boot server and file and still reaches
  only the scopes bound to the profile. Both the agent's Kea config
  and the config preview change.
