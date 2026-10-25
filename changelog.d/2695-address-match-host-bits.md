### Fixed

- **A DNS address-match entry with host bits set is refused instead of
  saved (#2695).** `10.0.0.5/24` in a server group's options (allow-query
  and the other address-match lists), a named ACL, a view's match lists
  or a zone's allow-query or allow-transfer answered 200 and was saved,
  but BIND refuses it (`named-checkconf`: "address/prefix length
  mismatch"), so every BIND9 server in the group kept its old config and
  refused each new bundle while the value stood. The API now answers 422
  and names what to use instead: the network (`10.0.0.0/24`) or the one
  address (`10.0.0.5`). A mask written where the length goes
  (`10.0.0.0/255.255.255.0`), which BIND refuses the same way ("expected
  prefix length"), is refused too, naming `10.0.0.0/24`. A value of
  either kind saved before this fix is left out of a BIND9 server's
  bundle with a warning, so the group converges again; an access list it
  empties ships as `none`, never opened up. Bundles for Technitium and
  PowerDNS servers are unchanged: their agents apply such a value as its
  network.
