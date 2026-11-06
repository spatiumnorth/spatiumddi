### Fixed

- **Address routes hold an address-set holder to the zone rule, and a
  delete needs a delete grant covering the address (#3636).** A user
  admitted through an address-set grant could name any DNS zone on
  Allocate IP, Next available, an address edit, Bulk allocate or a bulk
  edit, and the record was written there; only a holder of a grant scoped
  to one subnet was held to the subnet's own zones (#2438). Every caller
  without write on subnets at the type level now meets that check on all
  of those routes; the subnet's own zones stay open to it. A delete grant
  scoped to one address set no longer lets a user with write on subnets
  delete any address it can write: deleting an address or one of its
  aliases, singly or in bulk, needs delete on subnets or on an address set
  that contains the address, and the console offers Delete on the same
  rule. Bulk delete skips the rows without such a grant and says why in
  `skipped_reasons`.
