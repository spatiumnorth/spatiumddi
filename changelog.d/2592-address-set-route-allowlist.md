### Changed

- **An address-set grant reaches only the address routes that check it.** A
  role scoped to one address set (the Address Set Editor role) is admitted to
  an explicit list of IPAM routes: create, next-IP, bulk-allocate (preview and
  commit), edit and delete an address, add and remove its aliases, bulk-edit
  and bulk-delete addresses, deprecate stale IPs, and the address import
  (preview and commit). Each checks every address against the sets the caller
  holds. Every other mutating IPAM route, including the address profile scan,
  allocation planning, find-free and the whole-tree import preview, now
  answers 403 to such a role unless it also holds a type-level grant, and a
  route added later stays closed to it until it is listed. Adding or removing
  an alias now needs write on that address (subnet-wide, or through a set
  covering it). The bulk-allocate and address-import previews refuse a caller
  who can write nothing on the subnet, and report addresses outside the
  caller's sets the way the commit does (`conflicts_no_perm`, and a per-row
  error) instead of showing the existing rows there.
