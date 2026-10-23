### Fixed

- **The resize dialogs' warning no longer offers a revert the API
  refuses, or a netmask change for a block (#2416).** Resize is
  grow-only, so the subnet banner now says to delete and recreate to
  go smaller, and the block banner says child subnets are unchanged
  and no client needs reconfiguring.
