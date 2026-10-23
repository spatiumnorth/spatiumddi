### Fixed

- **Edit Zone and Edit Group show what is stored after a save (#2462).**
  The DNS page kept the zone or group object from the moment it was
  clicked in the tree, so after a save the zone header and a reopened
  dialog showed the old values and an untouched Save wrote them back
  (a Default TTL change, or "Allow recursion" turned off, was undone).
  The page now reads the selected zone and group from the refreshed
  lists.
