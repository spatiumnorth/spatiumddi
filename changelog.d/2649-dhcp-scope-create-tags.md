### Fixed

- **Creating a DHCP scope no longer drops its tags (#2649).** The create
  handler never passed `tags` to the scope row, so they were audited but not
  stored. They are now saved on create.
