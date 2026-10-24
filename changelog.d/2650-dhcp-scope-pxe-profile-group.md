### Fixed

- **A DHCP scope can no longer be bound to a PXE profile from another server
  group (#2650).** The update was accepted and rendered the other group's boot
  server into this group's agents. It now answers 422.
