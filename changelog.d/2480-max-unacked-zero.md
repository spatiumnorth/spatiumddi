### Fixed

- **A Max Unacked Clients of 0 is saved as 0 (#2480).** The DHCP
  server group dialog sent `parseInt(value) || 5`, turning the 0 its
  field offers into 5, and an untouched Edit of a group stored with 0
  rewrote it to 5.
