### Fixed

- **Delete dialogs name everything the delete removes (#4143, #4144,
  #4145).** Trash "Delete permanently" on a block or space now names the
  address sets, OT zones, OT devices and BACnet/IP devices on its
  subnets; Multicast "Delete selected" names the group's AV flow; IPAM
  "Delete Permanently" names the address's OT device and BACnet/IP
  device. The lists come from one registry that a backend test checks
  against the database's cascades, so a new child table cannot be left
  out.
