### Fixed

- **A search or filter that matches nothing on the E911 lists no longer says
  the list is empty (#2800).** Emergency Response Locations and Bindings, plus
  the OT devices, BACnet devices, AV flows and DICOM application entities
  lists, answered "No X yet" while holding rows. They now say "No X match the
  current search or filter" with a Clear filters link, through the shared
  `ListEmpty` option #2616 added; "No X yet" stays for a list that really is
  empty.
