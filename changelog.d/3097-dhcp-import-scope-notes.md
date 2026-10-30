### Fixed

- **The DHCP import preview now shows each scope's notes (#3097).** A scope's
  own warnings, such as a Kea or ISC pool left out because it lies outside
  the subnet, runs backwards or is not an address range, appeared only as a
  count ("3 notes") with no text, so the operator committed without knowing
  which pools would be missing. The notes are now listed under the scope's
  subnet in the review table.
