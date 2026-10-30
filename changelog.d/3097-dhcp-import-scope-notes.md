### Fixed

- **The DHCP and DNS import previews now show each scope's or zone's notes
  (#3097).** A scope's own warnings, such as a Kea or ISC pool left out because
  it lies outside the subnet, runs backwards or is not an address range,
  appeared only as a count ("3 notes"), and a DNS zone's only as a "warnings"
  pill, so the operator committed without knowing what would be missing. The
  notes are now listed under the scope's subnet or the zone's name. A pool the
  Kea, ISC or Windows importer could not read at all (a Kea pool that is not an
  object, an ISC `range` with no address in it, a Windows range with no start
  or end) is now named in a note too, instead of being dropped without one.
