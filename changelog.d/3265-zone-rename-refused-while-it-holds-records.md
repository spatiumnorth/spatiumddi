### Fixed

- **A zone that holds records can no longer be renamed through the API (#3265).**
  The rename answered 200 and left every record's name, the name IPAM keeps on
  each address and every PTR value IPAM published on the old name, and a name
  with an underscore label took the zone out of service while the console read
  "in sync". The API now answers 409 while the zone holds records, as the
  console's greyed-out name already implied; records in the Trash count, since a
  restore brings them back under the old name. A zone with no records still renames.
