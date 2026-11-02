### Fixed

- **Global search no longer finds a deleted circuit (#3191).** A circuit
  deleted from the Circuits page still turned up in the header search, by
  name and by carrier id, and its result opened a Circuits list that did
  not contain it. Search now skips deleted circuits, as the list does. An
  overlay site's preferred circuits no longer accept a deleted circuit
  (422, as for an unknown id), and the overlay simulation no longer names
  one as a site's primary circuit, while a deleted circuit still counts when
  it is taken down in a what-if, so a transport-class policy is not reported
  unaffected while its site is blackholed. A new test walks the search providers
  and fails if one reads a soft-deletable table without excluding deleted
  rows.
