### Fixed

- **Global search no longer finds a deleted circuit (#3191).** A circuit
  deleted from the Circuits page still turned up in the header search, by
  name and by carrier id, and its result opened a Circuits list that did
  not contain it. Search now skips deleted circuits, as the list does. A
  new test walks the search providers and fails if one reads a
  soft-deletable table without excluding deleted rows.
