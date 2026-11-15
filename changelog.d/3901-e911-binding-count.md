### Fixed
- The E911 location lookup, and the ERL answers to an edit or a validation verdict, reported `binding_count: 0` for an ERL that has bindings; they now return the real count, as the list and the single read already did ([#3901](https://github.com/spatiumnorth/spatiumddi/issues/3901)).
