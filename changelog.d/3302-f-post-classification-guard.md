### Changed

- Every POST route now has to declare whether a read-scoped API token may call it: `@read_only_post`, or the new `@token_write("reason")`. A new POST with neither fails CI, and the older unclassified routes are a checked-in baseline that can only shrink. The hand-kept list of "deliberately write" routes and its name-matching guard are gone; its entries are now annotations on the handlers, with reasons that were checked against each one. No endpoint behaves differently.
