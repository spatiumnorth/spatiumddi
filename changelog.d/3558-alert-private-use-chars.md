### Fixed

- An alert message and its notifications keep U+E000 and U+E001 when a subnet or pool name contains them; the internal threshold marks now carry a random per-process token instead of a bare character pair (#3558).
