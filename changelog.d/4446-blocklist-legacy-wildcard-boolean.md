### Fixed

- Updating a DNS blocklist with the deprecated `feed_entries_are_wildcard` boolean no longer turns a `by_syntax` list into `always` when the client sends back the value it was given; the boolean is applied only when it differs from the stored mode (#4446).
