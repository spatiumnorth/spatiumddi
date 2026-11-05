### Fixed

- The adblock blocklist skip banner, the `feed_parse_skipped` API field and the blocklist MCP tool now say why each rule was skipped, instead of one `malformed` count: a `*` inside the name, no `||` anchor, a trailing dot, a `|` start anchor, a bare `*`, a single-label name, or another shape. `malformed` stays as the total, and the same rules are skipped as before (#3519).

