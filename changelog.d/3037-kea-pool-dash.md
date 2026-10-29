### Fixed

- The Kea importer reads a pool written `"a-b"` (no spaces) as the range it is, as Kea does, and a pool or ISC range it cannot read or that falls outside its subnet is left out of the scope and named in the preview (and again at commit, which re-checks the plan it is sent) instead of failing the scope there. An ISC range written high-to-low, or a `range6` prefix, imports as dhcpd reads it. A scope that still fails at commit reports a plain sentence, not the database error and SQL (#3037).
