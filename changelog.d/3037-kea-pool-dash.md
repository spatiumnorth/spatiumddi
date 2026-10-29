### Fixed

- The Kea importer reads a pool written `"a-b"` (no spaces) as the range it is, as Kea does, and a pool or ISC range it cannot read or that falls outside its subnet is named in the preview instead of failing the scope at commit. A scope that still fails at commit reports a plain sentence, not the database error and SQL (#3037).
