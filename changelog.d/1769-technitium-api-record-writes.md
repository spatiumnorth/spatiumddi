### Fixed

- On a Technitium group managed through the API (`technitium_api`), a DNS pool now serves every healthy member instead of only the last one written, adding a record no longer deletes the operator's own records of the same type at that name (such as a site-verification TXT), and a zone missing on the server is reported as an error instead of reading or writing its parent zone.
