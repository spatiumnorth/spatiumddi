### Fixed

- E911: a HELD lookup past the per-caller per-minute budget is now refused with HTTP 429 and a `Retry-After` header and resolves nothing, instead of being answered and merely counted, so every location returned has its own lookup-trail row. A change to the lookup budget setting now writes an audit row.
