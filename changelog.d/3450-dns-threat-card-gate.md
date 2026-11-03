### Fixed
- The Dashboard Security tab's DNS tunneling card no longer asks for its summary every 60 s when your role cannot read DNS servers (each ask was refused with a 403 and logged as a denied request); the card now says it needs read on DNS servers instead of being silently missing. (#3450)
