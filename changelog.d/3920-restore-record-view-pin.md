### Fixed

- A DNS record restored from the Trash into a zone that has since been pinned to a different view is now refused, naming the record, its view and the zone's pin, instead of coming back scoped to a view the zone no longer serves (#3920).
