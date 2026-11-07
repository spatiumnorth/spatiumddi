### Fixed

- Saving a backup destination's Edit with nothing changed no longer writes an update audit row that lists every field and config key as changed; the row now records only what changed (with `old_value`, `changed_fields`, and secret keys by name only), and an edit that changes nothing writes none (#3697).
