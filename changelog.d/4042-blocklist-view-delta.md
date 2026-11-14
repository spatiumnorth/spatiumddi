### Fixed

- `PUT /dns/blocklists/{id}/assignments` with only `add_view_ids` / `remove_view_ids` answered 200 and attached or detached nothing; view deltas now apply, and a delta that changes nothing still writes no audit row (#4042).
