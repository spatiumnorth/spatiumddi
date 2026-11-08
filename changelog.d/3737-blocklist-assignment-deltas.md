### Fixed

- DNS server group, Blocking Lists tab: Apply, Detach, the bulk Apply / Detach and Save scope no longer overwrite a list's assignments with the tab's possibly stale copy, so a group or view another operator attached in the meantime keeps the list. They now send add / remove changes for this group only, which the server applies under a row lock; `PUT /api/v1/dns/blocklists/{id}/assignments` gains `add_*` / `remove_*` fields for this, refuses a full set mixed with changes for the same relationship with 422, and treats an empty body as a no-op (#3737).
