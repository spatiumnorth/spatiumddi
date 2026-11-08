### Fixed

- DNS server group, Blocking Lists tab: Apply, Detach, the bulk Apply / Detach and Save scope no longer overwrite a list's assignments with the tab's possibly stale copy, so a group or view another operator attached in the meantime keeps the list. They now send add / remove changes for this group only, which the server applies under a row lock (#3737).
