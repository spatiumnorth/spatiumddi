### Fixed

- **A quick reopen of a DNS edit dialog shows what was saved (#2830).**
  Edit Group, Edit Zone, the server dialog and Edit View seeded their form
  from a cached list row and started a refetch on Save without waiting for
  it, so a reopen before the refetch landed showed the old values (for
  example "Allow recursion" ticked after it was turned off) and an untouched
  Save wrote them back. Save now writes the returned row into the cached
  lists before closing; the refetch still runs.
