### Fixed

- Delegate (and its preview) looked for a child zone's parent by name across every view of the group, so a child pinned to one view could get its NS and glue records written into the same-named parent of another view, whichever the database returned first. The parent is now looked up in the child's own view (a parent pinned to that view, or one pinned to no view); a child pinned to no view takes only a parent pinned to no view, and the dialog names the parent's view. (#4389)
