### Fixed

- A DNS record written into a secondary, stub or forward zone (create, bulk create, edit, zone-file and spreadsheet import including their previews, pool create, Copilot, request portal) is now refused with a 422 naming the zone type, instead of being stored and listed though nothing serves it. Add Record, its `n` shortcut and the two import entries are disabled with the reason on those zones. Deleting an existing record still works (#3838).
