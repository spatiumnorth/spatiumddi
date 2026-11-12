### Fixed

- A DNS record written into a secondary, stub or forward zone (create, bulk create, edit, zone-file and spreadsheet import, Copilot, request portal) is now refused with a 422 naming the zone type, instead of being stored and listed though nothing serves it (#3838).
