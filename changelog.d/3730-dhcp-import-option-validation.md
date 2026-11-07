### Fixed

- The DHCP importer (Kea, ISC, Windows) now holds a scope's, reservation's and client class's options to the same check the scope API runs on save: an option the API refuses (a name the platform does not map, such as `dhcp-renewal-time`, or a value Kea cannot load, such as `routers` `10.250.4.999`) is left out of the import and named in the preview and commit warnings, instead of being stored and reaching the rendered Kea config (#3730).
