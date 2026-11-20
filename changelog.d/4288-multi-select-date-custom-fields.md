### Fixed

- Custom fields can now be defined as `multi_select` and `date`, as the data model and the IPAM importer already assumed; the API and the console refused both. A `multi_select` takes an options list like `select` and holds a list of those options, shown as ticked boxes in the edit dialogs and comma-joined in tables; a `date` holds `YYYY-MM-DD` and gets a date picker. Block, subnet and address writes (create, update, bulk edit) refuse, with a 422, an option outside the list, a value that is not a list, or a value that is not a date. (#4288)
