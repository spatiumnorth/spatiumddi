### Fixed

- Edit Zone no longer pins a zone to one view while it holds records scoped to another view. The change is refused with a 422 naming those records, the same rule the record API already applies; before, it answered 200 and those records were served in no view. (#3839)
