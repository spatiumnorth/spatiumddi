### Fixed

- API tokens: the resource-binding access select now starts at "read" and disables write/admin when the user does not hold them on the chosen resource type, instead of pre-selecting "write" and refusing it only after the name and password were filled in. (#4846)
