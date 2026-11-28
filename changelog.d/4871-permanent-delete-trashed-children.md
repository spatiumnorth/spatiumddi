### Fixed

- A permanent delete of a subnet, block or IP space through the API is now refused (409) while a DHCP scope, block or subnet of it sits in the Trash, instead of silently destroying it with no audit row; the approval preview counts trashed scopes too.
