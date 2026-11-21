### Fixed

- A custom field value an API client stored as an object or list now reads as text everywhere: the subnet and block pages, the subnet table and the address detail show an object as JSON instead of "[object Object]", and the PDF export and the search "Matched field" label print JSON instead of Python's repr.
