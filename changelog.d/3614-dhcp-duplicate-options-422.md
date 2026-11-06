### Fixed

- A DHCP option list that names the same option twice, by name, by code or one of each, is now refused with a 422 naming the option and both entries on scope and option-template saves, instead of silently keeping the last one (#3614).
