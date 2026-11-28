### Fixed

- Changing an appliance's DNS engine to PowerDNS (Fleet or the Copilot) is now refused when its kept DNS group holds a forward or stub zone, naming the group and the zone, instead of leaving a zone that is accepted and never answers (#4681).
