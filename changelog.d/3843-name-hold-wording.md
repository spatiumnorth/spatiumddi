### Fixed

- A zone the BIND9 agent holds back because its name is too long for its files is no longer reported as zone data its daemon refused: the agent's report says its name is too long for the agent's files, and the server chip reads "Zones held back" with a title that points at each zone's reason instead of asking to fix the zone's data (#3843).
