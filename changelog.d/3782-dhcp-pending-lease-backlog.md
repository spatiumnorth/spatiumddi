### Fixed

- The servers page now shows how far behind a DHCP agent is on lease events: the count includes rows the agent has read but not yet delivered and an estimate of rows still unread in Kea's lease file, and both the count and the age fall as the agent catches up. The age is the agent's own at its heartbeat, and the chip appears only once the lag passes two heartbeat intervals (60 s), so a healthy agent under steady renewal traffic shows nothing; counts print with a thousands separator (#3782).
