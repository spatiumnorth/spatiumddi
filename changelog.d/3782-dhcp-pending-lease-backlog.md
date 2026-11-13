### Fixed

- The servers page now shows how far behind a DHCP agent is on lease events: the count includes an estimate of rows still unread in Kea's lease file, the chip leads with the lag (which falls as the agent catches up), and it only appears once the lag is well past the normal flush interval, so steady traffic shows nothing (#3782).
