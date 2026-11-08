### Fixed

- A scope change on a Kea HA group no longer resets the HA pair more than it has to (#3779): the DHCP agent reloads only the daemon whose configuration changed (a v6-only change leaves dhcp4 and its HA state alone), and the HA heartbeat delay now defaults to 2 s instead of 10 s for new groups, cutting the hot-standby outage of a reload from about 21 s to about 4 s. Existing groups keep their stored value.
