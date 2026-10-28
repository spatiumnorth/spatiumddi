### Fixed

- **Packet capture's appliance-vantage empty state no longer suggests
  `eth0` (#2884).** The appliance vantage already lists the host NICs
  the supervisor reports per appliance, and never the api container's
  list; before the first report it showed an empty list with a note
  telling the operator to type `eth0`, which is the container's NIC name
  and not the host's. The note now says to wait for the heartbeat or type
  the host NIC name as `ip link` shows it. A test pins that the appliance
  vantage never returns the container's interfaces.
