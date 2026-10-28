### Fixed

- **Packet capture's appliance-vantage empty state no longer suggests
  `eth0` (#2884).** The appliance vantage already lists the host NICs
  the supervisor reports per appliance, and never the api container's
  list; before the first report it showed an empty list with a note
  telling the operator to type `eth0`, which is the container's NIC name
  and not the host's. The note now says to wait for the heartbeat or type
  the host NIC name as `ip link` shows it. A test pins that the appliance
  vantage never returns the container's interfaces.
- **Fleet's "Host NICs" now lists the host's NICs, not the supervisor
  pod's (#2884).** `capabilities.host_nics` came from `/sys/class/net`
  inside the supervisor pod's network namespace, so an appliance showed
  `eth0` while `appliance.host_interfaces` (udev) correctly said
  `cni0, enp1s0`. Both now come from the same function,
  `appliance_state.host_network_interfaces()`, so they cannot disagree.
  The list is the same one the packet-capture picker uses (`cni0` is
  included, as a real capture target; loopback, veths and docker
  devices are not). Nothing gates on `host_nics` (it is display only).
  The issue was rescoped after the original "appliance picker shows
  eth0" report did not reproduce.
