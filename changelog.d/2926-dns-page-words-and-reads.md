### Fixed

- Add Zone no longer asks for the domain list when the user lacks read
  on domains (the IPAM, DNS and DHCP Editor roles do): no refused
  request, and the Linked Domain select is disabled with a note saying
  the list is not available. (#2926)
- A disabled DNS server's detail now reads "Enabled: no (disabled)"
  instead of "no (paused)", and the zone sync pill counts disabled and
  paused servers apart ("1 paused · 1 disabled"). (#2927)
