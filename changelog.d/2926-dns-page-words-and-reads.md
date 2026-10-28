### Fixed

- Add Zone no longer asks for the domain list when the user lacks read
  on domains (the IPAM, DNS and DHCP Editor roles do) or when domain
  tracking (`network.domains`) is turned off: no refused request, and
  the Linked Domain select is disabled with a note saying why. Editing a
  zone that is already linked keeps the link, and the select shows it as
  linked rather than as "auto-match". (#2926)
- A disabled DNS server's detail now reads "Enabled: no (disabled)"
  instead of "no (paused)", and the zone sync pill counts disabled and
  paused servers apart ("1 paused · 1 disabled"). (#2927)
