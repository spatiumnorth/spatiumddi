### Fixed

- **The DNS page's labels name their boxes (#3509).** The DNS page
  drew each field's label beside its box without tying it to it, so
  Edit Zone's Default TTL (seconds) was read by its placeholder, 3600,
  and no box in the zone, record, view, server and other DNS dialogs,
  or in a server group's options, was named by its label. The page now
  uses the labelled field the DHCP and IPAM dialogs use.
