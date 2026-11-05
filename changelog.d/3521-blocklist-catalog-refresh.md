### Changed

- **The curated blocklist catalog is refreshed against upstream
  (#3521).** Catalog version 2026.11.05. URLhaus now downloads from
  AdGuard's HostlistsRegistry copy of the malware-filter URLhaus list,
  because abuse.ch answers 410 Gone to anonymous downloads. 1Hosts Lite
  points at the maintained upstream list instead of a mirror that
  stopped at about 3,700 entries. DigitalSide Threat-Intel is removed:
  its host no longer answers. The OISD and 1Hosts license labels are
  corrected, and Hagezi Light, Hagezi Normal and Hagezi Threat
  Intelligence (Medium) are added, none of them recommended.
  A list you already subscribed to keeps the URL it was created with,
  because a subscribed list does not remember which catalog entry it
  came from. Check yours on the DNS page's Blocking Lists tab: a
  URLhaus list on `urlhaus.abuse.ch` or a DigitalSide list shows a
  failed refresh, and a 1Hosts Lite list on `o0.pages.dev` still
  refreshes but stays small.
  Delete it and subscribe again from the catalog, or edit its feed URL
  and format to the catalog's (URLhaus also changes format from hosts
  to adblock).
