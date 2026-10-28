### Fixed

- The DHCP `domain-name` and `domain-search` options are now stored, and
  served to Kea, Windows DHCP and the cloud DHCP drivers, in the DNS form
  the validator already computed: IDNA A-labels, lower case, no trailing
  root dot (`Cafe-é.example.test.` becomes `xn--cafe--fsa.example.test`).
  This covers scope, pool, reservation, client-class, device-policy and
  option-template writes and the DHCP importers. Rows stored earlier are
  normalised when the config is rendered, so no migration is needed. (#2924)
