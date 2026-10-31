### Fixed

- The DHCP `domain-name` and `domain-search` options are now stored, and
  served to Kea, Windows DHCP and the cloud DHCP drivers, in the DNS form
  the validator already computed: IDNA A-labels, lower case, no trailing
  root dot (`Cafe-é.example.test.` becomes `xn--cafe--fsa.example.test`).
  This covers scope, pool, reservation, client-class, device-policy and
  option-template writes, the Windows raw spelling `opt-15` / `opt-119`,
  and the DHCP importers, whose preview now shows the form commit stores.
  Rows stored earlier are normalised when the config is rendered, so no
  migration is needed — but on upgrade the DHCP config bundle, and so its
  ETag, changes once for every group holding one of these options in
  another form, and its agents re-apply it once. A stored value with an
  entry the validator refuses is left exactly as it is, so it neither
  changes on render nor blocks an unrelated edit of its scope. The Windows
  cutover parity check compares these two options in DNS form, so an
  imported scope no longer reads as diverged over case or a root dot.
  (#2924)
