### Fixed

- **A rolling update of a formed cluster's database no longer turns new
  connections away for three and a half minutes (#2831).** With two or
  more Postgres instances the chart now sets CloudNativePG's
  `primaryUpdateMethod: switchover`, so a spec change that rolls the
  instances (a resources or parameter change, on an upgrade, a resize or a
  promote) promotes an updated replica first. Before, the operator deleted
  the primary's pod while it still served, and its smart shutdown refused
  every new connection for the full 180 s `smartShutdownTimeout` because
  the services' pooled sessions never end. A single instance keeps
  CloudNativePG's in-place restart, and the field is not part of the
  instance pods' spec, so an upgrade into this rolls nothing.
