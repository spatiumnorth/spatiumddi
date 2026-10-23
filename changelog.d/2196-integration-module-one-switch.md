### Fixed

- **An integration's sync, alerts and dashboard panels now follow
  its feature module, and nothing else (#2196, #2197).** Each
  integration had two switches: the module in Settings → Features,
  and a `PlatformSettings.integration_*_enabled` column that the beat
  sweeps, the Tailscale token alert and the dashboards actually read.
  The toggle copied one into the other, and the copy failed two ways.
  A module turned on before the settings row existed was never
  copied, so the module read on while its sync never ran and nothing
  reported why. And Fortinet and Meraki were never in the copy at
  all, so their periodic sync never ran on any install; only Sync Now
  worked. Now the sweeps, the alert and both dashboard surfaces ask
  the module, so there is one switch and nothing to drift. The
  columns stay as a derived copy that nothing in the app reads,
  rewritten on every toggle (creating the settings row if needed) and
  at API startup, which also corrects installs already in this state.
  `GET /settings` now carries all eleven integration flags (NetBird,
  PAN-OS, Fortinet and Meraki were missing), reported from the
  module. Writing one in `PUT /settings` switches the module, is
  audited as a feature-module change, and needs a superadmin, like the
  Features toggle; sending the current value back is a no-op. A guard
  test fails if an integration module lacks a mirror entry, a
  settings field, a gated sweep or a dashboard panel, or if app code
  reads the columns.
