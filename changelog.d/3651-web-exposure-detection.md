### Added

- **Web exposure detection (#3651).** A new opt-in feature module,
  `security.web_exposure` (off by default, Features & Integrations), answers
  "is my install reachable from the internet?" with a verdict and its
  evidence: which outside networks reached the sign-in screen or the
  api, how many requests, first and last seen, and which endpoints.
  "Internal" means private, CGNAT and ULA space plus an explicit
  trusted-networks list. Adds a `web_ui_exposed` alert rule, a
  Reachability card on the Security dashboard, a Settings -> Security
  -> Reachability section, two read-only copilot tools, and opt-in,
  default-off mitigations that never apply to internal or trusted
  sources: a stricter external sign-in throttle, a temporary source ban,
  a second factor required from outside, and an appliance Web UI
  allow-list bridge. Makes no outbound connection. The break glass is
  `WEB_EXPOSURE_MITIGATIONS=off`. An application-layer allow-list for
  Compose / Helm is not included.

### Migrations

- `b7d3e91c5a24` — #3651, adds `platform_settings.web_exposure` (JSONB,
  default `{}`).
