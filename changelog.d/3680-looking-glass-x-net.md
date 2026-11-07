### Fixed

- **The looking-glass image builds against golang.org/x/net 0.62.0 (#3680).**
  The 0.60.0 pin carried CVE-2026-78661 (HIGH, a denial of service in
  `x/net/html`), which failed the Trivy gate and the nightly build. The pin is
  raised to 0.62.0, the release that fixes it.
