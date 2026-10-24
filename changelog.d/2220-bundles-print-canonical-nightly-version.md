### Fixed

- **The support bundle and appliance diagnostics name a nightly the same
  way `/api/v1/version` does (#2220).** Their manifests printed the bare
  image tag `nightly-YYYYMMDD`, while `/version`, the agents and the
  supervisor report `0.0.0-nightly-YYYYMMDD+<sha>`, so one bundle named
  its version two ways. Both now use the canonical spelling. Release
  builds are unchanged.
