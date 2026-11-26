### Fixed

- Switching an InfluxDB export target between v1 and v2/v3 now removes the secret the new version does not use (the v1 password or the v2/v3 token), which its form neither showed nor could clear, and a changed Base URL no longer asks to re-enter that hidden secret. ([#4889](https://github.com/spatiumnorth/spatiumddi/issues/4889))
