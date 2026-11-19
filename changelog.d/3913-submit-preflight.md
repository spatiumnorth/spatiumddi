### Added

- **Release submits preflight results for the `-ubi` images (#3913).**
  After the multi-arch `:<version>-ubi` is published, a non-gating
  release job submits Red Hat `preflight` results for each of the four
  images and both architectures to their Partner Connect certification
  components, when the `PYXIS_API_TOKEN` secret is set. A failed
  submission only warns; without the secret nothing is submitted.
