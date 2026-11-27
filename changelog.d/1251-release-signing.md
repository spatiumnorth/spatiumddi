### Added

- Release container images (including the `-ubi` variants) and the Helm chart are now signed keylessly with cosign, each image also carries a signed SPDX SBOM and a build-provenance attestation, and signing happens before `:latest` moves. The new "Verifying a release" page gives the exact `cosign verify` and `gh attestation verify` commands. The appliance ISO and slot image are not covered yet. (#1251)
