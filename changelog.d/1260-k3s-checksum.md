### Fixed

- The appliance build now verifies the downloaded k3s binary and airgap image tarball against the `sha256sum-<arch>.txt` file published with the k3s release, and fails the build on a mismatch instead of baking an unverified download into the image.
