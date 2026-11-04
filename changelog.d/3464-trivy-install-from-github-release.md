### Fixed

- CI's Trivy image scans run again. `aquasecurity/trivy-action` installs Trivy from `get.trivy.dev`, which stopped resolving on 3 Nov 2026, so every scan failed before it started: the nightly image builds, the release gate (no release could publish), and the agent-image PR checks. Trivy v0.70.0, the version the action used, is now installed from its GitHub release archive and checked against the release's checksums file before use, and every scan step skips the action's own installer. `make trivy` and the weekly scheduled scan run the Trivy container image and were not affected.
