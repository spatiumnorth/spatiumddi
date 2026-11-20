### Fixed

- **A SemVer pre-release tag can now be cut from a `release/*` branch.** `release.yml` accepts a pre-release such as `1.0.1-soak.1` whose commit is on a `release/*` branch (CI must still have passed on it, and the changelog fragments need not be folded), so the QA soak can install it. It publishes as a GitHub pre-release and never moves `:latest`. Final tags are still refused unless they are on `main`.
