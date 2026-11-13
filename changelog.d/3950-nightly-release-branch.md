### Changed

- The nightly build can now run for a release branch as well as `main`: dispatching `nightly.yml` with `ref=release/X.Y.Z` builds that branch's images and appliance and publishes them under their own names (`:nightly-X.Y.Z-YYYYMMDD`, pre-release `nightly-X.Y.Z-YYYY.MM.DD`), skips when that branch has not moved since its last nightly, keeps its own 7-night ring, and never touches `:latest` or `main`'s nightlies. The nightly trigger now dispatches `main` and `release/1.0.1` each evening. `main`'s nightly is unchanged.
