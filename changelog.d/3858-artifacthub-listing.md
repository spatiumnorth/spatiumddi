### Added

- The Helm chart now carries Artifact Hub metadata (license, links, image list generated from `.github/images.json`, prerelease flag, release-notes link), and the release workflow pushes `artifacthub-repo.yml` to the chart's OCI repository once a maintainer has registered it. README and the Kubernetes guide gain an Artifact Hub badge.
