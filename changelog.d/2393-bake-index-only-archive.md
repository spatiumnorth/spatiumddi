### Fixed

- **Appliance bake could ship an index-only image archive (#2393).**
  A bake run without `BAKE_SAVE_PLATFORM` saved images platform-less,
  and under Docker's containerd store that can write the index with
  no layers, which air-gapped k3s cannot use. The platform now always
  defaults to the appliance architecture, and each archive is read
  back after saving; a missing config or layer fails the bake.
  When a platform save fails (a containerd-store copy that lost layer
  blobs), the bake removes only that image reference, pulls it again
  for the platform and retries the save once. If that still fails
  (on some builders a pull never refetches blobs whose unpacked
  snapshot already exists, so rmi + pull cannot repair the store),
  it copies the image from the registry straight to an archive with
  skopeo (run in a container, pinned in `versions.json`), which does
  not depend on the local store; the archive is verified like any
  other, and the bake refuses only if that fails too. The `rmi`,
  `pull` and recovery results are now logged instead of discarded.
  The Docker version and image store are logged.
