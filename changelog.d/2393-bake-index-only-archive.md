### Fixed

- **Appliance bake could ship an index-only image archive (#2393).**
  A bake run without `BAKE_SAVE_PLATFORM` saved images platform-less,
  and under Docker's containerd store that can write the index with
  no layers, which air-gapped k3s cannot use. The platform now always
  defaults to the appliance architecture, and each archive is read
  back after saving; a missing config or layer fails the bake.
  When a platform save fails (a containerd-store copy that lost layer
  blobs), the bake removes only that image reference, pulls it again
  for the platform and retries the save once before refusing; the
  Docker version and image store are logged.
