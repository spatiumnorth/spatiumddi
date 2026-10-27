### Fixed

- **An upgrade image can be stored on a cluster with the slot-image
  mirror again (#2855).** The app-wide 8 MiB request body cap added by
  #2796 also applies to the slot-image mirror, which is the same app,
  and it had no allowance for the mirror's write,
  `PUT /api/v1/appliance/internal/slot-images/{id}`. The api stores
  every image through that write, so uploading, repairing or importing
  an image from a GitHub release failed with
  `502 "Mirror upload failed"`, and the cluster could not be upgraded. The write now
  carries an allowance of the upload's own limit (4 GiB, one shared
  constant), and the mirror checks the caller's `X-Mirror-Auth`
  header as a dependency, before reading the image body. The
  supervisor's packet-capture upload, which also streams its body,
  now checks its appliance certificate the same way, and the
  structural test covers routes that read a raw body stream.
