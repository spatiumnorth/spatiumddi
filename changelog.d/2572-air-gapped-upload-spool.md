### Fixed

- **An air-gapped upgrade-image upload no longer fills the receiving
  node's /var on a multi-node control plane (#2572).** #2452 refuses an
  upload that would leave the image store under the kubelet's eviction
  margin. With the slot-image mirror on, the store is the mirror's PVC on
  the mirror's node, but a multipart upload is buffered whole onto the
  node of whichever api pod receives it (its own /var) before the handler
  runs, and that node is never checked. A near-full receiving node could
  therefore be driven into DiskPressure by the transfer itself while the
  check passed against a roomy mirror. The upload is now refused before
  its body is read when buffering it would take the receiving node across
  the kubelet's 5% eviction trigger, as well as when storing it would
  leave the store under its 15% margin. (The spool is temporary, so it
  only has to stay above the trigger, where a stored image must leave the
  full 15%.) The import-from-GitHub path, which streams to the store
  without buffering on the node, is unchanged.
