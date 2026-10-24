### Fixed

- **MAC sightings now match an existing IPAM row (#2651).** The lookup keyed
  on the raw address type, so every sighting of a known IP ran a failing
  INSERT before falling back. Both sides are normalised.
