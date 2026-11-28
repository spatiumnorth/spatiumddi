### Fixed

- IPAM: an address's PTR record now goes into the reverse zone in the same view as the forward zone its A record is in. Before, a group holding the same reverse zone in two views could take it into either view's zone depending on row order; when the forward zone's view has no reverse zone, no PTR is written. ([#4797](https://github.com/spatiumnorth/spatiumddi/issues/4797))
