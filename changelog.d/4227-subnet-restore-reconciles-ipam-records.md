### Fixed

- A subnet restored from the Trash after its DNS zone was restored now has its IPAM-generated records reconciled to what IPAM holds now, as a restored zone does, so an address renamed meanwhile is published under its new name whichever of the two is restored first ([#4227](https://github.com/spatiumnorth/spatiumddi/issues/4227)).
