### Fixed

- The appliance Releases tab's Manual upgrade dialog no longer hardcodes `helm upgrade spatiumddi` with no namespace; it shows `<release>` and `-n <namespace>` placeholders and points at `helm list -A` ([#4295](https://github.com/spatiumnorth/spatiumddi/issues/4295)).
