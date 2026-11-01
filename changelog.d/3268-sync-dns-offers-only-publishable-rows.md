### Fixed

- **Sync DNS no longer offers a fix for the subnet's own zone that its Apply always refuses (#3268).** When the subnet's zone has an underscore label (or a host name that would not fit in it), the preview listed the address's A or PTR as missing or mismatched, the Apply refused it with the record API's reason, and the same row came back after every Apply. The preview now applies the same publish rule the Apply does to the subnet's own zone, as it already did for the extra zones, and offers no row there.
