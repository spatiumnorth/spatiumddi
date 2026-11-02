### Fixed

- **Sync DNS no longer offers a fix that its Apply always refuses (#3268).** When a subnet's DNS zone has an underscore label in its name, Sync DNS listed an address's A or PTR as missing or mismatched, the Apply refused it with the record API's reason, and the same row came back after every Apply. The preview now applies the rule the Apply does: an address whose name cannot be published in its own zone gets no row, and neither do its extra zones, which the refused Apply never reaches either.
