### Fixed

- **Customer Delete no longer promises to clear references (#2613).** The row and bulk dialogs said cross-references "will be cleared"; the delete only hides the customer, so subnets, zones and ASNs that name it keep pointing at it. The dialogs now say so.
