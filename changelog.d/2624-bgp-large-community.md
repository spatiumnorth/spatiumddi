### Fixed

- **A valid large or standard BGP community can be added (#2624).** Create checked every value as a regular community because the validator ran before the kind was known, so every large community (the only form carrying a 4-byte ASN) was refused with a message about the two-part form. The value is now checked against its own kind, and the Add dialog shows a refusal's reason instead of crashing on the 422 list.
