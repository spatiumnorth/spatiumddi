### Fixed

- **Split and merge read the integration-ownership columns from the shared
  list.** `subnet_carry.py` kept its own copy of the ownership FKs, which the
  integration-ownership guard refuses; it now builds from
  `INTEGRATION_OWNERSHIP_FKS`, so a new integration is covered without a
  second edit. The columns are unchanged.
