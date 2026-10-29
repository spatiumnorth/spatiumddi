### Fixed

- **The audit list and chain-check descriptions now say what they do
  (#3043, #3044).** The OpenAPI description of `include_details` on
  `GET /api/v1/audit` named three of the four fields it returns; it now
  names `error_detail` too. The Audit Log chain badge's tooltip and the
  description of `GET /api/v1/audit/integrity` said the nightly verify
  walks the whole chain; it checks the rows added since its last clean
  run, and walks the whole chain again once its last full pass is more
  than 7 days old. Both texts now say that, and so does SYSTEM_ADMIN.md,
  which had promised a full pass "at least once every 7 days".
