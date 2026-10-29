### Fixed

- **The audit list and chain-check descriptions now say what they do
  (#3043, #3044).** The OpenAPI description of `include_details` on
  `GET /api/v1/audit` named three of the four fields it returns; it now
  names `error_detail` too. The Audit Log chain badge's tooltip and the
  description of `GET /api/v1/audit/integrity` said the nightly verify
  walks the whole chain; it checks the rows added since its last clean
  run, and re-walks the whole chain at least once every 7 days. Both
  texts now say that.
