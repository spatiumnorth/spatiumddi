### Fixed

- **The DNS encrypted-transport card, its refusal and the certificate
  notes now say where the Web UI Certificate really is (#3045).** They
  sent the admin to an Appliance tab called "Web UI Certificate"; since
  #404 it is an entry in the Fleet tab's side list. On an appliance the
  DoT / DoH card now links straight to it, and the 422 on enabling DoT,
  DoH or DoQ without a certificate, the certificate-expiry alert, the
  notes stored with new appliance certificates and the supervisor's TLS
  log messages say "Appliance → Fleet → Web UI Certificate". Fleet shows
  that entry only on an appliance-hosted control plane, so on Docker or
  Kubernetes the card, the 422 and the alert name the API that holds the
  certificate store instead of a page that is not there. The docs that
  named the old tab are corrected too, and a CI linter keeps the old name
  out. Notes already stored on existing certificates keep their old
  wording.
