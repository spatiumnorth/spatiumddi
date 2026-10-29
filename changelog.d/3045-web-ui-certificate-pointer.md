### Fixed

- **The DNS encrypted-transport card, its refusal and the certificate
  notes now name where the Web UI Certificate really is (#3045).** They
  sent the admin to an Appliance tab called "Web UI Certificate"; since
  #404 it is an entry in the Fleet tab's side list. The DoT / DoH card now
  links straight to it, and the 422 on enabling DoT, DoH or DoQ without a
  certificate, the certificate-expiry alert, the notes stored with new
  appliance certificates and the supervisor's TLS log messages say
  "Appliance → Fleet → Web UI Certificate". Notes already stored on
  existing certificates keep their old wording.
