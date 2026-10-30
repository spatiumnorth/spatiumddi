### Fixed

- **The TLS certificate store has its own permission, `certificate_store`
  (#3067).** Uploading, generating a CSR for, issuing with Let's Encrypt,
  listing or deleting the certificates DoT / DoH / DoQ serve used to need
  `read` or `admin` on `appliance`, which also grants fleet approve,
  upgrade and reboot, so only a superadmin or an Appliance Operator could
  do it. The built-in DNS Editor role now holds `admin` on
  `certificate_store`, and the store is reachable from the DNS server
  group's Encrypted transports card and, for a non-superadmin, from
  Appliance → Fleet. On an appliance that caller sees the appliance's
  store, the served certificate marked Active and not deletable: the page
  reads the install type from the public version endpoint rather than
  from appliance info it is not allowed to read. Making a certificate the Web UI certificate still
  needs `admin` on `appliance`: that covers Activate, and `activate: true`
  on an upload, a signed-cert import or a Let's Encrypt issue (the
  default, as before; a caller without it sends `activate: false`).
  Re-pointing or deleting the ACME account also needs it on an appliance
  whose Web UI certificate is a Let's Encrypt one, since that account
  renews it.
  **Existing custom roles lose nothing**: every store route still accepts
  the `appliance` grant it took before (`read` to read, `admin` for the
  rest), and the Appliance Operator role is granted `certificate_store`
  too. A custom role that should manage certificates without touching the
  appliance can now be given `certificate_store` alone. The
  `get_acme_account` Copilot tool now takes the same read grant as the
  REST route it mirrors instead of superadmin. Turning a DoT / DoH / DoQ
  listener on is unchanged and still superadmin-only. Migration
  `e3a9c71f40d2` adds `acme_order.activate_on_issue`.
