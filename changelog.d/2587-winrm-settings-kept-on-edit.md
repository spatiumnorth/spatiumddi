### Fixed

- **Editing a Windows DNS or Windows DHCP server keeps its stored WinRM
  settings.** The edit dialogs did not know the stored WinRM port,
  transport, HTTPS and certificate-validation settings, so they opened on
  the defaults (5985, NTLM, HTTP, no validation) and sent those back on
  every save, even an untouched one. A server set up for HTTPS on 5986 with
  certificate validation went back to plain HTTP the next time anyone saved
  its dialog. The server responses now carry these settings as
  `winrm_settings` (the username and password are never returned), the
  dialogs open on the stored values, and an edit sends only the settings the
  operator changed, so an untouched save sends none. The API still merges a
  partial credentials block over the stored one, so a setting a request does
  not send keeps its stored value. The audit row for a credentials change now
  records the old and new value of each WinRM setting it changed.
