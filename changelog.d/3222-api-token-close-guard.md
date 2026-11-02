### Fixed

- **Dialogs that show a secret once no longer lose it to a stray click (#3222).**
  The API-token, webhook-secret, TSIG-secret, ephemeral pairing-code,
  replacement pairing-code and regenerated recovery-code dialogs now ask
  "close anyway?" when Done, Esc or the close button is used before the
  value was copied (or, for the masked API token, revealed). A copy that
  failed does not count; selecting the value and copying it by hand does.
  A webhook secret you typed yourself, and a persistent pairing code (which
  can be re-revealed later), still close without asking.
