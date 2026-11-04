### Fixed

- **Refused DHCP deletes say why: option templates, MAC blocks, phone
  profiles (#3441).** When the server refuses Delete Option Template,
  Unblock MAC or Delete Phone Profile, the dialog now shows its reason
  and stays open, instead of staying open with nothing said: a row
  deleted elsewhere (404) and a role without delete (403) alike, as
  Delete Client Class already does. Closing the dialog clears the
  reason, so the next row's dialog opens clean.
