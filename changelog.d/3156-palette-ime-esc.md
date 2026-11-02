### Fixed

- **Esc that ends an IME composition no longer closes the search
  palette (#3156).** Cancelling a Japanese, Chinese or Korean
  composition with Esc left the palette open with its query, as it
  already does in dialogs. The same guard now covers the Copilot
  drawer, its prompt menu, the IP table's inline editors and the tag
  filter's suggestion list.
