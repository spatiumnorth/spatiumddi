### Fixed

- **Esc closes only the innermost layer, and the search palette is drawn on
  top (#2720, #2721).** With a suggestion list open inside a dialog (the DHCP
  option catalog, the request resource picker, the IP picker), one Esc closed
  the whole dialog and the text typed into it; the Esc that ends an IME
  composition did the same. The lists now close themselves on Esc and the
  dialog leaves an Esc that a control handled, or that belongs to a
  composition, alone. Ctrl/Cmd+K over a dialog opened the search palette
  beneath it while it held the keyboard; the palette is now rendered on
  `<body>` after the dialog, so it paints above it.
