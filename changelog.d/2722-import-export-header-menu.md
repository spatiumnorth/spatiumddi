### Fixed

- **IPAM Import / Export menus behave like the header menus beside them (#2722).** The subnet "Import / Export" and the space/block "Export" menus ignored Esc and outside clicks, stayed open next to other header menus, and dropped focus on the page body when the import dialog closed. They are now built on the shared `HeaderMenu`: Esc and an outside click close them, one is open at a time, and the import dialog returns focus to the trigger. "Include IP addresses" is a checkbox item that keeps the menu open, and an export error shows next to the button.
