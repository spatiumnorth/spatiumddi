### Fixed

- Adblock feeds such as the AdGuard DNS Filter: a dot-led rule that is a complete name (`.bbelements.com^`) now blocks that name's subdomains (not the apex), and `|name^` blocks exactly that name, instead of both being skipped; filename fragments like `.n.2.1.js^` stay skipped. The "rules skipped" note now leads with how many entries are enforced and explains each skipped count in plain words instead of reading like an error (#4037).
