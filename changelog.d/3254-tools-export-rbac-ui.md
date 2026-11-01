### Fixed

- A user the API refuses is no longer offered controls that fail: Network Tools disables Run and says up front that the user lacks read on `use_network_tools`; Conformity's Export PDF and E911's CSV and IOS snippets are disabled when the page's own read is refused, and a started export that fails now says "not permitted" (403) or "unavailable" (5xx) in words instead of a status code or silence. The IPAM, DNS zone and support-bundle downloads now show the server's reason when refused, too (#3254, #3255).
