### Fixed

- A blocklist set to the hosts or domains format but fed an adblock file no longer stores every `||name^` rule as a name that blocks nothing, and a domains-format list fed a hosts file no longer empties itself. The refresh is refused with an error naming the detected format, the list's entries are left as they were, and tokens in a hosts or domains feed that are not DNS names are skipped and counted (#3531).
- The reverse case: a blocklist set to the adblock format but fed a hosts or domains file no longer refreshes "successfully" and empties itself. The refresh is refused with an error naming the format to switch to, and the list keeps its entries; real adblock feeds (AdGuard DNS filter, URLhaus, EasyPrivacy) parse exactly as before (#3597).
