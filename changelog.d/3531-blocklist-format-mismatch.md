### Fixed

- A blocklist set to the hosts or domains format but fed an adblock file no longer stores every `||name^` rule as a name that blocks nothing. The refresh is refused with an error naming the detected format, the existing entries are kept, and tokens in a hosts or domains feed that are not DNS names are skipped and counted (#3531).
