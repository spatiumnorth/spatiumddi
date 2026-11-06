### Fixed

- A blocklist whose feed URL answers with a web page (HTML) or, on a list that already has feed entries, an empty file is no longer emptied by the refresh. The refresh is refused with an error naming the reason and the existing entries stay; a first refresh of a genuinely empty feed is still allowed and reported (#3607).
