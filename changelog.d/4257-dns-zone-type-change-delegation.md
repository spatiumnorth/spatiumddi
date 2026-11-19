### Fixed

- DNS: Edit Zone no longer turns a zone that holds records into a secondary, stub or forward zone, or promotes an empty secondary or stub to primary (409, naming why and what to do first: Sync with server), and Delegate no longer writes NS and glue records into a secondary or stub parent zone (409; the preview names the parent and the reason, and the console's Delegate item is disabled with it). The migration recipe now runs Sync with server before the promotion (#4257, #4258, #4261).
