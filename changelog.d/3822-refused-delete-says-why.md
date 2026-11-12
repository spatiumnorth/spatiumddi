### Fixed
- A delete the server refuses (404, 409, 403) now says why, in the server's words, and re-reads the list instead of closing silently: Delete API Token keeps its dialog open with the reason, and the Overlays, Customers, PIM domains, Circuits, Services and TLS certificate lists show an alert line like Providers does (#3822).
