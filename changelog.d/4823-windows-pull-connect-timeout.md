### Fixed

- A scheduled zone pull from a Windows DNS server that answers nothing now gives up after 5 seconds of connecting instead of waiting about 135 seconds, so one dead server no longer holds the worker for most of every pass (#4823).
