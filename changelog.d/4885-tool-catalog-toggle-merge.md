### Fixed

- Copilot Tool Catalog: switching one tool now changes only that tool. The page used to re-send the whole list as it last read it, which put back another admin's change and left the tools of a switched-off feature module off after the module came back; `PUT /ai/tools/catalog` now takes `changes` and merges it into the stored list (#4885).
