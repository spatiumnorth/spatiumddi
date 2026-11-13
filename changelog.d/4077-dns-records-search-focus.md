### Fixed
- DNS server group → Records: the search box no longer loses focus after every character. The search is debounced (300 ms), the previous rows stay on screen while a new search loads, and a small inline "searching…" replaces the full-page "Loading records…"; the zone Records search is debounced the same way (#4077).
