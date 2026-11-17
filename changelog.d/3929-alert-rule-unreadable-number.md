### Fixed
- Alert rules: a number field holding text the browser cannot read as a number (such as `85-`) was saved as empty, so the rule ran at the default threshold (or a pool rule with no free-address floor) with no word. Save now refuses it in words and keeps the stored value ([#3929](https://github.com/spatiumnorth/spatiumddi/issues/3929)).
