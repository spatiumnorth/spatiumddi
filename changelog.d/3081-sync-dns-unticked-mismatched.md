### Fixed

- Sync DNS no longer rewrites a mismatched record you left unticked when another row of the same address is ticked: an unticked hand-edited PTR keeps its value while the address's ticked A is corrected, at subnet, block and space scope. A commit now changes exactly the existing records it names in `update_record_ids` ([#3081](https://github.com/spatiumnorth/spatiumddi/issues/3081)).
