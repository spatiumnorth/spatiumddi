### Fixed

- Sync DNS no longer rewrites a mismatched record you left unticked when another row of the same address is ticked: an unticked hand-edited PTR keeps its value while the address's ticked A is corrected, at subnet, block and space scope. A commit now changes exactly the existing records it names in `update_record_ids`; an unticked move of a host record into its zone writes no second record beside it, and an unticked Stale record is removed only through the delete list ([#3081](https://github.com/spatiumnorth/spatiumddi/issues/3081)).
