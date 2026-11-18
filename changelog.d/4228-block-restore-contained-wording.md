### Fixed

- Restoring a block from the Trash whose range a live block now contains is still refused, but the refusal no longer tells the operator to set `parent_block_id` (which a Restore cannot do): it names the live block and says to move, resize or delete it first.
