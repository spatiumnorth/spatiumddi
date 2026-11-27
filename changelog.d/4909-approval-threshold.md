### Fixed

- An approval policy saved with a Threshold (min rows) now gates the deletes it names: a single-target delete counts as one row, so a threshold of 1 queues a change request instead of the delete running inline (#4909).
