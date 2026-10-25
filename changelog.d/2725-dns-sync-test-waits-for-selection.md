### Fixed

- Sync DNS's Apply now sends the selection the button shows. The request was built from the selection of an earlier render, so a fast click could commit nothing for the ticked rows; the selection is now passed in at click time (#2725).
