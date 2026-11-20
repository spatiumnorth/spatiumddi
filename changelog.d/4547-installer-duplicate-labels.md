### Fixed

- The appliance installer now checks, before it wipes anything, whether another attached disk carries the `var` / `state` / `ESP` filesystem labels the installed system mounts by, and stops instead of leaving two filesystems answering to one label. Interactively you can cancel, or clear the labels on the other disk after typing `CLEAR`; a headless install halts unless the preseed sets `clear_foreign_labels: true`. (#4547)
