### Fixed

- IP discovery: a long subnet sweep is no longer followed by repeat sweeps of the same subnet queued while it ran. Duplicates the dispatcher queued during a running sweep now skip once that sweep has finished.
