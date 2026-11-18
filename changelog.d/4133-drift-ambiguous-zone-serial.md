### Fixed

- A zone created in one DNS view and then again, under the same name, in a second view no longer reads "behind" in the drift report for as long as both copies exist; the first copy's stored creation serial is dropped when the name becomes ambiguous, so the report falls back to comparing records (#4133).
