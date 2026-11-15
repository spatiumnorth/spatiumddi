### Fixed

- A spreadsheet (CSV / XLSX) DNS import no longer stores a record scoped to a view that its pinned zone never serves: the preview flags the row and the commit refuses, the same rule the record API and the zone-file import apply (#3942).
