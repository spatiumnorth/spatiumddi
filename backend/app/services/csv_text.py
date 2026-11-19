"""Read operator-supplied CSV text the same way in every importer.

The DICOM AE, OT device and IPAM importers each read a pasted or uploaded
table with ``csv.DictReader(io.StringIO(text))``. ``io.StringIO`` without
``newline=""`` splits lines on ``\\n`` only, so a file saved with classic
Mac line endings (a bare ``\\r`` between rows, or a paste that keeps them)
reached the csv module with a ``\\r`` inside an unquoted field, and it raised
``_csv.Error: new-line character seen in unquoted field``. None of the
callers turned that into a 4xx, so all three imports answered 500
(#1370, #1637, #1711).

:func:`read_csv_table` is the one place that opens the text: with
``newline=""``, as the csv module documents, so ``\\n``, ``\\r\\n`` and a
bare ``\\r`` all read alike, and with every ``csv.Error`` (a cell over
``csv.field_size_limit()``, say) raised as :class:`CSVReadError`, which each
importer turns into its own 422 with the reader's reason.

The table is read eagerly. Every caller already bounds its input (a
character cap on the pasted body, or the upload size), and reading it all
here is what keeps the ``csv.Error`` handling in one place instead of
wrapped around each caller's loop.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from typing import Any


class CSVReadError(ValueError):
    """The csv module refused the text. The message carries its reason."""


@dataclass(frozen=True)
class CSVTable:
    """A header row and its data rows, as ``csv.DictReader`` yields them.

    ``fieldnames`` is empty when the text has no header row. A row with
    more cells than headers keeps the extras in a list under the ``None``
    key, and a short row fills the missing cells with ``None``: the
    ``DictReader`` defaults, which the importers already handle.
    """

    fieldnames: list[str]
    rows: list[dict[str, Any]]


def read_csv_table(text: str, *, delimiter: str = ",") -> CSVTable:
    """Parse ``text`` as a CSV table with a header row.

    Raises :class:`CSVReadError` when the csv module cannot read it.
    """
    # newline="" leaves line endings to the csv module (#1370).
    reader = csv.DictReader(io.StringIO(text, newline=""), delimiter=delimiter)
    try:
        fieldnames = list(reader.fieldnames or [])
        rows: list[dict[str, Any]] = list(reader)
    except csv.Error as exc:
        raise CSVReadError(f"CSV could not be read: {exc}") from exc
    return CSVTable(fieldnames=fieldnames, rows=rows)
